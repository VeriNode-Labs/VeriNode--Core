//! Integration test: BFT view-change Quorum Certificate partition resolver (issue #142).
//!
//! Under network partitions, disjoint committees produce divergent QCs for the same view.
//! When the partition heals, nodes exchange divergent QCs.
//! This test suite simulates partition divergence, cross-partition healing, deterministic
//! tie-breaking (highest qc_epoch, followed by lexicographical public-key set hash),
//! 2-round quarantine retention with GC, observability event emission, and convergence
//! within 3 view-change rounds.

use sorosusu_contracts::consensus::view_change::{
    compute_public_key_set_hash, AggregateSignature, BlockHash, PublicKey, QcProcessOutcome,
    ViewChangeEvent, ViewChangeResolver, CONVERGENCE_ROUND_LIMIT, QC,
};

fn make_pk(id: u8) -> PublicKey {
    let mut pk = [0u8; 32];
    pk[0] = 0xAA;
    pk[31] = id;
    pk
}

fn make_block_hash(id: u8) -> BlockHash {
    let mut h = [0u8; 32];
    h[0] = 0xBB;
    h[31] = id;
    h
}

fn make_sig(id: u8) -> AggregateSignature {
    let mut sig = [0u8; 96];
    sig[0] = 0xCC;
    sig[95] = id;
    sig
}

#[test]
fn test_partition_divergent_qcs_heal_and_converge_by_epoch() {
    // 1. Simulate two partitions of nodes: Partition A and Partition B at view 10.
    let mut node_a = ViewChangeResolver::new(10);
    let mut node_b = ViewChangeResolver::new(10);

    // Partition A proposes QC_A with epoch 1.
    let qc_a = node_a
        .create_proposal(
            10,
            make_block_hash(1),
            vec![make_pk(1), make_pk(2), make_pk(3)],
            make_sig(1),
        )
        .expect("proposal creation succeeds");
    assert_eq!(qc_a.qc_epoch, 1);

    // Partition B proposes QC_B with epoch 2 (more recent network state in partition B).
    let _ = node_b
        .create_proposal(9, make_block_hash(99), vec![make_pk(4)], make_sig(99))
        .expect("dummy proposal to advance epoch");
    let qc_b = node_b
        .create_proposal(
            10,
            make_block_hash(2),
            vec![make_pk(4), make_pk(5), make_pk(6)],
            make_sig(2),
        )
        .expect("proposal creation succeeds");
    assert_eq!(qc_b.qc_epoch, 2);

    // Both partitions accept their local QCs during partition.
    assert_eq!(
        node_a.process_qc(qc_a.clone()).unwrap(),
        QcProcessOutcome::AcceptedNew
    );
    assert_eq!(
        node_b.process_qc(qc_b.clone()).unwrap(),
        QcProcessOutcome::AcceptedNew
    );

    assert_eq!(node_a.get_accepted_qc(10), Some(&qc_a));
    assert_eq!(node_b.get_accepted_qc(10), Some(&qc_b));
    assert_ne!(node_a.get_accepted_qc(10), node_b.get_accepted_qc(10));

    // 2. Heal network partition: cross-exchange QCs.
    let outcome_a = node_a.process_qc(qc_b.clone()).unwrap();
    let outcome_b = node_b.process_qc(qc_a.clone()).unwrap();

    // Node A replaces QC_A with QC_B (epoch 2 > epoch 1).
    assert_eq!(outcome_a, QcProcessOutcome::ConflictResolvedAccepted);
    assert_eq!(node_a.get_accepted_qc(10), Some(&qc_b));
    assert!(node_a.is_quarantined(&qc_a));
    assert!(!node_a.is_quarantined(&qc_b));

    // Node B retains QC_B (epoch 2 > epoch 1) and quarantines QC_A.
    assert_eq!(outcome_b, QcProcessOutcome::ConflictResolvedQuarantined);
    assert_eq!(node_b.get_accepted_qc(10), Some(&qc_b));
    assert!(node_b.is_quarantined(&qc_a));
    assert!(!node_b.is_quarantined(&qc_b));

    // Assert both nodes have converged deterministically to the exact same QC!
    assert_eq!(node_a.get_accepted_qc(10), node_b.get_accepted_qc(10));

    // 3. Verify observability events were emitted on both nodes.
    let events_a = node_a.events();
    assert!(events_a.iter().any(|e| matches!(
        e,
        ViewChangeEvent::QcConflictDetected {
            view: 10,
            qc_epoch_a: 1,
            qc_epoch_b: 2,
        }
    )));

    let events_b = node_b.events();
    assert!(events_b.iter().any(|e| matches!(
        e,
        ViewChangeEvent::QcConflictDetected {
            view: 10,
            qc_epoch_a: 2,
            qc_epoch_b: 1,
        }
    )));

    // 4. Assert convergence and quarantine GC across 3 view-change rounds.
    // Round 1 (view 11): 1 round elapsed since quarantine at view 10 -> qc_a remains quarantined.
    let evicted_a_r1 = node_a.advance_view(11);
    let evicted_b_r1 = node_b.advance_view(11);
    assert!(evicted_a_r1.is_empty());
    assert!(evicted_b_r1.is_empty());
    assert!(node_a.is_quarantined(&qc_a));
    assert!(node_b.is_quarantined(&qc_a));

    // Round 2 (view 12): 2 rounds elapsed (12 - 10 = 2 >= QUARANTINE_ROUND_LIMIT) -> qc_a is garbage collected!
    let evicted_a_r2 = node_a.advance_view(12);
    let evicted_b_r2 = node_b.advance_view(12);
    assert_eq!(evicted_a_r2, vec![qc_a.clone()]);
    assert_eq!(evicted_b_r2, vec![qc_a.clone()]);
    assert!(!node_a.is_quarantined(&qc_a));
    assert!(!node_b.is_quarantined(&qc_a));
    assert!(node_a.quarantine_buffer().is_empty());
    assert!(node_b.quarantine_buffer().is_empty());

    // Round 3 (view 13): Well within 3 rounds, both nodes remain healthy, converged, and clear of quarantine.
    let evicted_a_r3 = node_a.advance_view(13);
    let evicted_b_r3 = node_b.advance_view(13);
    assert!(evicted_a_r3.is_empty());
    assert!(evicted_b_r3.is_empty());
    assert_eq!(node_a.get_accepted_qc(10), node_b.get_accepted_qc(10));
}

#[test]
fn test_partition_equal_epoch_deterministic_public_key_hash_tie_breaking() {
    let mut node_1 = ViewChangeResolver::new(20);
    let mut node_2 = ViewChangeResolver::new(20);

    let pks_a = vec![make_pk(1), make_pk(2), make_pk(3)];
    let pks_b = vec![make_pk(4), make_pk(5), make_pk(6)];

    let hash_a = compute_public_key_set_hash(&pks_a);
    let hash_b = compute_public_key_set_hash(&pks_b);
    assert_ne!(hash_a, hash_b);

    // Create divergent QCs for view 20 with identical epoch 5.
    let qc_a = QC::new(20, 5, make_block_hash(1), pks_a, make_sig(1));
    let qc_b = QC::new(20, 5, make_block_hash(2), pks_b, make_sig(2));

    // Node 1 starts with QC_A; Node 2 starts with QC_B.
    node_1.process_qc(qc_a.clone()).unwrap();
    node_2.process_qc(qc_b.clone()).unwrap();

    // Cross-exchange QCs upon partition heal.
    node_1.process_qc(qc_b.clone()).unwrap();
    node_2.process_qc(qc_a.clone()).unwrap();

    // Determine expected winner based on lexicographical public-key set hash.
    let (expected_winner, expected_loser) = if hash_a > hash_b {
        (&qc_a, &qc_b)
    } else {
        (&qc_b, &qc_a)
    };

    // Both nodes MUST select the exact same winner.
    assert_eq!(node_1.get_accepted_qc(20), Some(expected_winner));
    assert_eq!(node_2.get_accepted_qc(20), Some(expected_winner));

    // Both nodes MUST quarantine the exact same loser.
    assert!(node_1.is_quarantined(expected_loser));
    assert!(node_2.is_quarantined(expected_loser));
    assert!(!node_1.is_quarantined(expected_winner));
    assert!(!node_2.is_quarantined(expected_winner));

    // Advance 3 rounds and verify clean convergence and quarantine purge.
    for v in 21..=23 {
        node_1.advance_view(v);
        node_2.advance_view(v);
    }
    assert!(node_1.quarantine_buffer().is_empty());
    assert!(node_2.quarantine_buffer().is_empty());
}

#[test]
fn test_partition_multi_node_cluster_simulation() {
    const NUM_NODES: usize = 7;
    // 7 nodes: partition 1 (nodes 0..3) and partition 2 (nodes 4..6)
    let mut cluster: Vec<ViewChangeResolver> = (0..NUM_NODES)
        .map(|_| ViewChangeResolver::new(50))
        .collect();

    // Partition 1 generates QC_P1 for view 50.
    let qc_p1 = cluster[0]
        .create_proposal(
            50,
            make_block_hash(10),
            vec![make_pk(0), make_pk(1), make_pk(2), make_pk(3)],
            make_sig(10),
        )
        .unwrap();

    // Partition 2 generates QC_P2 for view 50 with a higher epoch.
    // Advance epoch in partition 2 by creating earlier proposals.
    let _ = cluster[4]
        .create_proposal(48, make_block_hash(1), vec![make_pk(4)], make_sig(1))
        .unwrap();
    let _ = cluster[4]
        .create_proposal(49, make_block_hash(2), vec![make_pk(5)], make_sig(2))
        .unwrap();
    let qc_p2 = cluster[4]
        .create_proposal(
            50,
            make_block_hash(20),
            vec![make_pk(4), make_pk(5), make_pk(6)],
            make_sig(20),
        )
        .unwrap();

    assert!(qc_p2.qc_epoch > qc_p1.qc_epoch);

    // Nodes 0..3 accept QC_P1 locally.
    for node in cluster.iter_mut().take(4) {
        node.process_qc(qc_p1.clone()).unwrap();
        assert_eq!(node.get_accepted_qc(50), Some(&qc_p1));
    }

    // Nodes 4..6 accept QC_P2 locally.
    for node in cluster.iter_mut().skip(4) {
        node.process_qc(qc_p2.clone()).unwrap();
        assert_eq!(node.get_accepted_qc(50), Some(&qc_p2));
    }

    // Heal network partition: broadcast all QCs to all cluster nodes.
    for node in cluster.iter_mut() {
        node.process_qc(qc_p1.clone()).unwrap();
        node.process_qc(qc_p2.clone()).unwrap();
    }

    // Assert that every single node in the cluster converged to QC_P2!
    for (i, node) in cluster.iter().enumerate() {
        assert_eq!(
            node.get_accepted_qc(50),
            Some(&qc_p2),
            "Node {} did not converge to QC_P2",
            i
        );
        assert!(
            node.is_quarantined(&qc_p1),
            "Node {} did not quarantine divergent QC_P1",
            i
        );
    }

    // Advance 3 view-change rounds: 51, 52, 53 (CONVERGENCE_ROUND_LIMIT = 3).
    for v in 51..=(50 + CONVERGENCE_ROUND_LIMIT) {
        for node in cluster.iter_mut() {
            node.advance_view(v);
        }
    }

    // Assert that all nodes purged the quarantine buffer and remain converged.
    for (i, node) in cluster.iter().enumerate() {
        assert!(
            node.quarantine_buffer().is_empty(),
            "Node {} has non-empty quarantine buffer after 3 rounds",
            i
        );
        assert_eq!(node.get_accepted_qc(50), Some(&qc_p2));
    }
}

#[test]
fn test_quarantine_exact_2_round_lifecycle() {
    let mut resolver = ViewChangeResolver::new(100);
    let qc_canonical = QC::new(100, 2, make_block_hash(1), vec![make_pk(1)], make_sig(1));
    let qc_conflicting = QC::new(100, 1, make_block_hash(2), vec![make_pk(2)], make_sig(2));

    resolver.process_qc(qc_canonical).unwrap();
    resolver.process_qc(qc_conflicting.clone()).unwrap();

    assert!(resolver.is_quarantined(&qc_conflicting));

    // View 100: 0 rounds elapsed -> not evicted.
    let evicted_100 = resolver.advance_view(100);
    assert!(evicted_100.is_empty());
    assert!(resolver.is_quarantined(&qc_conflicting));

    // View 101: 1 round elapsed (101 - 100 = 1 < QUARANTINE_ROUND_LIMIT = 2) -> not evicted.
    let evicted_101 = resolver.advance_view(101);
    assert!(evicted_101.is_empty());
    assert!(resolver.is_quarantined(&qc_conflicting));

    // View 102: 2 rounds elapsed (102 - 100 = 2 >= QUARANTINE_ROUND_LIMIT = 2) -> evicted!
    let evicted_102 = resolver.advance_view(102);
    assert_eq!(evicted_102, vec![qc_conflicting.clone()]);
    assert!(!resolver.is_quarantined(&qc_conflicting));
    assert!(resolver.quarantine_buffer().is_empty());
}
