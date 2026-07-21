#[cfg(test)]
mod tests {
    use sorosusu_contracts::slashing::mempool::{SlashingMempool, Evidence, OverflowError};

    #[test]
    fn test_minimal_evidence_flood_griefing_resistance() {
        let mut mempool = SlashingMempool::new();
        let victim_validator = 101; 

        // 1. Submit the first evidence entry - must be accepted
        let first_evidence = Evidence { validator_index: victim_validator, data: vec![] };
        assert!(mempool.push_evidence(first_evidence).is_ok(), "First evidence should be accepted");

        // 2. Submit 99 additional duplicate/minimal evidence entries
        for _ in 0..99 {
            let redundant_evidence = Evidence { validator_index: victim_validator, data: vec![] };
            let result = mempool.push_evidence(redundant_evidence);
            
            // Assert they are all rejected with OverflowError
            assert_eq!(result, Err(OverflowError::RateLimitReached));
        }

        // 3. Drain and assert only 1 evidence was actually processed into the mempool
        let processed = mempool.drain_all();
        assert_eq!(processed.len(), 1, "Mempool should only contain 1 evidence entry");
        assert_eq!(processed[0].validator_index, victim_validator);
    }
}
