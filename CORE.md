# VeriNode Core Guide

This is the consolidated guide for `sorosusu-contracts`, the VeriNode Core
Rust/Soroban workspace. It replaces the previous scattered status reports,
feature notes, runbooks, and API notes with one source of truth for setup,
module ownership, exported APIs, operational checks, and troubleshooting.

## Contents

- [Project Overview](#project-overview)
- [Repository Layout](#repository-layout)
- [Setup And Build](#setup-and-build)
- [Core Contract API](#core-contract-api)
- [Root Module Exports](#root-module-exports)
- [Module API Inventory](#module-api-inventory)
- [Operational Guides](#operational-guides)
- [Testing And CI](#testing-and-ci)
- [Troubleshooting](#troubleshooting)

## Project Overview

VeriNode Core implements a decentralized savings-circle protocol on Stellar
Soroban. The root contract is `SoroSusu`; it manages rotating savings circles,
member deposits, round finalization, insurance coverage, collateralized entry,
buddy safety deposits, leniency voting, quadratic governance, and collateral
slashing/release flows.

The crate also includes companion modules for validator and consensus support:
attestation, BLS-style key utilities, DKG serialization, slashing evidence,
settlement proofs, mempool ordering, fee burn accounting, backups, webhooks,
runtime configuration, SLO monitoring, chaos experiments, replication,
incident response, rate limiting, secret rotation, job scheduling, and Kafka
consumer-lag scaling primitives.

Package metadata:

| Item | Value |
| --- | --- |
| Package | `sorosusu-contracts` |
| Library crate | `sorosusu_contracts` |
| Edition | Rust 2021 |
| Contract framework | `soroban-sdk = 21.0.0` |
| Crate types | `cdylib`, `rlib` |
| License | MIT |

## Repository Layout

| Path | Purpose |
| --- | --- |
| `src/lib.rs` | Root `SoroSusu` contract, contract data types, public traits, and module declarations. |
| `src/attestation/` | Attestation verification, bitfields, BLS-style aggregation helpers, nonce handling, proof of connectivity, and key rotation. |
| `src/attestation_core/` | Lower-level attestation aggregation state and signature aggregation helpers. |
| `src/backup/` | State snapshot, integrity, retention, and restore-test primitives. |
| `src/consensus/` | Fork-choice weighting and fee split/burn accounting. |
| `src/crypto/` | Hashing, domain separation, DKG, merkleization, and model BLS key utilities. |
| `src/db/` | Cache and schema-migration helpers. |
| `src/mempool/` | Priority transaction queue, block builder, eviction, and reorg recovery. |
| `src/network/` | DKG message serialization, peer message parsing, and SSZ-style attestation encoding. |
| `src/pool_manager/` | Tenant bond lock/unlock manager and reentrancy guard. |
| `src/reputation/` | Fixed-point helpers, circular windows, score ledgers, decay, and EMA score updates. |
| `src/settlement/` | Bond-settlement commitment/proof primitives. |
| `src/slashing/` and `src/slashing_core/` | Slashing evidence, penalties, relay handling, monitoring, execution, storage, and reward-pool helpers. |
| `src/state/` and `src/validator/` | Validator set, activation/exit queues, balance tracking, committee assignment, and epoch transition helpers. |
| `src/webhook/` | Domain-separated webhook delivery and retry engine. |
| `src/config*.rs`, `src/slo.rs`, `src/chaos.rs`, `src/replication/`, `src/incident_response/` | Operational controls for configuration, SLOs, staging experiments, DR planning, and incident routing. |
| `src/job_scheduler/`, `src/rate_limit.rs`, `src/secret_rotation/`, `src/kafka_consumer/` | Service-support primitives for background work, tenant throttling, credential rotation, and consumer scaling. |
| `scripts/` | Developer setup, quality checks, dependency security scans, and storage-layout validation. |
| `tests/` | Integration and feature tests for slashing, BLS, DKG, proof of connectivity, backups, webhooks, Kafka lag, and contract flows. |

## Setup And Build

Install the Rust toolchain and the WASM target used by Soroban contracts:

```bash
rustup target add wasm32-unknown-unknown
```

Build the contract:

```bash
cargo build --target wasm32-unknown-unknown --release
```

Run tests:

```bash
cargo test
```

Run the repository setup helper:

```bash
scripts/dev-setup.sh
```

Run the pre-commit quality helper against changed files:

```bash
scripts/pre-commit-quality.sh
```

Run the storage layout check:

```bash
python scripts/storage-layout-check.py
```

## Core Contract API

The root contract API is declared by `SoroSusuTrait` in `src/lib.rs` and
implemented by `SoroSusu`.

### Contract Clients

| Export | Purpose |
| --- | --- |
| `SusuNftTrait` / `SusuNftClient` | External NFT client used for membership-token mint/burn integration. |
| `LendingPoolTrait` / `LendingPoolClient` | External lending-pool client used to supply and withdraw token liquidity. |

### Lifecycle And Administration

| Function | Purpose |
| --- | --- |
| `init(env, admin)` | Initializes `CircleCount` and stores the contract administrator. |
| `set_lending_pool(env, admin, pool)` | Authenticated admin call that stores the external lending-pool address. |

### Circle Lifecycle

| Function | Purpose |
| --- | --- |
| `create_circle(env, creator, amount, max_members, token, cycle_duration, insurance_fee_bps, nft_contract) -> u64` | Creates a savings circle, rate-limits the creator, configures collateral requirements for high-value circles, and returns the new circle id. |
| `join_circle(env, user, circle_id, tier_multiplier, referrer)` | Adds an authenticated user to an active circle, applies referral tiering, and enforces collateral requirements when enabled. |
| `deposit(env, user, circle_id)` | Records the member contribution, transfers funds from the member to the contract, and supports buddy safety-deposit fallback. |
| `finalize_round(env, caller, circle_id)` | Marks a round finalized after all active members have contributed. |
| `claim_pot(env, user, circle_id)` | Lets the scheduled recipient claim the current pot after finalization and advances the recipient index. |

### Insurance, Buddy, And Membership Safety

| Function | Purpose |
| --- | --- |
| `trigger_insurance_coverage(env, caller, circle_id, member)` | Lets the circle creator or admin cover a missed member contribution from insurance balance. |
| `eject_member(env, caller, circle_id, member)` | Lets the circle creator or admin eject a member from an active circle. |
| `pair_with_member(env, user, buddy_address)` | Stores a buddy relationship for safety-deposit fallback. |
| `set_safety_deposit(env, user, circle_id, amount)` | Stores a safety-deposit balance for a member/circle pair. |

### Leniency Voting

| Function | Purpose |
| --- | --- |
| `request_leniency(env, requester, circle_id, reason)` | Creates a pending grace-period request for a member. |
| `vote_on_leniency(env, voter, circle_id, requester, vote)` | Records one approve/reject vote from another active circle member. |
| `finalize_leniency_vote(env, caller, circle_id, requester)` | Finalizes a request after the voting period and updates circle grace-period state and statistics. |
| `get_leniency_request(env, circle_id, requester) -> LeniencyRequest` | Reads a stored leniency request. |
| `get_social_capital(env, member, circle_id) -> SocialCapital` | Reads trust-score and voting-participation state. |
| `get_leniency_stats(env, circle_id) -> LeniencyStats` | Reads aggregate leniency statistics for a circle. |

### Quadratic Governance

| Function | Purpose |
| --- | --- |
| `create_proposal(env, proposer, circle_id, proposal_type, title, description, execution_data) -> u64` | Creates an active governance proposal for a circle. |
| `quadratic_vote(env, voter, proposal_id, vote_weight, vote_choice)` | Records a weighted vote where cost is `vote_weight * vote_weight`. |
| `execute_proposal(env, caller, proposal_id)` | Closes a proposal after the voting period and executes approved proposal logic. |
| `get_proposal(env, proposal_id) -> Proposal` | Reads proposal state. |
| `get_voting_power(env, member, circle_id) -> VotingPower` | Reads current quadratic voting power. |
| `get_proposal_stats(env, circle_id) -> ProposalStats` | Reads proposal aggregate statistics. |
| `update_voting_power(env, member, circle_id, token_balance)` | Updates a member's voting power from token balance. |

### Collateral

| Function | Purpose |
| --- | --- |
| `stake_collateral(env, user, circle_id, amount)` | Locks collateral for a high-value circle before joining. |
| `slash_collateral(env, caller, circle_id, member)` | Moves a defaulted member's staked collateral into the group reserve. |
| `release_collateral(env, caller, circle_id, member)` | Releases staked collateral after the member completes all required contributions. |
| `mark_member_defaulted(env, caller, circle_id, member)` | Marks a member defaulted and triggers collateral slashing when applicable. |

### Root Contract Types

| Export | Purpose |
| --- | --- |
| `Error` | Contract error codes for authorization, circle state, collateral, leniency, and governance failures. |
| `DataKey` | Contract storage keys for admin, circles, members, deposits, proposals, votes, collateral, and statistics. |
| `MemberStatus` | `Active`, `AwaitingReplacement`, `Ejected`, or `Defaulted`. |
| `LeniencyVote` | Leniency ballot value: `Approve` or `Reject`. |
| `LeniencyRequestStatus` | `Pending`, `Approved`, `Rejected`, or `Expired`. |
| `ProposalType` | Governance proposal category. |
| `ProposalStatus` | Proposal lifecycle state. |
| `QuadraticVoteChoice` | `For`, `Against`, or `Abstain`. |
| `LeniencyRequest` | Stored leniency request fields. |
| `Proposal` | Stored governance proposal fields. |
| `QuadraticVote` | Individual quadratic vote record. |
| `VotingPower` | Member voting power snapshot. |
| `ProposalStats` | Aggregate proposal counters. |
| `LeniencyStats` | Aggregate leniency counters. |
| `CollateralStatus` | `NotStaked`, `Staked`, `Slashed`, or `Released`. |
| `SocialCapital` | Member trust metrics. |
| `CollateralInfo` | Member collateral vault record. |
| `Member` | Circle membership record. |
| `CircleInfo` | Circle configuration and lifecycle state. |
| `SoroSusu` | Soroban contract type implementing `SoroSusuTrait`. |

## Root Module Exports

`src/lib.rs` exports these public modules:

| Module | Responsibility |
| --- | --- |
| `slashing_core` | Core slashing monitor, executor, event store, and reward-pool primitives. |
| `slashing` | Slashing evidence validation, relay handling, mempool constraints, penalties, and evidence types. |
| `network` | DKG message serialization, peer message parsing, and SSZ-style attestation codec. |
| `reputation` | Reputation ledger, fixed-point arithmetic, historical windows, score engine, and decay types. |
| `attestation_core` | Attestation aggregation state and signature aggregation helpers. |
| `attestation` | Connectivity proofs, nonces, key registry, attestation data, verification, bitfields, and inclusion rewards. |
| `crypto` | Hashing, domain separation, merkleization, DKG, and BLS-style key utilities. |
| `consensus` | Fork-choice weighting and fee burn/split accounting. |
| `state` | Epoch transition helpers. |
| `validator` | Validator activation, balances, committees, exits, and set state. |
| `db` | Committee cache and schema migration helpers. |
| `settlement` | Bond settlement commitments, merkle proofs, and pool-manager settlement logic. |
| `mempool` | Priority queue, block builder, eviction, and reorg recovery. |
| `pool_manager` | Tenant bond manager and reentrancy guard. |
| `backup` | State snapshot and restore-test primitives. |
| `webhook` | Webhook payload delivery, retry state, and backoff calculation. |
| `config_audit` | Runtime configuration drift detection. |
| `replication` | Multi-region replication topology, failover planning, and DR reporting. |
| `job_scheduler` | Lease-based background job scheduler. |
| `incident_response` | Incident plan and PagerDuty event construction. |
| `rate_limit` | Per-tenant token-bucket rate limiting. |
| `config` | Runtime config validation and hot-reload gating. |
| `slo` | Error-budget and burn-rate evaluation. |
| `chaos` | Staging chaos experiment catalog and rollout-gate helpers. |
| `secret_rotation` | Credential versioning and rotation service. |
| `kafka_consumer` | Consumer lag metrics, canary analysis, scaling decisions, and group registry. |

## Module API Inventory

This section lists the durable public surface by module. Internal helper
functions that are not exported from a module remain implementation details.

### Attestation

| Export | Purpose |
| --- | --- |
| `AttestationBitfield`, `BitfieldError`, `MAX_COMMITTEE_SIZE` | Tracks committee participation bits and bounds. |
| `SignatureVerifierConfig`, `sign_message`, `verify_single_signature`, `verify_aggregate` | BLS-style signature helper facade. |
| `wall_slots_between`, `compute_inclusion_delay`, `update_delay_rewards`, `delay_reward` | Inclusion-delay and reward calculations. |
| `KeyRegistry`, `KeySnapshot`, `VerificationCache`, `verify_with_rotation` | Validator key history and rotation-aware verification. |
| `derive_nonce` | Deterministic epoch/node nonce derivation. |
| `ConnectivityProtocol` | Proof-of-connectivity challenge/response flow. |
| `Challenge`, `ChallengeResponse`, `ConnectivityError`, `NodeFailureRecord`, `RandomSeed` | Connectivity proof data model. |
| `AttestationData`, `compute_signing_root`, `sign_attestation`, `verify_attestation_signature`, `verify_aggregate_signature`, `verify_attestation`, `verify_attestation_with_committee_view`, `verify_attestation_with_root` | Attestation signing and verification surface. |

### Attestation Core

| Export | Purpose |
| --- | --- |
| `AttestationEntry`, `AggregationState` | Aggregation input and node-local aggregation state. |
| `bls_aggregate`, `aggregate_signatures`, `build_aggregation_state`, `initial_state` | Signature aggregation and initial state helpers. |

### Backup

| Export | Purpose |
| --- | --- |
| `StateChunk`, `StateSnapshot`, `BackupScheduler`, `RestoreResult`, `SnapshotHealth` | Snapshot, chunk, scheduler, restore, and health state. |
| `test_restore` | Restore-test helper for snapshot verification. |
| `SNAPSHOT_INTERVAL_SECONDS`, `MAX_SNAPSHOT_COUNT`, `MAX_CHUNKS_PER_SNAPSHOT` | Snapshot cadence and retention bounds. |

### Consensus

| Export | Purpose |
| --- | --- |
| `IncludedAttestation`, `branch_weighting` | Fork-choice weighting by included attestations. |
| `AccountId`, `FeeSplit`, `FinalizedBlockFees`, `FeeBurnError`, `split_fee`, `finalize_block_fees` | Transaction fee split and finalized block fee-burn accounting. |

### Crypto

| Export | Purpose |
| --- | --- |
| `blake2b_256`, `sha256` | Hash helpers. |
| `G1Point`, `G2Point`, `SharedPublicKey`, `scalar_mul`, `add`, `subgroup_check_g1`, `subgroup_check_g2`, `subgroup_member`, `low_order_point`, `serialize_shared_public_key`, `deserialize_shared_public_key` | Model BLS key/group utilities. |
| `DkgRound1Message`, `DkgError`, `DistributedKeyGeneration` | DKG message and state helpers. |
| `DomainType`, `ForkVersion`, `Domain`, `compute_domain`, domain constants | Domain separation helpers. |
| `Hash256`, `hash_nodes`, `merkleize_8` | Merkle helpers. |

### Database

| Export | Purpose |
| --- | --- |
| `CommitteeCache` | Committee lookup cache. |
| `CacheConfig`, `RedisCacheConfig`, `CacheMetrics`, `TtlCache`, `DEFAULT_TTL_MS`, `DEFAULT_NAMESPACE`, `DEFAULT_OPERATION_BUDGET_MS` | TTL/cache configuration and metrics. |
| `Migration`, `MigrationManager`, `SchemaState`, `MigrationEvent`, `MigrationDirection`, `MigrationMetrics`, `MigrationError` | Schema migration abstraction and bookkeeping. |

### Mempool

| Export | Purpose |
| --- | --- |
| `PriorityMempool`, `Transaction`, `TxHash`, `FeeAmount`, `Gas`, `TransactionError`, `MempoolError`, `MempoolMetrics` | Priority-fee transaction queue. |
| `BlockBuilder`, `BuiltBlock`, `BLOCK_GAS_LIMIT` | Builds blocks from eligible mempool transactions. |
| `InsertOutcome`, `MempoolEvicted`, `EVICTION_BATCH_SIZE`, `MEMPOOL_CAPACITY` | Capacity management and eviction accounting. |
| `ReorgHandler`, `ReorgOutcome` | Reorg recovery helpers. |

### Network

| Export | Purpose |
| --- | --- |
| `serialize_dkg_round1_message`, `deserialize_dkg_round1_message` | DKG round-one message codec. |
| `DeserializationError`, `read_varint_length`, `read_payload` | Length-prefixed peer message parsing. |
| `PeerMessageError`, `deserialize_public_key` | Peer public-key parsing. |
| `SszError`, `ATTESTATION_DATA_SSZ_LEN`, `encode_attestation_data`, `decode_attestation_data` | SSZ-style attestation data codec. |

### Operations And Platform Modules

| Export | Purpose |
| --- | --- |
| `ServiceConfig`, `MonitoringConfig`, `DeploymentConfig`, `SystemConfig`, `ConfigError`, `ConfigChangeEvent`, `ConfigManager`, `validate_reload`, `validate_config` | Runtime config validation and hot reload. |
| `ConfigAuditor`, `ConfigBaseline`, `RuntimeSnapshot`, `AuditReport`, `DriftRecord`, `DriftKind`, `ConfigEntry`, `DeploymentStage`, `ConfigSeverity` | Runtime drift audit. |
| `SloTarget`, `SloWindow`, `SloEvaluation`, `SloSignal`, `evaluate_window`, `publish_slo_evaluation` | SLO and burn-rate evaluation. |
| `ChaosExperiment`, `ChaosHealthSnapshot`, `ServiceSurface`, `FaultKind`, `RolloutPhase`, `next_rollout_phase`, `STAGING_CHAOS_EXPERIMENTS` | Staging chaos blueprint and rollout safety gates. |
| `ReplicationTopology`, `RegionStatus`, `FailoverPlan`, `CanaryAnalysis`, `DisasterRecoveryTestReport`, `ReplicationMetrics`, `DeploymentColor`, `RegionHealth`, `ReplicationError` | Multi-region topology and DR planning. |
| `IncidentSignal`, `IncidentAutomationPlan`, `RunbookStep`, `PagerDutyEvent`, `DeploymentGate`, `IncidentSeverity`, `PagerDutyAction`, `build_incident_plan`, `build_pagerduty_event`, `choose_deployment_gate` | Incident response and PagerDuty payload preparation. |

### Pool, Settlement, Slashing, Reputation, Validator

| Export | Purpose |
| --- | --- |
| `TenantBondManager`, `TenantBondEntry`, `TenantBondKey`, `BondError`, `MIN_BOND_AMOUNT`, `MAX_BOND_AMOUNT`, `MIN_LOCK_DURATION` | Tenant bond lifecycle. |
| `ReentrancyGuard`, `ReentrancyGuardKey` | Storage-backed reentrancy guard. |
| `SettlementLeaf`, `Commitment`, `SettlementDataKey`, `SettlementError`, `PoolManager`, `MIN_REVEAL_DELAY_SECONDS`, `MAX_REVEAL_DELAY_SECONDS`, `MAX_PROOF_DEPTH`, `MAX_BATCH_SIZE`, `hash_leaf`, `verify_proof`, `compute_commitment_hash` | Settlement commit/reveal and merkle proof surface. |
| `SlashingEvidence`, `verify_evidence_expiry`, `verify_surround_vote`, `compute_slashing_penalty`, `compute_inactivity_penalty`, `cap_effective_balance`, `SlashingMempool`, `Evidence`, `OverflowError`, `RelayedSlashingEvidence`, `deserialize_evidence`, `process_relayed_slashing` | Slashing evidence and penalty surface. |
| `SlashingMonitor`, `SlashingExecutor`, `SlashingEventStore`, `SlashingRewardPool`, `ClaimError`, `SlashingReason`, `SlashingEventStatus`, `SlashingEvent`, `NodeState`, `SlashingDataKey`, `SCAN_INTERVAL_SECONDS`, `NODE_BOND_AMOUNT`, `SLASHING_PENALTY` | Core slashing workflow and reward-pool surface. |
| `CircularWindow`, `WINDOW_SIZE`, `ReputationLedger`, `ReputationEvent`, `ReputationSource`, `compute_weighted_average`, `ema_update`, `reputation_weight`, `apply_decay`, `decay_for_epochs`, `update_reputation`, `DecayFactor`, `ReputationScore`, `EmaWeights`, `MAX_REPUTATION` | Reputation scoring and decay. |
| `ActivationQueue`, `ActivationQueueError`, `BalanceTracker`, `BalanceError`, `CommitteeAssignment`, `CommitteeView`, `PendingReorg`, `get_beacon_committee`, `ExitQueue`, `ExitQueueError`, `Validator`, `ValidatorSet`, `ValidatorStatus`, `epoch_transition`, `exit_queue_root`, validator constants | Validator lifecycle and epoch transition helpers. |

### Services

| Export | Purpose |
| --- | --- |
| `Job`, `JobScheduler`, `SchedulerConfig`, `SchedulerMetrics`, `SchedulerError`, `JobState`, `Lease`, job constants and aliases | Lease-based background job scheduling. |
| `TenantRateLimiter`, `RateLimitConfig`, `BucketSnapshot`, `RateLimitMetrics`, `RateLimitDecision`, tenant-rate constants | Per-tenant token-bucket rate limiting. |
| `SecretRotationService`, `Credential`, `CredentialBinding`, `RotationConfig`, `RotationMetrics`, `RotationError`, credential aliases and constants | Credential rotation with grace windows and active-version bounds. |
| `PartitionLag`, `ConsumerGroupState`, `ConsumerLagMonitor`, `ConsumerAutoScaler`, `ConsumerGroupRegistry`, `LagAlertLevel`, `ScalingDecision`, `ConsumerCanaryAnalysis`, `ScalingConfig`, `ConsumerLagMetrics`, `LagEvaluation`, `ConsumerLagError`, Kafka aliases and constants | Consumer-lag monitoring and scaling policy evaluation. |
| `WebhookPayload`, `DeliveryRecord`, `DeliveryEngine`, `DeliveryStatus`, `compute_backoff`, webhook retry constants | Webhook delivery and retry accounting. |

## Operational Guides

### Dependency Vulnerability Scanning

The workflow `.github/workflows/dependency-vulnerability-scan.yml` installs
`cargo-audit` and `cargo-deny`, then runs
`scripts/dependency-vulnerability-scan.sh`. Scan outputs are uploaded from
`target/security/*.json`.

Run locally:

```bash
scripts/dependency-vulnerability-scan.sh
```

Keep advisory ignores documented in `.cargo/audit.toml` and `deny.toml`.
When scanner versions change, migrate config keys instead of disabling scans.

### Runtime Configuration

`config.rs` validates service, monitoring, and deployment configuration.
`config_audit.rs` compares runtime snapshots with approved baselines and
emits drift records. Use these modules for canary and blue-green deployment
gates where service configuration must change monotonically and only through
approved reload paths.

### Configuration Hot Reload

Use `validate_reload(old, new)` to enforce version monotonicity, service-count
bounds, and service-level hot-reload flags. Services that do not support hot
reload should be rolled through deployment orchestration instead of in-place
reload.

### SLO Monitoring And Incident Response

`slo.rs` evaluates rolling windows against availability and p99 latency
targets. `incident_response.rs` converts incident signals into runbook steps,
deployment gates, and PagerDuty Events API payloads. Keep incident routing
keys outside the contract/runtime state and pass them only to event builders.

### Chaos Engineering

`chaos.rs` contains the canonical staging experiment catalog and safety
thresholds. Experiments should run only in staging, stay within
`MAX_EXPERIMENT_DURATION_SECS`, and require the configured number of security
approvals before execution.

### Multi-Region Disaster Recovery

`replication.rs` models deployment color, region health, failover plans,
canary analysis, and DR test reports. Failover should require at least two
healthy regions when `MIN_HEALTHY_REGIONS_FOR_DR` is enforced.

## Testing And CI

Expected local checks:

```bash
git diff --check
cargo build --target wasm32-unknown-unknown --release
cargo test
python scripts/storage-layout-check.py
```

Coverage CI uses `cargo-llvm-cov` and the threshold in
`.github/workflows/rust.yml`.

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
cargo llvm-cov --workspace --all-targets --locked --fail-under-lines 80 --summary-only
```

Security CI runs dependency scanning and uploads JSON reports:

```bash
scripts/dependency-vulnerability-scan.sh
```

Named tests in `Cargo.toml` include:

| Test | Path |
| --- | --- |
| `griefing_resistance_test` | `tests/slashing/griefing_resistance_test.rs` |
| `bls_comprehensive_test` | `tests/bls_comprehensive_test.rs` |
| `dkg_serialization_roundtrip_test` | `tests/crypto/dkg_serialization_roundtrip_test.rs` |
| `proof_of_connectivity_epoch_nonce_test` | `tests/attestation/proof_of_connectivity_epoch_nonce_test.rs` |
| `backup_verification_test` | `tests/backup_verification_test.rs` |
| `webhook_delivery_test` | `tests/webhook_delivery_test.rs` |
| `kafka_consumer_lag_test` | `tests/kafka_consumer_lag_test.rs` |

## Troubleshooting

| Symptom | Likely Cause | Resolution |
| --- | --- | --- |
| `RateLimitExceeded` while creating a circle | Creator called `create_circle` inside the cooldown window. | Wait for `RATE_LIMIT_SECONDS` before retrying. |
| `CircleFull` or `AlreadyMember` on join | Circle capacity reached, or the member storage key already exists. | Query circle state and membership before retrying. |
| Collateral join failure | High-value circle requires a staked `CollateralInfo` record. | Call `stake_collateral` with at least the required amount before joining. |
| Leniency finalization expires a request | Minimum participation or majority was not met. | Reopen a new request if the voting window has passed. |
| Proposal execution rejected | Voting period not ended, quorum missing, or supermajority not met. | Read `Proposal` and `ProposalStats` before executing. |
| Dependency scan fails on config parsing | Scanner schema changed. | Migrate `.cargo/audit.toml` or `deny.toml` to the current scanner schema while preserving policy intent. |
| WASM build target missing | `wasm32-unknown-unknown` not installed. | Run `rustup target add wasm32-unknown-unknown`. |

When adding or changing public exports, update this guide in the same pull
request so `CORE.md` stays the single durable documentation source.
