use alloc::collections::BTreeMap;
use alloc::vec::Vec;

// Mocking required types since the original codebase is absent
pub type ValidatorIndex = u64;

#[derive(Debug, PartialEq)]
pub enum OverflowError {
    RateLimitReached,
    MempoolFull,
}

#[derive(Clone, Debug)]
pub struct Evidence {
    pub validator_index: ValidatorIndex,
    pub data: Vec<u8>,
}

pub const MAX_EVIDENCE_PER_VALIDATOR_PER_EPOCH: u8 = 1;
const MEMPOOL_CAPACITY: usize = 1024;

pub struct SlashingMempool {
    evidence: Vec<Evidence>, 
    rate_limits: BTreeMap<ValidatorIndex, u8>,
}

impl SlashingMempool {
    pub fn new() -> Self {
        Self {
            evidence: Vec::with_capacity(MEMPOOL_CAPACITY),
            rate_limits: BTreeMap::new(),
        }
    }

    pub fn push_evidence(&mut self, evidence: Evidence) -> Result<(), OverflowError> {
        let count = self.rate_limits.entry(evidence.validator_index).or_insert(0);
        
        if *count >= MAX_EVIDENCE_PER_VALIDATOR_PER_EPOCH {
            return Err(OverflowError::RateLimitReached);
        }

        if self.evidence.len() >= MEMPOOL_CAPACITY {
            return Err(OverflowError::MempoolFull);
        }

        *count += 1;
        self.evidence.push(evidence);
        
        Ok(())
    }

    pub fn drain_all(&mut self) -> Vec<Evidence> {
        self.evidence.drain(..).collect()
    }

    pub fn reset_epoch(&mut self) {
        self.rate_limits.clear();
    }
}
