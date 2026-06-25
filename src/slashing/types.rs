use alloc::vec::Vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayedSlashingEvidence {
    pub chain_id: u32,
    pub msg_type: u32,
    pub length: u32,
    pub evidence: Vec<u8>,
}
