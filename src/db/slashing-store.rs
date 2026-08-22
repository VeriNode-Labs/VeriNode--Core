//! Database storage and serialization for generational slashing accumulator state.
//!
//! Provides deterministic binary persistence, snapshots, and retrieval for
//! validator slashing records with rollover generation tags.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use crate::slashing::accumulator::SlashingAccumulator;
use crate::slashing::types::{
    EpochIndex, GenerationalTag, SlashingRecord, ValidatorIndex, WindowOffset,
    DEFAULT_SLASHING_WINDOW,
};

/// Binary serialization format identifier.
pub const SLASHING_STORE_MAGIC: [u8; 8] = *b"VNSLASH1";

/// Current serialization format version.
pub const CURRENT_STORE_VERSION: u32 = 1;

/// Error conditions during slashing store serialization and parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlashingStoreError {
    InvalidMagic,
    UnsupportedVersion(u32),
    PayloadTruncated,
    CorruptedData,
}

/// Persistent snapshot of generational slashing state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingStoreSnapshot {
    pub version: u32,
    pub current_epoch: EpochIndex,
    pub window_generation: u16,
    pub window_size: u16,
    pub records: Vec<SlashingRecord>,
}

/// Store for persisting and querying generational slashing accumulator data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingStore {

    records: BTreeMap<(ValidatorIndex, EpochIndex), SlashingRecord>,
    generational_tags: BTreeMap<ValidatorIndex, GenerationalTag>,
    bit_states: BTreeMap<ValidatorIndex, bool>,
    current_epoch: EpochIndex,
    window_generation: u16,
    window_size: u16,
}

impl SlashingStore {
    /// Create a new empty SlashingStore with default window size.
    pub fn new() -> Self {
        Self::with_window_size(DEFAULT_SLASHING_WINDOW as u16)
    }

    /// Create a new empty SlashingStore with specified window size.
    pub fn with_window_size(window_size: u16) -> Self {
        let size = if window_size == 0 { DEFAULT_SLASHING_WINDOW as u16 } else { window_size };
        Self {
            records: BTreeMap::new(),
            generational_tags: BTreeMap::new(),
            bit_states: BTreeMap::new(),
            current_epoch: 0,
            window_generation: 0,
            window_size: size,
        }
    }

    /// Save full accumulator state into the store.
    pub fn save_accumulator(&mut self, accumulator: &SlashingAccumulator) {
        self.current_epoch = accumulator.current_epoch();
        self.window_generation = accumulator.current_generation();
        self.window_size = accumulator.window_size() as u16;

        self.records.clear();
        self.generational_tags.clear();
        self.bit_states.clear();

        for record in accumulator.iter_records() {
            self.generational_tags.insert(
                record.validator_index,
                GenerationalTag {
                    window_generation: record.window_generation,
                    offset: record.offset,
                },
            );
            self.bit_states.insert(record.validator_index, true);
            self.records
                .insert((record.validator_index, record.epoch), record);
        }
    }

    /// Load accumulator from store state.
    pub fn load_accumulator(&self) -> SlashingAccumulator {
        let mut acc = SlashingAccumulator::with_window_size(self.window_size as usize);
        for record in self.records.values() {
            acc.record_slashing(record.validator_index, record.epoch);
        }
        acc.advance_to_epoch(self.current_epoch);
        acc
    }

    /// Save a single slashing record into the store.
    pub fn save_record(&mut self, record: SlashingRecord) {
        if record.epoch > self.current_epoch {
            self.current_epoch = record.epoch;
            self.window_generation = record.window_generation;
        }
        self.generational_tags.insert(
            record.validator_index,
            GenerationalTag {
                window_generation: record.window_generation,
                offset: record.offset,
            },
        );
        self.bit_states.insert(record.validator_index, true);
        self.records
            .insert((record.validator_index, record.epoch), record);
    }

    /// Retrieve a slashing record by validator index and epoch.
    pub fn get_record(&self, validator_index: ValidatorIndex, epoch: EpochIndex) -> Option<&SlashingRecord> {
        self.records.get(&(validator_index, epoch))
    }

    /// Retrieve the generational tag for a validator.
    pub fn get_generational_tag(&self, validator_index: ValidatorIndex) -> Option<GenerationalTag> {
        self.generational_tags.get(&validator_index).copied()
    }

    /// Check if a validator has bit state marked.
    pub fn is_slashed_bit(&self, validator_index: ValidatorIndex) -> bool {
        self.bit_states.get(&validator_index).copied().unwrap_or(false)
    }

    /// Current epoch recorded in store.
    pub fn current_epoch(&self) -> EpochIndex {
        self.current_epoch
    }

    /// Current window generation recorded in store.
    pub fn window_generation(&self) -> u16 {
        self.window_generation
    }

    /// Number of records in store.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Clear all records and state.
    pub fn clear(&mut self) {
        self.records.clear();
        self.generational_tags.clear();
        self.bit_states.clear();
        self.current_epoch = 0;
        self.window_generation = 0;
    }

    /// Export snapshot of store state.
    pub fn export_snapshot(&self) -> SlashingStoreSnapshot {
        SlashingStoreSnapshot {
            version: CURRENT_STORE_VERSION,
            current_epoch: self.current_epoch,
            window_generation: self.window_generation,
            window_size: self.window_size,
            records: self.records.values().cloned().collect(),
        }
    }

    /// Import snapshot into store.
    pub fn import_snapshot(&mut self, snapshot: SlashingStoreSnapshot) {
        self.clear();
        self.current_epoch = snapshot.current_epoch;
        self.window_generation = snapshot.window_generation;
        self.window_size = snapshot.window_size;
        for record in snapshot.records {
            self.save_record(record);
        }
    }

    /// Serialize store state into deterministic binary bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&SLASHING_STORE_MAGIC);
        bytes.extend_from_slice(&CURRENT_STORE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.current_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.window_generation.to_be_bytes());
        bytes.extend_from_slice(&self.window_size.to_be_bytes());

        let record_count = self.records.len() as u32;
        bytes.extend_from_slice(&record_count.to_be_bytes());

        for record in self.records.values() {
            bytes.extend_from_slice(&record.validator_index.to_be_bytes());
            bytes.extend_from_slice(&record.epoch.to_be_bytes());
            bytes.extend_from_slice(&record.window_generation.to_be_bytes());
            bytes.extend_from_slice(&record.offset.0.to_be_bytes());
        }

        bytes
    }

    /// Deserialize store from binary bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlashingStoreError> {
        if bytes.len() < 28 {
            return Err(SlashingStoreError::PayloadTruncated);
        }

        if &bytes[0..8] != &SLASHING_STORE_MAGIC {
            return Err(SlashingStoreError::InvalidMagic);
        }

        let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != CURRENT_STORE_VERSION {
            return Err(SlashingStoreError::UnsupportedVersion(version));
        }

        let current_epoch = u64::from_be_bytes([
            bytes[12], bytes[13], bytes[14], bytes[15],
            bytes[16], bytes[17], bytes[18], bytes[19],
        ]);
        let window_generation = u16::from_be_bytes([bytes[20], bytes[21]]);
        let window_size = u16::from_be_bytes([bytes[22], bytes[23]]);
        let record_count = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as usize;

        let record_stride = 20; // 8 + 8 + 2 + 2
        let expected_len = 28 + record_count * record_stride;
        if bytes.len() < expected_len {
            return Err(SlashingStoreError::PayloadTruncated);
        }

        let mut store = Self::with_window_size(window_size);
        store.current_epoch = current_epoch;
        store.window_generation = window_generation;

        let mut offset = 28;
        for _ in 0..record_count {
            let val_idx = u64::from_be_bytes([
                bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
                bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
            ]);
            let epoch = u64::from_be_bytes([
                bytes[offset + 8], bytes[offset + 9], bytes[offset + 10], bytes[offset + 11],
                bytes[offset + 12], bytes[offset + 13], bytes[offset + 14], bytes[offset + 15],
            ]);
            let gen = u16::from_be_bytes([bytes[offset + 16], bytes[offset + 17]]);
            let win_offset = u16::from_be_bytes([bytes[offset + 18], bytes[offset + 19]]);

            let record = SlashingRecord {
                validator_index: val_idx,
                epoch,
                window_generation: gen,
                offset: WindowOffset(win_offset),
            };
            store.save_record(record);
            offset += record_stride;
        }

        Ok(store)
    }
}

impl Default for SlashingStore {
    fn default() -> Self {
        Self::new()
    }
}
