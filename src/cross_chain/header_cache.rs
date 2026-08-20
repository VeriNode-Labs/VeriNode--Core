//! Bounded cache of recently observed chain headers (issue #136).
//!
//! A light client retains the [`HEADER_CACHE_CAPACITY`] most recent headers per
//! chain so it can (a) verify committee attestations against the header a
//! signature commits to and (b) measure finality lag from a header's block
//! timestamp. The cache is a plain `Vec` ordered by insertion (ascending block
//! height); when it overflows, the oldest header is evicted from the front.

extern crate alloc;

use alloc::vec::Vec;

use super::types::HEADER_CACHE_CAPACITY;

/// A recently observed chain header together with the committee weight that has
/// attested to it and the local time at which it was first seen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecentHeader {
    /// Block height.
    pub height: u64,
    /// Block production timestamp on the source chain, in milliseconds.
    pub timestamp_ms: u64,
    /// Total committee weight eligible to attest to this header.
    pub committee_weight: u64,
    /// Committee weight that has attested to this header so far.
    pub attesting_weight: u64,
    /// Local time at which the light client first observed this header, in
    /// milliseconds (i.e. block timestamp plus relay latency).
    pub observed_at_ms: u64,
    /// Whether this header has crossed the finality threshold locally.
    pub finalized: bool,
}

impl RecentHeader {
    /// Creates a new, not-yet-finalized header observation.
    pub fn new(
        height: u64,
        timestamp_ms: u64,
        committee_weight: u64,
        attesting_weight: u64,
        observed_at_ms: u64,
    ) -> Self {
        Self {
            height,
            timestamp_ms,
            committee_weight,
            attesting_weight,
            observed_at_ms,
            finalized: false,
        }
    }
}

/// Bounded, insertion-ordered cache of recent headers for one chain.
#[derive(Clone, Debug, Default)]
pub struct HeaderCache {
    headers: Vec<RecentHeader>,
}

impl HeaderCache {
    /// Creates an empty header cache.
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
        }
    }

    /// Inserts or updates a header.
    ///
    /// If a header at the same height already exists it is replaced in place
    /// (attestations accumulate over time); otherwise the header is appended.
    /// When the cache exceeds [`HEADER_CACHE_CAPACITY`] the oldest header is
    /// evicted from the front so the working set stays bounded.
    pub fn insert(&mut self, header: RecentHeader) {
        if let Some(existing) = self.headers.iter_mut().find(|h| h.height == header.height) {
            *existing = header;
            return;
        }
        self.headers.push(header);
        if self.headers.len() > HEADER_CACHE_CAPACITY {
            self.headers.remove(0);
        }
    }

    /// Marks the header at `height` finalized. Returns `true` if it was found.
    pub fn mark_finalized(&mut self, height: u64) -> bool {
        match self.headers.iter_mut().find(|h| h.height == height) {
            Some(h) => {
                h.finalized = true;
                true
            }
            None => false,
        }
    }

    /// Returns the most recently inserted (highest-height) header, if any.
    pub fn latest(&self) -> Option<&RecentHeader> {
        self.headers.last()
    }

    /// Returns the highest-height header that has been finalized, if any.
    pub fn latest_finalized(&self) -> Option<&RecentHeader> {
        self.headers.iter().rev().find(|h| h.finalized)
    }

    /// Returns the header at the given height, if cached.
    pub fn get(&self, height: u64) -> Option<&RecentHeader> {
        self.headers.iter().find(|h| h.height == height)
    }

    /// Number of headers currently cached.
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Returns `true` when no headers are cached.
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Maximum number of headers the cache retains.
    pub fn capacity(&self) -> usize {
        HEADER_CACHE_CAPACITY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(height: u64) -> RecentHeader {
        RecentHeader::new(height, height * 1_000, 100, 70, height * 1_000 + 50)
    }

    #[test]
    fn insert_appends_and_tracks_latest() {
        let mut cache = HeaderCache::new();
        assert!(cache.is_empty());
        cache.insert(header(1));
        cache.insert(header(2));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.latest().unwrap().height, 2);
    }

    #[test]
    fn insert_at_existing_height_replaces_in_place() {
        let mut cache = HeaderCache::new();
        cache.insert(header(1));
        let mut updated = header(1);
        updated.attesting_weight = 99;
        cache.insert(updated);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(1).unwrap().attesting_weight, 99);
    }

    #[test]
    fn cache_evicts_oldest_beyond_capacity() {
        let mut cache = HeaderCache::new();
        for h in 0..(HEADER_CACHE_CAPACITY as u64 + 10) {
            cache.insert(header(h));
        }
        assert_eq!(cache.len(), HEADER_CACHE_CAPACITY);
        // The ten oldest heights (0..10) were evicted.
        assert!(cache.get(9).is_none());
        assert!(cache.get(10).is_some());
        assert_eq!(
            cache.latest().unwrap().height,
            HEADER_CACHE_CAPACITY as u64 + 9
        );
    }

    #[test]
    fn mark_finalized_sets_flag_and_tracks_latest_finalized() {
        let mut cache = HeaderCache::new();
        cache.insert(header(1));
        cache.insert(header(2));
        cache.insert(header(3));
        assert!(cache.mark_finalized(2));
        assert!(!cache.mark_finalized(99));
        assert_eq!(cache.latest_finalized().unwrap().height, 2);
        // A later finalization wins.
        assert!(cache.mark_finalized(3));
        assert_eq!(cache.latest_finalized().unwrap().height, 3);
    }

    #[test]
    fn latest_finalized_is_none_until_something_finalizes() {
        let mut cache = HeaderCache::new();
        cache.insert(header(1));
        assert!(cache.latest_finalized().is_none());
    }

    #[test]
    fn capacity_reports_the_configured_bound() {
        assert_eq!(HeaderCache::new().capacity(), HEADER_CACHE_CAPACITY);
    }
}
