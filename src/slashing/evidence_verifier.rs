// Evidence verifier utilities for slashing expiry checks

pub type Slot = u64;
pub type Epoch = u64;

pub const SLOTS_PER_EPOCH: Slot = 32;
pub const MAX_SLASHING_WINDOW: Slot = 8192; // in slots (~36 hours)

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingEvidence {
    /// For single-slot infractions (double-vote) this contains the offending slot.
    pub slot: Option<Slot>,
    /// For surround-vote evidence include source and target epochs.
    pub source_epoch: Option<Epoch>,
    pub target_epoch: Option<Epoch>,
}

impl SlashingEvidence {
    pub fn new(slot: Option<Slot>, source_epoch: Option<Epoch>, target_epoch: Option<Epoch>) -> Self {
        Self { slot, source_epoch, target_epoch }
    }
}

/// Returns inclusive slot range (start, end) that covers the infraction represented by `ev`.
/// For epoch-based timestamps, we use the epoch's slot range: [epoch * SLOTS_PER_EPOCH, epoch * SLOTS_PER_EPOCH + (SLOTS_PER_EPOCH - 1)].
/// If multiple timestamps present, the returned range spans the earliest start to the latest end.
pub fn evidence_infraction_slot_range(ev: &SlashingEvidence) -> (Slot, Slot) {
    // Start with large bounds depending on what is present
    let mut starts: Vec<Slot> = Vec::new();
    let mut ends: Vec<Slot> = Vec::new();

    if let Some(s) = ev.slot {
        starts.push(s);
        ends.push(s);
    }
    if let Some(se) = ev.source_epoch {
        let start = se.saturating_mul(SLOTS_PER_EPOCH);
        let end = start + (SLOTS_PER_EPOCH - 1);
        starts.push(start);
        ends.push(end);
    }
    if let Some(te) = ev.target_epoch {
        let start = te.saturating_mul(SLOTS_PER_EPOCH);
        let end = start + (SLOTS_PER_EPOCH - 1);
        starts.push(start);
        ends.push(end);
    }

    // If nothing present, treat as slot 0
    if starts.is_empty() {
        return (0, 0);
    }

    let start = *starts.iter().min().unwrap();
    let end = *ends.iter().max().unwrap();
    (start, end)
}

/// Verify whether the evidence is still within the slashing window relative to `current_slot`.
/// Returns true if the evidence is considered expired (outside the max slashing window).
/// The rule: evidence is valid if earliest_infraction_start + MAX_SLASHING_WINDOW >= current_slot.
/// Expired when earliest_start + MAX_SLASHING_WINDOW < current_slot.
pub fn verify_evidence_expiry(ev: &SlashingEvidence, current_slot: Slot) -> bool {
    let (earliest_start, _latest_end) = evidence_infraction_slot_range(ev);
    // Accept evidence at the boundary (inclusive). Expire if strictly past the window.
    let valid_until = earliest_start.saturating_add(MAX_SLASHING_WINDOW);
    // expired = current_slot > valid_until
    current_slot > valid_until
}

/// Verify surround vote semantics: evidence must include both source and target epochs and
/// source_epoch < target_epoch. This function returns true if the surround evidence is valid
/// and within the slashing window (not expired).
pub fn verify_surround_vote(ev: &SlashingEvidence, current_slot: Slot) -> Result<bool, &'static str> {
    match (ev.source_epoch, ev.target_epoch) {
        (Some(s), Some(t)) => {
            if s >= t { return Err("invalid_surround_vote_epochs"); }
            Ok(!verify_evidence_expiry(ev, current_slot))
        }
        _ => Err("missing_surround_vote_epochs"),
    }
}
