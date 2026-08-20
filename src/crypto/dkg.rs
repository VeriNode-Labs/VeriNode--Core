//! Distributed Key Generation (DKG) protocol implementation.
//!
//! This module implements the DKG protocol for generating shared public keys
//! among validators in a distributed manner. The protocol ensures that no
//! single party knows the complete private key, while allowing the group to
//! jointly sign messages.

use crate::crypto::bls_keys::{G1Point, SharedPublicKey};

/// DKG Round 1 message containing the dealer's public key commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgRound1Message {
    /// The dealer's validator index
    pub dealer_index: u32,
    /// The shared public key (coefficient a0 and commitment a1)
    pub shared_public_key: SharedPublicKey,
}

impl DkgRound1Message {
    /// Create a new DKG Round 1 message.
    pub fn new(dealer_index: u32, shared_public_key: SharedPublicKey) -> Self {
        DkgRound1Message {
            dealer_index,
            shared_public_key,
        }
    }

    /// Serialize the DKG Round 1 message to bytes.
    /// Format: 4 bytes (dealer_index) + 96 bytes (shared_public_key)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(100);
        bytes.extend_from_slice(&self.dealer_index.to_be_bytes());
        bytes.extend_from_slice(&self.shared_public_key.to_bytes());
        bytes
    }

    /// Deserialize a DKG Round 1 message from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DkgError> {
        if bytes.len() < 100 {
            return Err(DkgError::InvalidMessageLength);
        }

        let mut dealer_index_bytes = [0u8; 4];
        dealer_index_bytes.copy_from_slice(&bytes[0..4]);
        let dealer_index = u32::from_be_bytes(dealer_index_bytes);

        let mut key_bytes = [0u8; 96];
        key_bytes.copy_from_slice(&bytes[4..100]);
        let shared_public_key = SharedPublicKey::from_bytes(&key_bytes);

        Ok(DkgRound1Message {
            dealer_index,
            shared_public_key,
        })
    }

    /// Validate the shared public key in this message.
    pub fn validate(&self) -> Result<(), DkgError> {
        if !self.shared_public_key.is_valid_on_curve() {
            return Err(DkgError::InvalidCurvePoint);
        }
        Ok(())
    }
}

/// Errors that can occur during DKG operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DkgError {
    /// The message length is invalid.
    InvalidMessageLength,
    /// The shared public key does not lie on the curve.
    InvalidCurvePoint,
    /// The deserialized point failed validation.
    PointValidationFailed,
}

/// Represents the state of a distributed key generation session.
pub struct DistributedKeyGeneration {
    /// This validator's index
    pub validator_index: u32,
    /// Total number of validators participating
    pub num_validators: u32,
    /// Threshold for signature reconstruction (t-of-n)
    pub threshold: u32,
    /// Received Round 1 messages from other validators
    pub round1_messages: Vec<DkgRound1Message>,
}

impl DistributedKeyGeneration {
    /// Create a new DKG session.
    pub fn new(validator_index: u32, num_validators: u32, threshold: u32) -> Self {
        DistributedKeyGeneration {
            validator_index,
            num_validators,
            threshold,
            round1_messages: Vec::new(),
        }
    }

    /// Process a received Round 1 message.
    pub fn handle_round1_message(&mut self, message: DkgRound1Message) -> Result<(), DkgError> {
        // Validate the message
        message.validate()?;

        // Store the message
        self.round1_messages.push(message);

        Ok(())
    }

    /// Generate a Round 1 message for this validator.
    /// In a real implementation, this would generate secret polynomial coefficients
    /// and compute the corresponding public commitments.
    pub fn generate_round1_message(&self, a0: G1Point, a1: G1Point) -> DkgRound1Message {
        let shared_public_key = SharedPublicKey::new(a0, a1);
        DkgRound1Message::new(self.validator_index, shared_public_key)
    }

    /// Check if we have received messages from all other validators.
    pub fn is_round1_complete(&self) -> bool {
        self.round1_messages.len() >= (self.num_validators - 1) as usize
    }

    /// Aggregate the shared public keys from all validators.
    /// In a real implementation, this would combine the public key shares
    /// to produce the group's aggregate public key.
    pub fn aggregate_public_keys(&self) -> Option<SharedPublicKey> {
        if !self.is_round1_complete() {
            return None;
        }

        // For the model, we just return the first key as a placeholder
        // Real implementation would properly aggregate all public keys
        self.round1_messages
            .first()
            .map(|msg| msg.shared_public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkg_round1_message_serialization() {
        let a0 = G1Point::new(12345, true);
        let a1 = G1Point::new(67890, false);
        let shared_key = SharedPublicKey::new(a0, a1);
        let message = DkgRound1Message::new(42, shared_key);

        let bytes = message.to_bytes();
        let deserialized = DkgRound1Message::from_bytes(&bytes).unwrap();

        assert_eq!(message, deserialized);
    }

    #[test]
    fn test_dkg_session() {
        let mut dkg = DistributedKeyGeneration::new(0, 4, 3);

        let a0 = G1Point::new(100, true);
        let a1 = G1Point::new(200, false);
        let msg1 = DkgRound1Message::new(1, SharedPublicKey::new(a0, a1));

        assert!(dkg.handle_round1_message(msg1).is_ok());
        assert_eq!(dkg.round1_messages.len(), 1);
    }
}
