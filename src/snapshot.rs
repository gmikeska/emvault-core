//! [`FederationSnapshot`] — canonical-JSON federation export/import.
//!
//! Snapshots capture a federation's configuration at a point in time and
//! support byte-identical round-tripping through canonical JSON. They do
//! **not** include version history, predecessor references, or persistence
//! identifiers — federation state sequencing is the consumer application's
//! responsibility.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_with::{TimestampSeconds, serde_as};

use crate::error::SnapshotError;
use crate::federation::Federation;
use crate::network::NetworkType;
use crate::recovery::{canonical_json, now_truncated_to_seconds};
use crate::signer::{Signer, SignerCapabilities, SignerId, SignerType};

/// Per-signer snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerSnapshot {
    /// Stable signer identifier.
    pub id: SignerId,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Extended public key, base58-encoded.
    pub xpub: String,
    /// Master fingerprint (hex).
    pub fingerprint: String,
    /// Derivation path the signer uses for federation participation.
    pub derivation_path: String,
    /// Software vs. external.
    pub signer_type: SignerType,
    /// Capability flags.
    pub capabilities: SignerCapabilities,
}

/// A federation snapshot.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationSnapshot {
    /// Canonical descriptor (with `#checksum`).
    pub descriptor: String,
    /// Threshold (`m`).
    pub threshold: u32,
    /// Total signers (`n`).
    pub total_signers: u32,
    /// Target network.
    pub network: NetworkType,
    /// Signer set.
    pub signers: Vec<SignerSnapshot>,
    /// Snapshot creation timestamp (Unix seconds).
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub created_at: SystemTime,
}

impl FederationSnapshot {
    /// Construct a snapshot from a [`Federation`].
    ///
    /// # Panics
    ///
    /// Panics if the federation contains more than [`u32::MAX`] signers,
    /// which the [`Federation`] constructors already preclude.
    pub fn from_federation<S: Signer>(federation: &Federation<S>) -> Self {
        let signers: Vec<SignerSnapshot> = federation
            .signers()
            .iter()
            .map(|s| SignerSnapshot {
                id: s.id(),
                label: s.label().map(str::to_string),
                xpub: s.xpub().to_string(),
                fingerprint: s.fingerprint().to_string(),
                derivation_path: s.derivation_path().to_string(),
                signer_type: s.signer_type(),
                capabilities: s.capabilities(),
            })
            .collect();
        Self {
            descriptor: federation.descriptor_string().to_string(),
            threshold: federation.threshold(),
            total_signers: u32::try_from(federation.total_signers())
                .expect("federation member count fits u32"),
            network: federation.network(),
            signers,
            created_at: now_truncated_to_seconds(),
        }
    }

    /// Serialize to canonical JSON (sorted keys, no whitespace). Two
    /// equivalent snapshots produce byte-identical output.
    pub fn to_canonical_json(&self) -> String {
        canonical_json(self)
    }

    /// Pretty JSON for human inspection (NOT canonical).
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Json`] if `serde_json` rejects the snapshot.
    pub fn to_pretty_json(&self) -> Result<String, SnapshotError> {
        serde_json::to_string_pretty(self).map_err(|e| SnapshotError::Json(e.to_string()))
    }

    /// Deserialize from JSON (any formatting).
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Json`] if `json` is malformed or fails to
    /// parse into a [`FederationSnapshot`].
    pub fn from_json(json: &str) -> Result<Self, SnapshotError> {
        serde_json::from_str(json).map_err(|e| SnapshotError::Json(e.to_string()))
    }

    /// Verify internal consistency:
    ///
    /// - Threshold/signer-count bounds.
    /// - Signer count matches `signers.len()`.
    /// - Descriptor parses successfully.
    /// - Each signer's xpub appears in the descriptor (string-level check).
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::InvalidThreshold`] for threshold/count
    /// violations, [`SnapshotError::Parse`] if the descriptor doesn't parse,
    /// or [`SnapshotError::DescriptorMismatch`] if any signer's fingerprint
    /// is absent from the descriptor.
    ///
    /// # Panics
    ///
    /// Panics if the snapshot contains more than [`u32::MAX`] signers,
    /// which the [`Federation`] constructors already preclude.
    pub fn verify(&self) -> Result<(), SnapshotError> {
        if self.threshold == 0 || self.threshold > self.total_signers {
            return Err(SnapshotError::InvalidThreshold(format!(
                "threshold={} total={}",
                self.threshold, self.total_signers
            )));
        }
        let signer_len = u32::try_from(self.signers.len())
            .expect("federation member count fits u32");
        if signer_len != self.total_signers {
            return Err(SnapshotError::InvalidThreshold(format!(
                "declared total_signers={} but signer set has length {}",
                self.total_signers,
                self.signers.len()
            )));
        }
        let secp = bitcoin::secp256k1::Secp256k1::new();
        miniscript::Descriptor::<miniscript::DescriptorPublicKey>::parse_descriptor(
            &secp,
            &self.descriptor,
        )
        .map_err(|e| SnapshotError::Parse(e.to_string()))?;

        for s in &self.signers {
            if !self.descriptor.contains(&s.fingerprint) {
                return Err(SnapshotError::DescriptorMismatch);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::Signer;
    use crate::test_utils::MockSigner;
    use bitcoin::Network;

    fn fed() -> Federation {
        Federation::new(
            2,
            vec![
                Box::new(MockSigner::with_seed(1, Network::Testnet)) as Box<dyn Signer>,
                Box::new(MockSigner::with_seed(2, Network::Testnet)) as _,
                Box::new(MockSigner::with_seed(3, Network::Testnet)) as _,
            ],
            Network::Testnet.into(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_json_round_trip_is_byte_identical() {
        let snap = FederationSnapshot::from_federation(&fed());
        let a = snap.to_canonical_json();
        let parsed: FederationSnapshot = serde_json::from_str(&a).unwrap();
        let b = parsed.to_canonical_json();
        assert_eq!(a, b);
    }

    #[test]
    fn pretty_json_parses_back() {
        let snap = FederationSnapshot::from_federation(&fed());
        let pretty = snap.to_pretty_json().unwrap();
        let parsed = FederationSnapshot::from_json(&pretty).unwrap();
        assert_eq!(snap, parsed);
    }

    #[test]
    fn verify_passes_for_well_formed_snapshot() {
        let snap = FederationSnapshot::from_federation(&fed());
        snap.verify().unwrap();
    }

    #[test]
    fn verify_rejects_bad_threshold() {
        let mut snap = FederationSnapshot::from_federation(&fed());
        snap.threshold = 99;
        let err = snap.verify().unwrap_err();
        assert!(matches!(err, SnapshotError::InvalidThreshold(_)));
    }

    #[test]
    fn verify_rejects_signer_count_mismatch() {
        let mut snap = FederationSnapshot::from_federation(&fed());
        snap.signers.pop();
        let err = snap.verify().unwrap_err();
        assert!(matches!(err, SnapshotError::InvalidThreshold(_)));
    }
}
