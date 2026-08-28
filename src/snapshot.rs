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

    /// Verify internal **consistency** (a corruption check, not authentication —
    /// see the note below):
    ///
    /// - Threshold/signer-count bounds.
    /// - Signer count matches `signers.len()`.
    /// - Descriptor parses and is a supported multisig shape
    ///   (`wsh(sortedmulti)` or `tr(NUMS, multi_a)`).
    /// - The descriptor's threshold equals `self.threshold`.
    /// - The descriptor binds exactly this signer set: it holds `total_signers`
    ///   cosigner keys and **each signer's full xpub** appears among them.
    ///
    /// The last two close the old gap where verification only tested that each
    /// 8-hex **fingerprint** was a *substring* of the descriptor — which any
    /// origin `[fp/path]` satisfies even if the key after it differs, and which
    /// never cross-checked the threshold. Binding on the full base58 xpub and
    /// the parsed threshold rejects a swapped key or an altered `m`.
    ///
    /// ## This is not authentication
    ///
    /// A passing `verify()` means the snapshot is internally *consistent*, not
    /// that it is *authentic*. `verify()` uses no secret, so an attacker who
    /// rewrites both the descriptor and the signer set consistently still
    /// passes. At-rest config authenticity rests on trusted storage plus the
    /// on-device first-address confirmation — or, for cryptographic
    /// tamper-detection, [`FederationSnapshot::authenticate`] /
    /// [`FederationSnapshot::verify_authentic`] with an operator-held key.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::InvalidThreshold`] for threshold/count
    /// violations, [`SnapshotError::Parse`] if the descriptor doesn't parse,
    /// or [`SnapshotError::DescriptorMismatch`] if the descriptor is an
    /// unsupported shape, its threshold disagrees, or any signer's xpub is
    /// absent from it.
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
        let signer_len =
            u32::try_from(self.signers.len()).expect("federation member count fits u32");
        if signer_len != self.total_signers {
            return Err(SnapshotError::InvalidThreshold(format!(
                "declared total_signers={} but signer set has length {}",
                self.total_signers,
                self.signers.len()
            )));
        }
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (descriptor, _) =
            miniscript::Descriptor::<miniscript::DescriptorPublicKey>::parse_descriptor(
                &secp,
                &self.descriptor,
            )
            .map_err(|e| SnapshotError::Parse(e.to_string()))?;

        // Normalize to the shape-aware (threshold, key-set) identity. An
        // unsupported shape is a mismatch, not a silent pass.
        let policy = crate::verify::multisig_policy(&descriptor)
            .map_err(|_| SnapshotError::DescriptorMismatch)?;

        // Threshold must agree with the declared threshold.
        if policy.threshold != self.threshold as usize {
            return Err(SnapshotError::DescriptorMismatch);
        }
        // The descriptor must carry exactly the declared number of cosigner keys.
        if policy.keys.len() != self.signers.len() {
            return Err(SnapshotError::DescriptorMismatch);
        }
        // Every signer must be bound in the descriptor by BOTH its origin
        // fingerprint AND its key material, co-located in the same descriptor
        // key — far stronger than the previous "fingerprint appears *somewhere*"
        // substring test, which any origin satisfies regardless of the key.
        //
        // The key material is matched in whichever form the builder emitted:
        // the full xpub (Ranged mode) or the compressed public key the xpub
        // derives to (Fixed mode). A snapshot that reuses a real fingerprint
        // over a swapped key no longer verifies.
        for s in &self.signers {
            let derived_pk_hex = s
                .xpub
                .parse::<bitcoin::bip32::Xpub>()
                .ok()
                .map(|xp| hex::encode(xp.public_key.serialize()));
            let origin = format!("[{}", s.fingerprint);
            let bound = policy.keys.iter().any(|k| {
                let origin_ok = k.contains(&origin);
                let key_ok =
                    k.contains(&s.xpub) || derived_pk_hex.as_deref().is_some_and(|h| k.contains(h));
                origin_ok && key_ok
            });
            if !bound {
                return Err(SnapshotError::DescriptorMismatch);
            }
        }
        Ok(())
    }

    /// Produce a keyed authentication tag (HMAC-SHA256, hex) over this
    /// snapshot's canonical JSON using an operator-held `mac_key`.
    ///
    /// Genuine tamper-evidence for at-rest config: unlike [`Self::verify`]
    /// (which uses no secret and only detects corruption), a tag produced here
    /// cannot be forged without `mac_key`. Store the key separately from the
    /// snapshot it authenticates.
    #[must_use]
    pub fn authenticate(&self, mac_key: &[u8]) -> String {
        let canonical = crate::recovery::canonical_json(self);
        hex::encode(crate::recovery::hmac_sha256(mac_key, canonical.as_bytes()))
    }

    /// Verify a keyed authentication tag produced by [`Self::authenticate`] with
    /// the same `mac_key`. Constant-time comparison.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::AuthenticationFailed`] if the recomputed tag
    /// does not match `mac_hex`.
    pub fn verify_authentic(&self, mac_key: &[u8], mac_hex: &str) -> Result<(), SnapshotError> {
        let expected = self.authenticate(mac_key);
        if crate::recovery::constant_time_eq(expected.as_bytes(), mac_hex.as_bytes()) {
            Ok(())
        } else {
            Err(SnapshotError::AuthenticationFailed)
        }
    }
}

// ---------------------------------------------------------------------------
// FederatedWalletSnapshot
// ---------------------------------------------------------------------------

/// A snapshot of an entire [`FederatedWallet`](crate::federated_wallet::FederatedWallet),
/// capturing every historical federation version in order.
///
/// Wallet instances are runtime handles and are **not** serialized — the
/// application reconstructs them on startup from the snapshot's federation
/// list.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedWalletSnapshot {
    /// All federation snapshots, ordered oldest-first.
    pub federations: Vec<FederationSnapshot>,
    /// The network all federations operate on.
    pub network: NetworkType,
    /// Snapshot creation timestamp (Unix seconds).
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub created_at: SystemTime,
}

impl FederatedWalletSnapshot {
    /// Construct a snapshot from any [`FederatedWallet`](crate::federated_wallet::FederatedWallet)
    /// implementation.
    pub fn from_wallet<S: Signer, W>(
        wallet: &impl crate::federated_wallet::FederatedWallet<S, W>,
    ) -> Self {
        let federations = wallet
            .federation_wallets()
            .iter()
            .map(|fw| FederationSnapshot::from_federation(&fw.federation))
            .collect();
        Self {
            federations,
            network: wallet.network(),
            created_at: now_truncated_to_seconds(),
        }
    }

    /// Serialize to canonical JSON (sorted keys, no whitespace).
    pub fn to_canonical_json(&self) -> String {
        canonical_json(self)
    }

    /// Pretty JSON for human inspection (NOT canonical).
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Json`] if serialization fails.
    pub fn to_pretty_json(&self) -> Result<String, SnapshotError> {
        serde_json::to_string_pretty(self).map_err(|e| SnapshotError::Json(e.to_string()))
    }

    /// Deserialize from JSON (any formatting).
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Json`] if `json` is malformed.
    pub fn from_json(json: &str) -> Result<Self, SnapshotError> {
        serde_json::from_str(json).map_err(|e| SnapshotError::Json(e.to_string()))
    }

    /// Verify internal consistency:
    ///
    /// - At least one federation in the stack.
    /// - Each federation snapshot passes its own [`FederationSnapshot::verify`].
    /// - All federations share the same network as the top-level `network` field.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError`] on the first failed check.
    pub fn verify(&self) -> Result<(), SnapshotError> {
        if self.federations.is_empty() {
            return Err(SnapshotError::InvalidThreshold(
                "FederatedWalletSnapshot must contain at least one federation".into(),
            ));
        }
        for (i, fs) in self.federations.iter().enumerate() {
            fs.verify().map_err(|e| {
                SnapshotError::Json(format!("federation[{i}] verification failed: {e}"))
            })?;
            if fs.network != self.network {
                return Err(SnapshotError::Json(format!(
                    "federation[{i}] network {:?} does not match wallet network {:?}",
                    fs.network, self.network
                )));
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

    #[test]
    fn verify_rejects_swapped_signer_key() {
        // F2b: a signer whose fingerprint stays but whose xpub is swapped for a
        // key NOT in the descriptor must be rejected (the old fingerprint-
        // substring check let this through).
        let mut snap = FederationSnapshot::from_federation(&fed());
        let intruder = MockSigner::with_seed(99, Network::Testnet);
        snap.signers[0].xpub = intruder.xpub().to_string();
        // fingerprint left untouched → still a substring of the descriptor.
        let err = snap.verify().unwrap_err();
        assert!(
            matches!(err, SnapshotError::DescriptorMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_descriptor_threshold_disagreement() {
        // A descriptor whose embedded threshold differs from the declared one
        // is a mismatch, even with the right keys.
        let snap_2of3 = FederationSnapshot::from_federation(&fed());
        let mut snap = FederationSnapshot::from_federation(
            &Federation::new(
                1,
                vec![
                    Box::new(MockSigner::with_seed(1, Network::Testnet)) as Box<dyn Signer>,
                    Box::new(MockSigner::with_seed(2, Network::Testnet)) as _,
                    Box::new(MockSigner::with_seed(3, Network::Testnet)) as _,
                ],
                Network::Testnet.into(),
            )
            .unwrap(),
        );
        // Claim threshold 2 while the descriptor encodes sortedmulti(1,...).
        snap.threshold = 2;
        assert_ne!(snap.descriptor, snap_2of3.descriptor);
        let err = snap.verify().unwrap_err();
        assert!(
            matches!(err, SnapshotError::DescriptorMismatch),
            "got {err:?}"
        );
    }

    #[test]
    fn snapshot_keyed_authentication_detects_tamper() {
        let key = b"operator-held-snapshot-mac-key!!";
        let snap = FederationSnapshot::from_federation(&fed());
        let mac = snap.authenticate(key);
        snap.verify_authentic(key, &mac).unwrap();

        // A consistent swap (still passes verify) fails authentication.
        let mut forged = snap.clone();
        forged.threshold = 1;
        let err = forged.verify_authentic(key, &mac).unwrap_err();
        assert!(matches!(err, SnapshotError::AuthenticationFailed));

        // Wrong key fails.
        let err = snap
            .verify_authentic(b"the-wrong-snapshot-mac-key-32by!", &mac)
            .unwrap_err();
        assert!(matches!(err, SnapshotError::AuthenticationFailed));
    }

    // -----------------------------------------------------------------------
    // FederatedWalletSnapshot tests
    // -----------------------------------------------------------------------

    use crate::federated_wallet::BtcFederatedWallet;

    fn make_fed(seeds: &[u64]) -> Federation<MockSigner> {
        let signers: Vec<MockSigner> = seeds
            .iter()
            .map(|&s| MockSigner::with_seed(s, Network::Regtest))
            .collect();
        Federation::new(2, signers, Network::Regtest.into()).unwrap()
    }

    fn make_wallet(federation: &Federation<MockSigner>) -> bdk_wallet::Wallet {
        let desc = federation.descriptor().to_string();
        bdk_wallet::Wallet::create_single(desc)
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .expect("valid wallet")
    }

    #[test]
    fn federated_wallet_snapshot_round_trip() {
        let fed1 = make_fed(&[1, 2, 3]);
        let w1 = make_wallet(&fed1);
        let fw = BtcFederatedWallet::new(fed1, w1).unwrap();

        let fed2 = make_fed(&[1, 3, 4]);
        let w2 = make_wallet(&fed2);
        let fw = fw.with_federation(fed2, w2).unwrap();

        let snap = FederatedWalletSnapshot::from_wallet(&fw);
        assert_eq!(snap.federations.len(), 2);
        assert_eq!(snap.network, NetworkType::Bitcoin(Network::Regtest));

        let json = snap.to_canonical_json();
        let parsed = FederatedWalletSnapshot::from_json(&json).unwrap();
        let json2 = parsed.to_canonical_json();
        assert_eq!(json, json2);
    }

    #[test]
    fn federated_wallet_snapshot_pretty_json_parses_back() {
        let fed1 = make_fed(&[1, 2, 3]);
        let w1 = make_wallet(&fed1);
        let fw = BtcFederatedWallet::new(fed1, w1).unwrap();

        let snap = FederatedWalletSnapshot::from_wallet(&fw);
        let pretty = snap.to_pretty_json().unwrap();
        let parsed = FederatedWalletSnapshot::from_json(&pretty).unwrap();
        assert_eq!(snap, parsed);
    }

    #[test]
    fn federated_wallet_snapshot_verify_passes() {
        let fed1 = make_fed(&[1, 2, 3]);
        let w1 = make_wallet(&fed1);
        let fw = BtcFederatedWallet::new(fed1, w1).unwrap();

        let snap = FederatedWalletSnapshot::from_wallet(&fw);
        snap.verify().unwrap();
    }

    #[test]
    fn federated_wallet_snapshot_verify_rejects_empty() {
        let snap = FederatedWalletSnapshot {
            federations: vec![],
            network: NetworkType::Bitcoin(Network::Regtest),
            created_at: now_truncated_to_seconds(),
        };
        let err = snap.verify().unwrap_err();
        assert!(matches!(err, SnapshotError::InvalidThreshold(_)));
    }

    #[test]
    fn federated_wallet_snapshot_verify_rejects_network_mismatch() {
        let fed1 = make_fed(&[1, 2, 3]);
        let w1 = make_wallet(&fed1);
        let fw = BtcFederatedWallet::new(fed1, w1).unwrap();

        let mut snap = FederatedWalletSnapshot::from_wallet(&fw);
        snap.network = NetworkType::Bitcoin(Network::Testnet);
        let err = snap.verify().unwrap_err();
        assert!(matches!(err, SnapshotError::Json(_)));
    }
}
