//! Canonical construction of federation artifacts from a signer set.
//!
//! Turning a set of [`Signer`]s + a threshold into the exact same canonical
//! multipath descriptor and snapshot is needed wherever a federation version is
//! minted — initial creation and a migration's next-version alike. Centralising
//! it here guarantees those paths can never diverge in how they build the
//! descriptor, which is what makes a migration's successor a faithful version.
//!
//! Generic over the [`Signer`] implementation so any backend (consumer hardware
//! wallets, HSMs, …) builds federations the same way.

use crate::descriptor::{KeyMode, to_multipath_string};
use crate::error::{AsterismError, SnapshotError};
use crate::signer::Signer;
use crate::{DescriptorBuilder, Federation, FederationSnapshot, NetworkType};

/// The artifacts needed to persist a federation version.
pub struct BuiltFederation {
    /// Canonical multipath `wsh(sortedmulti(...))/<0;1>/*` descriptor string.
    pub descriptor_string: String,
    /// Canonical `FederationSnapshot` JSON.
    pub snapshot_json: serde_json::Value,
}

/// Build the canonical descriptor + snapshot for a ranged P2WSH federation over
/// `signers` with the given `threshold`. The signer order is preserved
/// (`sortedmulti` canonicalises key order in the descriptor regardless).
///
/// # Errors
///
/// Returns [`AsterismError`] if [`DescriptorBuilder`] or [`Federation::new`]
/// rejects the inputs (duplicate xpub, network mismatch, threshold out of
/// range — surfaced as [`AsterismError::Descriptor`] / [`AsterismError::Federation`]),
/// or if the snapshot fails to serialise ([`AsterismError::Snapshot`]).
pub fn build_federation<S: Signer>(
    signers: Vec<S>,
    threshold: u32,
    network: NetworkType,
) -> Result<BuiltFederation, AsterismError> {
    let mut builder = DescriptorBuilder::new(threshold, network).key_mode(KeyMode::Ranged);
    for s in &signers {
        builder.add_signer(s)?;
    }
    let descriptor = builder.build()?;
    let descriptor_string = to_multipath_string(&descriptor);

    let federation = Federation::new(threshold, signers, network)?;

    let snapshot_json: serde_json::Value =
        serde_json::from_str(&FederationSnapshot::from_federation(&federation).to_canonical_json())
            .map_err(|e| SnapshotError::Json(e.to_string()))?;

    Ok(BuiltFederation {
        descriptor_string,
        snapshot_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockSigner;
    use bitcoin::Network;

    fn roster(seeds: &[u64]) -> Vec<MockSigner> {
        seeds
            .iter()
            .map(|&s| MockSigner::with_seed(s, Network::Testnet))
            .collect()
    }

    #[test]
    fn builds_descriptor_and_snapshot() {
        let built = build_federation(
            roster(&[1, 2, 3]),
            2,
            NetworkType::Bitcoin(Network::Testnet),
        )
        .unwrap();
        assert!(built.descriptor_string.starts_with("wsh(sortedmulti(2"));
        assert!(built.snapshot_json.is_object());
    }

    #[test]
    fn same_roster_yields_same_descriptor() {
        let net = NetworkType::Bitcoin(Network::Testnet);
        let a = build_federation(roster(&[1, 2, 3]), 2, net).unwrap();
        // Different input order — sortedmulti must canonicalise to the same descriptor.
        let b = build_federation(roster(&[3, 1, 2]), 2, net).unwrap();
        assert_eq!(a.descriptor_string, b.descriptor_string);
    }
}
