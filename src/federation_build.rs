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

use crate::descriptor::{
    Bip388TaprootPolicy, KeyMode, ScriptType, TaprootInternalKey, to_multipath_string,
};
use crate::error::{DescriptorError, EmVaultError, SnapshotError};
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
/// Returns [`EmVaultError`] if [`DescriptorBuilder`] or [`Federation::new`]
/// rejects the inputs (duplicate xpub, network mismatch, threshold out of
/// range — surfaced as [`EmVaultError::Descriptor`] / [`EmVaultError::Federation`]),
/// or if the snapshot fails to serialise ([`EmVaultError::Snapshot`]).
pub fn build_federation<S: Signer>(
    signers: Vec<S>,
    threshold: u32,
    network: NetworkType,
) -> Result<BuiltFederation, EmVaultError> {
    build_federation_with(signers, threshold, network, ScriptType::Wsh)
}

/// Build the canonical descriptor + snapshot for a ranged federation over
/// `signers` with the given `threshold` and `script_type`
/// (`Wsh` → `wsh(sortedmulti(...))`, `Tr` → `tr(NUMS, multi_a(...))`). Always
/// [`KeyMode::Ranged`] — the multipath HD shape both the apps and consumer
/// hardware wallets use. [`build_federation`] is the `Wsh` shorthand.
///
/// # Errors
///
/// Same as [`build_federation`]: [`EmVaultError`] if [`DescriptorBuilder`] or
/// [`Federation`] rejects the inputs, or if the snapshot fails to serialise.
pub fn build_federation_with<S: Signer>(
    signers: Vec<S>,
    threshold: u32,
    network: NetworkType,
    script_type: ScriptType,
) -> Result<BuiltFederation, EmVaultError> {
    let mut builder = DescriptorBuilder::new(threshold, network)
        .key_mode(KeyMode::Ranged)
        .script_type(script_type);
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

/// Where the NUMS-xpub chain code comes from when building a consumer-hardware
/// (BIP-388) taproot federation.
///
/// - [`Random`](NumsChaincode::Random): a fresh 32-byte chain code (default for
///   new vaults — privacy: vaults aren't linkable by a shared internal key).
/// - [`Custom`](NumsChaincode::Custom): a specified chain code, to reproduce an
///   existing vault's addresses when importing a multisig arrangement.
#[derive(Clone, Copy, Debug)]
pub enum NumsChaincode {
    /// Generate a fresh random chain code.
    Random,
    /// Use this exact 32-byte chain code (import/reproduce).
    Custom([u8; 32]),
}

impl NumsChaincode {
    /// Resolve to concrete bytes, generating randomness for [`Self::Random`].
    ///
    /// # Errors
    /// [`EmVaultError`] if the system RNG (`getrandom`) fails — a fatal
    /// environment condition under which no wallet material can be generated.
    fn resolve(self) -> Result<[u8; 32], EmVaultError> {
        match self {
            Self::Custom(cc) => Ok(cc),
            Self::Random => {
                let mut cc = [0u8; 32];
                getrandom::fill(&mut cc).map_err(|e| {
                    DescriptorError::Parse(format!("nums chaincode rng failed: {e}"))
                })?;
                Ok(cc)
            }
        }
    }
}

/// Build a **Taproot** federation whose internal key is the BIP-388-registerable
/// NUMS-as-xpub (so consumer hardware like Ledger can register + sign it), over
/// `signers` with the given `threshold`. Always [`KeyMode::Ranged`].
///
/// Returns the built federation **and the resolved 32-byte chain code** — the
/// caller MUST persist the chain code (it is recovery material: it lives in the
/// descriptor, and devices-only recovery cannot regenerate it).
///
/// Use [`NumsChaincode::Random`] for a new vault, [`NumsChaincode::Custom`] to
/// reproduce an imported one. This is additive: the raw-NUMS taproot path
/// (`build_federation_with(…, ScriptType::Tr)`) is unchanged.
///
/// # Errors
/// Same as [`build_federation_with`].
pub fn build_federation_taproot_with<S: Signer>(
    signers: Vec<S>,
    threshold: u32,
    network: NetworkType,
    chaincode: NumsChaincode,
) -> Result<(BuiltFederation, [u8; 32]), EmVaultError> {
    let resolved = chaincode.resolve()?;
    let mut builder = DescriptorBuilder::new(threshold, network)
        .key_mode(KeyMode::Ranged)
        .script_type(ScriptType::Tr)
        .taproot_internal_key(TaprootInternalKey::NumsXpub(resolved));
    for s in &signers {
        builder.add_signer(s)?;
    }
    let descriptor = builder.build()?;
    let descriptor_string = to_multipath_string(&descriptor);

    let federation = Federation::new(threshold, signers, network)?;

    let snapshot_json: serde_json::Value =
        serde_json::from_str(&FederationSnapshot::from_federation(&federation).to_canonical_json())
            .map_err(|e| SnapshotError::Json(e.to_string()))?;

    Ok((
        BuiltFederation {
            descriptor_string,
            snapshot_json,
        },
        resolved,
    ))
}

/// Build the BIP-388 taproot wallet policy (`{template, keys}`) for `signers` at
/// `threshold`, using the **same** xpub-NUMS setup as
/// [`build_federation_taproot_with`] — so the policy a consumer device (Ledger)
/// registers matches the funded descriptor's scriptPubKeys exactly. `chaincode`
/// is the federation's stored NUMS chain code.
///
/// This is the single source of truth for the Ledger taproot policy: callers
/// pass the same signer set + chain code they built the federation with.
///
/// # Errors
/// [`EmVaultError`] if descriptor/policy assembly rejects the inputs.
pub fn bip388_taproot_policy<S: Signer>(
    signers: &[S],
    threshold: u32,
    network: NetworkType,
    chaincode: [u8; 32],
) -> Result<Bip388TaprootPolicy, EmVaultError> {
    let mut builder = DescriptorBuilder::new(threshold, network)
        .key_mode(KeyMode::Ranged)
        .script_type(ScriptType::Tr)
        .taproot_internal_key(TaprootInternalKey::NumsXpub(chaincode));
    for s in signers {
        builder.add_signer(s)?;
    }
    builder.bip388_taproot_policy().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockSigner;
    use bitcoin::Network;

    /// The raw BIP-341 `H` literal the *raw-NUMS* taproot path emits (and the
    /// xpub-NUMS path must not).
    const RAW_NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

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

    // ── Taproot xpub-NUMS (F3) ───────────────────────────────────────────

    #[test]
    fn taproot_xpub_nums_descriptor_shape() {
        let net = NetworkType::Bitcoin(Network::Testnet);
        let (built, cc) = build_federation_taproot_with(
            roster(&[1, 2, 3]),
            2,
            net,
            NumsChaincode::Custom([7; 32]),
        )
        .unwrap();
        assert_eq!(cc, [7u8; 32], "resolved chaincode echoes the Custom bytes");
        let d = &built.descriptor_string;
        assert!(d.starts_with("tr("), "want tr(...): {d}");
        assert!(d.contains("multi_a(2,"), "want multi_a(2, : {d}");
        assert!(d.contains("/<0;1>/*"), "multipath lifted: {d}");
        assert!(
            d.contains("tpub"),
            "nums + cosigners are tpub on testnet: {d}"
        );
        assert!(
            !d.contains(RAW_NUMS),
            "xpub-NUMS descriptor must NOT contain the raw NUMS literal: {d}"
        );
    }

    #[test]
    fn raw_nums_taproot_path_unchanged() {
        // The pre-existing raw-NUMS taproot builder (pkcs11 path) is untouched.
        let net = NetworkType::Bitcoin(Network::Testnet);
        let built = build_federation_with(roster(&[1, 2, 3]), 2, net, ScriptType::Tr).unwrap();
        assert!(
            built.descriptor_string.contains(RAW_NUMS),
            "raw-NUMS path must still emit the literal: {}",
            built.descriptor_string
        );
    }

    #[test]
    fn custom_reproducible_random_unique() {
        let net = NetworkType::Bitcoin(Network::Testnet);
        // Same chaincode + same signer set (any input order) → identical descriptor.
        let a = build_federation_taproot_with(
            roster(&[1, 2, 3]),
            2,
            net,
            NumsChaincode::Custom([9; 32]),
        )
        .unwrap()
        .0;
        let b = build_federation_taproot_with(
            roster(&[3, 1, 2]),
            2,
            net,
            NumsChaincode::Custom([9; 32]),
        )
        .unwrap()
        .0;
        assert_eq!(a.descriptor_string, b.descriptor_string);
        // Two Random builds → different chaincodes and different descriptors.
        let r1 = build_federation_taproot_with(roster(&[1, 2, 3]), 2, net, NumsChaincode::Random)
            .unwrap();
        let r2 = build_federation_taproot_with(roster(&[1, 2, 3]), 2, net, NumsChaincode::Random)
            .unwrap();
        assert_ne!(r1.1, r2.1, "two Random chaincodes must differ");
        assert_ne!(r1.0.descriptor_string, r2.0.descriptor_string);
    }

    #[test]
    fn taproot_xpub_nums_derives_p2tr_address() {
        let net = NetworkType::Bitcoin(Network::Testnet);
        let signers = roster(&[1, 2, 3]);
        let mut b = DescriptorBuilder::new(2, net)
            .key_mode(KeyMode::Ranged)
            .script_type(ScriptType::Tr)
            .taproot_internal_key(TaprootInternalKey::NumsXpub([3; 32]));
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        let desc = b.build().unwrap();
        let addr = desc
            .at_derivation_index(0)
            .unwrap()
            .address(Network::Testnet)
            .unwrap();
        assert!(
            addr.to_string().starts_with("tb1p"),
            "want P2TR, got {addr}"
        );
    }

    #[test]
    fn bip388_policy_free_fn_matches_builder() {
        // The free `bip388_taproot_policy(...)` uses the same setup as the
        // descriptor build, so the Ledger policy matches the funded addresses.
        let net = NetworkType::Bitcoin(Network::Testnet);
        let pol = bip388_taproot_policy(&roster(&[1, 2, 3]), 2, net, [5; 32]).unwrap();
        assert_eq!(pol.template, "tr(@0/**,multi_a(2,@1/**,@2/**,@3/**))");
        assert_eq!(pol.keys.len(), 4);
        assert!(pol.keys[0].starts_with("tpub") && !pol.keys[0].contains('['));
    }

    #[test]
    fn bip388_policy_matches_descriptor() {
        let net = NetworkType::Bitcoin(Network::Testnet);
        let signers = roster(&[1, 2, 3]);
        let mut b = DescriptorBuilder::new(2, net)
            .key_mode(KeyMode::Ranged)
            .script_type(ScriptType::Tr)
            .taproot_internal_key(TaprootInternalKey::NumsXpub([5; 32]));
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        let pol = b.bip388_taproot_policy().unwrap();
        assert_eq!(pol.template, "tr(@0/**,multi_a(2,@1/**,@2/**,@3/**))");
        assert_eq!(pol.keys.len(), 4, "@0 NUMS + 3 cosigners");
        assert!(
            pol.keys[0].starts_with("tpub") && !pol.keys[0].contains('['),
            "@0 is the origin-less NUMS tpub: {}",
            pol.keys[0]
        );
        assert!(
            pol.keys[1..]
                .iter()
                .all(|k| k.contains('[') && k.contains("tpub")),
            "cosigners are origin-annotated: {:?}",
            &pol.keys[1..]
        );
        assert!(
            pol.keys.iter().all(|k| !k.contains('*')),
            "key-info carries no wildcard (the /** is in the template): {:?}",
            pol.keys
        );
    }
}
