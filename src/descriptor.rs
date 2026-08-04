//! Descriptor construction and validation.
//!
//! [`DescriptorBuilder`] produces canonical `wsh(sortedmulti(m, ...))` (Segwit
//! v0) or `tr(NUMS, multi_a(m, ...))` (Taproot, BIP-86 style) descriptors with
//! deterministic key ordering and key-origin metadata. The [`ScriptType`]
//! selects the output; within each, two key-encoding [`KeyMode`]s are
//! supported:
//!
//! - **Fixed (default)** — each signer contributes a single public key at the
//!   federation derivation path. The descriptor produces one P2WSH address.
//!   This is the right model for HSM federations where the HSM holds a single
//!   key, and for any deployment that prefers per-federation address rotation.
//! - **Ranged** — each signer contributes an extended public key, and the
//!   descriptor uses BIP-389 multipath wildcards (`xpub.../<0;1>/*`) to
//!   produce many receive/change addresses per federation. Useful when all
//!   signers are HD-capable (consumer hardware wallets).
//!
//! The two modes are interoperable inside a federation only if **all** signers
//! agree — the builder errors out on a mix.
//!
//! # Taproot ([`ScriptType::Tr`])
//!
//! Taproot output is a **script-path-only** P2TR: the internal key is the
//! BIP-341 "nothing up my sleeve" point *H* (provably unspendable, so the
//! key-path can never be used), and the sole tap leaf is an `m`-of-`n`
//! `multi_a` script — the BIP-342 `OP_CHECKSIGADD` multisig.
//!
//! The pinned `miniscript` (12.x) exposes `multi_a` but **not** `sortedmulti_a`,
//! so the builder reproduces `sortedmulti_a` semantics itself: it sorts the
//! x-only cosigner keys lexicographically (the BIP-341 canonical order) before
//! emitting `multi_a`. The resulting leaf script, tap tweak, and address are
//! byte-identical to `tr(H, sortedmulti_a(m, ...))`; only the descriptor
//! **string** differs (`multi_a` with the sort baked in vs. `sortedmulti_a`).
//! A watch-only import of the emitted `multi_a` descriptor into Core/BDK
//! yields the same address.
//!
//! Taproot is currently implemented for [`KeyMode::Fixed`] only — the HSM
//! federation model this path targets. Ranged taproot would need the
//! cosigner order recomputed per derivation index (what `sortedmulti_a` does
//! at address-generation time), which the pinned miniscript cannot express;
//! [`ScriptType::Tr`] + [`KeyMode::Ranged`] is rejected rather than emitting a
//! subtly wrong sort.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use miniscript::descriptor::{DescriptorXKey, SinglePub, SinglePubKey, Wildcard};
use miniscript::{Descriptor, DescriptorPublicKey};

use crate::error::DescriptorError;
use crate::network::NetworkType;
use crate::signer::{Signer, SignerId};

/// BIP-341 "nothing up my sleeve" x-only point *H*, used as the provably
/// unspendable internal key for script-path-only taproot outputs. This is the
/// value specified in BIP-341 (`lift_x` of the SHA-256 of the standard
/// generator's compressed encoding); using it guarantees no key-path spend is
/// possible, so the federation's `multi_a` policy is the only way to spend.
const NUMS_INTERNAL_KEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// The on-chain script form the descriptor compiles to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ScriptType {
    /// Segwit v0 `wsh(sortedmulti(m, ...))`. The default; interoperable across
    /// every signer and backend in the suite.
    #[default]
    Wsh,
    /// Taproot script-path-only `tr(NUMS, multi_a(m, ...))` (BIP-341/342).
    /// Requires [`KeyMode::Fixed`].
    Tr,
}

/// How descriptor keys are encoded.
///
/// Defaults to [`KeyMode::Fixed`], the only mode that works uniformly across
/// HSM (PKCS#11) and HD signers — `Pkcs11Signer` in the `FixedKey` strategy
/// stores a single key per signer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyMode {
    /// Each signer contributes a single public key. The descriptor produces
    /// one address.
    #[default]
    Fixed,
    /// Each signer contributes an xpub, and the descriptor uses BIP-389
    /// multipath wildcards (`/<0;1>/*`) for receive/change derivation.
    Ranged,
}

/// Builder for the canonical `wsh(sortedmulti(m, ...))` federation descriptor.
///
/// See the module-level docs for a discussion of the [`KeyMode`] choice.
#[derive(Debug)]
pub struct DescriptorBuilder {
    threshold: u32,
    mode: KeyMode,
    script_type: ScriptType,
    network: NetworkType,
    /// Ordered by [`SignerId`] for canonical output before passing to
    /// `sortedmulti` (which performs its own lexicographic sort over the
    /// resulting public keys at signing time).
    entries: BTreeMap<SignerId, KeyEntry>,
}

#[derive(Clone, Debug)]
struct KeyEntry {
    fingerprint: Fingerprint,
    derivation_path: DerivationPath,
    xpub: Xpub,
}

impl DescriptorBuilder {
    /// Create a new builder with the given threshold and target network.
    pub fn new(threshold: u32, network: NetworkType) -> Self {
        Self {
            threshold,
            mode: KeyMode::default(),
            script_type: ScriptType::default(),
            network,
            entries: BTreeMap::new(),
        }
    }

    /// Override the [`KeyMode`].
    #[must_use]
    pub fn key_mode(mut self, mode: KeyMode) -> Self {
        self.mode = mode;
        self
    }

    /// Override the [`ScriptType`] (Segwit v0 `wsh` vs. Taproot `tr`).
    #[must_use]
    pub fn script_type(mut self, script_type: ScriptType) -> Self {
        self.script_type = script_type;
        self
    }

    /// Add a signer's contribution. Returns an error if a signer with the
    /// same id is already registered.
    ///
    /// # Errors
    ///
    /// Returns [`DescriptorError::DuplicateKey`] if a signer with the same
    /// [`SignerId`] has already been added.
    pub fn add_signer(&mut self, signer: &dyn Signer) -> Result<&mut Self, DescriptorError> {
        let id = signer.id();
        let entry = KeyEntry {
            fingerprint: signer.fingerprint(),
            derivation_path: signer.derivation_path().clone(),
            xpub: *signer.xpub(),
        };
        if self.entries.insert(id.clone(), entry).is_some() {
            return Err(DescriptorError::DuplicateKey(id.to_string()));
        }
        Ok(self)
    }

    /// Build the canonical descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`DescriptorError::Parse`] if no signers have been added or
    /// the configured network is unsupported, [`DescriptorError::NetworkMismatch`]
    /// if any signer's xpub is on a different network,
    /// [`DescriptorError::DuplicateKey`] if two formatted keys collide,
    /// [`DescriptorError::TaprootRangedUnsupported`] for a
    /// [`ScriptType::Tr`] + [`KeyMode::Ranged`] combination, or
    /// [`DescriptorError::Miniscript`] if miniscript rejects the assembled
    /// descriptor.
    pub fn build(self) -> Result<Descriptor<DescriptorPublicKey>, DescriptorError> {
        if self.entries.is_empty() {
            return Err(DescriptorError::Parse(
                "descriptor builder has no signers".into(),
            ));
        }
        let bitcoin_net = self
            .network
            .bitcoin()
            .ok_or_else(|| DescriptorError::Parse("only Bitcoin networks supported".into()))?;
        for entry in self.entries.values() {
            // Xpub::network is `bitcoin::NetworkKind`; any non-Mainnet
            // network is treated as testnet-equivalent for this check.
            let xpub_kind = entry.xpub.network;
            let expected_kind = bitcoin::NetworkKind::from(bitcoin_net);
            if xpub_kind != expected_kind {
                return Err(DescriptorError::NetworkMismatch {
                    expected: format!("{expected_kind:?}"),
                    actual: format!("{xpub_kind:?}"),
                });
            }
        }
        match self.script_type {
            ScriptType::Wsh => self.build_wsh(),
            ScriptType::Tr => self.build_taproot(),
        }
    }

    /// Assemble the Segwit v0 `wsh(sortedmulti(m, ...))` descriptor.
    fn build_wsh(&self) -> Result<Descriptor<DescriptorPublicKey>, DescriptorError> {
        let keys: Vec<DescriptorPublicKey> = self
            .entries
            .values()
            .map(|e| build_descriptor_key(self.mode, e))
            .collect::<Result<_, _>>()?;

        reject_duplicate_keys(&keys)?;

        Descriptor::new_wsh_sortedmulti(self.threshold as usize, keys)
            .map_err(DescriptorError::Miniscript)
    }

    /// Assemble the Taproot `tr(NUMS, multi_a(m, ...))` descriptor.
    ///
    /// Reproduces `sortedmulti_a` ordering by sorting the x-only cosigner keys
    /// lexicographically (BIP-341) before emitting `multi_a`, since the pinned
    /// miniscript lacks a native `sortedmulti_a`. See the module docs.
    fn build_taproot(&self) -> Result<Descriptor<DescriptorPublicKey>, DescriptorError> {
        if self.mode != KeyMode::Fixed {
            return Err(DescriptorError::TaprootRangedUnsupported);
        }

        // (x-only serialization, descriptor key). Sorting by the 32-byte
        // x-only key is the canonical BIP-341 `sortedmulti_a` order.
        let mut keyed: Vec<([u8; 32], DescriptorPublicKey)> = self
            .entries
            .values()
            .map(|e| {
                let (xonly, _parity) = e.xpub.public_key.x_only_public_key();
                (xonly.serialize(), build_taproot_key(e))
            })
            .collect();
        keyed.sort_by_key(|(xonly, _)| *xonly);

        let keys: Vec<DescriptorPublicKey> = keyed.into_iter().map(|(_, k)| k).collect();
        reject_duplicate_keys(&keys)?;

        let joined = keys
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let desc_str = format!(
            "tr({NUMS_INTERNAL_KEY},multi_a({threshold},{joined}))",
            threshold = self.threshold,
        );
        Descriptor::from_str(&desc_str).map_err(DescriptorError::Miniscript)
    }
}

/// Reject any pair of formatted keys that collide — distinct [`SignerId`]s with
/// identical keys would still collide on chain.
fn reject_duplicate_keys(keys: &[DescriptorPublicKey]) -> Result<(), DescriptorError> {
    let mut seen = std::collections::HashSet::new();
    for k in keys {
        let s = k.to_string();
        if !seen.insert(s.clone()) {
            return Err(DescriptorError::DuplicateKey(s));
        }
    }
    Ok(())
}

/// Build the x-only, origin-annotated descriptor key for a taproot `multi_a`
/// cosigner slot (Fixed mode: one key per signer at the federation path).
fn build_taproot_key(entry: &KeyEntry) -> DescriptorPublicKey {
    let (xonly, _parity) = entry.xpub.public_key.x_only_public_key();
    DescriptorPublicKey::Single(SinglePub {
        origin: Some((entry.fingerprint, entry.derivation_path.clone())),
        key: SinglePubKey::XOnly(xonly),
    })
}

fn build_descriptor_key(
    mode: KeyMode,
    entry: &KeyEntry,
) -> Result<DescriptorPublicKey, DescriptorError> {
    let origin = Some((entry.fingerprint, entry.derivation_path.clone()));
    match mode {
        KeyMode::Fixed => {
            // Single public key at the federation derivation path. The xpub's
            // public_key field IS the key we want to use.
            let pk = bitcoin::PublicKey::new(entry.xpub.public_key);
            Ok(DescriptorPublicKey::Single(SinglePub {
                origin,
                key: SinglePubKey::FullKey(pk),
            }))
        }
        KeyMode::Ranged => {
            // BIP-389 multipath /<0;1>/* — but miniscript 12 only exposes
            // MultiXPub through string parsing for multipath. For our v1, we
            // emit an unhardened single-path xpub-with-wildcard (`xpub/0/*`)
            // for the external chain and rely on the consumer to construct
            // the internal-chain descriptor by replacing /0/ with /1/.
            //
            // Callers that want both keychains in one descriptor can parse
            // the resulting string, swap `/0/` to `/<0;1>/`, and re-parse via
            // `Descriptor::from_str`. This keeps the builder's typed output
            // simple while remaining BIP-389-compatible at the string layer.
            let zero = ChildNumber::from_normal_idx(0)
                .map_err(|e| DescriptorError::KeyConversion(e.to_string()))?;
            let derivation_path = DerivationPath::from(vec![zero]);
            let xkey = DescriptorXKey {
                origin,
                xkey: entry.xpub,
                derivation_path,
                wildcard: Wildcard::Unhardened,
            };
            Ok(DescriptorPublicKey::XPub(xkey))
        }
    }
}

/// Convert a single-keychain descriptor produced in `KeyMode::Ranged` into a
/// BIP-389 multipath descriptor that covers both the external (`/0/*`) and
/// internal (`/1/*`) keychains.
///
/// `Descriptor::to_string()` always appends a `#checksum` suffix computed
/// over the single-path body. Rewriting `/0/*` → `/<0;1>/*` would invalidate
/// that checksum, and downstream parsers (miniscript, BDK) reject the result
/// with `The provided descriptor doesn't match its checksum`. We therefore
/// strip the suffix before substituting and return a checksum-less string —
/// every consumer of multipath descriptors in this codebase
/// (BDK's `Wallet::create_from_two_path_descriptor`, miniscript's
/// `Descriptor::from_str`) accepts a body without a checksum and computes
/// the canonical one internally.
///
/// Returns the multipath descriptor as a string. Use
/// `<miniscript::Descriptor as std::str::FromStr>::from_str` to re-parse if a
/// typed descriptor is needed.
pub fn to_multipath_string(desc: &Descriptor<DescriptorPublicKey>) -> String {
    let s = desc.to_string();
    let body = s.split_once('#').map_or(s.as_str(), |(b, _)| b);
    body.replace("/0/*", "/<0;1>/*")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockSigner;
    use bitcoin::Network;

    fn three_signers() -> [MockSigner; 3] {
        [
            MockSigner::with_seed(1, Network::Testnet),
            MockSigner::with_seed(2, Network::Testnet),
            MockSigner::with_seed(3, Network::Testnet),
        ]
    }

    #[test]
    fn fixed_mode_produces_wsh_sortedmulti() {
        let signers = three_signers();
        let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet));
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        let desc = b.build().unwrap();
        let s = desc.to_string();
        assert!(s.starts_with("wsh(sortedmulti(2,"), "got {s}");
        assert!(!s.contains("/*"), "fixed mode should not contain wildcard");
    }

    #[test]
    fn ranged_mode_includes_wildcard() {
        let signers = three_signers();
        let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet))
            .key_mode(KeyMode::Ranged);
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        let desc = b.build().unwrap();
        let s = desc.to_string();
        assert!(s.contains("/0/*"));
    }

    #[test]
    fn duplicate_signer_id_rejected() {
        let s1 = MockSigner::with_seed(7, Network::Testnet);
        let s1b = s1.clone();
        let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet));
        b.add_signer(&s1).unwrap();
        let err = b.add_signer(&s1b).unwrap_err();
        assert!(matches!(err, DescriptorError::DuplicateKey(_)));
    }

    #[test]
    fn ordering_is_canonical_by_signer_id() {
        let s1 = MockSigner::with_seed(11, Network::Testnet);
        let s2 = MockSigner::with_seed(12, Network::Testnet);
        let s3 = MockSigner::with_seed(13, Network::Testnet);
        let mk = |order: [&MockSigner; 3]| -> String {
            let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet));
            for s in order {
                b.add_signer(s).unwrap();
            }
            b.build().unwrap().to_string()
        };
        let a = mk([&s1, &s2, &s3]);
        let b = mk([&s3, &s1, &s2]);
        let c = mk([&s2, &s3, &s1]);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn multipath_helper_replaces_external_wildcard() {
        let signers = three_signers();
        let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet))
            .key_mode(KeyMode::Ranged);
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        let desc = b.build().unwrap();
        let mp = to_multipath_string(&desc);
        assert!(mp.contains("/<0;1>/*"));
        assert!(!mp.contains("/0/*"));
    }

    #[test]
    fn multipath_helper_strips_stale_checksum() {
        // Regression: `Descriptor::to_string()` appends a `#checksum`
        // computed over the single-path body. Naively replacing `/0/*`
        // leaves that stale checksum attached and downstream parsers
        // reject it. The helper must drop the suffix before substitution.
        let signers = three_signers();
        let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet))
            .key_mode(KeyMode::Ranged);
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        let desc = b.build().unwrap();
        let mp = to_multipath_string(&desc);
        assert!(
            !mp.contains('#'),
            "multipath string must not carry the stale single-path checksum, got {mp}"
        );
    }

    #[test]
    fn tr_mode_produces_tr_multi_a() {
        let signers = three_signers();
        let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet))
            .script_type(ScriptType::Tr);
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        let desc = b.build().unwrap();
        let s = desc.to_string();
        assert!(s.starts_with("tr("), "got {s}");
        assert!(
            s.contains(NUMS_INTERNAL_KEY),
            "internal key must be NUMS: {s}"
        );
        assert!(s.contains("multi_a(2,"), "got {s}");
        assert!(
            !s.contains("sortedmulti"),
            "miniscript 12 has no sortedmulti_a; must emit multi_a: {s}"
        );
    }

    #[test]
    fn tr_mode_address_is_p2tr() {
        let signers = three_signers();
        let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet))
            .script_type(ScriptType::Tr);
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        let desc = b.build().unwrap();
        // Fixed mode has no wildcard, so index 0 is the sole definite address.
        let addr = desc
            .at_derivation_index(0)
            .unwrap()
            .address(Network::Testnet)
            .unwrap();
        assert!(
            addr.script_pubkey().is_p2tr(),
            "expected a P2TR scriptPubKey, got {addr}"
        );
        assert!(addr.to_string().starts_with("tb1p"), "got {addr}");
    }

    #[test]
    fn tr_mode_ordering_is_canonical() {
        let s1 = MockSigner::with_seed(21, Network::Testnet);
        let s2 = MockSigner::with_seed(22, Network::Testnet);
        let s3 = MockSigner::with_seed(23, Network::Testnet);
        let mk = |order: [&MockSigner; 3]| -> String {
            let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet))
                .script_type(ScriptType::Tr);
            for s in order {
                b.add_signer(s).unwrap();
            }
            b.build().unwrap().to_string()
        };
        // Insertion order must not change the emitted descriptor: the x-only
        // BIP-341 sort is what fixes cosigner order.
        assert_eq!(mk([&s1, &s2, &s3]), mk([&s3, &s1, &s2]));
        assert_eq!(mk([&s1, &s2, &s3]), mk([&s2, &s3, &s1]));
    }

    #[test]
    fn tr_keys_are_x_only() {
        // multi_a cosigner keys must be 64-hex x-only, never 66-hex compressed.
        let signers = three_signers();
        let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet))
            .script_type(ScriptType::Tr);
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        let s = b.build().unwrap().to_string();
        // Each cosigner appears as `]<64hex>` (origin close-bracket then x-only).
        for entry in three_signers() {
            let (xonly, _) = entry.xpub().public_key.x_only_public_key();
            let hex = format!("{xonly}");
            assert_eq!(hex.len(), 64, "x-only key must be 64 hex chars");
            assert!(
                s.contains(&hex),
                "descriptor missing x-only cosigner key: {s}"
            );
        }
    }

    #[test]
    fn tr_ranged_is_rejected() {
        let signers = three_signers();
        let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet))
            .script_type(ScriptType::Tr)
            .key_mode(KeyMode::Ranged);
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        let err = b.build().unwrap_err();
        assert!(
            matches!(err, DescriptorError::TaprootRangedUnsupported),
            "got {err:?}"
        );
    }

    #[test]
    fn multipath_helper_output_parses_back() {
        // The multipath string must round-trip through miniscript so
        // BDK's `Wallet::create_from_two_path_descriptor` accepts it.
        use std::str::FromStr;

        let signers = three_signers();
        let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet))
            .key_mode(KeyMode::Ranged);
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        let desc = b.build().unwrap();
        let mp = to_multipath_string(&desc);
        miniscript::Descriptor::<DescriptorPublicKey>::from_str(&mp)
            .expect("miniscript should accept the checksum-less multipath descriptor");
    }
}
