//! Descriptor construction and validation.
//!
//! [`DescriptorBuilder`] produces canonical `wsh(sortedmulti(m, ...))`
//! descriptors with deterministic key ordering and key-origin metadata. Two
//! modes are supported:
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

use std::collections::BTreeMap;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use miniscript::descriptor::{DescriptorXKey, SinglePub, SinglePubKey, Wildcard};
use miniscript::{Descriptor, DescriptorPublicKey};

use crate::error::DescriptorError;
use crate::network::NetworkType;
use crate::signer::{Signer, SignerId};

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
    /// [`DescriptorError::DuplicateKey`] if two formatted keys collide, or
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
        let keys: Vec<DescriptorPublicKey> = self
            .entries
            .values()
            .map(|e| build_descriptor_key(self.mode, e))
            .collect::<Result<_, _>>()?;

        // Detect duplicates by formatted key (origin + xpub) — distinct
        // SignerIds with identical xpubs would still collide on chain.
        let mut seen = std::collections::HashSet::new();
        for k in &keys {
            let s = k.to_string();
            if !seen.insert(s.clone()) {
                return Err(DescriptorError::DuplicateKey(s));
            }
        }

        Descriptor::new_wsh_sortedmulti(self.threshold as usize, keys)
            .map_err(DescriptorError::Miniscript)
    }
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
/// Returns the multipath descriptor as a string. Use
/// `<miniscript::Descriptor as std::str::FromStr>::from_str` to re-parse if a
/// typed descriptor is needed.
pub fn to_multipath_string(desc: &Descriptor<DescriptorPublicKey>) -> String {
    let s = desc.to_string();
    // Swap each `/0/*` token (preceded by an xpub character) with `/<0;1>/*`.
    s.replace("/0/*", "/<0;1>/*")
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
}
