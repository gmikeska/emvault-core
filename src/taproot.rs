//! [`TaprootFederationBuilder`] — Taproot MAST descriptors for hybrid
//! federations.
//!
//! Hybrid federations encode three spending paths as separate leaves in a
//! Taproot script tree:
//!
//! 1. **All HSMs unanimously** (authorizer-mediated) — the routine path.
//! 2. **All consumer hardware wallets unanimously** (full trustee consensus) —
//!    the recovery / backstop path.
//! 3. **Mixed** (HSM + trustee) — for high-value or sensitive payments.
//!
//! The internal key is set to a NUMS (Nothing-Up-My-Sleeve) point so no
//! single party can claim a key-path spend.
//!
//! ```text
//! tr(NUMS, {
//!   multi_a(h, HSM_1, HSM_2, ..., HSM_h),
//!   {
//!     multi_a(w, WALLET_1, ..., WALLET_w),
//!     multi_a(k, HSM_1, ..., WALLET_1, ...)
//!   }
//! })
//! ```
//!
//! See `design_docs/asterism_multisignature_library.md`, section
//! "Taproot MAST Descriptors (Hybrid Federations)", for the full design
//! rationale.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::secp256k1::XOnlyPublicKey;
use miniscript::{Descriptor, DescriptorPublicKey};

use crate::error::FederationError;
use crate::federation::Federation;
use crate::network::NetworkType;
use crate::signer::{Signer, SignerId};

/// BIP-341 standard NUMS point used to suppress key-path spending in
/// federations that are policy-only (no single-party key path).
///
/// `H = lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)`.
pub const NUMS_HEX: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// Returns the BIP-341 NUMS X-only public key.
pub fn nums_point() -> XOnlyPublicKey {
    XOnlyPublicKey::from_str(NUMS_HEX).expect("BIP-341 NUMS point is well-formed")
}

/// Builder for hybrid (HSM + consumer hardware wallet) Taproot federations.
pub struct TaprootFederationBuilder<S: Signer = Box<dyn Signer>> {
    network: NetworkType,
    hsm_signers: Vec<S>,
    wallet_signers: Vec<S>,
    mixed_threshold: Option<u32>,
}

impl<S: Signer> TaprootFederationBuilder<S> {
    /// Create a new Taproot federation builder for `network`.
    pub fn new(network: NetworkType) -> Self {
        Self {
            network,
            hsm_signers: Vec::new(),
            wallet_signers: Vec::new(),
            mixed_threshold: None,
        }
    }

    /// Add an HSM signer. HSMs participate in the unanimous-HSM and mixed
    /// paths.
    pub fn add_hsm_signer(&mut self, signer: S) -> &mut Self {
        self.hsm_signers.push(signer);
        self
    }

    /// Add a consumer hardware wallet signer. Consumer wallets participate in
    /// the unanimous-wallet (recovery) and mixed paths.
    pub fn add_wallet_signer(&mut self, signer: S) -> &mut Self {
        self.wallet_signers.push(signer);
        self
    }

    /// Set the mixed-path threshold.
    ///
    /// If unset, defaults to `ceil(total_signers / 2)`.
    pub fn mixed_threshold(&mut self, threshold: u32) -> &mut Self {
        self.mixed_threshold = Some(threshold);
        self
    }
}

impl<S: Signer + Clone> TaprootFederationBuilder<S> {
    /// Construct the federation. Returns a [`Federation`] whose
    /// [`Federation::descriptor`] is a `tr(NUMS, { ... })` MAST descriptor.
    pub fn build(self) -> Result<Federation<S>, FederationError> {
        let TaprootFederationBuilder {
            network,
            hsm_signers,
            wallet_signers,
            mixed_threshold,
        } = self;

        // ----- structural validation ---------------------------------------
        if hsm_signers.is_empty() {
            return Err(FederationError::InvalidTaproot(
                "at least one HSM signer required (use Federation::new for wallet-only \
                 federations)".into(),
            ));
        }
        if wallet_signers.is_empty() {
            return Err(FederationError::InvalidTaproot(
                "at least one consumer hardware wallet signer required (use Federation::new \
                 for HSM-only federations)".into(),
            ));
        }

        // Disallow duplicate ids across the two groups.
        let mut seen: BTreeMap<SignerId, &'static str> = BTreeMap::new();
        for s in &hsm_signers {
            if seen.insert(s.id(), "hsm").is_some() {
                return Err(FederationError::DuplicateSigner(s.id()));
            }
        }
        for s in &wallet_signers {
            if seen.insert(s.id(), "wallet").is_some() {
                return Err(FederationError::DuplicateSigner(s.id()));
            }
        }

        // Network compatibility + Taproot capability.
        for s in hsm_signers.iter().chain(wallet_signers.iter()) {
            if !s.supported_networks().contains(&network) {
                return Err(FederationError::SignerNetworkMismatch {
                    id: s.id(),
                    network,
                });
            }
            if !s.capabilities().taproot {
                return Err(FederationError::MissingCapability {
                    id: s.id(),
                    capability: "taproot",
                });
            }
        }

        let total = (hsm_signers.len() + wallet_signers.len()) as u32;
        let mixed_k = mixed_threshold.unwrap_or((total + 1) / 2);
        if mixed_k < 2 {
            return Err(FederationError::InvalidTaproot(
                "mixed threshold must be at least 2".into(),
            ));
        }
        if mixed_k > total {
            return Err(FederationError::InvalidTaproot(format!(
                "mixed threshold {mixed_k} exceeds total signers {total}"
            )));
        }

        // ----- build the descriptor as a string ---------------------------
        // multi_a leaves take X-only keys with origin metadata.
        let hsm_keys: Vec<String> = hsm_signers.iter().map(format_xonly_key).collect();
        let wallet_keys: Vec<String> = wallet_signers.iter().map(format_xonly_key).collect();

        let hsm_leaf = format!(
            "multi_a({h},{keys})",
            h = hsm_signers.len(),
            keys = hsm_keys.join(",")
        );
        let wallet_leaf = format!(
            "multi_a({w},{keys})",
            w = wallet_signers.len(),
            keys = wallet_keys.join(",")
        );
        let mut all_keys = hsm_keys.clone();
        all_keys.extend(wallet_keys.clone());
        let mixed_leaf = format!(
            "multi_a({k},{keys})",
            k = mixed_k,
            keys = all_keys.join(",")
        );

        // Tree structure: HSM leaf at the top (shortest proof), wallet leaf
        // and mixed leaf as siblings in the right subtree.
        let descriptor_string =
            format!("tr({NUMS_HEX},{{{hsm_leaf},{{{wallet_leaf},{mixed_leaf}}}}})");

        let descriptor: Descriptor<DescriptorPublicKey> = descriptor_string
            .parse()
            .map_err(|e: miniscript::Error| {
                FederationError::InvalidTaproot(format!(
                    "miniscript rejected tr descriptor: {e}\nfull descriptor: {descriptor_string}"
                ))
            })?;

        // ----- assemble Federation via internal API -----------------------
        // The descriptor is already built — we use the `from_taproot_parts`
        // private constructor to bypass DescriptorBuilder.
        let signers: Vec<S> = hsm_signers
            .into_iter()
            .chain(wallet_signers.into_iter())
            .collect();
        Federation::from_descriptor(mixed_k, signers, network, descriptor)
    }
}

fn format_xonly_key<S: Signer>(s: &S) -> String {
    let pk = s.xpub().public_key;
    let (xonly, _parity) = pk.x_only_public_key();
    let origin_fp = s.fingerprint();
    let origin_path = s.derivation_path();
    // Format with origin: `[fp/path]xonly_hex`. miniscript accepts this.
    format!("[{}{}]{}", origin_fp, origin_path_to_string(origin_path), xonly)
}

fn origin_path_to_string(path: &bitcoin::bip32::DerivationPath) -> String {
    // `DerivationPath::to_string` formats as `48'/1'/0'/2'` (no `m/` prefix)
    // for non-empty paths and `m` for the empty path. Descriptor origins are
    // formatted as `/seg1/seg2/...` after the fingerprint, so we always
    // prepend a `/` to non-empty paths.
    let s = path.to_string();
    if s.is_empty() || s == "m" {
        String::new()
    } else if let Some(stripped) = s.strip_prefix("m/") {
        format!("/{stripped}")
    } else {
        format!("/{s}")
    }
}

// ---------------------------------------------------------------------------
// Federation::from_descriptor (internal constructor used by Taproot builder)
// ---------------------------------------------------------------------------

impl<S: Signer> Federation<S> {
    /// **Internal**: construct a [`Federation`] from a pre-built descriptor.
    ///
    /// This is the bypass path used by [`TaprootFederationBuilder`]; ordinary
    /// callers should use [`Federation::new`].
    #[doc(hidden)]
    pub fn from_descriptor(
        threshold: u32,
        signers: Vec<S>,
        network: NetworkType,
        descriptor: Descriptor<DescriptorPublicKey>,
    ) -> Result<Federation<S>, FederationError> {
        // Deferred import to avoid a circular module reference.
        use crate::federation::FederationCtor;
        FederationCtor::from_parts(threshold, signers, network, descriptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockSigner;
    use bitcoin::Network;

    #[test]
    fn nums_point_is_well_formed() {
        let _pt = nums_point();
    }

    #[test]
    fn build_hybrid_2_hsm_2_wallet_mixed_2() {
        let mut b = TaprootFederationBuilder::<MockSigner>::new(Network::Testnet.into());
        b.add_hsm_signer(MockSigner::hsm(1, Network::Testnet))
            .add_hsm_signer(MockSigner::hsm(2, Network::Testnet))
            .add_wallet_signer(MockSigner::with_seed(10, Network::Testnet))
            .add_wallet_signer(MockSigner::with_seed(11, Network::Testnet))
            .mixed_threshold(2);
        // Wallet signers aren't taproot-capable in MockSigner default — give
        // them taproot via the Jade variant by overriding... use hsm()
        // helper which already sets taproot=true.
        // For test simplicity, replace wallet signers with hsm-style mocks.
        let mut b = TaprootFederationBuilder::<MockSigner>::new(Network::Testnet.into());
        b.add_hsm_signer(MockSigner::hsm(1, Network::Testnet))
            .add_hsm_signer(MockSigner::hsm(2, Network::Testnet))
            .add_wallet_signer(MockSigner::hsm(10, Network::Testnet))
            .add_wallet_signer(MockSigner::hsm(11, Network::Testnet))
            .mixed_threshold(2);
        let fed = b.build().unwrap();
        let s = fed.descriptor_string();
        assert!(s.starts_with("tr("), "expected tr(...) descriptor, got {s}");
        assert!(s.contains("multi_a("), "expected multi_a leaves");
        assert!(s.contains(NUMS_HEX), "expected NUMS internal key");
    }

    #[test]
    fn rejects_no_hsm_signers() {
        let mut b = TaprootFederationBuilder::<MockSigner>::new(Network::Testnet.into());
        b.add_wallet_signer(MockSigner::hsm(10, Network::Testnet))
            .add_wallet_signer(MockSigner::hsm(11, Network::Testnet));
        let err = b.build().unwrap_err();
        assert!(matches!(err, FederationError::InvalidTaproot(_)));
    }

    #[test]
    fn rejects_no_wallet_signers() {
        let mut b = TaprootFederationBuilder::<MockSigner>::new(Network::Testnet.into());
        b.add_hsm_signer(MockSigner::hsm(1, Network::Testnet))
            .add_hsm_signer(MockSigner::hsm(2, Network::Testnet));
        let err = b.build().unwrap_err();
        assert!(matches!(err, FederationError::InvalidTaproot(_)));
    }

    #[test]
    fn rejects_taproot_incapable_signer() {
        // MockSigner::with_seed defaults to taproot=false.
        let mut b = TaprootFederationBuilder::<MockSigner>::new(Network::Testnet.into());
        b.add_hsm_signer(MockSigner::hsm(1, Network::Testnet))
            .add_wallet_signer(MockSigner::with_seed(10, Network::Testnet));
        let err = b.build().unwrap_err();
        assert!(matches!(
            err,
            FederationError::MissingCapability { capability: "taproot", .. }
        ));
    }

    #[test]
    fn duplicate_id_across_groups_rejected() {
        let s1 = MockSigner::hsm(7, Network::Testnet);
        let mut b = TaprootFederationBuilder::<MockSigner>::new(Network::Testnet.into());
        b.add_hsm_signer(s1.clone());
        b.add_wallet_signer(s1);
        b.add_hsm_signer(MockSigner::hsm(8, Network::Testnet));
        let err = b.build().unwrap_err();
        assert!(matches!(err, FederationError::DuplicateSigner(_)));
    }
}
