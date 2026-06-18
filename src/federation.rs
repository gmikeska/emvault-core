//! [`Federation`] — an m-of-n multi-signature group with mutation APIs.
//!
//! `Federation` is **immutable**. Every mutation method (`rotate_signer`,
//! `add_signer`, `remove_signer`, `change_threshold`) returns a fresh
//! `Federation` instance. The library does not move funds — the consuming
//! application must coordinate a migration transaction (see
//! [`crate::migration`]).

use std::collections::HashSet;
use std::time::SystemTime;

use miniscript::{Descriptor, DescriptorPublicKey};

use crate::descriptor::{DescriptorBuilder, KeyMode};
use crate::error::FederationError;
use crate::network::NetworkType;
use crate::signer::{Signer, SignerId};

/// An m-of-n multi-signature federation.
///
/// The generic parameter `S` defaults to `Box<dyn Signer>` so heterogeneous
/// signer collections (HSM + consumer hardware) work out of the box. Concrete
/// `S` types are useful when the consumer wants compile-time access to
/// backend-specific methods.
pub struct Federation<S: Signer = Box<dyn Signer>> {
    threshold: u32,
    signers: Vec<S>,
    descriptor: Descriptor<DescriptorPublicKey>,
    descriptor_string: String,
    network: NetworkType,
    key_mode: KeyMode,
    created_at: SystemTime,
}

impl<S: Signer> std::fmt::Debug for Federation<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Federation")
            .field("threshold", &self.threshold)
            .field("signer_count", &self.signers.len())
            .field("network", &self.network)
            .field("key_mode", &self.key_mode)
            .field("descriptor", &self.descriptor_string)
            .finish()
    }
}

impl<S: Signer> Federation<S> {
    /// Construct a new federation.
    ///
    /// # Errors
    ///
    /// - [`FederationError::ZeroThreshold`] if `threshold == 0`.
    /// - [`FederationError::InsufficientSigners`] if `signers.len() < 2`.
    /// - [`FederationError::ThresholdExceedsSignerCount`] if
    ///   `threshold > signers.len()`.
    /// - [`FederationError::DuplicateSigner`] if two signers share an id.
    /// - [`FederationError::SignerNetworkMismatch`] if any signer does not
    ///   support `network`.
    pub fn new(
        threshold: u32,
        signers: Vec<S>,
        network: NetworkType,
    ) -> Result<Self, FederationError> {
        Self::with_key_mode(threshold, signers, network, KeyMode::default())
    }

    /// Like [`Federation::new`] but with an explicit [`KeyMode`]. Use
    /// [`KeyMode::Ranged`] when all signers are HD-capable consumer hardware
    /// wallets and you want gap-limit-style address derivation.
    pub fn with_key_mode(
        threshold: u32,
        signers: Vec<S>,
        network: NetworkType,
        key_mode: KeyMode,
    ) -> Result<Self, FederationError> {
        validate_inputs(threshold, &signers, network)?;
        let descriptor = build_descriptor(threshold, &signers, network, key_mode)?;
        let descriptor_string = descriptor.to_string();
        Ok(Self {
            threshold,
            signers,
            descriptor,
            descriptor_string,
            network,
            key_mode,
            created_at: SystemTime::now(),
        })
    }

    /// The signing threshold (`m`).
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Total signer count (`n`).
    pub fn total_signers(&self) -> usize {
        self.signers.len()
    }

    /// Borrow the federation's signer set.
    pub fn signers(&self) -> &[S] {
        &self.signers
    }

    /// The federation's network.
    pub fn network(&self) -> NetworkType {
        self.network
    }

    /// The federation's [`KeyMode`].
    pub fn key_mode(&self) -> KeyMode {
        self.key_mode
    }

    /// When the federation was constructed (or last mutated).
    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    /// The canonical output descriptor.
    pub fn descriptor(&self) -> &Descriptor<DescriptorPublicKey> {
        &self.descriptor
    }

    /// The canonical output descriptor as a string.
    pub fn descriptor_string(&self) -> &str {
        &self.descriptor_string
    }

    /// The descriptor with a `#checksum` suffix appended (in the standard
    /// rust-miniscript format).
    pub fn descriptor_with_checksum(&self) -> String {
        // `Descriptor::to_string()` already includes the `#checksum`.
        self.descriptor_string.clone()
    }

    /// Find a signer by id.
    pub fn find(&self, id: &SignerId) -> Option<&S> {
        self.signers.iter().find(|s| &s.id() == id)
    }

    /// True if `id` is a member of this federation.
    pub fn contains(&self, id: &SignerId) -> bool {
        self.find(id).is_some()
    }
}

// ---------------------------------------------------------------------------
// Mutation APIs (return fresh federations)
// ---------------------------------------------------------------------------

impl<S: Signer + Clone> Federation<S> {
    /// Replace `old` with `new`. Returns a new federation with `n` unchanged.
    pub fn rotate_signer(&self, old: &SignerId, new: S) -> Result<Federation<S>, FederationError> {
        if !self.contains(old) {
            return Err(FederationError::SignerNotFound(old.clone()));
        }
        if self.contains(&new.id()) && &new.id() != old {
            return Err(FederationError::DuplicateSigner(new.id()));
        }
        let signers: Vec<S> = self
            .signers
            .iter()
            .map(|s| {
                if &s.id() == old {
                    new.clone()
                } else {
                    s.clone()
                }
            })
            .collect();
        Federation::with_key_mode(self.threshold, signers, self.network, self.key_mode)
    }

    /// Add `new` to the federation. `n` increases by 1; threshold unchanged.
    pub fn add_signer(&self, new: S) -> Result<Federation<S>, FederationError> {
        if self.contains(&new.id()) {
            return Err(FederationError::DuplicateSigner(new.id()));
        }
        let mut signers: Vec<S> = self.signers.iter().cloned().collect();
        signers.push(new);
        Federation::with_key_mode(self.threshold, signers, self.network, self.key_mode)
    }

    /// Remove the signer with `id`. `n` decreases by 1; threshold unchanged
    /// (must still satisfy `m <= n`).
    pub fn remove_signer(&self, id: &SignerId) -> Result<Federation<S>, FederationError> {
        if !self.contains(id) {
            return Err(FederationError::SignerNotFound(id.clone()));
        }
        let signers: Vec<S> = self
            .signers
            .iter()
            .filter(|s| &s.id() != id)
            .cloned()
            .collect();
        Federation::with_key_mode(self.threshold, signers, self.network, self.key_mode)
    }

    /// Change the signing threshold without modifying the signer set.
    pub fn change_threshold(&self, new_threshold: u32) -> Result<Federation<S>, FederationError> {
        let signers: Vec<S> = self.signers.iter().cloned().collect();
        Federation::with_key_mode(new_threshold, signers, self.network, self.key_mode)
    }
}

// ---------------------------------------------------------------------------
// Internal constructor used by TaprootFederationBuilder
// ---------------------------------------------------------------------------

/// Internal constructor surface used by [`crate::TaprootFederationBuilder`].
///
/// Not part of the stable public API — please construct federations through
/// [`Federation::new`] or the Taproot builder.
#[doc(hidden)]
pub struct FederationCtor;

impl FederationCtor {
    /// Build a `Federation` from a pre-constructed descriptor (e.g. one
    /// produced by the Taproot MAST builder). Performs the same input
    /// validation as `Federation::new` but skips descriptor construction.
    pub fn from_parts<S: Signer>(
        threshold: u32,
        signers: Vec<S>,
        network: NetworkType,
        descriptor: Descriptor<DescriptorPublicKey>,
    ) -> Result<Federation<S>, FederationError> {
        validate_inputs(threshold, &signers, network)?;
        let descriptor_string = descriptor.to_string();
        Ok(Federation {
            threshold,
            signers,
            descriptor,
            descriptor_string,
            network,
            // Taproot federations don't fit the wsh KeyMode discriminant; we
            // use Fixed as an inert placeholder for now.
            key_mode: KeyMode::Fixed,
            created_at: SystemTime::now(),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_inputs<S: Signer>(
    threshold: u32,
    signers: &[S],
    network: NetworkType,
) -> Result<(), FederationError> {
    if threshold == 0 {
        return Err(FederationError::ZeroThreshold);
    }
    if signers.len() < 2 {
        return Err(FederationError::InsufficientSigners(signers.len() as u32));
    }
    if (threshold as usize) > signers.len() {
        return Err(FederationError::ThresholdExceedsSignerCount {
            threshold,
            signers: signers.len() as u32,
        });
    }
    let mut seen = HashSet::new();
    for s in signers {
        let id = s.id();
        if !seen.insert(id.clone()) {
            return Err(FederationError::DuplicateSigner(id));
        }
        if !s.supported_networks().contains(&network) {
            return Err(FederationError::SignerNetworkMismatch { id, network });
        }
    }
    Ok(())
}

fn build_descriptor<S: Signer>(
    threshold: u32,
    signers: &[S],
    network: NetworkType,
    key_mode: KeyMode,
) -> Result<Descriptor<DescriptorPublicKey>, FederationError> {
    let mut builder = DescriptorBuilder::new(threshold, network).key_mode(key_mode);
    for s in signers {
        // Treat each S as a `&dyn Signer` via auto-deref of the impl on Box.
        builder.add_signer(s_as_dyn(s))?;
    }
    builder.build().map_err(FederationError::from)
}

// Helper to coerce any `&S` where `S: Signer` into a `&dyn Signer` reference
// without imposing a `Sized` requirement on `S` (works for both concrete
// types and `Box<dyn Signer>`).
fn s_as_dyn<S: Signer>(s: &S) -> &dyn Signer {
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockSigner;
    use bitcoin::Network;

    fn dyn_signers(seeds: &[u64]) -> Vec<Box<dyn Signer>> {
        seeds
            .iter()
            .map(|&s| Box::new(MockSigner::with_seed(s, Network::Testnet)) as Box<dyn Signer>)
            .collect()
    }

    #[test]
    fn build_2_of_3() {
        let f = Federation::new(2, dyn_signers(&[1, 2, 3]), Network::Testnet.into()).unwrap();
        assert_eq!(f.threshold(), 2);
        assert_eq!(f.total_signers(), 3);
        assert!(f.descriptor_string().starts_with("wsh(sortedmulti(2,"));
    }

    #[test]
    fn rejects_zero_threshold() {
        let err = Federation::new(0, dyn_signers(&[1, 2]), Network::Testnet.into()).unwrap_err();
        assert!(matches!(err, FederationError::ZeroThreshold));
    }

    #[test]
    fn rejects_threshold_above_n() {
        let err = Federation::new(4, dyn_signers(&[1, 2, 3]), Network::Testnet.into()).unwrap_err();
        assert!(matches!(
            err,
            FederationError::ThresholdExceedsSignerCount {
                threshold: 4,
                signers: 3
            }
        ));
    }

    #[test]
    fn rejects_too_few_signers() {
        let err = Federation::new(1, dyn_signers(&[1]), Network::Testnet.into()).unwrap_err();
        assert!(matches!(err, FederationError::InsufficientSigners(1)));
    }

    #[test]
    fn rejects_network_mismatch() {
        let s_test = Box::new(MockSigner::with_seed(1, Network::Testnet)) as Box<dyn Signer>;
        let s_main = Box::new(MockSigner::with_seed(2, Network::Bitcoin)) as Box<dyn Signer>;
        let err = Federation::new(2, vec![s_test, s_main], Network::Testnet.into()).unwrap_err();
        assert!(matches!(err, FederationError::SignerNetworkMismatch { .. }));
    }

    #[test]
    fn add_signer_extends_set() {
        let f: Federation = Federation::new(
            2,
            vec![
                Box::new(MockSigner::with_seed(1, Network::Testnet)) as Box<dyn Signer>,
                Box::new(MockSigner::with_seed(2, Network::Testnet)) as Box<dyn Signer>,
                Box::new(MockSigner::with_seed(3, Network::Testnet)) as Box<dyn Signer>,
            ],
            Network::Testnet.into(),
        )
        .unwrap();
        // Use concrete type to satisfy Clone.
        let signers: Vec<MockSigner> = vec![
            MockSigner::with_seed(1, Network::Testnet),
            MockSigner::with_seed(2, Network::Testnet),
        ];
        let typed = Federation::new(1, signers, Network::Testnet.into()).unwrap();
        let added = typed
            .add_signer(MockSigner::with_seed(3, Network::Testnet))
            .unwrap();
        assert_eq!(added.total_signers(), 3);
        // Original federation's descriptor should NOT contain the new signer
        // — verify by descriptor inequality.
        assert_ne!(typed.descriptor_string(), added.descriptor_string());
        // Sanity: dyn version still works.
        assert_eq!(f.total_signers(), 3);
    }

    #[test]
    fn remove_signer_shrinks_set() {
        let s1 = MockSigner::with_seed(1, Network::Testnet);
        let s2 = MockSigner::with_seed(2, Network::Testnet);
        let s3 = MockSigner::with_seed(3, Network::Testnet);
        let id1 = s1.id();
        let f = Federation::new(2, vec![s1, s2, s3], Network::Testnet.into()).unwrap();
        let smaller = f.remove_signer(&id1).unwrap();
        assert_eq!(smaller.total_signers(), 2);
        assert!(!smaller.contains(&id1));
    }

    #[test]
    fn remove_below_threshold_fails() {
        let s1 = MockSigner::with_seed(1, Network::Testnet);
        let s2 = MockSigner::with_seed(2, Network::Testnet);
        let id1 = s1.id();
        let f = Federation::new(2, vec![s1, s2], Network::Testnet.into()).unwrap();
        let err = f.remove_signer(&id1).unwrap_err();
        // n becomes 1, n < 2 → InsufficientSigners; or m=2 > n=1.
        assert!(matches!(
            err,
            FederationError::InsufficientSigners(_)
                | FederationError::ThresholdExceedsSignerCount { .. }
        ));
    }

    #[test]
    fn rotate_signer_replaces_one() {
        let s1 = MockSigner::with_seed(1, Network::Testnet);
        let s2 = MockSigner::with_seed(2, Network::Testnet);
        let s3 = MockSigner::with_seed(3, Network::Testnet);
        let id1 = s1.id();
        let f = Federation::new(2, vec![s1.clone(), s2, s3], Network::Testnet.into()).unwrap();
        let new = MockSigner::with_seed(99, Network::Testnet);
        let rotated = f.rotate_signer(&id1, new.clone()).unwrap();
        assert_eq!(rotated.total_signers(), 3);
        assert!(!rotated.contains(&id1));
        assert!(rotated.contains(&new.id()));
    }

    #[test]
    fn change_threshold_updates_descriptor() {
        let f = Federation::new(
            2,
            vec![
                MockSigner::with_seed(1, Network::Testnet),
                MockSigner::with_seed(2, Network::Testnet),
                MockSigner::with_seed(3, Network::Testnet),
            ],
            Network::Testnet.into(),
        )
        .unwrap();
        let f3 = f.change_threshold(3).unwrap();
        assert_eq!(f3.threshold(), 3);
        assert!(f3.descriptor_string().starts_with("wsh(sortedmulti(3,"));
    }
}
