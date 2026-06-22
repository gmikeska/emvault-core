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
///
/// ## Elements / Liquid networks
///
/// When `network` is `NetworkType::Elements` (only possible with the
/// `elements` cargo feature), the federation does **not** carry a Bitcoin
/// `miniscript::Descriptor`. The Elements descriptor type
/// (`elements_miniscript::ConfidentialDescriptor`) lives in the
/// [`asterism-elements`](https://docs.rs/asterism-elements) companion
/// crate and is built via `CtDescriptorBuilder`. Calling
/// [`Federation::descriptor`] or [`Federation::descriptor_string`] on an
/// Elements federation will panic with a clear message; use
/// [`Federation::try_descriptor`] for code that needs to handle both
/// network families uniformly.
pub struct Federation<S: Signer = Box<dyn Signer>> {
    threshold: u32,
    signers: Vec<S>,
    /// `None` for Elements federations; the Elements descriptor type lives
    /// in `asterism-elements` and is built separately via
    /// `CtDescriptorBuilder`.
    descriptor: Option<Descriptor<DescriptorPublicKey>>,
    /// Empty for Elements federations. See `descriptor` field comment.
    descriptor_string: String,
    network: NetworkType,
    key_mode: KeyMode,
    created_at: SystemTime,
}

impl<S: Signer + Clone> Clone for Federation<S> {
    fn clone(&self) -> Self {
        Self {
            threshold: self.threshold,
            signers: self.signers.clone(),
            descriptor: self.descriptor.clone(),
            descriptor_string: self.descriptor_string.clone(),
            network: self.network,
            key_mode: self.key_mode,
            created_at: self.created_at,
        }
    }
}

impl<S: Signer> std::fmt::Debug for Federation<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Federation")
            .field("threshold", &self.threshold)
            .field("signer_count", &self.signers.len())
            .field("network", &self.network)
            .field("key_mode", &self.key_mode)
            .field("descriptor", &self.descriptor_string)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
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
    ///
    /// # Errors
    ///
    /// Same conditions as [`Federation::new`], plus [`FederationError::Descriptor`]
    /// if the underlying [`DescriptorBuilder`] rejects the inputs.
    pub fn with_key_mode(
        threshold: u32,
        signers: Vec<S>,
        network: NetworkType,
        key_mode: KeyMode,
    ) -> Result<Self, FederationError> {
        validate_inputs(threshold, &signers, network)?;
        // Bitcoin networks build a `wsh(sortedmulti(...))` descriptor here.
        // Elements networks defer to the `asterism-elements` crate's
        // `CtDescriptorBuilder` and store no Bitcoin descriptor.
        let (descriptor, descriptor_string) = if network.is_bitcoin() {
            let desc = build_descriptor(threshold, &signers, network, key_mode)?;
            let s = desc.to_string();
            (Some(desc), s)
        } else {
            (None, String::new())
        };
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

    /// The canonical Bitcoin output descriptor.
    ///
    /// # Panics
    ///
    /// Panics if this is an Elements federation. Use
    /// [`Federation::try_descriptor`] to handle both network families
    /// uniformly, or build an Elements descriptor via
    /// `asterism_elements::CtDescriptorBuilder`.
    pub fn descriptor(&self) -> &Descriptor<DescriptorPublicKey> {
        self.descriptor.as_ref().expect(
            "Federation::descriptor() called on a non-Bitcoin federation; use \
             asterism_elements::CtDescriptorBuilder for Elements federations or \
             Federation::try_descriptor() for code that handles both",
        )
    }

    /// The canonical Bitcoin output descriptor, if this is a Bitcoin
    /// federation.
    pub fn try_descriptor(&self) -> Option<&Descriptor<DescriptorPublicKey>> {
        self.descriptor.as_ref()
    }

    /// The canonical Bitcoin output descriptor as a string.
    ///
    /// Returns an empty string for Elements federations — see
    /// [`Federation::descriptor`] for the rationale.
    pub fn descriptor_string(&self) -> &str {
        &self.descriptor_string
    }

    /// The Bitcoin descriptor with a `#checksum` suffix appended (in the
    /// standard rust-miniscript format).
    ///
    /// Returns an empty string for Elements federations.
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
    ///
    /// # Errors
    ///
    /// [`FederationError::SignerNotFound`] if `old` is not a member,
    /// [`FederationError::DuplicateSigner`] if `new` is already a member,
    /// or any error returned by [`Self::with_key_mode`].
    pub fn rotate_signer(&self, old: &SignerId, new: &S) -> Result<Self, FederationError> {
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
        Self::with_key_mode(self.threshold, signers, self.network, self.key_mode)
    }

    /// Add `new` to the federation. `n` increases by 1; threshold unchanged.
    ///
    /// # Errors
    ///
    /// [`FederationError::DuplicateSigner`] if `new` is already a member, or
    /// any error returned by [`Self::with_key_mode`].
    pub fn add_signer(&self, new: S) -> Result<Self, FederationError> {
        if self.contains(&new.id()) {
            return Err(FederationError::DuplicateSigner(new.id()));
        }
        let mut signers: Vec<S> = self.signers.clone();
        signers.push(new);
        Self::with_key_mode(self.threshold, signers, self.network, self.key_mode)
    }

    /// Remove the signer with `id`. `n` decreases by 1; threshold unchanged
    /// (must still satisfy `m <= n`).
    ///
    /// # Errors
    ///
    /// [`FederationError::SignerNotFound`] if `id` is not a member, or any
    /// error returned by [`Self::with_key_mode`] (notably
    /// [`FederationError::InsufficientSigners`] if removal would shrink `n`
    /// below 2).
    pub fn remove_signer(&self, id: &SignerId) -> Result<Self, FederationError> {
        if !self.contains(id) {
            return Err(FederationError::SignerNotFound(id.clone()));
        }
        let signers: Vec<S> = self
            .signers
            .iter()
            .filter(|s| &s.id() != id)
            .cloned()
            .collect();
        Self::with_key_mode(self.threshold, signers, self.network, self.key_mode)
    }

    /// Change the signing threshold without modifying the signer set.
    ///
    /// # Errors
    ///
    /// Any error returned by [`Self::with_key_mode`].
    pub fn change_threshold(&self, new_threshold: u32) -> Result<Self, FederationError> {
        let signers: Vec<S> = self.signers.clone();
        Self::with_key_mode(new_threshold, signers, self.network, self.key_mode)
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
    let signer_count = u32::try_from(signers.len()).expect("federation member count fits u32");
    if signers.len() < 2 {
        return Err(FederationError::InsufficientSigners(signer_count));
    }
    if (threshold as usize) > signers.len() {
        return Err(FederationError::ThresholdExceedsSignerCount {
            threshold,
            signers: signer_count,
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
        let f = Federation::new(2, vec![s1, s2, s3], Network::Testnet.into()).unwrap();
        let new = MockSigner::with_seed(99, Network::Testnet);
        let rotated = f.rotate_signer(&id1, &new).unwrap();
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
