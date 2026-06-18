//! Property tests for asterism-core invariants.
//!
//! These complement the per-module unit tests by exercising arbitrary
//! threshold/signer-count combinations and verifying the round-trip
//! invariants documented in the design.
//!
//! Requires the `test-utils` feature for `MockSigner`. Run via:
//! `cargo test -p asterism-core --features test-utils`.
#![cfg(feature = "test-utils")]

use asterism_core::{
    Federation, FederationError, FederationSnapshot, NetworkType, RecoveryTemplate, Signer,
};
use bitcoin::Network;
use proptest::prelude::*;

mod harness {
    use asterism_core::test_utils::MockSigner;
    use asterism_core::Signer;
    use bitcoin::Network;

    pub fn make_signers(seeds: &[u64]) -> Vec<Box<dyn Signer>> {
        seeds
            .iter()
            .map(|&s| Box::new(MockSigner::with_seed(s, Network::Testnet)) as Box<dyn Signer>)
            .collect()
    }

    pub fn make_typed(seeds: &[u64]) -> Vec<MockSigner> {
        seeds
            .iter()
            .map(|&s| MockSigner::with_seed(s, Network::Testnet))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Federation construction invariants
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(60))]

    /// Any valid (m, n) where 1 <= m <= n <= 10 produces a well-formed
    /// federation whose descriptor parses back via miniscript.
    #[test]
    fn arbitrary_m_of_n_produces_parseable_descriptor(
        n in 2u32..=10u32,
        m_offset in 0u32..=9u32,
    ) {
        let n_us = n as usize;
        let m = (m_offset % n).max(1);
        let seeds: Vec<u64> = (1..=n as u64).collect();
        let signers = harness::make_signers(&seeds);
        let fed = Federation::new(m, signers, NetworkType::Bitcoin(Network::Testnet))
            .expect("valid federation");
        prop_assert_eq!(fed.threshold(), m);
        prop_assert_eq!(fed.total_signers(), n_us);

        // Descriptor parses.
        let secp = bitcoin::secp256k1::Secp256k1::new();
        miniscript::Descriptor::<miniscript::DescriptorPublicKey>::parse_descriptor(
            &secp,
            fed.descriptor_string(),
        )
        .expect("descriptor must parse back");
    }

    /// Construction order does not matter: any permutation of the same
    /// signer set yields the same descriptor (sorted-multi canonicalization).
    #[test]
    fn order_independence(seed in any::<u64>()) {
        let mut rng_state = seed;
        let next = |s: &mut u64| { *s = s.wrapping_mul(6364136223846793005).wrapping_add(1); *s };
        let mut perm = vec![1u64, 2, 3, 4, 5];
        // Fisher-Yates with the deterministic LCG above.
        for i in (1..perm.len()).rev() {
            let j = (next(&mut rng_state) as usize) % (i + 1);
            perm.swap(i, j);
        }
        let original = harness::make_signers(&[1, 2, 3, 4, 5]);
        let permuted = harness::make_signers(&perm);
        let f1 = Federation::new(3, original, NetworkType::Bitcoin(Network::Testnet)).unwrap();
        let f2 = Federation::new(3, permuted, NetworkType::Bitcoin(Network::Testnet)).unwrap();
        prop_assert_eq!(f1.descriptor_string(), f2.descriptor_string());
    }

    /// `m > n` is always rejected.
    #[test]
    fn m_above_n_always_rejected(
        n in 2u32..=8u32,
        excess in 1u32..=4u32,
    ) {
        let seeds: Vec<u64> = (1..=n as u64).collect();
        let signers = harness::make_signers(&seeds);
        let m = n + excess;
        let err = Federation::new(m, signers, NetworkType::Bitcoin(Network::Testnet))
            .expect_err("m > n must fail");
        let is_threshold_err =
            matches!(err, FederationError::ThresholdExceedsSignerCount { .. });
        prop_assert!(is_threshold_err);
    }
}

// ---------------------------------------------------------------------------
// JSON round-trip invariants
// ---------------------------------------------------------------------------

#[test]
fn snapshot_canonical_json_round_trip_idempotent() {
    let signers = harness::make_signers(&[1, 2, 3]);
    let fed = Federation::new(2, signers, NetworkType::Bitcoin(Network::Testnet)).unwrap();
    let snap = FederationSnapshot::from_federation(&fed);
    let a = snap.to_canonical_json();
    let parsed: FederationSnapshot = serde_json::from_str(&a).unwrap();
    let b = parsed.to_canonical_json();
    let parsed2: FederationSnapshot = serde_json::from_str(&b).unwrap();
    let c = parsed2.to_canonical_json();
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn recovery_json_round_trip_preserves_checksum() {
    let signers = harness::make_signers(&[10, 11, 12, 13]);
    let fed = Federation::new(3, signers, NetworkType::Bitcoin(Network::Testnet)).unwrap();
    let t = RecoveryTemplate::from_federation(&fed);
    let json = t.to_json().unwrap();
    let parsed = RecoveryTemplate::from_json(&json).unwrap();
    parsed.verify().expect("checksum must verify after round-trip");
    assert_eq!(t.checksum, parsed.checksum);
}

// ---------------------------------------------------------------------------
// Federation mutation invariants
// ---------------------------------------------------------------------------

#[test]
fn add_then_remove_returns_same_descriptor() {
    let original = Federation::new(
        2,
        harness::make_typed(&[1, 2, 3]),
        NetworkType::Bitcoin(Network::Testnet),
    )
    .unwrap();
    let new_signer = asterism_core::test_utils::MockSigner::with_seed(99, Network::Testnet);
    let new_id = new_signer.id();
    let added = original.add_signer(new_signer).unwrap();
    let restored = added.remove_signer(&new_id).unwrap();
    assert_eq!(original.descriptor_string(), restored.descriptor_string());
}

#[test]
fn rotate_then_rotate_back_returns_same_descriptor() {
    let s1 = asterism_core::test_utils::MockSigner::with_seed(1, Network::Testnet);
    let s2 = asterism_core::test_utils::MockSigner::with_seed(2, Network::Testnet);
    let s3 = asterism_core::test_utils::MockSigner::with_seed(3, Network::Testnet);
    let id1 = s1.id();
    let signers = vec![s1.clone(), s2, s3];
    let original = Federation::new(2, signers, NetworkType::Bitcoin(Network::Testnet)).unwrap();
    let replacement = asterism_core::test_utils::MockSigner::with_seed(99, Network::Testnet);
    let replacement_id = replacement.id();
    let rotated = original.rotate_signer(&id1, replacement).unwrap();
    let unrotated = rotated.rotate_signer(&replacement_id, s1).unwrap();
    assert_eq!(original.descriptor_string(), unrotated.descriptor_string());
}
