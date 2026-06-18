//! Address derivation tests for every descriptor shape Asterism produces.
//!
//! These tests are pure-local: they never touch a network or an HSM. They
//! verify the chain of `Federation` -> `Descriptor` -> `Address` is sound and
//! deterministic for Fixed wsh, Ranged wsh, and Taproot MAST descriptors.
//!
//! Run with: `cargo test -p asterism-core --features test-utils --test address_derivation`.
#![cfg(feature = "test-utils")]

use asterism_core::{
    Federation, FederationSnapshot, NetworkType, RecoveryTemplate, Signer,
    TaprootFederationBuilder, test_utils::MockSigner,
};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use miniscript::{Descriptor, DescriptorPublicKey};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn typed_signers(seeds: &[u64], net: Network) -> Vec<MockSigner> {
    seeds
        .iter()
        .map(|&s| MockSigner::with_seed(s, net))
        .collect()
}

fn dyn_signers(seeds: &[u64], net: Network) -> Vec<Box<dyn Signer>> {
    seeds
        .iter()
        .map(|&s| Box::new(MockSigner::with_seed(s, net)) as Box<dyn Signer>)
        .collect()
}

fn hsm_signers(seeds: &[u64], net: Network) -> Vec<MockSigner> {
    seeds.iter().map(|&s| MockSigner::hsm(s, net)).collect()
}

/// Derive the address at index 0 for any descriptor (works for both
/// wildcard-bearing and definite descriptors — `at_derivation_index` is a
/// no-op when no wildcards are present).
fn derive_address(desc: &Descriptor<DescriptorPublicKey>, net: Network) -> Address {
    desc.at_derivation_index(0)
        .expect("derivation index 0 always valid")
        .address(net)
        .expect("descriptor must produce an address")
}

fn derive_address_at(desc: &Descriptor<DescriptorPublicKey>, net: Network, idx: u32) -> Address {
    desc.at_derivation_index(idx)
        .expect("valid derivation index")
        .address(net)
        .expect("descriptor must produce an address")
}

fn parse_descriptor(s: &str) -> Descriptor<DescriptorPublicKey> {
    let secp = Secp256k1::new();
    Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, s)
        .expect("descriptor must parse")
        .0
}

// ---------------------------------------------------------------------------
// Fixed-mode wsh
// ---------------------------------------------------------------------------

#[test]
fn fixed_mode_yields_p2wsh_testnet_address() {
    let fed: Federation = Federation::new(
        2,
        dyn_signers(&[1, 2, 3], Network::Testnet),
        Network::Testnet.into(),
    )
    .expect("valid federation");
    let addr = derive_address(fed.descriptor(), Network::Testnet);
    assert_eq!(addr.address_type(), Some(bitcoin::AddressType::P2wsh));
    let s = addr.to_string();
    assert!(
        s.starts_with("tb1q"),
        "expected testnet P2WSH (tb1q...) prefix, got {s}"
    );
}

#[test]
fn fixed_mode_address_is_deterministic_across_builds() {
    let f1: Federation = Federation::new(
        2,
        dyn_signers(&[1, 2, 3], Network::Testnet),
        Network::Testnet.into(),
    )
    .unwrap();
    let f2: Federation = Federation::new(
        2,
        dyn_signers(&[3, 1, 2], Network::Testnet),
        Network::Testnet.into(),
    )
    .unwrap();
    let a1 = derive_address(f1.descriptor(), Network::Testnet);
    let a2 = derive_address(f2.descriptor(), Network::Testnet);
    assert_eq!(a1, a2, "sortedmulti must canonicalize order");
}

#[test]
fn fixed_mode_descriptor_script_pubkey_matches_address_script() {
    let fed: Federation = Federation::new(
        2,
        dyn_signers(&[1, 2, 3], Network::Testnet),
        Network::Testnet.into(),
    )
    .unwrap();
    let definite = fed.descriptor().at_derivation_index(0).unwrap();
    let addr = definite.address(Network::Testnet).unwrap();
    assert_eq!(definite.script_pubkey(), addr.script_pubkey());
}

// ---------------------------------------------------------------------------
// Ranged-mode wsh
// ---------------------------------------------------------------------------

#[test]
fn ranged_mode_yields_distinct_addresses_per_index() {
    use asterism_core::descriptor::{DescriptorBuilder, KeyMode};

    let signers = typed_signers(&[1, 2, 3], Network::Testnet);
    let mut b =
        DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet)).key_mode(KeyMode::Ranged);
    for s in &signers {
        b.add_signer(s).unwrap();
    }
    let desc = b.build().unwrap();

    let indexes = [0u32, 1, 2, 5, 100];
    let mut seen = std::collections::HashSet::new();
    for idx in indexes {
        let a = derive_address_at(&desc, Network::Testnet, idx);
        assert_eq!(a.address_type(), Some(bitcoin::AddressType::P2wsh));
        assert!(
            a.to_string().starts_with("tb1q"),
            "expected testnet P2WSH at index {idx}, got {a}"
        );
        assert!(
            seen.insert(a),
            "address at index {idx} collided with a prior index"
        );
    }
    assert_eq!(seen.len(), indexes.len());
}

// ---------------------------------------------------------------------------
// Taproot MAST
// ---------------------------------------------------------------------------

#[test]
fn taproot_mast_yields_p2tr_testnet_address() {
    let mut b = TaprootFederationBuilder::<MockSigner>::new(Network::Testnet.into());
    for s in hsm_signers(&[1, 2], Network::Testnet) {
        b.add_hsm_signer(s);
    }
    for s in hsm_signers(&[10, 11], Network::Testnet) {
        b.add_wallet_signer(s);
    }
    b.mixed_threshold(2);
    let fed = b.build().unwrap();
    let addr = derive_address(fed.descriptor(), Network::Testnet);
    assert_eq!(addr.address_type(), Some(bitcoin::AddressType::P2tr));
    assert!(
        addr.to_string().starts_with("tb1p"),
        "expected testnet P2TR (tb1p...) prefix, got {addr}"
    );
}

#[test]
fn taproot_mast_address_is_deterministic() {
    let build = || -> Federation<MockSigner> {
        let mut b = TaprootFederationBuilder::<MockSigner>::new(Network::Testnet.into());
        for s in hsm_signers(&[1, 2], Network::Testnet) {
            b.add_hsm_signer(s);
        }
        for s in hsm_signers(&[10, 11], Network::Testnet) {
            b.add_wallet_signer(s);
        }
        b.mixed_threshold(2);
        b.build().unwrap()
    };
    let a1 = derive_address(build().descriptor(), Network::Testnet);
    let a2 = derive_address(build().descriptor(), Network::Testnet);
    assert_eq!(a1, a2);
}

// ---------------------------------------------------------------------------
// Mutations preserve derivability and shift addresses where expected
// ---------------------------------------------------------------------------

#[test]
fn add_signer_changes_address() {
    let original: Federation<MockSigner> = Federation::new(
        2,
        typed_signers(&[1, 2, 3], Network::Testnet),
        Network::Testnet.into(),
    )
    .unwrap();
    let extended = original
        .add_signer(MockSigner::with_seed(99, Network::Testnet))
        .unwrap();
    let a_orig = derive_address(original.descriptor(), Network::Testnet);
    let a_ext = derive_address(extended.descriptor(), Network::Testnet);
    assert_ne!(a_orig, a_ext);
    assert_eq!(a_orig.address_type(), Some(bitcoin::AddressType::P2wsh));
    assert_eq!(a_ext.address_type(), Some(bitcoin::AddressType::P2wsh));
}

#[test]
fn remove_signer_changes_address() {
    let signers = typed_signers(&[1, 2, 3, 4], Network::Testnet);
    let id_to_remove = signers[0].id();
    let original: Federation<MockSigner> =
        Federation::new(2, signers, Network::Testnet.into()).unwrap();
    let smaller = original.remove_signer(&id_to_remove).unwrap();
    let a_orig = derive_address(original.descriptor(), Network::Testnet);
    let a_small = derive_address(smaller.descriptor(), Network::Testnet);
    assert_ne!(a_orig, a_small);
}

#[test]
fn rotate_signer_changes_address() {
    let signers = typed_signers(&[1, 2, 3], Network::Testnet);
    let id_old = signers[0].id();
    let original: Federation<MockSigner> =
        Federation::new(2, signers, Network::Testnet.into()).unwrap();
    let replacement = MockSigner::with_seed(42, Network::Testnet);
    let rotated = original.rotate_signer(&id_old, &replacement).unwrap();
    let a_orig = derive_address(original.descriptor(), Network::Testnet);
    let a_rot = derive_address(rotated.descriptor(), Network::Testnet);
    assert_ne!(a_orig, a_rot);
}

#[test]
fn change_threshold_changes_address() {
    let original: Federation<MockSigner> = Federation::new(
        2,
        typed_signers(&[1, 2, 3], Network::Testnet),
        Network::Testnet.into(),
    )
    .unwrap();
    let stricter = original.change_threshold(3).unwrap();
    let a_orig = derive_address(original.descriptor(), Network::Testnet);
    let a_strict = derive_address(stricter.descriptor(), Network::Testnet);
    assert_ne!(a_orig, a_strict);
}

// ---------------------------------------------------------------------------
// Recovery / Snapshot derivation parity
// ---------------------------------------------------------------------------

#[test]
fn recovery_template_descriptor_matches_federation_address() {
    let fed: Federation = Federation::new(
        3,
        dyn_signers(&[10, 11, 12, 13], Network::Testnet),
        Network::Testnet.into(),
    )
    .unwrap();
    let template = RecoveryTemplate::from_federation(&fed);
    let parsed = parse_descriptor(&template.descriptor);
    let a_fed = derive_address(fed.descriptor(), Network::Testnet);
    let a_template = derive_address(&parsed, Network::Testnet);
    assert_eq!(a_fed, a_template);
}

#[test]
fn snapshot_descriptor_matches_federation_address() {
    let fed: Federation = Federation::new(
        2,
        dyn_signers(&[7, 8, 9], Network::Testnet),
        Network::Testnet.into(),
    )
    .unwrap();
    let snapshot = FederationSnapshot::from_federation(&fed);
    let parsed = parse_descriptor(&snapshot.descriptor);
    let a_fed = derive_address(fed.descriptor(), Network::Testnet);
    let a_snap = derive_address(&parsed, Network::Testnet);
    assert_eq!(a_fed, a_snap);
}

#[test]
fn snapshot_descriptor_for_taproot_matches_federation_address() {
    let mut b = TaprootFederationBuilder::<MockSigner>::new(Network::Testnet.into());
    for s in hsm_signers(&[1, 2], Network::Testnet) {
        b.add_hsm_signer(s);
    }
    for s in hsm_signers(&[10, 11], Network::Testnet) {
        b.add_wallet_signer(s);
    }
    b.mixed_threshold(2);
    let fed = b.build().unwrap();
    let snapshot = FederationSnapshot::from_federation(&fed);
    let parsed = parse_descriptor(&snapshot.descriptor);
    let a_fed = derive_address(fed.descriptor(), Network::Testnet);
    let a_snap = derive_address(&parsed, Network::Testnet);
    assert_eq!(a_fed, a_snap);
    assert_eq!(a_fed.address_type(), Some(bitcoin::AddressType::P2tr));
}

// ---------------------------------------------------------------------------
// Network differentiation
// ---------------------------------------------------------------------------

#[test]
fn mainnet_and_testnet_addresses_differ() {
    let f_test: Federation = Federation::new(
        2,
        dyn_signers(&[1, 2, 3], Network::Testnet),
        Network::Testnet.into(),
    )
    .unwrap();
    let f_main: Federation = Federation::new(
        2,
        dyn_signers(&[1, 2, 3], Network::Bitcoin),
        Network::Bitcoin.into(),
    )
    .unwrap();
    let a_test = derive_address(f_test.descriptor(), Network::Testnet);
    let a_main = derive_address(f_main.descriptor(), Network::Bitcoin);
    assert!(a_test.to_string().starts_with("tb1q"));
    assert!(a_main.to_string().starts_with("bc1q"));
    assert_ne!(a_test.to_string(), a_main.to_string());
}

#[test]
fn signet_address_uses_testnet_hrp() {
    // Signet uses the same `tb` HRP as testnet; this test pins that
    // expectation so a future bitcoin-rs change is caught early.
    let f_signet: Federation = Federation::new(
        2,
        dyn_signers(&[1, 2, 3], Network::Signet),
        Network::Signet.into(),
    )
    .unwrap();
    let a = derive_address(f_signet.descriptor(), Network::Signet);
    assert!(
        a.to_string().starts_with("tb1q"),
        "signet shares testnet HRP, got {a}"
    );
}
