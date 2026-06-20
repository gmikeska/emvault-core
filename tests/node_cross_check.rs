//! Cross-validate Asterism's locally-derived descriptors and addresses
//! against a running Bitcoin Core node via JSON-RPC.
//!
//! Gated behind the `node-tests` feature. Tests skip with a printed message
//! when the node is unreachable, so the suite passes cleanly without a
//! configured node.
//!
//! Run with:
//! ```bash
//! cargo test -p asterism-core --features "test-utils node-tests" \
//!   --test node_cross_check -- --nocapture
//! ```
#![cfg(all(feature = "test-utils", feature = "node-tests"))]

use asterism_core::{Federation, NetworkType, Signer, test_utils::MockSigner};
use bitcoin::Network;
use miniscript::{Descriptor, DescriptorPublicKey};

mod common;

use common::rpc::RpcClient;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Acquire an `RpcClient` or print a skip notice and return `None`.
fn rpc_or_skip(test_name: &str) -> Option<RpcClient> {
    let Some(c) = RpcClient::from_env() else {
        eprintln!("[{test_name}] SKIP: BITCOIN_RPC_* env vars not set");
        return None;
    };
    match c.getblockchaininfo() {
        Ok(info) => {
            let chain = info
                .get("chain")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let ibd = info
                .get("initialblockdownload")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            eprintln!(
                "[{test_name}] connected to {chain} (IBD={ibd}, label={label})",
                label = c.network_label,
            );
            Some(c)
        }
        Err(e) => {
            eprintln!("[{test_name}] SKIP: bitcoind getblockchaininfo failed: {e}");
            None
        }
    }
}

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

/// Derive the address at `idx` from a descriptor (works for both wildcard
/// and non-wildcard descriptors).
fn local_address_at(
    desc: &Descriptor<DescriptorPublicKey>,
    net: Network,
    idx: u32,
) -> bitcoin::Address {
    desc.at_derivation_index(idx)
        .expect("derivation index in range")
        .address(net)
        .expect("descriptor must produce an address")
}

/// Strip a `#checksum` suffix from a descriptor string if present.
fn strip_checksum(s: &str) -> &str {
    s.split_once('#').map_or(s, |(d, _)| d)
}

/// Compare a Bitcoin Core descriptor (potentially decorated by core) to the
/// asterism-produced descriptor. Both must produce the same checksum.
fn assert_descriptors_equivalent(local: &str, remote: &str, remote_checksum: &str) {
    // Bitcoin Core canonicalizes `sortedmulti` sometimes by reordering
    // pre-derivation; the checksum comparison is the strongest invariant.
    let local_no_ck = strip_checksum(local);
    let remote_no_ck = strip_checksum(remote);
    assert_eq!(
        local_no_ck, remote_no_ck,
        "descriptor body should match bit-for-bit\n  local : {local_no_ck}\n  remote: {remote_no_ck}"
    );
    if let Some((_, local_ck)) = local.split_once('#') {
        assert_eq!(local_ck, remote_checksum, "checksum mismatch");
    }
}

// ---------------------------------------------------------------------------
// Connectivity smoke test
// ---------------------------------------------------------------------------

#[test]
fn connects_to_bitcoind() {
    let Some(c) = rpc_or_skip("connects_to_bitcoind") else {
        return;
    };
    let info = c.getblockchaininfo().expect("getblockchaininfo");
    assert!(
        info.get("chain").and_then(|v| v.as_str()).is_some(),
        "expected 'chain' field in getblockchaininfo response"
    );
}

// ---------------------------------------------------------------------------
// Fixed-mode wsh (no wildcard, single address)
// ---------------------------------------------------------------------------

#[test]
fn fixed_wsh_descriptor_round_trips_through_core() {
    let Some(c) = rpc_or_skip("fixed_wsh_descriptor_round_trips_through_core") else {
        return;
    };
    let fed: Federation = Federation::new(
        2,
        dyn_signers(&[1, 2, 3], Network::Testnet),
        Network::Testnet.into(),
    )
    .unwrap();
    let local_desc = fed.descriptor_string().to_string();
    let info = c.getdescriptorinfo(&local_desc).expect("getdescriptorinfo");
    assert!(!info.isrange, "Fixed-mode descriptor should be non-ranged");
    assert_descriptors_equivalent(&local_desc, &info.descriptor, &info.checksum);

    // Without isrange, deriveaddresses must NOT take a range param.
    let addrs = c
        .deriveaddresses(&info.descriptor, None)
        .expect("deriveaddresses (no range)");
    assert_eq!(addrs.len(), 1, "Fixed mode yields a single address");

    let local_addr = local_address_at(fed.descriptor(), Network::Testnet, 0);
    assert_eq!(
        addrs[0],
        local_addr.to_string(),
        "address must match local derivation"
    );
}

// ---------------------------------------------------------------------------
// Ranged-mode wsh (with /0/* wildcard)
// ---------------------------------------------------------------------------

#[test]
fn ranged_wsh_descriptor_round_trips_through_core() {
    use asterism_core::descriptor::{DescriptorBuilder, KeyMode};

    let Some(c) = rpc_or_skip("ranged_wsh_descriptor_round_trips_through_core") else {
        return;
    };
    let signers = typed_signers(&[1, 2, 3], Network::Testnet);
    let mut b =
        DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet)).key_mode(KeyMode::Ranged);
    for s in &signers {
        b.add_signer(s).unwrap();
    }
    let desc = b.build().unwrap();
    let local_desc = desc.to_string();

    let info = c.getdescriptorinfo(&local_desc).expect("getdescriptorinfo");
    assert!(info.isrange, "Ranged-mode descriptor should be ranged");
    assert_descriptors_equivalent(&local_desc, &info.descriptor, &info.checksum);

    // Derive indexes 0..=4 on both sides and compare.
    let remote = c
        .deriveaddresses(&info.descriptor, Some([0, 4]))
        .expect("deriveaddresses 0..=4");
    assert_eq!(
        remote.len(),
        5,
        "expected 5 addresses for inclusive range 0..=4"
    );
    for (i, remote_addr) in remote.iter().enumerate() {
        let idx = u32::try_from(i).unwrap();
        let local = local_address_at(&desc, Network::Testnet, idx).to_string();
        assert_eq!(
            *remote_addr, local,
            "address mismatch at index {idx}\n  local : {local}\n  remote: {remote_addr}"
        );
    }
}
