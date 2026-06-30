//! Live verification of [`emvault_core::chain_sync::emitter_sync`] against a
//! running Bitcoin Core regtest node (E3b).
//!
//! Gated behind the `node-tests` feature. Skips with a printed message when
//! the RPC env vars are absent or the node is unreachable, so the suite still
//! passes cleanly without a configured node.
//!
//! Run with (from inside the container, overriding the host-oriented `.env`):
//! ```bash
//! BITCOIN_RPC_HOST=host.docker.internal \
//!   cargo test -p emvault-core --features "test-utils node-tests" \
//!   --test emitter_sync_live -- --nocapture
//! ```
#![cfg(all(feature = "test-utils", feature = "node-tests"))]

use std::path::PathBuf;

use bitcoin::Network;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use emvault_core::chain_sync::{emitter_sync, init_or_load_wallet};
use emvault_core::{NetworkType, build_federation, test_utils::MockSigner};

/// Best-effort load of `emvault-core/.env`. Does **not** override env vars
/// already set in the process, so a runtime `BITCOIN_RPC_HOST` override (e.g.
/// `host.docker.internal` from inside a container) wins over the file's value.
fn load_env() {
    let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&env_path);
}

/// Build a `bitcoincore_rpc::Client` from env, or print a skip notice and
/// return `None` (missing env or an unreachable node both skip).
fn client_or_skip(test: &str) -> Option<Client> {
    load_env();
    let user = std::env::var("BITCOIN_RPC_USER").ok()?;
    let pass = std::env::var("BITCOIN_RPC_PASSWORD").ok()?;
    let host = std::env::var("BITCOIN_RPC_HOST").ok()?;
    let port = std::env::var("BITCOIN_RPC_PORT").ok()?;
    let url = format!("http://{host}:{port}");
    match Client::new(&url, Auth::UserPass(user, pass)) {
        Ok(client) => match client.get_blockchain_info() {
            Ok(info) => {
                eprintln!(
                    "[{test}] connected to {url} (chain={}, blocks={})",
                    info.chain, info.blocks
                );
                Some(client)
            }
            Err(e) => {
                eprintln!("[{test}] SKIP: node unreachable at {url}: {e}");
                None
            }
        },
        Err(e) => {
            eprintln!("[{test}] SKIP: RPC client init failed: {e}");
            None
        }
    }
}

/// A fresh federation wallet must sync from genesis up to the node's tip, and
/// a second pass must be a no-op (idempotent).
#[test]
fn emitter_sync_reaches_node_tip() {
    let test = "emitter_sync_reaches_node_tip";
    let Some(rpc) = client_or_skip(test) else {
        return;
    };
    let node_tip = u32::try_from(rpc.get_block_count().expect("get_block_count"))
        .expect("regtest tip fits in u32");

    // A real two-path federation descriptor (wsh(sortedmulti(...))/<0;1>/*).
    let signers = vec![
        MockSigner::with_seed(1, Network::Regtest),
        MockSigner::with_seed(2, Network::Regtest),
        MockSigner::with_seed(3, Network::Regtest),
    ];
    let built = build_federation(signers, 2, NetworkType::Bitcoin(Network::Regtest))
        .expect("build_federation");

    let mut loaded = init_or_load_wallet(Network::Regtest, built.descriptor_string, None)
        .expect("init_or_load_wallet");
    assert!(loaded.fresh, "no persisted changeset → fresh wallet");

    let first = emitter_sync(&mut loaded.wallet, &rpc).expect("emitter_sync");
    eprintln!(
        "[{test}] first pass: blocks_synced={}, tip_height={}, mempool_txs={} (node_tip={node_tip})",
        first.blocks_synced, first.tip_height, first.new_mempool_txs
    );
    assert_eq!(
        first.tip_height, node_tip,
        "wallet tip must match the node's tip after a full sync"
    );
    assert!(
        first.blocks_synced >= 1,
        "a fresh wallet on a non-empty chain must connect at least one block"
    );

    // Idempotency: the wallet is already at the tip, so a second pass connects
    // no new blocks and reports the same tip.
    let second = emitter_sync(&mut loaded.wallet, &rpc).expect("second emitter_sync");
    eprintln!(
        "[{test}] second pass: blocks_synced={}, tip_height={}",
        second.blocks_synced, second.tip_height
    );
    assert_eq!(
        second.blocks_synced, 0,
        "an already-synced wallet must pull no new blocks"
    );
    assert_eq!(second.tip_height, node_tip);
}
