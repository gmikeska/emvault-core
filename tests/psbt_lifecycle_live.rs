//! Live verification of the `emvault_core::psbt` synchronous primitives
//! against a running Bitcoin Core regtest node (E4).
//!
//! Exercises the full extracted lifecycle end-to-end:
//!
//! ```text
//! build_spend ─► wallet.sign(try_finalize:false) ─► finalize_and_extract ─► broadcast
//! ```
//!
//! against the funded regtest `default` wallet, asserting the broadcast txid
//! lands in the mempool and then confirms in the next block.
//!
//! Gated behind the `node-tests` feature. Skips with a printed message when the
//! RPC env vars are absent or the node is unreachable, so the suite still
//! passes cleanly without a configured node.
//!
//! Run with (from inside the container, overriding the host-oriented `.env`):
//! ```bash
//! BITCOIN_RPC_HOST=host.docker.internal \
//!   cargo test -p emvault-core --features node-tests \
//!   --test psbt_lifecycle_live -- --nocapture
//! ```
#![cfg(feature = "node-tests")]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use emvault_core::chain_sync::emitter_sync;
use emvault_core::psbt::{build_spend, finalize_and_extract};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use bitcoin::bip32::Xpriv;
use bitcoin::{Amount, FeeRate, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};

/// Best-effort load of `emvault-core/.env`. Does **not** override env vars
/// already set in the process, so a runtime `BITCOIN_RPC_HOST` override (e.g.
/// `host.docker.internal` from inside a container) wins over the file's value.
fn load_env() {
    let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&env_path);
}

/// RPC connection parameters pulled from the environment.
struct RpcEnv {
    url: String,
    auth: Auth,
}

/// Read RPC params from env, or print a skip notice and return `None`.
fn rpc_env_or_skip(test: &str) -> Option<RpcEnv> {
    load_env();
    let user = std::env::var("BITCOIN_RPC_USER").ok();
    let pass = std::env::var("BITCOIN_RPC_PASSWORD").ok();
    let host = std::env::var("BITCOIN_RPC_HOST").ok();
    let port = std::env::var("BITCOIN_RPC_PORT").ok();
    let (Some(user), Some(pass), Some(host), Some(port)) = (user, pass, host, port) else {
        eprintln!("[{test}] SKIP: BITCOIN_RPC_* env vars not all set");
        return None;
    };
    Some(RpcEnv {
        url: format!("http://{host}:{port}"),
        auth: Auth::UserPass(user, pass),
    })
}

/// Connect a base (non-wallet) client and confirm the node is reachable.
fn base_client_or_skip(test: &str, env: &RpcEnv) -> Option<Client> {
    let client = match Client::new(&env.url, env.auth.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[{test}] SKIP: RPC client init failed: {e}");
            return None;
        }
    };
    match client.get_blockchain_info() {
        Ok(info) => {
            eprintln!(
                "[{test}] connected to {} (chain={}, blocks={})",
                env.url, info.chain, info.blocks
            );
            Some(client)
        }
        Err(e) => {
            eprintln!("[{test}] SKIP: node unreachable at {}: {e}", env.url);
            None
        }
    }
}

/// A unique 32-byte seed per run so each invocation uses a fresh descriptor
/// (and therefore fresh, un-spent addresses) — no cross-run UTXO interference.
fn fresh_seed() -> [u8; 32] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let mut seed = [0u8; 32];
    for (i, b) in nanos.to_le_bytes().iter().cycle().take(32).enumerate() {
        seed[i] = *b;
    }
    seed
}

/// Full PSBT lifecycle against the live node: fund a fresh signable single-sig
/// wallet, build → sign → finalize → broadcast a real spend, and assert it
/// lands in the mempool and confirms.
#[test]
fn psbt_lifecycle_reaches_mempool_and_confirms() {
    let test = "psbt_lifecycle_reaches_mempool_and_confirms";
    let Some(env) = rpc_env_or_skip(test) else {
        return;
    };
    let Some(base) = base_client_or_skip(test, &env) else {
        return;
    };
    // Wallet-scoped client for the funding `default` wallet (sendtoaddress,
    // getnewaddress, generatetoaddress, gettransaction all need a wallet path).
    let wallet_url = format!("{}/wallet/default", env.url);
    let funder = Client::new(&wallet_url, env.auth.clone()).expect("wallet rpc client");

    // A fresh, signable single-sig wallet (xprv embedded → BDK derives the
    // signer automatically). Single-path external/internal descriptors —
    // miniscript rejects a *multipath* private key, so we split the keychains.
    let xpriv = Xpriv::new_master(Network::Regtest, &fresh_seed()).expect("valid master");
    let external = format!("wpkh({xpriv}/84h/1h/0h/0/*)");
    let internal = format!("wpkh({xpriv}/84h/1h/0h/1/*)");
    let mut wallet = Wallet::create(external, internal)
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .expect("create signable single-sig wallet");

    // Fund the wallet by mining a coinbase straight to its first receive
    // address, then mining past the 100-block coinbase maturity window. This
    // sidesteps the node wallet's fee estimation (regtest disables
    // `fallbackfee`, so `sendtoaddress` would fail).
    let receive = wallet.reveal_next_address(KeychainKind::External).address;
    eprintln!("[{test}] funding {receive} via coinbase");
    let mine_to = funder
        .get_new_address(None, None)
        .expect("get_new_address (mine target)")
        .assume_checked();
    base.generate_to_address(1, &receive)
        .expect("generate_to_address (coinbase to wallet)");
    // 100 + slack confirmations so the coinbase matures and is spendable.
    base.generate_to_address(101, &mine_to)
        .expect("generate_to_address (mature coinbase)");

    // Sync the wallet so it sees the confirmed UTXO (E3b primitive).
    let sync = emitter_sync(&mut wallet, &base).expect("emitter_sync");
    eprintln!(
        "[{test}] synced to tip {} (blocks_synced={})",
        sync.tip_height, sync.blocks_synced
    );
    let balance = wallet.balance();
    assert!(
        balance.confirmed > Amount::from_sat(100_000),
        "wallet should see a matured coinbase UTXO, saw {} (immature={})",
        balance.confirmed,
        balance.immature
    );

    // --- build_spend (core primitive) ---
    let dest = funder
        .get_new_address(None, None)
        .expect("get_new_address (spend dest)")
        .assume_checked();
    // Spend half the balance; the remainder comfortably covers fee + change.
    let amount = Amount::from_sat(balance.confirmed.to_sat() / 2);
    let fee_rate = FeeRate::from_sat_per_vb(2).expect("non-zero fee rate");
    let mut psbt =
        build_spend(&mut wallet, dest.script_pubkey(), amount, fee_rate).expect("build_spend");

    // --- sign without finalizing (mirrors the apps' try_finalize:false path) ---
    let sign_only = SignOptions {
        try_finalize: false,
        ..SignOptions::default()
    };
    // `Wallet::sign` returns the *finalized* status, which is `false` under
    // `try_finalize:false` even though signatures were added — so we assert on
    // the partial-signature count, not the return value.
    let _finalized = wallet.sign(&mut psbt, sign_only).expect("wallet.sign");
    let partials: usize = psbt.inputs.iter().map(|i| i.partial_sigs.len()).sum();
    assert!(
        partials >= 1,
        "try_finalize:false must leave partial signatures in place, found {partials}"
    );

    // --- finalize_and_extract (core primitive) ---
    let (tx, txid) = finalize_and_extract(&wallet, psbt).expect("finalize_and_extract");
    eprintln!("[{test}] finalized tx {txid}");

    // --- broadcast (app-layer in production; done directly here) ---
    let broadcast_txid = base
        .send_raw_transaction(&tx)
        .expect("send_raw_transaction");
    assert_eq!(
        broadcast_txid, txid,
        "broadcast txid must match the extracted transaction's txid"
    );

    // Mempool assertion.
    let mempool = base.get_raw_mempool().expect("get_raw_mempool");
    assert!(
        mempool.contains(&txid),
        "broadcast txid {txid} must appear in the mempool"
    );

    // Confirm it in the next block.
    base.generate_to_address(1, &mine_to)
        .expect("generate_to_address (confirm spend)");
    let gt = funder
        .get_transaction(&txid, None)
        .expect("get_transaction after confirmation");
    assert!(
        gt.info.confirmations >= 1,
        "spend must confirm; confirmations={}",
        gt.info.confirmations
    );
    eprintln!(
        "[{test}] confirmed tx {txid} ({} confirmations)",
        gt.info.confirmations
    );
}
