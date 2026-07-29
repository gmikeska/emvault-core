//! Cross-backend reorg **signal-parity** proof (Phase 3 of the reorg-reconcile arc).
//!
//! ## What this proves
//! Greg's bar for the reorg work is *"switch freely between all three chain
//! backends, no app code rewrite."* That holds only if every backend emits the
//! **same** reorg signal for the **same** reorg — not merely "both reach zero
//! balance." This test drives the **identical** reorg-below-tip (§6.2 recipe: a
//! confirmed funding tx `D` permanently double-spent by `D'`) through the
//! **bitcoind-RPC emitter** (`chain_sync::emitter_sync`) and the **electrum**
//! backend (`ElectrumBackend::sync`) against the *same* regtest chain, and asserts:
//!
//! - both report `reorg_rebuilt == true`,
//! - both reach **0 sats** (phantom cleared, D5 eviction), and
//! - **both produce the identical `evicted_txids` set — exactly `[D]`.**
//!
//! The two backends share the watch-only descriptor + funding address, so the
//! evicted txid is the same `D` on both sides; asserting set-equality is the
//! cross-check that the `evicted_txids` signal is backend-agnostic. (esplora shares
//! electrum's rebuild path byte-for-byte; its live proof lands with the
//! test-app-pkcs11 e2e — no esplora regtest harness this session.)
//!
//! ## Harness (see `groupvault/deploy/regtest/`)
//! - regtest bitcoind — JSON-RPC `host.docker.internal:18543` (`regtest`/`regtest`),
//!   wallet `miner`.
//! - Fulcrum electrum server — TCP `host.docker.internal:60011` (indexes the same
//!   chain; lags bitcoind by one poll, so we wait on its tip before each sync).
//!
//! ## Run
//! ```text
//! RPC_REORG_LIVE=1 cargo test -p emvault-core --features electrum \
//!   --test reorg_cross_backend_live -- --nocapture
//! ```
//! Optional overrides: `BITCOIND_RPC`, `BITCOIND_RPC_AUTH`, `MINER_WALLET`,
//! `ELECTRUM_URL`.

// Requires the `electrum` backend to drive the electrum side of the parity check;
// compiled out (and thus skipped) when the feature is off.
#![cfg(feature = "electrum")]
// Live integration harness: a few pedantic lints are noise for a linear, scripted
// regtest scenario.
#![allow(
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::process::Command;
use std::time::{Duration, Instant};

use emvault_core::bdk_wallet::{KeychainKind, Wallet};
use emvault_core::bitcoin::{Network, Txid};
use emvault_core::bitcoincore_rpc::{Auth, Client as RpcClient};
use emvault_core::chain_sync::emitter_sync;
use emvault_core::electrum::ElectrumBackend;
use emvault_core::electrum::electrum_client::{Client as ElectrumClient, ElectrumApi};
use serde_json::{Value, json};

// Neutral watch-only wpkh descriptors (no personal data), identical to the two
// single-backend reorg harnesses so the funding address — and thus the evicted
// txid — is shared across all three backends.
const EXT: &str = "wpkh([8c687226/84h/1h/0h]tpubDDA4qW7KBpEGQMonifLDCfewTzaxRynkd874Mm8xBYJ3W4fbFJbWV2fKvAjmBAu1N13mzXcQ7HHN1REJprMT7T2g85SzYnTRWFUXZji9t2o/0/*)#jvvd6yfn";
const INT: &str = "wpkh([8c687226/84h/1h/0h]tpubDDA4qW7KBpEGQMonifLDCfewTzaxRynkd874Mm8xBYJ3W4fbFJbWV2fKvAjmBAu1N13mzXcQ7HHN1REJprMT7T2g85SzYnTRWFUXZji9t2o/1/*)#rcfv83et";

const FUND_SATS: u64 = 500_000_000; // 5 BTC
const EVICT_FEE_SATS: u64 = 1_000_000; // 0.01 BTC — dwarfs the funding fee, so D' wins

fn skip() -> bool {
    if std::env::var("RPC_REORG_LIVE").is_err() {
        eprintln!("SKIP: set RPC_REORG_LIVE=1 to run the live cross-backend reorg parity test");
        return true;
    }
    false
}

fn rpc_base() -> String {
    std::env::var("BITCOIND_RPC")
        .unwrap_or_else(|_| "http://host.docker.internal:18543".to_string())
}
fn rpc_auth() -> (String, String) {
    let a = std::env::var("BITCOIND_RPC_AUTH").unwrap_or_else(|_| "regtest:regtest".to_string());
    let (u, p) = a.split_once(':').unwrap_or(("regtest", "regtest"));
    (u.to_string(), p.to_string())
}
fn miner_wallet() -> String {
    std::env::var("MINER_WALLET").unwrap_or_else(|_| "miner".to_string())
}
fn electrum_url() -> String {
    std::env::var("ELECTRUM_URL").unwrap_or_else(|_| "tcp://host.docker.internal:60011".to_string())
}

/// Minimal bitcoind JSON-RPC over `curl` (mirrors `drive.sh`) for chain
/// manipulation. Panics on transport or RPC error.
fn curl_rpc(method: &str, params: &Value, wallet: Option<&str>) -> Value {
    let (user, pass) = rpc_auth();
    let url = format!(
        "{}{}",
        rpc_base(),
        wallet.map(|w| format!("/wallet/{w}")).unwrap_or_default()
    );
    let body = json!({"jsonrpc": "1.0", "id": "xbackend", "method": method, "params": params});
    let out = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "60",
            "--user",
            &format!("{user}:{pass}"),
            "--data-binary",
            &body.to_string(),
            "-H",
            "content-type: text/plain;",
            &url,
        ])
        .output()
        .expect("spawn curl");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "rpc {method}: bad JSON: {e}: {}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert!(
        v.get("error").is_none_or(Value::is_null),
        "rpc {method} error: {}",
        v["error"]
    );
    v["result"].clone()
}

fn mine(n: u32) -> u64 {
    let miner = miner_wallet();
    let addr = curl_rpc("getnewaddress", &json!([]), Some(&miner));
    let addr = addr.as_str().expect("getnewaddress");
    curl_rpc("generatetoaddress", &json!([n, addr]), None);
    block_count()
}
fn block_count() -> u64 {
    curl_rpc("getblockcount", &json!([]), None)
        .as_u64()
        .unwrap()
}
fn block_hash(height: u64) -> String {
    curl_rpc("getblockhash", &json!([height]), None)
        .as_str()
        .unwrap()
        .to_string()
}
fn btc(sats: u64) -> f64 {
    sats as f64 / 100_000_000.0
}

/// Poll Fulcrum's tip until it reaches `target` (README lag gotcha: Fulcrum
/// re-indexes on its next poll, so wait between a chain change and an electrum sync).
fn wait_fulcrum(target: u64) {
    let url = electrum_url();
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let tip = ElectrumClient::new(&url)
            .ok()
            .and_then(|c| c.block_headers_subscribe().ok())
            .map(|h| h.height as u64);
        match tip {
            Some(h) if h >= target => {
                eprintln!("fulcrum caught up: tip={h} (>= {target})");
                return;
            }
            _ => {}
        }
        assert!(
            Instant::now() < deadline,
            "fulcrum did not reach height {target} within 90s"
        );
        std::thread::sleep(Duration::from_millis(750));
    }
}

fn fresh_wallet() -> Wallet {
    Wallet::create(EXT.to_string(), INT.to_string())
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .expect("watch-only regtest wallet")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpc_and_electrum_emit_identical_reorg_signal() {
    if skip() {
        return;
    }

    let (user, pass) = rpc_auth();
    let rpc = RpcClient::new(&rpc_base(), Auth::UserPass(user, pass)).expect("rpc client");
    let electrum =
        ElectrumBackend::connect(&electrum_url(), Network::Regtest).expect("connect fulcrum");

    // Two wallets watching the SAME descriptor → SAME funding address on both, so a
    // single funding tx D lands in both wallets and the evicted txid is identical.
    let mut w_rpc = fresh_wallet();
    let mut w_el = fresh_wallet();
    let addr = w_rpc.reveal_next_address(KeychainKind::External).address;
    // Reveal the same index on the electrum wallet so it watches the identical spk.
    let addr_el = w_el.reveal_next_address(KeychainKind::External).address;
    assert_eq!(
        addr.to_string(),
        addr_el.to_string(),
        "shared funding address"
    );
    eprintln!("shared funding address: {addr}");

    // --- Fund D, confirm it, bury it below the tip. ---
    let miner = miner_wallet();
    let d_txid = curl_rpc(
        "sendtoaddress",
        &json!([addr.to_string(), btc(FUND_SATS)]),
        Some(&miner),
    );
    let d_txid = d_txid.as_str().expect("sendtoaddress txid").to_string();
    let d: Txid = d_txid.parse().expect("D txid");
    // Capture D's funding input U (while D is still in the mempool).
    let dv = curl_rpc("getrawtransaction", &json!([d_txid, true]), None);
    let u_txid = dv["vin"][0]["txid"].as_str().unwrap().to_string();
    let u_vout = dv["vin"][0]["vout"].as_u64().unwrap();
    let uv = curl_rpc("getrawtransaction", &json!([u_txid, true]), None);
    let u_value_btc = uv["vout"][u_vout as usize]["value"].as_f64().unwrap();
    eprintln!("D={d_txid}  U={u_txid}:{u_vout} ({u_value_btc} BTC)");

    let h0 = mine(1); // confirm D in B0
    let b0 = block_hash(h0);
    let h_pre = mine(2); // bury B0 two deep
    eprintln!("D confirmed @ B0 height={h0} hash={b0}; pre-reorg tip={h_pre}");

    // --- Both backends sync to the pre-reorg tip and see the funding UTXO. ---
    wait_fulcrum(h_pre);
    let r1_rpc = emitter_sync(&mut w_rpc, &rpc).expect("rpc sync #1");
    let r1_el = electrum.sync(&mut w_el).await.expect("electrum sync #1");
    let bal1_rpc = w_rpc.balance().total().to_sat();
    let bal1_el = w_el.balance().total().to_sat();
    eprintln!(
        "pre-reorg: rpc(tip={} bal={}) electrum(tip={} bal={})",
        r1_rpc.tip_height, bal1_rpc, r1_el.tip_height, bal1_el
    );
    assert_eq!(bal1_rpc, FUND_SATS, "rpc wallet sees funding UTXO");
    assert_eq!(bal1_el, FUND_SATS, "electrum wallet sees funding UTXO");

    // --- The reorg: invalidate B0, double-spend U, mine a strictly longer branch. ---
    curl_rpc("invalidateblock", &json!([b0]), None); // D -> mempool
    let dest = curl_rpc("getnewaddress", &json!([]), Some(&miner));
    let dest = dest.as_str().unwrap();
    let out_sats = (u_value_btc * 100_000_000.0).round() as u64 - EVICT_FEE_SATS;
    let mut outputs = serde_json::Map::new();
    outputs.insert(dest.to_string(), json!(btc(out_sats)));
    let raw = curl_rpc(
        "createrawtransaction",
        &json!([[{"txid": u_txid, "vout": u_vout}], Value::Object(outputs)]),
        None,
    );
    let signed = curl_rpc(
        "signrawtransactionwithwallet",
        &json!([raw.as_str().unwrap()]),
        Some(&miner),
    );
    assert!(
        signed["complete"].as_bool().unwrap_or(false),
        "miner signs the double-spend of U: {signed}"
    );
    let d_prime = curl_rpc(
        "sendrawtransaction",
        &json!([signed["hex"].as_str().unwrap()]),
        None,
    );
    eprintln!("broadcast D' (evicts D): {}", d_prime.as_str().unwrap());
    let h_post = mine((h_pre - block_count()) as u32 + 3);
    assert!(h_post > h_pre, "reorg branch must be strictly longer");
    eprintln!("post-reorg tip={h_post} (was {h_pre})");

    // Confirm the reorg genuinely happened on-chain (independent of the wallets).
    assert_ne!(
        block_hash(h0),
        b0,
        "funding block genuinely replaced on-chain"
    );

    // --- Re-sync both backends over the identical reorg. ---
    wait_fulcrum(h_post);
    let r2_rpc = emitter_sync(&mut w_rpc, &rpc).expect("rpc sync #2 recovers");
    let r2_el = electrum
        .sync(&mut w_el)
        .await
        .expect("electrum sync #2 recovers");
    let bal2_rpc = w_rpc.balance().total().to_sat();
    let bal2_el = w_el.balance().total().to_sat();

    eprintln!("========== CROSS-BACKEND REORG SIGNAL ==========");
    eprintln!(
        "  RPC:      reorg_rebuilt={} evicted={:?} bal={}",
        r2_rpc.reorg_rebuilt, r2_rpc.evicted_txids, bal2_rpc
    );
    eprintln!(
        "  ELECTRUM: reorg_rebuilt={} evicted={:?} bal={}",
        r2_el.reorg_rebuilt, r2_el.evicted_txids, bal2_el
    );
    eprintln!("================================================");

    // (1) Both backends rebuilt.
    assert!(r2_rpc.reorg_rebuilt, "rpc must report reorg_rebuilt=true");
    assert!(
        r2_el.reorg_rebuilt,
        "electrum must report reorg_rebuilt=true"
    );
    // (2) Both reached post-reorg ground truth (phantom cleared).
    assert_eq!(bal2_rpc, 0, "rpc balance → 0 after reorg");
    assert_eq!(bal2_el, 0, "electrum balance → 0 after reorg");
    // (3) THE cross-check: identical evicted_txids set — exactly [D] — on both.
    assert_eq!(r2_rpc.evicted_txids, vec![d], "rpc evicted set == [D]");
    assert_eq!(r2_el.evicted_txids, vec![d], "electrum evicted set == [D]");
    assert_eq!(
        r2_rpc.evicted_txids, r2_el.evicted_txids,
        "RPC and electrum must emit the IDENTICAL evicted_txids set for the same reorg"
    );

    eprintln!(
        "CONCLUSION: RPC and electrum emit the identical reorg signal (reorg_rebuilt=true, \
         evicted=[D], 0 sats) for the same reorg — the signal is backend-agnostic (P0 holds \
         cross-backend), so the app reconcile needs zero backend-specific branches."
    );
}
