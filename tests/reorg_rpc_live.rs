//! Live regtest reorg test for the **bitcoind-RPC emitter** backend
//! ([`emvault_core::chain_sync::emitter_sync`]).
//!
//! ## What this proves (Step 1.5 of the reorg-reconcile arc)
//! After a **reorg-below-the-persisted-tip** that permanently double-spends the
//! funding input, the bitcoind-RPC backend must reach the **same** post-reorg
//! ground truth as electrum/esplora: the reverted tx **absent entirely** (D5),
//! balance 0, with `evicted_txids == [D]` and `reorg_rebuilt == true`.
//!
//! Phase 1 (characterization) proved the raw emitter surfaces a reorg-below-tip as
//! an [`emvault_core::bdk_wallet::chain::local_chain::ApplyHeaderError::CannotConnect`]
//! and left the wallet frozen/stale. Step 1.5 makes
//! [`emvault_core::chain_sync::emitter_sync`] *catch* that and rebuild from genesis
//! in place, so `sync()` returns `Ok` at ground truth — establishing precondition
//! **P0** (every backend's sync leaves the wallet post-reorg-truthful) for the RPC
//! path. This test now asserts that recovered behavior, not the bare error.
//!
//! ## Harness (see `groupvault/deploy/regtest/`)
//! - regtest bitcoind — JSON-RPC `host.docker.internal:18543` (user/pass
//!   `regtest`/`regtest`), wallet `miner`.
//! - No Electrum/Fulcrum needed: the emitter talks to bitcoind directly.
//!
//! ## Run
//! ```text
//! RPC_REORG_LIVE=1 cargo test -p emvault-core --test reorg_rpc_live -- --nocapture
//! ```
//! Optional overrides: `BITCOIND_RPC`, `BITCOIND_RPC_AUTH`, `MINER_WALLET`.

// Live integration harness: a few pedantic lints are noise for a linear,
// scripted regtest scenario.
#![allow(
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::process::Command;

use emvault_core::bdk_wallet::chain::ChainPosition;
use emvault_core::bdk_wallet::{KeychainKind, Wallet};
use emvault_core::bitcoin::{Network, Txid};
use emvault_core::bitcoincore_rpc::{Auth, Client, RpcApi};
use emvault_core::chain_sync::emitter_sync;
use serde_json::{Value, json};

// Neutral watch-only wpkh descriptors (no personal data). tpub key material is
// testnet-encoded, which BDK accepts for `Network::Regtest`; addresses render as
// `bcrt1…`. Reused verbatim from the electrum live_reorg harness.
const EXT: &str = "wpkh([8c687226/84h/1h/0h]tpubDDA4qW7KBpEGQMonifLDCfewTzaxRynkd874Mm8xBYJ3W4fbFJbWV2fKvAjmBAu1N13mzXcQ7HHN1REJprMT7T2g85SzYnTRWFUXZji9t2o/0/*)#jvvd6yfn";
const INT: &str = "wpkh([8c687226/84h/1h/0h]tpubDDA4qW7KBpEGQMonifLDCfewTzaxRynkd874Mm8xBYJ3W4fbFJbWV2fKvAjmBAu1N13mzXcQ7HHN1REJprMT7T2g85SzYnTRWFUXZji9t2o/1/*)#rcfv83et";

const FUND_SATS: u64 = 500_000_000; // 5 BTC
const EVICT_FEE_SATS: u64 = 1_000_000; // 0.01 BTC — dwarfs the funding fee, so D' replaces D via RBF

fn skip() -> bool {
    if std::env::var("RPC_REORG_LIVE").is_err() {
        eprintln!("SKIP: set RPC_REORG_LIVE=1 to run the live regtest RPC-emitter reorg test");
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

/// Minimal bitcoind JSON-RPC over `curl` (mirrors `drive.sh`) for chain
/// manipulation. `wallet` is an optional `/wallet/<name>` path suffix. Panics on
/// transport or RPC error. (We use the typed `bitcoincore_rpc::Client` only for
/// the emitter under test; curl keeps the scripted manipulation identical to the
/// proven electrum harness and dodges typed-arg friction.)
fn curl_rpc(method: &str, params: &Value, wallet: Option<&str>) -> Value {
    let (user, pass) = rpc_auth();
    let url = format!(
        "{}{}",
        rpc_base(),
        wallet.map(|w| format!("/wallet/{w}")).unwrap_or_default()
    );
    let body =
        json!({"jsonrpc": "1.0", "id": "reorg-rpc-test", "method": method, "params": params});
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

/// Describe the wallet's view of a specific txid: absent / unconfirmed / confirmed.
fn tx_state(wallet: &Wallet, txid: Txid) -> String {
    match wallet.get_tx(txid) {
        None => "ABSENT (not in graph)".to_string(),
        Some(wtx) => match wtx.chain_position {
            ChainPosition::Confirmed { anchor, .. } => {
                format!("CONFIRMED @ height {}", anchor.block_id.height)
            }
            ChainPosition::Unconfirmed {
                last_seen,
                first_seen,
            } => {
                format!("UNCONFIRMED (first_seen={first_seen:?}, last_seen={last_seen:?})")
            }
        },
    }
}

#[test]
fn reorg_below_persisted_tip_rpc_emitter() {
    if skip() {
        return;
    }

    let (user, pass) = rpc_auth();
    let rpc = Client::new(&rpc_base(), Auth::UserPass(user, pass)).expect("rpc client");
    let node_tip = rpc.get_block_count().expect("get_block_count");
    eprintln!("connected to bitcoind; node tip={node_tip}");

    let mut wallet = Wallet::create(EXT.to_string(), INT.to_string())
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .expect("watch-only regtest wallet");

    // --- Phase 1: fund a wallet address, confirm it, bury it below the tip. ---
    let addr = wallet.reveal_next_address(KeychainKind::External).address;
    eprintln!("funding address: {addr}");
    let miner = miner_wallet();
    let d_txid = curl_rpc(
        "sendtoaddress",
        &json!([addr.to_string(), btc(FUND_SATS)]),
        Some(&miner),
    );
    let d_txid = d_txid.as_str().expect("sendtoaddress txid").to_string();
    // Capture D's funding input U (while D is still in the mempool).
    let d = curl_rpc("getrawtransaction", &json!([d_txid, true]), None);
    let u_txid = d["vin"][0]["txid"].as_str().unwrap().to_string();
    let u_vout = d["vin"][0]["vout"].as_u64().unwrap();
    let u = curl_rpc("getrawtransaction", &json!([u_txid, true]), None);
    let u_value_btc = u["vout"][u_vout as usize]["value"].as_f64().unwrap();
    eprintln!("D={d_txid}  U={u_txid}:{u_vout} ({u_value_btc} BTC)");

    let h0 = mine(1); // confirm D in B0
    let b0 = block_hash(h0);
    eprintln!("D confirmed in B0 height={h0} hash={b0}");
    let h_pre = mine(2); // bury B0 two deep
    eprintln!("pre-reorg tip height={h_pre}");

    let r1 = emitter_sync(&mut wallet, &rpc).expect("emitter_sync #1");
    let bal1 = wallet.balance().total().to_sat();
    eprintln!(
        "sync #1: blocks_synced={} tip={} balance={} sats",
        r1.blocks_synced, r1.tip_height, bal1
    );
    let d: Txid = d_txid.parse().expect("D txid");
    assert_eq!(bal1, FUND_SATS, "wallet should see the funding UTXO");
    assert_eq!(
        u64::from(r1.tip_height),
        h_pre,
        "persisted tip == pre-reorg tip"
    );
    eprintln!("sync #1 wallet view of D: {}", tx_state(&wallet, d));

    // --- Phase 2: reorg below the persisted tip, evicting the funding tx. ---
    curl_rpc("invalidateblock", &json!([b0]), None); // rolls back B0..tip; D -> mempool
    eprintln!("invalidated B0; tip now {}", block_count());
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
        "miner should sign the double-spend of U: {signed}"
    );
    let d_prime = curl_rpc(
        "sendrawtransaction",
        &json!([signed["hex"].as_str().unwrap()]),
        None,
    );
    eprintln!("broadcast D' (evicts D): {}", d_prime.as_str().unwrap());
    let h_post = mine((h_pre - block_count()) as u32 + 3);
    eprintln!("post-reorg tip height={h_post} (was {h_pre})");
    assert!(h_post > h_pre, "reorg branch must be strictly longer");

    // --- Phase 3: THE OBSERVATION — re-sync via the RPC emitter. ---
    // POST-Step-1.5 GROUND TRUTH: `emitter_sync` now *catches* the reorg-below-tip
    // (which the emitter surfaces as `ApplyHeaderError::CannotConnect`) and recovers
    // by rebuilding the wallet's graph from genesis in place (D2/D3). So the pass
    // returns `Ok` with `reorg_rebuilt: true`, `evicted_txids == [D]`, and the
    // rebuilt wallet at post-reorg ground truth (D absent, balance 0). This makes
    // P0 hold for the RPC backend exactly as it does for electrum/esplora — the app
    // reads post-reorg truth directly from the returned wallet, no backend-specific
    // CannotConnect handling in app logic.
    let r2 = emitter_sync(&mut wallet, &rpc).expect("emitter_sync #2 must recover, not error");
    let bal2 = wallet.balance().total().to_sat();
    eprintln!("========== RPC-EMITTER REORG OBSERVATION (post-1.5) ==========");
    eprintln!(
        "sync #2 returned: Ok reorg_rebuilt={} evicted={:?} tip={} balance={} sats",
        r2.reorg_rebuilt, r2.evicted_txids, r2.tip_height, bal2
    );
    eprintln!("  post-rebuild wallet view of D = {}", tx_state(&wallet, d));
    eprintln!("==============================================================");

    // Idempotency: a follow-up sync on the now-rebuilt wallet is a clean forward
    // pass — no spurious second rebuild, no phantom re-introduced.
    let r3 = emitter_sync(&mut wallet, &rpc).expect("emitter_sync #3 (idempotent follow-up)");
    let bal3 = wallet.balance().total().to_sat();
    eprintln!(
        "sync #3 (idempotent): reorg_rebuilt={} evicted={:?} balance={} sats",
        r3.reorg_rebuilt, r3.evicted_txids, bal3
    );

    // Confirm the reorg genuinely happened on the node (independent of the wallet).
    let node_hash_h0 = block_hash(h0);
    assert_ne!(
        node_hash_h0, b0,
        "funding block was genuinely replaced on-chain"
    );
    eprintln!("DIAG node chain@{h0}: was {b0}, now {node_hash_h0} (genuinely reorged)");

    // --- Locked assertions (the proven post-Step-1.5 ground truth) ---
    // (1) The RPC emitter recovers the reorg-below-tip by rebuilding, not erroring.
    assert!(
        r2.reorg_rebuilt,
        "emitter_sync must report reorg_rebuilt=true on a reorg-below-tip"
    );
    // (2) `evicted_txids` names exactly the reorged-out funding tx D — the same
    //     signal the electrum/esplora backends emit for the identical reorg.
    assert_eq!(
        r2.evicted_txids,
        vec![d],
        "evicted_txids must be exactly [D] (the double-spent funding tx)"
    );
    // (3) The rebuilt wallet is at post-reorg ground truth: D absent, balance 0.
    assert_eq!(
        bal2, 0,
        "rebuild clears the reorged-out funding (phantom gone)"
    );
    assert!(
        wallet.get_tx(d).is_none(),
        "rebuilt graph must not contain the reorged-out funding tx"
    );
    // (4) Idempotent: the follow-up pass neither rebuilds again nor re-evicts.
    assert!(
        !r3.reorg_rebuilt,
        "follow-up sync must not spuriously rebuild"
    );
    assert!(r3.evicted_txids.is_empty(), "follow-up sync evicts nothing");
    assert_eq!(bal3, 0, "balance stays 0 after the idempotent follow-up");

    eprintln!(
        "CONCLUSION: RPC emitter now recovers a reorg-below-tip in-place \
         (Ok, reorg_rebuilt=true, evicted=[D], balance 0) — P0 holds for the RPC backend."
    );
}
