//! Live signet proof for the Esplora chain backend (feature `esplora`).
//!
//! Skipped unless `ESPLORA_LIVE_TEST=1`. Requires a reachable signet `bitcoind`
//! (`BITCOIN_RPC_HOST/PORT/USER/PASSWORD`, optional `BITCOIN_WALLET`, default
//! `default`) with spendable funds, plus outbound HTTPS to the Esplora API
//! (`ESPLORA_URL`, default Blockstream signet). It sends a small real deposit
//! to a throwaway wallet and asserts `esplora_sync` ingests it from the
//! network's mempool.
#![cfg(feature = "esplora")]

use std::time::Duration;

use emvault_core::bdk_wallet::{KeychainKind, Wallet};
use emvault_core::bitcoin::bip32::Xpriv;
use emvault_core::bitcoin::{Amount, Network};
use emvault_core::bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use emvault_core::esplora_sync::{EsploraBackend, esplora_sync};

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

#[tokio::test]
async fn esplora_sync_sees_a_live_signet_deposit() {
    if env("ESPLORA_LIVE_TEST").as_deref() != Some("1") {
        eprintln!("skipping live signet test (set ESPLORA_LIVE_TEST=1 to run)");
        return;
    }

    let esplora_url =
        env("ESPLORA_URL").unwrap_or_else(|| "https://blockstream.info/signet/api".to_owned());
    let host = env("BITCOIN_RPC_HOST").expect("BITCOIN_RPC_HOST");
    let port = env("BITCOIN_RPC_PORT").expect("BITCOIN_RPC_PORT");
    let user = env("BITCOIN_RPC_USER").expect("BITCOIN_RPC_USER");
    let pass = env("BITCOIN_RPC_PASSWORD").expect("BITCOIN_RPC_PASSWORD");
    let wallet_name = env("BITCOIN_WALLET").unwrap_or_else(|| "default".to_owned());

    // Deterministic throwaway signet wallet — a plain wpkh single-sig is enough
    // to exercise the adapter's scan/apply path.
    let seed = [0x42u8; 32];
    let xprv = Xpriv::new_master(Network::Signet, &seed).expect("xprv");
    let external = format!("wpkh({xprv}/84h/1h/0h/0/*)");
    let internal = format!("wpkh({xprv}/84h/1h/0h/1/*)");
    let mut wallet = Wallet::create(external, internal)
        .network(Network::Signet)
        .create_wallet_no_persist()
        .expect("wallet");
    let addr = wallet.reveal_next_address(KeychainKind::External).address;
    eprintln!("funding address: {addr}");

    // Fund it from the node (wallet-scoped RPC).
    let rpc = RpcClient::new(
        &format!("http://{host}:{port}/wallet/{wallet_name}"),
        Auth::UserPass(user, pass),
    )
    .expect("rpc client");
    let sent = Amount::from_sat(15_000);
    let txid = rpc
        .send_to_address(&addr, sent, None, None, None, None, None, None)
        .expect("sendtoaddress");
    eprintln!("sent {sent} in tx {txid}");

    // Poll esplora_sync until the deposit lands (mempool shows within seconds).
    let backend = EsploraBackend::new_public(&esplora_url, Network::Signet).expect("backend");
    let mut found = Amount::ZERO;
    for attempt in 0..40 {
        let result = esplora_sync(&mut wallet, &backend)
            .await
            .expect("esplora_sync");
        found = wallet.balance().total();
        eprintln!(
            "attempt {attempt}: esplora tip={} wallet balance={} sats",
            result.tip_height,
            found.to_sat()
        );
        if found >= sent {
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    assert!(
        found >= sent,
        "esplora_sync never saw the {sent} deposit (saw {found})"
    );
    eprintln!(
        "✅ esplora_sync ingested the live signet deposit: {} sats",
        found.to_sat()
    );
}
