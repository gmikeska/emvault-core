//! Nodeless Esplora HTTP chain backend (feature `esplora`).
//!
//! A pull-based sibling to [`chain_sync::emitter_sync`](crate::chain_sync::emitter_sync):
//! instead of driving a `bitcoind` RPC [`Emitter`](bdk_bitcoind_rpc::Emitter),
//! it scans the wallet's script pubkeys against a Blockstream **Esplora** HTTP
//! API (via the [`esplora_rs`] client), assembles a BDK
//! [`FullScanResponse`](bdk_wallet::chain::spk_client::FullScanResponse), and
//! applies it to the wallet. This lets sync/broadcast run **without a local
//! node** — e.g. serverless deploys.
//!
//! # Ergonomics
//! Adoption is meant to be as close to a one-liner as [`emitter_sync`]:
//!
//! ```no_run
//! # async fn demo(wallet: &mut bdk_wallet::Wallet) -> Result<(), emvault_core::esplora_sync::EsploraSyncError> {
//! use emvault_core::esplora_sync::{EsploraBackend, esplora_sync};
//! use emvault_core::bitcoin::Network;
//!
//! let backend = EsploraBackend::new_public("https://blockstream.info/signet/api", Network::Signet)?;
//! let result = esplora_sync(wallet, &backend).await?; // same `SyncResult` as `emitter_sync`
//! # let _ = result; Ok(())
//! # }
//! ```
//!
//! [`emitter_sync`]: crate::chain_sync::emitter_sync

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bdk_wallet::chain::local_chain::CannotConnectError;
use bdk_wallet::chain::spk_client::{FullScanResponse, SyncResponse};
use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::{KeychainKind, Wallet};

use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::{Amount, BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid};

/// Extra unrevealed indices probed past the last revealed one during an
/// incremental sync (mirrors a node index's lookahead — catches the next few
/// addresses before they're formally revealed).
const INCREMENTAL_LOOKAHEAD: u32 = 5;

use crate::chain_sync::SyncResult;

/// Esplora returns confirmed address history in pages of this size; a short page
/// means the history is exhausted.
const ESPLORA_PAGE_SIZE: usize = 25;

/// Errors raised while syncing or broadcasting through the Esplora backend.
#[derive(Debug, thiserror::Error)]
pub enum EsploraSyncError {
    /// An Esplora HTTP request failed.
    #[error("esplora HTTP request failed")]
    Http(#[from] esplora_rs::Error),
    /// Esplora returned a value that didn't parse into the expected Bitcoin type.
    #[error("esplora returned a malformed {what}: {value}")]
    Malformed {
        /// What we were trying to parse (e.g. `"txid"`, `"block hash"`).
        what: &'static str,
        /// The offending raw value.
        value: String,
    },
    /// The assembled update couldn't be connected to the wallet's local chain
    /// (usually a reorg below the last persisted tip).
    #[error("failed to connect esplora update to the wallet's local chain")]
    CannotConnect(#[from] CannotConnectError),
}

/// Tuning knobs for [`esplora_sync`]. [`Default`] is the common path
/// (gap limit 20, sequential requests).
#[derive(Debug, Clone, Copy)]
pub struct EsploraSyncOpts {
    /// Stop scanning a keychain after this many consecutive unused addresses.
    pub gap_limit: u32,
    /// Reserved for future concurrent SPK fetching. `1` = sequential (current).
    pub parallelism: usize,
}

impl Default for EsploraSyncOpts {
    fn default() -> Self {
        Self {
            gap_limit: 20,
            parallelism: 1,
        }
    }
}

/// A nodeless Esplora chain backend: owns an [`esplora_rs::Client`] plus the
/// target [`Network`] and scan options.
#[derive(Debug, Clone)]
pub struct EsploraBackend {
    client: esplora_rs::Client,
    network: Network,
    opts: EsploraSyncOpts,
}

impl EsploraBackend {
    /// Build an **unauthenticated** backend against a public/self-hosted Esplora
    /// (e.g. `https://blockstream.info/signet/api`).
    ///
    /// # Errors
    /// [`EsploraSyncError::Http`] if the base URL is invalid.
    pub fn new_public(base_url: &str, network: Network) -> Result<Self, EsploraSyncError> {
        Ok(Self {
            client: esplora_rs::Client::new_public(&ensure_trailing_slash(base_url))?,
            network,
            opts: EsploraSyncOpts::default(),
        })
    }

    /// Build an **enterprise** backend that authenticates via Blockstream OAuth,
    /// reading `ESPLORA_CLIENT_ID` / `ESPLORA_CLIENT_SECRET` from the environment.
    ///
    /// The `esplora-rs` auth path is not yet exercised end-to-end — see the
    /// workstream Phase 4.
    ///
    /// # Errors
    /// [`EsploraSyncError::Http`] if the credentials are missing or the URL is
    /// invalid.
    pub fn new_enterprise(base_url: &str, network: Network) -> Result<Self, EsploraSyncError> {
        Ok(Self {
            client: esplora_rs::Client::new(&ensure_trailing_slash(base_url))?,
            network,
            opts: EsploraSyncOpts::default(),
        })
    }

    /// Override the default scan options.
    #[must_use]
    pub fn with_opts(mut self, opts: EsploraSyncOpts) -> Self {
        self.opts = opts;
        self
    }

    /// The network this backend targets.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// The underlying Esplora client (for callers needing raw endpoints).
    #[must_use]
    pub fn client(&self) -> &esplora_rs::Client {
        &self.client
    }
}

/// Sync `wallet` against the Esplora backend and return the staged changeset
/// plus counters — the **same [`SyncResult`]** shape as
/// [`emitter_sync`](crate::chain_sync::emitter_sync), so persistence is
/// identical across backends.
///
/// A wallet's **first** sync does a full gap-limit scan ([`esplora_rescan`]) to
/// discover history; **subsequent** syncs take a fast, concurrent incremental
/// path over only the already-revealed address range. The caller merges
/// [`SyncResult::changeset`] into its aggregate and persists it.
///
/// # Errors
/// [`EsploraSyncError::Http`] on request failure, [`EsploraSyncError::Malformed`]
/// if Esplora returns an unparseable value, or [`EsploraSyncError::CannotConnect`]
/// if the update can't attach to the wallet's local chain.
pub async fn esplora_sync(
    wallet: &mut Wallet,
    backend: &EsploraBackend,
) -> Result<SyncResult, EsploraSyncError> {
    // First sync (fresh wallet, only the genesis checkpoint) → full gap-limit
    // scan to discover history. Steady state → cheap, concurrent incremental
    // sync over only the already-revealed address range. This mirrors the
    // bitcoind `Emitter` backend, which likewise tracks revealed SPKs from the
    // last checkpoint rather than re-deriving from index 0 each poll — so the
    // two chain backends stay interchangeable behind the same `SyncResult`.
    if wallet.latest_checkpoint().height() == 0 {
        esplora_rescan(wallet, backend).await
    } else {
        esplora_incremental(wallet, backend).await
    }
}

/// Full gap-limit scan of every keychain — derives SPKs from index 0 until a
/// gap of unused addresses, discovering history on **unrevealed** indices.
/// Used automatically on a wallet's first sync, and as the explicit "rescan"
/// entry point. Sequential (it's a one-time cost; correctness over speed).
///
/// Returns the same [`SyncResult`] as [`esplora_sync`].
///
/// # Errors
/// See [`esplora_sync`].
pub async fn esplora_rescan(
    wallet: &mut Wallet,
    backend: &EsploraBackend,
) -> Result<SyncResult, EsploraSyncError> {
    let client = backend.client();
    let start_time = now_secs();
    let base_cp = wallet.latest_checkpoint();
    let gap = backend.opts.gap_limit;

    let mut tx_update = TxUpdate::<ConfirmationBlockTime>::default();
    let mut last_active_indices = BTreeMap::<KeychainKind, u32>::new();
    let mut fetched = BTreeSet::<Txid>::new();
    let mut anchor_blocks = BTreeSet::<BlockId>::new();
    let mut new_mempool_txs = 0u32;

    for keychain in [KeychainKind::External, KeychainKind::Internal] {
        let mut index: u32 = 0;
        let mut unused_run: u32 = 0;
        loop {
            let address = wallet.peek_address(keychain, index).address;
            let addr_str = address.to_string();

            if address_is_active(client, &addr_str).await? {
                unused_run = 0;
                last_active_indices.insert(keychain, index);
                for tx in fetch_address_txs(client, &addr_str).await? {
                    ingest_tx(
                        client,
                        &tx,
                        start_time,
                        &mut tx_update,
                        &mut fetched,
                        &mut anchor_blocks,
                        &mut new_mempool_txs,
                    )
                    .await?;
                }
            } else {
                unused_run += 1;
                if unused_run >= gap {
                    break;
                }
            }
            index = index.saturating_add(1);
        }
    }

    // Assemble the chain update: extend the wallet's current checkpoint with
    // every anchor block plus the fresh tip, so confirmed txs canonicalize.
    let tip_height = u32::try_from(client.get_tip_height().await?).unwrap_or(u32::MAX);
    let tip_hash = convert::block_hash(&client.get_tip_hash().await?)?;
    let mut cp = base_cp;
    for block in anchor_blocks {
        cp = cp.insert(block);
    }
    cp = cp.insert(BlockId {
        height: tip_height,
        hash: tip_hash,
    });

    let response = FullScanResponse::<KeychainKind> {
        tx_update,
        last_active_indices,
        chain_update: Some(cp),
    };

    wallet.apply_update(response)?;
    let changeset = wallet.take_staged();
    let final_tip = wallet.latest_checkpoint().height();

    Ok(SyncResult {
        changeset,
        blocks_synced: 0,
        new_mempool_txs,
        tip_height: final_tip,
    })
}

/// Incremental sync: re-check only the wallet's already-revealed address range
/// (plus a small [`INCREMENTAL_LOOKAHEAD`]), fetching all addresses
/// **concurrently** (bounded by [`SCAN_CONCURRENCY`]). The fast, steady-state
/// path — no unbounded gap walk, no re-derivation from index 0. New funds sent
/// to as-yet-unrevealed indices are picked up on the next [`esplora_rescan`].
///
/// Returns the same [`SyncResult`] as [`esplora_sync`].
///
/// # Errors
/// See [`esplora_sync`].
async fn esplora_incremental(
    wallet: &mut Wallet,
    backend: &EsploraBackend,
) -> Result<SyncResult, EsploraSyncError> {
    let client = backend.client();
    let start_time = now_secs();
    let base_cp = wallet.latest_checkpoint();

    // Bounded target set: indices 0..=revealed(+lookahead) per keychain. Peek is
    // read-only, so collect the address strings before any `&mut` borrow.
    let mut targets: Vec<String> = Vec::new();
    for keychain in [KeychainKind::External, KeychainKind::Internal] {
        let last = wallet.derivation_index(keychain).unwrap_or(0);
        let hi = last.saturating_add(INCREMENTAL_LOOKAHEAD);
        for index in 0..=hi {
            targets.push(wallet.peek_address(keychain, index).address.to_string());
        }
    }

    // Fetch each revealed address's history, then dedupe to the unique Esplora
    // transactions touching the wallet. Sequential: the scan only covers the
    // already-revealed range (not a full gap walk), and staying off
    // `buffer_unordered` keeps this future `for<'a> Send` — which an async
    // request handler awaiting this sync requires. Concurrency lives in the
    // waterfalls path instead.
    let mut seen = BTreeSet::<Txid>::new();
    let mut unique: Vec<esplora_rs::Transaction> = Vec::new();
    for addr in &targets {
        if !address_is_active(client, addr).await? {
            continue;
        }
        for tx in fetch_address_txs(client, addr).await? {
            let txid = convert::txid(&tx.txid)?;
            if seen.insert(txid) {
                unique.push(tx);
            }
        }
    }

    // Fetch each unique tx's raw bytes (sequential; same Send rationale).
    let mut raw_txs: Vec<Transaction> = Vec::with_capacity(unique.len());
    for tx in &unique {
        let raw = client.get_tx_hex(&tx.txid).await?;
        raw_txs.push(convert::tx(&raw)?);
    }

    // Assemble the update (in-memory).
    let mut tx_update = TxUpdate::<ConfirmationBlockTime>::default();
    let mut anchor_blocks = BTreeSet::<BlockId>::new();
    let mut new_mempool_txs = 0u32;
    for tx in raw_txs {
        tx_update.txs.push(Arc::new(tx));
    }
    for tx in &unique {
        let txid = convert::txid(&tx.txid)?;
        for vin in &tx.vin {
            if let Some(prevout) = &vin.prevout {
                let outpoint = OutPoint {
                    txid: convert::txid(&vin.txid)?,
                    vout: vin.vout,
                };
                tx_update.txouts.insert(outpoint, convert::txout(prevout)?);
            }
        }
        if tx.status.confirmed {
            if let Some(anchor) = convert::anchor(&tx.status)? {
                anchor_blocks.insert(anchor.block_id);
                tx_update.anchors.insert((anchor, txid));
            }
        } else if tx_update.seen_ats.insert((txid, start_time)) {
            new_mempool_txs = new_mempool_txs.saturating_add(1);
        }
    }

    // Chain update: extend the checkpoint with anchor blocks + the fresh tip.
    let tip_height = u32::try_from(client.get_tip_height().await?).unwrap_or(u32::MAX);
    let tip_hash = convert::block_hash(&client.get_tip_hash().await?)?;
    let mut cp = base_cp;
    for block in anchor_blocks {
        cp = cp.insert(block);
    }
    cp = cp.insert(BlockId {
        height: tip_height,
        hash: tip_hash,
    });

    let response = SyncResponse {
        tx_update,
        chain_update: Some(cp),
    };
    wallet.apply_update(response)?;
    let changeset = wallet.take_staged();
    let final_tip = wallet.latest_checkpoint().height();

    Ok(SyncResult {
        changeset,
        blocks_synced: 0,
        new_mempool_txs,
        tip_height: final_tip,
    })
}

/// Extra derivation indices scanned past the last revealed one on the waterfalls
/// path (the server-side `to_index`). Mirrors [`EsploraSyncOpts::gap_limit`]'s
/// role, but the whole range is covered in a single descriptor query.
const WATERFALLS_GAP: u32 = 20;

/// Sync `wallet` via the **`QuickSync` / Waterfalls** descriptor-scan endpoint:
/// one `get_waterfalls_all` call per keychain returns that keychain's entire
/// per-index history, so the whole wallet is discovered in **~2 descriptor
/// queries + one fetch per unique tx** instead of the address-by-address gap walk
/// in [`esplora_rescan`]. Returns the same [`SyncResult`] as
/// [`esplora_sync`], so persistence is identical across backends.
///
/// Requires a host that serves waterfalls (e.g. `enterprise.blockstream.info/
/// <chain>/api`, authenticated). The descriptor is sent to that server, so this
/// is a dev/staging chain source, not for descriptor-private production.
///
/// # Errors
/// See [`esplora_sync`].
pub async fn esplora_waterfalls_sync(
    wallet: &mut Wallet,
    backend: &EsploraBackend,
) -> Result<SyncResult, EsploraSyncError> {
    let client = backend.client();
    let start_time = now_secs();
    let base_cp = wallet.latest_checkpoint();

    let mut tx_update = TxUpdate::<ConfirmationBlockTime>::default();
    let mut last_active_indices = BTreeMap::<KeychainKind, u32>::new();
    let mut fetched = BTreeSet::<Txid>::new();
    let mut anchor_blocks = BTreeSet::<BlockId>::new();
    let mut new_mempool_txs = 0u32;

    for keychain in [KeychainKind::External, KeychainKind::Internal] {
        // The keychain's single-path public descriptor (e.g. `wsh(...)/0/*#cks`).
        let descriptor = wallet.public_descriptor(keychain).to_string();
        let revealed = wallet.derivation_index(keychain).unwrap_or(0);
        let to_index = revealed.saturating_add(WATERFALLS_GAP);

        let resp = client.get_waterfalls_all(descriptor, to_index).await?;
        // `txs_seen` is keyed by descriptor; the outer Vec index is the
        // derivation index and the inner Vec holds that index's sightings.
        // Collect the txids into an owned list *before* any await, so no
        // response-borrowing iterator is held across `.await` (that trips the
        // "Send is not general enough" HRTB bound in async request handlers).
        let mut txids: Vec<String> = Vec::new();
        for per_index in resp.txs_seen.values() {
            for (index, sightings) in per_index.iter().enumerate() {
                if sightings.is_empty() {
                    continue;
                }
                let index = u32::try_from(index).unwrap_or(u32::MAX);
                let entry = last_active_indices.entry(keychain).or_insert(index);
                *entry = (*entry).max(index);
                txids.extend(sightings.iter().map(|s| s.txid.clone()));
            }
        }
        drop(resp);

        for txid_str in txids {
            let txid = convert::txid(&txid_str)?;
            if fetched.contains(&txid) {
                continue;
            }
            // Waterfalls gives txids only; fetch the full tx for its inputs'
            // prevouts (fees) + confirmation status, then fold it in exactly like
            // the address-scan path.
            let tx = client.get_tx(&txid_str).await?;
            ingest_tx(
                client,
                &tx,
                start_time,
                &mut tx_update,
                &mut fetched,
                &mut anchor_blocks,
                &mut new_mempool_txs,
            )
            .await?;
        }
    }

    // Chain update: extend the checkpoint with anchor blocks + the fresh tip.
    let tip_height = u32::try_from(client.get_tip_height().await?).unwrap_or(u32::MAX);
    let tip_hash = convert::block_hash(&client.get_tip_hash().await?)?;
    let mut cp = base_cp;
    for block in anchor_blocks {
        cp = cp.insert(block);
    }
    cp = cp.insert(BlockId {
        height: tip_height,
        hash: tip_hash,
    });

    let response = FullScanResponse::<KeychainKind> {
        tx_update,
        last_active_indices,
        chain_update: Some(cp),
    };
    wallet.apply_update(response)?;
    let changeset = wallet.take_staged();
    let final_tip = wallet.latest_checkpoint().height();

    Ok(SyncResult {
        changeset,
        blocks_synced: 0,
        new_mempool_txs,
        tip_height: final_tip,
    })
}

/// Broadcast a fully-signed transaction through the Esplora backend and return
/// its txid. Required where no local node is available (e.g. serverless).
///
/// # Errors
/// [`EsploraSyncError::Http`] if the broadcast is rejected, or
/// [`EsploraSyncError::Malformed`] if the returned txid doesn't parse.
pub async fn esplora_broadcast(
    backend: &EsploraBackend,
    tx: &Transaction,
) -> Result<Txid, EsploraSyncError> {
    let hex = serialize_hex(tx);
    let txid = backend.client().broadcast_tx(&hex).await?;
    convert::txid(&txid)
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

/// Cheap activity probe: one `address` call, no history paging.
async fn address_is_active(
    client: &esplora_rs::Client,
    address: &str,
) -> Result<bool, EsploraSyncError> {
    let info = client.get_address_info(address).await?;
    Ok(info.chain_stats.tx_count > 0 || info.mempool_stats.tx_count > 0)
}

/// All transactions touching `address`: confirmed history (paged) + mempool.
async fn fetch_address_txs(
    client: &esplora_rs::Client,
    address: &str,
) -> Result<Vec<esplora_rs::Transaction>, EsploraSyncError> {
    let mut out = Vec::new();
    let mut last_seen: Option<String> = None;
    loop {
        let page = client
            .get_address_txs_chain(address, last_seen.as_deref())
            .await?;
        let page_len = page.len();
        if let Some(last) = page.last() {
            last_seen = Some(last.txid.clone());
        }
        out.extend(page);
        if page_len < ESPLORA_PAGE_SIZE {
            break;
        }
    }
    out.extend(client.get_address_mempool_txs(address).await?);
    Ok(out)
}

/// Fold one Esplora transaction into the accumulating [`TxUpdate`].
async fn ingest_tx(
    client: &esplora_rs::Client,
    tx: &esplora_rs::Transaction,
    start_time: u64,
    tx_update: &mut TxUpdate<ConfirmationBlockTime>,
    fetched: &mut BTreeSet<Txid>,
    anchor_blocks: &mut BTreeSet<BlockId>,
    new_mempool_txs: &mut u32,
) -> Result<(), EsploraSyncError> {
    let txid = convert::txid(&tx.txid)?;
    if fetched.insert(txid) {
        let raw = client.get_tx_hex(&tx.txid).await?;
        tx_update.txs.push(Arc::new(convert::tx(&raw)?));
        // Esplora embeds each input's prevout (script + value), so we can supply
        // the floating txouts BDK needs for fee calculation with no extra
        // requests. Coinbase inputs carry no prevout.
        for vin in &tx.vin {
            if let Some(prevout) = &vin.prevout {
                let outpoint = OutPoint {
                    txid: convert::txid(&vin.txid)?,
                    vout: vin.vout,
                };
                tx_update.txouts.insert(outpoint, convert::txout(prevout)?);
            }
        }
    }
    if tx.status.confirmed {
        if let Some(anchor) = convert::anchor(&tx.status)? {
            anchor_blocks.insert(anchor.block_id);
            tx_update.anchors.insert((anchor, txid));
        }
    } else if tx_update.seen_ats.insert((txid, start_time)) {
        *new_mempool_txs = new_mempool_txs.saturating_add(1);
    }
    Ok(())
}

/// Esplora endpoints are resolved via `Url::join`, which drops the final path
/// segment when the base lacks a trailing slash (`…/api` + `blocks/tip` →
/// `…/blocks/tip`). Normalize so callers can pass the URL either way.
fn ensure_trailing_slash(url: &str) -> String {
    if url.ends_with('/') {
        url.to_owned()
    } else {
        format!("{url}/")
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `esplora-rs` String DTOs → `bitcoin` types.
mod convert {
    use super::{
        Amount, BlockHash, BlockId, ConfirmationBlockTime, EsploraSyncError, ScriptBuf,
        Transaction, TxOut, Txid, deserialize,
    };

    pub(super) fn txid(s: &str) -> Result<Txid, EsploraSyncError> {
        s.parse().map_err(|_| EsploraSyncError::Malformed {
            what: "txid",
            value: s.to_owned(),
        })
    }

    pub(super) fn block_hash(s: &str) -> Result<BlockHash, EsploraSyncError> {
        s.parse().map_err(|_| EsploraSyncError::Malformed {
            what: "block hash",
            value: s.to_owned(),
        })
    }

    pub(super) fn tx(raw_hex: &str) -> Result<Transaction, EsploraSyncError> {
        let bytes = hex::decode(raw_hex).map_err(|_| EsploraSyncError::Malformed {
            what: "tx hex",
            value: raw_hex.chars().take(16).collect(),
        })?;
        deserialize(&bytes).map_err(|_| EsploraSyncError::Malformed {
            what: "transaction",
            value: raw_hex.chars().take(16).collect(),
        })
    }

    /// An input's previous output (script + value), from Esplora's embedded
    /// `prevout` — supplied to BDK so it can compute fees on incoming txs.
    pub(super) fn txout(prevout: &esplora_rs::models::Prevout) -> Result<TxOut, EsploraSyncError> {
        let bytes =
            hex::decode(&prevout.scriptpubkey).map_err(|_| EsploraSyncError::Malformed {
                what: "scriptpubkey hex",
                value: prevout.scriptpubkey.clone(),
            })?;
        Ok(TxOut {
            value: Amount::from_sat(prevout.value),
            script_pubkey: ScriptBuf::from_bytes(bytes),
        })
    }

    /// Build a confirmation anchor from an Esplora tx status. Returns `Ok(None)`
    /// when the tx is unconfirmed or the status is missing block fields.
    pub(super) fn anchor(
        status: &esplora_rs::TxStatus,
    ) -> Result<Option<ConfirmationBlockTime>, EsploraSyncError> {
        if !status.confirmed {
            return Ok(None);
        }
        let (Some(height), Some(hash), Some(time)) = (
            status.block_height,
            status.block_hash.as_deref(),
            status.block_time,
        ) else {
            return Ok(None);
        };
        let height = u32::try_from(height).map_err(|_| EsploraSyncError::Malformed {
            what: "block height",
            value: height.to_string(),
        })?;
        Ok(Some(ConfirmationBlockTime {
            block_id: BlockId {
                height,
                hash: block_hash(hash)?,
            },
            confirmation_time: time,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;

    const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn empty_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    }

    #[test]
    fn tx_hex_round_trips() {
        let tx = empty_tx();
        let hex = serialize_hex(&tx);
        let back = convert::tx(&hex).expect("round-trip");
        assert_eq!(back.compute_txid(), tx.compute_txid());
    }

    #[test]
    fn tx_hex_rejects_garbage() {
        assert!(convert::tx("nothex").is_err());
        assert!(convert::tx("dead").is_err());
    }

    #[test]
    fn txid_and_block_hash_parse() {
        assert!(convert::txid(ZERO_HASH).is_ok());
        assert!(convert::block_hash(ZERO_HASH).is_ok());
        assert!(convert::txid("xyz").is_err());
        assert!(convert::block_hash("xyz").is_err());
    }

    #[test]
    fn anchor_built_from_confirmed_status() {
        let status = esplora_rs::TxStatus {
            confirmed: true,
            block_height: Some(312_760),
            block_hash: Some(ZERO_HASH.to_owned()),
            block_time: Some(1_700_000_000),
        };
        let anchor = convert::anchor(&status).expect("ok").expect("some");
        assert_eq!(anchor.block_id.height, 312_760);
        assert_eq!(anchor.confirmation_time, 1_700_000_000);
    }

    #[test]
    fn txout_built_from_prevout() {
        // p2wpkh scriptpubkey (OP_0 <20-byte hash>), 50_000 sats.
        let prevout = esplora_rs::models::Prevout {
            scriptpubkey: "00140000000000000000000000000000000000000000".to_owned(),
            scriptpubkey_asm: String::new(),
            scriptpubkey_type: "v0_p2wpkh".to_owned(),
            scriptpubkey_address: None,
            value: 50_000,
        };
        let txout = convert::txout(&prevout).expect("txout");
        assert_eq!(txout.value.to_sat(), 50_000);
        assert_eq!(txout.script_pubkey.len(), 22);
    }

    #[test]
    fn txout_rejects_bad_script_hex() {
        let prevout = esplora_rs::models::Prevout {
            scriptpubkey: "nothex".to_owned(),
            scriptpubkey_asm: String::new(),
            scriptpubkey_type: String::new(),
            scriptpubkey_address: None,
            value: 1,
        };
        assert!(convert::txout(&prevout).is_err());
    }

    #[test]
    fn anchor_none_when_unconfirmed_or_partial() {
        let unconfirmed = esplora_rs::TxStatus {
            confirmed: false,
            block_height: None,
            block_hash: None,
            block_time: None,
        };
        assert!(convert::anchor(&unconfirmed).expect("ok").is_none());

        let partial = esplora_rs::TxStatus {
            confirmed: true,
            block_height: Some(1),
            block_hash: None,
            block_time: Some(1),
        };
        assert!(convert::anchor(&partial).expect("ok").is_none());
    }
}
