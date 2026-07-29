//! Bitcoin Core RPC chain-sync helpers shared by the consuming apps.
//!
//! Extracted from the per-app `wallet.rs` files (E3b). Two patterns were
//! duplicated across `test-app-xpub` and `test-app-pkcs11`:
//!
//! 1. The **init-or-load** BDK wallet construction — load a persisted
//!    [`ChangeSet`] (or create a fresh wallet from a two-path descriptor).
//! 2. The **emitter sync** drive loop — pull blocks + mempool from bitcoind
//!    via [`bdk_bitcoind_rpc::Emitter`] until the wallet matches the node's
//!    tip.
//!
//! This module owns the *pure BDK* part of those flows. Persistence —
//! database writes, changeset aggregation, signer registration — stays in
//! each app, because the two apps diverge there (typed vs. stringified
//! errors, and different fresh-wallet handling). Accordingly:
//!
//! - [`emitter_sync`] never touches a database; it returns the staged
//!   [`SyncResult::changeset`] for the caller to merge and persist.
//! - [`init_or_load_wallet`] does **not** call `take_staged` on the fresh
//!   path; it returns the wallet with its staged changeset intact and a
//!   `fresh` flag, so each app can persist (xpub) or defer (pkcs11) exactly
//!   as it did before.
//!
//! `emitter_sync` is synchronous and CPU/IO-blocking (it makes blocking RPC
//! calls); call it from a `spawn_blocking` context in async code. It does not
//! persist (Foible 7). The optional async wrapper is deferred to E5f.

use std::collections::HashSet;

use bdk_bitcoind_rpc::{Emitter, NO_EXPECTED_MEMPOOL_TXS};
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::chain::local_chain::ApplyHeaderError;
use bdk_wallet::{ChangeSet, KeychainKind, Wallet};
use bitcoin::{Network, Txid};
use bitcoincore_rpc::RpcApi;
use serde_json::Value;

// ---------------------------------------------------------------------------
// init-or-load
// ---------------------------------------------------------------------------

/// A BDK wallet produced by [`init_or_load_wallet`], plus the context the
/// caller needs to finish wiring it up.
pub struct LoadedWallet {
    /// The constructed wallet. On the fresh path its staged changeset is left
    /// **intact** (not taken) so the caller controls when/whether to persist.
    pub wallet: Wallet,
    /// On the load path: the aggregate changeset that was loaded (the caller
    /// keeps this as its persisted aggregate). On the fresh path: an empty
    /// [`ChangeSet`] — the real initial diff is staged inside `wallet`.
    pub changeset: ChangeSet,
    /// `true` when the wallet was created fresh from the descriptor (no
    /// persisted changeset existed), `false` when loaded from `persisted`.
    pub fresh: bool,
}

/// Errors raised while constructing a BDK wallet from a persisted changeset
/// or a descriptor.
///
/// The variants mirror the BDK error surfaces each app previously wrapped in
/// its own `WalletError`, so callers can map them back without losing detail.
#[derive(Debug, thiserror::Error)]
pub enum InitWalletError {
    /// The stored aggregate changeset wouldn't deserialize.
    #[error("stored bdk_changeset is malformed")]
    Decode(#[source] serde_json::Error),
    /// `Wallet::load_wallet_no_persist` rejected the stored changeset
    /// (e.g. a network mismatch).
    #[error("failed to load persisted wallet")]
    Load(#[source] bdk_wallet::LoadError),
    /// The stored changeset existed but didn't describe a wallet (empty /
    /// missing descriptor). Indicates a corrupt row.
    #[error("stored bdk_changeset is empty after merge")]
    EmptyChangeSet,
    /// `Wallet::create_from_two_path_descriptor` rejected the descriptor.
    #[error("failed to construct wallet from descriptor")]
    Create(#[source] Box<bdk_wallet::descriptor::error::Error>),
}

/// Load a BDK wallet from a persisted changeset, or create a fresh one from
/// `descriptor` when `persisted` is `None`.
///
/// `descriptor` must be a two-path (multipath) descriptor — the same form the
/// federation builder emits. `persisted` is the JSON-encoded aggregate
/// [`ChangeSet`] stored on the wallet's row (or `None` for a never-synced
/// wallet).
///
/// On the fresh path the wallet's staged changeset is intentionally left in
/// place; see the module docs and [`LoadedWallet`].
///
/// # Errors
/// See [`InitWalletError`].
pub fn init_or_load_wallet(
    network: Network,
    descriptor: String,
    persisted: Option<Value>,
) -> Result<LoadedWallet, InitWalletError> {
    if let Some(json) = persisted {
        let aggregate: ChangeSet = serde_json::from_value(json).map_err(InitWalletError::Decode)?;
        let wallet = Wallet::load()
            .check_network(network)
            .load_wallet_no_persist(aggregate.clone())
            .map_err(InitWalletError::Load)?
            .ok_or(InitWalletError::EmptyChangeSet)?;
        Ok(LoadedWallet {
            wallet,
            changeset: aggregate,
            fresh: false,
        })
    } else {
        let wallet = Wallet::create_from_two_path_descriptor(descriptor)
            .network(network)
            .create_wallet_no_persist()
            .map_err(|source| InitWalletError::Create(Box::new(source)))?;
        Ok(LoadedWallet {
            wallet,
            changeset: ChangeSet::default(),
            fresh: true,
        })
    }
}

// ---------------------------------------------------------------------------
// emitter sync
// ---------------------------------------------------------------------------

/// Outcome of an [`emitter_sync`] pass.
#[derive(Debug)]
pub struct SyncResult {
    /// The wallet's staged changeset (the diff produced by this pass), or
    /// `None` when the wallet was already in sync and nothing was staged. The
    /// caller merges this into its aggregate and persists it.
    pub changeset: Option<ChangeSet>,
    /// Number of blocks connected in this pass.
    pub blocks_synced: u32,
    /// Number of mempool transactions ingested in this pass.
    pub new_mempool_txs: u32,
    /// The wallet's chain tip after the sync, in blocks.
    pub tip_height: u32,
    /// Txids that were **confirmed** in the wallet's graph before this pass but are
    /// **absent entirely** from the chain after it (reorged/evicted out — not merely
    /// demoted to mempool). Empty on a normal forward sync; only populated on the
    /// reorg-rebuild path. The consuming app unions these across all wallets it syncs
    /// to drive migration reconcile.
    ///
    /// The bitcoind-RPC [`emitter_sync`] populates this the same way the nodeless
    /// backends do: [`bdk_bitcoind_rpc::Emitter`] surfaces a reorg-below-tip as a
    /// [`ApplyHeaderError::CannotConnect`], which `emitter_sync` catches and recovers
    /// from by rebuilding the wallet's graph from genesis (D2/D3), then reports the
    /// evicted set as confirmed-before minus present-anywhere-after (D5).
    pub evicted_txids: Vec<Txid>,
    /// `true` when this pass detected a reorg below the persisted tip and rebuilt the
    /// wallet's tx graph from scratch. When `true`, `changeset` is the **complete**
    /// rebuilt changeset and the app must **replace** its persisted aggregate, not
    /// merge it (a merge would re-introduce the reorged-out phantom UTXO).
    pub reorg_rebuilt: bool,
}

/// Adapt an [`emvault_esplora::EsploraSyncResult`] into the shared
/// [`SyncResult`], so the nodeless Esplora/Waterfalls backend drops into the
/// exact same seam as [`emitter_sync`]. The fields are identical by design.
#[cfg(feature = "esplora")]
impl From<emvault_esplora::EsploraSyncResult> for SyncResult {
    fn from(r: emvault_esplora::EsploraSyncResult) -> Self {
        Self {
            changeset: r.changeset,
            blocks_synced: r.blocks_synced,
            new_mempool_txs: r.new_mempool_txs,
            tip_height: r.tip_height,
            evicted_txids: r.evicted_txids,
            reorg_rebuilt: r.reorg_rebuilt,
        }
    }
}

/// Adapt an [`emvault_electrum::ElectrumSyncResult`] into the shared
/// [`SyncResult`], so the descriptor-private Electrum backend drops into the
/// exact same seam as [`emitter_sync`]. The fields are identical by design.
#[cfg(feature = "electrum")]
impl From<emvault_electrum::ElectrumSyncResult> for SyncResult {
    fn from(r: emvault_electrum::ElectrumSyncResult) -> Self {
        Self {
            changeset: r.changeset,
            blocks_synced: r.blocks_synced,
            new_mempool_txs: r.new_mempool_txs,
            tip_height: r.tip_height,
            evicted_txids: r.evicted_txids,
            reorg_rebuilt: r.reorg_rebuilt,
        }
    }
}

/// Errors raised while driving the chain-sync emitter.
#[derive(Debug, thiserror::Error)]
pub enum ChainSyncError {
    /// A bitcoind RPC call failed.
    #[error("bitcoind RPC error during sync")]
    Rpc(#[source] bitcoincore_rpc::Error),
    /// An emitted block couldn't be connected to the wallet's local chain for a
    /// reason other than a reorg-below-tip (a reorg-below-tip is caught and
    /// recovered by rebuilding — see [`emitter_sync`]). In practice this is
    /// [`ApplyHeaderError::InconsistentBlocks`].
    #[error("failed to apply block at height {height}")]
    ApplyBlock {
        /// Height of the block that failed to connect.
        height: u32,
        /// The underlying BDK error.
        #[source]
        source: ApplyHeaderError,
    },
    /// A reorg-below-tip was detected (via [`ApplyHeaderError::CannotConnect`]) but
    /// rebuilding the wallet's graph from its descriptors failed.
    #[error("failed to rebuild wallet after reorg: {0}")]
    Rebuild(String),
}

/// Drive [`bdk_bitcoind_rpc::Emitter`] against `rpc` until `wallet` matches
/// bitcoind's tip, ingest mempool transactions, and return the staged
/// changeset plus sync counters.
///
/// This is the pure-BDK core of each app's `FederationWallet::sync`: it does
/// **not** touch any database. Callers merge [`SyncResult::changeset`] into
/// their aggregate and persist it (or persist tip-only when it's `None`).
///
/// Cheap and idempotent when the wallet is already in sync — the common case
/// after the first request for a given wallet.
///
/// # Errors
/// [`ChainSyncError::Rpc`] on RPC failure; [`ChainSyncError::ApplyBlock`] if
/// an emitted block can't be connected to the wallet's local chain.
pub fn emitter_sync<R: RpcApi>(wallet: &mut Wallet, rpc: &R) -> Result<SyncResult, ChainSyncError> {
    // Snapshot the confirmed-txid set *before* any mutation — the eviction baseline
    // used only if this pass turns into a reorg rebuild (D5).
    let before_confirmed = confirmed_txids(wallet);

    let cp = wallet.latest_checkpoint();
    let start_height = cp.height();
    let mut emitter = Emitter::new(rpc, cp, start_height, NO_EXPECTED_MEMPOOL_TXS);

    let mut blocks_synced = 0u32;
    while let Some(block_event) = emitter.next_block().map_err(ChainSyncError::Rpc)? {
        let height = block_event.block_height();
        let connected_to = block_event.connected_to();
        match wallet.apply_block_connected_to(&block_event.block, height, connected_to) {
            Ok(()) => {}
            // A reorg below the persisted tip: the emitter reaches a block that
            // cannot connect to the wallet's stale local chain. The nodeless backends
            // reorg silently and leave a phantom UTXO; the emitter instead *errors*
            // here (`live_reorg.rs` / `reorg_rpc_live.rs` prove both). Either way the
            // only correct recovery is a from-scratch rebuild (D3), so we do it here
            // and return the same `evicted_txids` + `reorg_rebuilt` shape as electrum
            // / esplora — making P0 ("every backend's sync leaves the wallet at
            // post-reorg ground truth") hold for all three.
            Err(ApplyHeaderError::CannotConnect(_)) => {
                return rebuild_on_reorg(wallet, rpc, &before_confirmed);
            }
            Err(source) => return Err(ChainSyncError::ApplyBlock { height, source }),
        }
        blocks_synced = blocks_synced.saturating_add(1);
    }

    let mempool = emitter.mempool().map_err(ChainSyncError::Rpc)?;
    let new_mempool_txs = u32::try_from(mempool.update.len()).unwrap_or(u32::MAX);
    wallet.apply_unconfirmed_txs(mempool.update);

    let tip_height = wallet.latest_checkpoint().height();
    let changeset = wallet.take_staged();

    Ok(SyncResult {
        changeset,
        blocks_synced,
        new_mempool_txs,
        tip_height,
        // Normal forward sync: nothing evicted, no rebuild.
        evicted_txids: Vec::new(),
        reorg_rebuilt: false,
    })
}

/// Reorg-recovery rebuild for the bitcoind-RPC path (decisions D2/D3/D5), the
/// analog of `emvault-electrum`'s `ElectrumBackend::rebuild_on_reorg`. Reconstructs
/// the wallet's tx graph from scratch by re-driving the emitter **from genesis**
/// against the post-reorg chain — the only operation that clears the reorged-out
/// phantom — and **replaces** the caller's wallet in place (D2).
///
/// Unlike the electrum/esplora `full_scan` (which self-discovers used addresses via
/// a gap limit), the bitcoind emitter only indexes txouts for **revealed** SPKs, so
/// we first reveal the fresh wallet up to the live wallet's derivation indices.
/// Otherwise a confirmed UTXO that *survived* the reorg would be silently dropped.
///
/// `evicted_txids` = confirmed-before minus present-anywhere in the rebuilt graph
/// (D5: absent *entirely*, so a re-queued mempool tx is not evicted). The returned
/// `changeset` is the **complete** rebuilt changeset with `reorg_rebuilt: true`; the
/// app must persist it as a **replace**, not a merge.
fn rebuild_on_reorg<R: RpcApi>(
    wallet: &mut Wallet,
    rpc: &R,
    before_confirmed: &HashSet<Txid>,
) -> Result<SyncResult, ChainSyncError> {
    // Rebuild from the live wallet's own public (watch-only) descriptors — a
    // scan-equivalent wallet. Signing keys are intentionally not carried; the app
    // re-registers signers after a rebuild (it does so on every load).
    let ext = wallet.public_descriptor(KeychainKind::External).clone();
    let int = wallet.public_descriptor(KeychainKind::Internal).clone();
    let reveal_ext = wallet.derivation_index(KeychainKind::External);
    let reveal_int = wallet.derivation_index(KeychainKind::Internal);
    let network = wallet.network();

    let mut fresh = Wallet::create(ext, int)
        .network(network)
        .create_wallet_no_persist()
        .map_err(|e| ChainSyncError::Rebuild(e.to_string()))?;

    // Reveal SPKs *before* the scan so the emitter can match historical outputs to
    // the same address range the live wallet had handed out (emitter matches only
    // revealed SPKs — see fn docs).
    if let Some(idx) = reveal_ext {
        let _ = fresh
            .reveal_addresses_to(KeychainKind::External, idx)
            .count();
    }
    if let Some(idx) = reveal_int {
        let _ = fresh
            .reveal_addresses_to(KeychainKind::Internal, idx)
            .count();
    }

    // Drive the emitter from genesis (the fresh wallet's checkpoint) against the
    // post-reorg chain.
    let cp = fresh.latest_checkpoint();
    let start_height = cp.height();
    let mut emitter = Emitter::new(rpc, cp, start_height, NO_EXPECTED_MEMPOOL_TXS);
    let mut blocks_synced = 0u32;
    while let Some(block_event) = emitter.next_block().map_err(ChainSyncError::Rpc)? {
        let height = block_event.block_height();
        let connected_to = block_event.connected_to();
        fresh
            .apply_block_connected_to(&block_event.block, height, connected_to)
            .map_err(|source| ChainSyncError::ApplyBlock { height, source })?;
        blocks_synced = blocks_synced.saturating_add(1);
    }
    let mempool = emitter.mempool().map_err(ChainSyncError::Rpc)?;
    let new_mempool_txs = u32::try_from(mempool.update.len()).unwrap_or(u32::MAX);
    fresh.apply_unconfirmed_txs(mempool.update);

    // evicted = confirmed-before − present-anywhere-after (D5).
    let after_all: HashSet<Txid> = fresh.transactions().map(|wtx| wtx.tx_node.txid).collect();
    let mut evicted_txids: Vec<Txid> = before_confirmed
        .iter()
        .filter(|txid| !after_all.contains(*txid))
        .copied()
        .collect();
    evicted_txids.sort_unstable(); // deterministic order for the app/audit trail

    let tip_height = fresh.latest_checkpoint().height();

    // Swap in the rebuilt wallet (D2: the backend replaces the wallet).
    *wallet = fresh;

    Ok(SyncResult {
        changeset: wallet.take_staged(),
        blocks_synced,
        new_mempool_txs,
        tip_height,
        evicted_txids,
        reorg_rebuilt: true,
    })
}

/// The set of txids the wallet's graph currently considers **confirmed**. Snapshot
/// before the sync to form the eviction baseline (a reorg demotes/evicts the
/// reorged-out tx, so a post-rebuild read would miss it).
fn confirmed_txids(wallet: &Wallet) -> HashSet<Txid> {
    wallet
        .transactions()
        .filter(|wtx| matches!(wtx.chain_position, ChainPosition::Confirmed { .. }))
        .map(|wtx| wtx.tx_node.txid)
        .collect()
}
