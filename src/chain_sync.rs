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

use bdk_bitcoind_rpc::{Emitter, NO_EXPECTED_MEMPOOL_TXS};
use bdk_wallet::chain::local_chain::ApplyHeaderError;
use bdk_wallet::{ChangeSet, Wallet};
use bitcoin::Network;
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
}

/// Errors raised while driving the chain-sync emitter.
#[derive(Debug, thiserror::Error)]
pub enum ChainSyncError {
    /// A bitcoind RPC call failed.
    #[error("bitcoind RPC error during sync")]
    Rpc(#[source] bitcoincore_rpc::Error),
    /// An emitted block couldn't be connected to the wallet's local chain
    /// (usually a reorg below the last persisted tip).
    #[error("failed to apply block at height {height}")]
    ApplyBlock {
        /// Height of the block that failed to connect.
        height: u32,
        /// The underlying BDK error.
        #[source]
        source: ApplyHeaderError,
    },
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
pub fn emitter_sync<R: RpcApi>(
    wallet: &mut Wallet,
    rpc: &R,
) -> Result<SyncResult, ChainSyncError> {
    let cp = wallet.latest_checkpoint();
    let start_height = cp.height();
    let mut emitter = Emitter::new(rpc, cp, start_height, NO_EXPECTED_MEMPOOL_TXS);

    let mut blocks_synced = 0u32;
    while let Some(block_event) = emitter.next_block().map_err(ChainSyncError::Rpc)? {
        let height = block_event.block_height();
        let connected_to = block_event.connected_to();
        wallet
            .apply_block_connected_to(&block_event.block, height, connected_to)
            .map_err(|source| ChainSyncError::ApplyBlock { height, source })?;
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
    })
}
