# emvault-core

Core abstractions for the EmVault multi-signature custody platform: the
`Signer` trait, the `Federation` type, descriptor construction, the PSBT
signing pipeline, recovery templates, and snapshots.

See the [CHANGELOG](https://github.com/gmikeska/emvault-core/blob/master/CHANGELOG.md) for release notes.

`emvault-core` is the foundation crate of the [EmVault] library family. It
is the only crate every EmVault consumer depends on; the backend crates
([`emvault-pkcs11`](https://github.com/gmikeska/emvault-pkcs11),
[`emvault-xpub`](https://github.com/gmikeska/emvault-xpub)) and the Elements
integration crate
([`emvault-elements`](https://github.com/gmikeska/emvault-elements)) layer on
top of it. The [`emvault`](https://github.com/gmikeska/emvault) umbrella crate
re-exports the whole family behind feature gates.

[EmVault]: https://github.com/gmikeska/emvault

## Install

```toml
[dependencies]
emvault-core = "0.9"
```

## Design priorities

In order, this crate optimizes for:

1. **Developer ergonomics.** Building a federation, generating its descriptor,
   and coordinating signing should be a handful of lines of obvious code.
2. **Ecosystem leverage.** Wallet state, coin selection, chain sync, and
   transaction broadcast are not EmVault's job — `bdk_wallet::Wallet` (and
   later `lwk_wollet::Wollet`) own those. We coordinate; we do not duplicate.
3. **Compile-time safety.** `UnsignedPsbt` and `FinalizedPsbt` newtypes make
   invalid states unrepresentable. The signing pipeline cannot accept a
   half-signed PSBT where a fully-signed transaction is required.
4. **Auditability.** No magic. Every signing path, every policy check, every
   signer dispatch is traceable by reading the code linearly.

## What's in the box

| Module                       | Purpose                                            |
| ---------------------------- | -------------------------------------------------- |
| [`signer`](src/signer.rs)    | `Signer` trait + identity types                    |
| [`network`](src/network.rs)  | `NetworkType` (Bitcoin; `Elements` behind the `elements` feature, `#[non_exhaustive]`) |
| [`federation`](src/federation.rs) | `Federation<S>` + immutable mutation APIs     |
| [`federation_build`](src/federation_build.rs) | `build_federation` — canonical descriptor + snapshot from a signer set |
| [`descriptor`](src/descriptor.rs) | `wsh(sortedmulti(...))` + `tr(NUMS, multi_a(...))` builder (SegWit v0 & Taproot script-path)              |
| [`federated_wallet`](src/federated_wallet.rs) | `BtcFederatedWallet` — version-aware federated wallet |
| [`psbt`](src/psbt.rs)        | `UnsignedPsbt` / `FinalizedPsbt`, `SigningCoordinator` |
| [`chain_sync`](src/chain_sync.rs) | Bitcoin Core `Emitter` drive loop for chain sync (nodeless Esplora/Waterfalls alternative via the `esplora` feature → `emvault_core::esplora`); `SyncResult` carries the reorg-reconciliation signals (`evicted_txids`, `reorg_rebuilt`) — see [Reorg reconciliation](#reorg-reconciliation) |
| [`verify`](src/verify.rs)    | Descriptor / PSBT-output verification (`descriptors_match`, `verify_psbt_outputs`, `MultisigPolicy`) |
| [`roster`](src/roster.rs)    | Pure roster arithmetic for migrations (add/remove/threshold) |
| [`recovery`](src/recovery.rs) | `RecoveryTemplate` with per-software instructions |
| [`snapshot`](src/snapshot.rs) | Canonical-JSON federation export/import          |
| [`migration`](src/migration.rs) | `SweepAlgorithm`, `FederationMigration`, plans |
| [`error`](src/error.rs)      | `thiserror`-derived error hierarchy                |

## A 20-line example

Building a 2-of-3 federation and deriving the canonical descriptor:

```rust
use emvault_core::{Federation, NetworkType, Signer};
use bitcoin::Network;

// In real code, `alice`/`bob`/`carol` come from companion crates:
//   emvault_xpub::ExternalSigner   for consumer hardware wallets,
//   emvault_pkcs11::Pkcs11Signer  for HSMs.
// Both implement `emvault_core::Signer`.
let alice: Box<dyn Signer> = /* ... build via emvault-xpub ... */;
let bob:   Box<dyn Signer> = /* ... build via emvault-pkcs11 ... */;
let carol: Box<dyn Signer> = /* ... build via emvault-xpub ... */;

let federation = Federation::new(
    2,
    vec![alice, bob, carol],
    NetworkType::Bitcoin(Network::Testnet),
)?;

// Feed the canonical descriptor straight into bdk_wallet:
let descriptor = federation.descriptor_string();
println!("descriptor: {descriptor}");

// Or drop into a recovery-friendly artifact:
let template = emvault_core::RecoveryTemplate::from_federation(&federation);
println!("{}", template.to_printable());
# Ok::<(), emvault_core::EmVaultError>(())
```

## Taproot federations

As of **0.8.0** the crate builds **`tr(NUMS, multi_a(m, …))`** script-path Taproot
federations alongside the original `wsh(sortedmulti(...))` P2WSH ones — select via
`ScriptType` on the descriptor builder / `Federation::with_config`. The internal
key is the provably-unspendable BIP-341 NUMS point, so the `multi_a` multisig
script is the sole spending path.

> **Roadmap.** A richer Taproot **MAST** encoding *distinct* spending-path leaves
> (HSM-unanimous, wallet-unanimous, mixed) remains a future item; today's Taproot
> mode is the single-leaf `multi_a` script path (see
> [`descriptor`](src/descriptor.rs)).

## Signing flow

```
                ┌─────────────────────────────┐
                │  Wallet::build_tx()         │  bdk_wallet
                │   (consumer's wallet code)  │
                └──────────────┬──────────────┘
                               │ Psbt
                ┌──────────────▼──────────────┐
                │ UnsignedPsbt::new(psbt)     │  emvault-core
                └──────────────┬──────────────┘
                               │
                ┌──────────────▼──────────────┐
                │ SigningCoordinator::new(    │
                │   &federation, unsigned)    │
                └──────────────┬──────────────┘
                               │
        ┌──────────────────────┴──────────────────────┐
        │ request_signatures(&wallet, opts)           │
        │   ↓                                         │
        │   Software signers → Wallet::sign()         │
        │   External signers → SigningRequest →       │
        │                       browser → device      │
        └──────────────────────┬──────────────────────┘
                               │  external sigs returned
                ┌──────────────▼──────────────┐
                │ receive_signature(...)      │
                └──────────────┬──────────────┘
                               │ threshold met
                ┌──────────────▼──────────────┐
                │ finalize(&wallet, opts)     │ → FinalizedPsbt
                └─────────────────────────────┘
```

## Federation lifecycle

`Federation` is **immutable**. Every mutation
(`add_signer`, `remove_signer`, `rotate_signer`, `change_threshold`) returns a
fresh `Federation`. Funds do not move automatically — the consuming app uses
`SweepAlgorithm` impls (`AccountForAccountSweep`, `AccountForAccountBatchedSweep`)
inside a `FederationMigration` to plan the actual transfer of UTXOs to the new
federation.

## Reorg reconciliation

A confirmed migration sweep can lose its confirmation to a chain reorg. The
sync layer surfaces the two signals a consuming app needs to *reconcile* that —
i.e. revert a migration it had marked `complete` back to `pending` without ever
double-counting or losing funds — via [`chain_sync::SyncResult`](src/chain_sync.rs):

- **`evicted_txids: Vec<Txid>`** — txids that were **confirmed before** this sync
  pass but are **absent entirely** from the chain after it (reorged/evicted out,
  not merely demoted to the mempool). An app unions these across every wallet in
  a federation lineage; if a version's recorded sweep txid lands in the union,
  that migration's on-chain settlement is gone → revert it to `pending` (the
  funds are preserved on the pre-migration version).
- **`reorg_rebuilt: bool`** — `true` when the pass detected a reorg **below** the
  persisted tip and rebuilt the wallet's tx graph from genesis. When set,
  `changeset` is the **complete** rebuilt graph and the app must **replace** its
  persisted aggregate, not merge it (merging would re-introduce the reorged-out
  phantom UTXO).

`chain_sync::emitter_sync` (the Bitcoin Core RPC path) produces these directly:
a reorg-below-tip surfaces as [`ApplyHeaderError::CannotConnect`], which it
catches and recovers from by rebuilding from genesis (decisions D2/D3), then
reports the evicted set as *confirmed-before minus present-anywhere-after* (D5).
The nodeless backends behind the `esplora` / `electrum` features expose
`From<…SyncResult> for chain_sync::SyncResult`, so **every backend feeds the same
reconciliation seam**. (The migration *revert* + funds-preserving *re-sweep*
policy itself is the consuming app's — see the `test-app-*` `FEATURES.md` — built
on these signals plus the `migration` sweep engine.)

## Recovery templates

`RecoveryTemplate::from_federation(...)` produces a self-contained artifact
with the descriptor, signer metadata, and ready-to-paste import instructions
for Bitcoin Core, Sparrow, Specter, and Nunchuk. A SHA-256 checksum over
canonical content protects against tampering.

## Snapshots

`FederationSnapshot::from_federation(...)` produces a canonical-JSON
representation suitable for safe persistence. `to_canonical_json` is
byte-stable: equivalent snapshots always serialize to identical bytes.

## Build and test

```sh
cargo build
cargo test
cargo test --features test-utils                    # property + address-derivation tests
cargo test --features "test-utils node-tests"       # + Bitcoin Core RPC cross-check
cargo doc --no-deps
```

`node-tests` reads `BITCOIN_RPC_*` from `.env` and cross-validates
descriptors and addresses against a running `bitcoind` via
`getdescriptorinfo`/`deriveaddresses`. Tests skip gracefully when the env
vars are missing or the node is unreachable.

## Cargo features

| Feature       | Default | Effect                                                                |
| ------------- | ------- | --------------------------------------------------------------------- |
| `test-utils`  | off     | Re-exports `MockSigner` for downstream test suites.                   |
| `node-tests`  | off     | Enables the `node_cross_check` integration tests against `bitcoind`.  |
| `elements`    | off     | Adds Elements/Liquid discriminant variants to `NetworkType` (the pipeline lives in `emvault-elements`). |
| `hsm-sweep-tests` | off | Integration tests exercising sweep algorithms with real HSM-backed signers (`emvault-pkcs11` + `emvault-dev-signer` + SoftHSM2). |
| `esplora`     | off     | Pulls in the [`emvault-esplora`](https://github.com/gmikeska/emvault-esplora) companion crate — a nodeless **Esplora + Waterfalls** chain backend (sync/broadcast + `tip_height()`/`get_tx()` accessors) — and re-exports it as `emvault_core::esplora` (plus `From<EsploraSyncResult> for chain_sync::SyncResult`). |
| `electrum`    | off     | Pulls in the [`emvault-electrum`](https://github.com/gmikeska/emvault-electrum) companion crate — a **descriptor-private** electrs/Electrum chain backend (sync/broadcast + a scripthash watch layer + `tip_height()`/`get_tx()` accessors) — and re-exports it as `emvault_core::electrum` (plus `From<ElectrumSyncResult> for chain_sync::SyncResult`). |

## License

MIT OR Apache-2.0.
