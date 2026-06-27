# emvault-core

Core abstractions for the Emerald multi-signature custody platform: the
`Signer` trait, the `Federation` type, descriptor construction, the PSBT
signing pipeline, recovery templates, and snapshots.

`emvault-core` is the foundation crate of the [EmVault] library family. It
is the only crate every EmVault consumer depends on; the backend crates
([`emvault-pkcs11`](https://github.com/gmikeska/emvault-pkcs11),
[`emvault-xpub`](https://github.com/gmikeska/emvault-xpub)) and the Elements
integration crate
([`emvault-elements`](https://github.com/gmikeska/emvault-elements)) layer on
top of it. The [`emvault`](https://github.com/gmikeska/emvault) umbrella crate
re-exports the whole family behind feature gates.

[EmVault]: https://github.com/gmikeska/emvault

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
| [`network`](src/network.rs)  | `NetworkType` (Bitcoin only in v1, `#[non_exhaustive]`) |
| [`federation`](src/federation.rs) | `Federation<S>` + immutable mutation APIs     |
| [`federation_build`](src/federation_build.rs) | `build_federation` — canonical descriptor + snapshot from a signer set |
| [`descriptor`](src/descriptor.rs) | `wsh(sortedmulti(...))` builder              |
| [`federated_wallet`](src/federated_wallet.rs) | `BtcFederatedWallet` — version-aware federated wallet |
| [`psbt`](src/psbt.rs)        | `UnsignedPsbt` / `FinalizedPsbt`, `SigningCoordinator` |
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

## Roadmap: hybrid (Taproot MAST) federations

> **Planned, not yet implemented.** A `tr(NUMS, { … })` MAST builder encoding
> distinct spending paths (HSM-unanimous, wallet-unanimous, mixed) with the
> internal key pinned to the BIP-341 NUMS point is a roadmap item. Today the
> crate ships `wsh(sortedmulti(...))` P2WSH federations only (see
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

## License

MIT OR Apache-2.0.
