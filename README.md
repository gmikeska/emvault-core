# asterism-core

Core abstractions for the Emerald multi-signature custody platform: the
`Signer` trait, the `Federation` type, descriptor construction, the PSBT
signing pipeline, recovery templates, and snapshots.

`asterism-core` is the foundation crate of the [Asterism] library family. It
is the only crate every Asterism consumer depends on; backend crates
(`asterism-pkcs11`, `asterism-xpub`) and integration crates
(`asterism-elements`, `asterism-policy`) layer on top of it.

[Asterism]: ../design_docs/asterism_multisignature_library.md

## Design priorities

In order, this crate optimizes for:

1. **Developer ergonomics.** Building a federation, generating its descriptor,
   and coordinating signing should be a handful of lines of obvious code.
2. **Ecosystem leverage.** Wallet state, coin selection, chain sync, and
   transaction broadcast are not Asterism's job — `bdk_wallet::Wallet` (and
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
| [`descriptor`](src/descriptor.rs) | `wsh(sortedmulti(...))` builder              |
| [`taproot`](src/taproot.rs)  | `tr(NUMS, { ... })` MAST builder                  |
| [`psbt`](src/psbt.rs)        | `UnsignedPsbt` / `FinalizedPsbt`, `SigningCoordinator` |
| [`recovery`](src/recovery.rs) | `RecoveryTemplate` with per-software instructions |
| [`snapshot`](src/snapshot.rs) | Canonical-JSON federation export/import          |
| [`migration`](src/migration.rs) | `SweepAlgorithm`, `FederationMigration`, plans |
| [`error`](src/error.rs)      | `thiserror`-derived error hierarchy                |

## A 20-line example

Building a 2-of-3 federation and deriving the canonical descriptor:

```rust
use asterism_core::{Federation, NetworkType, Signer};
use bitcoin::Network;

// In real code, `alice`/`bob`/`carol` come from companion crates:
//   asterism_xpub::ExternalSigner   for consumer hardware wallets,
//   asterism_pkcs11::Pkcs11Signer  for HSMs.
// Both implement `asterism_core::Signer`.
let alice: Box<dyn Signer> = /* ... build via asterism-xpub ... */;
let bob:   Box<dyn Signer> = /* ... build via asterism-pkcs11 ... */;
let carol: Box<dyn Signer> = /* ... build via asterism-xpub ... */;

let federation = Federation::new(
    2,
    vec![alice, bob, carol],
    NetworkType::Bitcoin(Network::Testnet),
)?;

// Feed the canonical descriptor straight into bdk_wallet:
let descriptor = federation.descriptor_string();
println!("descriptor: {descriptor}");

// Or drop into a recovery-friendly artifact:
let template = asterism_core::RecoveryTemplate::from_federation(&federation);
println!("{}", template.to_printable());
# Ok::<(), asterism_core::AsterismError>(())
```

## Hybrid (Taproot MAST) federations

For deployments mixing HSMs with consumer hardware wallets, use
`TaprootFederationBuilder` to encode three spending paths as separate MAST
leaves: HSM-unanimous, wallet-unanimous, and mixed. The internal key is set to
the BIP-341 NUMS point so no single-party key path is possible.

```rust
use asterism_core::{NetworkType, TaprootFederationBuilder};
use bitcoin::Network;

let mut b = TaprootFederationBuilder::new(NetworkType::Bitcoin(Network::Testnet));
// b.add_hsm_signer(...).add_hsm_signer(...);
// b.add_wallet_signer(...).add_wallet_signer(...);
// b.mixed_threshold(2);
// let federation = b.build()?;
# Ok::<(), asterism_core::AsterismError>(())
```

## Signing flow

```
                ┌─────────────────────────────┐
                │  Wallet::build_tx()         │  bdk_wallet
                │   (consumer's wallet code)  │
                └──────────────┬──────────────┘
                               │ Psbt
                ┌──────────────▼──────────────┐
                │ UnsignedPsbt::new(psbt)     │  asterism-core
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
`SweepAlgorithm` impls (`ConsolidationSweep`, `AddressForAddressSweep`,
`BatchedSweep`) inside a `FederationMigration` to plan the actual transfer
of UTXOs to the new federation.

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
cargo test --features test-utils  # also runs property tests
cargo doc --no-deps
```

## Cargo features

| Feature      | Default | Effect                                                  |
| ------------ | ------- | ------------------------------------------------------- |
| `test-utils` | off     | Re-exports `MockSigner` for downstream test suites.     |

## License

MIT OR Apache-2.0.
