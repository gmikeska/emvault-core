//! # emvault-core
//!
//! Core abstractions for the EmVault multi-signature custody platform.
//!
//! `emvault-core` provides the backend-agnostic cryptographic machinery for
//! constructing, managing, and signing multi-signature Bitcoin transactions
//! across heterogeneous signer backends. It is a pure library with no runtime,
//! no network, and no persistent state of its own — it operates on stateful
//! [`bdk_wallet::Wallet`] instances that the consuming application owns and
//! synchronizes.
//!
//! ## What this crate provides
//!
//! - [`Signer`] — the central trait representing "I know who this signer is and
//!   what keys they control". Concrete implementations live in companion crates
//!   ([`emvault-pkcs11`](https://docs.rs/emvault-pkcs11) for HSMs,
//!   [`emvault-xpub`](https://docs.rs/emvault-xpub) for consumer hardware
//!   wallets).
//! - [`Federation`] — an m-of-n multi-signature group with mutation APIs
//!   (`rotate_signer`, `add_signer`, `remove_signer`, `change_threshold`).
//! - [`DescriptorBuilder`] — `wsh(sortedmulti(...))` descriptor construction.
//! - [`SigningCoordinator`] — routes signing across software (HSM) and external
//!   (browser-side hardware wallet) signers, delegating to BDK's
//!   [`Wallet::sign`](bdk_wallet::Wallet::sign) for software signers.
//! - [`RecoveryTemplate`] — self-contained federation reconstruction data with
//!   per-software import instructions.
//! - [`FederationSnapshot`] — canonical-JSON federation export/import.
//! - [`SweepAlgorithm`] + [`FederationMigration`] — pluggable strategies for
//!   sweeping funds between federations during signer rotation.
//!
//! ## A 20-line example: build a federation and derive an address
//!
//! ```ignore
//! use emvault_core::{Federation, NetworkType, Signer};
//! use bitcoin::Network;
//!
//! // Three signers come from companion crates: ExternalSigner from
//! // emvault-xpub for consumer hardware wallets, Pkcs11Signer from
//! // emvault-pkcs11 for HSMs. Both implement `emvault_core::Signer`.
//! let alice: Box<dyn Signer> = /* ... build from emvault-xpub or emvault-pkcs11 ... */;
//! let bob:   Box<dyn Signer> = /* ... */;
//! let carol: Box<dyn Signer> = /* ... */;
//!
//! // Build a 2-of-3 federation.
//! let federation = Federation::new(
//!     2,
//!     vec![alice, bob, carol],
//!     NetworkType::Bitcoin(Network::Testnet),
//! ).expect("valid federation");
//!
//! // Print the canonical descriptor — feed this directly into bdk_wallet::Wallet.
//! println!("{}", federation.descriptor_string());
//! ```
//!
//! ## Design priorities
//!
//! See `design_docs/emvault_multisignature_library.md` and `.cursorrules` for
//! the full design rationale. The short version:
//!
//! 1. Developer ergonomics — common patterns are short, errors are specific.
//! 2. Leverage the ecosystem — BDK, rust-bitcoin, rust-miniscript do the
//!    heavy lifting.
//! 3. Focused responsibility — wallet state, persistence, chain sync, and
//!    transaction broadcast are the consumer's job, not ours.
//! 4. Compile-time safety — invalid states (e.g. an unsigned PSBT used where a
//!    signed one is required) are unrepresentable via newtype wrappers.
//! 5. Security — private keys never transit through the library in plaintext;
//!    XPUBs, sighashes, and signatures only.
//!
//! ## Cargo features
//!
//! - `test-utils` — re-exports `MockSigner` and other test scaffolding.
//! - `node-tests` — gates RPC-driven tests against an external `bitcoind`.
//! - `elements` — adds the `NetworkType::Elements` variant and
//!   `ElementsNetworkId` enum, consumed by the
//!   [`emvault-elements`](https://docs.rs/emvault-elements) companion crate.
//!   No additional dependencies are pulled in by enabling this feature.
//! - `esplora` — pulls in the
//!   [`emvault-esplora`](https://docs.rs/emvault-esplora) companion crate (a
//!   nodeless Esplora + Waterfalls chain backend) and re-exports it as
//!   `emvault_core::esplora`, with a `From<EsploraSyncResult>` for
//!   [`chain_sync::SyncResult`].

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![allow(
    // chatty on every getter/builder; not a footgun in this codebase
    clippy::must_use_candidate,
    // const-fn surface area is still evolving in stable Rust
    clippy::missing_const_for_fn,
)]

pub mod chain_sync;
pub mod descriptor;
pub mod error;
pub mod federated_wallet;
pub mod federation;
pub mod federation_build;
pub mod migration;
pub mod network;
pub mod psbt;
pub mod recovery;
pub mod roster;
pub mod signer;
pub mod snapshot;
pub mod verify;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::MockSigner;

pub use descriptor::DescriptorBuilder;
pub use error::{
    DescriptorError, EmVaultError, FederatedWalletError, FederationError, MigrationError,
    PsbtError, RecoveryError, SignerError, SnapshotError,
};
pub use federated_wallet::{BtcFederatedWallet, FederatedWallet, FederationWallet};
pub use federation::Federation;
pub use federation_build::{BuiltFederation, build_federation};
pub use migration::{
    AccountForAccountBatchedSweep, AccountForAccountSweep, AccountUtxoSet, FederationMigration,
    MigrationPlan, SweepAlgorithm, SweepOutput, SweepTransaction,
};
#[cfg(feature = "elements")]
pub use network::ElementsNetworkId;
pub use network::NetworkType;
pub use psbt::{FinalizedPsbt, SigningAction, SigningCoordinator, SigningRequest, UnsignedPsbt};
pub use recovery::{RecoveryInstructions, RecoverySoftware, RecoveryTemplate};
pub use signer::{
    DeviceType, Signer, SignerCapabilities, SignerHealth, SignerId, SignerType, TransportType,
};
pub use snapshot::{FederatedWalletSnapshot, FederationSnapshot, SignerSnapshot};
pub use verify::{
    ExpectedOutput, MultisigPolicy, descriptors_match, ensure_descriptor_string_matches,
    ensure_descriptors_match, multisig_policy, verify_psbt_outputs,
};

// ── Canonical chain-stack crates ────────────────────────────────────────────
// These re-exports are the single source of truth for the third-party crates
// whose *types cross the EmVault public API* (PSBTs, wallets, descriptors, RPC
// errors, the block Emitter). Downstream apps should consume them via these
// paths (`emvault::core::bitcoin`, `…::bdk_wallet`, …) instead of pinning their
// own versions, so the app can never compile against a mismatched major and end
// up with two incompatible copies of the same type.
/// Re-export of [`bdk_bitcoind_rpc`] (the chain-sync `Emitter`). Itself
/// re-exports [`bitcoincore_rpc`], so that client is reachable via this path too.
pub use bdk_bitcoind_rpc;
/// Re-export of [`bdk_wallet`] (`Wallet`, `ChangeSet`, `KeychainKind`, signing).
pub use bdk_wallet;
/// Re-export of the [`bitcoin`] crate (addresses, `Psbt`, `Network`, amounts…).
pub use bitcoin;
/// Re-export of [`bitcoincore_rpc`] (RPC `Client`/`RpcApi`/`Error`; also the
/// generic `call` path used for Elements-only RPCs).
pub use bitcoincore_rpc;
/// Re-export of the nodeless Esplora + Waterfalls backend (`EsploraBackend`,
/// `SyncMode`, `EsploraSyncResult`, …), behind the `esplora` feature. Its
/// [`chain_sync::SyncResult`] `From` impl lets it share the emitter seam.
#[cfg(feature = "esplora")]
pub use emvault_esplora as esplora;
/// Re-export of the descriptor-private Electrum backend (`ElectrumBackend`,
/// `ElectrumSyncResult`, `WatchPool`, …), behind the `electrum` feature. Its
/// [`chain_sync::SyncResult`] `From` impl lets it share the emitter seam.
#[cfg(feature = "electrum")]
pub use emvault_electrum as electrum;
/// Re-export of [`miniscript`] (descriptor parsing/derivation).
pub use miniscript;
