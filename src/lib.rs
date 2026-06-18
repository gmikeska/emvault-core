//! # asterism-core
//!
//! Core abstractions for the Emerald multi-signature custody platform.
//!
//! `asterism-core` provides the backend-agnostic cryptographic machinery for
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
//!   ([`asterism-pkcs11`](https://docs.rs/asterism-pkcs11) for HSMs,
//!   [`asterism-xpub`](https://docs.rs/asterism-xpub) for consumer hardware
//!   wallets).
//! - [`Federation`] — an m-of-n multi-signature group with mutation APIs
//!   (`rotate_signer`, `add_signer`, `remove_signer`, `change_threshold`).
//! - [`DescriptorBuilder`] — `wsh(sortedmulti(...))` descriptor construction.
//! - [`TaprootFederationBuilder`] — Taproot MAST descriptors for hybrid
//!   federations with HSM-only, wallet-only, and mixed spending paths.
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
//! use asterism_core::{Federation, NetworkType, Signer};
//! use bitcoin::Network;
//!
//! // Three signers come from companion crates: ExternalSigner from
//! // asterism-xpub for consumer hardware wallets, Pkcs11Signer from
//! // asterism-pkcs11 for HSMs. Both implement `asterism_core::Signer`.
//! let alice: Box<dyn Signer> = /* ... build from asterism-xpub or asterism-pkcs11 ... */;
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
//! See `design_docs/asterism_multisignature_library.md` and `.cursorrules` for
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

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![allow(
    // chatty on every getter/builder; not a footgun in this codebase
    clippy::must_use_candidate,
    // const-fn surface area is still evolving in stable Rust
    clippy::missing_const_for_fn,
)]

pub mod descriptor;
pub mod error;
pub mod federation;
pub mod migration;
pub mod network;
pub mod psbt;
pub mod recovery;
pub mod signer;
pub mod snapshot;
pub mod taproot;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::MockSigner;

pub use descriptor::DescriptorBuilder;
pub use error::{
    AsterismError, DescriptorError, FederationError, MigrationError, PsbtError, RecoveryError,
    SignerError, SnapshotError,
};
pub use federation::Federation;
pub use migration::{
    AddressForAddressSweep, BatchedSweep, ConsolidationSweep, FederationMigration, MigrationPlan,
    SweepAlgorithm, SweepTransaction,
};
pub use network::NetworkType;
pub use psbt::{FinalizedPsbt, SigningAction, SigningCoordinator, SigningRequest, UnsignedPsbt};
pub use recovery::{RecoveryInstructions, RecoverySoftware, RecoveryTemplate};
pub use signer::{
    DeviceType, Signer, SignerCapabilities, SignerHealth, SignerId, SignerType, TransportType,
};
pub use snapshot::{FederationSnapshot, SignerSnapshot};
pub use taproot::TaprootFederationBuilder;

/// Re-export of [`bitcoin`] crate types for downstream convenience.
pub use bitcoin;
/// Re-export of [`miniscript`] crate types for downstream convenience.
pub use miniscript;
