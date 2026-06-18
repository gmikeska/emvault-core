//! Error types for `asterism-core`.
//!
//! Each subsystem has its own [`thiserror`]-derived error enum. Cross-cutting
//! callers can use [`AsterismError`] which `From`-converts every subsystem
//! error.

use crate::network::NetworkType;
use crate::signer::SignerId;

/// Top-level error type that aggregates every subsystem error.
#[derive(Debug, thiserror::Error)]
pub enum AsterismError {
    /// Federation construction or mutation failed.
    #[error(transparent)]
    Federation(#[from] FederationError),
    /// Descriptor construction or parsing failed.
    #[error(transparent)]
    Descriptor(#[from] DescriptorError),
    /// PSBT pipeline error.
    #[error(transparent)]
    Psbt(#[from] PsbtError),
    /// A signer reported an error.
    #[error(transparent)]
    Signer(#[from] SignerError),
    /// Recovery template error.
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
    /// Federation snapshot error.
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    /// Federation migration error.
    #[error(transparent)]
    Migration(#[from] MigrationError),
}

// ---------------------------------------------------------------------------
// Federation
// ---------------------------------------------------------------------------

/// Errors raised when constructing or mutating a [`crate::Federation`].
#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    /// `m` exceeds `n`.
    #[error("threshold {threshold} exceeds signer count {signers}")]
    ThresholdExceedsSignerCount {
        /// Requested threshold.
        threshold: u32,
        /// Number of signers in the federation.
        signers: u32,
    },
    /// Threshold must be at least 1.
    #[error("threshold must be at least 1, got 0")]
    ZeroThreshold,
    /// A federation must have at least 2 signers.
    #[error("federation requires at least 2 signers, got {0}")]
    InsufficientSigners(u32),
    /// Two signers share the same identity.
    #[error("duplicate signer: {0}")]
    DuplicateSigner(SignerId),
    /// A signer does not support the federation's target network.
    #[error("signer {id} does not support network {network}")]
    SignerNetworkMismatch {
        /// The offending signer.
        id: SignerId,
        /// The target network.
        network: NetworkType,
    },
    /// A signer required for a mutation was not found.
    #[error("signer not found in federation: {0}")]
    SignerNotFound(SignerId),
    /// The federation requires a particular capability that a signer lacks.
    #[error("signer {id} lacks required capability: {capability}")]
    MissingCapability {
        /// The offending signer.
        id: SignerId,
        /// The missing capability (e.g. `"taproot"`, `"blind_signing"`).
        capability: &'static str,
    },
    /// Taproot federation builder rejected the input.
    #[error("invalid taproot federation: {0}")]
    InvalidTaproot(String),
    /// Wrapped descriptor error.
    #[error(transparent)]
    Descriptor(#[from] DescriptorError),
}

// ---------------------------------------------------------------------------
// Descriptor
// ---------------------------------------------------------------------------

/// Errors raised by the [`crate::DescriptorBuilder`].
#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    /// A required key is missing key origin information.
    #[error("descriptor key for signer {0} is missing key origin")]
    MissingKeyOrigin(SignerId),
    /// Two signers contributed the same descriptor key.
    #[error("duplicate descriptor key: {0}")]
    DuplicateKey(String),
    /// The miniscript library refused to compile the descriptor.
    #[error("miniscript rejected descriptor: {0}")]
    Miniscript(#[from] miniscript::Error),
    /// Failed to parse a descriptor string.
    #[error("failed to parse descriptor: {0}")]
    Parse(String),
    /// Network mismatch between a key and the federation network.
    #[error("network mismatch: descriptor expects {expected}, key declares {actual}")]
    NetworkMismatch {
        /// The federation's declared network.
        expected: String,
        /// The network embedded in the offending key.
        actual: String,
    },
    /// A descriptor public key conversion failed.
    #[error("descriptor key conversion failed: {0}")]
    KeyConversion(String),
}

// ---------------------------------------------------------------------------
// PSBT
// ---------------------------------------------------------------------------

/// Errors from the PSBT pipeline (construction → signing → finalization).
#[derive(Debug, thiserror::Error)]
pub enum PsbtError {
    /// The PSBT contained partial signatures when an unsigned PSBT was
    /// expected.
    #[error("PSBT was expected to be unsigned but contained {found} partial signatures")]
    UnexpectedSignatures {
        /// Number of partial signatures found.
        found: usize,
    },
    /// The PSBT did not match the federation's descriptor.
    #[error("PSBT does not match federation descriptor: {0}")]
    DescriptorMismatch(String),
    /// A signature returned from an external signer did not validate.
    #[error("invalid signature from signer {0}: {1}")]
    InvalidSignature(SignerId, String),
    /// The signer returning a partial signature is not part of the federation.
    #[error("signer {0} is not a member of this federation")]
    UnknownSigner(SignerId),
    /// Finalization failed because not enough signatures were present.
    #[error("cannot finalize: have {have} signatures, need at least {need}")]
    InsufficientSignatures {
        /// Number of signatures collected.
        have: usize,
        /// Threshold required.
        need: usize,
    },
    /// BDK refused to finalize the PSBT.
    #[error("PSBT finalization failed: {0}")]
    FinalizationFailed(String),
    /// Wrapped BDK signer error.
    #[error("BDK signer error: {0}")]
    BdkSigner(String),
    /// Wrapped bitcoin PSBT error.
    #[error("bitcoin PSBT error: {0}")]
    Bitcoin(String),
}

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

/// Errors raised by signer implementations.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// The signer could not be reached (offline, disconnected, etc.).
    #[error("signer {id} unreachable: {reason}")]
    Unreachable {
        /// The signer that could not be reached.
        id: SignerId,
        /// Human-readable reason.
        reason: String,
    },
    /// The signer rejected the signing request.
    #[error("signer {id} signing failed: {reason}")]
    SigningFailed {
        /// The signer that failed.
        id: SignerId,
        /// Human-readable reason.
        reason: String,
    },
    /// The HSM-local policy rejected the transaction before signing.
    #[error("signer {id} policy violation: {rule}")]
    PolicyViolation {
        /// The signer whose policy fired.
        id: SignerId,
        /// The rule that was violated.
        rule: String,
    },
    /// The signer's hardware does not support secp256k1.
    #[error("signer {id} does not support secp256k1")]
    UnsupportedCurve {
        /// The offending signer.
        id: SignerId,
    },
    /// Generic backend error from a backend-specific signer crate.
    #[error("signer backend error: {0}")]
    Backend(String),
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/// Errors from [`crate::RecoveryTemplate`] generation and verification.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// The template's checksum did not match its content.
    #[error("recovery template checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch {
        /// The checksum embedded in the template.
        expected: String,
        /// The checksum recomputed from the content.
        actual: String,
    },
    /// The descriptor in the template is malformed.
    #[error("recovery template descriptor invalid: {0}")]
    InvalidDescriptor(String),
    /// JSON serialization or deserialization failed.
    #[error("recovery JSON error: {0}")]
    Json(String),
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

/// Errors from [`crate::FederationSnapshot`] export/import.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// The snapshot's descriptor does not match its declared signer set.
    #[error("snapshot descriptor does not match signer set")]
    DescriptorMismatch,
    /// Threshold or signer count outside permitted bounds.
    #[error("snapshot has invalid threshold/signer combination: {0}")]
    InvalidThreshold(String),
    /// JSON serialization or deserialization failed.
    #[error("snapshot JSON error: {0}")]
    Json(String),
    /// The snapshot's descriptor failed to parse.
    #[error("snapshot descriptor parse error: {0}")]
    Parse(String),
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/// Errors from federation migration / sweep planning.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// No UTXOs were supplied to plan over.
    #[error("no UTXOs to migrate")]
    NoUtxos,
    /// Construction of a sweep transaction failed.
    #[error("sweep construction failed: {0}")]
    SweepFailed(String),
    /// The supplied old/new federations are on different networks.
    #[error("network mismatch: old {old}, new {new}")]
    NetworkMismatch {
        /// Old federation's network.
        old: NetworkType,
        /// New federation's network.
        new: NetworkType,
    },
    /// Configuration invalid (e.g. `BatchedSweep` with batch size 0).
    #[error("invalid migration configuration: {0}")]
    InvalidConfig(String),
}
