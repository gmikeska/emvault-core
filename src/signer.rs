//! The [`Signer`] trait and associated types.
//!
//! `Signer` represents the **identity** of a federation participant — who they
//! are and which keys they control. It is deliberately signing-agnostic
//! because not all signers can sign server-side: consumer hardware wallets
//! ([`crate::SignerType::External`]) require a browser round-trip, while HSMs
//! ([`crate::SignerType::Software`]) sign locally.
//!
//! Concrete signing methods (`sign_psbt`) live on the per-backend types
//! ([`asterism_pkcs11::Pkcs11Signer`](https://docs.rs/asterism-pkcs11/),
//! etc.), not on this trait.

use std::fmt;
use std::time::SystemTime;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use serde::{Deserialize, Serialize};

use crate::error::SignerError;
use crate::network::NetworkType;

// ---------------------------------------------------------------------------
// SignerId
// ---------------------------------------------------------------------------

/// A stable, hashable identifier for a [`Signer`].
///
/// Derived from the master fingerprint for XPUB-based signers, or from the
/// HSM serial number + slot ID for PKCS#11 signers. `SignerId` is the key
/// used to track signers across federation mutations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignerId(String);

impl SignerId {
    /// Create a `SignerId` from a raw string.
    ///
    /// Callers are expected to use a stable, deterministic source — typically
    /// the master fingerprint hex (e.g. `"d34db33f"`) or `"hsm:<serial>:<slot>"`.
    pub fn new(s: impl Into<String>) -> Self {
        SignerId(s.into())
    }

    /// Create a `SignerId` from a [`Fingerprint`] (hex-encoded).
    pub fn from_fingerprint(fp: Fingerprint) -> Self {
        SignerId(fp.to_string())
    }

    /// The raw string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SignerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<Fingerprint> for SignerId {
    fn from(fp: Fingerprint) -> Self {
        SignerId::from_fingerprint(fp)
    }
}

// ---------------------------------------------------------------------------
// SignerType
// ---------------------------------------------------------------------------

/// Whether a signer can sign locally (server-side) or requires an external
/// round-trip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerType {
    /// Can sign locally — HSM via PKCS#11, software wallet, etc.
    Software,
    /// Requires an external round-trip — consumer hardware wallets in the
    /// trustee's browser, air-gapped devices, etc.
    External,
}

// ---------------------------------------------------------------------------
// TransportType / DeviceType
// ---------------------------------------------------------------------------

/// Transport mechanisms a signer supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportType {
    /// USB HID (Trezor, Ledger).
    Usb,
    /// Bluetooth Low Energy (Jade, Passport Prime).
    Ble,
    /// Camera + display QR-code exchange (Jade, Passport Prime).
    Qr,
    /// SD card / microSD (Coldcard, Passport Prime).
    SdCard,
    /// NFC (Coldcard).
    Nfc,
    /// PKCS#11 (HSMs).
    Pkcs11,
}

/// Concrete device families a signer might represent.
///
/// This enum exists so that backend-specific quirks (e.g. Jade's Liquid
/// support, Passport Prime's QR fallback) can be handled without polluting
/// the core abstractions.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeviceType {
    /// Trezor Model T / Safe 3 / Safe 5 / Model One.
    Trezor,
    /// Blockstream Jade.
    Jade,
    /// Foundation Passport Prime.
    PassportPrime,
    /// Ledger.
    Ledger,
    /// Coldcard.
    Coldcard,
    /// PKCS#11-accessed HSM.
    Hsm {
        /// Free-form vendor name (`"YubiHSM"`, `"Thales Luna"`, `"SoftHSMv2"`,
        /// `"AWS CloudHSM"`, etc.).
        vendor: String,
    },
    /// Generic / other.
    Generic,
}

// ---------------------------------------------------------------------------
// SignerCapabilities / SignerHealth
// ---------------------------------------------------------------------------

/// Capability flags reported by a signer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignerCapabilities {
    /// Can this signer perform blind signing (required for Liquid confidential
    /// transactions)?
    pub blind_signing: bool,
    /// Can this signer handle Taproot key-path and script-path spends?
    pub taproot: bool,
    /// Can this signer participate in a Musig2 federation? (Phase 2 roadmap.)
    pub musig2: bool,
    /// Supported transport mechanisms.
    pub transports: Vec<TransportType>,
}

impl SignerCapabilities {
    /// Bitcoin-only, P2WSH, no Taproot, no Musig2 — the conservative default.
    pub fn p2wsh_only(transports: Vec<TransportType>) -> Self {
        Self {
            blind_signing: false,
            taproot: false,
            musig2: false,
            transports,
        }
    }
}

/// Result of a [`Signer::health_check`] call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerHealth {
    /// Whether the signer responded to the health check.
    pub reachable: bool,
    /// The signer's reported firmware/version string, if available.
    pub firmware_version: Option<String>,
    /// When the signer was last successfully contacted.
    pub last_seen: Option<SystemTime>,
}

// ---------------------------------------------------------------------------
// Signer trait
// ---------------------------------------------------------------------------

/// The central abstraction: "I know who this signer is and what keys they
/// control."
///
/// Note that the trait is deliberately **signing-agnostic**. Concrete signing
/// methods live on per-backend types because not every signer can sign
/// server-side. See [`crate::SigningCoordinator`] for how the library routes
/// signing requests across heterogeneous signers.
pub trait Signer: Send + Sync {
    /// Stable identifier for this signer instance.
    fn id(&self) -> SignerId;

    /// Optional human-readable label (e.g. `"Alice's Trezor"`,
    /// `"HSM Slot 3"`).
    fn label(&self) -> Option<&str>;

    /// The extended public key at the federation derivation path.
    fn xpub(&self) -> &Xpub;

    /// The master fingerprint used in descriptor key origins.
    fn fingerprint(&self) -> Fingerprint;

    /// The derivation path this signer uses for multi-sig participation.
    fn derivation_path(&self) -> &DerivationPath;

    /// Whether this signer can sign locally or requires an external
    /// round-trip.
    fn signer_type(&self) -> SignerType;

    /// Networks this signer supports.
    fn supported_networks(&self) -> Vec<NetworkType>;

    /// Device-specific capability flags.
    fn capabilities(&self) -> SignerCapabilities;

    /// Health check — can this signer be reached and is it ready?
    fn health_check(&self) -> Result<SignerHealth, SignerError>;
}

// Implement Signer for Box<dyn Signer> so Federation<Box<dyn Signer>> works.
impl Signer for Box<dyn Signer> {
    fn id(&self) -> SignerId {
        (**self).id()
    }
    fn label(&self) -> Option<&str> {
        (**self).label()
    }
    fn xpub(&self) -> &Xpub {
        (**self).xpub()
    }
    fn fingerprint(&self) -> Fingerprint {
        (**self).fingerprint()
    }
    fn derivation_path(&self) -> &DerivationPath {
        (**self).derivation_path()
    }
    fn signer_type(&self) -> SignerType {
        (**self).signer_type()
    }
    fn supported_networks(&self) -> Vec<NetworkType> {
        (**self).supported_networks()
    }
    fn capabilities(&self) -> SignerCapabilities {
        (**self).capabilities()
    }
    fn health_check(&self) -> Result<SignerHealth, SignerError> {
        (**self).health_check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_id_from_fingerprint_is_hex() {
        let fp = Fingerprint::from([0xde, 0xad, 0xbe, 0xef]);
        let id: SignerId = fp.into();
        assert_eq!(id.as_str(), "deadbeef");
    }

    #[test]
    fn capabilities_p2wsh_default() {
        let caps = SignerCapabilities::p2wsh_only(vec![TransportType::Pkcs11]);
        assert!(!caps.taproot);
        assert!(!caps.musig2);
        assert!(!caps.blind_signing);
        assert_eq!(caps.transports, vec![TransportType::Pkcs11]);
    }

    #[test]
    fn signer_type_serializes_lowercase() {
        let s = serde_json::to_string(&SignerType::Software).unwrap();
        assert_eq!(s, "\"software\"");
        let s = serde_json::to_string(&SignerType::External).unwrap();
        assert_eq!(s, "\"external\"");
    }
}
