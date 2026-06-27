//! Test utilities (also gated behind the `test-utils` feature for downstream
//! crates that want to build mock signers in their own tests).
//!
//! Nothing in this module should be used outside of tests or local
//! development — the keys are derived deterministically from in-process
//! state and provide no security.

use std::time::SystemTime;

use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;

use crate::error::SignerError;
use crate::network::NetworkType;
use crate::signer::{
    DeviceType, Signer, SignerCapabilities, SignerHealth, SignerId, SignerType, TransportType,
};

/// A deterministic in-memory signer for tests and documentation examples.
#[derive(Clone, Debug)]
pub struct MockSigner {
    label: String,
    xpub: Xpub,
    fingerprint: Fingerprint,
    derivation_path: DerivationPath,
    network: Network,
    signer_type: SignerType,
    device_type: DeviceType,
}

impl MockSigner {
    /// Build a `MockSigner` from a deterministic numeric seed. Two calls with
    /// the same seed return the same xpub.
    pub fn with_seed(seed: u64, network: Network) -> Self {
        Self::with_seed_and_type(seed, network, SignerType::External, DeviceType::Generic)
    }

    /// Build a `MockSigner` declaring itself as an HSM (i.e. `Software` signer
    /// type). Useful for testing federation flows that need a `Software`
    /// signer without depending on `emvault-pkcs11`.
    pub fn hsm(seed: u64, network: Network) -> Self {
        Self::with_seed_and_type(
            seed,
            network,
            SignerType::Software,
            DeviceType::Hsm {
                vendor: "MockHSM".into(),
            },
        )
    }

    /// Generate a `MockSigner` with a label.
    pub fn generate(label: &str, network: Network) -> Self {
        let seed = label
            .bytes()
            .fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(u64::from(b)));
        let mut s = Self::with_seed(seed, network);
        s.label = label.into();
        s
    }

    fn with_seed_and_type(
        seed: u64,
        network: Network,
        signer_type: SignerType,
        device_type: DeviceType,
    ) -> Self {
        let secp = Secp256k1::new();
        // 32-byte seed: repeat the u64 four times.
        let mut seed_bytes = [0u8; 32];
        for (i, b) in seed.to_be_bytes().iter().cycle().take(32).enumerate() {
            seed_bytes[i] = *b;
        }
        let xpriv = Xpriv::new_master(network, &seed_bytes).expect("valid master");
        let derivation_path: DerivationPath = match network {
            Network::Bitcoin => "m/48'/0'/0'/2'".parse().unwrap(),
            _ => "m/48'/1'/0'/2'".parse().unwrap(),
        };
        let derived = xpriv.derive_priv(&secp, &derivation_path).unwrap();
        let xpub = Xpub::from_priv(&secp, &derived);
        let fingerprint = xpriv.fingerprint(&secp);
        Self {
            label: format!("mock-{seed}"),
            xpub,
            fingerprint,
            derivation_path,
            network,
            signer_type,
            device_type,
        }
    }
}

impl Signer for MockSigner {
    fn id(&self) -> SignerId {
        SignerId::from_fingerprint(self.fingerprint)
    }
    fn label(&self) -> Option<&str> {
        Some(&self.label)
    }
    fn xpub(&self) -> &Xpub {
        &self.xpub
    }
    fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }
    fn derivation_path(&self) -> &DerivationPath {
        &self.derivation_path
    }
    fn signer_type(&self) -> SignerType {
        self.signer_type
    }
    fn supported_networks(&self) -> Vec<NetworkType> {
        vec![NetworkType::Bitcoin(self.network)]
    }
    fn capabilities(&self) -> SignerCapabilities {
        SignerCapabilities {
            blind_signing: false,
            taproot: matches!(self.device_type, DeviceType::Jade | DeviceType::Hsm { .. }),
            musig2: false,
            transports: match self.signer_type {
                SignerType::Software => vec![TransportType::Pkcs11],
                SignerType::External => vec![TransportType::Usb, TransportType::Qr],
            },
        }
    }
    fn health_check(&self) -> Result<SignerHealth, SignerError> {
        Ok(SignerHealth {
            reachable: true,
            firmware_version: Some("mock-1.0".into()),
            last_seen: Some(SystemTime::now()),
        })
    }
}
