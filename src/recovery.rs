//! [`RecoveryTemplate`] — self-contained federation reconstruction data.
//!
//! A recovery template captures everything needed to reconstruct a federation
//! and its address space using third-party wallet software, without requiring
//! the Emerald platform to be online. Templates include:
//!
//! - The output descriptor (with origin metadata and `#checksum`).
//! - Threshold and signer count.
//! - Per-signer metadata (fingerprint, derivation path, device type).
//! - Last-used receive/change indexes for efficient recovery scanning.
//! - Programmatically-generated, per-software import instructions.
//! - A SHA-256 content checksum for tamper detection.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_with::{TimestampSeconds, serde_as};
use sha2::{Digest, Sha256};

use crate::error::RecoveryError;
use crate::federation::Federation;
use crate::network::NetworkType;
use crate::signer::{DeviceType, Signer, SignerId, SignerType};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Built-in target software for recovery instructions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecoverySoftware {
    /// Bitcoin Core (`bitcoind` / `bitcoin-cli`).
    BitcoinCore,
    /// Sparrow Wallet.
    SparrowWallet,
    /// Specter Desktop.
    SpecterDesktop,
    /// Nunchuk.
    Nunchuk,
    /// Other software not covered by built-ins.
    Other {
        /// Free-form software name.
        name: String,
    },
}

impl RecoverySoftware {
    /// Display name.
    pub fn name(&self) -> &str {
        match self {
            RecoverySoftware::BitcoinCore => "Bitcoin Core",
            RecoverySoftware::SparrowWallet => "Sparrow Wallet",
            RecoverySoftware::SpecterDesktop => "Specter Desktop",
            RecoverySoftware::Nunchuk => "Nunchuk",
            RecoverySoftware::Other { name } => name,
        }
    }
}

/// Per-software import instructions, generated from descriptor properties.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryInstructions {
    /// The target software.
    pub software: RecoverySoftware,
    /// Minimum software version, if known.
    pub min_version: Option<String>,
    /// Ordered import steps.
    pub steps: Vec<String>,
}

/// Per-signer recovery metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySignerInfo {
    /// Stable signer id.
    pub id: SignerId,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Master fingerprint as hex.
    pub fingerprint: String,
    /// Derivation path used by this signer.
    pub derivation_path: String,
    /// Whether this signer is software (HSM) or external (consumer hardware).
    pub signer_type: SignerType,
    /// Concrete device family.
    pub device_type: DeviceType,
}

/// A recovery template.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryTemplate {
    /// The output descriptor (with `#checksum` already appended by miniscript).
    pub descriptor: String,
    /// Signing threshold (`m`).
    pub threshold: u32,
    /// Total signers (`n`).
    pub total_signers: u32,
    /// Target network.
    pub network: NetworkType,
    /// Per-signer info.
    pub signer_info: Vec<RecoverySignerInfo>,
    /// Reconstruction instructions for one or more wallet softwares.
    pub reconstruction_instructions: Vec<RecoveryInstructions>,
    /// Last-used receive index (for recovery scanning hint).
    pub last_receive_index: Option<u32>,
    /// Last-used change index (for recovery scanning hint).
    pub last_change_index: Option<u32>,
    /// SHA-256 hex checksum over the canonical content of this template.
    pub checksum: String,
    /// Generation timestamp (Unix seconds).
    #[serde_as(as = "TimestampSeconds<i64>")]
    pub generated_at: SystemTime,
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for [`RecoveryTemplate`]. Use this rather than constructing the
/// struct directly so the checksum is always computed correctly.
pub struct RecoveryTemplateBuilder<'a, S: Signer = Box<dyn Signer>> {
    federation: &'a Federation<S>,
    softwares: Vec<RecoverySoftware>,
    last_receive_index: Option<u32>,
    last_change_index: Option<u32>,
    labels: std::collections::HashMap<SignerId, String>,
    device_types: std::collections::HashMap<SignerId, DeviceType>,
}

impl<'a, S: Signer> RecoveryTemplateBuilder<'a, S> {
    /// New builder with default targets (Bitcoin Core, Sparrow, Specter,
    /// Nunchuk).
    pub fn new(federation: &'a Federation<S>) -> Self {
        Self {
            federation,
            softwares: vec![
                RecoverySoftware::BitcoinCore,
                RecoverySoftware::SparrowWallet,
                RecoverySoftware::SpecterDesktop,
                RecoverySoftware::Nunchuk,
            ],
            last_receive_index: None,
            last_change_index: None,
            labels: Default::default(),
            device_types: Default::default(),
        }
    }

    /// Replace the target softwares list.
    pub fn softwares(mut self, sw: Vec<RecoverySoftware>) -> Self {
        self.softwares = sw;
        self
    }

    /// Set the last-used external (receive) index.
    pub fn last_receive_index(mut self, idx: u32) -> Self {
        self.last_receive_index = Some(idx);
        self
    }

    /// Set the last-used internal (change) index.
    pub fn last_change_index(mut self, idx: u32) -> Self {
        self.last_change_index = Some(idx);
        self
    }

    /// Override a signer's label.
    pub fn signer_label(mut self, id: SignerId, label: String) -> Self {
        self.labels.insert(id, label);
        self
    }

    /// Override a signer's device type (e.g. for HSM federations where
    /// `Pkcs11Signer` reports `DeviceType::Hsm` already).
    pub fn signer_device_type(mut self, id: SignerId, dt: DeviceType) -> Self {
        self.device_types.insert(id, dt);
        self
    }

    /// Build the template.
    pub fn build(self) -> RecoveryTemplate {
        let descriptor = self.federation.descriptor_string().to_string();
        let signer_info: Vec<RecoverySignerInfo> = self
            .federation
            .signers()
            .iter()
            .map(|s| RecoverySignerInfo {
                id: s.id(),
                label: self
                    .labels
                    .get(&s.id())
                    .cloned()
                    .or_else(|| s.label().map(str::to_string)),
                fingerprint: s.fingerprint().to_string(),
                derivation_path: s.derivation_path().to_string(),
                signer_type: s.signer_type(),
                device_type: self
                    .device_types
                    .get(&s.id())
                    .cloned()
                    .unwrap_or(DeviceType::Generic),
            })
            .collect();

        let mut t = RecoveryTemplate {
            descriptor,
            threshold: self.federation.threshold(),
            total_signers: self.federation.total_signers() as u32,
            network: self.federation.network(),
            signer_info,
            reconstruction_instructions: Vec::new(),
            last_receive_index: self.last_receive_index,
            last_change_index: self.last_change_index,
            checksum: String::new(),
            generated_at: now_truncated_to_seconds(),
        };
        t.reconstruction_instructions = self
            .softwares
            .iter()
            .map(|sw| generate_instructions(sw, &t))
            .collect();
        t.checksum = compute_checksum(&t);
        t
    }
}

// ---------------------------------------------------------------------------
// RecoveryTemplate impl
// ---------------------------------------------------------------------------

impl RecoveryTemplate {
    /// Convenience: build a template with default settings.
    pub fn from_federation<S: Signer>(federation: &Federation<S>) -> Self {
        RecoveryTemplateBuilder::new(federation).build()
    }

    /// Serialize to (canonical) JSON.
    pub fn to_json(&self) -> Result<String, RecoveryError> {
        serde_json::to_string_pretty(self).map_err(|e| RecoveryError::Json(e.to_string()))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, RecoveryError> {
        serde_json::from_str(json).map_err(|e| RecoveryError::Json(e.to_string()))
    }

    /// Verify internal consistency: the checksum must match the canonical
    /// content of the template.
    pub fn verify(&self) -> Result<(), RecoveryError> {
        let recomputed = compute_checksum(self);
        if recomputed != self.checksum {
            return Err(RecoveryError::ChecksumMismatch {
                expected: self.checksum.clone(),
                actual: recomputed,
            });
        }
        // Check that the descriptor parses.
        let secp = bitcoin::secp256k1::Secp256k1::new();
        miniscript::Descriptor::<miniscript::DescriptorPublicKey>::parse_descriptor(
            &secp,
            &self.descriptor,
        )
        .map_err(|e| RecoveryError::InvalidDescriptor(e.to_string()))?;
        Ok(())
    }

    /// Render a human-readable text representation suitable for printing.
    pub fn to_printable(&self) -> String {
        let mut out = String::new();
        out.push_str("Asterism Federation Recovery Template\n");
        out.push_str("======================================\n");
        out.push_str(&format!(
            "Threshold: {} of {}\n",
            self.threshold, self.total_signers
        ));
        out.push_str(&format!("Network:   {}\n", self.network));
        out.push_str(&format!("Generated: {:?}\n", self.generated_at));
        out.push_str(&format!("Checksum:  {}\n\n", self.checksum));
        out.push_str("Descriptor:\n");
        out.push_str(&self.descriptor);
        out.push_str("\n\nSigners:\n");
        for s in &self.signer_info {
            out.push_str(&format!(
                "  - {}{} fingerprint={} path={}\n",
                s.id,
                s.label
                    .as_ref()
                    .map(|l| format!(" ({l})"))
                    .unwrap_or_default(),
                s.fingerprint,
                s.derivation_path
            ));
        }
        if let (Some(r), Some(c)) = (self.last_receive_index, self.last_change_index) {
            out.push_str(&format!("\nLast indexes: receive={r}, change={c}\n"));
        }
        out.push_str("\nReconstruction instructions:\n");
        for inst in &self.reconstruction_instructions {
            out.push_str(&format!(
                "\n--- {}{} ---\n",
                inst.software.name(),
                inst.min_version
                    .as_ref()
                    .map(|v| format!(" (>= {v})"))
                    .unwrap_or_default()
            ));
            for (i, step) in inst.steps.iter().enumerate() {
                out.push_str(&format!("{}. {step}\n", i + 1));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Instruction generation
// ---------------------------------------------------------------------------

fn generate_instructions(sw: &RecoverySoftware, t: &RecoveryTemplate) -> RecoveryInstructions {
    match sw {
        RecoverySoftware::BitcoinCore => bitcoin_core_instructions(t),
        RecoverySoftware::SparrowWallet => sparrow_instructions(t),
        RecoverySoftware::SpecterDesktop => specter_instructions(t),
        RecoverySoftware::Nunchuk => nunchuk_instructions(t),
        RecoverySoftware::Other { name } => RecoveryInstructions {
            software: sw.clone(),
            min_version: None,
            steps: vec![format!(
                "Import the following descriptor into {name}: {}",
                t.descriptor
            )],
        },
    }
}

fn bitcoin_core_instructions(t: &RecoveryTemplate) -> RecoveryInstructions {
    let timestamp = "\"now\"";
    let payload = serde_json::to_string_pretty(&serde_json::json!([
        {
            "desc": t.descriptor,
            "active": true,
            "internal": false,
            "timestamp": "now",
            "range": [0, t.last_receive_index.unwrap_or(20)],
        },
    ]))
    .unwrap_or_default();

    RecoveryInstructions {
        software: RecoverySoftware::BitcoinCore,
        min_version: Some("24.0".into()),
        steps: vec![
            "Start `bitcoind` and create (or unlock) a descriptor wallet:".into(),
            "  bitcoin-cli createwallet \"asterism-recovery\" false false \"\" false true".into(),
            format!(
                "Import the federation descriptor with `importdescriptors` (timestamp={timestamp} performs a full chain rescan):"
            ),
            format!("  bitcoin-cli -rpcwallet=asterism-recovery importdescriptors '{payload}'"),
            "Once the import completes, use `getbalance` and `listtransactions` to confirm the federation's UTXO history is visible.".into(),
        ],
    }
}

fn sparrow_instructions(t: &RecoveryTemplate) -> RecoveryInstructions {
    RecoveryInstructions {
        software: RecoverySoftware::SparrowWallet,
        min_version: Some("1.7.0".into()),
        steps: vec![
            "Open Sparrow → File → New Wallet → choose a wallet name.".into(),
            "Set the policy type to \"Multi Signature\" (m of n).".into(),
            format!(
                "Choose Threshold = {} and add Cosigners = {} keystores.",
                t.threshold, t.total_signers
            ),
            "Click \"Edit Policy → Output Descriptor\" and paste the descriptor below.".into(),
            t.descriptor.clone(),
            "Apply, then verify the first receive address matches a known reference.".into(),
        ],
    }
}

fn specter_instructions(t: &RecoveryTemplate) -> RecoveryInstructions {
    RecoveryInstructions {
        software: RecoverySoftware::SpecterDesktop,
        min_version: Some("1.14.0".into()),
        steps: vec![
            "Open Specter Desktop and connect to your Bitcoin Core node.".into(),
            format!(
                "Devices → Add new device for each of the {} cosigners.",
                t.total_signers
            ),
            "Wallets → Add new wallet → choose \"Multisignature\".".into(),
            format!(
                "Set quorum to {} of {} and select the cosigner devices in the order encoded in the descriptor.",
                t.threshold, t.total_signers
            ),
            "Advanced → \"Edit descriptor\" → paste the descriptor below.".into(),
            t.descriptor.clone(),
            "Save the wallet and verify Specter generates the same first receive address as the source federation.".into(),
        ],
    }
}

fn nunchuk_instructions(t: &RecoveryTemplate) -> RecoveryInstructions {
    RecoveryInstructions {
        software: RecoverySoftware::Nunchuk,
        min_version: Some("1.9.0".into()),
        steps: vec![
            "Open Nunchuk → Wallets → Add → \"Recover wallet\".".into(),
            "Choose \"Recover from descriptor\".".into(),
            "Paste the descriptor:".into(),
            t.descriptor.clone(),
            format!(
                "Confirm Threshold = {} of {} and complete the recovery flow.",
                t.threshold, t.total_signers
            ),
        ],
    }
}

// ---------------------------------------------------------------------------
// Checksum
// ---------------------------------------------------------------------------

fn compute_checksum(t: &RecoveryTemplate) -> String {
    // Canonicalize: serialize a content-only struct without the checksum
    // field, with sorted keys, to a JSON string. SHA-256 of that string.
    let content = ChecksumContent {
        descriptor: &t.descriptor,
        threshold: t.threshold,
        total_signers: t.total_signers,
        network: &t.network,
        signer_info: &t.signer_info,
        reconstruction_instructions: &t.reconstruction_instructions,
        last_receive_index: t.last_receive_index,
        last_change_index: t.last_change_index,
    };
    let canonical = canonical_json(&content);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Serialize)]
struct ChecksumContent<'a> {
    descriptor: &'a str,
    threshold: u32,
    total_signers: u32,
    network: &'a NetworkType,
    signer_info: &'a Vec<RecoverySignerInfo>,
    reconstruction_instructions: &'a Vec<RecoveryInstructions>,
    last_receive_index: Option<u32>,
    last_change_index: Option<u32>,
}

/// Truncate `SystemTime::now()` to whole seconds. We use this everywhere we
/// store a time in serializable form because `serde_with::TimestampSeconds`
/// only round-trips with second precision.
pub(crate) fn now_truncated_to_seconds() -> SystemTime {
    let now = SystemTime::now();
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Serialize `value` to canonical JSON: object keys sorted lexicographically,
/// no whitespace. Used for content checksums and snapshot canonicalization.
pub(crate) fn canonical_json<T: Serialize>(value: &T) -> String {
    let v = serde_json::to_value(value).expect("canonical_json: input is not serializable");
    let mut buf = String::new();
    write_canonical(&v, &mut buf);
    buf
}

fn write_canonical(v: &serde_json::Value, buf: &mut String) {
    match v {
        serde_json::Value::Null => buf.push_str("null"),
        serde_json::Value::Bool(b) => buf.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => buf.push_str(&n.to_string()),
        serde_json::Value::String(s) => {
            buf.push_str(&serde_json::to_string(s).unwrap());
        }
        serde_json::Value::Array(items) => {
            buf.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    buf.push(',');
                }
                write_canonical(item, buf);
            }
            buf.push(']');
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            buf.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    buf.push(',');
                }
                buf.push_str(&serde_json::to_string(k).unwrap());
                buf.push(':');
                write_canonical(&map[*k], buf);
            }
            buf.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockSigner;
    use bitcoin::Network;

    fn fed() -> Federation {
        Federation::new(
            2,
            vec![
                Box::new(MockSigner::with_seed(1, Network::Testnet)) as Box<dyn Signer>,
                Box::new(MockSigner::with_seed(2, Network::Testnet)) as _,
                Box::new(MockSigner::with_seed(3, Network::Testnet)) as _,
            ],
            Network::Testnet.into(),
        )
        .unwrap()
    }

    #[test]
    fn template_round_trip_via_json() {
        let t = RecoveryTemplate::from_federation(&fed());
        let json = t.to_json().unwrap();
        let parsed = RecoveryTemplate::from_json(&json).unwrap();
        assert_eq!(t, parsed);
        parsed.verify().unwrap();
    }

    #[test]
    fn checksum_detects_tamper() {
        let mut t = RecoveryTemplate::from_federation(&fed());
        t.threshold = 99; // tamper
        let err = t.verify().unwrap_err();
        assert!(matches!(err, RecoveryError::ChecksumMismatch { .. }));
    }

    #[test]
    fn includes_default_softwares() {
        let t = RecoveryTemplate::from_federation(&fed());
        let names: Vec<&str> = t
            .reconstruction_instructions
            .iter()
            .map(|i| i.software.name())
            .collect();
        assert_eq!(
            names,
            vec![
                "Bitcoin Core",
                "Sparrow Wallet",
                "Specter Desktop",
                "Nunchuk"
            ]
        );
    }

    #[test]
    fn printable_contains_descriptor() {
        let t = RecoveryTemplate::from_federation(&fed());
        let p = t.to_printable();
        assert!(p.contains(&t.descriptor));
        assert!(p.contains("Threshold: 2 of 3"));
    }
}
