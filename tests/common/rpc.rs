//! Minimal Bitcoin Core JSON-RPC client for descriptor cross-validation.
//!
//! Only the methods we actually use are implemented:
//!
//! - [`RpcClient::getblockchaininfo`]
//! - [`RpcClient::getdescriptorinfo`]
//! - [`RpcClient::deriveaddresses`]
//!
//! Reads connection parameters from the workspace `.env`:
//!
//! - `BITCOIN_RPC_HOST`
//! - `BITCOIN_RPC_PORT`
//! - `BITCOIN_RPC_USER`
//! - `BITCOIN_RPC_PASSWORD`
//! - `BITCOIN_NETWORK` (optional, just for diagnostics)
//!
//! Tests calling [`RpcClient::from_env`] should treat `None` as a graceful
//! skip — the helper does not panic when env vars are missing.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Loads the workspace `.env` file (the one at `asterism-core/.env`).
///
/// Best-effort — silently no-ops if the file is missing.
pub fn load_env() {
    let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&env_path);
    // Fall back to crate-relative path for asterism-pkcs11 use.
    let alt = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("asterism-core/.env"));
    if let Some(p) = alt {
        let _ = dotenvy::from_path(&p);
    }
}

/// A minimal JSON-RPC client targeting Bitcoin Core.
#[allow(dead_code)]
pub struct RpcClient {
    url: String,
    auth_header: String,
    /// The `BITCOIN_NETWORK` value (informational only).
    pub network_label: String,
}

#[derive(Debug)]
pub enum RpcError {
    Transport(String),
    Status { code: u16, body: String },
    Json(String),
    Rpc { code: i64, message: String },
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::Status { code, body } => write!(f, "HTTP {code}: {body}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::Rpc { code, message } => write!(f, "RPC error {code}: {message}"),
        }
    }
}

impl std::error::Error for RpcError {}

impl RpcClient {
    /// Build a client from environment variables. Returns `None` if any of
    /// the required variables are missing — callers should treat this as a
    /// "skip this test" signal rather than a failure.
    pub fn from_env() -> Option<Self> {
        load_env();
        let user = std::env::var("BITCOIN_RPC_USER").ok()?;
        let password = std::env::var("BITCOIN_RPC_PASSWORD").ok()?;
        let host = std::env::var("BITCOIN_RPC_HOST").ok()?;
        let port = std::env::var("BITCOIN_RPC_PORT").ok()?;
        let network_label = std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "unknown".into());
        let url = format!("http://{host}:{port}/");
        let auth = format!("{user}:{password}");
        // base64 without pulling a base64 crate: cheap manual encoder.
        let auth_header = format!("Basic {}", base64_encode(auth.as_bytes()));
        Some(Self {
            url,
            auth_header,
            network_label,
        })
    }

    fn call(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "asterism-test",
            "method": method,
            "params": params.clone(),
        });
        let req = ureq::AgentBuilder::new()
            .timeout(TIMEOUT)
            .build()
            .post(&self.url)
            .set("Authorization", &self.auth_header)
            .set("Content-Type", "application/json");
        let resp = match req.send_json(body) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                return Err(RpcError::Status { code, body });
            }
            Err(e) => return Err(RpcError::Transport(e.to_string())),
        };
        let v: Value = resp
            .into_json()
            .map_err(|e| RpcError::Json(e.to_string()))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return Err(RpcError::Rpc { code, message });
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| RpcError::Json("missing 'result' field".into()))
    }

    /// `getblockchaininfo`. Returns the raw JSON object.
    pub fn getblockchaininfo(&self) -> Result<Value, RpcError> {
        self.call("getblockchaininfo", &json!([]))
    }

    /// `getdescriptorinfo(descriptor)`. Returns the canonical descriptor
    /// (with computed checksum), the checksum string, and `isrange`.
    pub fn getdescriptorinfo(&self, descriptor: &str) -> Result<DescriptorInfo, RpcError> {
        let v = self.call("getdescriptorinfo", &json!([descriptor]))?;
        Ok(DescriptorInfo {
            descriptor: v
                .get("descriptor")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::Json("missing 'descriptor'".into()))?
                .to_string(),
            checksum: v
                .get("checksum")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::Json("missing 'checksum'".into()))?
                .to_string(),
            isrange: v.get("isrange").and_then(Value::as_bool).unwrap_or(false),
            issolvable: v
                .get("issolvable")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }

    /// `deriveaddresses(descriptor[, range])`. Returns the addresses as
    /// strings.
    pub fn deriveaddresses(
        &self,
        descriptor: &str,
        range: Option<[u32; 2]>,
    ) -> Result<Vec<String>, RpcError> {
        let params = match range {
            Some([lo, hi]) => json!([descriptor, [lo, hi]]),
            None => json!([descriptor]),
        };
        let v = self.call("deriveaddresses", &params)?;
        let arr = v
            .as_array()
            .ok_or_else(|| RpcError::Json("expected array of addresses".into()))?;
        Ok(arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect())
    }
}

/// Parsed `getdescriptorinfo` response.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct DescriptorInfo {
    /// Bitcoin Core's canonical form of the descriptor (always with a `#checksum`).
    pub descriptor: String,
    /// Just the checksum portion (8 lowercase chars).
    pub checksum: String,
    /// True if the descriptor contains a wildcard `*`.
    pub isrange: bool,
    /// True if Bitcoin Core's wallet would consider the descriptor solvable.
    pub issolvable: bool,
}

// ---------------------------------------------------------------------------
// Tiny base64 encoder (avoids pulling base64 crate as a test dep).
// RFC-4648 standard alphabet, no padding configurability.
// ---------------------------------------------------------------------------

fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64_encode;

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        // Auth-style: "user:pass" -> "dXNlcjpwYXNz"
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }
}
