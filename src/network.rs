//! Network types.
//!
//! [`NetworkType`] discriminates between supported networks. v1 supports only
//! Bitcoin (mainnet, testnet, signet, regtest). The enum is `#[non_exhaustive]`
//! so future Elements/Liquid support can be added without a breaking change.

use serde::{Deserialize, Serialize};

/// The network a federation operates on.
///
/// This is a runtime discriminant; compile-time network separation is
/// established at the wallet layer ([`bdk_wallet::Wallet`] for Bitcoin).
///
/// `#[non_exhaustive]` reserves space for an `Elements { network_id: String }`
/// variant when `asterism-elements` support lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkType {
    /// Bitcoin mainnet, testnet, signet, or regtest.
    Bitcoin(bitcoin::Network),
}

impl NetworkType {
    /// Returns the underlying [`bitcoin::Network`] if this is a Bitcoin network.
    pub fn bitcoin(&self) -> Option<bitcoin::Network> {
        match self {
            Self::Bitcoin(n) => Some(*n),
        }
    }

    /// Whether this network is a Bitcoin network.
    pub fn is_bitcoin(&self) -> bool {
        matches!(self, Self::Bitcoin(_))
    }
}

impl From<bitcoin::Network> for NetworkType {
    fn from(n: bitcoin::Network) -> Self {
        Self::Bitcoin(n)
    }
}

impl std::fmt::Display for NetworkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bitcoin(n) => write!(f, "bitcoin:{n}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitcoin_returns_inner_network() {
        let nt = NetworkType::Bitcoin(bitcoin::Network::Testnet);
        assert_eq!(nt.bitcoin(), Some(bitcoin::Network::Testnet));
        assert!(nt.is_bitcoin());
    }

    #[test]
    fn display_includes_kind_and_network() {
        let s = NetworkType::from(bitcoin::Network::Bitcoin).to_string();
        assert_eq!(s, "bitcoin:bitcoin");
    }

    #[test]
    fn json_round_trip() {
        let nt = NetworkType::Bitcoin(bitcoin::Network::Testnet);
        let json = serde_json::to_string(&nt).unwrap();
        let parsed: NetworkType = serde_json::from_str(&json).unwrap();
        assert_eq!(nt, parsed);
    }
}
