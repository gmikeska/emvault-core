//! Network types.
//!
//! [`NetworkType`] discriminates between supported networks. The Bitcoin
//! variant is always available; the Elements variant is gated behind the
//! `elements` feature and is consumed by the
//! [`emvault-elements`](https://docs.rs/emvault-elements) crate.
//!
//! The enum is `#[non_exhaustive]` so additional networks can be added
//! without a breaking change.

use serde::{Deserialize, Serialize};

/// The network a federation operates on.
///
/// This is a runtime discriminant; compile-time network separation is
/// established at the wallet layer ([`bdk_wallet::Wallet`] for Bitcoin,
/// `lwk_wollet::Wollet` for Elements).
///
/// # Example
///
/// ```
/// use bitcoin::Network;
/// use emvault_core::NetworkType;
///
/// let net = NetworkType::from(Network::Testnet);
/// assert!(net.is_bitcoin());
/// assert_eq!(net.bitcoin(), Some(Network::Testnet));
/// assert_eq!(net.to_string(), "bitcoin:testnet");
///
/// // Round-trips through serde as an internally-tagged enum.
/// let json = serde_json::to_string(&net).unwrap();
/// let back: NetworkType = serde_json::from_str(&json).unwrap();
/// assert_eq!(net, back);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkType {
    /// Bitcoin mainnet, testnet, signet, or regtest.
    Bitcoin(bitcoin::Network),
    /// Elements / Liquid network. The richer
    /// `emvault_elements::ElementsNetwork` type lives in the companion
    /// crate and converts to/from this lightweight discriminant.
    #[cfg(feature = "elements")]
    Elements(ElementsNetworkId),
}

/// Identifier for an Elements/Liquid network.
///
/// This is a deliberately small enum carried inside [`NetworkType::Elements`]
/// so that `emvault-core` does not need to depend on `lwk_wollet` or
/// `elements`. The richer
/// [`emvault_elements::ElementsNetwork`](https://docs.rs/emvault-elements)
/// adds parameters like the policy asset for regtest deployments and converts
/// to/from this type.
#[cfg(feature = "elements")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElementsNetworkId {
    /// The Liquid main network.
    Liquid,
    /// The Liquid test network.
    LiquidTestnet,
    /// A locally-deployed Elements regtest.
    ElementsRegtest,
}

impl NetworkType {
    /// Returns the underlying [`bitcoin::Network`] if this is a Bitcoin network.
    pub fn bitcoin(&self) -> Option<bitcoin::Network> {
        match self {
            Self::Bitcoin(n) => Some(*n),
            #[cfg(feature = "elements")]
            Self::Elements(_) => None,
        }
    }

    /// Whether this network is a Bitcoin network.
    pub fn is_bitcoin(&self) -> bool {
        matches!(self, Self::Bitcoin(_))
    }

    /// Returns the Elements network identifier if this is an Elements
    /// network.
    #[cfg(feature = "elements")]
    pub fn elements(&self) -> Option<ElementsNetworkId> {
        match self {
            Self::Elements(id) => Some(*id),
            Self::Bitcoin(_) => None,
        }
    }

    /// Whether this network is an Elements network.
    #[cfg(feature = "elements")]
    pub fn is_elements(&self) -> bool {
        matches!(self, Self::Elements(_))
    }
}

impl From<bitcoin::Network> for NetworkType {
    fn from(n: bitcoin::Network) -> Self {
        Self::Bitcoin(n)
    }
}

#[cfg(feature = "elements")]
impl From<ElementsNetworkId> for NetworkType {
    fn from(id: ElementsNetworkId) -> Self {
        Self::Elements(id)
    }
}

#[cfg(feature = "elements")]
impl std::fmt::Display for ElementsNetworkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Liquid => "liquid",
            Self::LiquidTestnet => "liquid_testnet",
            Self::ElementsRegtest => "elements_regtest",
        };
        f.write_str(s)
    }
}

impl std::fmt::Display for NetworkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bitcoin(n) => write!(f, "bitcoin:{n}"),
            #[cfg(feature = "elements")]
            Self::Elements(id) => write!(f, "elements:{id}"),
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

    #[cfg(feature = "elements")]
    #[test]
    fn elements_variant_round_trips() {
        let nt = NetworkType::Elements(ElementsNetworkId::LiquidTestnet);
        assert!(nt.is_elements());
        assert!(!nt.is_bitcoin());
        assert_eq!(nt.elements(), Some(ElementsNetworkId::LiquidTestnet));
        assert_eq!(nt.bitcoin(), None);
        let json = serde_json::to_string(&nt).unwrap();
        let parsed: NetworkType = serde_json::from_str(&json).unwrap();
        assert_eq!(nt, parsed);
        assert_eq!(nt.to_string(), "elements:liquid_testnet");
    }
}
