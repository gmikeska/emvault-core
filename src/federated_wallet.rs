//! [`FederatedWallet`] — a wallet spanning all historical federation versions.
//!
//! As federation membership evolves, old descriptors remain valid because
//! someone may still hold an address derived from a prior composition. A
//! `FederatedWallet` pairs each [`Federation`] version with its own dedicated
//! watch-only wallet instance, so UTXOs, balances, and transaction history are
//! tracked per-federation natively by the underlying wallet infrastructure.
//!
//! `FederatedWallet` is **immutable** — adding a new federation via
//! [`BtcFederatedWallet::with_federation`] returns a fresh instance; the
//! original is unchanged. Wallet creation, persistence, and chain sync are
//! the application's responsibility.

use std::collections::HashSet;
use std::sync::Arc;

use bdk_wallet::LocalOutput;
use bitcoin::{Amount, FeeRate};

use crate::error::{FederatedWalletError, MigrationError};
use crate::federation::Federation;
use crate::migration::{MigrationPlan, SweepAlgorithm};
use crate::network::NetworkType;
use crate::psbt::UnsignedPsbt;
use crate::signer::{Signer, SignerId};

// ---------------------------------------------------------------------------
// FederationWallet — the per-federation pairing
// ---------------------------------------------------------------------------

/// A single federation paired with its dedicated watch-only wallet instance.
///
/// `W` is the wallet type: `bdk_wallet::Wallet` for Bitcoin,
/// `ElementsWalletHandle` for Elements.
#[derive(Debug)]
pub struct FederationWallet<S: Signer, W> {
    /// The federation this wallet watches.
    pub federation: Federation<S>,
    /// The dedicated wallet instance for this federation.
    pub wallet: W,
    /// Position in the `FederatedWallet` stack (0 = oldest).
    pub index: usize,
}

// ---------------------------------------------------------------------------
// FederatedWallet trait
// ---------------------------------------------------------------------------

/// Chain-agnostic interface for a wallet spanning multiple federation versions.
pub trait FederatedWallet<S: Signer, W> {
    /// All federation-wallet pairs, ordered oldest-first.
    fn federation_wallets(&self) -> &[FederationWallet<S, W>];

    /// The newest/active federation-wallet pair.
    fn current(&self) -> &FederationWallet<S, W>;

    /// Look up a federation-wallet pair by index.
    fn at(&self, index: usize) -> Option<&FederationWallet<S, W>>;

    /// Number of federation versions in the stack.
    fn federation_count(&self) -> usize;

    /// The network all federations operate on.
    fn network(&self) -> NetworkType;

    /// The current federation's signing threshold (convenience).
    fn threshold(&self) -> u32;

    /// All federation-wallets containing the given signer.
    fn find_by_signer(&self, id: &SignerId) -> Vec<&FederationWallet<S, W>>;

    /// Whether the given signer is a member of the current (newest) federation.
    fn signer_is_current(&self, id: &SignerId) -> bool;

    /// Union of all signer IDs across every federation version.
    fn all_signer_ids(&self) -> HashSet<SignerId>;

    /// Signer IDs in the current (newest) federation only.
    fn current_signer_ids(&self) -> HashSet<SignerId>;
}

// ---------------------------------------------------------------------------
// BtcFederatedWallet
// ---------------------------------------------------------------------------

/// Bitcoin implementation of [`FederatedWallet`], backed by per-federation
/// `bdk_wallet::Wallet` instances wrapped in `Arc` for cheap sharing between
/// immutable wallet versions.
pub struct BtcFederatedWallet<S: Signer = Box<dyn Signer>> {
    federation_wallets: Vec<FederationWallet<S, Arc<bdk_wallet::Wallet>>>,
    network: NetworkType,
}

impl<S: Signer> std::fmt::Debug for BtcFederatedWallet<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtcFederatedWallet")
            .field("federation_count", &self.federation_wallets.len())
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl<S: Signer> BtcFederatedWallet<S> {
    /// Create a new `BtcFederatedWallet` with the initial federation and its
    /// pre-created wallet instance.
    ///
    /// # Errors
    ///
    /// Returns [`FederatedWalletError::NonBitcoinNetwork`] if the federation's
    /// network is not a Bitcoin network.
    pub fn new(
        federation: Federation<S>,
        wallet: bdk_wallet::Wallet,
    ) -> Result<Self, FederatedWalletError> {
        if !federation.network().is_bitcoin() {
            return Err(FederatedWalletError::NonBitcoinNetwork);
        }
        let network = federation.network();
        let fw = FederationWallet {
            federation,
            wallet: Arc::new(wallet),
            index: 0,
        };
        Ok(Self {
            network,
            federation_wallets: vec![fw],
        })
    }

    /// Return a **new** `BtcFederatedWallet` containing all existing
    /// federation-wallet pairs plus the new one. The original is unchanged.
    ///
    /// # Errors
    ///
    /// - [`FederatedWalletError::NetworkMismatch`] if the new federation's
    ///   network differs from the existing federations.
    /// - [`FederatedWalletError::NonBitcoinNetwork`] if the federation is not
    ///   Bitcoin.
    pub fn with_federation(
        &self,
        federation: Federation<S>,
        wallet: bdk_wallet::Wallet,
    ) -> Result<Self, FederatedWalletError>
    where
        S: Clone,
    {
        if !federation.network().is_bitcoin() {
            return Err(FederatedWalletError::NonBitcoinNetwork);
        }
        if federation.network() != self.network {
            return Err(FederatedWalletError::NetworkMismatch {
                existing: self.network,
                incoming: federation.network(),
            });
        }
        let new_index = self.federation_wallets.len();
        let mut new_wallets: Vec<FederationWallet<S, Arc<bdk_wallet::Wallet>>> =
            Vec::with_capacity(new_index + 1);
        for fw in &self.federation_wallets {
            new_wallets.push(FederationWallet {
                federation: fw.federation.clone(),
                wallet: Arc::clone(&fw.wallet),
                index: fw.index,
            });
        }
        new_wallets.push(FederationWallet {
            federation,
            wallet: Arc::new(wallet),
            index: new_index,
        });
        Ok(Self {
            federation_wallets: new_wallets,
            network: self.network,
        })
    }

    /// Sum of confirmed balances across all wallet instances.
    pub fn total_balance(&self) -> Amount {
        self.federation_wallets
            .iter()
            .map(|fw| fw.wallet.balance().total())
            .fold(Amount::ZERO, |acc, b| acc + b)
    }

    /// Confirmed balance for a single federation's wallet.
    pub fn balance_at(&self, index: usize) -> Option<Amount> {
        self.federation_wallets
            .get(index)
            .map(|fw| fw.wallet.balance().total())
    }

    /// All UTXOs across all wallet instances, tagged with federation index.
    pub fn all_utxos(&self) -> Vec<(usize, LocalOutput)> {
        self.federation_wallets
            .iter()
            .flat_map(|fw| {
                fw.wallet
                    .list_unspent()
                    .map(move |utxo| (fw.index, utxo))
            })
            .collect()
    }

    /// UTXOs for a single federation's wallet.
    pub fn utxos_at(&self, index: usize) -> Option<Vec<LocalOutput>> {
        self.federation_wallets
            .get(index)
            .map(|fw| fw.wallet.list_unspent().collect())
    }

    /// Direct access to a wallet instance by federation index.
    pub fn wallet_at(&self, index: usize) -> Option<&bdk_wallet::Wallet> {
        self.federation_wallets
            .get(index)
            .map(|fw| fw.wallet.as_ref())
    }

    /// Iterate all wallet instances (for sync fan-out by the application).
    pub fn wallets(&self) -> impl Iterator<Item = &bdk_wallet::Wallet> {
        self.federation_wallets
            .iter()
            .map(|fw| fw.wallet.as_ref())
    }

}

impl BtcFederatedWallet<Box<dyn Signer>> {
    /// For each non-current federation wallet with a non-zero balance, produce
    /// a migration plan sweeping its UTXOs to the current federation's wallet.
    ///
    /// Each result is tagged with the source federation index. The sweep
    /// algorithm and fee rate are caller-supplied; PSBT construction uses the
    /// source federation's `bdk_wallet::Wallet` instance (it has the descriptor
    /// needed to build the spending transaction).
    ///
    /// # Errors
    ///
    /// Returns the first [`MigrationError`] encountered from the sweep
    /// algorithm.
    pub fn plan_migrations(
        &self,
        sweep: &dyn SweepAlgorithm<LocalOutput, UnsignedPsbt>,
        fee_rate: FeeRate,
    ) -> Result<Vec<(usize, MigrationPlan<UnsignedPsbt>)>, MigrationError> {
        let current = self
            .federation_wallets
            .last()
            .expect("BtcFederatedWallet always has at least one federation");
        let mut plans = Vec::new();
        for fw in &self.federation_wallets {
            if fw.index == current.index {
                continue;
            }
            let utxos: Vec<LocalOutput> = fw.wallet.list_unspent().collect();
            if utxos.is_empty() {
                continue;
            }
            let plan = sweep.plan(
                &utxos,
                &fw.federation,
                &current.federation,
                fee_rate,
            )?;
            plans.push((fw.index, plan));
        }
        Ok(plans)
    }
}

// ---------------------------------------------------------------------------
// FederatedWallet trait impl for BtcFederatedWallet
// ---------------------------------------------------------------------------

impl<S: Signer> FederatedWallet<S, Arc<bdk_wallet::Wallet>> for BtcFederatedWallet<S> {
    fn federation_wallets(&self) -> &[FederationWallet<S, Arc<bdk_wallet::Wallet>>] {
        &self.federation_wallets
    }

    fn current(&self) -> &FederationWallet<S, Arc<bdk_wallet::Wallet>> {
        self.federation_wallets
            .last()
            .expect("BtcFederatedWallet always has at least one federation")
    }

    fn at(&self, index: usize) -> Option<&FederationWallet<S, Arc<bdk_wallet::Wallet>>> {
        self.federation_wallets.get(index)
    }

    fn federation_count(&self) -> usize {
        self.federation_wallets.len()
    }

    fn network(&self) -> NetworkType {
        self.network
    }

    fn threshold(&self) -> u32 {
        self.current().federation.threshold()
    }

    fn find_by_signer(&self, id: &SignerId) -> Vec<&FederationWallet<S, Arc<bdk_wallet::Wallet>>> {
        self.federation_wallets
            .iter()
            .filter(|fw| fw.federation.contains(id))
            .collect()
    }

    fn signer_is_current(&self, id: &SignerId) -> bool {
        self.current().federation.contains(id)
    }

    fn all_signer_ids(&self) -> HashSet<SignerId> {
        self.federation_wallets
            .iter()
            .flat_map(|fw| fw.federation.signers().iter().map(|s| s.id()))
            .collect()
    }

    fn current_signer_ids(&self) -> HashSet<SignerId> {
        self.current()
            .federation
            .signers()
            .iter()
            .map(|s| s.id())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockSigner;
    use bitcoin::Network;

    fn make_federation(seeds: &[u64], threshold: u32) -> Federation<MockSigner> {
        let signers: Vec<MockSigner> = seeds
            .iter()
            .map(|&s| MockSigner::with_seed(s, Network::Regtest))
            .collect();
        Federation::new(threshold, signers, Network::Regtest.into()).unwrap()
    }

    fn make_wallet(federation: &Federation<MockSigner>) -> bdk_wallet::Wallet {
        let desc = federation.descriptor().to_string();
        bdk_wallet::Wallet::create_single(desc)
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .expect("valid wallet")
    }

    #[test]
    fn construct_with_initial_federation() {
        let fed = make_federation(&[1, 2, 3], 2);
        let wallet = make_wallet(&fed);
        let fw = BtcFederatedWallet::new(fed, wallet).unwrap();
        assert_eq!(fw.federation_count(), 1);
        assert_eq!(fw.current().index, 0);
        assert_eq!(fw.threshold(), 2);
    }

    #[test]
    fn with_federation_adds_and_preserves_original() {
        let fed1 = make_federation(&[1, 2, 3], 2);
        let w1 = make_wallet(&fed1);
        let fw1 = BtcFederatedWallet::new(fed1, w1).unwrap();

        let fed2 = make_federation(&[1, 3, 4], 2);
        let w2 = make_wallet(&fed2);
        let fw2 = fw1.with_federation(fed2, w2).unwrap();

        assert_eq!(fw1.federation_count(), 1, "original unchanged");
        assert_eq!(fw2.federation_count(), 2, "new has both");
        assert_eq!(fw2.current().index, 1);
    }

    #[test]
    fn find_by_signer_returns_correct_federations() {
        let s1 = MockSigner::with_seed(1, Network::Regtest);
        let s2 = MockSigner::with_seed(2, Network::Regtest);
        let s3 = MockSigner::with_seed(3, Network::Regtest);
        let s4 = MockSigner::with_seed(4, Network::Regtest);
        let id2 = s2.id();

        let fed1 = Federation::new(2, vec![s1.clone(), s2, s3.clone()], Network::Regtest.into()).unwrap();
        let w1 = make_wallet(&fed1);
        let fw = BtcFederatedWallet::new(fed1, w1).unwrap();

        let fed2 = Federation::new(2, vec![s1, s3, s4], Network::Regtest.into()).unwrap();
        let w2 = make_wallet(&fed2);
        let fw = fw.with_federation(fed2, w2).unwrap();

        let matches = fw.find_by_signer(&id2);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].index, 0);
    }

    #[test]
    fn network_mismatch_rejected() {
        let fed1 = make_federation(&[1, 2, 3], 2);
        let w1 = make_wallet(&fed1);
        let fw = BtcFederatedWallet::new(fed1, w1).unwrap();

        let signers: Vec<MockSigner> = [4, 5, 6]
            .iter()
            .map(|&s| MockSigner::with_seed(s, Network::Testnet))
            .collect();
        let fed2 = Federation::new(2, signers, Network::Testnet.into()).unwrap();
        let w2 = {
            let desc = fed2.descriptor().to_string();
            bdk_wallet::Wallet::create_single(desc)
                .network(Network::Testnet)
                .create_wallet_no_persist()
                .unwrap()
        };

        let err = fw.with_federation(fed2, w2).unwrap_err();
        assert!(matches!(err, FederatedWalletError::NetworkMismatch { .. }));
    }

    #[test]
    fn current_returns_last() {
        let fed1 = make_federation(&[1, 2, 3], 2);
        let w1 = make_wallet(&fed1);
        let fw = BtcFederatedWallet::new(fed1, w1).unwrap();

        let fed2 = make_federation(&[1, 3, 4], 2);
        let w2 = make_wallet(&fed2);
        let fw = fw.with_federation(fed2, w2).unwrap();

        let fed3 = make_federation(&[1, 4, 5], 2);
        let w3 = make_wallet(&fed3);
        let fw = fw.with_federation(fed3, w3).unwrap();

        assert_eq!(fw.current().index, 2);
        assert_eq!(fw.federation_count(), 3);
    }

    #[test]
    fn total_balance_sums_all_wallets() {
        let fed = make_federation(&[1, 2, 3], 2);
        let wallet = make_wallet(&fed);
        let fw = BtcFederatedWallet::new(fed, wallet).unwrap();
        assert_eq!(fw.total_balance(), Amount::ZERO);
    }

    #[test]
    fn utxos_at_returns_only_indexed_federation() {
        let fed1 = make_federation(&[1, 2, 3], 2);
        let w1 = make_wallet(&fed1);
        let fw = BtcFederatedWallet::new(fed1, w1).unwrap();

        let fed2 = make_federation(&[1, 3, 4], 2);
        let w2 = make_wallet(&fed2);
        let fw = fw.with_federation(fed2, w2).unwrap();

        let utxos0 = fw.utxos_at(0).unwrap();
        let utxos1 = fw.utxos_at(1).unwrap();
        assert!(utxos0.is_empty());
        assert!(utxos1.is_empty());
        assert!(fw.utxos_at(99).is_none());
    }

    #[test]
    fn removed_signer_in_all_but_not_current() {
        let s1 = MockSigner::with_seed(1, Network::Regtest);
        let s2 = MockSigner::with_seed(2, Network::Regtest);
        let s3 = MockSigner::with_seed(3, Network::Regtest);
        let s4 = MockSigner::with_seed(4, Network::Regtest);
        let id2 = s2.id();

        let fed1 = Federation::new(2, vec![s1.clone(), s2, s3.clone()], Network::Regtest.into()).unwrap();
        let w1 = make_wallet(&fed1);
        let fw = BtcFederatedWallet::new(fed1, w1).unwrap();

        let fed2 = Federation::new(2, vec![s1, s3, s4], Network::Regtest.into()).unwrap();
        let w2 = make_wallet(&fed2);
        let fw = fw.with_federation(fed2, w2).unwrap();

        assert!(fw.all_signer_ids().contains(&id2));
        assert!(!fw.current_signer_ids().contains(&id2));
    }

    #[test]
    fn signer_is_current_false_for_rotated_out() {
        let s1 = MockSigner::with_seed(1, Network::Regtest);
        let s2 = MockSigner::with_seed(2, Network::Regtest);
        let s3 = MockSigner::with_seed(3, Network::Regtest);
        let s4 = MockSigner::with_seed(4, Network::Regtest);
        let id2 = s2.id();

        let fed1 = Federation::new(2, vec![s1.clone(), s2, s3.clone()], Network::Regtest.into()).unwrap();
        let w1 = make_wallet(&fed1);
        let fw = BtcFederatedWallet::new(fed1, w1).unwrap();

        let fed2 = Federation::new(2, vec![s1, s3, s4], Network::Regtest.into()).unwrap();
        let w2 = make_wallet(&fed2);
        let fw = fw.with_federation(fed2, w2).unwrap();

        assert!(!fw.signer_is_current(&id2));
        assert!(fw.signer_is_current(&MockSigner::with_seed(4, Network::Regtest).id()));
    }

    #[test]
    fn immutability_original_unchanged_after_with_federation() {
        let fed1 = make_federation(&[1, 2, 3], 2);
        let w1 = make_wallet(&fed1);
        let fw1 = BtcFederatedWallet::new(fed1, w1).unwrap();

        let original_count = fw1.federation_count();
        let original_threshold = fw1.threshold();

        let fed2 = make_federation(&[1, 3, 4], 3);
        let w2 = make_wallet(&fed2);
        let _fw2 = fw1.with_federation(fed2, w2).unwrap();

        assert_eq!(fw1.federation_count(), original_count);
        assert_eq!(fw1.threshold(), original_threshold);
    }
}
