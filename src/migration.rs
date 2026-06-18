//! Federation migration helpers — pluggable strategies for sweeping funds
//! from an old federation to a new one after a signer rotation.
//!
//! This module provides:
//!
//! - The [`SweepAlgorithm`] trait, generic over the UTXO and PSBT types so
//!   future Elements / Liquid implementations slot in cleanly.
//! - Three Bitcoin-targeted built-in algorithms:
//!   - [`ConsolidationSweep`] — collects all UTXOs into a single output at
//!     the new federation's first receive address.
//!   - [`AddressForAddressSweep`] — preserves per-address segregation by
//!     mapping each old-federation derived address to the corresponding
//!     new-federation address.
//!   - [`BatchedSweep`] — splits the migration into multiple transactions
//!     bounded by `max_inputs_per_tx`.
//!
//! ## Scope
//!
//! v1 sweep algorithms produce a [`MigrationPlan`] describing the **shape** of
//! the migration (source UTXOs + destination addresses + amount estimates).
//! The `psbt: Option<P>` field is left as `None` — the consumer assembles the
//! actual PSBT via [`bdk_wallet::Wallet::build_tx`], which gives BDK control
//! over coin selection details, fee rounding, and BIP-32 derivation
//! population. Future versions may populate `psbt` directly.
//!
//! See `design_docs/asterism_multisignature_library.md`, section
//! "Federation Migration Types and Sweep Algorithms".

use std::collections::BTreeMap;
use std::marker::PhantomData;

use bdk_wallet::LocalOutput;
use bitcoin::{Address, Amount, FeeRate, OutPoint, ScriptBuf};

use crate::error::MigrationError;
use crate::federation::Federation;
use crate::psbt::UnsignedPsbt;
use crate::signer::Signer;

// ---------------------------------------------------------------------------
// Generic types
// ---------------------------------------------------------------------------

/// A federation migration: an old federation, a new federation, and the
/// chosen sweep algorithm.
pub struct FederationMigration<U, P, S: Signer = Box<dyn Signer>>
where
    P: Send + Sync + std::fmt::Debug,
{
    /// The federation being migrated away from.
    pub old_federation: Federation<S>,
    /// The federation being migrated to.
    pub new_federation: Federation<S>,
    /// The pluggable sweep algorithm.
    pub sweep_algorithm: Box<dyn SweepAlgorithm<U, P>>,
}

/// The plan produced by a [`SweepAlgorithm`].
#[derive(Debug)]
pub struct MigrationPlan<P: std::fmt::Debug> {
    /// One [`SweepTransaction`] per migration tx, in execution order.
    pub sweep_transactions: Vec<SweepTransaction<P>>,
    /// Estimated total fees across all sweep transactions, at the requested
    /// `fee_rate`.
    pub total_fees: Amount,
    /// Total UTXO count being migrated.
    pub utxo_count: usize,
}

/// A single sweep transaction's shape.
#[derive(Debug)]
pub struct SweepTransaction<P: std::fmt::Debug> {
    /// Source UTXO outpoints to spend.
    pub source_utxos: Vec<OutPoint>,
    /// Output destinations: `(address, amount)`. The `amount` is a
    /// pre-fee estimate; the consumer's PSBT builder adjusts for actual
    /// fees.
    pub destinations: Vec<(Address, Amount)>,
    /// The constructed PSBT, if the algorithm provides one.
    ///
    /// v1 built-in algorithms leave this `None`; the consumer builds the
    /// PSBT via [`bdk_wallet::Wallet::build_tx`] using the destinations
    /// described above.
    pub psbt: Option<P>,
}

/// Pluggable sweep algorithm.
pub trait SweepAlgorithm<U, P = UnsignedPsbt>: Send + Sync
where
    P: std::fmt::Debug,
{
    /// Produce a migration plan for sweeping `utxos` from `old_federation`
    /// to `new_federation` at the given `fee_rate`.
    fn plan(
        &self,
        utxos: &[U],
        old_federation: &Federation,
        new_federation: &Federation,
        fee_rate: FeeRate,
    ) -> Result<MigrationPlan<P>, MigrationError>;
}

// ---------------------------------------------------------------------------
// Built-in algorithms (Bitcoin)
// ---------------------------------------------------------------------------

/// Sweeps every UTXO into a single output at `destination_address`.
///
/// The destination address is supplied at construction time (typically the
/// new federation's first receive address, derived via
/// [`bdk_wallet::Wallet::reveal_next_address`] before invoking the
/// migration).
pub struct ConsolidationSweep {
    destination_address: Address,
}

impl ConsolidationSweep {
    /// Construct with the new federation's destination address.
    pub fn new(destination_address: Address) -> Self {
        Self {
            destination_address,
        }
    }
}

impl SweepAlgorithm<LocalOutput, UnsignedPsbt> for ConsolidationSweep {
    fn plan(
        &self,
        utxos: &[LocalOutput],
        old_federation: &Federation,
        new_federation: &Federation,
        fee_rate: FeeRate,
    ) -> Result<MigrationPlan<UnsignedPsbt>, MigrationError> {
        ensure_same_network(old_federation, new_federation)?;
        if utxos.is_empty() {
            return Err(MigrationError::NoUtxos);
        }
        let total_value: Amount = utxos
            .iter()
            .map(|u| u.txout.value)
            .fold(Amount::ZERO, |a, b| a + b);
        let fee = estimate_fee(utxos.len(), 1, fee_rate);
        let net = total_value.checked_sub(fee).ok_or_else(|| {
            MigrationError::SweepFailed(format!("fee {fee} exceeds total UTXO value {total_value}"))
        })?;
        Ok(MigrationPlan {
            sweep_transactions: vec![SweepTransaction {
                source_utxos: utxos.iter().map(|u| u.outpoint).collect(),
                destinations: vec![(self.destination_address.clone(), net)],
                psbt: None,
            }],
            total_fees: fee,
            utxo_count: utxos.len(),
        })
    }
}

/// Maps each distinct old-federation derived address to a corresponding
/// new-federation address, sweeping per-address groups into separate
/// transactions.
///
/// `address_map` provides the explicit pairing from old `script_pubkey` to
/// new [`Address`] that the consumer derived from the new federation. (We
/// take a script-pubkey key rather than `Address` because `LocalOutput`'s
/// `txout.script_pubkey` is what we have to match against.)
pub struct AddressForAddressSweep {
    /// `old script_pubkey` → `new federation address`.
    pub address_map: BTreeMap<ScriptBuf, Address>,
}

impl AddressForAddressSweep {
    /// Construct from the explicit `script_pubkey → new Address` mapping.
    pub fn new(address_map: BTreeMap<ScriptBuf, Address>) -> Self {
        Self { address_map }
    }
}

impl SweepAlgorithm<LocalOutput, UnsignedPsbt> for AddressForAddressSweep {
    fn plan(
        &self,
        utxos: &[LocalOutput],
        old_federation: &Federation,
        new_federation: &Federation,
        fee_rate: FeeRate,
    ) -> Result<MigrationPlan<UnsignedPsbt>, MigrationError> {
        ensure_same_network(old_federation, new_federation)?;
        if utxos.is_empty() {
            return Err(MigrationError::NoUtxos);
        }
        // Group UTXOs by source script_pubkey.
        let mut groups: BTreeMap<ScriptBuf, Vec<&LocalOutput>> = BTreeMap::new();
        for u in utxos {
            groups
                .entry(u.txout.script_pubkey.clone())
                .or_default()
                .push(u);
        }

        let mut sweep_transactions = Vec::with_capacity(groups.len());
        let mut total_fees = Amount::ZERO;
        for (spk, group) in &groups {
            let destination = self.address_map.get(spk).ok_or_else(|| {
                MigrationError::InvalidConfig(format!(
                    "address_map missing entry for source script_pubkey {spk:?}"
                ))
            })?;
            let value: Amount = group
                .iter()
                .map(|u| u.txout.value)
                .fold(Amount::ZERO, |a, b| a + b);
            let fee = estimate_fee(group.len(), 1, fee_rate);
            total_fees += fee;
            let net = value.checked_sub(fee).ok_or_else(|| {
                MigrationError::SweepFailed(format!("fee {fee} exceeds group value {value}"))
            })?;
            sweep_transactions.push(SweepTransaction {
                source_utxos: group.iter().map(|u| u.outpoint).collect(),
                destinations: vec![(destination.clone(), net)],
                psbt: None,
            });
        }
        Ok(MigrationPlan {
            sweep_transactions,
            total_fees,
            utxo_count: utxos.len(),
        })
    }
}

/// Splits the migration into batches of at most `max_inputs_per_tx` UTXOs,
/// each consolidated to `destination_address`.
pub struct BatchedSweep {
    /// Maximum inputs per individual sweep transaction. Must be >= 1.
    pub max_inputs_per_tx: usize,
    /// Destination for every batch.
    pub destination_address: Address,
}

impl BatchedSweep {
    /// Construct with explicit batch size.
    pub fn new(max_inputs_per_tx: usize, destination_address: Address) -> Self {
        Self {
            max_inputs_per_tx,
            destination_address,
        }
    }
}

impl SweepAlgorithm<LocalOutput, UnsignedPsbt> for BatchedSweep {
    fn plan(
        &self,
        utxos: &[LocalOutput],
        old_federation: &Federation,
        new_federation: &Federation,
        fee_rate: FeeRate,
    ) -> Result<MigrationPlan<UnsignedPsbt>, MigrationError> {
        ensure_same_network(old_federation, new_federation)?;
        if self.max_inputs_per_tx == 0 {
            return Err(MigrationError::InvalidConfig(
                "max_inputs_per_tx must be at least 1".into(),
            ));
        }
        if utxos.is_empty() {
            return Err(MigrationError::NoUtxos);
        }
        let mut sweep_transactions = Vec::new();
        let mut total_fees = Amount::ZERO;
        for chunk in utxos.chunks(self.max_inputs_per_tx) {
            let value: Amount = chunk
                .iter()
                .map(|u| u.txout.value)
                .fold(Amount::ZERO, |a, b| a + b);
            let fee = estimate_fee(chunk.len(), 1, fee_rate);
            total_fees += fee;
            let net = value.checked_sub(fee).ok_or_else(|| {
                MigrationError::SweepFailed(format!("fee {fee} exceeds chunk value {value}"))
            })?;
            sweep_transactions.push(SweepTransaction {
                source_utxos: chunk.iter().map(|u| u.outpoint).collect(),
                destinations: vec![(self.destination_address.clone(), net)],
                psbt: None,
            });
        }
        Ok(MigrationPlan {
            sweep_transactions,
            total_fees,
            utxo_count: utxos.len(),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ensure_same_network<S: Signer>(
    old: &Federation<S>,
    new: &Federation<S>,
) -> Result<(), MigrationError> {
    if old.network() != new.network() {
        return Err(MigrationError::NetworkMismatch {
            old: old.network(),
            new: new.network(),
        });
    }
    Ok(())
}

/// Rough P2WSH multisig fee estimate. Real fee accounting is left to BDK at
/// PSBT-construction time; this is a planning estimate.
fn estimate_fee(input_count: usize, output_count: usize, fee_rate: FeeRate) -> Amount {
    // Conservative average witness size for a 2-of-3 P2WSH multisig input,
    // adequate for planning. Real sizes vary by m-of-n.
    const APPROX_WSH_INPUT_VBYTES: u64 = 105;
    const APPROX_OUTPUT_VBYTES: u64 = 32;
    const APPROX_OVERHEAD_VBYTES: u64 = 10;
    let total_vb = APPROX_OVERHEAD_VBYTES
        + (input_count as u64) * APPROX_WSH_INPUT_VBYTES
        + (output_count as u64) * APPROX_OUTPUT_VBYTES;
    let weight = bitcoin::Weight::from_vb(total_vb).unwrap_or(bitcoin::Weight::ZERO);
    fee_rate.fee_wu(weight).unwrap_or(Amount::ZERO)
}

// Empty type used only by FederationMigration's PhantomData.
#[allow(dead_code)]
struct _PhantomP<P>(PhantomData<P>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockSigner;
    use bdk_wallet::KeychainKind;
    use bitcoin::hashes::Hash;
    use bitcoin::{Network, Txid};

    fn fed(seeds: &[u64]) -> Federation {
        Federation::new(
            2,
            seeds
                .iter()
                .map(|&s| Box::new(MockSigner::with_seed(s, Network::Testnet)) as Box<dyn Signer>)
                .collect(),
            Network::Testnet.into(),
        )
        .unwrap()
    }

    fn dummy_address() -> Address {
        // Standard testnet P2WPKH; only used as a sweep destination in tests.
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
            .parse::<Address<_>>()
            .unwrap()
            .require_network(Network::Testnet)
            .unwrap()
    }

    fn dummy_utxo(amount_sat: u64, idx: u32) -> LocalOutput {
        LocalOutput {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([idx as u8; 32]),
                vout: idx,
            },
            txout: bitcoin::TxOut {
                value: Amount::from_sat(amount_sat),
                script_pubkey: dummy_address().script_pubkey(),
            },
            keychain: KeychainKind::External,
            is_spent: false,
            derivation_index: idx,
            chain_position: bdk_wallet::chain::ChainPosition::Unconfirmed {
                first_seen: None,
                last_seen: None,
            },
        }
    }

    #[test]
    fn consolidation_produces_single_tx() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let utxos = vec![dummy_utxo(100_000, 0), dummy_utxo(200_000, 1)];
        let alg = ConsolidationSweep::new(dummy_address());
        let plan = alg
            .plan(&utxos, &old, &new, FeeRate::from_sat_per_vb_u32(2))
            .unwrap();
        assert_eq!(plan.sweep_transactions.len(), 1);
        assert_eq!(plan.utxo_count, 2);
        assert_eq!(plan.sweep_transactions[0].source_utxos.len(), 2);
        assert_eq!(plan.sweep_transactions[0].destinations.len(), 1);
    }

    #[test]
    fn batched_respects_max_inputs() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let utxos: Vec<_> = (0..10).map(|i| dummy_utxo(50_000, i)).collect();
        let alg = BatchedSweep::new(3, dummy_address());
        let plan = alg
            .plan(&utxos, &old, &new, FeeRate::from_sat_per_vb_u32(1))
            .unwrap();
        assert_eq!(plan.sweep_transactions.len(), 4); // 3+3+3+1
        assert_eq!(plan.utxo_count, 10);
    }

    #[test]
    fn batched_rejects_zero_batch_size() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let alg = BatchedSweep::new(0, dummy_address());
        let err = alg
            .plan(
                &[dummy_utxo(1000, 0)],
                &old,
                &new,
                FeeRate::from_sat_per_vb_u32(1),
            )
            .unwrap_err();
        assert!(matches!(err, MigrationError::InvalidConfig(_)));
    }

    #[test]
    fn empty_utxos_rejected() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let alg = ConsolidationSweep::new(dummy_address());
        let err = alg
            .plan(&[], &old, &new, FeeRate::from_sat_per_vb_u32(1))
            .unwrap_err();
        assert!(matches!(err, MigrationError::NoUtxos));
    }

    #[test]
    fn address_for_address_groups_per_script_pubkey() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let mut utxos = vec![dummy_utxo(100_000, 0)];
        // Construct a UTXO with a different script_pubkey:
        let mut alt = dummy_utxo(50_000, 1);
        alt.txout.script_pubkey =
            ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap();
        utxos.push(alt.clone());

        let mut map = BTreeMap::new();
        map.insert(utxos[0].txout.script_pubkey.clone(), dummy_address());
        map.insert(alt.txout.script_pubkey.clone(), dummy_address());

        let alg = AddressForAddressSweep::new(map);
        let plan = alg
            .plan(&utxos, &old, &new, FeeRate::from_sat_per_vb_u32(1))
            .unwrap();
        assert_eq!(plan.sweep_transactions.len(), 2);
    }
}
