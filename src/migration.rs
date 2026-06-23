//! Federation migration helpers — pluggable strategies for sweeping funds
//! from an old federation to a new one after a signer rotation.
//!
//! This module provides:
//!
//! - The [`SweepAlgorithm`] trait, generic over the UTXO and PSBT types so
//!   future Elements / Liquid implementations slot in cleanly.
//! - Single-account algorithms:
//!   - [`ConsolidationSweep`] — collects all UTXOs into a single output at
//!     the new federation's first receive address.
//!   - [`BatchedSweep`] — splits the migration into multiple transactions
//!     bounded by `max_inputs_per_tx`.
//! - Multi-account algorithms (operate across all BIP-48 account indices):
//!   - [`AccountForAccountSweep`] — sweeps all accounts in a single
//!     transaction. Fees paid by a designated internal account.
//!   - [`AccountForAccountBatchedSweep`] — one transaction per account by
//!     default; small accounts bundled. Fee account migrates last.
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

use std::marker::PhantomData;

use bdk_wallet::LocalOutput;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, FeeRate, OutPoint, Txid};

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
    ///
    /// # Errors
    ///
    /// Implementations return [`MigrationError`] when the inputs are
    /// inconsistent (network mismatch, empty UTXO set, missing destination
    /// mapping, fee exceeds value, etc.).
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
// Multi-account types
// ---------------------------------------------------------------------------

/// A single account's UTXOs and its destination address in the new federation.
///
/// Used as the UTXO type parameter `U` for multi-account sweep algorithms
/// ([`AccountForAccountSweep`], [`AccountForAccountBatchedSweep`]).
#[derive(Debug, Clone)]
pub struct AccountUtxoSet {
    /// BIP-48 account index (`m/48'/{coin}'/{account_idx}'/2'`).
    pub account_idx: u32,
    /// UTXOs belonging to this account in the old federation.
    pub utxos: Vec<LocalOutput>,
    /// Destination address in the new federation for this account's funds.
    pub destination_address: Address,
}

impl AccountUtxoSet {
    /// Total value across all UTXOs in this account.
    fn total_value(&self) -> Amount {
        self.utxos
            .iter()
            .map(|u| u.txout.value)
            .fold(Amount::ZERO, |a, b| a + b)
    }
}

// ---------------------------------------------------------------------------
// Multi-account algorithms
// ---------------------------------------------------------------------------

/// Sweeps all accounts in a single transaction. Fees paid by a designated
/// internal account; customer accounts receive their full balance.
pub struct AccountForAccountSweep {
    fee_account_idx: u32,
}

impl AccountForAccountSweep {
    /// Construct with the fee-paying account index.
    pub fn new(fee_account_idx: u32) -> Self {
        Self { fee_account_idx }
    }
}

impl SweepAlgorithm<AccountUtxoSet, UnsignedPsbt> for AccountForAccountSweep {
    fn plan(
        &self,
        utxos: &[AccountUtxoSet],
        old_federation: &Federation,
        new_federation: &Federation,
        fee_rate: FeeRate,
    ) -> Result<MigrationPlan<UnsignedPsbt>, MigrationError> {
        ensure_same_network(old_federation, new_federation)?;

        let funded: Vec<&AccountUtxoSet> =
            utxos.iter().filter(|a| !a.utxos.is_empty()).collect();
        if funded.is_empty() {
            return Err(MigrationError::NoUtxos);
        }

        let fee_account = funded
            .iter()
            .find(|a| a.account_idx == self.fee_account_idx)
            .ok_or_else(|| {
                MigrationError::InvalidConfig(format!(
                    "fee account index {} not found in input set or has no UTXOs",
                    self.fee_account_idx
                ))
            })?;

        let total_inputs: usize = funded.iter().map(|a| a.utxos.len()).sum();
        let fee = estimate_fee(total_inputs, funded.len(), fee_rate);

        let fee_account_value = fee_account.total_value();
        if fee_account_value < fee {
            return Err(MigrationError::InsufficientFeeBalance {
                fee_account_idx: self.fee_account_idx,
                available: fee_account_value,
                required: fee,
            });
        }

        let source_utxos: Vec<OutPoint> = funded
            .iter()
            .flat_map(|a| a.utxos.iter().map(|u| u.outpoint))
            .collect();

        let destinations: Vec<(Address, Amount)> = funded
            .iter()
            .map(|a| {
                let value = if a.account_idx == self.fee_account_idx {
                    a.total_value() - fee
                } else {
                    a.total_value()
                };
                (a.destination_address.clone(), value)
            })
            .collect();

        Ok(MigrationPlan {
            utxo_count: total_inputs,
            total_fees: fee,
            sweep_transactions: vec![SweepTransaction {
                source_utxos,
                destinations,
                psbt: None,
            }],
        })
    }
}

/// Sweeps each account in its own transaction. Small accounts are bundled.
/// Fees paid by a designated internal account that migrates last.
pub struct AccountForAccountBatchedSweep {
    fee_account_idx: u32,
    small_account_threshold: Amount,
}

impl AccountForAccountBatchedSweep {
    /// Construct with fee account index and small-account bundling threshold.
    pub fn new(fee_account_idx: u32, small_account_threshold: Amount) -> Self {
        Self {
            fee_account_idx,
            small_account_threshold,
        }
    }
}

/// Mutable state threaded through the batched sweep's transaction builders.
struct BatchedPlanState {
    sweep_transactions: Vec<SweepTransaction<UnsignedPsbt>>,
    total_utxo_count: usize,
    cumulative_fee: Amount,
}

impl AccountForAccountBatchedSweep {
    /// Build one `SweepTransaction` per large account, each funded by a
    /// fee-account UTXO (chain of unconfirmed change).
    fn plan_large_accounts(
        state: &mut BatchedPlanState,
        large: &[&AccountUtxoSet],
        fee_utxos: &[OutPoint],
        initial_fee_utxo_value: Amount,
        fee_account_dest: &Address,
        fee_rate: FeeRate,
    ) {
        for (tx_idx, acct) in large.iter().enumerate() {
            let acct_inputs = acct.utxos.len();
            let tx_fee = estimate_fee(acct_inputs + 1, 2, fee_rate);

            let mut source: Vec<OutPoint> =
                acct.utxos.iter().map(|u| u.outpoint).collect();
            if tx_idx == 0 {
                source.push(fee_utxos[0]);
            } else {
                source.push(synthetic_change_outpoint(tx_idx - 1));
            }

            let fee_input_value = if tx_idx == 0 {
                initial_fee_utxo_value
            } else {
                initial_fee_utxo_value - state.cumulative_fee
            };

            state.cumulative_fee += tx_fee;

            let destinations = vec![
                (acct.destination_address.clone(), acct.total_value()),
                (fee_account_dest.clone(), fee_input_value - tx_fee),
            ];

            state.total_utxo_count += acct_inputs + 1;
            state.sweep_transactions.push(SweepTransaction {
                source_utxos: source,
                destinations,
                psbt: None,
            });
        }
    }

    /// Build a single bundled `SweepTransaction` for all small accounts.
    fn plan_small_bundle(
        state: &mut BatchedPlanState,
        small: &[&AccountUtxoSet],
        fee_utxos: &[OutPoint],
        initial_fee_utxo_value: Amount,
        fee_account_dest: &Address,
        fee_rate: FeeRate,
        preceding_tx_count: usize,
    ) {
        let small_inputs: usize = small.iter().map(|a| a.utxos.len()).sum();
        let tx_fee = estimate_fee(small_inputs + 1, small.len() + 1, fee_rate);

        let mut source: Vec<OutPoint> = small
            .iter()
            .flat_map(|a| a.utxos.iter().map(|u| u.outpoint))
            .collect();

        if preceding_tx_count == 0 {
            source.push(fee_utxos[0]);
        } else {
            source.push(synthetic_change_outpoint(preceding_tx_count - 1));
        }

        let fee_input_value = if preceding_tx_count == 0 {
            initial_fee_utxo_value
        } else {
            initial_fee_utxo_value - state.cumulative_fee
        };

        state.cumulative_fee += tx_fee;

        let mut destinations: Vec<(Address, Amount)> = small
            .iter()
            .map(|a| (a.destination_address.clone(), a.total_value()))
            .collect();
        destinations.push((fee_account_dest.clone(), fee_input_value - tx_fee));

        state.total_utxo_count += small_inputs + 1;
        state.sweep_transactions.push(SweepTransaction {
            source_utxos: source,
            destinations,
            psbt: None,
        });
    }
}

impl SweepAlgorithm<AccountUtxoSet, UnsignedPsbt> for AccountForAccountBatchedSweep {
    fn plan(
        &self,
        utxos: &[AccountUtxoSet],
        old_federation: &Federation,
        new_federation: &Federation,
        fee_rate: FeeRate,
    ) -> Result<MigrationPlan<UnsignedPsbt>, MigrationError> {
        ensure_same_network(old_federation, new_federation)?;

        let funded: Vec<&AccountUtxoSet> =
            utxos.iter().filter(|a| !a.utxos.is_empty()).collect();
        if funded.is_empty() {
            return Err(MigrationError::NoUtxos);
        }

        let fee_account = funded
            .iter()
            .find(|a| a.account_idx == self.fee_account_idx)
            .ok_or_else(|| {
                MigrationError::InvalidConfig(format!(
                    "fee account index {} not found in input set or has no UTXOs",
                    self.fee_account_idx
                ))
            })?;
        let fee_account_dest = fee_account.destination_address.clone();
        let fee_account_total = fee_account.total_value();
        let initial_fee_utxo_value = fee_account.utxos[0].txout.value;

        let non_fee: Vec<&AccountUtxoSet> = funded
            .iter()
            .filter(|a| a.account_idx != self.fee_account_idx)
            .copied()
            .collect();

        let (large, small): (Vec<&AccountUtxoSet>, Vec<&AccountUtxoSet>) = non_fee
            .into_iter()
            .partition(|a| a.total_value() >= self.small_account_threshold);

        // Pre-flight: estimate total fees across all planned transactions.
        let planned_fees = batched_estimate_total_fees(
            &large, &small, fee_account.utxos.len(), fee_rate,
        );

        if fee_account_total < planned_fees {
            return Err(MigrationError::InsufficientFeeBalance {
                fee_account_idx: self.fee_account_idx,
                available: fee_account_total,
                required: planned_fees,
            });
        }

        let fee_utxos: Vec<OutPoint> =
            fee_account.utxos.iter().map(|u| u.outpoint).collect();

        let mut state = BatchedPlanState {
            sweep_transactions: Vec::new(),
            total_utxo_count: 0,
            cumulative_fee: Amount::ZERO,
        };

        Self::plan_large_accounts(
            &mut state, &large, &fee_utxos,
            initial_fee_utxo_value, &fee_account_dest, fee_rate,
        );

        if !small.is_empty() {
            Self::plan_small_bundle(
                &mut state, &small, &fee_utxos,
                initial_fee_utxo_value, &fee_account_dest, fee_rate,
                large.len(),
            );
        }

        // Fee account migration (always last)
        let fee_migration_fee = estimate_fee(fee_account.utxos.len(), 1, fee_rate);
        state.cumulative_fee += fee_migration_fee;

        let mut fee_source: Vec<OutPoint> = fee_utxos;
        if !state.sweep_transactions.is_empty() {
            fee_source.remove(0);
            fee_source.push(synthetic_change_outpoint(
                state.sweep_transactions.len() - 1,
            ));
        }

        let fee_account_remaining = fee_account_total - state.cumulative_fee;
        state.total_utxo_count += fee_source.len();

        state.sweep_transactions.push(SweepTransaction {
            source_utxos: fee_source,
            destinations: vec![(fee_account_dest, fee_account_remaining)],
            psbt: None,
        });

        Ok(MigrationPlan {
            sweep_transactions: state.sweep_transactions,
            total_fees: state.cumulative_fee,
            utxo_count: state.total_utxo_count,
        })
    }
}

fn batched_estimate_total_fees(
    large: &[&AccountUtxoSet],
    small: &[&AccountUtxoSet],
    fee_account_utxo_count: usize,
    fee_rate: FeeRate,
) -> Amount {
    let mut total = Amount::ZERO;
    for acct in large {
        total += estimate_fee(acct.utxos.len() + 1, 2, fee_rate);
    }
    if !small.is_empty() {
        let small_input_count: usize =
            small.iter().map(|a| a.utxos.len()).sum::<usize>() + 1;
        total += estimate_fee(small_input_count, small.len() + 1, fee_rate);
    }
    total += estimate_fee(fee_account_utxo_count, 1, fee_rate);
    total
}

/// Synthetic outpoint representing the change output from a preceding sweep
/// transaction in the fee-account chain. The actual outpoint is unknown at
/// planning time; this placeholder uses a zeroed txid with the transaction's
/// sequence index as vout.
fn synthetic_change_outpoint(preceding_tx_index: usize) -> OutPoint {
    #[allow(clippy::cast_possible_truncation)]
    OutPoint {
        txid: Txid::from_byte_array([0u8; 32]),
        vout: preceding_tx_index as u32,
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
        let byte = u8::try_from(idx & 0xff).expect("idx & 0xff fits u8");
        LocalOutput {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([byte; 32]),
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

    // -----------------------------------------------------------------------
    // Multi-account algorithm helpers
    // -----------------------------------------------------------------------

    fn account_set(account_idx: u32, amounts: &[u64]) -> AccountUtxoSet {
        AccountUtxoSet {
            account_idx,
            utxos: amounts
                .iter()
                .enumerate()
                .map(|(i, &amt)| {
                    let global_idx = account_idx * 100 + i as u32;
                    dummy_utxo(amt, global_idx)
                })
                .collect(),
            destination_address: dummy_address(),
        }
    }

    fn rate() -> FeeRate {
        FeeRate::from_sat_per_vb_u32(2)
    }

    // -----------------------------------------------------------------------
    // AccountForAccountSweep tests
    // -----------------------------------------------------------------------

    #[test]
    fn account_for_account_single_tx() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let accounts = vec![
            account_set(0, &[500_000]),       // fee account
            account_set(1, &[100_000]),
            account_set(2, &[200_000]),
            account_set(3, &[300_000, 50_000]),
        ];
        let alg = AccountForAccountSweep::new(0);
        let plan = alg.plan(&accounts, &old, &new, rate()).unwrap();

        assert_eq!(plan.sweep_transactions.len(), 1);
        assert_eq!(plan.sweep_transactions[0].destinations.len(), 4);
    }

    #[test]
    fn account_for_account_fee_from_designated_account() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let accounts = vec![
            account_set(0, &[500_000]),
            account_set(1, &[100_000]),
            account_set(2, &[200_000]),
        ];
        let alg = AccountForAccountSweep::new(0);
        let plan = alg.plan(&accounts, &old, &new, rate()).unwrap();

        let tx = &plan.sweep_transactions[0];
        // Destinations follow input order: acct 0 (fee), acct 1, acct 2.
        assert_eq!(tx.destinations.len(), 3);

        // Fee account (idx 0) gets its value minus the fee.
        assert_eq!(
            tx.destinations[0].1,
            Amount::from_sat(500_000) - plan.total_fees
        );
        // Customer accounts receive their exact input value.
        assert_eq!(tx.destinations[1].1, Amount::from_sat(100_000));
        assert_eq!(tx.destinations[2].1, Amount::from_sat(200_000));

        // Total output value + fees = total input value.
        let total_output: Amount = tx.destinations.iter().map(|(_, v)| *v).sum();
        assert_eq!(
            total_output + plan.total_fees,
            Amount::from_sat(800_000)
        );
    }

    #[test]
    fn account_for_account_skips_empty_accounts() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let accounts = vec![
            account_set(0, &[500_000]),
            AccountUtxoSet {
                account_idx: 1,
                utxos: vec![],
                destination_address: dummy_address(),
            },
            account_set(2, &[100_000]),
        ];
        let alg = AccountForAccountSweep::new(0);
        let plan = alg.plan(&accounts, &old, &new, rate()).unwrap();

        // Only 2 funded accounts → 2 outputs.
        assert_eq!(plan.sweep_transactions[0].destinations.len(), 2);
    }

    #[test]
    fn account_for_account_rejects_missing_fee_account() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let accounts = vec![
            account_set(1, &[100_000]),
            account_set(2, &[200_000]),
        ];
        let alg = AccountForAccountSweep::new(99);
        let err = alg.plan(&accounts, &old, &new, rate()).unwrap_err();
        assert!(matches!(err, MigrationError::InvalidConfig(_)));
    }

    #[test]
    fn account_for_account_rejects_insufficient_fee_balance() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        // Fee account has only 1 sat — way too small for any fee.
        let accounts = vec![
            account_set(0, &[1]),
            account_set(1, &[100_000]),
            account_set(2, &[200_000]),
        ];
        let alg = AccountForAccountSweep::new(0);
        let err = alg.plan(&accounts, &old, &new, rate()).unwrap_err();
        assert!(matches!(
            err,
            MigrationError::InsufficientFeeBalance { .. }
        ));
    }

    #[test]
    fn account_for_account_rejects_empty_input() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let alg = AccountForAccountSweep::new(0);
        let err = alg
            .plan(&[], &old, &new, rate())
            .unwrap_err();
        assert!(matches!(err, MigrationError::NoUtxos));
    }

    // -----------------------------------------------------------------------
    // AccountForAccountBatchedSweep tests
    // -----------------------------------------------------------------------

    #[test]
    fn batched_account_splits_by_threshold() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let threshold = Amount::from_sat(100_000);
        let accounts = vec![
            account_set(0, &[1_000_000]),         // fee account (large)
            account_set(1, &[200_000]),            // large
            account_set(2, &[150_000]),            // large
            account_set(3, &[50_000]),             // small
            account_set(4, &[30_000]),             // small
        ];
        let alg = AccountForAccountBatchedSweep::new(0, threshold);
        let plan = alg.plan(&accounts, &old, &new, rate()).unwrap();

        // 2 large individual txs + 1 small bundle + 1 fee account last = 4
        assert_eq!(plan.sweep_transactions.len(), 4);
    }

    #[test]
    fn batched_account_all_large() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let threshold = Amount::from_sat(10_000);
        let accounts = vec![
            account_set(0, &[1_000_000]),         // fee
            account_set(1, &[200_000]),
            account_set(2, &[150_000]),
        ];
        let alg = AccountForAccountBatchedSweep::new(0, threshold);
        let plan = alg.plan(&accounts, &old, &new, rate()).unwrap();

        // 2 large + 0 bundle + 1 fee = 3
        assert_eq!(plan.sweep_transactions.len(), 3);
    }

    #[test]
    fn batched_account_all_small() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let threshold = Amount::from_sat(1_000_000);
        let accounts = vec![
            account_set(0, &[5_000_000]),         // fee
            account_set(1, &[50_000]),
            account_set(2, &[30_000]),
            account_set(3, &[20_000]),
        ];
        let alg = AccountForAccountBatchedSweep::new(0, threshold);
        let plan = alg.plan(&accounts, &old, &new, rate()).unwrap();

        // 0 large + 1 bundle + 1 fee = 2
        assert_eq!(plan.sweep_transactions.len(), 2);
    }

    #[test]
    fn batched_account_fee_account_last() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let accounts = vec![
            account_set(0, &[1_000_000]),
            account_set(1, &[200_000]),
            account_set(2, &[50_000]),
        ];
        let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
        let plan = alg.plan(&accounts, &old, &new, rate()).unwrap();

        let last_tx = plan.sweep_transactions.last().unwrap();
        // The last transaction's single output goes to the fee account.
        assert_eq!(last_tx.destinations.len(), 1);
    }

    #[test]
    fn batched_account_fee_chain() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        // Use account index 5 for the fee account so its UTXO txid
        // ([5u8; 32]) is distinct from the synthetic zeroed txid.
        let accounts = vec![
            account_set(5, &[1_000_000]),
            account_set(1, &[200_000]),
            account_set(2, &[300_000]),
        ];
        let alg = AccountForAccountBatchedSweep::new(5, Amount::from_sat(100_000));
        let plan = alg.plan(&accounts, &old, &new, rate()).unwrap();

        // First non-fee tx uses the fee account's real UTXO.
        let first_tx = &plan.sweep_transactions[0];
        let fee_input = first_tx.source_utxos.last().unwrap();
        assert_ne!(fee_input.txid, Txid::from_byte_array([0u8; 32]));

        // Second non-fee tx uses a synthetic change outpoint from tx 0.
        if plan.sweep_transactions.len() > 2 {
            let second_tx = &plan.sweep_transactions[1];
            let fee_input_2 = second_tx.source_utxos.last().unwrap();
            assert_eq!(fee_input_2.txid, Txid::from_byte_array([0u8; 32]));
            assert_eq!(fee_input_2.vout, 0);
        }
    }

    #[test]
    fn batched_account_preflight_rejects_insufficient() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        // Fee account with tiny balance.
        let accounts = vec![
            account_set(0, &[100]),
            account_set(1, &[200_000]),
            account_set(2, &[300_000]),
        ];
        let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
        let err = alg.plan(&accounts, &old, &new, rate()).unwrap_err();
        assert!(matches!(
            err,
            MigrationError::InsufficientFeeBalance { .. }
        ));
    }

    #[test]
    fn batched_account_rejects_empty_input() {
        let old = fed(&[1, 2, 3]);
        let new = fed(&[4, 5, 6]);
        let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
        let err = alg
            .plan(&[], &old, &new, rate())
            .unwrap_err();
        assert!(matches!(err, MigrationError::NoUtxos));
    }

    #[test]
    fn both_account_algorithms_reject_network_mismatch() {
        let old = fed(&[1, 2, 3]);
        let new_mainnet = Federation::new(
            2,
            [10u64, 20, 30]
                .iter()
                .map(|&s| {
                    Box::new(MockSigner::with_seed(s, Network::Bitcoin)) as Box<dyn Signer>
                })
                .collect(),
            Network::Bitcoin.into(),
        )
        .unwrap();
        let accounts = vec![account_set(0, &[500_000])];

        let err1 = AccountForAccountSweep::new(0)
            .plan(&accounts, &old, &new_mainnet, rate())
            .unwrap_err();
        assert!(matches!(err1, MigrationError::NetworkMismatch { .. }));

        let err2 = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000))
            .plan(&accounts, &old, &new_mainnet, rate())
            .unwrap_err();
        assert!(matches!(err2, MigrationError::NetworkMismatch { .. }));
    }
}
