//! Federation migration helpers — pluggable strategies for sweeping funds
//! from an old federation to a new one after a signer rotation.
//!
//! This module provides:
//!
//! - The [`SweepAlgorithm`] trait, generic over the UTXO and PSBT types so
//!   future Elements / Liquid implementations slot in cleanly.
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
use crate::network::NetworkType;
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

/// A single output within a [`SweepTransaction`].
///
/// Customer outputs carry their concrete new-federation address. The
/// **fee-change** output deliberately carries *no address*: the consumer
/// resolves it to the fee account's **old**-federation address for intermediate
/// (chained) transactions and to its **new**-federation address for the final
/// fee-account transaction ([`SweepTransaction::is_fee_final`]). This keeps the
/// planner network/address-agnostic — it decides amounts and topology only —
/// and lets the consumer own which federation the fee change lives at per hop.
#[derive(Debug, Clone)]
pub enum SweepOutput {
    /// A customer account's funds, paid in full to its new-federation address.
    Customer {
        /// BIP-48 account index this output belongs to.
        account_idx: u32,
        /// The customer's destination address in the new federation.
        address: Address,
        /// The exact amount paid (the account's full balance).
        amount: Amount,
    },
    /// The fee account's change/consolidation output. The amount is the drained
    /// remainder (`fee_input_value - tx_fee`); the address is resolved by the
    /// consumer per [`SweepTransaction::is_fee_final`].
    FeeChange {
        /// The fee account's BIP-48 account index.
        account_idx: u32,
        /// The drained remainder routed to the fee account.
        amount: Amount,
    },
}

impl SweepOutput {
    /// The BIP-48 account index this output belongs to.
    #[must_use]
    pub fn account_idx(&self) -> u32 {
        match self {
            SweepOutput::Customer { account_idx, .. }
            | SweepOutput::FeeChange { account_idx, .. } => *account_idx,
        }
    }

    /// The output amount (pre-fee; the fee-change drain absorbs the real fee).
    #[must_use]
    pub fn amount(&self) -> Amount {
        match self {
            SweepOutput::Customer { amount, .. } | SweepOutput::FeeChange { amount, .. } => *amount,
        }
    }
}

/// A single sweep transaction's shape.
#[derive(Debug)]
pub struct SweepTransaction<P: std::fmt::Debug> {
    /// Source UTXO outpoints to spend.
    pub source_utxos: Vec<OutPoint>,
    /// The transaction's outputs. Amounts are pre-fee estimates; the consumer's
    /// PSBT builder adjusts for actual fees (the fee-change output absorbs the
    /// difference via `drain_to`).
    pub outputs: Vec<SweepOutput>,
    /// `true` for the final, fee-account-only transaction — the consumer routes
    /// its [`SweepOutput::FeeChange`] to the **new** federation. Intermediate
    /// transactions (`false`) route fee change to the fee account's **old**
    /// federation address so it stays old-fed-signed until this last hop.
    pub is_fee_final: bool,
    /// The constructed PSBT, if the algorithm provides one.
    ///
    /// v1 built-in algorithms leave this `None`; the consumer builds the
    /// PSBT via [`bdk_wallet::Wallet::build_tx`] using the outputs
    /// described above.
    pub psbt: Option<P>,
}

/// Pluggable sweep algorithm.
pub trait SweepAlgorithm<U, P = UnsignedPsbt>: Send + Sync
where
    P: std::fmt::Debug,
{
    /// Produce a migration plan for sweeping `utxos` from an old federation
    /// to a new one at the given `fee_rate`.
    ///
    /// `old_network` / `new_network` are validated to match. All UTXO
    /// source/destination resolution is the caller's responsibility.
    ///
    /// # Errors
    ///
    /// Implementations return [`MigrationError`] when the inputs are
    /// inconsistent (network mismatch, empty UTXO set, missing destination
    /// mapping, fee exceeds value, etc.).
    fn plan(
        &self,
        utxos: &[U],
        old_network: NetworkType,
        new_network: NetworkType,
        fee_rate: FeeRate,
    ) -> Result<MigrationPlan<P>, MigrationError>;
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
        old_network: NetworkType,
        new_network: NetworkType,
        fee_rate: FeeRate,
    ) -> Result<MigrationPlan<UnsignedPsbt>, MigrationError> {
        ensure_same_network(old_network, new_network)?;

        let funded: Vec<&AccountUtxoSet> = utxos.iter().filter(|a| !a.utxos.is_empty()).collect();
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

        let outputs: Vec<SweepOutput> = funded
            .iter()
            .map(|a| {
                if a.account_idx == self.fee_account_idx {
                    SweepOutput::FeeChange {
                        account_idx: a.account_idx,
                        amount: a.total_value() - fee,
                    }
                } else {
                    SweepOutput::Customer {
                        account_idx: a.account_idx,
                        address: a.destination_address.clone(),
                        amount: a.total_value(),
                    }
                }
            })
            .collect();

        Ok(MigrationPlan {
            utxo_count: total_inputs,
            total_fees: fee,
            // Single transaction: the fee account migrates in this same tx, so
            // its fee-change output resolves to the new federation.
            sweep_transactions: vec![SweepTransaction {
                source_utxos,
                outputs,
                is_fee_final: true,
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
        fee_account_idx: u32,
        fee_rate: FeeRate,
    ) {
        for (tx_idx, acct) in large.iter().enumerate() {
            let acct_inputs = acct.utxos.len();
            let tx_fee = estimate_fee(acct_inputs + 1, 2, fee_rate);

            let mut source: Vec<OutPoint> = acct.utxos.iter().map(|u| u.outpoint).collect();
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

            let outputs = vec![
                SweepOutput::Customer {
                    account_idx: acct.account_idx,
                    address: acct.destination_address.clone(),
                    amount: acct.total_value(),
                },
                SweepOutput::FeeChange {
                    account_idx: fee_account_idx,
                    amount: fee_input_value - tx_fee,
                },
            ];

            state.total_utxo_count += acct_inputs + 1;
            state.sweep_transactions.push(SweepTransaction {
                source_utxos: source,
                outputs,
                is_fee_final: false,
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
        fee_account_idx: u32,
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

        let mut outputs: Vec<SweepOutput> = small
            .iter()
            .map(|a| SweepOutput::Customer {
                account_idx: a.account_idx,
                address: a.destination_address.clone(),
                amount: a.total_value(),
            })
            .collect();
        outputs.push(SweepOutput::FeeChange {
            account_idx: fee_account_idx,
            amount: fee_input_value - tx_fee,
        });

        state.total_utxo_count += small_inputs + 1;
        state.sweep_transactions.push(SweepTransaction {
            source_utxos: source,
            outputs,
            is_fee_final: false,
            psbt: None,
        });
    }
}

impl SweepAlgorithm<AccountUtxoSet, UnsignedPsbt> for AccountForAccountBatchedSweep {
    fn plan(
        &self,
        utxos: &[AccountUtxoSet],
        old_network: NetworkType,
        new_network: NetworkType,
        fee_rate: FeeRate,
    ) -> Result<MigrationPlan<UnsignedPsbt>, MigrationError> {
        ensure_same_network(old_network, new_network)?;

        let funded: Vec<&AccountUtxoSet> = utxos.iter().filter(|a| !a.utxos.is_empty()).collect();
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
        let planned_fees =
            batched_estimate_total_fees(&large, &small, fee_account.utxos.len(), fee_rate);

        if fee_account_total < planned_fees {
            return Err(MigrationError::InsufficientFeeBalance {
                fee_account_idx: self.fee_account_idx,
                available: fee_account_total,
                required: planned_fees,
            });
        }

        let fee_utxos: Vec<OutPoint> = fee_account.utxos.iter().map(|u| u.outpoint).collect();

        let mut state = BatchedPlanState {
            sweep_transactions: Vec::new(),
            total_utxo_count: 0,
            cumulative_fee: Amount::ZERO,
        };

        Self::plan_large_accounts(
            &mut state,
            &large,
            &fee_utxos,
            initial_fee_utxo_value,
            self.fee_account_idx,
            fee_rate,
        );

        if !small.is_empty() {
            Self::plan_small_bundle(
                &mut state,
                &small,
                &fee_utxos,
                initial_fee_utxo_value,
                self.fee_account_idx,
                fee_rate,
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
            outputs: vec![SweepOutput::FeeChange {
                account_idx: self.fee_account_idx,
                amount: fee_account_remaining,
            }],
            is_fee_final: true,
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
        let small_input_count: usize = small.iter().map(|a| a.utxos.len()).sum::<usize>() + 1;
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

fn ensure_same_network(old: NetworkType, new: NetworkType) -> Result<(), MigrationError> {
    if old != new {
        return Err(MigrationError::NetworkMismatch { old, new });
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
    use bdk_wallet::KeychainKind;
    use bitcoin::hashes::Hash;
    use bitcoin::{Network, Txid};

    const TESTNET: NetworkType = NetworkType::Bitcoin(Network::Testnet);
    const MAINNET: NetworkType = NetworkType::Bitcoin(Network::Bitcoin);

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
                    let global_idx = account_idx * 100 + u32::try_from(i).expect("test index fits u32");
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
        let (old, new) = (TESTNET, TESTNET);
        let accounts = vec![
            account_set(0, &[500_000]), // fee account
            account_set(1, &[100_000]),
            account_set(2, &[200_000]),
            account_set(3, &[300_000, 50_000]),
        ];
        let alg = AccountForAccountSweep::new(0);
        let plan = alg.plan(&accounts, old, new, rate()).unwrap();

        assert_eq!(plan.sweep_transactions.len(), 1);
        assert_eq!(plan.sweep_transactions[0].outputs.len(), 4);
        assert!(plan.sweep_transactions[0].is_fee_final);
    }

    #[test]
    fn account_for_account_fee_from_designated_account() {
        let (old, new) = (TESTNET, TESTNET);
        let accounts = vec![
            account_set(0, &[500_000]),
            account_set(1, &[100_000]),
            account_set(2, &[200_000]),
        ];
        let alg = AccountForAccountSweep::new(0);
        let plan = alg.plan(&accounts, old, new, rate()).unwrap();

        let tx = &plan.sweep_transactions[0];
        // Outputs follow input order: acct 0 (fee), acct 1, acct 2.
        assert_eq!(tx.outputs.len(), 3);

        let amount_of = |idx: u32| {
            tx.outputs
                .iter()
                .find(|o| o.account_idx() == idx)
                .unwrap()
                .amount()
        };
        // Fee account (idx 0) is a FeeChange output: its value minus the fee.
        assert!(matches!(tx.outputs[0], SweepOutput::FeeChange { .. }));
        assert_eq!(amount_of(0), Amount::from_sat(500_000) - plan.total_fees);
        // Customer accounts receive their exact input value.
        assert!(matches!(tx.outputs[1], SweepOutput::Customer { .. }));
        assert_eq!(amount_of(1), Amount::from_sat(100_000));
        assert_eq!(amount_of(2), Amount::from_sat(200_000));

        // Total output value + fees = total input value.
        let total_output: Amount = tx.outputs.iter().map(SweepOutput::amount).sum();
        assert_eq!(total_output + plan.total_fees, Amount::from_sat(800_000));
    }

    #[test]
    fn account_for_account_skips_empty_accounts() {
        let (old, new) = (TESTNET, TESTNET);
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
        let plan = alg.plan(&accounts, old, new, rate()).unwrap();

        // Only 2 funded accounts → 2 outputs.
        assert_eq!(plan.sweep_transactions[0].outputs.len(), 2);
    }

    #[test]
    fn account_for_account_rejects_missing_fee_account() {
        let (old, new) = (TESTNET, TESTNET);
        let accounts = vec![account_set(1, &[100_000]), account_set(2, &[200_000])];
        let alg = AccountForAccountSweep::new(99);
        let err = alg.plan(&accounts, old, new, rate()).unwrap_err();
        assert!(matches!(err, MigrationError::InvalidConfig(_)));
    }

    #[test]
    fn account_for_account_rejects_insufficient_fee_balance() {
        let (old, new) = (TESTNET, TESTNET);
        // Fee account has only 1 sat — way too small for any fee.
        let accounts = vec![
            account_set(0, &[1]),
            account_set(1, &[100_000]),
            account_set(2, &[200_000]),
        ];
        let alg = AccountForAccountSweep::new(0);
        let err = alg.plan(&accounts, old, new, rate()).unwrap_err();
        assert!(matches!(err, MigrationError::InsufficientFeeBalance { .. }));
    }

    #[test]
    fn account_for_account_rejects_empty_input() {
        let (old, new) = (TESTNET, TESTNET);
        let alg = AccountForAccountSweep::new(0);
        let err = alg.plan(&[], old, new, rate()).unwrap_err();
        assert!(matches!(err, MigrationError::NoUtxos));
    }

    // -----------------------------------------------------------------------
    // AccountForAccountBatchedSweep tests
    // -----------------------------------------------------------------------

    #[test]
    fn batched_account_splits_by_threshold() {
        let (old, new) = (TESTNET, TESTNET);
        let threshold = Amount::from_sat(100_000);
        let accounts = vec![
            account_set(0, &[1_000_000]), // fee account (large)
            account_set(1, &[200_000]),   // large
            account_set(2, &[150_000]),   // large
            account_set(3, &[50_000]),    // small
            account_set(4, &[30_000]),    // small
        ];
        let alg = AccountForAccountBatchedSweep::new(0, threshold);
        let plan = alg.plan(&accounts, old, new, rate()).unwrap();

        // 2 large individual txs + 1 small bundle + 1 fee account last = 4
        assert_eq!(plan.sweep_transactions.len(), 4);
    }

    #[test]
    fn batched_account_all_large() {
        let (old, new) = (TESTNET, TESTNET);
        let threshold = Amount::from_sat(10_000);
        let accounts = vec![
            account_set(0, &[1_000_000]), // fee
            account_set(1, &[200_000]),
            account_set(2, &[150_000]),
        ];
        let alg = AccountForAccountBatchedSweep::new(0, threshold);
        let plan = alg.plan(&accounts, old, new, rate()).unwrap();

        // 2 large + 0 bundle + 1 fee = 3
        assert_eq!(plan.sweep_transactions.len(), 3);
    }

    #[test]
    fn batched_account_all_small() {
        let (old, new) = (TESTNET, TESTNET);
        let threshold = Amount::from_sat(1_000_000);
        let accounts = vec![
            account_set(0, &[5_000_000]), // fee
            account_set(1, &[50_000]),
            account_set(2, &[30_000]),
            account_set(3, &[20_000]),
        ];
        let alg = AccountForAccountBatchedSweep::new(0, threshold);
        let plan = alg.plan(&accounts, old, new, rate()).unwrap();

        // 0 large + 1 bundle + 1 fee = 2
        assert_eq!(plan.sweep_transactions.len(), 2);
    }

    #[test]
    fn batched_account_fee_account_last() {
        let (old, new) = (TESTNET, TESTNET);
        let accounts = vec![
            account_set(0, &[1_000_000]),
            account_set(1, &[200_000]),
            account_set(2, &[50_000]),
        ];
        let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
        let plan = alg.plan(&accounts, old, new, rate()).unwrap();

        let last_tx = plan.sweep_transactions.last().unwrap();
        // The last transaction is the fee-account migration: a single FeeChange
        // output and `is_fee_final` set.
        assert_eq!(last_tx.outputs.len(), 1);
        assert!(last_tx.is_fee_final);
        assert!(matches!(
            last_tx.outputs[0],
            SweepOutput::FeeChange { account_idx: 0, .. }
        ));

        // Every intermediate (non-final) tx carries exactly one FeeChange output
        // and is not marked final.
        for tx in &plan.sweep_transactions[..plan.sweep_transactions.len() - 1] {
            assert!(!tx.is_fee_final);
            let fee_outs = tx
                .outputs
                .iter()
                .filter(|o| matches!(o, SweepOutput::FeeChange { .. }))
                .count();
            assert_eq!(
                fee_outs, 1,
                "intermediate tx has exactly one FeeChange output"
            );
        }
    }

    #[test]
    fn batched_account_fee_chain() {
        let (old, new) = (TESTNET, TESTNET);
        // Use account index 5 for the fee account so its UTXO txid
        // ([5u8; 32]) is distinct from the synthetic zeroed txid.
        let accounts = vec![
            account_set(5, &[1_000_000]),
            account_set(1, &[200_000]),
            account_set(2, &[300_000]),
        ];
        let alg = AccountForAccountBatchedSweep::new(5, Amount::from_sat(100_000));
        let plan = alg.plan(&accounts, old, new, rate()).unwrap();

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
        let (old, new) = (TESTNET, TESTNET);
        // Fee account with tiny balance.
        let accounts = vec![
            account_set(0, &[100]),
            account_set(1, &[200_000]),
            account_set(2, &[300_000]),
        ];
        let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
        let err = alg.plan(&accounts, old, new, rate()).unwrap_err();
        assert!(matches!(err, MigrationError::InsufficientFeeBalance { .. }));
    }

    #[test]
    fn batched_account_rejects_empty_input() {
        let (old, new) = (TESTNET, TESTNET);
        let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
        let err = alg.plan(&[], old, new, rate()).unwrap_err();
        assert!(matches!(err, MigrationError::NoUtxos));
    }

    #[test]
    fn both_account_algorithms_reject_network_mismatch() {
        let accounts = vec![account_set(0, &[500_000])];

        let err1 = AccountForAccountSweep::new(0)
            .plan(&accounts, TESTNET, MAINNET, rate())
            .unwrap_err();
        assert!(matches!(err1, MigrationError::NetworkMismatch { .. }));

        let err2 = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000))
            .plan(&accounts, TESTNET, MAINNET, rate())
            .unwrap_err();
        assert!(matches!(err2, MigrationError::NetworkMismatch { .. }));
    }
}
