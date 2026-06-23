//! Sweep-destination correctness for the built-in migration algorithms.
//!
//! These tests verify that a [`MigrationPlan`] produced by `BatchedSweep`
//! or `ConsolidationSweep` populates destination addresses that are
//! actually derived from the new federation's descriptor.
//! No signing is performed; only the structural correctness of the plan.
//!
//! Run with: `cargo test -p asterism-core --features test-utils --test migration_destinations`.
#![cfg(feature = "test-utils")]

use asterism_core::{
    BatchedSweep, ConsolidationSweep, Federation, MigrationPlan, Signer, SweepAlgorithm,
    UnsignedPsbt, test_utils::MockSigner,
};
use bdk_wallet::{KeychainKind, LocalOutput, chain::ChainPosition};
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, TxOut, Txid};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn dyn_signers(seeds: &[u64]) -> Vec<Box<dyn Signer>> {
    seeds
        .iter()
        .map(|&s| Box::new(MockSigner::with_seed(s, Network::Testnet)) as Box<dyn Signer>)
        .collect()
}

fn fed(seeds: &[u64]) -> Federation {
    Federation::new(2, dyn_signers(seeds), Network::Testnet.into()).unwrap()
}

/// Derive the new-federation receive address at `idx`.
fn fed_address(f: &Federation, idx: u32) -> Address {
    f.descriptor()
        .at_derivation_index(idx)
        .unwrap()
        .address(Network::Testnet)
        .unwrap()
}

fn utxo(amount_sat: u64, idx: u32, script_pubkey: ScriptBuf) -> LocalOutput {
    let byte = u8::try_from(idx & 0xff).expect("byte fits");
    LocalOutput {
        outpoint: OutPoint {
            txid: Txid::from_byte_array([byte; 32]),
            vout: idx,
        },
        txout: TxOut {
            value: Amount::from_sat(amount_sat),
            script_pubkey,
        },
        keychain: KeychainKind::External,
        is_spent: false,
        derivation_index: idx,
        chain_position: ChainPosition::Unconfirmed {
            first_seen: None,
            last_seen: None,
        },
    }
}

fn assert_destination_belongs_to(plan: &MigrationPlan<UnsignedPsbt>, new_fed: &Federation) {
    let new_addr = fed_address(new_fed, 0);
    let new_script = new_addr.script_pubkey();
    for (i, sweep) in plan.sweep_transactions.iter().enumerate() {
        for (dest, _amount) in &sweep.destinations {
            assert_eq!(
                dest.script_pubkey(),
                new_script,
                "sweep tx {i} destination must match new federation script_pubkey",
            );
            assert_eq!(
                dest, &new_addr,
                "destination address must equal new federation address",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Consolidation sweep
// ---------------------------------------------------------------------------

#[test]
fn consolidation_destination_comes_from_new_federation() {
    let old = fed(&[1, 2, 3]);
    let new = fed(&[4, 5, 6]);
    let new_addr = fed_address(&new, 0);
    let old_script = fed_address(&old, 0).script_pubkey();

    let utxos = vec![
        utxo(100_000, 0, old_script.clone()),
        utxo(50_000, 1, old_script.clone()),
        utxo(25_000, 2, old_script),
    ];

    let plan = ConsolidationSweep::new(new_addr)
        .plan(
            &utxos,
            old.network(),
            new.network(),
            FeeRate::from_sat_per_vb_u32(2),
        )
        .unwrap();
    assert_eq!(plan.sweep_transactions.len(), 1);
    assert_eq!(plan.utxo_count, 3);
    assert_destination_belongs_to(&plan, &new);
}

// ---------------------------------------------------------------------------
// Batched sweep
// ---------------------------------------------------------------------------

#[test]
fn batched_destination_is_new_federation_for_every_batch() {
    let old = fed(&[1, 2, 3]);
    let new = fed(&[4, 5, 6]);
    let new_addr = fed_address(&new, 0);
    let old_script = fed_address(&old, 0).script_pubkey();

    let utxos: Vec<_> = (0..7)
        .map(|i| utxo(50_000, i, old_script.clone()))
        .collect();

    let plan = BatchedSweep::new(3, new_addr)
        .plan(
            &utxos,
            old.network(),
            new.network(),
            FeeRate::from_sat_per_vb_u32(1),
        )
        .unwrap();
    assert_eq!(
        plan.sweep_transactions.len(),
        3,
        "7 utxos / 3 = 3 batches (3 + 3 + 1)"
    );
    assert_destination_belongs_to(&plan, &new);
}

// ---------------------------------------------------------------------------
// Ranged-mode: distinct destination addresses per receive index
// ---------------------------------------------------------------------------

#[test]
fn ranged_mode_distinct_destinations_validate_per_index() {
    use asterism_core::descriptor::{DescriptorBuilder, KeyMode};

    let signers: Vec<MockSigner> = [1u64, 2, 3]
        .iter()
        .map(|&s| MockSigner::with_seed(s, Network::Testnet))
        .collect();
    let mut b = DescriptorBuilder::new(2, asterism_core::NetworkType::Bitcoin(Network::Testnet))
        .key_mode(KeyMode::Ranged);
    for s in &signers {
        b.add_signer(s).unwrap();
    }
    let desc = b.build().unwrap();
    let a0 = desc
        .at_derivation_index(0)
        .unwrap()
        .address(Network::Testnet)
        .unwrap();
    let a1 = desc
        .at_derivation_index(1)
        .unwrap()
        .address(Network::Testnet)
        .unwrap();
    assert_ne!(
        a0, a1,
        "Ranged-mode addresses at indexes 0 and 1 must differ"
    );
    assert_eq!(
        a0.script_pubkey().len(),
        a1.script_pubkey().len(),
        "P2WSH script lengths match"
    );
}
