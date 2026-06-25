//! Integration tests for sweep algorithms with real HSM-backed signers.
//!
//! Uses `asterism-pkcs11` + `asterism-dev-signer` + SoftHSM2 to derive
//! real federation keys, build descriptors, and exercise the sweep
//! planning logic with addresses derived from those descriptors.
//!
//! Tokens use the "core-test-{1..5}" label prefix — separate from
//! the test-app-pkcs11 tokens and the asterism-pkcs11 integration tokens.
//!
//! ```bash
//! cargo test -p asterism-core --features hsm-sweep-tests --test hsm_sweep -- --nocapture
//! ```

#![cfg(feature = "hsm-sweep-tests")]

use std::path::PathBuf;
use std::str::FromStr;

use asterism_core::descriptor::{KeyMode, to_multipath_string};
use asterism_core::federation::Federation;
use asterism_core::migration::{
    AccountForAccountBatchedSweep, AccountForAccountSweep, AccountUtxoSet, SweepAlgorithm,
    SweepOutput,
};
use asterism_core::network::NetworkType;
use asterism_core::signer::{Signer, SignerCapabilities, SignerHealth, SignerId, SignerType};
use asterism_core::{MigrationError, SignerError};
use asterism_dev_signer::{DevBackend, DevConfig, init_dev_token};
use asterism_pkcs11::{Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier};
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::{KeychainKind, LocalOutput};
use bitcoin::bip32::DerivationPath;
use bitcoin::bip32::{Fingerprint, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, Txid};
use serial_test::serial;

// =========================================================================
// Constants
// =========================================================================

const NUM_TOKENS: usize = 5;

const TOKEN_LABELS: [&str; NUM_TOKENS] = [
    "core-test-1",
    "core-test-2",
    "core-test-3",
    "core-test-4",
    "core-test-5",
];

const TOKEN_PINS: [&str; NUM_TOKENS] = [
    "core-test-pin-01",
    "core-test-pin-02",
    "core-test-pin-03",
    "core-test-pin-04",
    "core-test-pin-05",
];

const TOKEN_SO_PINS: [&str; NUM_TOKENS] = [
    "core-test-sopin-01",
    "core-test-sopin-02",
    "core-test-sopin-03",
    "core-test-sopin-04",
    "core-test-sopin-05",
];

const NETWORK: Network = Network::Regtest;
const NETWORK_TYPE: NetworkType = NetworkType::Bitcoin(Network::Regtest);

// =========================================================================
// Network-patched signer wrapper
// =========================================================================

/// The dev HSM shim always returns xpubs with `NetworkKind::Main`.
/// The descriptor builder checks xpub network vs federation network.
/// This wrapper patches the xpub's network kind to match regtest.
#[derive(Clone)]
struct PatchedSigner {
    inner: Pkcs11Signer,
    patched_xpub: Xpub,
}

impl PatchedSigner {
    fn new(inner: Pkcs11Signer) -> Self {
        let mut xpub = *inner.xpub();
        xpub.network = bitcoin::NetworkKind::from(NETWORK);
        Self {
            inner,
            patched_xpub: xpub,
        }
    }
}

impl Signer for PatchedSigner {
    fn id(&self) -> SignerId {
        self.inner.id()
    }
    fn label(&self) -> Option<&str> {
        self.inner.label()
    }
    fn xpub(&self) -> &Xpub {
        &self.patched_xpub
    }
    fn fingerprint(&self) -> Fingerprint {
        self.inner.fingerprint()
    }
    fn derivation_path(&self) -> &DerivationPath {
        self.inner.derivation_path()
    }
    fn signer_type(&self) -> SignerType {
        self.inner.signer_type()
    }
    fn supported_networks(&self) -> Vec<NetworkType> {
        self.inner.supported_networks()
    }
    fn capabilities(&self) -> SignerCapabilities {
        self.inner.capabilities()
    }
    fn health_check(&self) -> Result<SignerHealth, SignerError> {
        self.inner.health_check()
    }
}

// =========================================================================
// Harness
// =========================================================================

fn pkcs11_lib_path() -> PathBuf {
    let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&env_path);
    if let Ok(p) = Pkcs11Config::library_path_from_env()
        && p.exists()
    {
        return p;
    }
    let fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../libasterism_dev_hsm/target/release/libasterism_dev_hsm.so");
    assert!(
        fallback.exists(),
        "libasterism_dev_hsm.so not found; build it first or set PKCS11_LIB"
    );
    fallback
}

fn dev_hsm_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("dev-hsm-core-tests.toml")
}

/// Ensure all core-test tokens are initialized.
///
/// `init_dev_token` is idempotent — if the token already exists it
/// returns Ok immediately. The dev-HSM shim is process-global and
/// must only be initialized once per process; subsequent calls
/// return `CKR_CRYPTOKI_ALREADY_INITIALIZED` which is handled
/// internally. We therefore bootstrap once and never delete tokens
/// within the same test process.
fn ensure_tokens() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        unsafe { std::env::set_var("DEV_HSM_CONFIG", dev_hsm_config_path()) };
        let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
        let _ = dotenvy::from_path(&env_path);

        let lib = pkcs11_lib_path();
        let cfg = DevConfig {
            shim_library_path: lib,
        };
        for i in 0..NUM_TOKENS {
            init_dev_token(&cfg, TOKEN_LABELS[i], TOKEN_SO_PINS[i], TOKEN_PINS[i])
                .unwrap_or_else(|e| panic!("init_dev_token({}) failed: {e}", TOKEN_LABELS[i]));
        }
    });
}

/// Open a PKCS#11 session on token `idx` (0-based index into TOKEN_LABELS).
fn open_session(idx: usize, path: &DerivationPath) -> Pkcs11Session {
    let lib = pkcs11_lib_path();
    let label = TOKEN_LABELS[idx];
    let pin = TOKEN_PINS[idx];
    let cfg = Pkcs11Config::new(
        lib,
        SlotIdentifier::label(label),
        pin.to_string(),
        path.clone(),
        Box::new(DevBackend),
    );
    Pkcs11Session::open(&cfg, &SlotIdentifier::label(label), pin)
        .unwrap_or_else(|e| panic!("open session on {label}: {e}"))
}

/// Derive a signer on token `idx` with the given label and path.
fn derive_signer(idx: usize, key_label: &str, path: &DerivationPath) -> Pkcs11Signer {
    let session = open_session(idx, path);
    Pkcs11Signer::derive_from_seed(session, key_label, path, NETWORK, Box::new(DevBackend), &[])
        .unwrap_or_else(|e| panic!("derive_from_seed on {}: {e}", TOKEN_LABELS[idx]))
}

/// Build a Federation<PatchedSigner> from a subset of tokens.
fn build_federation(
    token_indices: &[usize],
    threshold: u32,
    key_label: &str,
    path: &DerivationPath,
) -> Federation<PatchedSigner> {
    let signers: Vec<PatchedSigner> = token_indices
        .iter()
        .map(|&idx| PatchedSigner::new(derive_signer(idx, key_label, path)))
        .collect();
    Federation::with_key_mode(threshold, signers, NETWORK_TYPE, KeyMode::Ranged)
        .expect("federation construction")
}

/// Derive a receive address from a federation's descriptor.
fn federation_address(fed: &Federation<PatchedSigner>) -> Address {
    let desc_str = to_multipath_string(
        fed.try_descriptor()
            .expect("Bitcoin federation has a descriptor"),
    );
    let desc: bdk_wallet::miniscript::Descriptor<bdk_wallet::miniscript::DescriptorPublicKey> =
        desc_str.parse().expect("valid descriptor");
    let mut wallet = bdk_wallet::Wallet::create_from_two_path_descriptor(desc)
        .network(NETWORK)
        .create_wallet_no_persist()
        .expect("create wallet from descriptor");
    wallet.reveal_next_address(KeychainKind::External).address
}

/// Create a synthetic LocalOutput (not on-chain, just for plan testing).
fn synthetic_utxo(amount_sat: u64, account_idx: u32, utxo_idx: u32) -> LocalOutput {
    let id = account_idx * 100 + utxo_idx;
    let byte = u8::try_from(id & 0xff).unwrap_or(0);
    LocalOutput {
        outpoint: OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([byte; 32])),
            vout: id,
        },
        txout: bitcoin::TxOut {
            value: Amount::from_sat(amount_sat),
            script_pubkey: bitcoin::ScriptBuf::new(),
        },
        keychain: KeychainKind::External,
        is_spent: false,
        derivation_index: id,
        chain_position: ChainPosition::Unconfirmed {
            first_seen: None,
            last_seen: None,
        },
    }
}

/// Build an AccountUtxoSet with synthetic UTXOs and a real HSM-derived
/// destination address from the new federation.
fn account_with_real_dest(
    account_idx: u32,
    amounts: &[u64],
    new_fed: &Federation<PatchedSigner>,
) -> AccountUtxoSet {
    AccountUtxoSet {
        account_idx,
        utxos: amounts
            .iter()
            .enumerate()
            .map(|(i, &amt)| synthetic_utxo(amt, account_idx, i as u32))
            .collect(),
        destination_address: federation_address(new_fed),
    }
}

fn rate() -> FeeRate {
    FeeRate::from_sat_per_vb_u32(2)
}

/// Build a vec of AccountUtxoSets from compact config. Each entry is
/// (account_idx, utxo_amounts). Destination addresses come from a real
/// federation built at the per-account derivation path.
fn build_accounts(
    configs: &[(u32, &[u64])],
    token_indices: &[usize],
    threshold: u32,
    key_label: &str,
) -> Vec<AccountUtxoSet> {
    configs
        .iter()
        .map(|(acct_idx, amounts)| {
            let path = DerivationPath::from_str(&format!("m/48'/1'/{acct_idx}'/2'")).unwrap();
            let fed = build_federation(token_indices, threshold, key_label, &path);
            account_with_real_dest(*acct_idx, amounts, &fed)
        })
        .collect()
}

// =========================================================================
// Tests
// =========================================================================

/// AccountForAccountSweep: all accounts in one transaction, fee account
/// pays fees, customer accounts receive exact balances.
#[test]
#[serial]
fn account_for_account_sweep_with_hsm_signers() {
    ensure_tokens();

    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();

    // Old federation: 3-of-3 from tokens 0, 1, 2.
    let _old_fed = build_federation(&[0, 1, 2], 3, "sweep-old", &path);

    // New federation: 3-of-3 from tokens 0, 2, 3 (swap out token 1, add 3).
    let new_fed = build_federation(&[0, 2, 3], 3, "sweep-new", &path);
    let new_desc_str = to_multipath_string(new_fed.try_descriptor().expect("descriptor"));

    // Build per-account destination addresses from the new federation at
    // different account indices. Each account needs its own derivation path.
    let mut accounts = Vec::new();
    for (acct_idx, amounts) in [
        (0u32, vec![1_000_000u64]),  // fee account
        (1, vec![200_000]),          // customer 1
        (2, vec![300_000, 150_000]), // customer 2 (2 UTXOs)
    ] {
        let acct_path = DerivationPath::from_str(&format!("m/48'/1'/{acct_idx}'/2'")).unwrap();
        let acct_new_fed = build_federation(&[0, 2, 3], 3, "sweep-new", &acct_path);
        accounts.push(account_with_real_dest(acct_idx, &amounts, &acct_new_fed));
    }

    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // Single transaction with all accounts.
    assert_eq!(plan.sweep_transactions.len(), 1);
    let tx = &plan.sweep_transactions[0];

    // 1 + 1 + 2 = 4 inputs.
    assert_eq!(tx.source_utxos.len(), 4);

    // 3 outputs (one per funded account).
    assert_eq!(tx.outputs.len(), 3);

    // Fee account (idx 0) absorbs the fee.
    let fee_account_output = tx.outputs[0].amount();
    assert_eq!(
        fee_account_output,
        Amount::from_sat(1_000_000) - plan.total_fees,
    );

    // Customer accounts receive exact input value.
    assert_eq!(tx.outputs[1].amount(), Amount::from_sat(200_000));
    assert_eq!(tx.outputs[2].amount(), Amount::from_sat(450_000));

    // Conservation: total output + fees = total input.
    let total_output: Amount = tx.outputs.iter().map(SweepOutput::amount).sum();
    assert_eq!(total_output + plan.total_fees, Amount::from_sat(1_650_000),);

    // Destinations are real HSM-derived addresses (not dummy).
    for out in &tx.outputs {
        if let SweepOutput::Customer { address, .. } = out {
            assert!(
                address.to_string().starts_with("bcrt1"),
                "expected regtest bech32 address, got {}",
                address,
            );
        }
    }

    // New federation descriptor is well-formed.
    let _ = miniscript::Descriptor::<miniscript::DescriptorPublicKey>::from_str(&new_desc_str)
        .expect("new federation descriptor round-trips");

    println!(
        "AccountForAccountSweep: plan OK — 1 tx, {} inputs, {} outputs, fee {}",
        tx.source_utxos.len(),
        tx.outputs.len(),
        plan.total_fees
    );
}

/// AccountForAccountBatchedSweep: large accounts get individual txs,
/// small accounts are bundled, fee account migrates last.
#[test]
#[serial]
fn account_for_account_batched_sweep_with_hsm_signers() {
    ensure_tokens();

    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();

    // Old federation: 3-of-3 from tokens 0, 1, 2.
    let _old_fed = build_federation(&[0, 1, 2], 3, "batch-old", &path);

    // New federation: 3-of-3 from tokens 1, 2, 4 (swap out token 0, add 4).
    let small_threshold = Amount::from_sat(100_000);

    // Build accounts with per-index federation addresses.
    // acct 0: fee account (large)
    // acct 1: large customer
    // acct 2: large customer (multiple UTXOs)
    // acct 3: small customer (below threshold)
    // acct 4: small customer (below threshold)
    let account_configs: Vec<(u32, Vec<u64>)> = vec![
        (0, vec![5_000_000]),        // fee account
        (1, vec![500_000]),          // large
        (2, vec![200_000, 150_000]), // large (2 UTXOs)
        (3, vec![50_000]),           // small
        (4, vec![30_000]),           // small
    ];

    let mut accounts = Vec::new();
    for (acct_idx, amounts) in &account_configs {
        let acct_path = DerivationPath::from_str(&format!("m/48'/1'/{acct_idx}'/2'")).unwrap();
        let acct_new_fed = build_federation(&[1, 2, 4], 3, "batch-new", &acct_path);
        accounts.push(account_with_real_dest(*acct_idx, amounts, &acct_new_fed));
    }

    let alg = AccountForAccountBatchedSweep::new(0, small_threshold);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // Expected structure:
    // - 2 large customer txs (accts 1, 2)
    // - 1 small bundle tx (accts 3, 4)
    // - 1 fee account tx (acct 0, last)
    // = 4 transactions total
    assert_eq!(
        plan.sweep_transactions.len(),
        4,
        "expected 4 txs (2 large + 1 small bundle + 1 fee), got {}",
        plan.sweep_transactions.len(),
    );

    // Last transaction is the fee account (single output).
    let last_tx = plan.sweep_transactions.last().unwrap();
    assert_eq!(
        last_tx.outputs.len(),
        1,
        "fee account tx should have exactly 1 output",
    );

    // The small bundle should have outputs for both small accounts + fee change.
    let small_bundle = &plan.sweep_transactions[2];
    assert_eq!(
        small_bundle.outputs.len(),
        3,
        "small bundle: 2 small account outputs + 1 fee change = 3 outputs",
    );

    // All destination addresses are real regtest bech32.
    for tx in &plan.sweep_transactions {
        for out in &tx.outputs {
            if let SweepOutput::Customer { address, .. } = out {
                assert!(
                    address.to_string().starts_with("bcrt1"),
                    "expected regtest bech32 address, got {}",
                    address,
                );
            }
        }
    }

    // Conservation: total input = total output + total fees.
    let total_input: u64 = account_configs
        .iter()
        .flat_map(|(_, amounts)| amounts)
        .sum();
    assert!(plan.total_fees > Amount::ZERO);
    assert!(plan.total_fees < Amount::from_sat(total_input));

    println!(
        "AccountForAccountBatchedSweep: plan OK — {} txs, {} UTXOs swept, total fees {}",
        plan.sweep_transactions.len(),
        plan.utxo_count,
        plan.total_fees,
    );
}

// =========================================================================
// Edge case 1: Fee account with multiple UTXOs
// =========================================================================

#[test]
#[serial]
fn sweep_multi_utxo_fee_account() {
    ensure_tokens();

    let accounts = build_accounts(
        &[
            (0, &[400_000, 300_000, 200_000]), // fee account — 3 UTXOs
            (1, &[100_000]),
            (2, &[250_000]),
        ],
        &[0, 1, 2],
        3,
        "ec1a",
    );

    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    assert_eq!(plan.sweep_transactions.len(), 1);
    let tx = &plan.sweep_transactions[0];

    // 3 + 1 + 1 = 5 inputs (all 3 fee UTXOs included).
    assert_eq!(tx.source_utxos.len(), 5);
    assert_eq!(plan.utxo_count, 5);

    // Fee account absorbs fee; its output = 900k - fees.
    assert_eq!(
        tx.outputs[0].amount(),
        Amount::from_sat(900_000) - plan.total_fees
    );
    // Customers untouched.
    assert_eq!(tx.outputs[1].amount(), Amount::from_sat(100_000));
    assert_eq!(tx.outputs[2].amount(), Amount::from_sat(250_000));

    let total_out: Amount = tx.outputs.iter().map(SweepOutput::amount).sum();
    assert_eq!(total_out + plan.total_fees, Amount::from_sat(1_250_000));
}

#[test]
#[serial]
fn batched_multi_utxo_fee_account() {
    ensure_tokens();

    // Fee account has 3 UTXOs. The batched algo uses utxo[0] for the chain
    // and spends the remaining UTXOs + synthetic change in the final tx.
    let accounts = build_accounts(
        &[
            (0, &[500_000, 300_000, 200_000]), // fee — 3 UTXOs, 1M total
            (1, &[400_000]),                   // large customer
        ],
        &[0, 2, 3],
        3,
        "ec1b",
    );

    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // 1 large customer tx + 1 fee-last tx = 2
    assert_eq!(plan.sweep_transactions.len(), 2);

    // Customer tx: customer's 1 UTXO + 1 fee-chain input = 2 inputs.
    assert_eq!(plan.sweep_transactions[0].source_utxos.len(), 2);
    // Customer gets exact value.
    assert_eq!(
        plan.sweep_transactions[0].outputs[0].amount(),
        Amount::from_sat(400_000)
    );

    // Fee-last tx: utxo[1] + utxo[2] + synthetic change = 3 inputs.
    let last = plan.sweep_transactions.last().unwrap();
    assert_eq!(last.source_utxos.len(), 3);
    assert_eq!(last.outputs.len(), 1);
    // Fee account output = total fee value - all accumulated fees.
    assert_eq!(
        last.outputs[0].amount(),
        Amount::from_sat(1_000_000) - plan.total_fees
    );
}

// =========================================================================
// Edge case 2: Account value exactly at small_account_threshold
// =========================================================================

#[test]
#[serial]
fn sweep_fee_barely_covers_fee() {
    ensure_tokens();

    // estimate_fee(2 inputs, 2 outputs, 2 sat/vB):
    //   vB = 10 + 2*105 + 2*32 = 284  →  fee = 568 sat
    // Give fee account 570 sat → output = 2 sat.
    let accounts = build_accounts(
        &[
            (0, &[570]),     // fee account — barely enough
            (1, &[100_000]), // customer
        ],
        &[0, 1, 2],
        3,
        "ec2a",
    );

    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    let tx = &plan.sweep_transactions[0];
    let fee_output = tx.outputs[0].amount();
    assert!(
        fee_output > Amount::ZERO,
        "fee account output should be positive"
    );
    assert!(
        fee_output < Amount::from_sat(10),
        "fee account output should be tiny"
    );
    assert_eq!(tx.outputs[1].amount(), Amount::from_sat(100_000));
}

#[test]
#[serial]
fn batched_threshold_boundary() {
    ensure_tokens();

    let threshold = Amount::from_sat(100_000);
    let accounts = build_accounts(
        &[
            (0, &[5_000_000]), // fee
            (1, &[100_000]),   // exactly at threshold → large (>=)
            (2, &[99_999]),    // 1 sat below threshold → small
            (3, &[200_000]),   // clearly large
        ],
        &[1, 2, 4],
        3,
        "ec2b",
    );

    let alg = AccountForAccountBatchedSweep::new(0, threshold);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // 2 large (accts 1, 3) + 1 small bundle (acct 2) + 1 fee = 4
    assert_eq!(
        plan.sweep_transactions.len(),
        4,
        "acct at threshold should be large, not bundled",
    );

    // The small bundle (tx index 2) should have exactly 1 customer output + 1 fee change.
    let bundle = &plan.sweep_transactions[2];
    assert_eq!(
        bundle.outputs.len(),
        2,
        "small bundle: 1 small account + 1 fee change",
    );
    // The small account gets its exact value.
    assert_eq!(bundle.outputs[0].amount(), Amount::from_sat(99_999));
}

// =========================================================================
// Edge case 3: Strict conservation
// =========================================================================

#[test]
#[serial]
fn sweep_strict_conservation() {
    ensure_tokens();

    let input_values: Vec<(u32, &[u64])> = vec![
        (0, &[800_000, 200_000]), // fee — 2 UTXOs, 1M total
        (1, &[150_000]),
        (2, &[300_000, 50_000]), // 2 UTXOs
        (3, &[75_000]),
    ];
    let accounts = build_accounts(&input_values, &[0, 2, 3], 3, "ec3a");

    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    let tx = &plan.sweep_transactions[0];

    // Per-account output checks.
    let expected_totals: Vec<u64> = input_values
        .iter()
        .map(|(_, amts)| amts.iter().sum::<u64>())
        .collect();

    for (i, output) in tx.outputs.iter().enumerate() {
        let output_val = output.amount();
        if input_values[i].0 == 0 {
            assert_eq!(
                output_val,
                Amount::from_sat(expected_totals[i]) - plan.total_fees,
                "fee account output mismatch",
            );
        } else {
            assert_eq!(
                output_val,
                Amount::from_sat(expected_totals[i]),
                "customer account {} output should equal its input",
                input_values[i].0,
            );
        }
    }

    // Global conservation.
    let total_input: u64 = expected_totals.iter().sum();
    let total_output: Amount = tx.outputs.iter().map(SweepOutput::amount).sum();
    assert_eq!(
        total_output + plan.total_fees,
        Amount::from_sat(total_input)
    );

    // utxo_count matches actual inputs.
    let actual_inputs: usize = plan
        .sweep_transactions
        .iter()
        .map(|t| t.source_utxos.len())
        .sum();
    assert_eq!(plan.utxo_count, actual_inputs);
}

#[test]
#[serial]
fn batched_strict_conservation() {
    ensure_tokens();

    let input_values: Vec<(u32, &[u64])> = vec![
        (0, &[3_000_000]),        // fee
        (1, &[500_000]),          // large
        (2, &[200_000, 100_000]), // large (2 UTXOs)
        (3, &[40_000]),           // small
        (4, &[60_000]),           // small
    ];
    let threshold = Amount::from_sat(100_000);
    let accounts = build_accounts(&input_values, &[0, 1, 2], 3, "ec3b");

    let alg = AccountForAccountBatchedSweep::new(0, threshold);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // 2 large + 1 small bundle + 1 fee = 4 txs
    assert_eq!(plan.sweep_transactions.len(), 4);

    // Large customer txs: each customer gets exact input value.
    assert_eq!(
        plan.sweep_transactions[0].outputs[0].amount(),
        Amount::from_sat(500_000),
        "large acct 1 should get exact value",
    );
    assert_eq!(
        plan.sweep_transactions[1].outputs[0].amount(),
        Amount::from_sat(300_000),
        "large acct 2 should get exact value",
    );

    // Small bundle: each small account gets exact value.
    let bundle = &plan.sweep_transactions[2];
    assert_eq!(bundle.outputs[0].amount(), Amount::from_sat(40_000));
    assert_eq!(bundle.outputs[1].amount(), Amount::from_sat(60_000));

    // Fee account final tx: output = fee_total - total_fees.
    let fee_total = Amount::from_sat(3_000_000);
    let last = plan.sweep_transactions.last().unwrap();
    assert_eq!(last.outputs[0].amount(), fee_total - plan.total_fees);

    // Global: sum of all customer outputs + fee output + total_fees = total input.
    let total_input: u64 = input_values.iter().flat_map(|(_, a)| a.iter()).sum();
    let customer_outputs = Amount::from_sat(500_000 + 300_000 + 40_000 + 60_000);
    let fee_output = last.outputs[0].amount();
    assert_eq!(
        customer_outputs + fee_output + plan.total_fees,
        Amount::from_sat(total_input)
    );

    // utxo_count matches sum of inputs across all txs.
    let actual_inputs: usize = plan
        .sweep_transactions
        .iter()
        .map(|t| t.source_utxos.len())
        .sum();
    assert_eq!(plan.utxo_count, actual_inputs);
}

// =========================================================================
// Edge case 4: Fee account only, no customer accounts
// =========================================================================

#[test]
#[serial]
fn sweep_fee_account_only() {
    ensure_tokens();

    let accounts = build_accounts(&[(0, &[1_000_000])], &[0, 1, 2], 3, "ec4a");

    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    assert_eq!(plan.sweep_transactions.len(), 1);
    let tx = &plan.sweep_transactions[0];
    assert_eq!(tx.source_utxos.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(
        tx.outputs[0].amount(),
        Amount::from_sat(1_000_000) - plan.total_fees,
    );
    assert!(plan.total_fees > Amount::ZERO);
}

#[test]
#[serial]
fn batched_fee_account_only() {
    ensure_tokens();

    // No customer accounts → 0 large txs, 0 bundles, just 1 fee-last tx.
    let accounts = build_accounts(&[(0, &[2_000_000])], &[1, 2, 4], 3, "ec4b");

    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    assert_eq!(plan.sweep_transactions.len(), 1);
    let tx = &plan.sweep_transactions[0];
    assert_eq!(tx.source_utxos.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(
        tx.outputs[0].amount(),
        Amount::from_sat(2_000_000) - plan.total_fees,
    );
    // With no intermediate txs, the source should be the original UTXO
    // outpoint — same as what we put in.
    assert_eq!(tx.source_utxos[0], accounts[0].utxos[0].outpoint);
}

// =========================================================================
// Edge case 5: Varied federation thresholds
// =========================================================================

#[test]
#[serial]
fn sweep_2_of_5_federation() {
    ensure_tokens();

    // 2-of-5 using all 5 tokens.
    let accounts = build_accounts(
        &[(0, &[500_000]), (1, &[200_000]), (2, &[300_000])],
        &[0, 1, 2, 3, 4],
        2,
        "ec5a",
    );

    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    assert_eq!(plan.sweep_transactions.len(), 1);
    let tx = &plan.sweep_transactions[0];
    assert_eq!(tx.outputs.len(), 3);

    // All addresses valid.
    for out in &tx.outputs {
        if let SweepOutput::Customer { address, .. } = out {
            assert!(address.to_string().starts_with("bcrt1"));
        }
    }

    // Conservation holds.
    let total_out: Amount = tx.outputs.iter().map(SweepOutput::amount).sum();
    assert_eq!(total_out + plan.total_fees, Amount::from_sat(1_000_000));

    // Verify the 2-of-5 descriptor round-trips.
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let fed = build_federation(&[0, 1, 2, 3, 4], 2, "ec5a", &path);
    let desc_str = to_multipath_string(fed.try_descriptor().unwrap());
    assert!(
        desc_str.contains("multi(2,"),
        "expected 2-of-N multisig descriptor"
    );
}

#[test]
#[serial]
fn batched_2_of_3_federation() {
    ensure_tokens();

    // 2-of-3 — different threshold than the 3-of-3 used elsewhere and
    // the 2-of-5 used in the sweep variant.
    let accounts = build_accounts(
        &[
            (0, &[1_000_000]),
            (1, &[300_000]), // large
            (2, &[50_000]),  // small
        ],
        &[0, 3, 4],
        2,
        "ec5b",
    );

    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // 1 large + 1 small bundle + 1 fee = 3
    assert_eq!(plan.sweep_transactions.len(), 3);

    for tx in &plan.sweep_transactions {
        for out in &tx.outputs {
            if let SweepOutput::Customer { address, .. } = out {
                assert!(address.to_string().starts_with("bcrt1"));
            }
        }
    }

    // Customer outputs exact.
    assert_eq!(
        plan.sweep_transactions[0].outputs[0].amount(),
        Amount::from_sat(300_000)
    );
    assert_eq!(
        plan.sweep_transactions[1].outputs[0].amount(),
        Amount::from_sat(50_000)
    );

    // Fee account conservation.
    let last = plan.sweep_transactions.last().unwrap();
    assert_eq!(
        last.outputs[0].amount(),
        Amount::from_sat(1_000_000) - plan.total_fees
    );

    // Verify the 2-of-3 descriptor round-trips.
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let fed = build_federation(&[0, 3, 4], 2, "ec5b", &path);
    let desc_str = to_multipath_string(fed.try_descriptor().unwrap());
    assert!(
        desc_str.contains("multi(2,"),
        "expected 2-of-3 multisig descriptor"
    );
}

// =========================================================================
// Error paths (items 1–5)
// =========================================================================

#[test]
#[serial]
fn sweep_empty_input() {
    ensure_tokens();
    let alg = AccountForAccountSweep::new(0);
    let err = alg
        .plan(&[], NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap_err();
    assert!(matches!(err, MigrationError::NoUtxos));
}

#[test]
#[serial]
fn batched_empty_input() {
    ensure_tokens();
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let err = alg
        .plan(&[], NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap_err();
    assert!(matches!(err, MigrationError::NoUtxos));
}

#[test]
#[serial]
fn sweep_missing_fee_account() {
    ensure_tokens();
    let accounts = build_accounts(&[(1, &[100_000]), (2, &[200_000])], &[0, 1], 2, "e2a");
    let alg = AccountForAccountSweep::new(99);
    let err = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap_err();
    assert!(matches!(err, MigrationError::InvalidConfig(_)));
}

#[test]
#[serial]
fn batched_missing_fee_account() {
    ensure_tokens();
    let accounts = build_accounts(&[(1, &[100_000]), (2, &[200_000])], &[0, 1], 2, "e2b");
    let alg = AccountForAccountBatchedSweep::new(99, Amount::from_sat(50_000));
    let err = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap_err();
    assert!(matches!(err, MigrationError::InvalidConfig(_)));
}

#[test]
#[serial]
fn sweep_insufficient_fee_balance() {
    ensure_tokens();
    let accounts = build_accounts(
        &[(0, &[1]), (1, &[100_000])], // fee account has 1 sat
        &[0, 1],
        2,
        "e3a",
    );
    let alg = AccountForAccountSweep::new(0);
    let err = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap_err();
    assert!(matches!(err, MigrationError::InsufficientFeeBalance { .. }));
}

#[test]
#[serial]
fn batched_insufficient_fee_balance() {
    ensure_tokens();
    let accounts = build_accounts(&[(0, &[1]), (1, &[100_000])], &[0, 1], 2, "e3b");
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(50_000));
    let err = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap_err();
    assert!(matches!(err, MigrationError::InsufficientFeeBalance { .. }));
}

#[test]
#[serial]
fn sweep_network_mismatch() {
    ensure_tokens();
    let accounts = build_accounts(&[(0, &[500_000])], &[0, 1], 2, "e4a");
    let alg = AccountForAccountSweep::new(0);
    let other = NetworkType::Bitcoin(Network::Bitcoin);
    let err = alg
        .plan(&accounts, NETWORK_TYPE, other, rate())
        .unwrap_err();
    assert!(matches!(err, MigrationError::NetworkMismatch { .. }));
}

#[test]
#[serial]
fn batched_network_mismatch() {
    ensure_tokens();
    let accounts = build_accounts(&[(0, &[500_000])], &[0, 1], 2, "e4b");
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let other = NetworkType::Bitcoin(Network::Bitcoin);
    let err = alg
        .plan(&accounts, NETWORK_TYPE, other, rate())
        .unwrap_err();
    assert!(matches!(err, MigrationError::NetworkMismatch { .. }));
}

#[test]
#[serial]
fn sweep_all_empty_utxos() {
    ensure_tokens();
    // Accounts exist but all have zero UTXOs.
    let accounts = build_accounts(&[(0, &[]), (1, &[]), (2, &[])], &[0, 1], 2, "e5a");
    let alg = AccountForAccountSweep::new(0);
    let err = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap_err();
    assert!(matches!(err, MigrationError::NoUtxos));
}

#[test]
#[serial]
fn batched_all_empty_utxos() {
    ensure_tokens();
    let accounts = build_accounts(&[(0, &[]), (1, &[]), (2, &[])], &[0, 1], 2, "e5b");
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let err = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap_err();
    assert!(matches!(err, MigrationError::NoUtxos));
}

// =========================================================================
// Partition boundary cases (items 7–10, batched only)
// =========================================================================

#[test]
#[serial]
fn batched_all_small() {
    ensure_tokens();
    let threshold = Amount::from_sat(1_000_000);
    let accounts = build_accounts(
        &[
            (0, &[5_000_000]),
            (1, &[50_000]),
            (2, &[30_000]),
            (3, &[20_000]),
        ],
        &[0, 1, 2],
        3,
        "p7",
    );
    let alg = AccountForAccountBatchedSweep::new(0, threshold);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    // 0 large + 1 bundle + 1 fee = 2
    assert_eq!(plan.sweep_transactions.len(), 2);
    // Bundle has 3 small outputs + 1 fee change = 4.
    assert_eq!(plan.sweep_transactions[0].outputs.len(), 4);
}

#[test]
#[serial]
fn batched_all_large() {
    ensure_tokens();
    let threshold = Amount::from_sat(10_000);
    let accounts = build_accounts(
        &[(0, &[1_000_000]), (1, &[200_000]), (2, &[150_000])],
        &[0, 1, 2],
        3,
        "p8",
    );
    let alg = AccountForAccountBatchedSweep::new(0, threshold);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    // 2 large + 0 bundle + 1 fee = 3
    assert_eq!(plan.sweep_transactions.len(), 3);
}

#[test]
#[serial]
fn batched_threshold_zero() {
    ensure_tokens();
    // threshold = 0 → everything >= 0 is "large".
    let accounts = build_accounts(
        &[(0, &[1_000_000]), (1, &[50_000]), (2, &[30_000])],
        &[0, 1, 2],
        3,
        "p9",
    );
    let alg = AccountForAccountBatchedSweep::new(0, Amount::ZERO);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    // 2 individual large txs + 0 bundle + 1 fee = 3
    assert_eq!(plan.sweep_transactions.len(), 3);
}

#[test]
#[serial]
fn batched_threshold_max() {
    ensure_tokens();
    // threshold = MAX → everything is "small" (no account can reach u64::MAX sats).
    let accounts = build_accounts(
        &[(0, &[5_000_000]), (1, &[500_000]), (2, &[300_000])],
        &[0, 1, 2],
        3,
        "p10",
    );
    let alg = AccountForAccountBatchedSweep::new(0, Amount::MAX);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    // 0 large + 1 bundle + 1 fee = 2
    assert_eq!(plan.sweep_transactions.len(), 2);
}

// =========================================================================
// Account configurations (items 12–14)
// =========================================================================

#[test]
#[serial]
fn sweep_minimal_two_accounts() {
    ensure_tokens();
    let accounts = build_accounts(&[(0, &[500_000]), (1, &[100_000])], &[0, 1, 2], 3, "c12a");
    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    assert_eq!(plan.sweep_transactions.len(), 1);
    assert_eq!(plan.sweep_transactions[0].outputs.len(), 2);
    assert_eq!(
        plan.sweep_transactions[0].outputs[1].amount(),
        Amount::from_sat(100_000)
    );
}

#[test]
#[serial]
fn batched_minimal_two_accounts() {
    ensure_tokens();
    let accounts = build_accounts(&[(0, &[500_000]), (1, &[100_000])], &[0, 1, 2], 3, "c12b");
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(50_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    // 1 large customer + 1 fee = 2
    assert_eq!(plan.sweep_transactions.len(), 2);
    assert_eq!(
        plan.sweep_transactions[0].outputs[0].amount(),
        Amount::from_sat(100_000)
    );
}

#[test]
#[serial]
fn sweep_many_accounts() {
    ensure_tokens();
    let mut configs: Vec<(u32, &[u64])> = Vec::new();
    // Account 0 = fee (large balance), accounts 1..20 = customers.
    // Use static slices so lifetimes work.
    static FEE: [u64; 1] = [10_000_000];
    static CUST: [u64; 1] = [50_000];
    configs.push((0, &FEE));
    for i in 1..=20 {
        configs.push((i, &CUST));
    }
    let accounts = build_accounts(&configs, &[0, 1, 2], 3, "c13a");

    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    assert_eq!(plan.sweep_transactions.len(), 1);
    assert_eq!(plan.sweep_transactions[0].outputs.len(), 21);
    assert_eq!(plan.utxo_count, 21);

    // Every customer gets exact 50k.
    for dest in &plan.sweep_transactions[0].outputs[1..] {
        assert_eq!(dest.amount(), Amount::from_sat(50_000));
    }
}

#[test]
#[serial]
fn batched_many_accounts() {
    ensure_tokens();
    static FEE: [u64; 1] = [10_000_000];
    static LARGE: [u64; 1] = [200_000];
    static SMALL: [u64; 1] = [30_000];
    let mut configs: Vec<(u32, &[u64])> = vec![(0, &FEE)];
    for i in 1..=5 {
        configs.push((i, &LARGE));
    }
    for i in 6..=15 {
        configs.push((i, &SMALL));
    }
    let accounts = build_accounts(&configs, &[0, 1, 2], 3, "c13b");

    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // 5 large + 1 small bundle + 1 fee = 7
    assert_eq!(plan.sweep_transactions.len(), 7);

    // Small bundle has 10 customer outputs + 1 fee change = 11.
    assert_eq!(plan.sweep_transactions[5].outputs.len(), 11);
}

#[test]
#[serial]
fn sweep_duplicate_account_idx() {
    ensure_tokens();
    // Two accounts share idx 1. A4A treats them as separate destinations
    // but both get fee-deducted if idx matches fee_account_idx. With idx 1
    // as non-fee, both should get exact values.
    let accounts = build_accounts(
        &[(0, &[500_000]), (1, &[100_000]), (1, &[200_000])],
        &[0, 1, 2],
        3,
        "c14a",
    );
    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    assert_eq!(plan.sweep_transactions[0].outputs.len(), 3);
    assert_eq!(
        plan.sweep_transactions[0].outputs[1].amount(),
        Amount::from_sat(100_000)
    );
    assert_eq!(
        plan.sweep_transactions[0].outputs[2].amount(),
        Amount::from_sat(200_000)
    );
}

#[test]
#[serial]
fn batched_duplicate_account_idx() {
    ensure_tokens();
    // Duplicate non-fee idx. Both are treated as separate accounts.
    let accounts = build_accounts(
        &[(0, &[5_000_000]), (1, &[300_000]), (1, &[200_000])],
        &[0, 1, 2],
        3,
        "c14b",
    );
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // Both duplicates are large → 2 individual txs + 1 fee = 3.
    assert_eq!(plan.sweep_transactions.len(), 3);
    assert_eq!(
        plan.sweep_transactions[0].outputs[0].amount(),
        Amount::from_sat(300_000)
    );
    assert_eq!(
        plan.sweep_transactions[1].outputs[0].amount(),
        Amount::from_sat(200_000)
    );
}

// =========================================================================
// Fee account edge cases (items 16-batched, 17)
// =========================================================================

#[test]
#[serial]
fn batched_fee_barely_sufficient() {
    ensure_tokens();
    // Give the fee account just enough to cover all fees.
    // 1 large customer (1 input + 1 fee input, 2 outputs) → fee ≈ (10+210+64)*2 = 568
    // fee migration (1 input, 1 output) → fee ≈ (10+105+32)*2 = 294
    // total ≈ 862. Give fee account 900 sat.
    let accounts = build_accounts(&[(0, &[900]), (1, &[100_000])], &[0, 1, 2], 3, "f16");
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(50_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    let last = plan.sweep_transactions.last().unwrap();
    let fee_output = last.outputs[0].amount();
    assert!(
        fee_output > Amount::ZERO,
        "fee account should have a tiny positive output"
    );
    assert!(
        fee_output < Amount::from_sat(100),
        "fee account output should be very small"
    );
}

#[test]
#[serial]
fn batched_fee_account_below_threshold() {
    ensure_tokens();
    // Fee account's value (800k) is below the small_account_threshold (1M).
    // But the fee account is excluded from the large/small partition, so this
    // should not affect its handling — it always migrates last.
    let accounts = build_accounts(
        &[(0, &[800_000]), (1, &[500_000]), (2, &[50_000])],
        &[0, 1, 2],
        3,
        "f17",
    );
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(1_000_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // acct 1 is small (500k < 1M), acct 2 is small → 0 large + 1 bundle + 1 fee = 2.
    assert_eq!(plan.sweep_transactions.len(), 2);

    // Fee account still migrates last with correct value.
    let last = plan.sweep_transactions.last().unwrap();
    assert_eq!(
        last.outputs[0].amount(),
        Amount::from_sat(800_000) - plan.total_fees
    );
}

// =========================================================================
// Value edge cases (items 18–21)
// =========================================================================

#[test]
#[serial]
fn sweep_dust_utxos() {
    ensure_tokens();
    let accounts = build_accounts(
        &[(0, &[500_000]), (1, &[546]), (2, &[300])], // dust-level customers
        &[0, 1, 2],
        3,
        "v18a",
    );
    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // Customers get their exact dust amounts (fee comes from acct 0).
    assert_eq!(
        plan.sweep_transactions[0].outputs[1].amount(),
        Amount::from_sat(546)
    );
    assert_eq!(
        plan.sweep_transactions[0].outputs[2].amount(),
        Amount::from_sat(300)
    );
}

#[test]
#[serial]
fn batched_dust_utxos() {
    ensure_tokens();
    let accounts = build_accounts(
        &[(0, &[5_000_000]), (1, &[546]), (2, &[300])],
        &[0, 1, 2],
        3,
        "v18b",
    );
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // Both dust accounts are small → bundled.
    // 0 large + 1 bundle + 1 fee = 2.
    assert_eq!(plan.sweep_transactions.len(), 2);
    let bundle = &plan.sweep_transactions[0];
    assert_eq!(bundle.outputs[0].amount(), Amount::from_sat(546));
    assert_eq!(bundle.outputs[1].amount(), Amount::from_sat(300));
}

#[test]
#[serial]
fn sweep_large_values() {
    ensure_tokens();
    // ~10 BTC per account. Tests no overflow in summation.
    let accounts = build_accounts(
        &[
            (0, &[1_000_000_000]),
            (1, &[1_000_000_000]),
            (2, &[1_000_000_000]),
        ],
        &[0, 1, 2],
        3,
        "v19a",
    );
    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    let total_out: Amount = plan.sweep_transactions[0]
        .outputs
        .iter()
        .map(SweepOutput::amount)
        .sum();
    assert_eq!(total_out + plan.total_fees, Amount::from_sat(3_000_000_000));
}

#[test]
#[serial]
fn batched_large_values() {
    ensure_tokens();
    let accounts = build_accounts(
        &[
            (0, &[5_000_000_000]),
            (1, &[1_000_000_000]),
            (2, &[2_000_000_000]),
        ],
        &[0, 1, 2],
        3,
        "v19b",
    );
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    assert_eq!(
        plan.sweep_transactions[0].outputs[0].amount(),
        Amount::from_sat(1_000_000_000)
    );
    assert_eq!(
        plan.sweep_transactions[1].outputs[0].amount(),
        Amount::from_sat(2_000_000_000)
    );
    let last = plan.sweep_transactions.last().unwrap();
    assert_eq!(
        last.outputs[0].amount(),
        Amount::from_sat(5_000_000_000) - plan.total_fees
    );
}

#[test]
#[serial]
fn sweep_zero_value_utxo() {
    ensure_tokens();
    // Customer has a zero-value UTXO. It still gets included (non-empty vec)
    // and receives 0 sats as output.
    let accounts = build_accounts(&[(0, &[500_000]), (1, &[0])], &[0, 1, 2], 3, "v20a");
    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    assert_eq!(plan.sweep_transactions[0].outputs[1].amount(), Amount::ZERO);
    assert_eq!(plan.utxo_count, 2);
}

#[test]
#[serial]
fn batched_zero_value_utxo() {
    ensure_tokens();
    let accounts = build_accounts(&[(0, &[5_000_000]), (1, &[0])], &[0, 1, 2], 3, "v20b");
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // 0-value account is small → bundled. 0 large + 1 bundle + 1 fee = 2.
    assert_eq!(plan.sweep_transactions.len(), 2);
    assert_eq!(plan.sweep_transactions[0].outputs[0].amount(), Amount::ZERO);
}

#[test]
#[serial]
fn sweep_one_sat_customer() {
    ensure_tokens();
    let accounts = build_accounts(&[(0, &[500_000]), (1, &[1])], &[0, 1, 2], 3, "v21a");
    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    assert_eq!(
        plan.sweep_transactions[0].outputs[1].amount(),
        Amount::from_sat(1)
    );
}

#[test]
#[serial]
fn batched_one_sat_customer() {
    ensure_tokens();
    let accounts = build_accounts(&[(0, &[5_000_000]), (1, &[1])], &[0, 1, 2], 3, "v21b");
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    // Small bundle: 1-sat customer output.
    assert_eq!(
        plan.sweep_transactions[0].outputs[0].amount(),
        Amount::from_sat(1)
    );
}

// =========================================================================
// Fee rate variations (items 22–24)
// =========================================================================

#[test]
#[serial]
fn sweep_zero_fee_rate() {
    ensure_tokens();
    let accounts = build_accounts(&[(0, &[500_000]), (1, &[100_000])], &[0, 1, 2], 3, "r22a");
    let alg = AccountForAccountSweep::new(0);
    let zero = FeeRate::from_sat_per_vb_u32(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, zero)
        .unwrap();

    assert_eq!(plan.total_fees, Amount::ZERO);
    // Fee account gets its full value (no deduction).
    assert_eq!(
        plan.sweep_transactions[0].outputs[0].amount(),
        Amount::from_sat(500_000)
    );
    assert_eq!(
        plan.sweep_transactions[0].outputs[1].amount(),
        Amount::from_sat(100_000)
    );
}

#[test]
#[serial]
fn batched_zero_fee_rate() {
    ensure_tokens();
    let accounts = build_accounts(
        &[(0, &[500_000]), (1, &[200_000]), (2, &[30_000])],
        &[0, 1, 2],
        3,
        "r22b",
    );
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let zero = FeeRate::from_sat_per_vb_u32(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, zero)
        .unwrap();

    assert_eq!(plan.total_fees, Amount::ZERO);
    let last = plan.sweep_transactions.last().unwrap();
    assert_eq!(last.outputs[0].amount(), Amount::from_sat(500_000));
}

#[test]
#[serial]
fn sweep_high_fee_rate() {
    ensure_tokens();
    // At 1000 sat/vB with 2 inputs + 2 outputs:
    // fee = (10 + 210 + 64) * 1000 = 284,000. Fee account has 300k → output = 16k.
    let accounts = build_accounts(&[(0, &[300_000]), (1, &[100_000])], &[0, 1, 2], 3, "r23a");
    let alg = AccountForAccountSweep::new(0);
    let high = FeeRate::from_sat_per_vb_u32(1000);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, high)
        .unwrap();

    assert!(plan.total_fees > Amount::from_sat(200_000));
    assert_eq!(
        plan.sweep_transactions[0].outputs[1].amount(),
        Amount::from_sat(100_000)
    );
    let fee_out = plan.sweep_transactions[0].outputs[0].amount();
    assert!(
        fee_out < Amount::from_sat(100_000),
        "fee account output should be small at high rate"
    );
}

#[test]
#[serial]
fn batched_high_fee_rate() {
    ensure_tokens();
    let accounts = build_accounts(&[(0, &[2_000_000]), (1, &[100_000])], &[0, 1, 2], 3, "r23b");
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(50_000));
    let high = FeeRate::from_sat_per_vb_u32(1000);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, high)
        .unwrap();

    assert!(plan.total_fees > Amount::from_sat(400_000));
    assert_eq!(
        plan.sweep_transactions[0].outputs[0].amount(),
        Amount::from_sat(100_000)
    );
}

#[test]
#[serial]
fn sweep_fee_rate_barely_under() {
    ensure_tokens();
    // Find a fee rate where fee ≈ fee_account_value - 1 sat.
    // 1 input, 1 output: vB = 10 + 105 + 32 = 147. fee = 147 * rate.
    // Fee account = 500_000. We want 147 * rate ≈ 499_999.
    // rate ≈ 3401.35 → use 3401.
    // fee = 147 * 3401 = 499,947. Output = 500,000 - 499,947 = 53.
    // But with 2 inputs (fee + customer) and 2 outputs: vB = 284. fee = 284 * 3401 = 965,884.
    // Too high. Let me use 1 account (fee only).
    let accounts = build_accounts(&[(0, &[500_000])], &[0, 1, 2], 3, "r24a");
    let alg = AccountForAccountSweep::new(0);
    // vB for 1 input, 1 output = 147. fee = 147 * rate.
    // Want fee just under 500,000: rate = 3401 → fee = 499,947.
    let tight = FeeRate::from_sat_per_vb_u32(3401);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, tight)
        .unwrap();

    let fee_out = plan.sweep_transactions[0].outputs[0].amount();
    assert!(fee_out > Amount::ZERO);
    assert!(fee_out < Amount::from_sat(200));
}

#[test]
#[serial]
fn batched_fee_rate_barely_under() {
    ensure_tokens();
    let accounts = build_accounts(&[(0, &[1_000_000]), (1, &[100_000])], &[0, 1, 2], 3, "r24b");
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(50_000));
    // vB for customer tx (2 in, 2 out) = 284. For fee tx (1 in, 1 out) = 147.
    // total fee ≈ (284 + 147) * rate = 431 * rate. Want ≈ 999,000.
    // rate ≈ 2318. fee = 431 * 2318 = 999,058.
    let tight = FeeRate::from_sat_per_vb_u32(2318);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, tight)
        .unwrap();

    let last = plan.sweep_transactions.last().unwrap();
    let fee_out = last.outputs[0].amount();
    assert!(
        fee_out > Amount::ZERO,
        "fee account output should still be positive"
    );
    assert!(fee_out < Amount::from_sat(5_000));
}

// =========================================================================
// Ordering and determinism (items 25–27)
// =========================================================================

#[test]
#[serial]
fn sweep_input_order_independent() {
    ensure_tokens();
    // Build accounts in forward order, then reverse. Plans should produce
    // the same total fees and conservation.
    let forward = build_accounts(
        &[(0, &[500_000]), (1, &[100_000]), (2, &[200_000])],
        &[0, 1, 2],
        3,
        "o25a",
    );
    let reverse = {
        let mut v = build_accounts(
            &[(2, &[200_000]), (1, &[100_000]), (0, &[500_000])],
            &[0, 1, 2],
            3,
            "o25a",
        );
        v.reverse();
        v
    };

    let alg = AccountForAccountSweep::new(0);
    let plan_f = alg
        .plan(&forward, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    let plan_r = alg
        .plan(&reverse, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    assert_eq!(plan_f.total_fees, plan_r.total_fees);
    assert_eq!(plan_f.utxo_count, plan_r.utxo_count);

    let sum_f: Amount = plan_f.sweep_transactions[0]
        .outputs
        .iter()
        .map(SweepOutput::amount)
        .sum();
    let sum_r: Amount = plan_r.sweep_transactions[0]
        .outputs
        .iter()
        .map(SweepOutput::amount)
        .sum();
    assert_eq!(sum_f, sum_r);
}

#[test]
#[serial]
fn batched_input_order_independent() {
    ensure_tokens();
    let forward = build_accounts(
        &[(0, &[5_000_000]), (1, &[300_000]), (2, &[50_000])],
        &[0, 1, 2],
        3,
        "o25b",
    );
    let mut reverse = build_accounts(
        &[(2, &[50_000]), (1, &[300_000]), (0, &[5_000_000])],
        &[0, 1, 2],
        3,
        "o25b",
    );
    reverse.reverse();

    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan_f = alg
        .plan(&forward, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    let plan_r = alg
        .plan(&reverse, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    assert_eq!(plan_f.total_fees, plan_r.total_fees);
    assert_eq!(
        plan_f.sweep_transactions.len(),
        plan_r.sweep_transactions.len()
    );
    assert_eq!(plan_f.utxo_count, plan_r.utxo_count);
}

#[test]
#[serial]
fn sweep_same_destination_address() {
    ensure_tokens();
    // All accounts share the same destination address (same federation, same path).
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let fed = build_federation(&[0, 1, 2], 3, "o27a", &path);
    let addr = federation_address(&fed);

    let accounts = vec![
        AccountUtxoSet {
            account_idx: 0,
            utxos: vec![synthetic_utxo(500_000, 0, 0)],
            destination_address: addr.clone(),
        },
        AccountUtxoSet {
            account_idx: 1,
            utxos: vec![synthetic_utxo(100_000, 1, 0)],
            destination_address: addr.clone(),
        },
        AccountUtxoSet {
            account_idx: 2,
            utxos: vec![synthetic_utxo(200_000, 2, 0)],
            destination_address: addr,
        },
    ];

    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // Decision (b): the planner assigns each Customer output its account's
    // new-fed address (all `addr` here), but the fee account's output is an
    // address-less FeeChange — the executor resolves its destination per hop.
    let tx = &plan.sweep_transactions[0];
    let customer_addrs: Vec<_> = tx
        .outputs
        .iter()
        .filter_map(|o| match o {
            SweepOutput::Customer { address, .. } => Some(address.to_string()),
            SweepOutput::FeeChange { .. } => None,
        })
        .collect();
    assert_eq!(customer_addrs.len(), 2, "two customer outputs (accts 1, 2)");
    assert_eq!(customer_addrs[0], customer_addrs[1]);
    assert!(
        matches!(tx.outputs[0], SweepOutput::FeeChange { .. }),
        "fee account (idx 0) output is an address-less FeeChange",
    );
}

#[test]
#[serial]
fn batched_same_destination_address() {
    ensure_tokens();
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let fed = build_federation(&[0, 1, 2], 3, "o27b", &path);
    let addr = federation_address(&fed);

    let accounts = vec![
        AccountUtxoSet {
            account_idx: 0,
            utxos: vec![synthetic_utxo(5_000_000, 0, 0)],
            destination_address: addr.clone(),
        },
        AccountUtxoSet {
            account_idx: 1,
            utxos: vec![synthetic_utxo(300_000, 1, 0)],
            destination_address: addr.clone(),
        },
        AccountUtxoSet {
            account_idx: 2,
            utxos: vec![synthetic_utxo(50_000, 2, 0)],
            destination_address: addr,
        },
    ];

    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // Decision (b): the planner no longer bakes a fee-change address. The
    // large customer tx carries the customer's new-fed address (Customer) plus
    // an address-less FeeChange that the executor routes to the fee account's
    // OLD federation (is_fee_final == false); only the final fee-account tx
    // crosses to the new federation.
    let large_tx = &plan.sweep_transactions[0];
    assert!(matches!(large_tx.outputs[0], SweepOutput::Customer { .. }));
    assert!(matches!(large_tx.outputs[1], SweepOutput::FeeChange { .. }));
    assert!(!large_tx.is_fee_final, "intermediate tx routes fee change to old-fed");

    let final_tx = plan.sweep_transactions.last().unwrap();
    assert!(matches!(final_tx.outputs[0], SweepOutput::FeeChange { .. }));
    assert!(final_tx.is_fee_final, "final fee-account tx crosses to new-fed");
}

// =========================================================================
// Federation configuration edge cases (items 29–31)
// =========================================================================

#[test]
#[serial]
fn sweep_complete_signer_replacement() {
    ensure_tokens();
    // Old: tokens [0,1], New: tokens [2,3] — zero overlap.
    let _old = build_federation(
        &[0, 1],
        2,
        "f29a-old",
        &DerivationPath::from_str("m/48'/1'/0'/2'").unwrap(),
    );
    let accounts = build_accounts(&[(0, &[500_000]), (1, &[100_000])], &[2, 3], 2, "f29a-new");
    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    assert_eq!(plan.sweep_transactions.len(), 1);
    assert_eq!(
        plan.sweep_transactions[0].outputs[1].amount(),
        Amount::from_sat(100_000)
    );
}

#[test]
#[serial]
fn batched_complete_signer_replacement() {
    ensure_tokens();
    let _old = build_federation(
        &[0, 1],
        2,
        "f29b-old",
        &DerivationPath::from_str("m/48'/1'/0'/2'").unwrap(),
    );
    let accounts = build_accounts(
        &[(0, &[5_000_000]), (1, &[300_000]), (2, &[50_000])],
        &[2, 3],
        2,
        "f29b-new",
    );
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    assert_eq!(plan.sweep_transactions.len(), 3);
}

#[test]
#[serial]
fn sweep_no_rotation() {
    ensure_tokens();
    // Old and new federations use the same signers and threshold.
    let tokens = &[0, 1, 2];
    let _old = build_federation(
        tokens,
        3,
        "f30a",
        &DerivationPath::from_str("m/48'/1'/0'/2'").unwrap(),
    );
    let accounts = build_accounts(&[(0, &[500_000]), (1, &[100_000])], tokens, 3, "f30a");
    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    assert_eq!(plan.sweep_transactions.len(), 1);
    // Still works even though addresses might be identical to old federation's.
    for out in &plan.sweep_transactions[0].outputs {
        if let SweepOutput::Customer { address, .. } = out {
            assert!(address.to_string().starts_with("bcrt1"));
        }
    }
}

#[test]
#[serial]
fn batched_no_rotation() {
    ensure_tokens();
    let tokens = &[0, 1, 2];
    let _old = build_federation(
        tokens,
        3,
        "f30b",
        &DerivationPath::from_str("m/48'/1'/0'/2'").unwrap(),
    );
    let accounts = build_accounts(&[(0, &[5_000_000]), (1, &[300_000])], tokens, 3, "f30b");
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    assert_eq!(plan.sweep_transactions.len(), 2);
}

#[test]
#[serial]
fn sweep_threshold_change_only() {
    ensure_tokens();
    // Same signers, threshold changes from 3-of-3 to 2-of-3.
    let tokens = &[0, 1, 2];
    let old = build_federation(
        tokens,
        3,
        "f31a",
        &DerivationPath::from_str("m/48'/1'/0'/2'").unwrap(),
    );
    let accounts = build_accounts(&[(0, &[500_000]), (1, &[100_000])], tokens, 2, "f31a");
    // New federation descriptor should differ from old.
    let new_fed = build_federation(
        tokens,
        2,
        "f31a",
        &DerivationPath::from_str("m/48'/1'/0'/2'").unwrap(),
    );
    let old_desc = to_multipath_string(old.try_descriptor().unwrap());
    let new_desc = to_multipath_string(new_fed.try_descriptor().unwrap());
    assert_ne!(
        old_desc, new_desc,
        "threshold change should produce different descriptor"
    );

    let alg = AccountForAccountSweep::new(0);
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    assert_eq!(plan.sweep_transactions.len(), 1);
}

#[test]
#[serial]
fn batched_threshold_change_only() {
    ensure_tokens();
    let tokens = &[0, 1, 2];
    let old = build_federation(
        tokens,
        3,
        "f31b",
        &DerivationPath::from_str("m/48'/1'/0'/2'").unwrap(),
    );
    let accounts = build_accounts(
        &[(0, &[5_000_000]), (1, &[300_000]), (2, &[50_000])],
        tokens,
        2,
        "f31b",
    );
    let new_fed = build_federation(
        tokens,
        2,
        "f31b",
        &DerivationPath::from_str("m/48'/1'/0'/2'").unwrap(),
    );
    let old_desc = to_multipath_string(old.try_descriptor().unwrap());
    let new_desc = to_multipath_string(new_fed.try_descriptor().unwrap());
    assert_ne!(old_desc, new_desc);

    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    assert_eq!(plan.sweep_transactions.len(), 3);
}

// =========================================================================
// Batched transaction ordering (item 35)
// =========================================================================

#[test]
#[serial]
fn batched_tx_ordering() {
    ensure_tokens();
    let accounts = build_accounts(
        &[
            (0, &[5_000_000]), // fee
            (1, &[500_000]),   // large
            (2, &[300_000]),   // large
            (3, &[50_000]),    // small
            (4, &[30_000]),    // small
        ],
        &[0, 1, 2],
        3,
        "o35",
    );
    let alg = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000));
    let plan = alg
        .plan(&accounts, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    assert_eq!(plan.sweep_transactions.len(), 4);

    // Txs 0,1: large accounts (2 outputs each: customer + fee change).
    assert_eq!(plan.sweep_transactions[0].outputs.len(), 2);
    assert_eq!(plan.sweep_transactions[1].outputs.len(), 2);

    // Tx 2: small bundle (2 small outputs + 1 fee change = 3).
    assert_eq!(plan.sweep_transactions[2].outputs.len(), 3);

    // Tx 3 (last): fee account migration (1 output).
    assert_eq!(plan.sweep_transactions[3].outputs.len(), 1);

    // Large customer outputs match their input values.
    assert_eq!(
        plan.sweep_transactions[0].outputs[0].amount(),
        Amount::from_sat(500_000)
    );
    assert_eq!(
        plan.sweep_transactions[1].outputs[0].amount(),
        Amount::from_sat(300_000)
    );

    // Small customer outputs match their input values.
    assert_eq!(
        plan.sweep_transactions[2].outputs[0].amount(),
        Amount::from_sat(50_000)
    );
    assert_eq!(
        plan.sweep_transactions[2].outputs[1].amount(),
        Amount::from_sat(30_000)
    );

    // Fee chain: each intermediate tx's last destination is fee change.
    // Fee change decreases across the chain.
    let change_0 = plan.sweep_transactions[0].outputs[1].amount();
    let change_1 = plan.sweep_transactions[1].outputs[1].amount();
    let change_2 = plan.sweep_transactions[2].outputs[2].amount();
    assert!(
        change_0 > change_1,
        "fee change should decrease after each tx"
    );
    assert!(
        change_1 > change_2,
        "fee change should decrease after each tx"
    );
}

// =========================================================================
// Cross-algorithm consistency (item 37)
// =========================================================================

#[test]
#[serial]
fn cross_algorithm_conservation() {
    ensure_tokens();
    // Same input through both algorithms. Total (customer outputs + fee output + fees)
    // must equal total input for both.
    let accounts_a = build_accounts(
        &[(0, &[1_000_000]), (1, &[200_000]), (2, &[300_000])],
        &[0, 1, 2],
        3,
        "x37",
    );
    let accounts_b = build_accounts(
        &[(0, &[1_000_000]), (1, &[200_000]), (2, &[300_000])],
        &[0, 1, 2],
        3,
        "x37",
    );
    let total_input = Amount::from_sat(1_500_000);

    let plan_a = AccountForAccountSweep::new(0)
        .plan(&accounts_a, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();
    let plan_b = AccountForAccountBatchedSweep::new(0, Amount::from_sat(100_000))
        .plan(&accounts_b, NETWORK_TYPE, NETWORK_TYPE, rate())
        .unwrap();

    // A4A: single tx, all outputs.
    let out_a: Amount = plan_a.sweep_transactions[0]
        .outputs
        .iter()
        .map(SweepOutput::amount)
        .sum();
    assert_eq!(out_a + plan_a.total_fees, total_input);

    // Batched: customer outputs are exact; fee output = fee_input - total_fees.
    let customer_out_b = Amount::from_sat(200_000 + 300_000);
    let fee_out_b = plan_b.sweep_transactions.last().unwrap().outputs[0].amount();
    assert_eq!(customer_out_b + fee_out_b + plan_b.total_fees, total_input);

    // Both algorithms sweep the same number of UTXOs.
    assert_eq!(plan_a.utxo_count, 3);
    // Batched counts fee-chain inputs too, so utxo_count is higher.
    assert!(plan_b.utxo_count >= plan_a.utxo_count);
}
