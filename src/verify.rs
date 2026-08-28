//! Hostile-host verification primitives.
//!
//! These helpers exist for the *hostile-wrapper* threat model: a host
//! (browser + server) that a signer must not blindly trust. They give a
//! consuming app one audited implementation of the two checks that stand
//! between a lying host and an unwanted signature, instead of app-local glue
//! re-implemented per host:
//!
//! 1. [`ensure_descriptors_match`] — does a descriptor handed to us (e.g. read
//!    back from a hardware device, or received in a `/sign-data` response)
//!    describe the **same multisig policy** as the federation descriptor we
//!    already trust? This is the reusable core of Anchor #1: compare by the
//!    normalized `(threshold, cosigner-key-set)`, order- and checksum-
//!    independent, so a swapped-cosigner descriptor is rejected before it is
//!    ever registered or signed against.
//! 2. [`verify_psbt_outputs`] — do a PSBT's outputs equal the outputs the
//!    human approved (recipients + amounts), with everything else being our
//!    own change? This catches a tampered `sign-data` PSBT — a swapped
//!    recipient script, an edited amount, a dropped payout, or an injected
//!    exfiltration output — before any device is asked to sign it.
//!
//! Both operate on plain values ([`Descriptor`], [`Psbt`]) and hold no wallet,
//! network, or persistence state — the caller owns those. Change detection in
//! [`verify_psbt_outputs`] is delegated to a caller-supplied predicate
//! (typically `bdk_wallet::Wallet::is_mine`) so this crate stays wallet-
//! agnostic while the app plugs in its own notion of "owned change".

use std::collections::BTreeSet;
use std::str::FromStr;

use bitcoin::{Amount, Psbt, ScriptBuf};
use miniscript::descriptor::WshInner;
use miniscript::{Descriptor, DescriptorPublicKey, Terminal};

use crate::error::{DescriptorError, PsbtError};

// ---------------------------------------------------------------------------
// Descriptor policy comparison (Anchor #1 core)
// ---------------------------------------------------------------------------

/// Which on-chain script shape a [`MultisigPolicy`] came from.
///
/// Part of the policy identity: a `wsh(sortedmulti)` and a `tr(NUMS, multi_a)`
/// over the *same* keys and threshold are **different** policies (they derive
/// different addresses), so a shape difference is a mismatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyShape {
    /// `wsh(sortedmulti(m, …))` — Segwit v0.
    Wsh,
    /// `tr(internal, multi_a(m, …))` — Taproot (BIP-341/342).
    Tr,
}

/// The normalized, order-independent identity of a supported multisig policy —
/// either `wsh(sortedmulti(m, …))` (Segwit v0) or `tr(internal, multi_a(m, …))`
/// (Taproot).
///
/// Two descriptors are the *same policy* — they lock coins to the same set of
/// spending conditions and therefore derive the same addresses — iff they agree
/// on [`shape`](MultisigPolicy::shape), [`threshold`](MultisigPolicy::threshold),
/// the [`keys`](MultisigPolicy::keys) set, **and** (Taproot only) the
/// [`internal_key`](MultisigPolicy::internal_key). Ordering of the cosigner keys
/// and the descriptor's trailing `#checksum` are irrelevant to that identity, so
/// this type ignores both: the keys live in a [`BTreeSet`] and the checksum
/// never enters the comparison.
///
/// Each key is captured as its canonical [`DescriptorPublicKey`] string
/// (`[fingerprint/derivation]key`), so the comparison binds not just the raw
/// key material but its **origin fingerprint and derivation path** — a hostile
/// host that reuses the real xpubs under a different origin/path (which would
/// change the derived addresses) is still rejected.
///
/// For Taproot, the internal key is captured too: a hostile host that keeps the
/// right `multi_a` script leaf but swaps in a *live* internal key it controls
/// (an unguarded key-path spend) produces a different `internal_key` and is
/// rejected. Callers building the trusted descriptor should additionally pin the
/// internal key to the expected unspendable NUMS point (see
/// [`ensure_taproot_internal_key_is`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigPolicy {
    /// The script shape this policy locks to.
    pub shape: PolicyShape,
    /// The `m` of an m-of-n policy.
    pub threshold: usize,
    /// The cosigner keys, each as its canonical `DescriptorPublicKey` string,
    /// held order-independently.
    pub keys: BTreeSet<String>,
    /// The Taproot internal key as its canonical `DescriptorPublicKey` string,
    /// or `None` for `wsh(sortedmulti)`.
    pub internal_key: Option<String>,
}

/// Extract the normalized [`MultisigPolicy`] from a `wsh(sortedmulti(m, …))` or
/// `tr(internal, multi_a(m, …))` descriptor.
///
/// These are the two shapes [`crate::DescriptorBuilder`] emits. Any other shape
/// means the descriptor did not come from where we think it did and must not be
/// trusted.
///
/// # Errors
///
/// Returns [`DescriptorError::UnsupportedShape`] if `desc` is neither
/// `wsh(sortedmulti(...))` nor `tr(internal, multi_a(...))` — including a
/// Taproot descriptor whose tree is empty (key-path only), has more than one
/// leaf, or whose single leaf is not a bare `multi_a`.
pub fn multisig_policy(
    desc: &Descriptor<DescriptorPublicKey>,
) -> Result<MultisigPolicy, DescriptorError> {
    match desc {
        Descriptor::Wsh(wsh) => match wsh.as_inner() {
            WshInner::SortedMulti(smv) => Ok(MultisigPolicy {
                shape: PolicyShape::Wsh,
                threshold: smv.k(),
                keys: smv.pks().iter().map(ToString::to_string).collect(),
                internal_key: None,
            }),
            WshInner::Ms(_) => Err(DescriptorError::UnsupportedShape(
                "wsh() body is raw miniscript, expected sortedmulti(...)".into(),
            )),
        },
        Descriptor::Tr(tr) => taproot_multi_a_policy(tr),
        other => Err(DescriptorError::UnsupportedShape(format!(
            "expected wsh(sortedmulti(...)) or tr(NUMS, multi_a(...)), got a {} descriptor",
            descriptor_kind(other)
        ))),
    }
}

/// Normalize a `tr(internal, multi_a(m, …))` descriptor into a
/// [`MultisigPolicy`].
///
/// Requires the taptree to be exactly one leaf holding a bare `multi_a`. Any
/// other tree shape (empty/key-path-only, multiple leaves, or a leaf that is not
/// a bare `multi_a`) is [`DescriptorError::UnsupportedShape`] — we normalize only
/// the shape this crate builds, never a best-effort guess at an unknown tree.
fn taproot_multi_a_policy(
    tr: &miniscript::descriptor::Tr<DescriptorPublicKey>,
) -> Result<MultisigPolicy, DescriptorError> {
    // Exactly one script leaf, at any depth (our builder emits a single leaf).
    let mut leaves = tr.iter_scripts();
    let (_, ms) = leaves.next().ok_or_else(|| {
        DescriptorError::UnsupportedShape(
            "tr() has no script leaf (key-path only), expected a single multi_a(...) leaf".into(),
        )
    })?;
    if leaves.next().is_some() {
        return Err(DescriptorError::UnsupportedShape(
            "tr() has more than one script leaf, expected a single multi_a(...) leaf".into(),
        ));
    }
    match ms.as_inner() {
        Terminal::MultiA(thresh) => Ok(MultisigPolicy {
            shape: PolicyShape::Tr,
            threshold: thresh.k(),
            keys: thresh.data().iter().map(ToString::to_string).collect(),
            internal_key: Some(tr.internal_key().to_string()),
        }),
        _ => Err(DescriptorError::UnsupportedShape(
            "tr() script leaf is not a bare multi_a(...)".into(),
        )),
    }
}

/// Assert that a Taproot descriptor's internal key equals `expected` — the
/// federation's known unspendable NUMS point.
///
/// Anchor #1's descriptor-equality already rejects a swapped internal key
/// *relative to the trusted descriptor*. This is the stronger, absolute check:
/// even when comparing two attacker-influenced descriptors, it refuses any
/// Taproot policy whose internal key is not the expected NUMS, closing an
/// unguarded key-path spend. `expected` is the canonical `DescriptorPublicKey`
/// string of the NUMS internal key (raw-`H` or NUMS-xpub, per the builder).
///
/// # Errors
///
/// - [`DescriptorError::UnsupportedShape`] if `desc` is not a supported Taproot
///   `multi_a` policy (a `wsh` descriptor has no internal key to pin).
/// - [`DescriptorError::PolicyMismatch`] if the internal key differs from
///   `expected`.
pub fn ensure_taproot_internal_key_is(
    desc: &Descriptor<DescriptorPublicKey>,
    expected: &str,
) -> Result<(), DescriptorError> {
    let policy = multisig_policy(desc)?;
    let Some(internal) = policy.internal_key.as_deref() else {
        return Err(DescriptorError::UnsupportedShape(
            "descriptor is not Taproot; no internal key to pin".into(),
        ));
    };
    if internal == expected {
        Ok(())
    } else {
        Err(DescriptorError::PolicyMismatch(format!(
            "taproot internal key {internal} != expected NUMS {expected}"
        )))
    }
}

/// Whether two descriptors describe the same multisig policy.
///
/// A convenience over [`multisig_policy`] + `==`; use
/// [`ensure_descriptors_match`] when you want a descriptive error on mismatch
/// rather than a bare `false`.
///
/// # Errors
///
/// Propagates [`DescriptorError::UnsupportedShape`] from [`multisig_policy`] if
/// either descriptor is not `wsh(sortedmulti(...))`.
pub fn descriptors_match(
    expected: &Descriptor<DescriptorPublicKey>,
    candidate: &Descriptor<DescriptorPublicKey>,
) -> Result<bool, DescriptorError> {
    Ok(multisig_policy(expected)? == multisig_policy(candidate)?)
}

/// Assert that `candidate` describes exactly the same multisig policy as the
/// trusted `expected` descriptor, returning a descriptive error otherwise.
///
/// This is the reusable heart of Anchor #1: before registering or signing
/// against a descriptor that reached us through the host, confirm it is the
/// federation we already trust. On mismatch the error names the exact
/// divergence — a threshold change and/or the specific keys that are extra
/// (present in `candidate` but not `expected`) or missing (vice-versa) — so the
/// caller can surface *why* it refused.
///
/// # Errors
///
/// - [`DescriptorError::UnsupportedShape`] if either descriptor is not
///   `wsh(sortedmulti(...))`.
/// - [`DescriptorError::PolicyMismatch`] if the threshold or the cosigner-key
///   set differs.
pub fn ensure_descriptors_match(
    expected: &Descriptor<DescriptorPublicKey>,
    candidate: &Descriptor<DescriptorPublicKey>,
) -> Result<(), DescriptorError> {
    let want = multisig_policy(expected)?;
    let got = multisig_policy(candidate)?;
    if want == got {
        return Ok(());
    }

    let mut reasons = Vec::new();
    if want.shape != got.shape {
        reasons.push(format!("shape {:?} != {:?}", want.shape, got.shape));
    }
    if want.threshold != got.threshold {
        reasons.push(format!("threshold {} != {}", want.threshold, got.threshold));
    }
    if want.internal_key != got.internal_key {
        reasons.push(format!(
            "taproot internal key {:?} != {:?}",
            want.internal_key, got.internal_key
        ));
    }
    let extra: Vec<&String> = got.keys.difference(&want.keys).collect();
    let missing: Vec<&String> = want.keys.difference(&got.keys).collect();
    if !extra.is_empty() {
        reasons.push(format!("unexpected key(s): {extra:?}"));
    }
    if !missing.is_empty() {
        reasons.push(format!("missing expected key(s): {missing:?}"));
    }
    Err(DescriptorError::PolicyMismatch(reasons.join("; ")))
}

/// Parse a descriptor string and assert it matches the trusted `expected`
/// descriptor.
///
/// The convenience form of [`ensure_descriptors_match`] for the common case
/// where the untrusted descriptor arrives as a string (a device read-back, a
/// server response). The candidate string may carry a `#checksum` or not; the
/// policy comparison ignores it either way.
///
/// # Errors
///
/// - [`DescriptorError::Parse`] if `candidate` is not a valid descriptor.
/// - Everything [`ensure_descriptors_match`] can return.
pub fn ensure_descriptor_string_matches(
    expected: &Descriptor<DescriptorPublicKey>,
    candidate: &str,
) -> Result<(), DescriptorError> {
    let parsed = Descriptor::<DescriptorPublicKey>::from_str(candidate)
        .map_err(|e| DescriptorError::Parse(e.to_string()))?;
    ensure_descriptors_match(expected, &parsed)
}

/// Human-readable descriptor-kind label, for error messages only.
fn descriptor_kind(desc: &Descriptor<DescriptorPublicKey>) -> &'static str {
    match desc {
        Descriptor::Bare(_) => "bare",
        Descriptor::Pkh(_) => "pkh",
        Descriptor::Wpkh(_) => "wpkh",
        Descriptor::Sh(_) => "sh",
        Descriptor::Wsh(_) => "wsh",
        Descriptor::Tr(_) => "tr",
    }
}

// ---------------------------------------------------------------------------
// PSBT output verification (Rec 3)
// ---------------------------------------------------------------------------

/// A single output the proposal approved: pay `amount` to `script_pubkey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedOutput {
    /// The recipient script the human approved.
    pub script_pubkey: ScriptBuf,
    /// The exact amount the human approved for that recipient.
    pub amount: Amount,
}

impl ExpectedOutput {
    /// Construct an expected output.
    pub fn new(script_pubkey: ScriptBuf, amount: Amount) -> Self {
        Self {
            script_pubkey,
            amount,
        }
    }
}

/// Assert that a PSBT spends to exactly the approved outputs, with every other
/// output being our own change.
///
/// For a hostile host the danger is a `/sign-data` PSBT that looks routine but
/// pays the attacker: a swapped recipient script, an edited amount, a silently
/// dropped payout, or an extra output disguised as "internal change". This
/// check closes all four:
///
/// - every `approved` output must appear in the PSBT with the **exact** script
///   and amount (each approved output is matched at most once, so duplicate
///   approved payouts are honored individually);
/// - every remaining PSBT output must satisfy `is_owned_change` — i.e. it pays
///   back to a script the wallet recognizes as its own. Any other output is
///   treated as an injected exfiltration output and rejected.
///
/// `is_owned_change` is supplied by the caller (typically
/// `|spk| wallet.is_mine(spk)`) so this crate needs no wallet state. Pass
/// `|_| false` to require the PSBT outputs to equal `approved` with no change
/// at all.
///
/// The check operates on `psbt.unsigned_tx`; partial signatures, if any, are
/// irrelevant to the output set and are ignored.
///
/// # Errors
///
/// Returns [`PsbtError::OutputMismatch`] describing the first divergence: an
/// unexpected/exfil output (with a dedicated note when a recipient script is
/// present but its amount was tampered) or, failing that, an approved output
/// that never appeared.
pub fn verify_psbt_outputs<F>(
    psbt: &Psbt,
    approved: &[ExpectedOutput],
    is_owned_change: F,
) -> Result<(), PsbtError>
where
    F: Fn(&bitcoin::Script) -> bool,
{
    // Track which approved outputs have been satisfied so duplicates are
    // matched one-for-one rather than all at once.
    let mut matched = vec![false; approved.len()];

    for txout in &psbt.unsigned_tx.output {
        // Try to claim an as-yet-unmatched approved output with an exact
        // (script, amount) match.
        let exact = approved.iter().enumerate().position(|(i, exp)| {
            !matched[i] && exp.script_pubkey == txout.script_pubkey && exp.amount == txout.value
        });
        if let Some(i) = exact {
            matched[i] = true;
            continue;
        }

        // Not an approved output. Legitimate iff it is our own change.
        if is_owned_change(txout.script_pubkey.as_script()) {
            continue;
        }

        // Unexpected output. If its script matches a still-unmatched approved
        // recipient, the amount was tampered — say so precisely.
        if let Some(exp) = approved
            .iter()
            .enumerate()
            .find(|(i, exp)| !matched[*i] && exp.script_pubkey == txout.script_pubkey)
            .map(|(_, exp)| exp)
        {
            return Err(PsbtError::OutputMismatch(format!(
                "amount to {} was changed: approved {}, PSBT has {}",
                txout.script_pubkey, exp.amount, txout.value
            )));
        }

        return Err(PsbtError::OutputMismatch(format!(
            "unexpected output not in proposal and not owned change: {} to {}",
            txout.value, txout.script_pubkey
        )));
    }

    if let Some((_, exp)) = approved.iter().enumerate().find(|(i, _)| !matched[*i]) {
        return Err(PsbtError::OutputMismatch(format!(
            "approved output missing from PSBT: {} to {}",
            exp.amount, exp.script_pubkey
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{DescriptorBuilder, KeyMode};
    use crate::network::NetworkType;
    use crate::test_utils::MockSigner;
    use bitcoin::{Network, OutPoint, Sequence, Transaction, TxIn, TxOut, transaction::Version};

    fn desc_from(seeds: &[u64], threshold: u32) -> Descriptor<DescriptorPublicKey> {
        let signers: Vec<MockSigner> = seeds
            .iter()
            .map(|s| MockSigner::with_seed(*s, Network::Testnet))
            .collect();
        let mut b = DescriptorBuilder::new(threshold, NetworkType::Bitcoin(Network::Testnet));
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        b.build().unwrap()
    }

    // ---- descriptor policy comparison ----

    #[test]
    fn identical_signer_sets_match_regardless_of_order() {
        let a = desc_from(&[1, 2, 3], 2);
        let b = desc_from(&[3, 1, 2], 2);
        assert!(descriptors_match(&a, &b).unwrap());
        ensure_descriptors_match(&a, &b).unwrap();
    }

    #[test]
    fn swapped_cosigner_is_rejected() {
        let expected = desc_from(&[1, 2, 3], 2);
        // Cosigner 3 replaced by an attacker key (seed 99).
        let hostile = desc_from(&[1, 2, 99], 2);
        assert!(!descriptors_match(&expected, &hostile).unwrap());
        let err = ensure_descriptors_match(&expected, &hostile).unwrap_err();
        assert!(matches!(err, DescriptorError::PolicyMismatch(_)));
        let msg = err.to_string();
        assert!(msg.contains("unexpected key"), "got {msg}");
        assert!(msg.contains("missing expected key"), "got {msg}");
    }

    #[test]
    fn threshold_change_is_rejected() {
        let expected = desc_from(&[1, 2, 3], 2);
        let hostile = desc_from(&[1, 2, 3], 1);
        let err = ensure_descriptors_match(&expected, &hostile).unwrap_err();
        assert!(err.to_string().contains("threshold 2 != 1"), "got {err}");
    }

    #[test]
    fn checksum_and_string_roundtrip_still_matches() {
        let expected = desc_from(&[5, 6, 7], 2);
        // Re-parse from the canonical string (with #checksum) — must match.
        let s = expected.to_string();
        assert!(s.contains('#'), "expected a checksum suffix in {s}");
        ensure_descriptor_string_matches(&expected, &s).unwrap();
    }

    #[test]
    fn string_match_rejects_swapped_cosigner() {
        let expected = desc_from(&[1, 2, 3], 2);
        let hostile = desc_from(&[1, 2, 99], 2).to_string();
        let err = ensure_descriptor_string_matches(&expected, &hostile).unwrap_err();
        assert!(matches!(err, DescriptorError::PolicyMismatch(_)));
    }

    #[test]
    fn ranged_mode_policy_extractable_and_matches() {
        let signers: Vec<MockSigner> = [1u64, 2, 3]
            .iter()
            .map(|s| MockSigner::with_seed(*s, Network::Testnet))
            .collect();
        let mk = || {
            let mut b = DescriptorBuilder::new(2, NetworkType::Bitcoin(Network::Testnet))
                .key_mode(KeyMode::Ranged);
            for s in &signers {
                b.add_signer(s).unwrap();
            }
            b.build().unwrap()
        };
        let a = mk();
        let b = mk();
        let pol = multisig_policy(&a).unwrap();
        assert_eq!(pol.threshold, 2);
        assert_eq!(pol.keys.len(), 3);
        ensure_descriptors_match(&a, &b).unwrap();
    }

    #[test]
    fn non_sortedmulti_descriptor_is_unsupported() {
        // A wpkh() descriptor is a valid descriptor but not our shape.
        let desc = Descriptor::<DescriptorPublicKey>::from_str(
            "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
        )
        .unwrap();
        let err = multisig_policy(&desc).unwrap_err();
        assert!(matches!(err, DescriptorError::UnsupportedShape(_)));
        assert!(err.to_string().contains("wpkh"), "got {err}");
    }

    // ---- Taproot (tr(NUMS, multi_a)) policy coverage — F4 / Phase 0+2 ----

    fn tr_desc_from(
        seeds: &[u64],
        threshold: u32,
        nums: crate::descriptor::TaprootInternalKey,
    ) -> Descriptor<DescriptorPublicKey> {
        use crate::descriptor::ScriptType;
        let signers: Vec<MockSigner> = seeds
            .iter()
            .map(|s| MockSigner::with_seed(*s, Network::Testnet))
            .collect();
        let mut b = DescriptorBuilder::new(threshold, NetworkType::Bitcoin(Network::Testnet))
            .key_mode(KeyMode::Ranged)
            .script_type(ScriptType::Tr)
            .taproot_internal_key(nums);
        for s in &signers {
            b.add_signer(s).unwrap();
        }
        b.build().unwrap()
    }

    #[test]
    fn taproot_policy_extractable_and_shape_is_tr() {
        use crate::descriptor::TaprootInternalKey;
        let d = tr_desc_from(&[1, 2, 3], 2, TaprootInternalKey::NumsXpub([3; 32]));
        assert!(d.to_string().starts_with("tr("), "got {d}");
        let pol = multisig_policy(&d).unwrap();
        assert_eq!(pol.shape, PolicyShape::Tr);
        assert_eq!(pol.threshold, 2);
        assert_eq!(pol.keys.len(), 3);
        assert!(
            pol.internal_key.is_some(),
            "taproot policy carries internal key"
        );
    }

    #[test]
    fn taproot_identical_rosters_match_regardless_of_order() {
        use crate::descriptor::TaprootInternalKey;
        let a = tr_desc_from(&[1, 2, 3], 2, TaprootInternalKey::NumsXpub([3; 32]));
        let b = tr_desc_from(&[3, 1, 2], 2, TaprootInternalKey::NumsXpub([3; 32]));
        ensure_descriptors_match(&a, &b).unwrap();
    }

    #[test]
    fn taproot_swapped_cosigner_is_rejected() {
        use crate::descriptor::TaprootInternalKey;
        let expected = tr_desc_from(&[1, 2, 3], 2, TaprootInternalKey::NumsXpub([3; 32]));
        let hostile = tr_desc_from(&[1, 2, 99], 2, TaprootInternalKey::NumsXpub([3; 32]));
        let err = ensure_descriptors_match(&expected, &hostile).unwrap_err();
        assert!(matches!(err, DescriptorError::PolicyMismatch(_)));
        let msg = err.to_string();
        assert!(msg.contains("unexpected key"), "got {msg}");
        assert!(msg.contains("missing expected key"), "got {msg}");
    }

    #[test]
    fn taproot_swapped_internal_key_is_rejected() {
        use crate::descriptor::TaprootInternalKey;
        // Same cosigners + threshold, different NUMS internal key → a live
        // key-path an attacker could control. Must be a PolicyMismatch.
        let expected = tr_desc_from(&[1, 2, 3], 2, TaprootInternalKey::NumsXpub([3; 32]));
        let hostile = tr_desc_from(&[1, 2, 3], 2, TaprootInternalKey::NumsXpub([9; 32]));
        assert!(!descriptors_match(&expected, &hostile).unwrap());
        let err = ensure_descriptors_match(&expected, &hostile).unwrap_err();
        assert!(matches!(err, DescriptorError::PolicyMismatch(_)));
        assert!(
            err.to_string().contains("internal key"),
            "reason names the internal key: {err}"
        );
    }

    #[test]
    fn mixed_shape_wsh_vs_tr_is_rejected_not_panic() {
        use crate::descriptor::TaprootInternalKey;
        let wsh = desc_from(&[1, 2, 3], 2);
        let tr = tr_desc_from(&[1, 2, 3], 2, TaprootInternalKey::NumsXpub([3; 32]));
        let err = ensure_descriptors_match(&wsh, &tr).unwrap_err();
        assert!(matches!(err, DescriptorError::PolicyMismatch(_)));
        assert!(err.to_string().contains("shape"), "got {err}");
    }

    #[test]
    fn taproot_internal_key_pin_accepts_expected_rejects_other() {
        use crate::descriptor::TaprootInternalKey;
        let d = tr_desc_from(&[1, 2, 3], 2, TaprootInternalKey::NumsXpub([3; 32]));
        let expected = multisig_policy(&d).unwrap().internal_key.unwrap();
        // The descriptor's own internal key pins fine.
        ensure_taproot_internal_key_is(&d, &expected).unwrap();
        // A different string is refused.
        let err = ensure_taproot_internal_key_is(&d, "tpubDIFFERENT").unwrap_err();
        assert!(matches!(err, DescriptorError::PolicyMismatch(_)));
        // A wsh descriptor has no internal key to pin.
        let wsh = desc_from(&[1, 2, 3], 2);
        let err = ensure_taproot_internal_key_is(&wsh, &expected).unwrap_err();
        assert!(matches!(err, DescriptorError::UnsupportedShape(_)));
    }

    // ---- PSBT output verification ----

    fn spk(byte: u8) -> ScriptBuf {
        // A distinct, valid-enough scriptPubKey for output comparison.
        ScriptBuf::from_bytes(vec![
            0x00, 0x14, byte, byte, byte, byte, byte, byte, byte, byte, byte, byte, byte, byte,
            byte, byte, byte, byte, byte, byte, byte, byte,
        ])
    }

    fn psbt_with_outputs(outs: &[(ScriptBuf, Amount)]) -> Psbt {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: outs
                .iter()
                .map(|(spk, amt)| TxOut {
                    value: *amt,
                    script_pubkey: spk.clone(),
                })
                .collect(),
        };
        Psbt::from_unsigned_tx(tx).unwrap()
    }

    #[test]
    fn outputs_match_recipient_plus_change() {
        let recipient = spk(0xAA);
        let change = spk(0xBB);
        let psbt = psbt_with_outputs(&[
            (recipient.clone(), Amount::from_sat(50_000)),
            (change.clone(), Amount::from_sat(49_000)),
        ]);
        let approved = [ExpectedOutput::new(recipient, Amount::from_sat(50_000))];
        verify_psbt_outputs(&psbt, &approved, |s| s == change.as_script()).unwrap();
    }

    #[test]
    fn tampered_amount_is_rejected() {
        let recipient = spk(0xAA);
        let change = spk(0xBB);
        let psbt = psbt_with_outputs(&[
            (recipient.clone(), Amount::from_sat(40_000)), // approved 50k
            (change.clone(), Amount::from_sat(59_000)),
        ]);
        let approved = [ExpectedOutput::new(recipient, Amount::from_sat(50_000))];
        let err = verify_psbt_outputs(&psbt, &approved, |s| s == change.as_script()).unwrap_err();
        assert!(matches!(err, PsbtError::OutputMismatch(_)));
        assert!(err.to_string().contains("was changed"), "got {err}");
    }

    #[test]
    fn injected_exfil_output_is_rejected() {
        let recipient = spk(0xAA);
        let change = spk(0xBB);
        let attacker = spk(0xCC);
        let psbt = psbt_with_outputs(&[
            (recipient.clone(), Amount::from_sat(50_000)),
            (attacker, Amount::from_sat(30_000)),
            (change.clone(), Amount::from_sat(19_000)),
        ]);
        let approved = [ExpectedOutput::new(recipient, Amount::from_sat(50_000))];
        let err = verify_psbt_outputs(&psbt, &approved, |s| s == change.as_script()).unwrap_err();
        assert!(err.to_string().contains("unexpected output"), "got {err}");
    }

    #[test]
    fn dropped_approved_output_is_rejected() {
        let recipient = spk(0xAA);
        let change = spk(0xBB);
        // Recipient omitted entirely; only change present.
        let psbt = psbt_with_outputs(&[(change.clone(), Amount::from_sat(99_000))]);
        let approved = [ExpectedOutput::new(recipient, Amount::from_sat(50_000))];
        let err = verify_psbt_outputs(&psbt, &approved, |s| s == change.as_script()).unwrap_err();
        assert!(err.to_string().contains("missing from PSBT"), "got {err}");
    }

    #[test]
    fn no_change_predicate_requires_exact_output_set() {
        let recipient = spk(0xAA);
        let psbt = psbt_with_outputs(&[(recipient.clone(), Amount::from_sat(50_000))]);
        let approved = [ExpectedOutput::new(recipient, Amount::from_sat(50_000))];
        verify_psbt_outputs(&psbt, &approved, |_| false).unwrap();
    }

    #[test]
    fn duplicate_approved_outputs_matched_individually() {
        let recipient = spk(0xAA);
        let psbt = psbt_with_outputs(&[
            (recipient.clone(), Amount::from_sat(50_000)),
            (recipient.clone(), Amount::from_sat(50_000)),
        ]);
        let approved = [
            ExpectedOutput::new(recipient.clone(), Amount::from_sat(50_000)),
            ExpectedOutput::new(recipient, Amount::from_sat(50_000)),
        ];
        verify_psbt_outputs(&psbt, &approved, |_| false).unwrap();
    }
}
