//! PSBT pipeline: construction, signing coordination, finalization.
//!
//! The pipeline is split into three discrete, auditable stages:
//!
//! 1. **Construction** — done outside this crate via
//!    [`bdk_wallet::Wallet::build_tx`]. The resulting PSBT is wrapped in
//!    [`UnsignedPsbt`].
//! 2. **Signing** — coordinated by [`SigningCoordinator`]. Software signers
//!    (HSMs implementing BDK's
//!    [`TransactionSigner`](bdk_wallet::signer::TransactionSigner)) are
//!    dispatched via [`bdk_wallet::Wallet::sign`]. External signers (consumer
//!    hardware wallets) get a [`SigningRequest`] for the browser.
//! 3. **Finalization** — [`SigningCoordinator::finalize`] delegates to
//!    [`bdk_wallet::Wallet::finalize_psbt`] and wraps the result in
//!    [`FinalizedPsbt`].
//!
//! The `Unsigned`/`Finalized` newtype distinction makes invalid states
//! unrepresentable: you cannot accidentally pass a half-signed PSBT to a
//! function that expects a fully-signed transaction.

use std::collections::HashMap;
use std::collections::HashSet;

use bdk_wallet::{SignOptions, Wallet};
use bitcoin::{Amount, FeeRate, Psbt, ScriptBuf, Transaction, Txid};

use crate::error::PsbtError;
use crate::federation::Federation;
use crate::signer::{Signer, SignerId, SignerType};

// ---------------------------------------------------------------------------
// Newtypes
// ---------------------------------------------------------------------------

/// A PSBT that is structurally guaranteed to carry zero partial signatures.
///
/// Construct via [`UnsignedPsbt::new`], which validates the invariant. The
/// inner PSBT can be borrowed via [`UnsignedPsbt::as_psbt`] and converted
/// back to a raw `Psbt` with [`UnsignedPsbt::into_psbt`].
#[derive(Clone, Debug)]
pub struct UnsignedPsbt(Psbt);

impl UnsignedPsbt {
    /// Wrap a `Psbt`. Errors if any input has partial signatures.
    ///
    /// # Errors
    ///
    /// Returns [`PsbtError::UnexpectedSignatures`] if any input already has a
    /// partial signature.
    pub fn new(psbt: Psbt) -> Result<Self, PsbtError> {
        let total_sigs: usize = psbt.inputs.iter().map(|i| i.partial_sigs.len()).sum();
        if total_sigs != 0 {
            return Err(PsbtError::UnexpectedSignatures { found: total_sigs });
        }
        Ok(Self(psbt))
    }

    /// Borrow the inner PSBT.
    pub fn as_psbt(&self) -> &Psbt {
        &self.0
    }

    /// Take ownership of the inner PSBT.
    pub fn into_psbt(self) -> Psbt {
        self.0
    }
}

/// A fully-signed, finalized PSBT, ready for broadcast.
#[derive(Clone, Debug)]
pub struct FinalizedPsbt {
    psbt: Psbt,
    transaction: bitcoin::Transaction,
}

impl FinalizedPsbt {
    /// The fully-signed transaction.
    pub fn transaction(&self) -> &bitcoin::Transaction {
        &self.transaction
    }

    /// The transaction id.
    pub fn txid(&self) -> bitcoin::Txid {
        self.transaction.compute_txid()
    }

    /// The serialized transaction bytes.
    pub fn serialize(&self) -> Vec<u8> {
        bitcoin::consensus::encode::serialize(&self.transaction)
    }

    /// The original PSBT (retained for audit purposes).
    pub fn as_psbt(&self) -> &Psbt {
        &self.psbt
    }
}

// ---------------------------------------------------------------------------
// Synchronous primitives
// ---------------------------------------------------------------------------
//
// These are the signing-model-agnostic, persistence-free building blocks the
// consuming apps compose into their full PSBT lifecycles. They deliberately do
// *not* touch a database, an RPC node, a mutex, or an async runtime — the
// caller owns the wallet lock, the changeset persistence, the broadcast, and
// the Interactive-vs-Autonomous signing orchestration around these calls.

/// Build an unsigned single-recipient spend PSBT.
///
/// A thin wrapper over
/// [`build_tx().add_recipient(..).fee_rate(..).finish()`](bdk_wallet::Wallet::build_tx)
/// using BDK's default coin-selection algorithm. The caller holds the wallet
/// lock and is responsible for persisting any reveal-induced changeset
/// (`take_staged`) afterwards — BDK may reveal a fresh internal change address
/// during construction.
///
/// This is the shared primitive under the xpub app's `build_proposal` and the
/// pkcs11 app's `build_sign_and_broadcast`. The wallet-draining variants
/// (`drain_wallet`/`drain_to` for migration sweeps) use a different builder
/// shape and are intentionally not covered here.
///
/// # Errors
///
/// Returns [`PsbtError::BuildFailed`] if BDK cannot satisfy the spec (no
/// spendable UTXOs, dust output, fee floor not met, etc.).
pub fn build_spend(
    wallet: &mut Wallet,
    recipient_spk: ScriptBuf,
    amount: Amount,
    fee_rate: FeeRate,
) -> Result<Psbt, PsbtError> {
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(recipient_spk, amount)
        .fee_rate(fee_rate);
    builder
        .finish()
        .map_err(|e| PsbtError::BuildFailed(e.to_string()))
}

/// Merge a cosigner's partial PSBT into a base PSBT via
/// [`Psbt::combine`](bitcoin::Psbt::combine), returning the merged result.
///
/// This is the neutral combine primitive under the xpub app's
/// `merge_partial_signature` (the only caller today — HSMs in the pkcs11 app
/// never produce a partial-merge step; they sign in one shot through the
/// [`SigningCoordinator`]). The wallet-dependent "does this now finalize?"
/// probe stays app-side, since it requires the wallet lock.
///
/// # Errors
///
/// Returns [`PsbtError::Bitcoin`] if [`Psbt::combine`](bitcoin::Psbt::combine)
/// rejects the input (e.g. the two PSBTs reference different unsigned
/// transactions).
pub fn combine_psbt(mut base: Psbt, partial: Psbt) -> Result<Psbt, PsbtError> {
    base.combine(partial)
        .map_err(|e| PsbtError::Bitcoin(e.to_string()))?;
    Ok(base)
}

/// Finalize a fully-signed PSBT and extract the broadcastable transaction.
///
/// Delegates to [`bdk_wallet::Wallet::finalize_psbt`] with
/// [`SignOptions::default`] and then [`Psbt::extract_tx`]. Distinguishes the
/// three failure modes the apps care about:
///
/// - a hard BDK finalizer error → [`PsbtError::FinalizationFailed`];
/// - `Ok(false)` (no error, but not every input is satisfied — the threshold
///   is not yet met) → [`PsbtError::ThresholdNotMet`];
/// - a malformed PSBT that finalizes but won't extract →
///   [`PsbtError::ExtractFailed`].
///
/// This is the standalone finalize path under the xpub app's
/// `finalize_and_extract`. (The pkcs11 app finalizes through
/// [`SigningCoordinator::finalize`] instead, which carries the coordinator's
/// signature-count invariant.)
///
/// # Errors
///
/// See the failure modes above.
pub fn finalize_and_extract(
    wallet: &Wallet,
    mut psbt: Psbt,
) -> Result<(Transaction, Txid), PsbtError> {
    let finalized = wallet
        .finalize_psbt(&mut psbt, SignOptions::default())
        .map_err(|e| PsbtError::FinalizationFailed(e.to_string()))?;
    if !finalized {
        return Err(PsbtError::ThresholdNotMet);
    }
    let transaction = psbt
        .extract_tx()
        .map_err(|e| PsbtError::ExtractFailed(e.to_string()))?;
    let txid = transaction.compute_txid();
    Ok((transaction, txid))
}

// ---------------------------------------------------------------------------
// SigningRequest / SigningAction
// ---------------------------------------------------------------------------

/// Data sent to an external signer (consumer hardware wallet) for signing.
///
/// The web layer is responsible for transporting this to the browser, the
/// browser invokes the device-specific SDK (Trezor Connect, Jade serial, etc.),
/// and the resulting signed PSBT is returned to
/// [`SigningCoordinator::receive_signature`].
#[derive(Clone, Debug)]
pub struct SigningRequest {
    /// Which signer this request is for.
    pub signer_id: SignerId,
    /// The signer's master fingerprint (helps the browser confirm device
    /// identity before signing).
    pub fingerprint: bitcoin::bip32::Fingerprint,
    /// The PSBT to sign.
    pub psbt: Psbt,
}

/// What the [`SigningCoordinator`] determined for a given signer.
///
/// The `External` variant is heap-allocated via [`Box`] to keep the enum
/// uniformly small (the inner [`SigningRequest`] embeds a full PSBT).
#[derive(Debug)]
pub enum SigningAction {
    /// The signer is software-resident (HSM). The coordinator has already
    /// invoked [`bdk_wallet::Wallet::sign`] which dispatched to the signer's
    /// [`TransactionSigner`](bdk_wallet::signer::TransactionSigner)
    /// implementation.
    Direct,
    /// The signer requires an external round-trip. The web layer must
    /// transport `request` to the browser and call
    /// [`SigningCoordinator::receive_signature`] when the browser returns
    /// a signed PSBT.
    External(Box<ExternalSigning>),
}

/// Payload carried by [`SigningAction::External`].
#[derive(Debug)]
pub struct ExternalSigning {
    /// Data for the browser to forward to the device.
    pub request: SigningRequest,
    /// Optional human-readable instructions for the trustee.
    pub instructions: Option<String>,
}

// ---------------------------------------------------------------------------
// SigningCoordinator
// ---------------------------------------------------------------------------

/// Coordinates signature collection across heterogeneous signers.
///
/// Holds a borrowed reference to the [`Federation`] and owns the in-flight
/// [`Psbt`].
pub struct SigningCoordinator<'a, S: Signer = Box<dyn Signer>> {
    federation: &'a Federation<S>,
    psbt: Psbt,
    /// Tracks signers that have already produced at least one partial
    /// signature (whether via Direct or External).
    signed: HashSet<SignerId>,
}

impl<'a, S: Signer> SigningCoordinator<'a, S> {
    /// Construct a new coordinator from a federation and an unsigned PSBT.
    pub fn new(federation: &'a Federation<S>, psbt: UnsignedPsbt) -> Self {
        Self {
            federation,
            psbt: psbt.into_psbt(),
            signed: HashSet::new(),
        }
    }

    /// The federation this coordinator operates against.
    pub fn federation(&self) -> &'a Federation<S> {
        self.federation
    }

    /// Borrow the current PSBT.
    pub fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    /// How many distinct signers have contributed signatures so far.
    pub fn signatures_collected(&self) -> usize {
        self.signed.len()
    }

    /// Whether the threshold has been met.
    ///
    /// # Panics
    ///
    /// Panics if more than [`u32::MAX`] distinct signers have contributed
    /// — practically impossible given federation membership constraints.
    pub fn is_complete(&self) -> bool {
        let collected =
            u32::try_from(self.signatures_collected()).expect("signature count fits u32");
        collected >= self.federation.threshold()
    }

    /// Apply software signers via BDK's wallet-level signer dispatch and
    /// return the [`SigningAction`] required for each external signer.
    ///
    /// The caller must have registered the federation's HSM signers with
    /// `wallet` via
    /// [`bdk_wallet::Wallet::add_signer`](bdk_wallet::Wallet::add_signer)
    /// before invoking this method.
    ///
    /// # Errors
    ///
    /// Returns [`PsbtError::BdkSigner`] if BDK rejects the PSBT during
    /// software-signer dispatch.
    pub fn request_signatures(
        &mut self,
        wallet: &Wallet,
        sign_options: SignOptions,
    ) -> Result<Vec<(SignerId, SigningAction)>, PsbtError> {
        let _ = wallet
            .sign(&mut self.psbt, sign_options)
            .map_err(|e| PsbtError::BdkSigner(e.to_string()))?;

        let after = signers_with_sigs(&self.psbt, self.federation);
        for id in &after {
            self.signed.insert(id.clone());
        }

        // Build per-signer actions.
        let mut actions = Vec::with_capacity(self.federation.signers().len());
        for s in self.federation.signers() {
            let id = s.id();
            let action = match s.signer_type() {
                // Either case (newly_signed contained or not, or already
                // recorded as signed) reports Direct so the caller can decide
                // whether to retry — we do not auto-promote a Software signer
                // that produced no partial signature to External.
                SignerType::Software => SigningAction::Direct,
                SignerType::External => SigningAction::External(Box::new(ExternalSigning {
                    request: SigningRequest {
                        signer_id: id.clone(),
                        fingerprint: s.fingerprint(),
                        psbt: self.psbt.clone(),
                    },
                    instructions: s.label().map(|l| {
                        format!(
                            "Hand the PSBT to {l} for signing on the connected hardware wallet."
                        )
                    }),
                })),
            };
            actions.push((id, action));
        }
        Ok(actions)
    }

    /// Ingest a signed PSBT returned by an external signer. Validates that
    /// `signer_id` is a member of the federation, merges new partial
    /// signatures into the coordinator's PSBT via
    /// [`Psbt::combine`](bitcoin::Psbt::combine), and updates internal
    /// tracking.
    ///
    /// # Errors
    ///
    /// Returns [`PsbtError::UnknownSigner`] if `signer_id` isn't in the
    /// federation, [`PsbtError::DescriptorMismatch`] if `signed_psbt`
    /// references a different unsigned transaction,
    /// [`PsbtError::Bitcoin`] if the PSBT combine call fails, or
    /// [`PsbtError::InvalidSignature`] if no new partial signature
    /// attributable to this signer is present.
    pub fn receive_signature(
        &mut self,
        signer_id: &SignerId,
        signed_psbt: Psbt,
    ) -> Result<(), PsbtError> {
        let signer = self
            .federation
            .find(signer_id)
            .ok_or_else(|| PsbtError::UnknownSigner(signer_id.clone()))?;
        let fp = signer.fingerprint();

        if signed_psbt.unsigned_tx.compute_txid() != self.psbt.unsigned_tx.compute_txid() {
            return Err(PsbtError::DescriptorMismatch(
                "returned PSBT does not match this signing session's unsigned transaction".into(),
            ));
        }
        let mut merged = self.psbt.clone();
        merged
            .combine(signed_psbt)
            .map_err(|e| PsbtError::Bitcoin(e.to_string()))?;
        let mut found_new = false;
        for (input_idx, input) in merged.inputs.iter().enumerate() {
            let prev_input = self.psbt.inputs.get(input_idx);
            for pk in input.partial_sigs.keys() {
                let inner: bitcoin::PublicKey = *pk;
                // The signer "owns" this partial sig if its master fingerprint
                // appears in either the BIP32 derivation map (P2WSH) or the
                // taproot key origins (P2TR).
                let fp_matches = input
                    .bip32_derivation
                    .iter()
                    .any(|(k, (f, _))| *f == fp && k == &inner.inner)
                    || input.tap_key_origins.iter().any(|(k, (_lh, (f, _)))| {
                        *f == fp && *k == inner.inner.x_only_public_key().0
                    });

                if fp_matches && !prev_input.is_some_and(|p| p.partial_sigs.contains_key(pk)) {
                    found_new = true;
                }
            }
        }
        if !found_new {
            return Err(PsbtError::InvalidSignature(
                signer_id.clone(),
                "no new partial signature attributable to this signer was present in the \
                 returned PSBT"
                    .into(),
            ));
        }
        self.psbt = merged;
        self.signed.insert(signer_id.clone());
        Ok(())
    }

    /// Finalize the PSBT once the threshold has been met. Delegates to
    /// [`bdk_wallet::Wallet::finalize_psbt`].
    ///
    /// # Errors
    ///
    /// Returns [`PsbtError::InsufficientSignatures`] if the threshold
    /// hasn't been met, or [`PsbtError::FinalizationFailed`] if BDK refuses
    /// to finalize or the resulting transaction can't be extracted.
    pub fn finalize(
        mut self,
        wallet: &Wallet,
        sign_options: SignOptions,
    ) -> Result<FinalizedPsbt, PsbtError> {
        if !self.is_complete() {
            return Err(PsbtError::InsufficientSignatures {
                have: self.signatures_collected(),
                need: self.federation.threshold() as usize,
            });
        }
        let finalized = wallet
            .finalize_psbt(&mut self.psbt, sign_options)
            .map_err(|e| PsbtError::FinalizationFailed(e.to_string()))?;
        if !finalized {
            return Err(PsbtError::FinalizationFailed(
                "BDK reported the PSBT could not be finalized".into(),
            ));
        }
        let transaction = self
            .psbt
            .clone()
            .extract_tx()
            .map_err(|e| PsbtError::FinalizationFailed(e.to_string()))?;
        Ok(FinalizedPsbt {
            psbt: self.psbt,
            transaction,
        })
    }
}

fn signers_with_sigs<S: Signer>(psbt: &Psbt, federation: &Federation<S>) -> HashSet<SignerId> {
    let mut out = HashSet::new();
    let mut fp_to_id: HashMap<bitcoin::bip32::Fingerprint, SignerId> = HashMap::new();
    for s in federation.signers() {
        fp_to_id.insert(s.fingerprint(), s.id());
    }
    for input in &psbt.inputs {
        for (fp, _path) in input.bip32_derivation.values() {
            // partial_sigs holds bitcoin::PublicKey -> ecdsa::Signature; we
            // detect a contribution if a partial sig exists for any pk that
            // shares this signer's fingerprint via bip32_derivation.
            if let Some(id) = fp_to_id.get(fp) {
                let signed_with_fp = input.partial_sigs.keys().any(|pk| {
                    input
                        .bip32_derivation
                        .get(&pk.inner)
                        .is_some_and(|(f, _)| f == fp)
                });
                if signed_with_fp {
                    out.insert(id.clone());
                }
            }
        }
        for (_lh, (fp, _path)) in input.tap_key_origins.values() {
            if let Some(id) = fp_to_id.get(fp)
                && (!input.tap_script_sigs.is_empty() || input.tap_key_sig.is_some())
            {
                out.insert(id.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_psbt() -> Psbt {
        empty_psbt_at(bitcoin::absolute::LockTime::ZERO)
    }

    fn empty_psbt_at(lock_time: bitcoin::absolute::LockTime) -> Psbt {
        // Construct a minimal PSBT (no inputs, no outputs) for newtype tests.
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time,
            input: vec![],
            output: vec![],
        };
        Psbt::from_unsigned_tx(tx).unwrap()
    }

    #[test]
    fn unsigned_psbt_accepts_zero_sig_psbt() {
        let p = empty_psbt();
        let _ = UnsignedPsbt::new(p).unwrap();
    }

    #[test]
    fn combine_psbt_merges_matching_unsigned_tx() {
        // Two PSBTs over the *same* unsigned tx combine without error.
        let base = empty_psbt();
        let other = empty_psbt();
        let merged = combine_psbt(base, other).expect("matching PSBTs combine");
        assert_eq!(merged.inputs.len(), 0);
    }

    #[test]
    fn combine_psbt_rejects_mismatched_unsigned_tx() {
        // PSBTs describing different unsigned transactions must be rejected
        // (mapped to PsbtError::Bitcoin), not silently merged.
        let base = empty_psbt_at(bitcoin::absolute::LockTime::ZERO);
        let other = empty_psbt_at(bitcoin::absolute::LockTime::from_height(1).unwrap());
        let err = combine_psbt(base, other).expect_err("mismatched PSBTs must error");
        assert!(matches!(err, PsbtError::Bitcoin(_)), "got {err:?}");
    }

    #[test]
    fn build_spend_on_unfunded_wallet_reports_build_failed() {
        // A wallet with no UTXOs cannot fund any spend; build_spend must
        // surface that as BuildFailed rather than panicking.
        let xpriv = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &[7u8; 32])
            .expect("valid master");
        let external = format!("wpkh({xpriv}/84h/1h/0h/0/*)");
        let internal = format!("wpkh({xpriv}/84h/1h/0h/1/*)");
        let mut wallet = Wallet::create(external, internal)
            .network(bitcoin::Network::Regtest)
            .create_wallet_no_persist()
            .expect("create signable single-sig wallet");
        let recipient = wallet
            .peek_address(bdk_wallet::KeychainKind::External, 0)
            .address
            .script_pubkey();
        let err = build_spend(
            &mut wallet,
            recipient,
            bitcoin::Amount::from_sat(10_000),
            bitcoin::FeeRate::from_sat_per_vb(1).unwrap(),
        )
        .expect_err("unfunded wallet cannot build a spend");
        assert!(matches!(err, PsbtError::BuildFailed(_)), "got {err:?}");
    }
}
