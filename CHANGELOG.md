# Changelog

All notable changes to `emvault-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries for 0.5.0 and earlier were reconstructed from git history.

## [0.12.0] - 2026-11-24

Supersedes **0.11.0, which is yanked**. The source is identical to 0.11.0; the version moves so
every inter-crate requirement in the suite resolves at one *resolvable* version (see
`emvault-pkcs11` 0.12.0 for this round's change).

## [0.11.0] - 2026-11-24

Released in lockstep with the suite. No functional change in this crate; the version
moves so every inter-crate requirement in the suite resolves at one version (see
`emvault-pkcs11` 0.11.0 for this round's change).

## [0.10.0] - 2026-08-28

Security-audit hardening of the Taproot signing/verification path and federation
config-at-rest (Rosie, EmVault v0.9.0 audit — F1/F4/F2). **Breaking:** the public
`MultisigPolicy` gains `shape` and `internal_key` fields (Phase 0 normalizer).

### Fixed
- **F1 — Taproot signature accounting is now sound** (`psbt.rs`,
  `SigningCoordinator`). Two defects fixed: `signers_with_sigs` no longer credits
  *every* cosigner in `tap_key_origins` off a single `tap_script_sig` — each
  signature is bound to the specific x-only key that produced it; and
  `receive_signature` now detects Taproot `tap_script_sigs` at ingest (it
  previously scanned only ECDSA `partial_sigs`, rejecting every hardware Taproot
  signature). Attributed signatures are additionally **Schnorr-verified against
  the BIP-341 script-spend sighash before counting**, so `is_complete()` /
  `signatures_collected()` reflect cryptographically valid signatures, not merely
  present ones. The production P2WSH path is unchanged.

### Added
- **F4 — Anchor #1 covers Taproot.** `multisig_policy` normalizes both
  `wsh(sortedmulti)` and `tr(NUMS, multi_a)` into a shape-aware
  `(shape, threshold, key-set, internal-key)` identity, so `ensure_descriptors_match`
  rejects a swapped cosigner **or** a swapped Taproot internal key on a Taproot
  federation. New `ensure_taproot_internal_key_is` pins the internal key to the
  expected unspendable NUMS point.
- **F2 — keyed authentication for config at rest.** `RecoveryTemplate` and
  `FederationSnapshot` gain `authenticate` / `verify_authentic` (HMAC-SHA256 over
  the canonical content, constant-time compare, dependency-free). The unkeyed
  checksum is re-documented as a **corruption** check, not tamper-evidence.

### Changed
- **Breaking:** `MultisigPolicy` now carries `shape: PolicyShape` and
  `internal_key: Option<String>` (both part of the equality that drives Anchor #1).
- **F2 — snapshot binding fix.** `FederationSnapshot::verify()` binds each signer
  by its origin fingerprint **and** key material (full xpub in Ranged mode, or the
  derived compressed public key in Fixed mode) plus the parsed threshold and shape
  — replacing the previous 8-hex fingerprint *substring* test that any origin
  satisfied. Corrects the xpub-vs-fingerprint doc/code mismatch.

## [0.9.0] - 2026-08-21

### Changed
- Released in lockstep with the suite-wide v0.9.0 (driven by `emvault-elements`'
  asset-aware federation migration). No functional changes to `emvault-core` this
  round; adds GitHub CI workflows and switches inter-crate dependencies to
  version-only requirements so isolated CI resolves against crates.io.

## [0.8.0] - 2026-08-16

### Added
- **Taproot descriptor support.** A new `ScriptType` (`Wsh` default / `Tr`),
  selectable via `DescriptorBuilder::script_type(...)` and
  `Federation::with_config(...)`, lets a federation emit
  `tr(NUMS, multi_a(m, ...))` — a script-path-only P2TR with the BIP-341 NUMS
  internal key (key-path provably unspendable) and BIP-341-sorted x-only
  cosigner keys. This is byte-identical to `sortedmulti_a`, which the pinned
  miniscript does not provide. Supported for `KeyMode::Fixed` (the HSM
  federation model); `Tr` + `KeyMode::Ranged` is rejected.
- `Federation::script_type()` accessor.

### Fixed
- Federation mutations (`rotate_signer`, `add_signer`, `remove_signer`,
  `change_threshold`) now preserve the `ScriptType`. Previously they rebuilt the
  descriptor as `wsh`, which would have silently changed a taproot vault's
  descriptor and address on any signer rotation.

## [0.7.0] - 2026-08-03

### Changed
- Released in lockstep with the suite-wide v0.7.0 update; no functional changes
  to `emvault-core` itself.
- The re-exported nodeless chain backends gained a `tip_height()` / `get_tx()`
  surface, available through the `esplora` and `electrum` features — see the
  `emvault-esplora` and `emvault-electrum` changelogs.

## [0.6.0] - 2026-07-29

### Added
- Reorg reconciliation: detect chain reorganizations and reconcile federated
  wallet state accordingly.

### Changed
- Documentation updates.

## [0.5.0] - 2026-07-27

### Changed
- Dependency and lockfile refresh; version realigned across the emvault suite.

## [0.4.0] - 2026-07-22

### Added
- Optional Electrum chain backend behind the `electrum` feature.

### Changed
- README/documentation updates.

## [0.3.0] - 2026-07-13

### Added
- `esplora` feature: re-exports `emvault-esplora` and provides
  `From<EsploraSyncResult> for SyncResult`, wiring the nodeless Esplora /
  Waterfalls backend into core.

### Changed
- Documentation updates.
