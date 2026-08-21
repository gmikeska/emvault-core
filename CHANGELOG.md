# Changelog

All notable changes to `emvault-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries for 0.5.0 and earlier were reconstructed from git history.

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
