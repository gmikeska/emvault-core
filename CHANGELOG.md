# Changelog

All notable changes to `emvault-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries for 0.5.0 and earlier were reconstructed from git history.

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
