# Changelog

This file records user-visible changes. The project follows Semantic Versioning for stable 1.x interfaces and file formats.

## 1.0.6 (2026-08-25)

This documentation release makes the public entry points faster to scan and easier to use.

### Added

- A focused installation and provenance guide.
- A focused reference for checker scope, evidence, and limits.

### Changed

- The README now leads with one purpose, one install command, one validation example, and the GitHub Action.
- Detailed checks, CAP-0086 behavior, OpenZeppelin compatibility, and archive verification now live in focused documents.
- The adoption guide now stops at signer review and separates checker evidence from deployment approval.
- Public wording now uses checker terms consistently.

### Compatibility

- Version 1.0.6 does not change CLI behavior or stable JSON formats.

## 1.0.5 (2026-08-25)

This maintenance release clarifies the product scope and completes the crates.io release path.

### Added

- Trusted Publishing for the core library and CLI.
- A pinned Cargo installation command in the README.

### Changed

- The product description now identifies Soroban Upgrades as an independent checker.
- The documentation states that the tool does not deploy contracts or execute review plans.
- The GitHub Action and crates.io package descriptions now use checking terms.

### Removed

- Launch evidence that did not measure the checker.

## 1.0.4 (2026-08-25)

First stable production release.

### Added

- Stable JSON Schemas for artifacts, policies, storage, history, reports, and plans.
- Cross-platform release archives for Linux, macOS, and Windows.
- crates.io packages for the core library and CLI.
- Shell and PowerShell installers, SHA-256 checksums, and GitHub provenance attestations.
- A reusable GitHub Action that verifies archive provenance before validation.
- Draft release smoke tests and immutable published release assets.
- Live plan checks for network identity, protocol, and current deployed executable.
- Required application invariant commands in signer review plans.
- Compiled host-call checks for the current and retained WASM replacement paths.
- Contract event compatibility checks and duplicate specification member rejection.

### Changed

- Validation now fails closed without complete storage declarations and cumulative history.
- The WASM parser now validates the complete module and exact Soroban environment metadata.
- Public impact analysis now uses bounded iterative traversal.
- Reports now embed complete revalidation evidence and stable tool format versions.
- Plans now bind all input paths, named migration arguments, and application invariant commands.
- Upload commands now disable Stellar CLI optimization to preserve the reviewed target hash.
- Plan verification now rebuilds the report and canonical command sequence before digest acceptance.
- Plan verification now reloads every artifact, policy, schema, and history file from its bound path.
- Blocked validation now returns status `2`. Operational failures return status `1`.

### Security

- Strict JSON parsing rejects unknown and duplicate fields.
- Plan output refuses overwrite without `--force`.
- Plans reject Stellar secret keys in identity, migration, and invariant arguments.
- Release workflows pin external actions and verify the `dist` installer checksum.

### Fixed

- A separate staging job now reads the draft with a write-scoped token.
- The validation job keeps read-only contents access while it runs the project Action.

### Limits

- The tool checks release evidence. It does not deploy contracts or replace a contract audit.
- Storage coverage, deployed callers, migration completion, and business invariants need external evidence.
- Upgrade and migration commands use separate transactions.
- A previous WASM hash alone does not prove rollback safety.

## 1.0.3 (unpublished)

The draft smoke test confirmed that a read-only workflow token cannot list draft releases.

Version 1.0.4 isolates draft access from the validation job.

## 1.0.2 (unpublished)

The draft smoke test stopped publication because its selector tried to iterate an absent asset list.

Version 1.0.3 uses a null-safe selector before the bounded retry.

## 1.0.1 (unpublished)

The draft smoke test stopped publication because its first API query did not show the new archive.

Version 1.0.2 adds a bounded retry for GitHub release API consistency.

## 1.0.0 (unpublished)

The draft smoke test stopped publication because standard release download does not expose draft assets.

Version 1.0.1 added an attested draft-archive path for the release smoke test.

## 0.1.0-alpha.1 (2026-08-06)

First public evaluation release.

### Added

- Rust validation core and native CLI.
- Compiled WASM identity and Contract Spec comparison.
- Versioned storage declarations and cumulative field history.
- Protocol-aware CAP-0086 checks and a Protocol 28 runtime witness.
- Deterministic non-signing upgrade plans.
- Six Soroban contract fixtures.

### Limits

- Prerelease interfaces and plan formats were unstable.
- Distribution used source installation only.
- Ledger rehearsal and deployed caller coverage remained external work.
