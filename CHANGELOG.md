# Changelog

This file records user-visible changes. The project follows Semantic Versioning for stable 1.x interfaces and file formats.

## 1.0.1 (2026-08-25)

First stable production release.

### Added

- Stable JSON Schemas for artifacts, policies, storage, history, reports, and plans.
- Cross-platform release archives for Linux, macOS, and Windows.
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

### Limits

- The tool remains a release gate, not a contract audit.
- Storage coverage, deployed callers, migration completion, and business invariants need external evidence.
- Upgrade and migration commands use separate transactions.
- A previous WASM hash alone does not prove rollback safety.

## 1.0.0 (unpublished)

The draft smoke test stopped publication because standard release download does not expose draft assets.

Version 1.0.1 adds an attested draft-archive path for the release smoke test.

## 0.1.0-alpha.1 (2026-08-06)

First public evaluation release.

### Added

- Rust validation core and native CLI.
- Compiled WASM identity and Contract Spec comparison.
- Versioned storage declarations and cumulative field history.
- Protocol-aware CAP-0086 checks and a Protocol 28 runtime witness.
- Deterministic non-signing upgrade plans.
- Six Soroban contract fixtures and a verified historical Testnet receipt.

### Limits

- Prerelease interfaces and plan formats were unstable.
- Distribution used source installation only.
- Ledger rehearsal and deployed caller coverage remained external work.
