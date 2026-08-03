# Soroban Upgrades

[![CI](https://github.com/bielcarpi/soroban-upgrades/actions/workflows/ci.yml/badge.svg)](https://github.com/bielcarpi/soroban-upgrades/actions/workflows/ci.yml)
[![Release: v0.1.0-alpha.1](https://img.shields.io/badge/release-v0.1.0--alpha.1-orange.svg)](https://github.com/bielcarpi/soroban-upgrades/releases/tag/v0.1.0-alpha.1)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> Catch unsafe Soroban contract upgrades before any signer approves them.

Soroban can replace a contract's WASM while preserving its address and state. **Soroban Upgrades** compares the old and new compiled artifacts, checks the declared storage evolution and migration, verifies protocol assumptions, and produces a deterministic review plan.

It brings the safety workflow of OpenZeppelin Upgrades Plugins to Soroban's native upgrade model. It is a CLI and CI gate, not a proxy framework or contract library.

Status: unaudited alpha, ready for evaluation and real-world pilots.

## Run the MVP

Verified with Rust 1.93.0, the `wasm32v1-none` target, and Stellar CLI 27.1.0.

```sh
./scripts/showcase.sh
```

The command builds six contracts, runs 45 engine and CLI tests plus eight adversarial Protocol-28 tests, reads the current Testnet protocol, and executes six release decisions:

| Scenario | Result |
| --- | --- |
| Compatible v1 to v2 migration | `PASS` |
| ABI, storage, version, and upgrade-path break | `BLOCKED` |
| Protocol 28 claimed without CAP-0086 imports | `BLOCKED` |
| Dense and sparse reader/writer runtime matrix | `PROVED` |
| Rename, retype, and required-field break under protocol 28 | `BLOCKED` |
| Content-addressed, non-signing release plan | `VERIFIED` |

Use `./scripts/showcase.sh --offline` for a reproducible protocol-27 run. The [six scenarios](examples/) explain every artifact pair and expected outcome.

## Try it on a contract

Install the CLI from a reviewed checkout:

```sh
cargo install --locked --path crates/soroban-upgrades-cli
```

Build both contract versions, keep their storage schemas in version control, and compare the compiled WASM before approval:

```sh
soroban-upgrades validate \
  --from old.wasm \
  --to new.wasm \
  --from-schema old.schema.json \
  --to-schema new.schema.json \
  --schema-history schema-history.json \
  --policy policy.json \
  --network testnet \
  --compact
```

Compatible upgrades exit zero. Blocked upgrades exit non-zero with stable finding codes. Use `--json` for the complete CI report.

## Why validate the compiled WASM

[Stellar upgrades a contract by the SHA-256 hash of an uploaded WASM](https://developers.stellar.org/docs/build/guides/conventions/upgrading-contracts), not by a source commit. The binary is therefore the release boundary: it contains the interface the ecosystem will call and the code the network will execute.

- **Exact identity:** build flags, dependencies, SDK code generation, and toolchain changes can produce different bytes from similar source.
- **Published interface:** [Contract Spec XDR](https://developers.stellar.org/docs/tools/sdks/build-your-own#contract-spec-generation) inside the WASM defines the exported functions and user-defined types seen by callers.
- **Runtime capabilities:** environment metadata, host imports, and direct-call reachability show which capabilities are present, while dynamic dispatch marks where static proof is incomplete.
- **State continuity:** replacing code does not rewrite existing ledger state; the new WASM must decode it safely or migrate it deliberately.
- **Upgrade continuity:** the candidate must retain its upgrade path and advance its version.

Source review explains intent. Artifact validation checks the exact candidate that will be uploaded, approved, and later fetched from the ledger.

## What it checks

| Surface | Evidence checked |
| --- | --- |
| Compiled WASM | Artifact hashes, Soroban spec, metadata, host imports, exports, and public types |
| Compatibility | Functions, nested public impact, retained upgrade entrypoint, and increasing SEP-49 `binver` |
| Storage | Versioned schemas, field history, retired names, migrations, and type-reuse hazards |
| Protocol | Live network version and whether the candidate actually imports the capability it claims |
| Reporting | Machine-readable findings labeled as fact, inference, or unknown |
| Release plan | Canonical artifact, policy, migration, network, verification, and rollback steps |

The plan is read-only. The MVP never holds keys, signs, uploads, or submits transactions.

## Where CAP-0086 fits

[CAP-0086](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0086.md) adds sparse Symbol-keyed map functions in protocol 28. This can make additions such as optional fields safer, but it cannot decide whether a compiled replacement preserves its ABI, storage history, upgrade path, or migration requirements.

The [CAP discussion](https://github.com/orgs/stellar/discussions/1877) identifies field-lifecycle checks as tooling work comparable to `cargo-semver`. This MVP checks the compiled candidate instead of assuming that protocol 28 or a source-level claim proves CAP-0086 compatibility.

## How it complements OpenZeppelin

| Layer | Role |
| --- | --- |
| Soroban | Executes same-address WASM replacement |
| [OpenZeppelin Stellar Contracts](https://docs.openzeppelin.com/stellar-contracts/utils/upgradeable) | Provides an upgrade entrypoint, schema-version helpers, and migration patterns |
| [OpenZeppelin EVM Upgrades](https://docs.openzeppelin.com/upgrades-plugins/api-core) | Validates Solidity proxy upgrades from Hardhat or Foundry build data |
| **Soroban Upgrades** | Validates Soroban WASM compatibility and produces reviewable release evidence before approval |

OpenZeppelin's EVM tooling does not parse Soroban WASM, Contract Spec XDR, SEP-49 metadata, CAP-0086 imports, or Stellar network evidence. This project fills that Soroban-specific gap without replacing OpenZeppelin's contract primitives.

## Verified Testnet upgrade

On 5 August 2026, the [reference contract](https://lab.stellar.org/r/testnet/contract/CAVRSELEZ6PAWEXGHPGNQ3VHI4LDT5QUA5MZWSMXYQLE7HACO6G3TUMJ) was upgraded at the same address. The successful [`executable_update` transaction](https://stellar.expert/explorer/testnet/tx/f7584b5c2c753ffcba2ccd60691714893e86a9c52a80e00d2ef3e9a39c25ccda) at ledger `3,985,019` binds the old WASM `c30ddc...c6a8` to the reviewed target `1494bf...d9e`.

After migration, the preserved counter returned `2`, the new `paused` function returned `false`, and the fetched on-chain WASM hashed to the reviewed target. This is historical Testnet execution evidence, not external adoption or Mainnet readiness.

## Roadmap

The MVP proves the core release decision. The roadmap turns it into a supported lifecycle toolchain covering artifact validation, state rehearsal, controlled rollout, and on-chain evidence.

### 1. Validator v1

- **Engine:** stabilize the policy, schema, report, and plan formats; normalize ABI, SEP-49, protocol, SDK, and CAP-0086 rules.
- **Validation:** add fuzzing, malformed-input and resource-limit tests, reviewed exceptions, and a public adversarial corpus.
- **Distribution:** publish a reusable GitHub Action, stable crates, cross-platform binaries with signed checksums, and a supported release matrix.
- **Acceptance:** reproduce every supported fixture from a clean checkout, block every labeled critical corpus hazard, and prevent malformed input from panicking or bypassing a failing rule.

### 2. State rehearsal and Testnet pilots

- **State model:** generate storage manifests, sample ledger snapshots, and compare current schemas with cumulative field history.
- **Rehearsal:** execute eager, lazy, paused, atomic, and rollback migrations with invariant, coverage, and resource reports.
- **Rollout:** add dependency-aware sequencing, policy-bound Stellar CLI workflows, and three external Testnet pilots.
- **Acceptance:** detect every labeled state break, reject substituted artifacts or current executables, and record before-and-after invariants for each pilot.

### 3. Production evidence

- **Monitoring:** match `executable_update` events and fetched WASM to the reviewed artifact and canonical plan.
- **Operations:** produce portable evidence bundles covering approval, simulation, execution, migration, invariants, and rollback.
- **Release:** ship stable v1 crates and binaries, a controlled Mainnet reference upgrade, and five verified external integrations in total.
- **Acceptance:** reproduce every tagged binary, detect synthetic event or hash mismatches, and publish the result and unresolved limits of each integration.

## License

Apache-2.0. The engine, CLI, schemas, fixtures, and documentation are open source.
