# Soroban Upgrades

[![CI](https://github.com/bielcarpi/soroban-upgrades/actions/workflows/ci.yml/badge.svg)](https://github.com/bielcarpi/soroban-upgrades/actions/workflows/ci.yml)
[![Release: v1.0.1](https://img.shields.io/badge/release-v1.0.1-2f855a.svg)](https://github.com/bielcarpi/soroban-upgrades/releases/tag/v1.0.1)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> Block unsafe Soroban contract upgrades before a signer approves them.

Soroban Upgrades is a production release gate for compiled Soroban contracts. It compares exact WASM files and checks their release evidence.

The gate checks the public interface, storage declarations, schema history, contract version, host interface, protocol evidence, and upgrade path.

It also creates a deterministic review plan. The plan binds every important release input to a SHA-256 digest.

The CLI never holds keys, signs data, uploads WASM, or submits transactions.

## Production status

Version 1.0.1 defines stable policy, report, schema, history, and plan formats. Later 1.x releases keep these formats backward compatible.

The release provides binaries for Linux, macOS, and Windows. GitHub attaches checksums and provenance attestations to the platform archives.

The release workflow tests the published action before publication. GitHub then locks the release tag and assets against later changes.

The tool is not a security audit. It cannot prove business logic, authorization rules, ledger coverage, or migration completion.

Read [Security limits](#security-limits) before you use a report for Mainnet approval.

## Install

The release page provides shell and PowerShell installers.

macOS or Linux:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/bielcarpi/soroban-upgrades/releases/download/v1.0.1/soroban-upgrades-cli-installer.sh | sh
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/bielcarpi/soroban-upgrades/releases/download/v1.0.1/soroban-upgrades-cli-installer.ps1 | iex"
```

For an approval system, download the platform archive and verify its attestation before extraction:

```sh
gh release download v1.0.1 \
  --repo bielcarpi/soroban-upgrades \
  --pattern 'soroban-upgrades-cli-aarch64-apple-darwin.tar.xz'
gh attestation verify \
  soroban-upgrades-cli-aarch64-apple-darwin.tar.xz \
  --repo bielcarpi/soroban-upgrades
```

The CLI needs Stellar CLI for live network checks. Install Stellar CLI 27.1.0 or a compatible later release.

## Validate an upgrade

Build the deployed source version and the candidate version. Keep complete storage declarations and cumulative history in version control.

```sh
soroban-upgrades validate \
  --from old.wasm \
  --to new.wasm \
  --from-schema old.schema.json \
  --to-schema new.schema.json \
  --schema-history schema-history.json \
  --policy policy.json \
  --network testnet \
  --json > upgrade-report.json
```

The command queries the selected network through Stellar CLI. Use `--protocol-version 27` only for an explicit offline assertion.

The exit status is part of the public contract:

| Status | Meaning |
| --- | --- |
| `0` | The configured gate passed. Review warnings and unknown evidence. |
| `2` | One or more release-blocking findings exist. |
| `1` | Input, parsing, filesystem, or network operation failed. |

The default policy fails closed without both storage schemas and complete schema history.

Use `--compact` for a short log. Use `--json` to keep the complete evidence report.

## Use the GitHub Action

The action downloads the release archive and verifies its GitHub attestation. It writes the report before it returns status `2`.

```yaml
- uses: bielcarpi/soroban-upgrades@v1.0.1
  with:
    from: artifacts/old.wasm
    to: artifacts/new.wasm
    from-schema: upgrade/old.schema.json
    to-schema: upgrade/new.schema.json
    schema-history: upgrade/schema-history.json
    policy: upgrade/policy.json
    network: testnet
    report: artifacts/soroban-upgrade-report.json
```

Pin the action to the full release tag or its commit SHA. Upload the JSON report as a separate workflow artifact.

## Create a review plan

Create the plan only after validation passes. A live plan also verifies the current contract executable against the source WASM.

```sh
soroban-upgrades plan \
  --from old.wasm \
  --to new.wasm \
  --from-schema old.schema.json \
  --to-schema new.schema.json \
  --schema-history schema-history.json \
  --policy policy.json \
  --network testnet \
  --contract-id "$CONTRACT_ID" \
  --source-identity release-signer \
  --migration-entrypoint migrate \
  --migration-arg operator=release-signer \
  --invariant-program ./verify-upgrade.sh \
  --out upgrade.plan.json
```

The plan uploads the exact reviewed bytes with `--optimize=false`. The candidate hash therefore remains the release boundary.

Run the final verification immediately before signer review:

```sh
soroban-upgrades verify-plan --plan upgrade.plan.json
```

This command verifies the report, digest, local artifacts, policy, schemas, history, network, protocol, and current deployed executable.

An offline plan has `offline_draft` status. Only a live plan can have `review_ready` status.

Read the [CLI reference](docs/CLI.md) for every command and option.

## What the gate checks

| Surface | Evidence |
| --- | --- |
| WASM identity | Exact bytes, size limits, format validity, and SHA-256 digest |
| Host interface | Embedded protocol version, prerelease value, imports, and export reachability |
| Public interface | Functions, arguments, results, contract events, public types, and nested type impact |
| Upgrade path | Compatible signature and direct compiled reachability to Stellar’s WASM update host function |
| Version | Increasing semantic `binver` metadata |
| Storage | Complete source and target declarations, migration data, and version links |
| History | Retired names, field types, first release, and reserved names |
| Protocol | Live network identity or an explicit offline assertion |
| CAP-0086 | Protocol activation, sparse imports, call reachability, and known proof limits |
| Plan | Canonical commands, exact inputs, local artifacts, and fresh network evidence |

The parser rejects unknown JSON fields, duplicate JSON fields, malformed WASM, oversized inputs, and unsupported format versions.

The impact traversal has fixed depth, path, and step limits. A limit breach creates blocking finding `RES001`.

## How it works with OpenZeppelin

[OpenZeppelin Stellar Contracts](https://docs.openzeppelin.com/stellar-contracts/utils/upgradeable) provides the on-chain upgrade entrypoint and migration patterns.

Soroban Upgrades checks the compiled release before that entrypoint receives approval. It does not replace OpenZeppelin contract components.

The planner requires this compatible signature:

```text
upgrade(new_wasm_hash: BytesN<32>, operator: Address)
```

OpenZeppelin does not verify constructor behavior, future upgrade access, or storage consistency for each replacement. This gate checks those release concerns.

Read the [adoption guide](docs/ADOPTION.md) for a complete contract setup.

## CAP-0086

[CAP-0086](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0086.md) adds sparse Symbol-keyed map functions in protocol 28.

Sparse decoding can support some optional-field changes. It does not make field renames, type changes, or required-field changes safe.

The gate checks the compiled imports and reachable calls. It reports per-type reader binding as unknown without stronger external evidence.

The [runtime witness](experiments/cap0086-runtime/) tests safe and unsafe reader and writer directions against host version 28.0.1.

## Historical Testnet evidence

On 5 August 2026, the reference contract kept its address and state through a Testnet WASM replacement.

The [`executable_update` transaction](https://stellar.expert/explorer/testnet/tx/f7584b5c2c753ffcba2ccd60691714893e86a9c52a80e00d2ef3e9a39c25ccda) occurred at ledger `3,985,019`.

The fetched executable matched the reviewed target hash. The preserved counter returned `2`, and the new `paused` function returned `false`.

This receipt proves one historical Testnet execution. It does not prove external adoption or Mainnet safety.

## Security limits

Treat `PASS` as one release gate, not as a security guarantee.

The gate does not observe these facts without external evidence:

- all deployed callers and their decoding behavior
- every historical ledger entry
- completion of an eager or lazy migration
- application authorization and signer policy
- business invariants and economic safety
- rollback compatibility after storage mutation

Upgrade and migration steps use separate transactions. Pause external access or use an authorized atomic design when the gap creates risk.

Do not treat the previous WASM hash as a verified rollback. Rehearse rollback against the post-migration storage state.

Read [SECURITY.md](SECURITY.md) to report a vulnerability. Do not place private contracts, keys, or Mainnet exploit details in an issue.

## Verify this repository

Install Rust 1.93.0, target `wasm32v1-none`, Stellar CLI 27.1.0, `cargo-audit` 0.22.2, and `actionlint` 1.7.12.

```sh
./scripts/verify-release.sh
```

The gate formats and lints the workspace. It also runs tests, builds all fixtures, verifies CAP-0086 evidence, packages the core, and audits dependencies.

See [Upgrade scenarios](examples/) for the accepted and blocked fixtures. See [Release process](docs/RELEASE.md) for distribution controls.

## License

Apache-2.0. The engine, CLI, schemas, fixtures, action, and documentation are open source.
