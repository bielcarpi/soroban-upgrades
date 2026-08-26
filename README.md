# Soroban Upgrades

[![CI](https://github.com/bielcarpi/soroban-upgrades/actions/workflows/ci.yml/badge.svg)](https://github.com/bielcarpi/soroban-upgrades/actions/workflows/ci.yml)
[![Fuzz](https://github.com/bielcarpi/soroban-upgrades/actions/workflows/fuzz.yml/badge.svg)](https://github.com/bielcarpi/soroban-upgrades/actions/workflows/fuzz.yml)
[![Release: v1.0.7](https://img.shields.io/badge/release-v1.0.7-2f855a.svg)](https://github.com/bielcarpi/soroban-upgrades/releases/tag/v1.0.7)
[![crates.io](https://img.shields.io/crates/v/soroban-upgrades-cli.svg)](https://crates.io/crates/soroban-upgrades-cli)
[![docs.rs: core](https://docs.rs/soroban-upgrades-core/badge.svg)](https://docs.rs/soroban-upgrades-core)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/bielcarpi/soroban-upgrades/blob/main/LICENSE)

> Check compiled Soroban contract upgrades before a signer approves them.

Soroban Upgrades compares the deployed WASM with a candidate WASM. It finds incompatible changes and records the evidence in a stable report.

The checker is read-only. It never holds keys, signs data, uploads WASM, deploys contracts, or submits transactions.

## What it checks

- WASM identity and Stellar host-interface compatibility
- functions, events, public types, and upgrade-entrypoint reachability
- storage declarations, schema history, migrations, and contract versions
- live network identity, protocol support, and the current deployed executable
- deterministic review plans that bind each input to a SHA-256 digest

A `PASS` result means that the configured checks passed. It is not a contract audit or a security guarantee.

Read [Checks and evidence](https://github.com/bielcarpi/soroban-upgrades/blob/main/docs/CHECKS.md) for the complete scope and limits.

## Install

Install the pinned release from crates.io with Rust 1.93 or later:

```sh
cargo install soroban-upgrades-cli --version 1.0.7 --locked
```

Prebuilt binaries are available for Linux, macOS, and Windows. Read the [installation guide](https://github.com/bielcarpi/soroban-upgrades/blob/main/docs/INSTALL.md) for installers and provenance checks.

Live network checks also need [Stellar CLI](https://developers.stellar.org/docs/tools/cli).

## Quick start

Compare two compiled contracts with complete storage and history evidence:

```sh
soroban-upgrades validate \
  --from old.wasm \
  --to new.wasm \
  --from-schema old.schema.json \
  --to-schema new.schema.json \
  --schema-history schema-history.json \
  --network testnet \
  --json > upgrade-report.json
```

| Status | Result |
| --- | --- |
| `0` | The configured checks passed. |
| `2` | The checker found a blocking change. |
| `1` | An input, parser, file, or network operation failed. |

Use `--compact` for a short CI log. Use `--json` to keep the complete report.

Run the repository showcase to see accepted and blocked upgrades:

```sh
git clone https://github.com/bielcarpi/soroban-upgrades.git
cd soroban-upgrades
./scripts/showcase.sh --offline
```

## GitHub Action

```yaml
- uses: bielcarpi/soroban-upgrades@v1.0.7
  with:
    from: artifacts/old.wasm
    to: artifacts/new.wasm
    from-schema: upgrade/old.schema.json
    to-schema: upgrade/new.schema.json
    schema-history: upgrade/schema-history.json
    network: testnet
    report: artifacts/soroban-upgrade-report.json
```

The action writes the report before it returns status `2`. Pin the action to a release tag or commit SHA.

## Documentation

- [Installation and release verification](https://github.com/bielcarpi/soroban-upgrades/blob/main/docs/INSTALL.md)
- [CLI reference](https://github.com/bielcarpi/soroban-upgrades/blob/main/docs/CLI.md)
- [Checks and evidence](https://github.com/bielcarpi/soroban-upgrades/blob/main/docs/CHECKS.md)
- [Adoption guide](https://github.com/bielcarpi/soroban-upgrades/blob/main/docs/ADOPTION.md)
- [Upgrade scenarios](https://github.com/bielcarpi/soroban-upgrades/blob/main/examples/README.md)
- [Security policy and limits](https://github.com/bielcarpi/soroban-upgrades/blob/main/SECURITY.md)
- [Release process](https://github.com/bielcarpi/soroban-upgrades/blob/main/docs/RELEASE.md)

Version 1.x keeps the policy, report, schema, history, plan, and finding-code formats backward compatible.

## Development

Run the complete repository gate:

```sh
./scripts/verify-release.sh
```

The gate enforces public API compatibility, core line coverage, dependency policy, release packaging, runtime witnesses, and accepted and blocked upgrade fixtures.

Dedicated fuzz targets exercise raw JSON, arbitrary bytes, and generated valid WASM modules on each relevant change and every week.

Read [CONTRIBUTING.md](https://github.com/bielcarpi/soroban-upgrades/blob/main/CONTRIBUTING.md) before you submit a change.

## License

Apache-2.0
