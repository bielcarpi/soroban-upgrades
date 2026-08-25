# Checks and evidence

Soroban Upgrades compares compiled contract artifacts and reviewed release evidence. The checker does not deploy or change a contract.

## Decision model

The checker returns one of these process results:

| Status | Meaning |
| --- | --- |
| `0` | The configured checks passed. |
| `2` | One or more blocking findings exist. |
| `1` | The checker stopped before it produced a release decision. |

Each finding identifies its evidence strength:

- `FACT` comes from a parsed artifact or a complete live-network response.
- `INFERENCE` comes from a declaration or bounded static analysis.
- `UNKNOWN` identifies evidence that the checker cannot observe.

A `PASS` report can contain warnings and unknown evidence. Review them before signer approval.

## Check surfaces

| Surface | Evidence |
| --- | --- |
| WASM identity | Exact bytes, size, format, and SHA-256 digest |
| Host interface | Embedded protocol, prerelease value, imports, exports, and reachable calls |
| Public interface | Functions, arguments, results, events, public types, and nested type effects |
| Upgrade path | Compatible signature and reachable Stellar WASM-update host call |
| Version | Increasing semantic `binver` metadata |
| Storage | Complete source and target declarations, migration data, and version links |
| History | Field types, first release, retired names, and reserved names |
| Protocol | Live network identity or an explicit offline assertion |
| CAP-0086 | Protocol activation, sparse imports, call reachability, and proof limits |
| Plan | Canonical commands, exact inputs, local artifacts, and current network evidence |

The JSON parsers reject unknown fields, duplicate fields, unsupported versions, and inputs larger than the documented limits.

## Analysis limits

The maximum WASM size is 16 MiB. The maximum JSON input size is 8 MiB.

Public-impact analysis stops at these limits:

- 64 nested type edges
- 256 public-impact paths
- 10,000 traversal steps

If a limit stops the analysis, finding `RES001` blocks the upgrade.

## OpenZeppelin compatibility

[OpenZeppelin Stellar Contracts](https://docs.openzeppelin.com/stellar-contracts/utils/upgradeable) provides on-chain upgrade components and migration patterns.

Soroban Upgrades checks a compiled release before signer approval. It does not replace the OpenZeppelin components.

The review-plan command requires this compatible signature:

```text
upgrade(new_wasm_hash: BytesN<32>, operator: Address)
```

Read the [adoption guide](ADOPTION.md) for the required contract evidence.

## CAP-0086

[CAP-0086](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0086.md) adds sparse Symbol-keyed map functions in protocol 28.

Sparse decoding can support some optional-field changes. It does not make field renames, type changes, or required-field changes safe.

The checker examines compiled imports and reachable calls. It reports per-type reader binding as unknown without stronger evidence.

The [runtime witness](../experiments/cap0086-runtime/README.md) covers safe and unsafe reader and writer directions with host version 28.0.1.

## Security boundary

The checker cannot prove business logic, authorization safety, ledger coverage, migration completion, deployed-caller compatibility, or rollback safety.

Read [SECURITY.md](../SECURITY.md) for the complete security boundary and vulnerability-reporting process.
