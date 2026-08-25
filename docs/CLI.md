# CLI reference

This reference describes Soroban Upgrades 1.0.3. All JSON input parsers reject unknown fields and duplicate fields.

## Exit status

| Status | Meaning |
| --- | --- |
| `0` | The command completed, and the configured validation gate passed. |
| `1` | An operation failed before the tool produced a release decision. |
| `2` | Validation completed, but one or more blocking findings exist. |

Status `2` is a normal gate result. CI systems must keep it distinct from an operational failure.

## Input limits

The maximum WASM size is 16 MiB. The maximum JSON input size is 8 MiB.

The public impact search stops at these limits:

- 64 nested type edges
- 256 public impact paths
- 10,000 traversal steps

Finding `RES001` blocks the upgrade after a search limit breach.

## `inspect`

Inspect one compiled contract:

```sh
soroban-upgrades inspect --wasm contract.wasm
```

Add `--json` to print the complete artifact model.

The model includes the hash, host interface, metadata, functions, events, public types, imports, and export call evidence.

## `schema`

Print a JSON Schema for a supported file format:

```sh
soroban-upgrades schema policy
soroban-upgrades schema storage
soroban-upgrades schema history
soroban-upgrades schema report
soroban-upgrades schema plan
soroban-upgrades schema artifact
```

Use these schemas in editors and CI validation. The generated schemas match the installed CLI version.

## `validate`

Compare a deployed source artifact with a candidate artifact:

```sh
soroban-upgrades validate \
  --from old.wasm \
  --to new.wasm \
  --from-schema old.schema.json \
  --to-schema new.schema.json \
  --schema-history schema-history.json \
  --policy policy.json \
  --network testnet \
  --json
```

Required inputs:

| Option | Purpose |
| --- | --- |
| `--from` | Exact source WASM that represents the deployed executable |
| `--to` | Exact candidate WASM for upload |
| `--from-schema` | Complete source storage declaration |
| `--to-schema` | Complete target storage declaration |
| `--schema-history` | Complete cumulative public field history |
| `--network` | Live Stellar CLI network evidence |
| `--protocol-version` | Offline protocol assertion that replaces `--network` |

`--network` and `--protocol-version` are mutually exclusive. One of them is required.

The `--policy` option is optional. Without it, the CLI uses the fail-closed default policy.

Output modes:

- The default output explains each finding and its remediation.
- `--compact` prints one short verdict and the finding codes.
- `--json` prints the complete stable report format.

`--compact` and `--json` are mutually exclusive.

## `plan`

Create a deterministic signer review plan:

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
  --invariant-arg testnet \
  --out upgrade.plan.json
```

The `--invariant-program` option is required. Repeat `--invariant-arg` for each structured argument.

Repeat `--migration-arg NAME=VALUE` for each migration argument. Argument names must match the compiled target specification exactly.

The planner verifies the OpenZeppelin-compatible `upgrade` arguments and types. It rejects a target with a different signature.

Without `--protocol-version`, the planner performs two live checks:

1. It reads the selected network identity and protocol.
2. It fetches the current contract and verifies the source hash.

The resulting plan has `review_ready` status.

With `--protocol-version`, the planner skips both live checks. The resulting plan has `offline_draft` status.

The planner refuses an existing output file. Add `--force` only after you intend to replace that exact file.

Plan format 3 contains these bindings:

- complete embedded validation evidence
- paths for every artifact and declaration
- source and target hashes
- network and contract identity
- migration call and named arguments
- operator-supplied invariant check
- canonical upload, simulation, execution, and verification steps
- previous WASM hash as a rollback candidate

The upload step includes `--optimize=false`. Stellar CLI therefore uploads the reviewed bytes without changing them.

The plan never contains a key or signature. It rejects Stellar secret keys in identity, migration, and invariant arguments.

## `verify-plan`

Verify a plan before signer review:

```sh
soroban-upgrades verify-plan --plan upgrade.plan.json
```

The command performs these checks:

1. Parse the plan with strict JSON rules.
2. Recompute the embedded validation report.
3. Rebuild the canonical plan structure.
4. Verify the plan SHA-256 digest.
5. Reparse both local WASM files and compare all embedded artifact evidence.
6. Reload the policy, schemas, and history from their bound paths.
7. Read the live network identity and protocol.
8. Fetch the current contract and verify its executable hash.

Relative input paths resolve from the current directory. Run the command from the same release workspace.

Add `--offline` to skip steps 7 and 8. Offline verification accepts an `offline_draft` plan.

Create a new live plan after any network protocol change. Also create a new plan after any source, target, policy, schema, or history change.

## Finding groups

| Prefix | Surface |
| --- | --- |
| `ABI` | Public functions and nested public types |
| `CAP` | CAP-0086 protocol and compiled capability evidence |
| `ENV` | WASM host interface compatibility |
| `EVT` | Contract event removal or schema changes |
| `HIS` | Cumulative field history |
| `NET` | Network and protocol evidence |
| `POL` | Policy format and policy safety |
| `RES` | Bounded analysis resources |
| `STO` | Storage declarations and migration evidence |
| `UPG` | Constructor and future upgrade path |
| `VER` | Semantic contract version |

Finding codes remain stable within major version 1. New 1.x releases can add codes.

## Evidence labels

Every report separates evidence strength:

- `FACT` comes directly from a parsed artifact or complete live network response.
- `INFERENCE` follows from declared input or bounded static analysis.
- `UNKNOWN` marks a question that needs external evidence.

A `PASS` report can contain warnings and unknown evidence. Review them before approval.
