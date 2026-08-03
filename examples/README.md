# Upgrade scenarios

These scenarios turn the compatibility model into concrete release decisions. The showcase rebuilds every contract fixture before running them, so the results come from the compiled WASM rather than checked-in output.

Run the complete sequence from the repository root:

```sh
./scripts/showcase.sh
```

Use `./scripts/showcase.sh --offline` when a live Testnet protocol read is unavailable. The offline mode records its protocol value as an assertion rather than network evidence.

## Six scenarios, six outcomes

| Scenario | Artifacts or evidence | What changes | Expected outcome |
| --- | --- | --- | --- |
| [Compatible migration](#1-compatible-migration) | `counter-v1` to `counter-v2` | Version increases, public API remains compatible, storage evolution and migration are declared | `PASS` |
| [Unsafe replacement](#2-unsafe-replacement) | `counter-v1` to `counter-unsafe` | Public ABI, storage history, version, and upgrade entrypoint break together | `BLOCKED` |
| [False CAP-0086 claim](#3-false-cap-0086-claim) | `cap86-v1` to `cap86-v2` | An optional field is added, but the compiled candidate lacks sparse decoding | `BLOCKED` |
| [Protocol-28 reader and writer matrix](#4-protocol-28-reader-and-writer-matrix) | Independent guest and host witness | Dense and sparse readers and writers are executed in both safe and unsafe directions | `PROVED` with direction-specific limits |
| [Semantic break under protocol 28](#5-semantic-break-under-protocol-28) | `cap86-v2` to `cap86-unsafe` | A field is renamed, retyped, and made required | `BLOCKED` |
| [Content-addressed release plan](#6-content-addressed-release-plan) | Safe counter pair plus policy, history, network, and migration inputs | The reviewed inputs are bound into a deterministic non-signing plan | `VERIFIED` |

## 1. Compatible migration

The candidate retains the upgrade entrypoint, increases the SEP-49 `binver`, preserves existing functions, adds new behavior, and declares how storage evolves. The validator accepts the release while keeping constructor, migration-completion, and authorization limits visible as warnings or unknown evidence.

Fixtures: [`counter-v1`](counter-v1/) and [`counter-v2`](counter-v2/).

## 2. Unsafe replacement

The candidate intentionally combines several hazards: removed or changed public interfaces, incompatible storage declarations, missing historical continuity, a non-increasing version, and loss of the future upgrade path. A release gate should not merely describe these changes. It must return a failing process status.

Fixtures: [`counter-v1`](counter-v1/) and [`counter-unsafe`](counter-unsafe/).

## 3. False CAP-0086 claim

The source-level change adds an optional field and the policy asserts protocol 28. That alone is not sufficient. The compiled SDK-27 candidate does not import CAP-0086 sparse decoding, so the validator blocks the release and traces the changed `Account` type to the retained `account()` output.

Fixtures: [`cap86-v1`](cap86-v1/) and [`cap86-v2`](cap86-v2/).

## 4. Protocol-28 reader and writer matrix

The independent witness executes the actual dense and sparse host behavior. It proves that a new sparse reader can consume old dense data with a missing optional field. It also proves that an old dense reader accepts a sparse writer only while the new value is omitted, then traps once that value is present.

Evidence: [Protocol-28 runtime witness](../experiments/cap0086-runtime/README.md).

## 5. Semantic break under protocol 28

Sparse decoding does not make every schema mutation safe. The unsafe candidate renames and retypes historical data and changes an optional field into a required field. The validator blocks those semantic and lifecycle breaks even when protocol 28 is asserted.

Fixtures: [`cap86-v2`](cap86-v2/) and [`cap86-unsafe`](cap86-unsafe/).

## 6. Content-addressed release plan

The safe pair is converted into a deterministic plan covering upload, simulation, authorization, upgrade, migration, executable verification, invariants, and rollback. `verify-plan` reconstructs the validation-derived content before checking its digest. The plan does not contain a key, signature, or approval identity.

Generated artifact: `target/showcase-upgrade-plan.json`.

## Evidence boundary

The scenarios demonstrate what the MVP can observe or enforce from compiled artifacts, version-controlled declarations, protocol evidence, and an independent runtime witness. They do not prove a complete deployed caller graph, migration of every historical ledger entry, application-specific business invariants, or signer authorization. Reports classify those boundaries as facts, declarations, inferences, or unknowns rather than turning missing evidence into approval.
