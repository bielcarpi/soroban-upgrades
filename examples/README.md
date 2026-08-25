# Upgrade scenarios

These scenarios turn the compatibility model into checker results.

The showcase rebuilds every contract fixture. Each result comes from compiled WASM instead of stored output.

Run the complete sequence from the repository root:

```sh
./scripts/showcase.sh
```

If a live Testnet protocol read is unavailable, use `./scripts/showcase.sh --offline`.

The offline mode records its protocol value as an assertion rather than network evidence.

## Six scenarios, six outcomes

| Scenario | Artifacts or evidence | What changes | Expected outcome |
| --- | --- | --- | --- |
| [Compatible migration](#1-compatible-migration) | `counter-v1` to `counter-v2` | Version increases, public API remains compatible, storage evolution and migration are declared | `PASS` |
| [Unsafe replacement](#2-unsafe-replacement) | `counter-v1` to `counter-unsafe` | Public ABI, storage history, version, and upgrade entrypoint break together | `BLOCKED` |
| [False CAP-0086 claim](#3-false-cap-0086-claim) | `cap86-v1` to `cap86-v2` | An optional field is added, but the compiled candidate lacks sparse decoding | `BLOCKED` |
| [Protocol 28 matrix](#4-protocol-28-reader-and-writer-matrix) | Guest and host witness | Dense and sparse directions | `PROVED` with limits |
| [Semantic break under protocol 28](#5-semantic-break-under-protocol-28) | `cap86-v2` to `cap86-unsafe` | A field is renamed, retyped, and made required | `BLOCKED` |
| [Content-addressed release plan](#6-content-addressed-release-plan) | Safe counter pair and release evidence | A deterministic plan binds the reviewed inputs | `VERIFIED` |

## 1. Compatible migration

The candidate keeps the upgrade entrypoint and existing functions. It increases SEP-49 `binver`, adds behavior, and declares storage changes.

The validator accepts the release. It keeps constructor, migration, and authorization limits visible as warnings or unknown evidence.

Fixtures: [`counter-v1`](counter-v1/) and [`counter-v2`](counter-v2/).

## 2. Unsafe replacement

The candidate combines several hazards. These include interface breaks, storage breaks, missing history, a non-increasing version, and loss of future upgrades.

The checker must return status `2`.

Fixtures: [`counter-v1`](counter-v1/) and [`counter-unsafe`](counter-unsafe/).

## 3. False CAP-0086 claim

The source change adds an optional field, and the policy asserts protocol 28. This evidence is not sufficient.

The compiled SDK 27 candidate does not import CAP-0086 sparse decoding. The validator therefore blocks the release.

The report traces the changed `Account` type to the retained `account()` output.

Fixtures: [`cap86-v1`](cap86-v1/) and [`cap86-v2`](cap86-v2/).

## 4. Protocol-28 reader and writer matrix

The independent witness executes the actual dense and sparse host behavior.

A new sparse reader can consume old dense data with a missing optional field.

An old dense reader accepts a sparse writer while the new value stays absent. The reader traps after the value becomes present.

Evidence: [Protocol-28 runtime witness](../experiments/cap0086-runtime/README.md).

## 5. Semantic break under protocol 28

Sparse decoding does not make every schema mutation safe.

The unsafe candidate renames and retypes historical data. It also changes an optional field into a required field.

The validator blocks those breaks under an asserted protocol 28.

Fixtures: [`cap86-v2`](cap86-v2/) and [`cap86-unsafe`](cap86-unsafe/).

## 6. Content-addressed review plan

The safe pair creates a deterministic plan for upload, simulation, upgrade, migration, executable verification, and application invariants.

`verify-plan` reconstructs the validation-derived content before it checks the digest.

The plan does not contain a key, signature, or approval identity. The previous WASM hash is only a rollback candidate.

Generated artifact: `target/showcase-upgrade-plan.json`.

## Evidence boundary

The scenarios show what the gate observes or enforces from compiled artifacts, reviewed declarations, protocol evidence, and an independent runtime witness.

They do not prove the complete caller graph, every historical ledger entry, business invariants, or signer authorization.

Reports classify those limits as facts, inferences, or unknowns. They do not convert missing evidence into approval.
