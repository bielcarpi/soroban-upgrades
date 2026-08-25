# Independent CAP-0086 Protocol-28 runtime witness

This experiment tests the compatibility directions behind the conservative CAP-0086 policy.

It uses `soroban-env-host` and `soroban-env-guest` 28.0.1 at ledger protocol 28.

The implementation uses public Stellar environment APIs and CAP-0086.

It does not copy source or artifacts from the private prototype that motivated the evidence standard.

## Reproduce

```sh
./scripts/verify-cap0086-runtime.sh
```

The script performs two clean guest builds and requires byte-identical WASM.

It verifies ordered imports and direct call reachability for each export. It rejects dynamic dispatch before it executes the protocol 28 matrix.

Eight adversarial tests cover extra, missing, duplicate, and reordered imports. They also cover swapped calls, dynamic dispatch, and hardcoded results.

## Expected matrix

| Writer | Reader | New field | Result |
| --- | --- | --- | --- |
| Dense V1 `{owner,value}` | Sparse V2 `{extra,owner,value}` | Missing | `extra = Void`. Old data remains readable. |
| Dense V1 | Dense V2 | Missing | Traps because dense decoding requires an exact shape |
| Sparse V2 | Dense V1 | `Void`/omitted | Old reader succeeds because the writer emits the old shape |
| Sparse V2 | Dense V1 | Present | Old reader traps on the additional key |
| Sparse V2 | Sparse V2 | Present | New reader receives all three values |
| Dense V1 | Sparse V2 | Missing, guest run under protocol 27 | Rejected because the guest requires protocol 28 |

## Evidence boundary

### FACT

- The exact guest exports reach the expected dense/sparse reader or writer imports through direct calls only.
- The witness rejects missing, extra, duplicate, or reordered imports and call-graph shortcuts.
- Two clean release builds are byte-identical.
- The five protocol-28 reader/writer cases produce the matrix above.
- The protocol-28 guest is rejected when invoked at protocol 27.

### INFERENCE

An optional-field rollout can preserve an old dense reader while the sparse writer omits the new field.

The old dense reader becomes incompatible after the new value becomes present. Rollout order and write policy therefore matter.

### UNKNOWN

- Whether a particular SDK-generated contract type uses sparse decoding.
- Persisted historical ledger behavior outside this in-memory witness.
- The complete deployed reader and writer graph.
- Public network activation at any later date.
- Application-specific rename, retype, required-field, or migration semantics.

This witness narrows one protocol question. It is not a general compatibility guarantee.
