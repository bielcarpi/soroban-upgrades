# Independent CAP-0086 Protocol-28 runtime witness

This experiment tests the compatibility directions behind the MVP's conservative CAP-0086 policy against `soroban-env-host` and `soroban-env-guest` 28.0.1 at ledger protocol 28.

It was independently implemented from public Stellar environment APIs and CAP-0086. It does not copy source or artifacts from the private comparison prototype that motivated the stricter evidence standard.

## Reproduce

```sh
./scripts/verify-cap0086-runtime.sh
```

The script performs two clean release builds of the guest, requires byte-identical WASM, verifies the exact ordered function-import contract and per-export direct-call reachability, rejects dynamic dispatch, and executes the matrix in a protocol-28 host. Eight adversarial runner tests prove that the witness fails closed on an extra manual-lookup import, a missing or duplicate sparse import, reordered imports, a swapped call target, dynamic dispatch, or a hardcoded-result shortcut.

## Expected matrix

| Writer | Reader | New field | Result |
| --- | --- | --- | --- |
| Dense V1 `{owner,value}` | Sparse V2 `{extra,owner,value}` | Missing | `extra = Void`; old data remains readable |
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

An optional-field rollout can preserve an old dense reader while the sparse writer omits the new field. Once the new value is present, the old dense reader is incompatible; rollout order and write policy therefore matter.

### UNKNOWN

- whether a particular SDK-generated contract type uses sparse decoding;
- persisted historical ledger-state behavior outside this in-memory witness;
- the complete deployed reader/writer graph;
- public-network activation at any later date;
- application-specific rename, retype, required-field, or migration semantics.

This witness narrows one protocol question. It is not a general compatibility guarantee.
