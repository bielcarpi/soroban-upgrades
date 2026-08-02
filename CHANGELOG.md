# Changelog

All notable public changes to Soroban Upgrades are recorded here. The project follows semantic versioning once stable interfaces are published; alpha report and plan formats may still change.

## 0.1.0-alpha.1 (2026-08-06)

First public MVP evidence release.

### Included

- Rust validation core and native CLI for `inspect`, `validate`, `plan`, and `verify-plan`.
- Compiled-WASM identity, Contract Spec and metadata comparison, nested public-impact paths, retained upgrade-path checks, and SEP-49 `binver` rules.
- Version-controlled storage schemas, cumulative history, migration declarations, retired-name controls, and strict bounded JSON decoding.
- Protocol-aware CAP-0086 checks that distinguish network activation, artifact imports, direct per-export reachability, and unresolved per-type binding.
- Independent guest/host 28.0.1 runtime witness with five reader/writer directions, eight adversarial mutation tests, and two byte-identical clean guest builds.
- Canonical non-signing upgrade plans bound to artifacts, policies, network evidence, contract identity, migrations, rollback, and invariants.
- Six real Soroban contract fixtures, 45 main tests, a one-command showcase, hosted CI, threat model, security baseline, and a verified Testnet upgrade receipt.

### Known limits

- Unaudited alpha MVP; it does not replace testing, formal verification, or professional review.
- The core never holds keys, signs, uploads, invokes, or submits transactions.
- Ledger-snapshot rehearsal, generalized dependency sequencing, stable CI distribution, and monitoring are planned work.
- Per-type CAP-0086 reader binding, deployed caller graphs, and ledger-wide migration completion remain explicit unknowns unless external evidence supplies them.
