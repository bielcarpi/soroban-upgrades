# Contributing

Real upgrade fixtures, parser hardening, and clear rule semantics provide the most value.

## Before you open a change

1. Do not submit private contract code, keys, customer data, or active exploit details.
2. State whether each fixture is safe, unsafe, or intentionally uncertain.
3. Explain the expected finding codes.
4. Add a regression test for every rule change.
5. Describe false positive and compatibility effects.
6. Run the complete release gate.

```sh
./scripts/verify-release.sh
```

## Rule design

Block unsupported artifacts, protocols, and host capabilities. Keep every error and warning actionable.

Do not convert missing evidence into approval. Use `FACT`, `INFERENCE`, and `UNKNOWN` consistently.

CAP-0086 changes need protocol, import, reachability, history, and cross-contract direction fixtures.

There is no unrecorded global bypass. Put an approved exception in a reviewed policy and evidence bundle.

## Documentation

Use short sentences and direct terms. Keep commands, option names, finding codes, and JSON field names exact.

Document verified behavior and explicit limits. Do not claim Mainnet safety from test evidence.

## Pull requests

Keep each change focused. Include the problem, release effect, evidence, tests, and remaining limits.

CI runs the full release gate on Linux. It also tests the library and CLI on Linux, macOS, and Windows.

## Package order

Publish `soroban-upgrades-core` before `soroban-upgrades-cli` for a future crates.io release.

Wait until that exact core version exists in the registry. Then package and publish the CLI.

Published distributions use attested GitHub release binaries.
