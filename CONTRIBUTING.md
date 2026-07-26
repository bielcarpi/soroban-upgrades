# Contributing

The most useful early contributions are real, minimized upgrade fixtures and review of rule semantics.

Before opening a change:

1. do not submit private contract code, keys, or customer data;
2. state whether the fixture is safe, unsafe, or intentionally ambiguous and why;
3. include a regression test for every rule change;
4. document false-positive and backward-compatibility impact;
5. run the complete local gate.

```sh
./scripts/verify-mvp.sh
```

Compatibility checks should fail closed on unsupported artifacts, protocols, and host capabilities, but warnings and errors must remain actionable. CAP-0086 rule changes need fixtures for protocol activation, actual sparse imports, historical field lifecycle, and cross-contract direction where relevant. There is no unrecorded global force flag: an approved exception belongs in a version-controlled policy and evidence bundle.

For a crates.io release, package and publish `soroban-upgrades-core` first. Only package and publish `soroban-upgrades-cli` after that exact core version is available in the registry; local source installation resolves the workspace path directly.
