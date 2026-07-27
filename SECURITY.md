# Security policy

Soroban Upgrades is an unaudited MVP. It cannot prove that a contract is secure and does not replace application-specific review, testing, formal verification, or a professional audit.

## Reporting a vulnerability

Until a dedicated private reporting address is published, do not include secrets, exploitable Mainnet details, private WASM, or customer data in a public issue. Contact the maintainers through the repository owner's verified private channel and request a disclosure path.

The production release will publish a security address, supported-version table, response targets, coordinated-disclosure process, and signed release provenance.

## Trust boundary

The default validator is read-only. It accepts untrusted WASM and JSON, emits findings and plans, and must not request a signing key or submit a transaction. Execution adapters remain separate and must re-verify hashes, network, current executable, policy approvals, and simulation/invariant results before invoking an existing signer.

Critical rule bypasses, parser denial of service, artifact substitution, plan/source mismatch, false-safe classification for a documented critical hazard, and secret exposure are security issues.
