# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 1.x | Yes |
| 0.1 prereleases | No |

Upgrade to the latest 1.x release before you report behavior from an older version.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/bielcarpi/soroban-upgrades/security/advisories/new).

Do not create a public issue for an unpatched vulnerability. Do not include private WASM, keys, customer data, or active Mainnet exploit details.

Include these items in the private report:

- affected version and platform
- exact command or API path
- minimal safe reproduction
- expected and observed result
- security impact
- proposed fix, when available

We target an initial response within three business days. We target an impact assessment within seven business days.

Response time depends on reproduction quality and release risk. We coordinate disclosure after a fix is available to supported users.

## Security boundary

The CLI is read-only. It accepts untrusted WASM and JSON, then writes reports and review plans.

The CLI does not request a signing key. It does not sign, upload, invoke, or submit a transaction.

The following defects are security issues:

- a false `PASS` for a documented blocking hazard
- a parser crash or practical denial of service within documented limits
- acceptance of malformed or substituted release evidence
- a plan digest or canonical command bypass
- a source, target, network, or current executable mismatch bypass
- private key exposure in a report or plan
- release artifact or workflow provenance compromise

## Known proof limits

Soroban Upgrades is not a contract audit. It does not prove application business logic or complete authorization safety.

WASM does not contain a complete ledger storage inventory. Storage declarations and history remain reviewed project evidence.

Static call analysis does not prove every dynamic call target. Reports mark unresolved CAP-0086 reader binding as unknown.

The gate does not prove migration completion. It also does not prove that every deployed caller can decode a changed public type.

The previous WASM hash does not prove rollback safety after storage changes.

## Release supply chain

Release builds run on GitHub-hosted platform runners. The workflow pins every external action to a full commit SHA.

The workflow verifies the `dist` installer checksum before execution. GitHub creates provenance attestations for each platform archive.

Verify an archive before you use it in an approval system:

```sh
gh attestation verify <archive> --repo bielcarpi/soroban-upgrades
```

Checksums detect download corruption. Provenance attestations bind an archive to the public release workflow and repository.

## Dependency exception

The release gate ignores advisory `RUSTSEC-2024-0436` for `paste` 1.0.15. This crate is an unmaintained fixture dependency from the Soroban host stack.

The distributed CLI does not include `paste`. The audit gate denies every other vulnerability, unmaintained crate, unsound crate, and yanked crate warning.
