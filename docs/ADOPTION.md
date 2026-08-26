# Adoption guide

Use this guide to add Soroban Upgrades before signer review. The checker does not deploy contracts or execute its plans.

## 1. Prepare the contract

Keep an authorized upgrade entrypoint in every upgradeable target. The planner requires the OpenZeppelin-compatible argument names and types.

The compiled source and target exports must reach Stellar `update_current_contract_wasm` directly.

The public Contract Spec must contain:

```text
upgrade(new_wasm_hash: BytesN<32>, operator: Address)
```

Store a semantic version in SEP-49 `binver` metadata. Increase that version for every candidate release.

Do not depend on `__constructor` during replacement. Soroban does not run the constructor after an executable update.

Put upgrade initialization in an idempotent migration. The migration must reject an unauthorized operator.

## 2. Declare all storage

Copy [the storage example](../examples/schemas/counter-v1.schema.json) for each released contract version.

List every storage key that the contract reads or writes. Include instance, persistent, and temporary entries.

Set `complete` to `true` only after a code review covers all storage access paths.

Each declaration links to the contract semantic version:

```json
{
  "formatVersion": 1,
  "complete": true,
  "schemaVersion": 2,
  "contractVersion": "2.0.0",
  "entries": []
}
```

Describe every changed entry with migration data. The declaration must name an exported migration entrypoint.

The tool verifies declaration consistency. It does not read every ledger entry.

## 3. Keep cumulative field history

Copy [the history example](../examples/schemas/counter-history.json). Keep one cumulative file for the full upgrade chain.

Record each public field name, exact type, and first release. Record the retirement release after field removal.

Keep every retired name in `reservedFields`. Never reuse a retired name for a different meaning.

Do not remove old history after ledger expiration assumptions. Archived or restored state can still require the old layout.

Set `complete` to `true` only after the file covers all released public types.

## 4. Select a policy

Start with [the default policy](../examples/policies/default.json). The built-in default has the same release-blocking settings.

Keep the policy in the contract repository. Review policy changes like source changes.

There is no global bypass flag. A permitted compatibility change belongs in a reviewed policy version or a new major tool version.

## 5. Add CI checks

Build both artifacts before validation. Use the same release toolchain for the candidate that you use for upload.

```yaml
- uses: bielcarpi/soroban-upgrades@v1.0.7
  with:
    from: artifacts/deployed.wasm
    to: artifacts/candidate.wasm
    from-schema: upgrade/deployed.schema.json
    to-schema: upgrade/candidate.schema.json
    schema-history: upgrade/schema-history.json
    policy: upgrade/policy.json
    network: testnet
    report: artifacts/soroban-upgrade-report.json
```

Keep the JSON report with the build evidence. Also keep both artifact hashes and the candidate toolchain version.

Use a full action tag or commit SHA. Do not use a moving branch for approval checks.

## 6. Prepare a live review plan

Fetch the deployed WASM before planning. Compare its hash with the source artifact in your release workspace.

Create an invariant program for the application. The program must verify state and behavior after migration.

Useful invariant checks include:

- contract version and schema version
- administrator and role state
- representative reads from old storage
- new function behavior
- token balances and accounting totals
- paused state and authorization failures
- repeated migration behavior

Create the live plan with the real network, contract, signer alias, migration arguments, and invariant program.

Run `verify-plan` immediately before signer review. Create a new plan after any live evidence change.

## 7. Review the result

Review each finding, command, and expected result. Do not send the plan command text to an automatic shell.

The checker result is one input to signer review. It is not deployment approval.

Before signer review, make sure that these checker conditions are true:

- The CI report has status `0`.
- A reviewer resolved each warning and unknown evidence item.
- The deployed executable matches the plan source hash.
- The candidate archive and CLI archive have valid provenance.
- The live plan has `review_ready` status.
- The plan still matches every local file and live-network input.

Your deployment process must separately cover signer authorization, transaction simulation, migration behavior, application invariants, and rollback safety.
