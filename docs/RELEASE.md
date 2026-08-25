# Release process

This process applies to maintainers of Soroban Upgrades.

## Release requirements

Use Rust 1.93.0, Stellar CLI 27.1.0, `cargo-audit` 0.22.2, `actionlint` 1.7.12, and `dist` 0.32.0.

Keep the repository clean before the final verification. Do not release from an unreviewed worktree.

## Prepare the version

1. Update the workspace version in `Cargo.toml`.
2. Update the matching core dependency version in the CLI manifest.
3. Update `CHANGELOG.md` with the release date and user-visible changes.
4. Update versioned installation examples in the documentation and action.
5. Run `cargo update --workspace` to refresh the lock file.
6. Review the release workflow after any distribution configuration change.

The release workflow contains a checksum patch for the `dist` installer. The `allow-dirty` setting protects that reviewed workflow from generation.

Both crates.io packages restrict publication to the `crates-io` registry. The CLI uses the exact core-library version for each release.

## Verify the candidate

Run the complete release gate:

```sh
./scripts/verify-release.sh
```

Verify the distribution plan:

```sh
dist plan --output-format=json > dist-plan.json
```

Review all target runners and artifact names. Stable releases support these targets:

- ARM64 macOS
- x64 macOS
- ARM64 GNU/Linux
- x64 GNU/Linux
- x64 Windows with MSVC

Validate the workflow files with `actionlint`. Verify that every external action uses a full commit SHA.

## Publish

1. Commit the release changes with the real current date.
2. Push the reviewed main branch.
3. Wait for every required CI job.
4. Create an annotated `vX.Y.Z` tag on the verified commit.
5. Push only that tag.
6. Wait for the Release workflow.

The workflow builds native archives, checksums, shell installers, and PowerShell installers. It also creates GitHub provenance attestations for platform archives.

The workflow creates a draft release and tests its action against compiled fixtures. It publishes the release only after that test passes.

For a stable release, the workflow publishes `soroban-upgrades-core` first. It waits for the registry index before it publishes `soroban-upgrades-cli`.

Both crates use crates.io trusted publishing for `bielcarpi/soroban-upgrades` and `release.yml`. The workflow does not store a crates.io API token.

The crates.io authentication action creates a short-lived token through OpenID Connect. The action revokes this token when the job ends.

The workflow announces the GitHub release only after both crates.io packages are available. A workflow retry skips a version that already exists.

GitHub immutable releases lock the published tag and assets against later changes.

Do not move or reuse a failed public release tag. Fix the problem and use a new patch version.

## Verify the published release

Download each platform archive from the GitHub release. Verify its checksum and attestation.

```sh
gh release download vX.Y.Z \
  --repo bielcarpi/soroban-upgrades \
  --pattern 'soroban-upgrades-cli-aarch64-apple-darwin.tar.xz'
gh attestation verify \
  soroban-upgrades-cli-aarch64-apple-darwin.tar.xz \
  --repo bielcarpi/soroban-upgrades
```

Install from a clean temporary directory. Run these smoke checks:

```sh
soroban-upgrades --version
soroban-upgrades schema plan > plan.schema.json
soroban-upgrades inspect --wasm a-reviewed-fixture.wasm
```

Verify that `--version` equals the release tag. Verify that the generated schema parses as JSON.

Install the CLI from crates.io in a clean temporary directory:

```sh
cargo install soroban-upgrades-cli --version X.Y.Z --locked --root "$INSTALL_ROOT"
"$INSTALL_ROOT/bin/soroban-upgrades" --version
```

Open the public pages for both crates. Make sure that the versions are not yanked and that docs.rs built the core API documentation.

Check the public release notes, asset table, checksums, and source archive. Check the CI and Release workflow results again.

## Repository controls

The main branch requires the release gate and platform tests. GitHub Actions has read-only default permissions outside the release workflow.

The release workflow receives `contents: write` only for release publication. Attestation jobs receive the identity permissions that GitHub requires.

The crates.io job receives `id-token: write` only for trusted publishing. It receives read-only repository contents.

Dependabot checks Cargo and GitHub Actions each week. Private vulnerability reports use GitHub Security Advisories.
