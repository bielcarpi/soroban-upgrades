# Installation

Soroban Upgrades provides source installation and prebuilt binaries for each stable release.

## Install from crates.io

This method needs Rust 1.93 or later.

```sh
cargo install soroban-upgrades-cli --version 1.0.7 --locked
```

Make sure that the installed version matches the selected release:

```sh
soroban-upgrades --version
```

## Install a prebuilt binary

The release installers select the correct archive for the current platform. They do not need a Rust toolchain.

macOS or Linux:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/bielcarpi/soroban-upgrades/releases/download/v1.0.7/soroban-upgrades-cli-installer.sh | sh
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/bielcarpi/soroban-upgrades/releases/download/v1.0.7/soroban-upgrades-cli-installer.ps1 | iex"
```

The release page provides archives for these targets:

- ARM64 macOS
- x64 macOS
- ARM64 GNU/Linux
- x64 GNU/Linux
- x64 Windows with MSVC

## Verify a release archive

For an approval system, download the archive before installation. Then verify its checksum and GitHub provenance attestation.

This example uses Apple Silicon macOS:

```sh
gh release download v1.0.7 \
  --repo bielcarpi/soroban-upgrades \
  --pattern 'soroban-upgrades-cli-aarch64-apple-darwin.tar.xz' \
  --pattern 'soroban-upgrades-cli-aarch64-apple-darwin.tar.xz.sha256'

shasum -a 256 -c \
  soroban-upgrades-cli-aarch64-apple-darwin.tar.xz.sha256

gh attestation verify \
  soroban-upgrades-cli-aarch64-apple-darwin.tar.xz \
  --repo bielcarpi/soroban-upgrades
```

Select the matching archive name for a different platform.

## Install Stellar CLI for live checks

Soroban Upgrades uses Stellar CLI to read network identity, protocol, and deployed contract evidence.

Install a compatible Stellar CLI release from the [official Stellar instructions](https://developers.stellar.org/docs/tools/cli).

Offline checks can use `--protocol-version`. This option records an assertion instead of live network evidence.

## Next step

Run the [quick start](../README.md#quick-start), or read the complete [CLI reference](CLI.md).
