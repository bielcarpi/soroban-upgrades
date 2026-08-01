#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo >/dev/null 2>&1; then
  task_toolchain_bin="$(dirname "$(rustup which cargo)")"
  export PATH="${task_toolchain_bin}:${PATH}"
fi

task_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
task_guest_manifest="${task_root}/experiments/cap0086-runtime/guest/Cargo.toml"
task_runner_manifest="${task_root}/experiments/cap0086-runtime/runner/Cargo.toml"
task_first="$(mktemp -d)"
task_second="$(mktemp -d)"
trap 'rm -rf "${task_first}" "${task_second}"' EXIT

cargo fmt --manifest-path "${task_guest_manifest}" -- --check
cargo fmt --manifest-path "${task_runner_manifest}" -- --check
cargo clippy \
  --locked \
  --manifest-path "${task_guest_manifest}" \
  --target wasm32v1-none \
  -- -D warnings
cargo clippy \
  --locked \
  --manifest-path "${task_runner_manifest}" \
  -- -D warnings
cargo test \
  --locked \
  --manifest-path "${task_runner_manifest}"

CARGO_TARGET_DIR="${task_first}" cargo build \
  --locked \
  --manifest-path "${task_guest_manifest}" \
  --release \
  --target wasm32v1-none
CARGO_TARGET_DIR="${task_second}" cargo build \
  --locked \
  --manifest-path "${task_guest_manifest}" \
  --release \
  --target wasm32v1-none

task_first_wasm="${task_first}/wasm32v1-none/release/cap0086_runtime_guest.wasm"
task_second_wasm="${task_second}/wasm32v1-none/release/cap0086_runtime_guest.wasm"
cmp "${task_first_wasm}" "${task_second_wasm}"

cargo run \
  --quiet \
  --locked \
  --manifest-path "${task_runner_manifest}" \
  -- "${task_first_wasm}"

echo "CAP-0086 runtime witness passed with two byte-identical clean guest builds."
