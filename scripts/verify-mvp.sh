#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo >/dev/null 2>&1; then
  task_toolchain_bin="$(dirname "$(rustup which cargo)")"
  export PATH="${task_toolchain_bin}:${PATH}"
fi

task_tmp="$(mktemp -d)"
trap 'rm -rf "${task_tmp}"' EXIT

expect_validation_failure() {
  local task_name="$1"
  shift
  local task_log="${task_tmp}/${task_name}.log"
  if "$@" >"${task_log}" 2>&1; then
    cat "${task_log}" >&2
    echo "${task_name} unexpectedly passed" >&2
    exit 1
  fi
  if ! grep -q '^BLOCKED ' "${task_log}"; then
    cat "${task_log}" >&2
    echo "${task_name} failed without a structured blocked verdict" >&2
    exit 1
  fi
  sed -n -E '/^(BLOCKED|  errors:|  warnings:|  artifact:|  CAP-0086)/p' "${task_log}"
}

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

stellar contract build --package counter-v1
stellar contract build --package counter-v2
stellar contract build --package counter-unsafe
stellar contract build --package cap86-v1
stellar contract build --package cap86-v2
stellar contract build --package cap86-unsafe

cargo run --quiet --package soroban-upgrades-cli -- validate \
  --from target/wasm32v1-none/release/counter_v1.wasm \
  --to target/wasm32v1-none/release/counter_v2.wasm \
  --from-schema examples/schemas/counter-v1.schema.json \
  --to-schema examples/schemas/counter-v2.schema.json \
  --schema-history examples/schemas/counter-history.json \
  --policy examples/policies/default.json \
  --protocol-version 27 \
  --compact

expect_validation_failure "unsafe fixture" cargo run --quiet --package soroban-upgrades-cli -- validate \
  --from target/wasm32v1-none/release/counter_v1.wasm \
  --to target/wasm32v1-none/release/counter_unsafe.wasm \
  --from-schema examples/schemas/counter-v1.schema.json \
  --to-schema examples/schemas/counter-unsafe.schema.json \
  --schema-history examples/schemas/counter-history.json \
  --protocol-version 27 \
  --compact

for task_protocol in 27 28; do
  expect_validation_failure "CAP-0086 fixture protocol ${task_protocol}" cargo run --quiet --package soroban-upgrades-cli -- validate \
    --from target/wasm32v1-none/release/cap86_v1.wasm \
    --to target/wasm32v1-none/release/cap86_v2.wasm \
    --from-schema examples/schemas/cap86-v1.schema.json \
    --to-schema examples/schemas/cap86-v2.schema.json \
    --schema-history examples/schemas/cap86-history.json \
    --protocol-version "${task_protocol}" \
    --compact
done

expect_validation_failure "CAP-0086 semantic-breaking fixture" cargo run --quiet --package soroban-upgrades-cli -- validate \
  --from target/wasm32v1-none/release/cap86_v2.wasm \
  --to target/wasm32v1-none/release/cap86_unsafe.wasm \
  --from-schema examples/schemas/cap86-v2.schema.json \
  --to-schema examples/schemas/cap86-unsafe.schema.json \
  --schema-history examples/schemas/cap86-history.json \
  --protocol-version 28 \
  --compact

cargo run --quiet --package soroban-upgrades-cli -- plan \
  --from target/wasm32v1-none/release/counter_v1.wasm \
  --to target/wasm32v1-none/release/counter_v2.wasm \
  --from-schema examples/schemas/counter-v1.schema.json \
  --to-schema examples/schemas/counter-v2.schema.json \
  --schema-history examples/schemas/counter-history.json \
  --policy examples/policies/default.json \
  --protocol-version 27 \
  --network testnet \
  --contract-id CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4 \
  --source-identity deployer \
  --migration-entrypoint migrate \
  --out target/mvp-upgrade-plan.json

cargo run --quiet --package soroban-upgrades-cli -- verify-plan \
  --plan target/mvp-upgrade-plan.json

./scripts/verify-cap0086-runtime.sh

echo "MVP verification passed: compatible upgrade accepted, unsafe and CAP-0086-gated upgrades rejected, Protocol-28 runtime directions witnessed, and plan digest verified."
