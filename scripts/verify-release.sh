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
  set +e
  "$@" >"${task_log}" 2>&1
  local task_status=$?
  set -e
  if [[ ${task_status} -eq 0 ]]; then
    cat "${task_log}" >&2
    echo "${task_name} unexpectedly passed" >&2
    exit 1
  fi
  if [[ ${task_status} -ne 2 ]]; then
    cat "${task_log}" >&2
    echo "${task_name} returned ${task_status}. Expected blocked status 2." >&2
    exit 1
  fi
  if ! grep --quiet '^BLOCKED ' "${task_log}"; then
    cat "${task_log}" >&2
    echo "${task_name} failed without a structured blocked verdict" >&2
    exit 1
  fi
  sed -n -E '/^(BLOCKED|  errors:|  warnings:|  artifact:|  CAP-0086)/p' "${task_log}"
}

actionlint
if grep --recursive --line-number --extended-regexp \
  'uses: [^@]+@(main|master|v[0-9])' .github/workflows; then
  echo "A workflow action is not pinned to a full commit SHA" >&2
  exit 1
fi

cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps

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
  --migration-arg operator=deployer \
  --invariant-program cargo \
  --invariant-arg test \
  --invariant-arg=--workspace \
  --out target/release-upgrade-plan.json \
  --force

cargo run --quiet --package soroban-upgrades-cli -- verify-plan \
  --plan target/release-upgrade-plan.json \
  --offline

./scripts/verify-cap0086-runtime.sh

cargo package --locked --allow-dirty --package soroban-upgrades-core
# `paste` is an unmaintained build-only dependency in the Soroban fixture stack.
# It is not part of the distributed CLI dependency graph.
cargo audit --deny warnings --ignore RUSTSEC-2024-0436

echo "Release verification passed: safe upgrade accepted, unsafe changes rejected, runtime directions witnessed, and release evidence verified."
