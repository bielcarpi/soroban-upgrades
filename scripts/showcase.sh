#!/usr/bin/env bash
set -euo pipefail

task_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${task_root}"

task_mode="live"
case "${1:-}" in
  "") ;;
  --offline) task_mode="offline" ;;
  -h|--help)
    echo "Usage: ./scripts/showcase.sh [--offline]"
    echo ""
    echo "Default: read the current Testnet protocol with Stellar CLI."
    echo "--offline: use a recorded protocol-27 assertion for the safe fixture."
    exit 0
    ;;
  *)
    echo "Unknown option: $1" >&2
    exit 2
    ;;
esac

if ! command -v cargo >/dev/null 2>&1; then
  if ! command -v rustup >/dev/null 2>&1; then
    echo "Rust is required: install rustup and Rust 1.93+" >&2
    exit 1
  fi
  task_toolchain_bin="$(dirname "$(rustup which cargo)")"
  export PATH="${task_toolchain_bin}:${PATH}"
fi

if ! command -v stellar >/dev/null 2>&1; then
  echo "Stellar CLI is required: https://developers.stellar.org/docs/tools/cli" >&2
  exit 1
fi

task_tmp="$(mktemp -d)"
trap 'rm -rf "${task_tmp}"' EXIT

task_cli="target/debug/soroban-upgrades"
task_packages=(counter-v1 counter-v2 counter-unsafe cap86-v1 cap86-v2 cap86-unsafe)

print_compact_result() {
  sed -n -E '/^(PASS|BLOCKED|  errors:|  warnings:|  artifact:|  CAP-0086)/p' "$1"
}

run_expected_block() {
  local task_name="$1"
  shift
  local task_log="${task_tmp}/${task_name}.log"
  if "$@" >"${task_log}" 2>&1; then
    cat "${task_log}" >&2
    echo "Expected ${task_name} to be blocked, but it passed." >&2
    exit 1
  fi
  print_compact_result "${task_log}"
}

echo "Soroban Upgrades — executable upgrade-safety proof"
echo ""
echo "[1/6] Build the CLI, run the engine tests, compile six contract fixtures"
cargo build --quiet --package soroban-upgrades-cli
if ! cargo test --workspace >"${task_tmp}/tests.log" 2>&1; then
  cat "${task_tmp}/tests.log" >&2
  exit 1
fi
task_test_count="$(awk '/test result: ok\./ { for (i = 1; i <= NF; i++) if ($i == "passed;") total += $(i - 1) } END { print total + 0 }' "${task_tmp}/tests.log")"

for task_package in "${task_packages[@]}"; do
  if ! stellar contract build --package "${task_package}" >>"${task_tmp}/build.log" 2>&1; then
    cat "${task_tmp}/build.log" >&2
    exit 1
  fi
done
echo "PASS ${task_test_count} tests; 6 compiled WASM fixtures"

echo ""
echo "[2/6] Accept a compatible v1 -> v2 migration"
task_safe_log="${task_tmp}/safe.log"
task_network_args=(--network testnet)
if [[ "${task_mode}" == "offline" ]]; then
  task_network_args+=(--protocol-version 27)
fi
if ! "${task_cli}" validate \
  --from target/wasm32v1-none/release/counter_v1.wasm \
  --to target/wasm32v1-none/release/counter_v2.wasm \
  --from-schema examples/schemas/counter-v1.schema.json \
  --to-schema examples/schemas/counter-v2.schema.json \
  --schema-history examples/schemas/counter-history.json \
  --policy examples/policies/default.json \
  "${task_network_args[@]}" \
  --compact >"${task_safe_log}" 2>&1; then
  cat "${task_safe_log}" >&2
  exit 1
fi
print_compact_result "${task_safe_log}"

echo ""
echo "[3/6] Reject an ABI, storage, version, and upgrade-path break"
run_expected_block "unsafe-upgrade" "${task_cli}" validate \
  --from target/wasm32v1-none/release/counter_v1.wasm \
  --to target/wasm32v1-none/release/counter_unsafe.wasm \
  --from-schema examples/schemas/counter-v1.schema.json \
  --to-schema examples/schemas/counter-unsafe.schema.json \
  --schema-history examples/schemas/counter-history.json \
  --network testnet \
  --protocol-version 27 \
  --compact

echo ""
echo "[4/6] Refuse a false CAP-0086 claim"
echo "      Protocol 28 is asserted; the candidate still lacks sparse decoding."
run_expected_block "cap-0086-gate" "${task_cli}" validate \
  --from target/wasm32v1-none/release/cap86_v1.wasm \
  --to target/wasm32v1-none/release/cap86_v2.wasm \
  --from-schema examples/schemas/cap86-v1.schema.json \
  --to-schema examples/schemas/cap86-v2.schema.json \
  --schema-history examples/schemas/cap86-history.json \
  --network testnet \
  --protocol-version 28 \
  --compact

echo ""
echo "[5/6] Reject semantic schema breaks even under protocol 28"
echo "      Sparse decoding cannot make a rename, retype, or required field safe."
run_expected_block "cap-0086-semantic-break" "${task_cli}" validate \
  --from target/wasm32v1-none/release/cap86_v2.wasm \
  --to target/wasm32v1-none/release/cap86_unsafe.wasm \
  --from-schema examples/schemas/cap86-v2.schema.json \
  --to-schema examples/schemas/cap86-unsafe.schema.json \
  --schema-history examples/schemas/cap86-history.json \
  --network testnet \
  --protocol-version 28 \
  --compact

echo ""
echo "[6/6] Create and verify a canonical, non-signing release plan"
task_plan="target/showcase-upgrade-plan.json"
"${task_cli}" plan \
  --from target/wasm32v1-none/release/counter_v1.wasm \
  --to target/wasm32v1-none/release/counter_v2.wasm \
  --from-schema examples/schemas/counter-v1.schema.json \
  --to-schema examples/schemas/counter-v2.schema.json \
  --schema-history examples/schemas/counter-history.json \
  --policy examples/policies/default.json \
  --network testnet \
  --protocol-version 27 \
  --contract-id CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4 \
  --source-identity deployer \
  --migration-entrypoint migrate \
  --out "${task_plan}"
"${task_cli}" verify-plan --plan "${task_plan}"

echo ""
echo "Historical Testnet receipt"
echo "  contract: CAVRSELEZ6PAWEXGHPGNQ3VHI4LDT5QUA5MZWSMXYQLE7HACO6G3TUMJ"
echo "  tx:       f7584b5c2c753ffcba2ccd60691714893e86a9c52a80e00d2ef3e9a39c25ccda"
echo "  result:   state survived; v2 code and migrations verified"
echo ""
echo "SHOWCASE PASS — read-only analysis; no keys, signatures, uploads, or transactions."
