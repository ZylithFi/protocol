#!/usr/bin/env bash
# differential vectors for the exchange statements: the rust reference (`zylith_core::exchange`)
# builds every scenario, the cairo transition statement must output the same commitment, and
# every tampered witness must be rejected.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${EXCHANGE_VECTORS_DIR:-${root_dir}/target/exchange-vectors}"
rm -rf "${out_dir}"
mkdir -p "${out_dir}"

RUSTC="$(rustup which --toolchain nightly-2026-01-15 rustc)" \
  CARGO_TARGET_DIR="${root_dir}/target/bench-native-compact" \
  cargo run --quiet --release -p zylith-core --manifest-path "${root_dir}/Cargo.toml" \
  --example exchange_vectors -- "${out_dir}"
scarb --manifest-path "${root_dir}/stwo_statement/Scarb.toml" build > /dev/null

failures=0
for input in "${out_dir}"/*.json; do
  name="$(basename "${input}" .json)"
  [[ "${name}" == "expectations" ]] && continue
  expect="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]['expect'])" "${out_dir}/expectations.json" "${name}")"
  executable="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]['executable'])" "${out_dir}/expectations.json" "${name}")"
  if output="$(scarb --manifest-path "${root_dir}/stwo_statement/Scarb.toml" execute \
      -p zylith_exchange_statement --executable-name "${executable}" --layout all_cairo \
      --arguments-file "${input}" --print-program-output --print-resource-usage 2>&1)"; then
    result=accept
  else
    result=reject
  fi
  steps="$(printf '%s\n' "${output}" | grep -Eo 'steps: [0-9,]+' | head -1 || true)"
  detail="$(printf '%s\n' "${output}" | grep -Eo "'[A-Z_]+'" | head -1 || true)"
  if [[ "${result}" == "accept" ]]; then
    # cairo prints felts above half the field as negative integers.
    produced="$(printf '%s\n' "${output}" | awk '/Program output:/{getline; print; exit}' | tr -d '[:space:]' \
      | python3 -c "import sys; print(int(sys.stdin.read()) % (2**251 + 17 * 2**192 + 1))")"
    expected="$(python3 -c "import json,sys; print(int(json.load(open(sys.argv[1]))[sys.argv[2]]['commitment'],16))" "${out_dir}/expectations.json" "${name}")"
    if [[ "${produced}" != "${expected}" ]]; then
      result=mismatch
    fi
    # the operator budgets transitions with its step estimate, which must bound the real count.
    max_steps="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]].get('max_steps', ''))" "${out_dir}/expectations.json" "${name}")"
    measured="$(printf '%s' "${steps}" | tr -dc '0-9')"
    if [[ -n "${max_steps}" && -n "${measured}" && "${measured}" -gt "${max_steps}" ]]; then
      result="over-estimate(${measured}>${max_steps})"
    fi
    steps="${steps} (estimate ${max_steps:-n/a})"
  fi
  if [[ "${result}" == "${expect}" ]]; then
    printf 'ok    %-28s %-7s %s %s\n' "${name}" "${result}" "${steps}" "${detail}"
  else
    printf 'FAIL  %-28s expected %s, got %s %s\n' "${name}" "${expect}" "${result}" "${detail}"
    failures=$((failures + 1))
  fi
done
exit "${failures}"
