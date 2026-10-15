#!/usr/bin/env bash
# Reproducible release benchmark for a canonical exchange witness. It records both standalone
# statement evidence and the complete queued SNIP-36 virtual transaction. A run is incomplete if
# the pinned prover adapter omits structured full-SNOS/component resource usage.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scenario="${ZYLITH_BENCHMARK_SCENARIO:-cross_256}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${ZYLITH_BENCHMARK_OUTPUT_DIR:-${root_dir}/target/prover-benchmarks/${timestamp}-${scenario}}"
vectors_dir="${run_dir}/vectors"
layout="${ZYLITH_BENCHMARK_LAYOUT:-all_cairo}"

if [[ -z "${ZYLITH_RELEASE_COMMIT:-}" ]]; then
  echo "ZYLITH_RELEASE_COMMIT is required for the full SNIP-36 release benchmark" >&2
  exit 1
fi
head_commit="$(git -C "${root_dir}" rev-parse HEAD)"
if [[ "${ZYLITH_RELEASE_COMMIT}" != "${head_commit}" ]]; then
  echo "ZYLITH_RELEASE_COMMIT must equal the benchmark source commit ${head_commit}" >&2
  exit 1
fi
if [[ -n "$(git -C "${root_dir}" status --porcelain --untracked-files=normal)" ]]; then
  echo "full SNIP-36 release benchmarks require a clean source tree" >&2
  exit 1
fi

mkdir -p "${vectors_dir}"

RUSTC="$(rustup which --toolchain nightly-2026-01-15 rustc)" \
  CARGO_TARGET_DIR="${root_dir}/target/bench-native-compact" \
  cargo run --quiet --release -p zylith-core --manifest-path "${root_dir}/Cargo.toml" \
  --example exchange_vectors -- "${vectors_dir}"

input_path="${vectors_dir}/${scenario}.json"
expectations_path="${vectors_dir}/expectations.json"
if [[ ! -f "${input_path}" ]]; then
  echo "unknown benchmark scenario: ${scenario}" >&2
  exit 1
fi

executable="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]["executable"])' "${expectations_path}" "${scenario}")"
manifest="${root_dir}/stwo_statement/Scarb.toml"
scarb --manifest-path "${manifest}" build >"${run_dir}/build.log"

{
  printf 'timestamp_utc=%s\n' "${timestamp}"
  printf 'scenario=%s\n' "${scenario}"
  printf 'executable=%s\n' "${executable}"
  printf 'layout=%s\n' "${layout}"
  printf 'git_commit=%s\n' "$(git -C "${root_dir}" rev-parse HEAD)"
  printf 'kernel=%s\n' "$(uname -a)"
  printf 'cpu=%s\n' "$(uname -m)"
  printf 'rustc=%s\n' "$(rustc --version)"
  printf 'scarb=%s\n' "$(scarb --version | head -1)"
} >"${run_dir}/metadata.txt"

time_command=(/usr/bin/time -v)
if [[ "$(uname -s)" == "Darwin" ]]; then
  time_command=(/usr/bin/time -l)
fi

if ! "${time_command[@]}" \
  scarb --manifest-path "${manifest}" execute \
    -p zylith_exchange_statement \
    --executable-name "${executable}" \
    --arguments-file "${input_path}" \
    --layout "${layout}" \
    --print-program-output \
    --print-resource-usage \
    -vv \
    >"${run_dir}/execute.log" 2>"${run_dir}/execute-time.txt"; then
  echo "statement execution failed; inspect ${run_dir}/execute.log and ${run_dir}/execute-time.txt" >&2
  exit 1
fi

if ! grep -q '^Program output:' "${run_dir}/execute.log"; then
  echo "the benchmark statement did not complete; inspect ${run_dir}/execute.log" >&2
  exit 1
fi

# the standalone stwo adapter does not support the signature builtin used by these statements.
# standalone execution is diagnostic only; the full queued snos proof and its resource evidence
# below remain mandatory. do not substitute a signature-free statement for that proof.

for name in \
  ZYLITH_STARKNET_RPC_URL \
  ZYLITH_CHAIN_ID \
  ZYLITH_PROOF_ACCOUNT_ADDRESS \
  ZYLITH_PROOF_ACCOUNT_PRIVATE_KEY \
  ZYLITH_PROOF_QUEUE_URL \
  ZYLITH_PROOF_QUEUE_CONTROL_TOKEN \
  ZYLITH_PROVER_BUILD_ID \
  ZYLITH_RELEASE_COMMIT \
  ZYLITH_PROOF_VERSION \
  ZYLITH_VIRTUAL_PROGRAM_HASH \
  ZYLITH_STARKNET_OS_CONFIG_HASH \
  ZYLITH_PROOF_VALIDITY_BLOCKS \
  ZYLITH_EXCHANGE_ADDRESS
do
  if [[ -z "${!name:-}" ]]; then
    echo "${name} is required for the full SNIP-36 release benchmark" >&2
    exit 1
  fi
done

case "${executable}" in
  transition)
    benchmark_statement_kind=TRANSITION
    required_program_env=ZYLITH_TRANSITION_PROOF_PROGRAM_ADDRESS
    ;;
  exchange_withdrawal)
    benchmark_statement_kind=WITHDRAWAL
    required_program_env=ZYLITH_WITHDRAWAL_PROOF_PROGRAM_ADDRESS
    ;;
  residual_recovery)
    benchmark_statement_kind=RESIDUAL_RECOVERY
    required_program_env=ZYLITH_RESIDUAL_RECOVERY_PROOF_PROGRAM_ADDRESS
    ;;
  *)
    echo "unsupported full SNIP-36 benchmark executable: ${executable}" >&2
    exit 1
    ;;
esac
if [[ -z "${!required_program_env:-}" ]]; then
  echo "${required_program_env} is required for ${benchmark_statement_kind}" >&2
  exit 1
fi

ZYLITH_BENCHMARK_REQUIRE_RESOURCE_USAGE=1 \
ZYLITH_BENCHMARK_STATEMENT_KIND="${benchmark_statement_kind}" \
  cargo run --quiet --release -p zylith-operator --manifest-path "${root_dir}/Cargo.toml" \
    -- bench "${input_path}" \
    >"${run_dir}/full-snip36.jsonl" 2>"${run_dir}/full-snip36.log"

node - "${run_dir}/full-snip36.jsonl" <<'NODE'
const fs = require("node:fs");
const { createHash } = require("node:crypto");
const path = process.argv[2];
const lines = fs.readFileSync(path, "utf8").trim().split(/\r?\n/).filter(Boolean);
if (lines.length !== 1) throw new Error("full SNIP-36 benchmark must emit exactly one report");
const report = JSON.parse(lines[0]);
const usage = report.resource_usage;
if (!usage || report.schema_version !== 3 || !report.identity) throw new Error("full SNIP-36 resource report is missing");
for (const field of ["raw_snos_steps", "adapted_rows", "memory_words", "max_domain_log_size", "peak_rss_bytes", "wall_time_ms"]) {
  if (!Number.isSafeInteger(usage[field]) || usage[field] <= 0) throw new Error(`invalid ${field}`);
}
for (const field of ["builtin_instances", "component_log_sizes"]) {
  const names = Object.keys(usage[field] ?? {});
  if (names.length === 0 || names.length > 256 || names.some((name) => !/^[A-Za-z0-9._\-/:]{1,128}$/.test(name))) {
    throw new Error(`invalid ${field} registry`);
  }
}
if (!("cpu" in usage.component_log_sizes)) throw new Error("component_log_sizes omits cpu");
const registry = JSON.stringify({
  schema_version: 1,
  builtin_components: Object.keys(usage.builtin_instances).sort(),
  trace_components: Object.keys(usage.component_log_sizes).sort(),
});
const expectedRegistryId = createHash("sha256").update("zylith/proof-component-registry/v1:").update(registry).digest("hex");
if (usage.component_registry_id !== expectedRegistryId) throw new Error("component registry id is invalid");
NODE

cp "${expectations_path}" "${run_dir}/expectations.json"
printf 'benchmark results: %s\n' "${run_dir}"
