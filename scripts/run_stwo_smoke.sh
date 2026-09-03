#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCARB_PROVE_LAYOUT="${SCARB_PROVE_LAYOUT:-stwo_no_ecop}"
SETTLEMENT_SCENARIOS=(noop lp-fill lp-lifecycle lp-oracle-skew lp-soak lp-open-fill-e2e)
SPLIT_SCENARIOS=(
  "lp-open-fill-e2e admission admission"
  "lp-open-fill-e2e auction-result auction_result"
  "lp-open-fill-e2e liquidity-position liquidity_position"
  "multi-pair multi-pair multi_pair"
  "lp-user-fill-auction-result settlement settlement"
)

mkdir -p "${ROOT_DIR}/target/smoke"

prove_smoke() {
  local SCENARIO="$1"
  local STATEMENT="$2"
  local EXECUTABLE="$3"
  INPUT_PATH="${ROOT_DIR}/target/smoke/stwo_${SCENARIO}.json"
  if [[ "${STATEMENT}" != "settlement" ]]; then
    INPUT_PATH="${ROOT_DIR}/target/smoke/stwo_${SCENARIO}_${STATEMENT}.json"
  fi

  cargo run --quiet \
    --manifest-path "${ROOT_DIR}/smoke/Cargo.toml" \
    --target-dir "${ROOT_DIR}/target" \
    -- \
    --output "${INPUT_PATH}" \
    --scenario "${SCENARIO}" \
    --statement "${STATEMENT}"

  PROVE_OUTPUT="$(
    scarb --manifest-path "${ROOT_DIR}/stwo_statement/Scarb.toml" \
      prove \
      -p zylith_settlement_statement \
      --executable-name "${EXECUTABLE}" \
      --execute \
      --arguments-file "${INPUT_PATH}" \
      --layout "${SCARB_PROVE_LAYOUT}" \
      --json
  )"

  printf '%s\n' "${PROVE_OUTPUT}"

  PROOF_PATH="$(
    printf '%s\n' "${PROVE_OUTPUT}" \
      | sed -n 's/.*"status":"saving proof to:","message":"\([^"]*\)".*/\1/p' \
      | tail -n 1
  )"

  if [[ -z "${PROOF_PATH}" ]]; then
    echo "failed to locate proof path in scarb prove output for ${SCENARIO}" >&2
    exit 1
  fi

  if [[ "${PROOF_PATH}" != /* ]]; then
    PROOF_PATH="${ROOT_DIR}/stwo_statement/${PROOF_PATH}"
  fi

  VERIFY_OUTPUT="$(
    scarb --manifest-path "${ROOT_DIR}/stwo_statement/Scarb.toml" \
      verify \
      --proof-file "${PROOF_PATH}" \
      --json
  )"

  printf '%s\n' "${VERIFY_OUTPUT}"
  echo "S-two smoke prove/verify succeeded for ${SCENARIO}/${STATEMENT} using ${INPUT_PATH}"
}

for SCENARIO in "${SETTLEMENT_SCENARIOS[@]}"; do
  prove_smoke "${SCENARIO}" settlement settlement
done

for SPEC in "${SPLIT_SCENARIOS[@]}"; do
  read -r SCENARIO STATEMENT EXECUTABLE <<<"${SPEC}"
  prove_smoke "${SCENARIO}" "${STATEMENT}" "${EXECUTABLE}"
done
