#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROOF_PROGRAM_DIR="${ROOT_DIR}/proof_program"
RPC_URL="${ZYLITH_PROOF_PROGRAM_DEPLOY_RPC_URL:-${ZYLITH_STARKNET_RPC_URL:-}}"
ACCOUNTS_FILE="${ZYLITH_DEPLOY_ACCOUNTS_FILE:-${ROOT_DIR}/.deploy/sepolia.accounts.json}"
ACCOUNT_NAME="${ZYLITH_DEPLOY_ACCOUNT_NAME:-zylith-sepolia-deployer}"

if [[ -f "${ROOT_DIR}/.deploy/sepolia.prover.env" ]]; then
  while IFS='=' read -r key value; do
    [[ -z "${key}" ]] && continue
    [[ "${key}" == \#* ]] && continue
    if [[ -z "${!key:-}" ]]; then
      export "${key}=${value}"
    fi
  done < "${ROOT_DIR}/.deploy/sepolia.prover.env"
fi

RPC_URL="${ZYLITH_PROOF_PROGRAM_DEPLOY_RPC_URL:-${ZYLITH_STARKNET_RPC_URL:-${RPC_URL}}}"

if [[ -z "${RPC_URL}" ]]; then
  echo "ZYLITH_STARKNET_RPC_URL or ZYLITH_PROOF_PROGRAM_DEPLOY_RPC_URL is required" >&2
  exit 1
fi

if [[ ! -f "${ACCOUNTS_FILE}" ]]; then
  echo "accounts file not found: ${ACCOUNTS_FILE}" >&2
  exit 1
fi

run_sncast() {
  sncast --wait --accounts-file "${ACCOUNTS_FILE}" --account "${ACCOUNT_NAME}" "$@"
}

SNCAST_RETRY_ATTEMPTS="${ZYLITH_SNCAST_RETRY_ATTEMPTS:-5}"
SNCAST_RETRY_DELAY_SECONDS="${ZYLITH_SNCAST_RETRY_DELAY_SECONDS:-10}"
SNCAST_DECLARE_ARGS=()
SNCAST_DEPLOY_ARGS=()
if [[ -n "${ZYLITH_SNCAST_DECLARE_ARGS:-}" ]]; then
  read -r -a SNCAST_DECLARE_ARGS <<< "${ZYLITH_SNCAST_DECLARE_ARGS}"
fi
if [[ -n "${ZYLITH_SNCAST_DEPLOY_ARGS:-}" ]]; then
  read -r -a SNCAST_DEPLOY_ARGS <<< "${ZYLITH_SNCAST_DEPLOY_ARGS}"
fi

is_retryable_sncast_output() {
  local output="$1"
  [[ "${output}" == *"Unknown RPC error"* ]] ||
    [[ "${output}" == *"spec_version"* ]] ||
    [[ "${output}" == *"expected value at line 1 column 1"* ]] ||
    [[ "${output}" == *"Error while getting Starknet version"* ]] ||
    [[ "${output}" == *"error sending request"* ]] ||
    [[ "${output}" == *"429"* ]] ||
    [[ "${output}" == *"Too Many Requests"* ]] ||
    [[ "${output}" == *"Monthly capacity limit exceeded"* ]]
}

declare_contract() {
  local contract_name="$1"
  local out class_hash status attempt
  for ((attempt = 1; attempt <= SNCAST_RETRY_ATTEMPTS; attempt++)); do
    set +e
    out="$(
      cd "${PROOF_PROGRAM_DIR}" &&
        run_sncast declare ${SNCAST_DECLARE_ARGS[@]+"${SNCAST_DECLARE_ARGS[@]}"} --url "${RPC_URL}" --contract-name "${contract_name}" --package zylith_proof_program 2>&1
    )"
    status=$?
    set -e
    printf '%s\n' "${out}" >&2
    class_hash="$(printf '%s\n' "${out}" | sed -n 's/^Class Hash:[[:space:]]*//p' | head -1)"
    if [[ -z "${class_hash}" ]]; then
      class_hash="$(printf '%s\n' "${out}" | sed -n 's/^Already declared class hash:[[:space:]]*//p' | head -1)"
    fi
    if [[ -z "${class_hash}" ]]; then
      class_hash="$(
        printf '%s\n' "${out}" |
          sed -n 's/^Error: Contract with class hash \([^[:space:]]*\) is already declared$/\1/p' |
          head -1
      )"
    fi
    if [[ -n "${class_hash}" ]]; then
      printf '%s' "${class_hash}"
      return 0
    fi
    if ((attempt < SNCAST_RETRY_ATTEMPTS)) && is_retryable_sncast_output "${out}"; then
      echo "retrying ${contract_name} declare after retryable RPC failure (${attempt}/${SNCAST_RETRY_ATTEMPTS})" >&2
      sleep "${SNCAST_RETRY_DELAY_SECONDS}"
      continue
    fi
    if [[ "${status}" -ne 0 ]]; then
      echo "${contract_name} declare failed with sncast status ${status}" >&2
    fi
    break
  done
  echo "failed to parse ${contract_name} class hash" >&2
  exit 1
}

deploy_contract() {
  local class_hash="$1"
  shift
  local out address status attempt
  for ((attempt = 1; attempt <= SNCAST_RETRY_ATTEMPTS; attempt++)); do
    set +e
    out="$(
      cd "${PROOF_PROGRAM_DIR}" &&
        run_sncast deploy --url "${RPC_URL}" --class-hash "${class_hash}" ${SNCAST_DEPLOY_ARGS[@]+"${SNCAST_DEPLOY_ARGS[@]}"} "$@" 2>&1
    )"
    status=$?
    set -e
    printf '%s\n' "${out}" >&2
    address="$(printf '%s\n' "${out}" | sed -n 's/^Contract Address:[[:space:]]*//p' | head -1)"
    if [[ -n "${address}" ]]; then
      printf '%s' "${address}"
      return 0
    fi
    if ((attempt < SNCAST_RETRY_ATTEMPTS)) && is_retryable_sncast_output "${out}"; then
      echo "retrying proof-program deploy after retryable RPC failure (${attempt}/${SNCAST_RETRY_ATTEMPTS})" >&2
      sleep "${SNCAST_RETRY_DELAY_SECONDS}"
      continue
    fi
    if [[ "${status}" -ne 0 ]]; then
      echo "proof-program deploy failed with sncast status ${status}" >&2
    fi
    break
  done
  echo "failed to parse deployed proof-program address" >&2
  exit 1
}

FORCE_REDEPLOY_NATIVE_STATEMENT_PROGRAMS="${ZYLITH_FORCE_REDEPLOY_NATIVE_STATEMENT_PROGRAMS:-false}"

is_nonzero_felt() {
  local value="$1"
  [[ -n "${value}" && "${value}" != "0" && "${value}" != "0x0" ]]
}

existing_statement_address() {
  local env_key="$1"
  local value="${!env_key:-}"
  if [[ "${FORCE_REDEPLOY_NATIVE_STATEMENT_PROGRAMS}" != "true" ]] && is_nonzero_felt "${value}"; then
    printf '%s' "${value}"
    return 0
  fi
  return 1
}

record_env_address() {
  local env_key="$1"
  local address="$2"
  python3 - "${ROOT_DIR}" "${env_key}" "${address}" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
env_path = root / ".deploy/sepolia.prover.env"
lines = []
seen = False
if env_path.exists():
    for line in env_path.read_text().splitlines():
        if line.split("=", 1)[0] == key:
            lines.append(f"{key}={value}")
            seen = True
        else:
            lines.append(line)
if not seen:
    lines.append(f"{key}={value}")
env_path.write_text("\n".join(lines) + "\n")
PY
}

deploy_or_reuse_contract() {
  local env_key="$1"
  local class_hash_var="$2"
  local address_var="$3"
  local contract_name="$4"
  shift 4
  local existing class_hash address
  if existing="$(existing_statement_address "${env_key}")"; then
    echo "reusing ${contract_name}: ${existing}" >&2
    printf -v "${class_hash_var}" '%s' "reused"
    printf -v "${address_var}" '%s' "${existing}"
    return 0
  fi
  class_hash="$(declare_contract "${contract_name}")"
  address="$(deploy_contract "${class_hash}" "$@")"
  record_env_address "${env_key}" "${address}"
  printf -v "${class_hash_var}" '%s' "${class_hash}"
  printf -v "${address_var}" '%s' "${address}"
}

update_env_address() {
  local proof_program_address="$1"
  local settlement_statement_program_address="$2"
  local settlement_note_fee_statement_program_address="$3"
  local settlement_output_recovery_statement_program_address="$4"
  local settlement_input_membership_statement_program_address="$5"
  local settlement_order_statement_program_address="$6"
  local nullifier_statement_program_address="$7"
  local renewal_statement_program_address="$8"
  local note_consolidation_statement_program_address="$9"
  local withdrawal_statement_program_address="${10}"
  local admission_statement_program_address="${11}"
  local auction_result_statement_program_address="${12}"
  local multi_pair_statement_program_address="${13}"
  local multi_pair_settlement_public_statement_program_address="${14}"
  local multi_pair_settlement_order_state_statement_program_address="${15}"
  local multi_pair_settlement_completion_statement_program_address="${16}"
  local multi_pair_settlement_fee_recovery_statement_program_address="${17}"
  local multi_pair_settlement_statement_program_address="${18}"
  local external_match_authorization_statement_program_address="${19}"
  python3 - "${ROOT_DIR}" \
    "${proof_program_address}" \
    "${settlement_statement_program_address}" \
    "${settlement_note_fee_statement_program_address}" \
    "${settlement_output_recovery_statement_program_address}" \
    "${settlement_input_membership_statement_program_address}" \
    "${settlement_order_statement_program_address}" \
    "${nullifier_statement_program_address}" \
    "${renewal_statement_program_address}" \
    "${note_consolidation_statement_program_address}" \
    "${withdrawal_statement_program_address}" \
    "${admission_statement_program_address}" \
    "${auction_result_statement_program_address}" \
    "${multi_pair_statement_program_address}" \
    "${multi_pair_settlement_public_statement_program_address}" \
    "${multi_pair_settlement_order_state_statement_program_address}" \
    "${multi_pair_settlement_completion_statement_program_address}" \
    "${multi_pair_settlement_fee_recovery_statement_program_address}" \
    "${multi_pair_settlement_statement_program_address}" \
    "${external_match_authorization_statement_program_address}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
proof_program_address = sys.argv[2]
settlement_statement_program_address = sys.argv[3]
settlement_note_fee_statement_program_address = sys.argv[4]
settlement_output_recovery_statement_program_address = sys.argv[5]
settlement_input_membership_statement_program_address = sys.argv[6]
settlement_order_statement_program_address = sys.argv[7]
nullifier_statement_program_address = sys.argv[8]
renewal_statement_program_address = sys.argv[9]
note_consolidation_statement_program_address = sys.argv[10]
withdrawal_statement_program_address = sys.argv[11]
admission_statement_program_address = sys.argv[12]
auction_result_statement_program_address = sys.argv[13]
multi_pair_statement_program_address = sys.argv[14]
multi_pair_settlement_public_statement_program_address = sys.argv[15]
multi_pair_settlement_order_state_statement_program_address = sys.argv[16]
multi_pair_settlement_completion_statement_program_address = sys.argv[17]
multi_pair_settlement_fee_recovery_statement_program_address = sys.argv[18]
multi_pair_settlement_statement_program_address = sys.argv[19]
external_match_authorization_statement_program_address = sys.argv[20]
env_path = root / ".deploy/sepolia.prover.env"
lines = []
updates = {
    "ZYLITH_NATIVE_PROOF_PROGRAM_ADDRESS": proof_program_address,
    "ZYLITH_NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS": settlement_statement_program_address,
    "ZYLITH_NATIVE_SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS": settlement_note_fee_statement_program_address,
    "ZYLITH_NATIVE_SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS": settlement_output_recovery_statement_program_address,
    "ZYLITH_NATIVE_SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS": settlement_input_membership_statement_program_address,
    "ZYLITH_NATIVE_SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS": settlement_order_statement_program_address,
    "ZYLITH_NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS": nullifier_statement_program_address,
    "ZYLITH_NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS": renewal_statement_program_address,
    "ZYLITH_NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS": note_consolidation_statement_program_address,
    "ZYLITH_NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS": withdrawal_statement_program_address,
    "ZYLITH_NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS": admission_statement_program_address,
    "ZYLITH_NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS": auction_result_statement_program_address,
    "ZYLITH_NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS": multi_pair_statement_program_address,
    "ZYLITH_NATIVE_MULTI_PAIR_SETTLEMENT_PUBLIC_STATEMENT_PROGRAM_ADDRESS": multi_pair_settlement_public_statement_program_address,
    "ZYLITH_NATIVE_MULTI_PAIR_SETTLEMENT_ORDER_STATE_STATEMENT_PROGRAM_ADDRESS": multi_pair_settlement_order_state_statement_program_address,
    "ZYLITH_NATIVE_MULTI_PAIR_SETTLEMENT_COMPLETION_STATEMENT_PROGRAM_ADDRESS": multi_pair_settlement_completion_statement_program_address,
    "ZYLITH_NATIVE_MULTI_PAIR_SETTLEMENT_FEE_RECOVERY_STATEMENT_PROGRAM_ADDRESS": multi_pair_settlement_fee_recovery_statement_program_address,
    "ZYLITH_NATIVE_MULTI_PAIR_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS": multi_pair_settlement_statement_program_address,
    "ZYLITH_NATIVE_EXTERNAL_MATCH_AUTHORIZATION_STATEMENT_PROGRAM_ADDRESS": external_match_authorization_statement_program_address,
}
seen = set()
if env_path.exists():
    for line in env_path.read_text().splitlines():
        key = line.split("=", 1)[0]
        if key in updates:
            lines.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            lines.append(line)
for key, value in updates.items():
    if key not in seen:
        lines.append(f"{key}={value}")
env_path.write_text("\n".join(lines) + "\n")

for path in [root / ".deploy/sepolia-live.json", root / "client/public/deployment.json"]:
    if not path.exists():
        continue
    data = json.loads(path.read_text())
    manifest = data.get("manifest", data)
    proof = manifest.setdefault("proof", {})
    proof["proof_program_address"] = proof_program_address
    proof["settlement_statement_program_address"] = settlement_statement_program_address
    proof["settlement_note_fee_statement_program_address"] = settlement_note_fee_statement_program_address
    proof["settlement_output_recovery_statement_program_address"] = settlement_output_recovery_statement_program_address
    proof["settlement_input_membership_statement_program_address"] = settlement_input_membership_statement_program_address
    proof["settlement_order_statement_program_address"] = settlement_order_statement_program_address
    proof["nullifier_statement_program_address"] = nullifier_statement_program_address
    proof["renewal_statement_program_address"] = renewal_statement_program_address
    proof["note_consolidation_statement_program_address"] = note_consolidation_statement_program_address
    proof["withdrawal_statement_program_address"] = withdrawal_statement_program_address
    proof["admission_statement_program_address"] = admission_statement_program_address
    proof["auction_result_statement_program_address"] = auction_result_statement_program_address
    proof["multi_pair_statement_program_address"] = multi_pair_statement_program_address
    proof["multi_pair_settlement_public_statement_program_address"] = multi_pair_settlement_public_statement_program_address
    proof["multi_pair_settlement_order_state_statement_program_address"] = multi_pair_settlement_order_state_statement_program_address
    proof["multi_pair_settlement_completion_statement_program_address"] = multi_pair_settlement_completion_statement_program_address
    proof["multi_pair_settlement_fee_recovery_statement_program_address"] = multi_pair_settlement_fee_recovery_statement_program_address
    proof["multi_pair_settlement_statement_program_address"] = multi_pair_settlement_statement_program_address
    proof["external_match_authorization_statement_program_address"] = external_match_authorization_statement_program_address
    path.write_text(json.dumps(data, indent=2) + "\n")
PY
}

(
  cd "${PROOF_PROGRAM_DIR}"
  scarb build
)

deploy_or_reuse_contract \
  ZYLITH_NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS \
  NULLIFIER_STATEMENT_CLASS_HASH \
  NULLIFIER_STATEMENT_PROGRAM_ADDRESS \
  NullifierStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS \
  RENEWAL_STATEMENT_CLASS_HASH \
  RENEWAL_STATEMENT_PROGRAM_ADDRESS \
  RenewalStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS \
  SETTLEMENT_NOTE_FEE_STATEMENT_CLASS_HASH \
  SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS \
  SettlementNoteFeeStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS \
  SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_CLASS_HASH \
  SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS \
  SettlementOutputRecoveryStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS \
  SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_CLASS_HASH \
  SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS \
  SettlementInputMembershipStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS \
  SETTLEMENT_ORDER_STATEMENT_CLASS_HASH \
  SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS \
  SettlementOrderStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS \
  SETTLEMENT_STATEMENT_CLASS_HASH \
  SETTLEMENT_STATEMENT_PROGRAM_ADDRESS \
  SettlementStatementProgram \
  --constructor-calldata \
  "${SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS}" \
  "${SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS}" \
  "${SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS}" \
  "${SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS}"
deploy_or_reuse_contract \
  ZYLITH_NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS \
  NOTE_CONSOLIDATION_STATEMENT_CLASS_HASH \
  NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS \
  NoteConsolidationStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS \
  WITHDRAWAL_STATEMENT_CLASS_HASH \
  WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS \
  WithdrawalStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS \
  ADMISSION_STATEMENT_CLASS_HASH \
  ADMISSION_STATEMENT_PROGRAM_ADDRESS \
  AdmissionStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS \
  AUCTION_RESULT_STATEMENT_CLASS_HASH \
  AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS \
  AuctionResultStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS \
  MULTI_PAIR_STATEMENT_CLASS_HASH \
  MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS \
  MultiPairStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_EXTERNAL_MATCH_AUTHORIZATION_STATEMENT_PROGRAM_ADDRESS \
  EXTERNAL_MATCH_AUTHORIZATION_STATEMENT_CLASS_HASH \
  EXTERNAL_MATCH_AUTHORIZATION_STATEMENT_PROGRAM_ADDRESS \
  ExternalMatchAuthorizationStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_MULTI_PAIR_SETTLEMENT_PUBLIC_STATEMENT_PROGRAM_ADDRESS \
  MULTI_PAIR_SETTLEMENT_PUBLIC_STATEMENT_CLASS_HASH \
  MULTI_PAIR_SETTLEMENT_PUBLIC_STATEMENT_PROGRAM_ADDRESS \
  MultiPairSettlementPublicStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_MULTI_PAIR_SETTLEMENT_ORDER_STATE_STATEMENT_PROGRAM_ADDRESS \
  MULTI_PAIR_SETTLEMENT_ORDER_STATE_STATEMENT_CLASS_HASH \
  MULTI_PAIR_SETTLEMENT_ORDER_STATE_STATEMENT_PROGRAM_ADDRESS \
  MultiPairSettlementOrderStateStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_MULTI_PAIR_SETTLEMENT_COMPLETION_STATEMENT_PROGRAM_ADDRESS \
  MULTI_PAIR_SETTLEMENT_COMPLETION_STATEMENT_CLASS_HASH \
  MULTI_PAIR_SETTLEMENT_COMPLETION_STATEMENT_PROGRAM_ADDRESS \
  MultiPairSettlementCompletionStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_MULTI_PAIR_SETTLEMENT_FEE_RECOVERY_STATEMENT_PROGRAM_ADDRESS \
  MULTI_PAIR_SETTLEMENT_FEE_RECOVERY_STATEMENT_CLASS_HASH \
  MULTI_PAIR_SETTLEMENT_FEE_RECOVERY_STATEMENT_PROGRAM_ADDRESS \
  MultiPairSettlementFeeRecoveryStatementProgram
deploy_or_reuse_contract \
  ZYLITH_NATIVE_MULTI_PAIR_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS \
  MULTI_PAIR_SETTLEMENT_STATEMENT_CLASS_HASH \
  MULTI_PAIR_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS \
  MultiPairSettlementStatementProgram \
  --constructor-calldata \
  "${MULTI_PAIR_SETTLEMENT_PUBLIC_STATEMENT_PROGRAM_ADDRESS}" \
  "${MULTI_PAIR_SETTLEMENT_ORDER_STATE_STATEMENT_PROGRAM_ADDRESS}" \
  "${MULTI_PAIR_SETTLEMENT_COMPLETION_STATEMENT_PROGRAM_ADDRESS}" \
  "${MULTI_PAIR_SETTLEMENT_FEE_RECOVERY_STATEMENT_PROGRAM_ADDRESS}"
AUCTION_PROOF_CLASS_HASH="$(declare_contract AuctionProofProgram)"
PROOF_PROGRAM_ADDRESS="$(
  deploy_contract "${AUCTION_PROOF_CLASS_HASH}" --constructor-calldata \
    "${SETTLEMENT_STATEMENT_PROGRAM_ADDRESS}" \
    "${NULLIFIER_STATEMENT_PROGRAM_ADDRESS}" \
    "${RENEWAL_STATEMENT_PROGRAM_ADDRESS}" \
    "${NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS}" \
    "${WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS}" \
    "${ADMISSION_STATEMENT_PROGRAM_ADDRESS}" \
    "${AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS}" \
    "${MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS}" \
    "${EXTERNAL_MATCH_AUTHORIZATION_STATEMENT_PROGRAM_ADDRESS}" \
    "${MULTI_PAIR_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS}"
)"
update_env_address \
  "${PROOF_PROGRAM_ADDRESS}" \
  "${SETTLEMENT_STATEMENT_PROGRAM_ADDRESS}" \
  "${SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS}" \
  "${SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS}" \
  "${SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS}" \
  "${SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS}" \
  "${NULLIFIER_STATEMENT_PROGRAM_ADDRESS}" \
  "${RENEWAL_STATEMENT_PROGRAM_ADDRESS}" \
  "${NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS}" \
  "${WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS}" \
  "${ADMISSION_STATEMENT_PROGRAM_ADDRESS}" \
  "${AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS}" \
  "${MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS}" \
  "${MULTI_PAIR_SETTLEMENT_PUBLIC_STATEMENT_PROGRAM_ADDRESS}" \
  "${MULTI_PAIR_SETTLEMENT_ORDER_STATE_STATEMENT_PROGRAM_ADDRESS}" \
  "${MULTI_PAIR_SETTLEMENT_COMPLETION_STATEMENT_PROGRAM_ADDRESS}" \
  "${MULTI_PAIR_SETTLEMENT_FEE_RECOVERY_STATEMENT_PROGRAM_ADDRESS}" \
  "${MULTI_PAIR_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS}" \
  "${EXTERNAL_MATCH_AUTHORIZATION_STATEMENT_PROGRAM_ADDRESS}"

cat <<EOF
Native proof program deployed.
SettlementStatementClassHash: ${SETTLEMENT_STATEMENT_CLASS_HASH}
SettlementStatementProgram: ${SETTLEMENT_STATEMENT_PROGRAM_ADDRESS}
SettlementNoteFeeStatementClassHash: ${SETTLEMENT_NOTE_FEE_STATEMENT_CLASS_HASH}
SettlementNoteFeeStatementProgram: ${SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS}
SettlementOutputRecoveryStatementClassHash: ${SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_CLASS_HASH}
SettlementOutputRecoveryStatementProgram: ${SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS}
SettlementInputMembershipStatementClassHash: ${SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_CLASS_HASH}
SettlementInputMembershipStatementProgram: ${SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS}
SettlementOrderStatementClassHash: ${SETTLEMENT_ORDER_STATEMENT_CLASS_HASH}
SettlementOrderStatementProgram: ${SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS}
NullifierStatementClassHash: ${NULLIFIER_STATEMENT_CLASS_HASH}
NullifierStatementProgram: ${NULLIFIER_STATEMENT_PROGRAM_ADDRESS}
RenewalStatementClassHash: ${RENEWAL_STATEMENT_CLASS_HASH}
RenewalStatementProgram: ${RENEWAL_STATEMENT_PROGRAM_ADDRESS}
NoteConsolidationStatementClassHash: ${NOTE_CONSOLIDATION_STATEMENT_CLASS_HASH}
NoteConsolidationStatementProgram: ${NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS}
WithdrawalStatementClassHash: ${WITHDRAWAL_STATEMENT_CLASS_HASH}
WithdrawalStatementProgram: ${WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS}
AdmissionStatementClassHash: ${ADMISSION_STATEMENT_CLASS_HASH}
AdmissionStatementProgram: ${ADMISSION_STATEMENT_PROGRAM_ADDRESS}
AuctionResultStatementClassHash: ${AUCTION_RESULT_STATEMENT_CLASS_HASH}
AuctionResultStatementProgram: ${AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS}
MultiPairStatementClassHash: ${MULTI_PAIR_STATEMENT_CLASS_HASH}
MultiPairStatementProgram: ${MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS}
ExternalMatchAuthorizationStatementClassHash: ${EXTERNAL_MATCH_AUTHORIZATION_STATEMENT_CLASS_HASH}
ExternalMatchAuthorizationStatementProgram: ${EXTERNAL_MATCH_AUTHORIZATION_STATEMENT_PROGRAM_ADDRESS}
MultiPairSettlementPublicStatementClassHash: ${MULTI_PAIR_SETTLEMENT_PUBLIC_STATEMENT_CLASS_HASH}
MultiPairSettlementPublicStatementProgram: ${MULTI_PAIR_SETTLEMENT_PUBLIC_STATEMENT_PROGRAM_ADDRESS}
MultiPairSettlementOrderStateStatementClassHash: ${MULTI_PAIR_SETTLEMENT_ORDER_STATE_STATEMENT_CLASS_HASH}
MultiPairSettlementOrderStateStatementProgram: ${MULTI_PAIR_SETTLEMENT_ORDER_STATE_STATEMENT_PROGRAM_ADDRESS}
MultiPairSettlementCompletionStatementClassHash: ${MULTI_PAIR_SETTLEMENT_COMPLETION_STATEMENT_CLASS_HASH}
MultiPairSettlementCompletionStatementProgram: ${MULTI_PAIR_SETTLEMENT_COMPLETION_STATEMENT_PROGRAM_ADDRESS}
MultiPairSettlementFeeRecoveryStatementClassHash: ${MULTI_PAIR_SETTLEMENT_FEE_RECOVERY_STATEMENT_CLASS_HASH}
MultiPairSettlementFeeRecoveryStatementProgram: ${MULTI_PAIR_SETTLEMENT_FEE_RECOVERY_STATEMENT_PROGRAM_ADDRESS}
MultiPairSettlementStatementClassHash: ${MULTI_PAIR_SETTLEMENT_STATEMENT_CLASS_HASH}
MultiPairSettlementStatementProgram: ${MULTI_PAIR_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS}
AuctionProofClassHash: ${AUCTION_PROOF_CLASS_HASH}
ProofProgram: ${PROOF_PROGRAM_ADDRESS}

Updated proof-program addresses in .deploy/sepolia.prover.env and deployment manifests.
Next: run a prove-only native Sepolia smoke to learn proof_facts.virtual_program_hash, then pin it with scripts/pin_native_proof_program_hash.sh.
EOF
