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
        run_sncast declare --url "${RPC_URL}" --contract-name "${contract_name}" --package zylith_proof_program 2>&1
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
        run_sncast deploy --url "${RPC_URL}" --class-hash "${class_hash}" "$@" 2>&1
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

update_env_address() {
  local proof_program_address="$1"
  local settlement_statement_program_address="$2"
  local settlement_note_fee_statement_program_address="$3"
  local settlement_output_recovery_statement_program_address="$4"
  local settlement_input_membership_statement_program_address="$5"
  local settlement_order_statement_program_address="$6"
  local nullifier_statement_program_address="$7"
  local renewal_statement_program_address="$8"
  local liquidity_position_statement_program_address="$9"
  local note_consolidation_statement_program_address="${10}"
  local withdrawal_statement_program_address="${11}"
  local admission_statement_program_address="${12}"
  local auction_result_statement_program_address="${13}"
  local multi_pair_statement_program_address="${14}"
  python3 - "${ROOT_DIR}" \
    "${proof_program_address}" \
    "${settlement_statement_program_address}" \
    "${settlement_note_fee_statement_program_address}" \
    "${settlement_output_recovery_statement_program_address}" \
    "${settlement_input_membership_statement_program_address}" \
    "${settlement_order_statement_program_address}" \
    "${nullifier_statement_program_address}" \
    "${renewal_statement_program_address}" \
    "${liquidity_position_statement_program_address}" \
    "${note_consolidation_statement_program_address}" \
    "${withdrawal_statement_program_address}" \
    "${admission_statement_program_address}" \
    "${auction_result_statement_program_address}" \
    "${multi_pair_statement_program_address}" <<'PY'
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
liquidity_position_statement_program_address = sys.argv[10]
note_consolidation_statement_program_address = sys.argv[11]
withdrawal_statement_program_address = sys.argv[12]
admission_statement_program_address = sys.argv[13]
auction_result_statement_program_address = sys.argv[14]
multi_pair_statement_program_address = sys.argv[15]
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
    "ZYLITH_NATIVE_LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS": liquidity_position_statement_program_address,
    "ZYLITH_NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS": note_consolidation_statement_program_address,
    "ZYLITH_NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS": withdrawal_statement_program_address,
    "ZYLITH_NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS": admission_statement_program_address,
    "ZYLITH_NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS": auction_result_statement_program_address,
    "ZYLITH_NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS": multi_pair_statement_program_address,
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
    proof["liquidity_position_statement_program_address"] = liquidity_position_statement_program_address
    proof["note_consolidation_statement_program_address"] = note_consolidation_statement_program_address
    proof["withdrawal_statement_program_address"] = withdrawal_statement_program_address
    proof["admission_statement_program_address"] = admission_statement_program_address
    proof["auction_result_statement_program_address"] = auction_result_statement_program_address
    proof["multi_pair_statement_program_address"] = multi_pair_statement_program_address
    path.write_text(json.dumps(data, indent=2) + "\n")
PY
}

(
  cd "${PROOF_PROGRAM_DIR}"
  scarb build
)

NULLIFIER_STATEMENT_CLASS_HASH="$(declare_contract NullifierStatementProgram)"
NULLIFIER_STATEMENT_PROGRAM_ADDRESS="$(deploy_contract "${NULLIFIER_STATEMENT_CLASS_HASH}")"
RENEWAL_STATEMENT_CLASS_HASH="$(declare_contract RenewalStatementProgram)"
RENEWAL_STATEMENT_PROGRAM_ADDRESS="$(deploy_contract "${RENEWAL_STATEMENT_CLASS_HASH}")"
LIQUIDITY_POSITION_STATEMENT_CLASS_HASH="$(declare_contract LiquidityPositionStatementProgram)"
LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS="$(deploy_contract "${LIQUIDITY_POSITION_STATEMENT_CLASS_HASH}")"
SETTLEMENT_NOTE_FEE_STATEMENT_CLASS_HASH="$(declare_contract SettlementNoteFeeStatementProgram)"
SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS="$(deploy_contract "${SETTLEMENT_NOTE_FEE_STATEMENT_CLASS_HASH}")"
SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_CLASS_HASH="$(declare_contract SettlementOutputRecoveryStatementProgram)"
SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS="$(deploy_contract "${SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_CLASS_HASH}")"
SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_CLASS_HASH="$(declare_contract SettlementInputMembershipStatementProgram)"
SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS="$(deploy_contract "${SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_CLASS_HASH}")"
SETTLEMENT_ORDER_STATEMENT_CLASS_HASH="$(declare_contract SettlementOrderStatementProgram)"
SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS="$(deploy_contract "${SETTLEMENT_ORDER_STATEMENT_CLASS_HASH}")"
SETTLEMENT_STATEMENT_CLASS_HASH="$(declare_contract SettlementStatementProgram)"
SETTLEMENT_STATEMENT_PROGRAM_ADDRESS="$(
  deploy_contract "${SETTLEMENT_STATEMENT_CLASS_HASH}" --constructor-calldata \
    "${SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS}" \
    "${SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS}" \
    "${SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS}" \
    "${SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS}" \
    "${LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS}"
)"
NOTE_CONSOLIDATION_STATEMENT_CLASS_HASH="$(declare_contract NoteConsolidationStatementProgram)"
NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS="$(deploy_contract "${NOTE_CONSOLIDATION_STATEMENT_CLASS_HASH}")"
WITHDRAWAL_STATEMENT_CLASS_HASH="$(declare_contract WithdrawalStatementProgram)"
WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS="$(deploy_contract "${WITHDRAWAL_STATEMENT_CLASS_HASH}")"
ADMISSION_STATEMENT_CLASS_HASH="$(declare_contract AdmissionStatementProgram)"
ADMISSION_STATEMENT_PROGRAM_ADDRESS="$(deploy_contract "${ADMISSION_STATEMENT_CLASS_HASH}")"
AUCTION_RESULT_STATEMENT_CLASS_HASH="$(declare_contract AuctionResultStatementProgram)"
AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS="$(deploy_contract "${AUCTION_RESULT_STATEMENT_CLASS_HASH}")"
MULTI_PAIR_STATEMENT_CLASS_HASH="$(declare_contract MultiPairStatementProgram)"
MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS="$(deploy_contract "${MULTI_PAIR_STATEMENT_CLASS_HASH}")"
AUCTION_PROOF_CLASS_HASH="$(declare_contract AuctionProofProgram)"
PROOF_PROGRAM_ADDRESS="$(
  deploy_contract "${AUCTION_PROOF_CLASS_HASH}" --constructor-calldata \
    "${SETTLEMENT_STATEMENT_PROGRAM_ADDRESS}" \
    "${NULLIFIER_STATEMENT_PROGRAM_ADDRESS}" \
    "${RENEWAL_STATEMENT_PROGRAM_ADDRESS}" \
    "${LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS}" \
    "${NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS}" \
    "${WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS}" \
    "${ADMISSION_STATEMENT_PROGRAM_ADDRESS}" \
    "${AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS}" \
    "${MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS}"
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
  "${LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS}" \
  "${NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS}" \
  "${WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS}" \
  "${ADMISSION_STATEMENT_PROGRAM_ADDRESS}" \
  "${AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS}" \
  "${MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS}"

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
LiquidityPositionStatementClassHash: ${LIQUIDITY_POSITION_STATEMENT_CLASS_HASH}
LiquidityPositionStatementProgram: ${LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS}
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
AuctionProofClassHash: ${AUCTION_PROOF_CLASS_HASH}
ProofProgram: ${PROOF_PROGRAM_ADDRESS}

Updated proof-program addresses in .deploy/sepolia.prover.env and deployment manifests.
Next: run a prove-only native Sepolia smoke to learn proof_facts.virtual_program_hash, then pin it with scripts/pin_native_proof_program_hash.sh.
EOF
