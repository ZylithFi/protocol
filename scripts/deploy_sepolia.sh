#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS_DIR="${ROOT_DIR}/contracts"

RPC_URL="${ZYLITH_STARKNET_RPC_URL:-}"
PUBLIC_RPC_URL="${ZYLITH_PUBLIC_STARKNET_RPC_URL:-${ZYLITH_PUBLIC_RPC_URL:-}}"
CHAIN_ID="${ZYLITH_STARKNET_CHAIN_ID:-0x534e5f5345504f4c4941}"
ACCOUNTS_FILE="${ZYLITH_DEPLOY_ACCOUNTS_FILE:-${ROOT_DIR}/.deploy/sepolia.accounts.json}"
ACCOUNT_NAME="${ZYLITH_DEPLOY_ACCOUNT_NAME:-zylith-sepolia-deployer}"
EXISTING_MANIFEST_PATH="${ZYLITH_EXISTING_DEPLOYMENT_MANIFEST:-${ROOT_DIR}/client/public/deployment.json}"
STRK_TOKEN_ADDRESS="${ZYLITH_STRK_TOKEN_ADDRESS:-0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d}"
ETH_TOKEN_ADDRESS="${ZYLITH_ETH_TOKEN_ADDRESS:-0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7}"
USDC_TOKEN_ADDRESS="${ZYLITH_USDC_TOKEN_ADDRESS:-0x0512feAc6339Ff7889822cb5aA2a86C848e9D392bB0E3E237C008674feeD8343}"
STRKBTC_TOKEN_ADDRESS="${ZYLITH_STRKBTC_TOKEN_ADDRESS:-0x45060889ad33e70531ae2683046bb9b0d7c8199fccd9acd544170a42b0a0fd0}"
WBTC_TOKEN_ADDRESS="${ZYLITH_WBTC_TOKEN_ADDRESS:-}"
USDT_TOKEN_ADDRESS="${ZYLITH_USDT_TOKEN_ADDRESS:-}"
PRIVACY_POOL_ADDRESS="${ZYLITH_STARKNET_PRIVACY_POOL_ADDRESS:-}"
LOCK_PROOF_PROGRAM_AFTER_DEPLOY="${ZYLITH_LOCK_PROOF_PROGRAM_AFTER_DEPLOY:-true}"
LOCK_OPERATIONAL_CONFIG_AFTER_DEPLOY="${ZYLITH_LOCK_OPERATIONAL_CONFIG_AFTER_DEPLOY:-true}"

if [[ -z "${RPC_URL}" ]]; then
  echo "ZYLITH_STARKNET_RPC_URL is required" >&2
  exit 1
fi

if [[ -z "${PUBLIC_RPC_URL}" ]]; then
  echo "ZYLITH_PUBLIC_STARKNET_RPC_URL is required for public deployment manifests" >&2
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
SNCAST_INVOKE_ARGS=()
if [[ -n "${ZYLITH_SNCAST_DECLARE_ARGS:-}" ]]; then
  read -r -a SNCAST_DECLARE_ARGS <<< "${ZYLITH_SNCAST_DECLARE_ARGS}"
fi
if [[ -n "${ZYLITH_SNCAST_DEPLOY_ARGS:-}" ]]; then
  read -r -a SNCAST_DEPLOY_ARGS <<< "${ZYLITH_SNCAST_DEPLOY_ARGS}"
fi
if [[ -n "${ZYLITH_SNCAST_INVOKE_ARGS:-}" ]]; then
  read -r -a SNCAST_INVOKE_ARGS <<< "${ZYLITH_SNCAST_INVOKE_ARGS}"
fi

is_retryable_sncast_output() {
  local output="$1"
  [[ "${output}" == *"Unknown RPC error"* ]] ||
    [[ "${output}" == *"spec_version"* ]] ||
    [[ "${output}" == *"expected value at line 1 column 1"* ]] ||
    [[ "${output}" == *"HTTP 429"* ]] ||
    [[ "${output}" == *"status code 429"* ]] ||
    [[ "${output}" == *"Too Many Requests"* ]] ||
    [[ "${output}" == *"Monthly capacity limit exceeded"* ]]
}

read_manifest_field() {
  local default_value="$1"
  shift
  python3 - "${EXISTING_MANIFEST_PATH}" "${default_value}" "$@" <<'PY'
import json, os, sys
from pathlib import Path

path = Path(sys.argv[1])
default = sys.argv[2]
keys = sys.argv[3:]
if not path.exists():
    print(default)
    raise SystemExit(0)

value = json.loads(path.read_text())
for key in keys:
    if not isinstance(value, dict) or key not in value:
        print(default)
        raise SystemExit(0)
    value = value[key]
print(value if isinstance(value, str) else default)
PY
}

read_account_field() {
  local field="$1"
  python3 - "${ACCOUNTS_FILE}" "${ACCOUNT_NAME}" "${field}" <<'PY'
import json, os, sys
path, name, field = sys.argv[1:4]
data = json.load(open(path))
for network in ("alpha-sepolia", "sepolia"):
    if network in data and name in data[network]:
        print(data[network][name][field])
        raise SystemExit(0)
raise SystemExit(f"account {name!r} not found in {path}")
PY
}

if [[ -z "${PRIVACY_POOL_ADDRESS}" ]]; then
  PRIVACY_POOL_ADDRESS="$(read_manifest_field "" funding starknet_privacy privacy_pool)"
fi

if [[ -z "${PRIVACY_POOL_ADDRESS}" ]]; then
  echo "ZYLITH_STARKNET_PRIVACY_POOL_ADDRESS or funding.starknet_privacy.privacy_pool is required for the privacy deposit bridge" >&2
  exit 1
fi

compute_asset_id() {
  local symbol="$1"
  node - "${symbol}" <<'NODE'
const { createHash } = require("node:crypto");
const symbol = process.argv[2];
const bytes = createHash("sha256")
  .update(`zylith/starknet-feltasset-id:${symbol}`)
  .digest();
bytes[0] &= 0x03;
console.log(`0x${bytes.toString("hex")}`);
NODE
}

compute_pair_id() {
  local pair="$1"
  node - "${pair}" <<'NODE'
const { createHash } = require("node:crypto");
const pair = process.argv[2];
const bytes = createHash("sha256")
  .update(`zylith/starknet-feltpair-id:${pair}`)
  .digest();
bytes[0] &= 0x03;
console.log(`0x${bytes.toString("hex")}`);
NODE
}

require_nonzero_address() {
  local name="$1"
  local value="$2"
  if [[ -z "${value}" || "${value}" == "0x0" || "${value}" == "0" ]]; then
    echo "${name} must be configured to a non-zero Starknet address" >&2
    exit 1
  fi
}

declare_contract() {
  local name="$1"
  local out class_hash status attempt hard_error
  for ((attempt = 1; attempt <= SNCAST_RETRY_ATTEMPTS; attempt++)); do
    set +e
    out="$(
      cd "${CONTRACTS_DIR}" &&
        run_sncast declare ${SNCAST_DECLARE_ARGS[@]+"${SNCAST_DECLARE_ARGS[@]}"} --url "${RPC_URL}" --contract-name "${name}" --package zylith_protocol 2>&1
    )"
    status=$?
    set -e
    printf '%s\n' "${out}" >&2
    hard_error=false
    if [[ "${out}" == *"Error:"* && "${out}" != *"already declared"* ]]; then
      hard_error=true
      status=1
    fi
    class_hash=""
    if [[ "${hard_error}" != "true" ]]; then
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
    fi
    if ((attempt < SNCAST_RETRY_ATTEMPTS)) && is_retryable_sncast_output "${out}"; then
      echo "retrying declare ${name} after retryable RPC failure (${attempt}/${SNCAST_RETRY_ATTEMPTS})" >&2
      sleep "${SNCAST_RETRY_DELAY_SECONDS}"
      continue
    fi
    if [[ "${status}" -ne 0 ]]; then
      echo "declare ${name} failed with sncast status ${status}" >&2
    fi
    break
  done
  if [[ "${status}" -eq 0 && "${hard_error:-false}" != "true" ]]; then
    class_hash="$(
      cd "${CONTRACTS_DIR}" &&
        sncast utils class-hash --contract-name "${name}" --package zylith_protocol 2>/dev/null |
          sed -n 's/^Class Hash:[[:space:]]*//p' |
          head -1
    )"
    if [[ -n "${class_hash}" ]]; then
      echo "using locally computed class hash for ${name} after successful declare receipt parsing failed: ${class_hash}" >&2
      printf '%s' "${class_hash}"
      return 0
    fi
  fi
  echo "failed to declare or parse class hash for ${name}" >&2
  exit 1
}

deploy_contract() {
  local class_hash="$1"
  shift
  local out address status attempt
  for ((attempt = 1; attempt <= SNCAST_RETRY_ATTEMPTS; attempt++)); do
    set +e
    out="$(
      cd "${CONTRACTS_DIR}" &&
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
      echo "retrying deploy ${class_hash} after retryable RPC failure (${attempt}/${SNCAST_RETRY_ATTEMPTS})" >&2
      sleep "${SNCAST_RETRY_DELAY_SECONDS}"
      continue
    fi
    if [[ "${status}" -ne 0 ]]; then
      echo "deploy ${class_hash} failed with sncast status ${status}" >&2
    fi
    break
  done
  echo "failed to parse deployed contract address for class ${class_hash}" >&2
  exit 1
}

invoke_contract() {
  local contract_address="$1"
  local function="$2"
  shift 2
  local out status attempt
  for ((attempt = 1; attempt <= SNCAST_RETRY_ATTEMPTS; attempt++)); do
    set +e
    if [[ "$#" -gt 0 ]]; then
      out="$(
        cd "${CONTRACTS_DIR}" &&
          run_sncast invoke --url "${RPC_URL}" --contract-address "${contract_address}" --function "${function}" ${SNCAST_INVOKE_ARGS[@]+"${SNCAST_INVOKE_ARGS[@]}"} --calldata "$@" 2>&1
      )"
    else
      out="$(
        cd "${CONTRACTS_DIR}" &&
          run_sncast invoke --url "${RPC_URL}" --contract-address "${contract_address}" --function "${function}" ${SNCAST_INVOKE_ARGS[@]+"${SNCAST_INVOKE_ARGS[@]}"} 2>&1
      )"
    fi
    status=$?
    set -e
    printf '%s\n' "${out}"
    if [[ "${status}" -eq 0 ]]; then
      return 0
    fi
    if ((attempt < SNCAST_RETRY_ATTEMPTS)) && is_retryable_sncast_output "${out}"; then
      echo "retrying invoke ${function} on ${contract_address} after retryable RPC failure (${attempt}/${SNCAST_RETRY_ATTEMPTS})" >&2
      sleep "${SNCAST_RETRY_DELAY_SECONDS}"
      continue
    fi
    return "${status}"
  done
  return 1
}

mkdir -p "${ROOT_DIR}/.deploy"

ACCOUNT_ADDRESS="$(read_account_field address)"
PRIVATE_KEY=""
DEFAULT_PUBLIC_KEY="$(read_account_field public_key)"
read_deployer_private_key() {
  if [[ -z "${PRIVATE_KEY}" ]]; then
    PRIVATE_KEY="$(read_account_field private_key)"
  fi
}
PROOF_VALIDITY_BLOCKS="${ZYLITH_PROOF_VALIDITY_BLOCKS:-450}"
OUTPUT_CLAIM_DELAY_SECONDS="${ZYLITH_OUTPUT_CLAIM_DELAY_SECONDS:-1800}"
INITIAL_NOTE_ROOT="${ZYLITH_INITIAL_NOTE_ROOT:-$(read_manifest_field 0 proof initial_note_root)}"
INITIAL_NULLIFIER_ROOT="${ZYLITH_INITIAL_NULLIFIER_ROOT:-$(read_manifest_field 0 proof initial_nullifier_root)}"
INITIAL_RENEWAL_ROOT="${ZYLITH_INITIAL_RENEWAL_ROOT:-$(read_manifest_field 0 proof initial_renewal_root)}"
INITIAL_FEE_ROOT="${ZYLITH_INITIAL_FEE_ROOT:-$(read_manifest_field 0 proof initial_fee_root)}"
NATIVE_PROOF_PROGRAM_HASH="${ZYLITH_NATIVE_PROOF_PROGRAM_HASH:-}"
NATIVE_PROOF_PROGRAM_ADDRESS="${ZYLITH_NATIVE_PROOF_PROGRAM_ADDRESS:-}"
STARKNET_OS_CONFIG_HASH="${ZYLITH_STARKNET_OS_CONFIG_HASH:-}"
NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS:-}"
NATIVE_SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS:-}"
NATIVE_SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS:-}"
NATIVE_SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS:-}"
NATIVE_SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS:-}"
NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS:-}"
NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS:-}"
NATIVE_LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS:-}"
NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS:-}"
NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS:-}"
NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS:-}"
NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS:-}"
NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS="${ZYLITH_NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS:-}"
PROTOCOL_FEE_RECIPIENT="${ZYLITH_PROTOCOL_FEE_RECIPIENT:-${ZYLITH_PROTOCOL_TREASURY_ADDRESS:-${ACCOUNT_ADDRESS}}}"
RELAY_FEE_RECIPIENT="${ZYLITH_RELAY_FEE_RECIPIENT:-${ZYLITH_RENEWAL_RELAY_FEE_RECIPIENT:-${ACCOUNT_ADDRESS}}}"
PAUSE_GUARDIAN_ADDRESS="${ZYLITH_PAUSE_GUARDIAN_ADDRESS:-${ACCOUNT_ADDRESS}}"
SETTLEMENT_ACCOUNT_ADDRESS="${ZYLITH_SETTLEMENT_ACCOUNT_ADDRESS:-${ACCOUNT_ADDRESS}}"
SETTLEMENT_ACCOUNT_PRIVATE_KEY="${ZYLITH_SETTLEMENT_ACCOUNT_PRIVATE_KEY:-}"
if [[ -z "${NATIVE_PROOF_PROGRAM_HASH}" ]]; then
  NATIVE_PROOF_PROGRAM_HASH="$(read_manifest_field "" proof proof_program_hash)"
fi
if [[ -z "${NATIVE_PROOF_PROGRAM_ADDRESS}" ]]; then
  NATIVE_PROOF_PROGRAM_ADDRESS="$(read_manifest_field "" proof proof_program_address)"
fi
if [[ -z "${NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof settlement_statement_program_address)"
fi
if [[ -z "${NATIVE_SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof settlement_note_fee_statement_program_address)"
fi
if [[ -z "${NATIVE_SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof settlement_order_statement_program_address)"
fi
if [[ -z "${NATIVE_SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof settlement_input_membership_statement_program_address)"
fi
if [[ -z "${NATIVE_SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof settlement_output_recovery_statement_program_address)"
fi
if [[ -z "${NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof nullifier_statement_program_address)"
fi
if [[ -z "${NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof renewal_statement_program_address)"
fi
if [[ -z "${NATIVE_LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof liquidity_position_statement_program_address)"
fi
if [[ -z "${NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof note_consolidation_statement_program_address)"
fi
if [[ -z "${NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof withdrawal_statement_program_address)"
fi
if [[ -z "${NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof admission_statement_program_address)"
fi
if [[ -z "${NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof auction_result_statement_program_address)"
fi
if [[ -z "${NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS}" ]]; then
  NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS="$(read_manifest_field "" proof multi_pair_statement_program_address)"
fi
if [[ ! "${PROOF_VALIDITY_BLOCKS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "ZYLITH_PROOF_VALIDITY_BLOCKS must be a positive integer" >&2
  exit 1
fi
if [[ ! "${OUTPUT_CLAIM_DELAY_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "ZYLITH_OUTPUT_CLAIM_DELAY_SECONDS must be a non-negative integer" >&2
  exit 1
fi
if [[ -z "${NATIVE_PROOF_PROGRAM_HASH}" ]]; then
  echo "ZYLITH_NATIVE_PROOF_PROGRAM_HASH or proof.proof_program_hash is required so AuctionVerifier can pin proof_facts.virtual_program_hash" >&2
  exit 1
fi
if [[ -z "${NATIVE_PROOF_PROGRAM_ADDRESS}" ]]; then
  echo "ZYLITH_NATIVE_PROOF_PROGRAM_ADDRESS or proof.proof_program_address is required so AuctionVerifier can bind proof_facts.message_to_l1_hashes" >&2
  exit 1
fi
if [[ -z "${STARKNET_OS_CONFIG_HASH}" || "${STARKNET_OS_CONFIG_HASH}" == "0" || "${STARKNET_OS_CONFIG_HASH}" == "0x0" ]]; then
  echo "ZYLITH_STARKNET_OS_CONFIG_HASH is required so AuctionVerifier can bind proof_facts.starknet_os_config_hash" >&2
  exit 1
fi
if [[ -z "${SETTLEMENT_ACCOUNT_PRIVATE_KEY}" ]]; then
  if [[ "${SETTLEMENT_ACCOUNT_ADDRESS}" == "${ACCOUNT_ADDRESS}" ]]; then
    read_deployer_private_key
    SETTLEMENT_ACCOUNT_PRIVATE_KEY="${PRIVATE_KEY}"
  else
    echo "ZYLITH_SETTLEMENT_ACCOUNT_PRIVATE_KEY is required when ZYLITH_SETTLEMENT_ACCOUNT_ADDRESS differs from the deployer account" >&2
    exit 1
  fi
fi
BATCH_REGISTRAR_ADDRESS="${ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS:-}"
BATCH_REGISTRAR_PRIVATE_KEY="${ZYLITH_BATCH_REGISTRAR_PRIVATE_KEY:-}"
if [[ -z "${BATCH_REGISTRAR_ADDRESS}" || -z "${BATCH_REGISTRAR_PRIVATE_KEY}" ]]; then
  echo "ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS and ZYLITH_BATCH_REGISTRAR_PRIVATE_KEY are required" >&2
  exit 1
fi
STRK_ASSET_ID="$(compute_asset_id STRK)"
ETH_ASSET_ID="$(compute_asset_id ETH)"
USDC_ASSET_ID="$(compute_asset_id USDC)"
STRKBTC_ASSET_ID="$(compute_asset_id strkBTC)"
WBTC_ASSET_ID="$(compute_asset_id WBTC)"
USDT_ASSET_ID="$(compute_asset_id USDT)"

require_nonzero_address ZYLITH_STRK_TOKEN_ADDRESS "${STRK_TOKEN_ADDRESS}"
require_nonzero_address ZYLITH_ETH_TOKEN_ADDRESS "${ETH_TOKEN_ADDRESS}"
require_nonzero_address ZYLITH_USDC_TOKEN_ADDRESS "${USDC_TOKEN_ADDRESS}"
require_nonzero_address ZYLITH_STRKBTC_TOKEN_ADDRESS "${STRKBTC_TOKEN_ADDRESS}"
require_nonzero_address ZYLITH_WBTC_TOKEN_ADDRESS "${WBTC_TOKEN_ADDRESS}"
require_nonzero_address ZYLITH_USDT_TOKEN_ADDRESS "${USDT_TOKEN_ADDRESS}"
require_nonzero_address ZYLITH_PROTOCOL_FEE_RECIPIENT "${PROTOCOL_FEE_RECIPIENT}"
require_nonzero_address ZYLITH_RELAY_FEE_RECIPIENT "${RELAY_FEE_RECIPIENT}"
require_nonzero_address ZYLITH_PAUSE_GUARDIAN_ADDRESS "${PAUSE_GUARDIAN_ADDRESS}"

(
  cd "${CONTRACTS_DIR}" &&
    scarb build
)

COMMITMENT_REGISTRY_CLASS="$(declare_contract CommitmentRegistry)"
BATCH_REGISTRY_CLASS="$(declare_contract BatchRegistry)"
PRIVACY_DEPOSIT_BRIDGE_CLASS="$(declare_contract PrivacyDepositBridge)"
AUCTION_VERIFIER_CLASS="$(declare_contract AuctionVerifier)"

COMMITMENT_REGISTRY_ADDRESS="$(
  deploy_contract "${COMMITMENT_REGISTRY_CLASS}" --constructor-calldata "${ACCOUNT_ADDRESS}"
)"
BATCH_REGISTRY_ADDRESS="$(
  deploy_contract "${BATCH_REGISTRY_CLASS}" --constructor-calldata "${ACCOUNT_ADDRESS}" "${BATCH_REGISTRAR_ADDRESS}"
)"
PRIVACY_DEPOSIT_BRIDGE_ADDRESS="$(
  deploy_contract "${PRIVACY_DEPOSIT_BRIDGE_CLASS}" --constructor-calldata \
    "${ACCOUNT_ADDRESS}" \
    "${COMMITMENT_REGISTRY_ADDRESS}" \
    "${PRIVACY_POOL_ADDRESS}"
)"
AUCTION_VERIFIER_ADDRESS="$(
  deploy_contract "${AUCTION_VERIFIER_CLASS}" --constructor-calldata \
    "${ACCOUNT_ADDRESS}" \
    "${BATCH_REGISTRY_ADDRESS}" \
    "${INITIAL_NOTE_ROOT}" \
    "${INITIAL_NULLIFIER_ROOT}" \
    "${INITIAL_RENEWAL_ROOT}" \
    "${INITIAL_FEE_ROOT}"
)"
NATIVE_PROOF_ACCOUNT_ADDRESS="${ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS:-${SETTLEMENT_ACCOUNT_ADDRESS}}"

invoke_contract "${COMMITMENT_REGISTRY_ADDRESS}" set_batch_registrar "${BATCH_REGISTRAR_ADDRESS}"
invoke_contract "${COMMITMENT_REGISTRY_ADDRESS}" set_privacy_deposit_bridge "${PRIVACY_DEPOSIT_BRIDGE_ADDRESS}"
invoke_contract "${COMMITMENT_REGISTRY_ADDRESS}" set_auction_verifier "${AUCTION_VERIFIER_ADDRESS}"
invoke_contract "${BATCH_REGISTRY_ADDRESS}" set_auction_verifier "${AUCTION_VERIFIER_ADDRESS}"
invoke_contract "${PRIVACY_DEPOSIT_BRIDGE_ADDRESS}" set_auction_verifier "${AUCTION_VERIFIER_ADDRESS}"
invoke_contract "${AUCTION_VERIFIER_ADDRESS}" set_pause_guardian "${PAUSE_GUARDIAN_ADDRESS}"
invoke_contract "${AUCTION_VERIFIER_ADDRESS}" set_authorized_settlement_account "${SETTLEMENT_ACCOUNT_ADDRESS}"
invoke_contract "${AUCTION_VERIFIER_ADDRESS}" set_shielded_asset_adapter "${PRIVACY_DEPOSIT_BRIDGE_ADDRESS}"
invoke_contract "${AUCTION_VERIFIER_ADDRESS}" set_deposit_root_registrar "${COMMITMENT_REGISTRY_ADDRESS}"
invoke_contract "${AUCTION_VERIFIER_ADDRESS}" set_protocol_fee_recipient "${PROTOCOL_FEE_RECIPIENT}"
invoke_contract "${AUCTION_VERIFIER_ADDRESS}" set_relay_fee_recipient "${RELAY_FEE_RECIPIENT}"
invoke_contract "${AUCTION_VERIFIER_ADDRESS}" set_proof_program "${NATIVE_PROOF_PROGRAM_ADDRESS}" "${NATIVE_PROOF_PROGRAM_HASH}"
for statement_kind in \
  "0x41444d495353494f4e" \
  "0x41554354494f4e5f524553554c54" \
  "0x4e554c4c4946494552" \
	  "0x52454e4557414c" \
	  "0x4c49515549444954595f504f534954494f4e" \
	  "0x534554544c454d454e54" \
	  "0x534554544c454d454e545f4f52444552" \
	  "0x534554544c454d454e545f494e5055545f4d454d42455253484950" \
	  "0x534554544c454d454e545f4f55545055545f5245434f56455259" \
	  "0x4e4f54455f434f4e534f4c49444154494f4e" \
	  "0x4147475245474154455f534554544c454d454e54" \
  "0x5749544844524157414c" \
  "0x4d554c54495f50414952"; do
  invoke_contract \
    "${AUCTION_VERIFIER_ADDRESS}" \
    set_statement_proof_program_hash \
    "${statement_kind}" \
    "${NATIVE_PROOF_PROGRAM_HASH}"
done
invoke_contract "${AUCTION_VERIFIER_ADDRESS}" set_expected_starknet_os_config_hash "${STARKNET_OS_CONFIG_HASH}"
invoke_contract "${AUCTION_VERIFIER_ADDRESS}" set_proof_validity_blocks "${PROOF_VALIDITY_BLOCKS}"
invoke_contract "${AUCTION_VERIFIER_ADDRESS}" set_output_claim_delay_seconds "${OUTPUT_CLAIM_DELAY_SECONDS}"
invoke_contract "${PRIVACY_DEPOSIT_BRIDGE_ADDRESS}" register_supported_asset "${STRK_ASSET_ID}" "${STRK_TOKEN_ADDRESS}"
invoke_contract "${PRIVACY_DEPOSIT_BRIDGE_ADDRESS}" register_supported_asset "${ETH_ASSET_ID}" "${ETH_TOKEN_ADDRESS}"
invoke_contract "${PRIVACY_DEPOSIT_BRIDGE_ADDRESS}" register_supported_asset "${USDC_ASSET_ID}" "${USDC_TOKEN_ADDRESS}"
invoke_contract "${PRIVACY_DEPOSIT_BRIDGE_ADDRESS}" register_supported_asset "${STRKBTC_ASSET_ID}" "${STRKBTC_TOKEN_ADDRESS}"
invoke_contract "${PRIVACY_DEPOSIT_BRIDGE_ADDRESS}" register_supported_asset "${WBTC_ASSET_ID}" "${WBTC_TOKEN_ADDRESS}"
invoke_contract "${PRIVACY_DEPOSIT_BRIDGE_ADDRESS}" register_supported_asset "${USDT_ASSET_ID}" "${USDT_TOKEN_ADDRESS}"

for pair_fee in \
  "STRK/USDC:4:0" \
  "ETH/USDC:4:0" \
  "strkBTC/USDC:4:0" \
  "STRK/ETH:4:0" \
  "STRK/strkBTC:4:0" \
  "WBTC/strkBTC:1:0" \
  "USDC/USDT:1:0"; do
  IFS=: read -r pair_id taker_fee relay_fee <<<"${pair_fee}"
  invoke_contract \
    "${AUCTION_VERIFIER_ADDRESS}" \
    set_pair_fee_config \
    "$(compute_pair_id "${pair_id}")" \
    "${taker_fee}" \
    "${relay_fee}"
done

if [[ "${LOCK_PROOF_PROGRAM_AFTER_DEPLOY}" == "true" ]]; then
  invoke_contract "${AUCTION_VERIFIER_ADDRESS}" lock_proof_program
fi
if [[ "${LOCK_OPERATIONAL_CONFIG_AFTER_DEPLOY}" == "true" ]]; then
  invoke_contract "${COMMITMENT_REGISTRY_ADDRESS}" lock_config
  invoke_contract "${BATCH_REGISTRY_ADDRESS}" lock_config
  invoke_contract "${PRIVACY_DEPOSIT_BRIDGE_ADDRESS}" lock_config
  invoke_contract "${AUCTION_VERIFIER_ADDRESS}" lock_operational_config
fi

python3 - "${ROOT_DIR}" "${EXISTING_MANIFEST_PATH}" "${RPC_URL}" "${PUBLIC_RPC_URL}" "${CHAIN_ID}" \
  "${COMMITMENT_REGISTRY_ADDRESS}" \
  "${BATCH_REGISTRY_ADDRESS}" \
  "${PRIVACY_DEPOSIT_BRIDGE_ADDRESS}" \
  "${AUCTION_VERIFIER_ADDRESS}" \
  "${NATIVE_PROOF_PROGRAM_ADDRESS}" \
  "${BATCH_REGISTRAR_ADDRESS}" \
  "${BATCH_REGISTRAR_PRIVATE_KEY}" \
  "${ACCOUNT_ADDRESS}" \
  "${DEFAULT_PUBLIC_KEY}" \
  "${STRK_ASSET_ID}" \
  "${ETH_ASSET_ID}" \
  "${USDC_ASSET_ID}" \
  "${STRKBTC_ASSET_ID}" \
  "${WBTC_ASSET_ID}" \
  "${USDT_ASSET_ID}" \
  "${STRK_TOKEN_ADDRESS}" \
  "${ETH_TOKEN_ADDRESS}" \
  "${USDC_TOKEN_ADDRESS}" \
  "${STRKBTC_TOKEN_ADDRESS}" \
  "${WBTC_TOKEN_ADDRESS}" \
  "${USDT_TOKEN_ADDRESS}" \
  "${PRIVACY_POOL_ADDRESS}" \
  "${PROOF_VALIDITY_BLOCKS}" \
  "${OUTPUT_CLAIM_DELAY_SECONDS}" \
  "${INITIAL_NOTE_ROOT}" \
  "${INITIAL_NULLIFIER_ROOT}" \
  "${INITIAL_RENEWAL_ROOT}" \
  "${INITIAL_FEE_ROOT}" \
  "${NATIVE_PROOF_PROGRAM_HASH}" \
  "${STARKNET_OS_CONFIG_HASH}" \
  "${NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_PROOF_ACCOUNT_ADDRESS}" \
  "${SETTLEMENT_ACCOUNT_ADDRESS}" \
  "${SETTLEMENT_ACCOUNT_PRIVATE_KEY}" \
  "${LOCK_PROOF_PROGRAM_AFTER_DEPLOY}" \
  "${LOCK_OPERATIONAL_CONFIG_AFTER_DEPLOY}" <<'PY'
import json, os, sys
from pathlib import Path

(
    root,
    existing_manifest_path,
    rpc_url,
    public_rpc_url,
    chain_id,
    commitment_registry,
    batch_registry,
    privacy_deposit_bridge,
    auction_verifier,
    native_proof_program_address,
    batch_registrar_address,
    batch_registrar_private_key,
    deployer_account_address,
    deployer_public_key,
    strk_asset_id,
    eth_asset_id,
    usdc_asset_id,
    strkbtc_asset_id,
    wbtc_asset_id,
    usdt_asset_id,
    strk_token_address,
    eth_token_address,
    usdc_token_address,
    strkbtc_token_address,
    wbtc_token_address,
    usdt_token_address,
    privacy_pool,
    proof_validity_blocks,
    output_claim_delay_seconds,
    initial_note_root,
    initial_nullifier_root,
    initial_renewal_root,
    initial_fee_root,
    proof_program_hash,
    starknet_os_config_hash,
    settlement_statement_program_address,
    settlement_note_fee_statement_program_address,
    settlement_order_statement_program_address,
    settlement_input_membership_statement_program_address,
    settlement_output_recovery_statement_program_address,
    nullifier_statement_program_address,
    renewal_statement_program_address,
    liquidity_position_statement_program_address,
    note_consolidation_statement_program_address,
    withdrawal_statement_program_address,
    admission_statement_program_address,
    auction_result_statement_program_address,
    multi_pair_statement_program_address,
    native_proof_account_address,
    settlement_account_address,
    settlement_account_private_key,
    proof_program_locked,
    operational_config_locked,
) = sys.argv[1:]

root = Path(root)
existing_path = Path(existing_manifest_path)
if existing_path.exists():
    manifest = json.loads(existing_path.read_text())
else:
    manifest = {}

contracts = {
    "commitment_registry": commitment_registry,
    "batch_registry": batch_registry,
    "shielded_asset_adapter": privacy_deposit_bridge,
    "privacy_deposit_bridge": privacy_deposit_bridge,
    "auction_verifier": auction_verifier,
}

token_addresses = {
    "STRK": strk_token_address,
    "ETH": eth_token_address,
    "USDC": usdc_token_address,
    "strkBTC": strkbtc_token_address,
    "WBTC": wbtc_token_address,
    "USDT": usdt_token_address,
}

source_funding = manifest.get("funding") if isinstance(manifest.get("funding"), dict) else {}
funding = {}
funding["primary"] = "starknet_privacy"
native_tx_prover_url = os.environ.get("ZYLITH_NATIVE_TX_PROVER_URL", "").strip()
source_privacy_config = source_funding.get("starknet_privacy") if isinstance(source_funding, dict) else None
if not isinstance(source_privacy_config, dict):
    source_privacy_config = {}
privacy_config = {}
privacy_config["privacy_pool"] = source_privacy_config.get("privacy_pool") or privacy_pool
privacy_config["bridge_adapter"] = privacy_deposit_bridge

def require_config_value(name, value):
    value = (value or "").strip() if isinstance(value, str) else value
    if not value:
        raise SystemExit(f"{name} is required for the Starknet Privacy funding rail")
    return value

privacy_config["discovery_url"] = (
    os.environ.get("ZYLITH_STARKNET_PRIVACY_PUBLIC_DISCOVERY_URL", "").strip()
    or os.environ.get("ZYLITH_STARKNET_PRIVACY_DISCOVERY_URL", "").strip()
    or source_privacy_config.get("discovery_url")
)
privacy_config["discovery_url"] = require_config_value(
    "ZYLITH_STARKNET_PRIVACY_PUBLIC_DISCOVERY_URL or funding.starknet_privacy.discovery_url",
    privacy_config["discovery_url"],
)
privacy_config["proving_url"] = (
    os.environ.get("ZYLITH_STARKNET_PRIVACY_PUBLIC_PROVING_URL", "").strip()
    or os.environ.get("ZYLITH_STARKNET_PRIVACY_PROVING_URL", "").strip()
    or source_privacy_config.get("proving_url")
    or native_tx_prover_url
)
privacy_config["proving_url"] = require_config_value(
    "ZYLITH_STARKNET_PRIVACY_PUBLIC_PROVING_URL or funding.starknet_privacy.proving_url",
    privacy_config["proving_url"],
)
privacy_config["paymaster_address"] = (
    os.environ.get("ZYLITH_STARKNET_PRIVACY_PAYMASTER_ADDRESS", "").strip()
    or os.environ.get("ZYLITH_PAYMASTER_ACCOUNT_ADDRESS", "").strip()
    or source_privacy_config.get("paymaster_address")
)
privacy_config["paymaster_address"] = require_config_value(
    "ZYLITH_STARKNET_PRIVACY_PAYMASTER_ADDRESS or funding.starknet_privacy.paymaster_address",
    privacy_config["paymaster_address"],
)
privacy_config["paymaster_url"] = (
    os.environ.get("ZYLITH_STARKNET_PRIVACY_PAYMASTER_URL", "").strip()
    or os.environ.get("ZYLITH_PAYMASTER_URL", "").strip()
    or source_privacy_config.get("paymaster_url")
)
privacy_config["paymaster_url"] = require_config_value(
    "ZYLITH_STARKNET_PRIVACY_PAYMASTER_URL or funding.starknet_privacy.paymaster_url",
    privacy_config["paymaster_url"],
)
proof_signer_class_hash = (
    os.environ.get("ZYLITH_STARKNET_PRIVACY_PROOF_SIGNER_CLASS_HASH", "").strip()
    or os.environ.get("ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH", "").strip()
    or source_privacy_config.get("proof_signer_class_hash")
)
privacy_config["proof_signer_class_hash"] = require_config_value(
    "ZYLITH_STARKNET_PRIVACY_PROOF_SIGNER_CLASS_HASH or funding.starknet_privacy.proof_signer_class_hash",
    proof_signer_class_hash,
)
ingress_fingerprint = (
    os.environ.get("ZYLITH_INGRESS_KEY_REGISTRY_PIN", "").strip()
    or os.environ.get("VITE_ZYLITH_INGRESS_KEY_REGISTRY_PIN", "").strip()
    or source_privacy_config.get("ingress_key_registry_fingerprint")
)
if ingress_fingerprint:
    privacy_config["ingress_key_registry_fingerprint"] = ingress_fingerprint
privacy_config["sdk_package"] = (
    source_privacy_config.get("sdk_package") or "@starkware-libs/starknet-privacy-sdk"
)
privacy_config["sdk_version"] = source_privacy_config.get("sdk_version") or "0.14.3-rc.0"
privacy_config["min_proving_delay_blocks"] = int(
    os.environ.get(
        "ZYLITH_STARKNET_PRIVACY_MIN_PROVING_DELAY_BLOCKS",
        source_privacy_config.get("min_proving_delay_blocks", 10),
    )
)
privacy_config["proving_ohttp_enabled"] = True
funding["starknet_privacy"] = privacy_config

proof = {}
proof["scheme"] = "native-starknet-proof-bearing-invoke-v3"
proof["proof_version"] = "PROOF1"
proof["settlement_statement_type"] = 1
proof["settlement_statement_schema"] = 1
proof["auction_statement_type"] = 2
proof["auction_statement_schema"] = 1
proof["settlement_entrypoint"] = "submit_settlement_with_proof_facts"
native_proof_entrypoint = os.environ.get(
    "ZYLITH_NATIVE_PROOF_ENTRYPOINT",
    "compile_settlement_proof",
).strip() or "compile_settlement_proof"
proof["proof_entrypoint"] = native_proof_entrypoint
proof["proof_program_address"] = native_proof_program_address
proof["proof_program_hash"] = proof_program_hash
statement_proof_program_hashes = {
    "ADMISSION": proof_program_hash,
    "AUCTION_RESULT": proof_program_hash,
    "NULLIFIER": proof_program_hash,
    "RENEWAL": proof_program_hash,
    "LIQUIDITY_POSITION": proof_program_hash,
    "SETTLEMENT": proof_program_hash,
    "SETTLEMENT_ORDER": proof_program_hash,
    "SETTLEMENT_INPUT_MEMBERSHIP": proof_program_hash,
    "SETTLEMENT_OUTPUT_RECOVERY": proof_program_hash,
    "NOTE_CONSOLIDATION": proof_program_hash,
    "AGGREGATE_SETTLEMENT": proof_program_hash,
    "WITHDRAWAL": proof_program_hash,
    "MULTI_PAIR": proof_program_hash,
}
proof["statement_proof_program_hashes"] = statement_proof_program_hashes
proof["admission_proof_program_hash"] = proof_program_hash
proof["auction_result_proof_program_hash"] = proof_program_hash
proof["nullifier_proof_program_hash"] = proof_program_hash
proof["renewal_proof_program_hash"] = proof_program_hash
proof["liquidity_position_proof_program_hash"] = proof_program_hash
proof["settlement_proof_program_hash"] = proof_program_hash
proof["settlement_order_proof_program_hash"] = proof_program_hash
proof["settlement_input_membership_proof_program_hash"] = proof_program_hash
proof["settlement_output_recovery_proof_program_hash"] = proof_program_hash
proof["note_consolidation_proof_program_hash"] = proof_program_hash
proof["aggregate_settlement_proof_program_hash"] = proof_program_hash
proof["withdrawal_proof_program_hash"] = proof_program_hash
proof["multi_pair_proof_program_hash"] = proof_program_hash
proof["starknet_os_config_hash"] = starknet_os_config_hash
if settlement_statement_program_address:
    proof["settlement_statement_program_address"] = settlement_statement_program_address
if settlement_note_fee_statement_program_address:
    proof["settlement_note_fee_statement_program_address"] = settlement_note_fee_statement_program_address
if settlement_order_statement_program_address:
    proof["settlement_order_statement_program_address"] = settlement_order_statement_program_address
if settlement_input_membership_statement_program_address:
    proof["settlement_input_membership_statement_program_address"] = settlement_input_membership_statement_program_address
if settlement_output_recovery_statement_program_address:
    proof["settlement_output_recovery_statement_program_address"] = settlement_output_recovery_statement_program_address
if nullifier_statement_program_address:
    proof["nullifier_statement_program_address"] = nullifier_statement_program_address
if renewal_statement_program_address:
    proof["renewal_statement_program_address"] = renewal_statement_program_address
if liquidity_position_statement_program_address:
    proof["liquidity_position_statement_program_address"] = liquidity_position_statement_program_address
if note_consolidation_statement_program_address:
    proof["note_consolidation_statement_program_address"] = note_consolidation_statement_program_address
if withdrawal_statement_program_address:
    proof["withdrawal_statement_program_address"] = withdrawal_statement_program_address
if admission_statement_program_address:
    proof["admission_statement_program_address"] = admission_statement_program_address
if auction_result_statement_program_address:
    proof["auction_result_statement_program_address"] = auction_result_statement_program_address
if multi_pair_statement_program_address:
    proof["multi_pair_statement_program_address"] = multi_pair_statement_program_address
proof["proof_account_address"] = native_proof_account_address
proof["settlement_account_address"] = settlement_account_address
proof["deposit_root_registrar_address"] = commitment_registry
proof["initial_note_root"] = initial_note_root
proof["initial_nullifier_root"] = initial_nullifier_root
proof["initial_renewal_root"] = initial_renewal_root
proof["initial_fee_root"] = initial_fee_root
proof["proof_validity_blocks"] = int(proof_validity_blocks)
proof["output_claim_delay_seconds"] = int(output_claim_delay_seconds)
proof["proof_program_locked_after_deploy"] = proof_program_locked == "true"
proof["operational_config_locked_after_deploy"] = operational_config_locked == "true"
proof["commitment_registry_config_locked_after_deploy"] = operational_config_locked == "true"
proof["batch_registry_config_locked_after_deploy"] = operational_config_locked == "true"
proof["privacy_deposit_bridge_config_locked_after_deploy"] = operational_config_locked == "true"
native_tx_prover_endpoint = native_tx_prover_url or privacy_config["proving_url"]
proof["native_tx_prover_url"] = native_tx_prover_endpoint
native_tx_prover_ohttp_key_config_hex = os.environ.get(
    "ZYLITH_NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX",
    "",
).strip()
proof["native_tx_prover_ohttp_enabled"] = True

asset_defs = {
    "STRK": {"token": strk_token_address, "decimals": 18, "pairs": ["STRK/ETH", "STRK/USDC", "STRK/strkBTC"]},
    "ETH": {"token": eth_token_address, "decimals": 18, "pairs": ["STRK/ETH", "ETH/USDC"]},
    "USDC": {"token": usdc_token_address, "decimals": 6, "pairs": ["STRK/USDC", "ETH/USDC", "strkBTC/USDC", "USDC/USDT"]},
    "strkBTC": {"token": strkbtc_token_address, "decimals": 8, "pairs": ["STRK/strkBTC", "strkBTC/USDC", "WBTC/strkBTC"]},
    "WBTC": {"token": wbtc_token_address, "decimals": 8, "pairs": ["WBTC/strkBTC"]},
    "USDT": {"token": usdt_token_address, "decimals": 6, "pairs": ["USDC/USDT"]},
}
pair_defs = {
    "STRK/USDC": ("STRK", "USDC", 4, 0),
    "ETH/USDC": ("ETH", "USDC", 4, 0),
    "strkBTC/USDC": ("strkBTC", "USDC", 4, 0),
    "STRK/ETH": ("STRK", "ETH", 4, 0),
    "STRK/strkBTC": ("STRK", "strkBTC", 4, 0),
    "WBTC/strkBTC": ("WBTC", "strkBTC", 1, 0),
    "USDC/USDT": ("USDC", "USDT", 1, 0),
}
product_pair_ids = ",".join(pair_defs.keys())
funding_assets = {}
for symbol, info in asset_defs.items():
    asset = dict(funding_assets.get(symbol) or {})
    asset["asset_id"] = symbol
    asset["token_address"] = info["token"]
    asset["rail_token_address"] = info["token"]
    asset["min_trade_amount"] = "1"
    asset["enabled_pairs"] = info["pairs"]
    funding_assets[symbol] = asset
funding["assets"] = funding_assets

product = {
    "assets": {
        symbol: {
            "asset_id": symbol,
            "token_address": info["token"],
            "min_trade_amount": "1",
            "decimals": info["decimals"],
            "enabled": True,
            "erc20_behavior": "vanilla-exact-delta",
            "audit_status": "approved",
        }
        for symbol, info in asset_defs.items()
    },
    "pairs": {
        pair_id: {
            "pair_id": pair_id,
            "base_asset_id": base_asset,
            "quote_asset_id": quote_asset,
            "min_order_amount": "1",
            "enabled": True,
            "taker_fee_bps": taker_fee,
            "relay_fee_bps": relay_fee,
            "heartbeat_cover_price": str(
                ((manifest.get("product") or {}).get("pairs") or {}).get(pair_id, {}).get(
                    "heartbeat_cover_price",
                    "1",
                )
            ),
        }
        for pair_id, (base_asset, quote_asset, taker_fee, relay_fee) in pair_defs.items()
    },
}

deployment = {
    **dict(manifest.get("deployment") or {}),
    "finalized": True,
}
release_commit = os.environ.get("ZYLITH_DEPLOYMENT_RELEASE_COMMIT", "").strip().lower()
if release_commit:
    deployment["release_commit"] = release_commit

manifest.update(
    {
        "deployment": deployment,
        "network": "sepolia",
        "rpc_url": public_rpc_url,
        "chain_id": chain_id,
        "contracts": contracts,
        "token_addresses": token_addresses,
        "funding": funding,
        "product": product,
        "proof": proof,
    }
)
(root / "client/public/deployment.json").write_text(json.dumps(manifest, indent=2) + "\n")
(root / ".deploy/sepolia-live.json").write_text(
    json.dumps(
        {
            "manifest": manifest,
            "deployer_account_address": deployer_account_address,
            "deployer_public_key": deployer_public_key,
            "settlement_account_address": settlement_account_address,
            "batch_registrar_account_address": batch_registrar_address,
            "asset_ids": {
                key: value
                for key, value in {
                    "STRK": strk_asset_id,
                    "ETH": eth_asset_id,
                    "USDC": usdc_asset_id,
                    "strkBTC": strkbtc_asset_id,
                    "WBTC": wbtc_asset_id,
                    "USDT": usdt_asset_id,
                }.items()
                if value
            },
            "token_addresses": manifest["token_addresses"],
        },
        indent=2,
    )
    + "\n"
)
prover_env_lines = [
    f"ZYLITH_STARKNET_RPC_URL={rpc_url}",
    f"ZYLITH_STARKNET_ACCOUNT_ADDRESS={settlement_account_address}",
    f"ZYLITH_STARKNET_PRIVATE_KEY={settlement_account_private_key}",
    f"ZYLITH_STARKNET_CHAIN_ID={chain_id}",
    f"ZYLITH_NATIVE_PROOF_ACCOUNT_ADDRESS={native_proof_account_address}",
    f"ZYLITH_NATIVE_PROOF_PROGRAM_ADDRESS={native_proof_program_address}",
    f"ZYLITH_NATIVE_PROOF_ENTRYPOINT={native_proof_entrypoint}",
    f"ZYLITH_NATIVE_PROOF_PROGRAM_HASH={proof_program_hash}",
    f"ZYLITH_STARKNET_OS_CONFIG_HASH={starknet_os_config_hash}",
    f"ZYLITH_AUCTION_VERIFIER_ADDRESS={auction_verifier}",
    f"ZYLITH_DEPOSIT_NOTE_ROOT_REGISTRAR_ADDRESS={commitment_registry}",
    f"ZYLITH_BATCH_REGISTRAR_ACCOUNT_ADDRESS={batch_registrar_address}",
    f"ZYLITH_BATCH_REGISTRAR_PRIVATE_KEY={batch_registrar_private_key}",
    f"ZYLITH_BATCH_REGISTRY_ADDRESS={batch_registry}",
    f"ZYLITH_INITIAL_NOTE_ROOT={initial_note_root}",
    f"ZYLITH_INITIAL_NULLIFIER_ROOT={initial_nullifier_root}",
    f"ZYLITH_INITIAL_RENEWAL_ROOT={initial_renewal_root}",
    f"ZYLITH_INITIAL_FEE_ROOT={initial_fee_root}",
    f"ZYLITH_PROOF_VALIDITY_BLOCKS={proof_validity_blocks}",
    f"ZYLITH_OUTPUT_CLAIM_DELAY_SECONDS={output_claim_delay_seconds}",
    f"ZYLITH_PRODUCT_PAIRS={product_pair_ids}",
    "ZYLITH_BATCH_WINDOW_MS=20000",
]
if settlement_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_SETTLEMENT_STATEMENT_PROGRAM_ADDRESS={settlement_statement_program_address}"
    )
if settlement_note_fee_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_SETTLEMENT_NOTE_FEE_STATEMENT_PROGRAM_ADDRESS={settlement_note_fee_statement_program_address}"
    )
if settlement_order_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_SETTLEMENT_ORDER_STATEMENT_PROGRAM_ADDRESS={settlement_order_statement_program_address}"
    )
if settlement_input_membership_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_SETTLEMENT_INPUT_MEMBERSHIP_STATEMENT_PROGRAM_ADDRESS={settlement_input_membership_statement_program_address}"
    )
if settlement_output_recovery_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_SETTLEMENT_OUTPUT_RECOVERY_STATEMENT_PROGRAM_ADDRESS={settlement_output_recovery_statement_program_address}"
    )
if nullifier_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS={nullifier_statement_program_address}"
    )
if renewal_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS={renewal_statement_program_address}"
    )
if liquidity_position_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS={liquidity_position_statement_program_address}"
    )
if note_consolidation_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS={note_consolidation_statement_program_address}"
    )
if withdrawal_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS={withdrawal_statement_program_address}"
    )
if admission_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS={admission_statement_program_address}"
    )
if auction_result_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS={auction_result_statement_program_address}"
    )
if multi_pair_statement_program_address:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS={multi_pair_statement_program_address}"
    )
prover_env_lines.insert(1, f"ZYLITH_NATIVE_TX_PROVER_URL={native_tx_prover_endpoint}")
if native_tx_prover_ohttp_key_config_hex:
    prover_env_lines.append(
        f"ZYLITH_NATIVE_TX_PROVER_OHTTP_KEY_CONFIG_HEX={native_tx_prover_ohttp_key_config_hex}"
    )
(root / ".deploy/sepolia.prover.env").write_text("\n".join(prover_env_lines + [""]))
PY

python3 - "${ROOT_DIR}" \
  "${WBTC_ASSET_ID}" \
  "${USDT_ASSET_ID}" \
  "${WBTC_TOKEN_ADDRESS}" \
  "${USDT_TOKEN_ADDRESS}" \
  "${NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS}" \
  "${NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS}" \
  "${PROTOCOL_FEE_RECIPIENT}" \
  "${RELAY_FEE_RECIPIENT}" \
  "${PAUSE_GUARDIAN_ADDRESS}" <<'PY'
import json
import sys
from pathlib import Path

(
    root,
    wbtc_asset_id,
    usdt_asset_id,
    wbtc_token_address,
    usdt_token_address,
    nullifier_statement_program_address,
    renewal_statement_program_address,
    liquidity_position_statement_program_address,
    note_consolidation_statement_program_address,
    withdrawal_statement_program_address,
    admission_statement_program_address,
    auction_result_statement_program_address,
    multi_pair_statement_program_address,
    protocol_fee_recipient,
    relay_fee_recipient,
    pause_guardian_address,
) = sys.argv[1:]

root = Path(root)

assets = {
    "STRK": {"asset_id": "STRK", "min_trade_amount": "1000000000000000000", "decimals": 18, "enabled": True},
    "ETH": {"asset_id": "ETH", "min_trade_amount": "1000000000000000", "decimals": 18, "enabled": True},
    "USDC": {"asset_id": "USDC", "min_trade_amount": "1000000", "decimals": 6, "enabled": True},
    "strkBTC": {"asset_id": "strkBTC", "min_trade_amount": "100000", "decimals": 8, "enabled": True},
    "WBTC": {"asset_id": "WBTC", "min_trade_amount": "100000", "decimals": 8, "enabled": True},
    "USDT": {"asset_id": "USDT", "min_trade_amount": "1000000", "decimals": 6, "enabled": True},
}

pairs = {
    "STRK/USDC": ("STRK", "USDC", "1000000000000000000", "1000000000000000000", 4, 0),
    "ETH/USDC": ("ETH", "USDC", "1000000000000000", "1000000000000000000", 4, 0),
    "strkBTC/USDC": ("strkBTC", "USDC", "100000", "100000000", 4, 0),
    "STRK/ETH": ("STRK", "ETH", "1000000000000000000", "1000000000000000000", 4, 0),
    "STRK/strkBTC": ("STRK", "strkBTC", "1000000000000000000", "1000000000000000000", 4, 0),
    "WBTC/strkBTC": ("WBTC", "strkBTC", "100000", "100000000", 1, 0),
    "USDC/USDT": ("USDC", "USDT", "1000000", "1000000", 1, 0),
}

asset_pairs = {asset: [] for asset in assets}
for pair_id, (base, quote, *_rest) in pairs.items():
    asset_pairs[base].append(pair_id)
    asset_pairs[quote].append(pair_id)

def update_manifest(data):
    manifest = data.get("manifest", data)
    token_addresses = dict(manifest.get("token_addresses") or {})
    token_addresses["WBTC"] = wbtc_token_address
    token_addresses["USDT"] = usdt_token_address
    manifest["token_addresses"] = token_addresses

    funding = dict(manifest.get("funding") or {})
    funding_assets = {}
    for symbol, asset in assets.items():
        token_address = token_addresses[symbol]
        funding_assets[symbol] = {
            "asset_id": symbol,
            "token_address": token_address,
            "rail_token_address": token_address,
            "min_trade_amount": asset["min_trade_amount"],
            "enabled_pairs": asset_pairs[symbol],
        }
    funding["assets"] = funding_assets
    manifest["funding"] = funding

    product_assets = {
        symbol: {
            **asset,
            "token_address": token_addresses[symbol],
            "erc20_behavior": "vanilla-exact-delta",
            "audit_status": "approved",
        }
        for symbol, asset in assets.items()
    }
    manifest["product"] = {
        "assets": product_assets,
        "pairs": {
            pair_id: {
                "pair_id": pair_id,
                "base_asset_id": base,
                "quote_asset_id": quote,
                "min_order_amount": min_order_amount,
                "price_base_scale": price_base_scale,
                "heartbeat_cover_price": str(
                    ((manifest.get("product") or {}).get("pairs") or {}).get(pair_id, {}).get(
                        "heartbeat_cover_price",
                        "1",
                    )
                ),
                "taker_fee_bps": taker_fee_bps,
                "relay_fee_bps": relay_fee_bps,
                "enabled": True,
            }
            for pair_id, (
                base,
                quote,
                min_order_amount,
                price_base_scale,
                taker_fee_bps,
                relay_fee_bps,
            )
            in pairs.items()
        },
    }

    proof = manifest.setdefault("proof", {})
    proof_program_hash = proof.get("proof_program_hash")
    if proof_program_hash:
        statement_proof_program_hashes = {
            "ADMISSION": proof_program_hash,
            "AUCTION_RESULT": proof_program_hash,
            "NULLIFIER": proof_program_hash,
            "RENEWAL": proof_program_hash,
            "LIQUIDITY_POSITION": proof_program_hash,
            "SETTLEMENT": proof_program_hash,
            "SETTLEMENT_ORDER": proof_program_hash,
            "SETTLEMENT_INPUT_MEMBERSHIP": proof_program_hash,
            "SETTLEMENT_OUTPUT_RECOVERY": proof_program_hash,
            "NOTE_CONSOLIDATION": proof_program_hash,
            "AGGREGATE_SETTLEMENT": proof_program_hash,
            "WITHDRAWAL": proof_program_hash,
            "MULTI_PAIR": proof_program_hash,
        }
        proof["statement_proof_program_hashes"] = statement_proof_program_hashes
        proof["admission_proof_program_hash"] = proof_program_hash
        proof["auction_result_proof_program_hash"] = proof_program_hash
        proof["nullifier_proof_program_hash"] = proof_program_hash
        proof["renewal_proof_program_hash"] = proof_program_hash
        proof["liquidity_position_proof_program_hash"] = proof_program_hash
        proof["settlement_proof_program_hash"] = proof_program_hash
        proof["settlement_order_proof_program_hash"] = proof_program_hash
        proof["settlement_input_membership_proof_program_hash"] = proof_program_hash
        proof["settlement_output_recovery_proof_program_hash"] = proof_program_hash
        proof["note_consolidation_proof_program_hash"] = proof_program_hash
        proof["aggregate_settlement_proof_program_hash"] = proof_program_hash
        proof["withdrawal_proof_program_hash"] = proof_program_hash
        proof["multi_pair_proof_program_hash"] = proof_program_hash
    if nullifier_statement_program_address:
        proof["nullifier_statement_program_address"] = nullifier_statement_program_address
    if renewal_statement_program_address:
        proof["renewal_statement_program_address"] = renewal_statement_program_address
    if liquidity_position_statement_program_address:
        proof["liquidity_position_statement_program_address"] = liquidity_position_statement_program_address
    if note_consolidation_statement_program_address:
        proof["note_consolidation_statement_program_address"] = note_consolidation_statement_program_address
    if withdrawal_statement_program_address:
        proof["withdrawal_statement_program_address"] = withdrawal_statement_program_address
    if admission_statement_program_address:
        proof["admission_statement_program_address"] = admission_statement_program_address
    if auction_result_statement_program_address:
        proof["auction_result_statement_program_address"] = auction_result_statement_program_address
    if multi_pair_statement_program_address:
        proof["multi_pair_statement_program_address"] = multi_pair_statement_program_address

    roles = dict(manifest.get("roles") or {})
    roles["protocol_fee_recipient"] = protocol_fee_recipient
    roles["relay_fee_recipient"] = relay_fee_recipient
    roles.pop("fee_claim_authority_address", None)
    roles["pause_guardian_address"] = pause_guardian_address
    manifest["roles"] = roles

    if "manifest" in data:
        data["manifest"] = manifest
    return data

for path in [root / "client/public/deployment.json", root / ".deploy/sepolia-live.json"]:
    data = json.loads(path.read_text())
    data = update_manifest(data)
    if path.name == "sepolia-live.json":
        data["asset_ids"] = {
            **data.get("asset_ids", {}),
            "WBTC": wbtc_asset_id,
            "USDT": usdt_asset_id,
        }
        data["token_addresses"] = data["manifest"]["token_addresses"]
    path.write_text(json.dumps(data, indent=2) + "\n")

env_path = root / ".deploy/sepolia.prover.env"
if env_path.exists():
    updates = {
        "ZYLITH_NATIVE_NULLIFIER_STATEMENT_PROGRAM_ADDRESS": nullifier_statement_program_address,
        "ZYLITH_NATIVE_RENEWAL_STATEMENT_PROGRAM_ADDRESS": renewal_statement_program_address,
        "ZYLITH_NATIVE_LIQUIDITY_POSITION_STATEMENT_PROGRAM_ADDRESS": liquidity_position_statement_program_address,
        "ZYLITH_NATIVE_NOTE_CONSOLIDATION_STATEMENT_PROGRAM_ADDRESS": note_consolidation_statement_program_address,
        "ZYLITH_NATIVE_WITHDRAWAL_STATEMENT_PROGRAM_ADDRESS": withdrawal_statement_program_address,
        "ZYLITH_NATIVE_ADMISSION_STATEMENT_PROGRAM_ADDRESS": admission_statement_program_address,
        "ZYLITH_NATIVE_AUCTION_RESULT_STATEMENT_PROGRAM_ADDRESS": auction_result_statement_program_address,
        "ZYLITH_NATIVE_MULTI_PAIR_STATEMENT_PROGRAM_ADDRESS": multi_pair_statement_program_address,
        "ZYLITH_PROTOCOL_FEE_RECIPIENT": protocol_fee_recipient,
        "ZYLITH_RELAY_FEE_RECIPIENT": relay_fee_recipient,
        "ZYLITH_PRODUCT_PAIRS": ",".join(pairs.keys()),
        "ZYLITH_BATCH_WINDOW_MS": "20000",
    }
    lines = []
    seen = set()
    for line in env_path.read_text().splitlines():
        key = line.split("=", 1)[0]
        if key in updates and updates[key]:
            lines.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            lines.append(line)
    for key, value in updates.items():
        if value and key not in seen:
            lines.append(f"{key}={value}")
    env_path.write_text("\n".join(lines) + "\n")
PY

cat <<EOF
Deployment complete.
CommitmentRegistry: ${COMMITMENT_REGISTRY_ADDRESS}
BatchRegistry: ${BATCH_REGISTRY_ADDRESS}
PrivacyDepositBridge: ${PRIVACY_DEPOSIT_BRIDGE_ADDRESS}
AuctionVerifier: ${AUCTION_VERIFIER_ADDRESS}
NativeProofProgram: ${NATIVE_PROOF_PROGRAM_ADDRESS}
StarknetOSConfigHash: ${STARKNET_OS_CONFIG_HASH}
SettlementAccount: ${SETTLEMENT_ACCOUNT_ADDRESS}
ProtocolFeeRecipient: ${PROTOCOL_FEE_RECIPIENT}
RelayFeeRecipient: ${RELAY_FEE_RECIPIENT}
PauseGuardian: ${PAUSE_GUARDIAN_ADDRESS}

Updated:
- client/public/deployment.json
- .deploy/sepolia-live.json
- .deploy/sepolia.prover.env
EOF
