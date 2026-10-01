#!/usr/bin/env bash
# deploys the exchange, its custody contracts and the proof programs, wires them together and
# writes the deployment manifest. `deploy_sepolia.sh pin <proof_version> <virtual_program_hash>
# <os_config_hash>` later pins the prover facts `zylith-operator bench` prints, and
# `deploy_sepolia.sh lock` freezes the configuration and finalizes the manifest.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS_DIR="${ROOT_DIR}/contracts"
PROOF_PROGRAM_DIR="${ROOT_DIR}/proof_program"
STATE_FILE="${ZYLITH_DEPLOY_STATE_FILE:-${ROOT_DIR}/.deploy/sepolia-live.json}"
DEPLOYMENT_TEMPLATE="${ZYLITH_DEPLOYMENT_TEMPLATE:-${ROOT_DIR}/client/public/deployment.example.json}"
MARKET_REGISTRY="${ZYLITH_MARKET_REGISTRY:-${ROOT_DIR}/config/market-registry.json}"
CLIENT_MANIFEST="${ROOT_DIR}/client/public/deployment.json"

RPC_URL="${ZYLITH_STARKNET_RPC_URL:?ZYLITH_STARKNET_RPC_URL is required}"
ACCOUNTS_FILE="${ZYLITH_DEPLOY_ACCOUNTS_FILE:-${ROOT_DIR}/.deploy/sepolia.accounts.json}"
ACCOUNT_NAME="${ZYLITH_DEPLOY_ACCOUNT_NAME:-zylith-sepolia-deployer}"
RETRY_ATTEMPTS="${ZYLITH_SNCAST_RETRY_ATTEMPTS:-5}"
RETRY_DELAY_SECONDS="${ZYLITH_SNCAST_RETRY_DELAY_SECONDS:-10}"
PROVER_BUILD_ID="${ZYLITH_PROVER_BUILD_ID:-}"

die() { echo "$1" >&2; exit 1; }
[[ -f "${ACCOUNTS_FILE}" ]] || die "accounts file not found: ${ACCOUNTS_FILE}"

retryable() {
  [[ "$1" == *"Unknown RPC error"* || "$1" == *"spec_version"* || "$1" == *"429"* ||
    "$1" == *"Too Many Requests"* || "$1" == *"error sending request"* ||
    "$1" == *"expected value at line 1 column 1"* ]]
}

# runs sncast in `dir` with retries on transient rpc failures and prints its output.
sncast_in() {
  local dir="$1" out status attempt
  shift
  for ((attempt = 1; attempt <= RETRY_ATTEMPTS; attempt++)); do
    set +e
    out="$(cd "${dir}" && sncast --wait --accounts-file "${ACCOUNTS_FILE}" --account "${ACCOUNT_NAME}" "$@" --url "${RPC_URL}" 2>&1)"
    status=$?
    set -e
    if [[ "${status}" -eq 0 ]] || ! retryable "${out}" || ((attempt == RETRY_ATTEMPTS)); then
      printf '%s\n' "${out}"
      return "${status}"
    fi
    echo "retrying sncast $1 after a transient rpc failure (${attempt}/${RETRY_ATTEMPTS})" >&2
    sleep "${RETRY_DELAY_SECONDS}"
  done
}

declare_class() {
  local dir="$1" package="$2" name="$3" out hash
  out="$(sncast_in "${dir}" declare --contract-name "${name}" --package "${package}" || true)"
  hash="$(printf '%s\n' "${out}" | sed -n -e 's/^Class Hash:[[:space:]]*//p' -e 's/.*class hash \(0x[0-9a-fA-F]*\) is already declared.*/\1/p' | head -1)"
  [[ -n "${hash}" ]] || { printf '%s\n' "${out}" >&2; echo "declaring ${name} failed" >&2; exit 1; }
  printf '%s' "${hash}"
}

deploy_class() {
  local class_hash="$1" out address
  shift
  if [[ "$#" -gt 0 ]]; then
    out="$(sncast_in "${CONTRACTS_DIR}" deploy --class-hash "${class_hash}" --constructor-calldata "$@")"
  else
    out="$(sncast_in "${CONTRACTS_DIR}" deploy --class-hash "${class_hash}")"
  fi
  address="$(printf '%s\n' "${out}" | sed -n 's/^Contract Address:[[:space:]]*//p' | head -1)"
  [[ -n "${address}" ]] || { printf '%s\n' "${out}" >&2; echo "deploying ${class_hash} failed" >&2; exit 1; }
  printf '%s' "${address}"
}

invoke() {
  local contract="$1" function="$2"
  shift 2
  echo "invoke ${function} on ${contract}" >&2
  if [[ "$#" -gt 0 ]]; then
    sncast_in "${CONTRACTS_DIR}" invoke --contract-address "${contract}" --function "${function}" --calldata "$@" > /dev/null
  else
    sncast_in "${CONTRACTS_DIR}" invoke --contract-address "${contract}" --function "${function}" > /dev/null
  fi
}

contract_address() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["contracts"][sys.argv[2]])' "${STATE_FILE}" "$1"
}

proof_field() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["proof"][sys.argv[2]])' "${STATE_FILE}" "$1"
}

# the felt ids the exchange uses for manifest asset and pair names.
# the manifest pins the operator's execution key registry; wallets seal to nothing else.
execution_key_fingerprint() {
  if [[ -n "${ZYLITH_EXECUTION_KEY_FINGERPRINT:-}" ]]; then
    printf '%s\n' "${ZYLITH_EXECUTION_KEY_FINGERPRINT}"
  elif [[ -n "${ZYLITH_EXECUTION_KEYS_PATH:-}" ]]; then
    cargo run --quiet --manifest-path "${ROOT_DIR}/Cargo.toml" -p zylith-operator --bin zylith-operator -- fingerprint "${ZYLITH_EXECUTION_KEYS_PATH}"
  else
    die "set ZYLITH_EXECUTION_KEY_FINGERPRINT or ZYLITH_EXECUTION_KEYS_PATH to pin the execution keys"
  fi
}

ids() {
  cargo run --quiet --manifest-path "${ROOT_DIR}/Cargo.toml" -p zylith-operator --bin zylith-operator -- ids "$@"
}

require_clean_release() {
  [[ -z "$(git -C "${ROOT_DIR}" status --porcelain=v1 --untracked-files=all)" ]] ||
    die "pinning or finalizing requires a clean release worktree"
  local release_commit
  release_commit="$(python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); print(data.get("manifest", data)["deployment"]["release_commit"])' "${STATE_FILE}")"
  [[ "${release_commit}" == "$(git -C "${ROOT_DIR}" rev-parse HEAD)" ]] ||
    die "deployment release commit does not match HEAD"
}

case "${1:-deploy}" in
  pin)
    [[ "$#" -eq 4 ]] || { echo "usage: $0 pin <proof_version> <virtual_program_hash> <os_config_hash>" >&2; exit 1; }
    require_clean_release
    exchange="$(contract_address exchange)"
    invoke "${exchange}" set_proof_programs \
      "$(proof_field transition_proof_program_address)" \
      "$(proof_field withdrawal_proof_program_address)" \
      "$(proof_field residual_recovery_proof_program_address)" \
      "$3"
    invoke "${exchange}" set_proof_validation "$2" "$4" "${ZYLITH_PROOF_VALIDITY_BLOCKS:-450}"
    python3 - "${STATE_FILE}" "${CLIENT_MANIFEST}" "$2" "$3" "$4" <<'PY'
import json, sys
state_path, client_path, version, program_hash, os_hash = sys.argv[1:]
for path in (state_path, client_path):
    data = json.load(open(path))
    manifest = data.get("manifest", data)
    manifest["proof"].update({"proof_version": version, "virtual_program_hash": program_hash, "starknet_os_config_hash": os_hash})
    json.dump(data, open(path, "w"), indent=2)
    open(path, "a").write("\n")
PY
    exit 0
    ;;
  lock)
    require_clean_release
    # a manifest is final only once the prover facts are pinned and the contracts are locked.
    python3 - "${STATE_FILE}" <<'PY' || die "pin the proof program before locking"
import json, sys
data = json.load(open(sys.argv[1]))
proof = data.get("manifest", data)["proof"]
sys.exit(0 if int(proof.get("virtual_program_hash") or "0x0", 16) != 0 else 1)
PY
    for name in exchange commitment_registry privacy_deposit_bridge; do
      invoke "$(contract_address "${name}")" lock_config
    done
    python3 - "${STATE_FILE}" "${CLIENT_MANIFEST}" <<'PY'
import json, sys
for path in sys.argv[1:]:
    data = json.load(open(path))
    manifest = data.get("manifest", data)
    manifest["proof"]["config_locked_after_deploy"] = True
    manifest["deployment"]["finalized"] = True
    json.dump(data, open(path, "w"), indent=2)
    open(path, "a").write("\n")
PY
    echo "locked; the manifest is final"
    exit 0
    ;;
  deploy) ;;
  *)
    echo "usage: $0 [deploy|pin|lock]" >&2
    exit 1
    ;;
esac

[[ -n "${PROVER_BUILD_ID}" ]] || die "ZYLITH_PROVER_BUILD_ID is required"
ADMIN="${ZYLITH_DEPLOY_ADMIN_ADDRESS:?ZYLITH_DEPLOY_ADMIN_ADDRESS is required}"
SETTLEMENT_ACCOUNT="${ZYLITH_SETTLEMENT_ACCOUNT_ADDRESS:?ZYLITH_SETTLEMENT_ACCOUNT_ADDRESS is required}"
PROOF_ACCOUNT_PUBLIC_KEY="${ZYLITH_PROOF_ACCOUNT_PUBLIC_KEY:?ZYLITH_PROOF_ACCOUNT_PUBLIC_KEY is required}"
PROOF_ACCOUNT_PRIVATE_KEY="${ZYLITH_PROOF_ACCOUNT_PRIVATE_KEY:?ZYLITH_PROOF_ACCOUNT_PRIVATE_KEY is required}"
derived_proof_public_key="$(
  ZYLITH_PROOF_ACCOUNT_PRIVATE_KEY="${PROOF_ACCOUNT_PRIVATE_KEY}" \
    cargo run --quiet --manifest-path "${ROOT_DIR}/Cargo.toml" -p zylith-operator --bin zylith-operator -- proof-public-key
)"
python3 -c 'import sys; raise SystemExit(0 if int(sys.argv[1], 0) == int(sys.argv[2], 0) else 1)' \
  "${PROOF_ACCOUNT_PUBLIC_KEY}" "${derived_proof_public_key}" ||
    die "the proof account public key does not match its private key"
PRIVACY_POOL="${ZYLITH_STARKNET_PRIVACY_POOL_ADDRESS:?ZYLITH_STARKNET_PRIVACY_POOL_ADDRESS is required}"
PRIVACY_DISCOVERY_URL="${ZYLITH_STARKNET_PRIVACY_DISCOVERY_URL:?ZYLITH_STARKNET_PRIVACY_DISCOVERY_URL is required}"
PRIVACY_PROVING_URL="${ZYLITH_STARKNET_PRIVACY_PROVING_URL:?ZYLITH_STARKNET_PRIVACY_PROVING_URL is required}"
PRIVACY_PAYMASTER_ADDRESS="${ZYLITH_STARKNET_PRIVACY_PAYMASTER_ADDRESS:?ZYLITH_STARKNET_PRIVACY_PAYMASTER_ADDRESS is required}"
PRIVACY_PAYMASTER_URL="${ZYLITH_STARKNET_PRIVACY_PAYMASTER_URL:?ZYLITH_STARKNET_PRIVACY_PAYMASTER_URL is required}"
PRIVACY_PROOF_SIGNER_CLASS_HASH="${ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH:?ZYLITH_PRIVACY_PROOF_SIGNER_CLASS_HASH is required}"
REFERENCE_SIGNER="${ZYLITH_REFERENCE_PRICE_SIGNER_PUBLIC_KEY:?ZYLITH_REFERENCE_PRICE_SIGNER_PUBLIC_KEY is required}"
FEE_RECIPIENT="${ZYLITH_PROTOCOL_FEE_RECIPIENT:?ZYLITH_PROTOCOL_FEE_RECIPIENT is required}"
PAUSE_GUARDIAN="${ZYLITH_PAUSE_GUARDIAN_ADDRESS:-${ADMIN}}"
EKUBO_CORE="${ZYLITH_EKUBO_CORE_ADDRESS:-0x0444a09d96389aa7148f1aada508e30b71299ffe650d9c97fdaae38cb9a23384}"
EKUBO_ROUTER="${ZYLITH_EKUBO_ROUTER_ADDRESS:-0x0045f933adf0607292468ad1c1dedaa74d5ad166392590e72676a34d01d7b763}"
EPOCH_MS="${ZYLITH_EPOCH_MS:-$(python3 - "${DEPLOYMENT_TEMPLATE}" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
print(manifest["runtime"]["epoch_ms"])
PY
)}"
MAX_CLOSE_DELAY_MS="${ZYLITH_MAX_CLOSE_DELAY_MS:-60000}"
WITHDRAWAL_DELAY_SECONDS="${ZYLITH_WITHDRAWAL_DELAY_SECONDS:-120}"
[[ -f "${MARKET_REGISTRY}" ]] || die "market registry not found: ${MARKET_REGISTRY}"
cargo run -q --manifest-path "${ROOT_DIR}/Cargo.toml" -p zylith-core \
  --example market_registry -- "${MARKET_REGISTRY}" --check >/dev/null
registry_value() {
  python3 - "${MARKET_REGISTRY}" "$1" <<'PY'
import json, sys
registry, field = json.load(open(sys.argv[1])), sys.argv[2]
assets = [asset for asset in registry["assets"] if asset["enabled"]]
markets = [market for market in registry["markets"] if market["enabled"]]
values = {
    "tokens": " ".join(f'{asset["asset_id"]}={asset["token_address"]}' for asset in assets),
    "pairs": " ".join(market["market_id"] for market in markets),
    "external_pairs": " ".join(market["market_id"] for market in markets if market["capabilities"]["external_matching"]),
    "objective_numeraire": registry["objective_numeraire_asset_id"],
    "registry_hash_high": int(registry["registry_hash"][:32], 16),
    "registry_hash_low": int(registry["registry_hash"][32:], 16),
}
print(values[field])
PY
}
TOKENS="$(registry_value tokens)"
PAIRS="$(registry_value pairs)"
EXTERNAL_PAIRS="$(registry_value external_pairs)"
OBJECTIVE_NUMERAIRE="$(registry_value objective_numeraire)"
REGISTRY_HASH_HIGH="$(registry_value registry_hash_high)"
REGISTRY_HASH_LOW="$(registry_value registry_hash_low)"
[[ -n "${TOKENS}" && -n "${PAIRS}" ]] || die "the market registry has no enabled assets or markets"
if [[ -n "${EXTERNAL_PAIRS}" ]]; then
  EXTERNAL_WINDOW_SECONDS="${ZYLITH_EXTERNAL_WINDOW_SECONDS:-30}"
  [[ "${EXTERNAL_WINDOW_SECONDS}" -gt 0 ]] || die "external markets need a nonzero external window"
else
  EXTERNAL_WINDOW_SECONDS="${ZYLITH_EXTERNAL_WINDOW_SECONDS:-0}"
  [[ "${EXTERNAL_WINDOW_SECONDS}" -eq 0 ]] || die "external window must be zero when no registry market enables external matching"
fi

market_field() {
  python3 - "${MARKET_REGISTRY}" "$1" "$2" <<'PY'
import json, sys
registry, market_id, field = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
market = next((market for market in registry["markets"] if market["market_id"] == market_id), None)
if market is None:
    sys.exit(f"unknown registry market {market_id}")
value = market
for part in field.split("."):
    value = value[part]
print(str(value).lower() if isinstance(value, bool) else value)
PY
}

# the manifest names the exact commit deployed, so the deployed code must be that commit.
if [[ "${ZYLITH_ALLOW_DIRTY_DEPLOY:-}" != "1" ]] && [[ -n "$(git -C "${ROOT_DIR}" status --porcelain=v1 --untracked-files=all)" ]]; then
  die "tracked or untracked files differ from HEAD; commit the release first (or set ZYLITH_ALLOW_DIRTY_DEPLOY=1 for a scratch deploy)"
fi
RELEASE_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)"

(cd "${CONTRACTS_DIR}" && scarb build)
(cd "${PROOF_PROGRAM_DIR}" && scarb build)

registry_class="$(declare_class "${CONTRACTS_DIR}" zylith_protocol CommitmentRegistry)"
bridge_class="$(declare_class "${CONTRACTS_DIR}" zylith_protocol PrivacyDepositBridge)"
exchange_class="$(declare_class "${CONTRACTS_DIR}" zylith_protocol Exchange)"
router_class=""
if [[ -n "${EXTERNAL_PAIRS}" ]]; then
  router_class="$(declare_class "${CONTRACTS_DIR}" zylith_protocol EkuboExternalMatchRouter)"
fi
transition_program_class="$(declare_class "${PROOF_PROGRAM_DIR}" zylith_proof_program TransitionProofProgram)"
withdrawal_program_class="$(declare_class "${PROOF_PROGRAM_DIR}" zylith_proof_program WithdrawalProofProgram)"
residual_recovery_program_class="$(declare_class "${PROOF_PROGRAM_DIR}" zylith_proof_program ResidualRecoveryProofProgram)"
proof_account_class="$(declare_class "${PROOF_PROGRAM_DIR}" zylith_proof_program ProofAccount)"

registry="$(deploy_class "${registry_class}" "${ADMIN}")"
bridge="$(deploy_class "${bridge_class}" "${ADMIN}" "${registry}" "${PRIVACY_POOL}")"
exchange="$(deploy_class "${exchange_class}" "${ADMIN}")"
router="0x0"
if [[ -n "${EXTERNAL_PAIRS}" ]]; then
  router="$(deploy_class "${router_class}" "${EKUBO_CORE}" "${EKUBO_ROUTER}" "${exchange}" "${bridge}")"
fi
transition_proof_program="$(deploy_class "${transition_program_class}")"
withdrawal_proof_program="$(deploy_class "${withdrawal_program_class}")"
residual_recovery_proof_program="$(deploy_class "${residual_recovery_program_class}")"
proof_account="$(deploy_class \
  "${proof_account_class}" \
  "${PROOF_ACCOUNT_PUBLIC_KEY}" \
  "${transition_proof_program}" \
  "${withdrawal_proof_program}" \
  "${residual_recovery_proof_program}")"

invoke "${registry}" set_privacy_deposit_bridge "${bridge}"
invoke "${registry}" set_exchange "${exchange}"
invoke "${bridge}" set_exchange "${exchange}"
token_names=()
for entry in ${TOKENS}; do token_names+=("${entry%%=*}"); done
IDS="$(ids "${token_names[@]}" ${PAIRS})"
id_of() { printf '%s\n' "${IDS}" | sed -n "s|^$1=||p"; }
for entry in ${TOKENS}; do
  invoke "${bridge}" register_supported_asset "$(id_of "${entry%%=*}")" "${entry#*=}"
done
invoke "${exchange}" set_custody "${bridge}" "${registry}" "${router}"
invoke "${exchange}" set_settlement_account "${SETTLEMENT_ACCOUNT}"
invoke "${exchange}" set_reference_signer "${REFERENCE_SIGNER}"
invoke "${exchange}" set_objective_numeraire "$(id_of "${OBJECTIVE_NUMERAIRE}")"
invoke "${exchange}" set_market_registry_hash "${REGISTRY_HASH_HIGH}" "${REGISTRY_HASH_LOW}"
invoke "${exchange}" set_timing "${EPOCH_MS}" "${MAX_CLOSE_DELAY_MS}" "${WITHDRAWAL_DELAY_SECONDS}" "${EXTERNAL_WINDOW_SECONDS}"
invoke "${exchange}" set_protocol_fee_recipient "${FEE_RECIPIENT}"
invoke "${exchange}" set_pause_guardian "${PAUSE_GUARDIAN}"
for pair in ${PAIRS}; do
  reference_methodology="$(market_field "${pair}" reference_price.methodology)"
  if [[ "${reference_methodology}" == "direct_bbo_midpoint" ]]; then
    reference_args=(0 0 0 0)
  elif [[ "${reference_methodology}" == "synthetic_cross_bbo_midpoint" ]]; then
    reference_args=(
      1
      "$(id_of "$(market_field "${pair}" reference_price.base_market_id)")"
      "$(id_of "$(market_field "${pair}" reference_price.quote_market_id)")"
      "$(market_field "${pair}" reference_price.max_leg_skew_ms)"
    )
  else
    die "unsupported reference methodology ${reference_methodology} for ${pair}"
  fi
  invoke "${exchange}" register_pair "$(id_of "${pair}")" "$(id_of "${pair%%/*}")" "$(id_of "${pair#*/}")" "$(market_field "${pair}" price_base_scale)" "$(market_field "${pair}" taker_fee_bps)" "${reference_args[@]}"
  if [[ " ${EXTERNAL_PAIRS} " == *" ${pair} "* ]]; then
    invoke "${exchange}" set_pair_external_support "$(id_of "${pair}")" "$(market_field "${pair}" external_settlement_support_quote)"
  fi
done

KEY_FINGERPRINT="$(execution_key_fingerprint)"
[[ "${KEY_FINGERPRINT}" =~ ^[0-9a-f]{64}$ ]] || die "the execution key fingerprint must be 64 lowercase hex characters"
mkdir -p "$(dirname "${STATE_FILE}")"
python3 - "${DEPLOYMENT_TEMPLATE}" "${MARKET_REGISTRY}" "${STATE_FILE}" "${CLIENT_MANIFEST}" <<PY
import json, sys
template, registry_path, state_path, client_path = sys.argv[1:]
manifest = json.load(open(template))
registry = json.load(open(registry_path))
manifest["deployment"] = {"finalized": False, "release_commit": "${RELEASE_COMMIT}"}
manifest["rpc_url"] = "${ZYLITH_PUBLIC_STARKNET_RPC_URL:-${RPC_URL}}"
manifest["network"] = registry["network"]
manifest["chain_id"] = registry["chain_id"]
manifest["market_registry"] = registry
manifest["contracts"] = {
    "commitment_registry": "${registry}",
    "privacy_deposit_bridge": "${bridge}",
    "ekubo_external_match_router": "${router}",
    "exchange": "${exchange}",
}
rail = manifest["funding"]["starknet_privacy"]
rail["privacy_pool"] = "${PRIVACY_POOL}"
rail["bridge_adapter"] = "${bridge}"
rail["discovery_url"] = "${PRIVACY_DISCOVERY_URL}"
rail["proving_url"] = "${PRIVACY_PROVING_URL}"
rail["paymaster_address"] = "${PRIVACY_PAYMASTER_ADDRESS}"
rail["paymaster_url"] = "${PRIVACY_PAYMASTER_URL}"
rail["proof_signer_class_hash"] = "${PRIVACY_PROOF_SIGNER_CLASS_HASH}"
rail["ingress_key_registry_fingerprint"] = "${KEY_FINGERPRINT}"
rail.pop("ingress_key_registry_next_fingerprint", None)
# the registry's decimals and minimum sizes must describe these exact deployed tokens.
import urllib.request
def token_decimals(token):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "starknet_call", "params": {"request": {"contract_address": token, "entry_point_selector": "0x004c4fb1ab068f6039d5780c68dd0fa2f8742cceb3426d19667778ca7f3518a9", "calldata": []}, "block_id": "latest"}}).encode()
    request = urllib.request.Request("${RPC_URL}", data=body, headers={"content-type": "application/json"})
    return int(json.load(urllib.request.urlopen(request, timeout=30))["result"][0], 16)
for asset in registry["assets"]:
    if asset["enabled"] and token_decimals(asset["token_address"]) != asset["decimals"]:
        sys.exit(f'{asset["asset_id"]} at {asset["token_address"]} does not match registry decimals {asset["decimals"]}')
manifest["proof"].update({"transition_proof_program_address": "${transition_proof_program}", "withdrawal_proof_program_address": "${withdrawal_proof_program}", "residual_recovery_proof_program_address": "${residual_recovery_proof_program}", "proof_account_address": "${proof_account}", "settlement_account_address": "${SETTLEMENT_ACCOUNT}", "config_locked_after_deploy": False, "prover_build_id": "${PROVER_BUILD_ID}"})
manifest["roles"] = {"protocol_fee_recipient": "${FEE_RECIPIENT}", "pause_guardian_address": "${PAUSE_GUARDIAN}", "reference_price_signer": "${REFERENCE_SIGNER}"}
manifest["runtime"].update({"epoch_ms": int("${EPOCH_MS}"), "max_close_delay_ms": int("${MAX_CLOSE_DELAY_MS}"), "withdrawal_delay_seconds": int("${WITHDRAWAL_DELAY_SECONDS}"), "external_window_seconds": int("${EXTERNAL_WINDOW_SECONDS}")})
for path in (state_path, client_path):
    json.dump(manifest, open(path, "w"), indent=2)
    open(path, "a").write("\n")
PY
echo "deployed: exchange ${exchange}, registry ${registry}, bridge ${bridge}, router ${router}, transition proof program ${transition_proof_program}, withdrawal proof program ${withdrawal_proof_program}, residual recovery proof program ${residual_recovery_proof_program}, proof account ${proof_account}"
echo "next: prove one transition with zylith-operator bench, then $0 pin <proof_version> <virtual_program_hash> <os_config_hash>, then $0 lock"
