#!/usr/bin/env bash
# deploys the exchange, its custody contracts and the proof program, wires them together and
# writes the deployment manifest. `deploy_sepolia.sh pin <proof_version> <virtual_program_hash>
# <os_config_hash>` later pins the proof program from the facts `zylith-prover bench` prints, and
# `deploy_sepolia.sh lock` freezes the configuration and finalizes the manifest.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS_DIR="${ROOT_DIR}/contracts"
PROOF_PROGRAM_DIR="${ROOT_DIR}/proof_program"
STATE_FILE="${ZYLITH_DEPLOY_STATE_FILE:-${ROOT_DIR}/.deploy/sepolia-live.json}"
MANIFEST_TEMPLATE="${ZYLITH_MANIFEST_TEMPLATE:-${ROOT_DIR}/client/public/deployment.example.json}"
CLIENT_MANIFEST="${ROOT_DIR}/client/public/deployment.json"

RPC_URL="${ZYLITH_STARKNET_RPC_URL:?ZYLITH_STARKNET_RPC_URL is required}"
ACCOUNTS_FILE="${ZYLITH_DEPLOY_ACCOUNTS_FILE:-${ROOT_DIR}/.deploy/sepolia.accounts.json}"
ACCOUNT_NAME="${ZYLITH_DEPLOY_ACCOUNT_NAME:-zylith-sepolia-deployer}"
RETRY_ATTEMPTS="${ZYLITH_SNCAST_RETRY_ATTEMPTS:-5}"
RETRY_DELAY_SECONDS="${ZYLITH_SNCAST_RETRY_DELAY_SECONDS:-10}"

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

state_field() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["contracts"][sys.argv[2]])' "${STATE_FILE}" "$1"
}

# the felt ids the exchange uses for manifest asset and pair names.
# the manifest pins the operator's execution key registry; wallets seal to nothing else.
execution_key_fingerprint() {
  if [[ -n "${ZYLITH_EXECUTION_KEY_FINGERPRINT:-}" ]]; then
    printf '%s\n' "${ZYLITH_EXECUTION_KEY_FINGERPRINT}"
  elif [[ -n "${ZYLITH_EXECUTION_KEYS_PATH:-}" ]]; then
    cargo run --quiet --manifest-path "${ROOT_DIR}/Cargo.toml" -p zylith-prover --bin zylith-prover -- fingerprint "${ZYLITH_EXECUTION_KEYS_PATH}"
  else
    die "set ZYLITH_EXECUTION_KEY_FINGERPRINT or ZYLITH_EXECUTION_KEYS_PATH to pin the execution keys"
  fi
}

ids() {
  cargo run --quiet --manifest-path "${ROOT_DIR}/Cargo.toml" -p zylith-prover --bin zylith-prover -- ids "$@"
}

case "${1:-deploy}" in
  pin)
    [[ "$#" -eq 4 ]] || { echo "usage: $0 pin <proof_version> <virtual_program_hash> <os_config_hash>" >&2; exit 1; }
    exchange="$(state_field exchange)"
    invoke "${exchange}" set_proof_program "$(state_field proof_program)" "$3"
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
    # a manifest is final only once the proof program is pinned and the contracts are locked.
    python3 - "${STATE_FILE}" <<'PY' || die "pin the proof program before locking"
import json, sys
data = json.load(open(sys.argv[1]))
proof = data.get("manifest", data)["proof"]
sys.exit(0 if int(proof.get("virtual_program_hash") or "0x0", 16) != 0 else 1)
PY
    for name in exchange commitment_registry privacy_deposit_bridge; do
      invoke "$(state_field "${name}")" lock_config
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

ADMIN="${ZYLITH_DEPLOY_ADMIN_ADDRESS:?ZYLITH_DEPLOY_ADMIN_ADDRESS is required}"
SETTLEMENT_ACCOUNT="${ZYLITH_SETTLEMENT_ACCOUNT_ADDRESS:?ZYLITH_SETTLEMENT_ACCOUNT_ADDRESS is required}"
PROOF_ACCOUNT="${ZYLITH_PROOF_ACCOUNT_ADDRESS:?ZYLITH_PROOF_ACCOUNT_ADDRESS is required}"
PRIVACY_POOL="${ZYLITH_STARKNET_PRIVACY_POOL_ADDRESS:?ZYLITH_STARKNET_PRIVACY_POOL_ADDRESS is required}"
REFERENCE_SIGNER="${ZYLITH_REFERENCE_PRICE_SIGNER_PUBLIC_KEY:?ZYLITH_REFERENCE_PRICE_SIGNER_PUBLIC_KEY is required}"
FEE_RECIPIENT="${ZYLITH_PROTOCOL_FEE_RECIPIENT:?ZYLITH_PROTOCOL_FEE_RECIPIENT is required}"
PAUSE_GUARDIAN="${ZYLITH_PAUSE_GUARDIAN_ADDRESS:-${ADMIN}}"
EKUBO_CORE="${ZYLITH_EKUBO_CORE_ADDRESS:-0x0444a09d96389aa7148f1aada508e30b71299ffe650d9c97fdaae38cb9a23384}"
EKUBO_ROUTER="${ZYLITH_EKUBO_ROUTER_ADDRESS:-0x0045f933adf0607292468ad1c1dedaa74d5ad166392590e72676a34d01d7b763}"
MAX_CLOSE_DELAY_MS="${ZYLITH_MAX_CLOSE_DELAY_MS:-60000}"
WITHDRAWAL_DELAY_SECONDS="${ZYLITH_WITHDRAWAL_DELAY_SECONDS:-120}"
PAIR_FEE_BPS="${ZYLITH_PAIR_FEE_BPS:-4}"
# symbol=token address for every asset the bridge custodies.
TOKENS="${ZYLITH_TOKENS:-STRK=0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d ETH=0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7 USDC=0x0512feAc6339Ff7889822cb5aA2a86C848e9D392bB0E3E237C008674feeD8343}"
# enabled markets come from the selected manifest unless an explicit subset is requested.
PAIRS="${ZYLITH_PAIRS:-$(python3 - "${MANIFEST_TEMPLATE}" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
print(" ".join(name for name, pair in manifest["product"]["pairs"].items() if pair.get("enabled")))
PY
)}"
[[ -n "${PAIRS}" ]] || die "the manifest has no enabled pairs"
# pairs whose unmatched remainder the operator routes through ekubo; empty keeps routing off.
EXTERNAL_PAIRS="${ZYLITH_EXTERNAL_PAIRS:-}"
# the window a capacity stays open for an external fill: nonzero exactly when a pair routes.
if [[ -n "${EXTERNAL_PAIRS}" ]]; then
  EXTERNAL_WINDOW_SECONDS="${ZYLITH_EXTERNAL_WINDOW_SECONDS:-30}"
  [[ "${EXTERNAL_WINDOW_SECONDS}" -gt 0 ]] || die "external pairs need a nonzero ZYLITH_EXTERNAL_WINDOW_SECONDS"
  for pair in ${EXTERNAL_PAIRS}; do
    [[ " ${PAIRS} " == *" ${pair} "* ]] || die "external pair ${pair} is not in ZYLITH_PAIRS"
  done
else
  EXTERNAL_WINDOW_SECONDS="${ZYLITH_EXTERNAL_WINDOW_SECONDS:-0}"
fi

# the manifest names the exact commit deployed, so the deployed code must be that commit.
if [[ "${ZYLITH_ALLOW_DIRTY_DEPLOY:-}" != "1" ]] && ! git -C "${ROOT_DIR}" diff --quiet HEAD --; then
  die "tracked files differ from HEAD; commit the release first (or set ZYLITH_ALLOW_DIRTY_DEPLOY=1 for a scratch deploy)"
fi
RELEASE_COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD)"

(cd "${CONTRACTS_DIR}" && scarb build)
(cd "${PROOF_PROGRAM_DIR}" && scarb build)

registry_class="$(declare_class "${CONTRACTS_DIR}" zylith_protocol CommitmentRegistry)"
bridge_class="$(declare_class "${CONTRACTS_DIR}" zylith_protocol PrivacyDepositBridge)"
exchange_class="$(declare_class "${CONTRACTS_DIR}" zylith_protocol Exchange)"
router_class="$(declare_class "${CONTRACTS_DIR}" zylith_protocol EkuboExternalMatchRouter)"
program_class="$(declare_class "${PROOF_PROGRAM_DIR}" zylith_proof_program ExchangeProofProgram)"

registry="$(deploy_class "${registry_class}" "${ADMIN}")"
bridge="$(deploy_class "${bridge_class}" "${ADMIN}" "${registry}" "${PRIVACY_POOL}")"
exchange="$(deploy_class "${exchange_class}" "${ADMIN}")"
router="$(deploy_class "${router_class}" "${EKUBO_CORE}" "${EKUBO_ROUTER}" "${exchange}" "${bridge}")"
proof_program="$(deploy_class "${program_class}")"

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
invoke "${exchange}" set_objective_numeraire "$(id_of USDC)"
invoke "${exchange}" set_timing "${MAX_CLOSE_DELAY_MS}" "${WITHDRAWAL_DELAY_SECONDS}" "${EXTERNAL_WINDOW_SECONDS}"
invoke "${exchange}" set_protocol_fee_recipient "${FEE_RECIPIENT}"
invoke "${exchange}" set_pause_guardian "${PAUSE_GUARDIAN}"
for pair in ${PAIRS}; do
  invoke "${exchange}" register_pair "$(id_of "${pair}")" "$(id_of "${pair%%/*}")" "$(id_of "${pair#*/}")" "${PAIR_FEE_BPS}"
done

KEY_FINGERPRINT="$(execution_key_fingerprint)"
[[ "${KEY_FINGERPRINT}" =~ ^[0-9a-f]{64}$ ]] || die "the execution key fingerprint must be 64 lowercase hex characters"
mkdir -p "$(dirname "${STATE_FILE}")"
python3 - "${MANIFEST_TEMPLATE}" "${STATE_FILE}" "${CLIENT_MANIFEST}" <<PY
import json, sys
template, state_path, client_path = sys.argv[1:]
manifest = json.load(open(template))
manifest["deployment"] = {"finalized": False, "release_commit": "${RELEASE_COMMIT}"}
manifest["rpc_url"] = "${ZYLITH_PUBLIC_STARKNET_RPC_URL:-${RPC_URL}}"
manifest["contracts"] = {
    "commitment_registry": "${registry}",
    "privacy_deposit_bridge": "${bridge}",
    "ekubo_external_match_router": "${router}",
    "exchange": "${exchange}",
}
tokens = dict(entry.split("=", 1) for entry in "${TOKENS}".split())
manifest["token_addresses"] = tokens
rail = manifest["funding"]["starknet_privacy"]
rail["privacy_pool"] = "${PRIVACY_POOL}"
rail["bridge_adapter"] = "${bridge}"
rail["ingress_key_registry_fingerprint"] = "${KEY_FINGERPRINT}"
rail.pop("ingress_key_registry_next_fingerprint", None)
manifest["funding"]["assets"] = {name: {**manifest["funding"]["assets"].get(name, {}), "asset_id": name, "token_address": token, "rail_token_address": token} for name, token in tokens.items()}
manifest["product"]["assets"] = {name: {**manifest["product"]["assets"].get(name, {}), "token_address": token} for name, token in tokens.items() if name in manifest["product"]["assets"]}
# the template's decimals and minimum sizes must describe these tokens: one asset name can be a
# different token, with different decimals, on another network.
import urllib.request
def token_decimals(token):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "starknet_call", "params": {"request": {"contract_address": token, "entry_point_selector": "0x004c4fb1ab068f6039d5780c68dd0fa2f8742cceb3426d19667778ca7f3518a9", "calldata": []}, "block_id": "latest"}}).encode()
    request = urllib.request.Request("${RPC_URL}", data=body, headers={"content-type": "application/json"})
    return int(json.load(urllib.request.urlopen(request, timeout=30))["result"][0], 16)
for name, token in tokens.items():
    asset = manifest["product"]["assets"].get(name)
    if asset is not None and token_decimals(token) != asset["decimals"]:
        sys.exit(f"{name} at {token} has {token_decimals(token)} decimals on chain, the template says {asset['decimals']}; fix its decimals and minimum sizes")
pairs = "${PAIRS}".split()
external = set("${EXTERNAL_PAIRS}".split())
manifest["product"]["pairs"] = {name: {**manifest["product"]["pairs"][name], "taker_fee_bps": int("${PAIR_FEE_BPS}"), "external_match_enabled": name in external} for name in pairs}
for asset in manifest["funding"]["assets"].values():
    asset["enabled_pairs"] = [pair for pair in pairs if asset["asset_id"] in pair.split("/")]
manifest["proof"].update({"proof_program_address": "${proof_program}", "proof_account_address": "${PROOF_ACCOUNT}", "settlement_account_address": "${SETTLEMENT_ACCOUNT}"})
manifest["roles"] = {"protocol_fee_recipient": "${FEE_RECIPIENT}", "pause_guardian_address": "${PAUSE_GUARDIAN}", "reference_price_signer": "${REFERENCE_SIGNER}"}
manifest["runtime"].update({"max_close_delay_ms": int("${MAX_CLOSE_DELAY_MS}"), "withdrawal_delay_seconds": int("${WITHDRAWAL_DELAY_SECONDS}"), "external_window_seconds": int("${EXTERNAL_WINDOW_SECONDS}")})
for path in (state_path, client_path):
    json.dump(manifest, open(path, "w"), indent=2)
    open(path, "a").write("\n")
PY
echo "deployed: exchange ${exchange}, registry ${registry}, bridge ${bridge}, router ${router}, proof program ${proof_program}"
echo "next: prove one transition with zylith-prover bench, then $0 pin <proof_version> <virtual_program_hash> <os_config_hash>, then $0 lock"
