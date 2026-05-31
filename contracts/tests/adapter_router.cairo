use core::integer::u256;
use core::poseidon::{hades_permutation, poseidon_hash_span};
use core::traits::TryInto;
use snforge_std::signature::stark_curve::{
    StarkCurveKeyPair, StarkCurveKeyPairImpl, StarkCurveSignerImpl,
};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_block_number, cheat_block_timestamp,
    cheat_chain_id, cheat_proof_facts, declare, start_cheat_caller_address,
    stop_cheat_caller_address,
};
use starknet::account::Call;
use starknet::{ContractAddress, SyscallResultTrait};
use zylith_protocol::auction_verifier::{
    IAuctionVerifierDispatcher, IAuctionVerifierDispatcherTrait, ProofFacts,
};
use zylith_protocol::batch_registry::{IBatchRegistryDispatcher, IBatchRegistryDispatcherTrait};
use zylith_protocol::commitment_registry::{
    ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
};
use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
use zylith_protocol::fee_ledger::{IFeeLedgerDispatcher, IFeeLedgerDispatcherTrait};
use zylith_protocol::privacy_deposit_bridge::{
    IPrivacyDepositBridgeDispatcher, IPrivacyDepositBridgeDispatcherTrait,
};
use zylith_protocol::privacy_proof_signer::{
    IPrivacyProofSignerDispatcher, IPrivacyProofSignerDispatcherTrait,
};
use zylith_protocol::shielded_asset_adapter::{
    IShieldedAssetAdapterDispatcher, IShieldedAssetAdapterDispatcherTrait,
};
use zylith_protocol::types::BatchStatus;
use crate::mock_erc20::{IMockERC20Dispatcher, IMockERC20DispatcherTrait};

const ASSET_ID: felt252 = 'USDC';
const NOTE_COMMITMENT: felt252 = 0x12345;
const PRIVACY_POOL: felt252 = 0x999;
const VIRTUAL_SNOS: felt252 = 'VIRTUAL_SNOS';
const VIRTUAL_SNOS0: felt252 = 'VIRTUAL_SNOS0';
const TEST_PROOF_PROGRAM_HASH: felt252 = 0x987654321;
const ADMISSION_MESSAGE_DOMAIN: felt252 = 'zylith_admit_v1';
const AUCTION_RESULT_MESSAGE_DOMAIN: felt252 = 'zylith_aucres_v1';
const NULLIFIER_MESSAGE_DOMAIN: felt252 = 'zylith_null_v1';
const RENEWAL_MESSAGE_DOMAIN: felt252 = 'zylith_renew_v1';
const NOTE_CONSOLIDATION_MESSAGE_DOMAIN: felt252 = 'zylith_consol_v1';
const PUBLIC_NOTE_CONSOLIDATION_DOMAIN: felt252 = 0x7a796c6974685f6e6f74655f636f6e736f6c5f7631;
const RENEWAL_PARENT_CANCEL_DOMAIN: felt252 =
    0x26f84b60309c08d4030876815edb467f89f78e5a5f62823af4521f1be502ca3;
const ROOT_ONLY_STATE_TRANSITION_DOMAIN: felt252 =
    0x01f14f0555b0b80fd6af9553623a021c472d8c930dfcb5b204b35b26f0d2b1b2;
const RENEWAL_CHILD_ROOT_DOMAIN: felt252 =
    0x03fa9bd33f1b9d3e1a22d77d4dc7ea4d33abd249f7585d0e451b0fafa39dfc43;
const RENEWAL_SPARSE_LEAF_DOMAIN: felt252 =
    0x03fd7c748b95292c230aa528dc391912cd4557ad3e157e94ab06b22af433f967;
const OUTPUT_NOTE_LEAF_DOMAIN: felt252 =
    0x0f0c89949c6cba4ac7f170f7f00809b458b997f2e394481c7ab58cc68aa49b3;
const OUTPUT_NOTE_NODE_DOMAIN: felt252 =
    0x03c6998f476a618431be1c1764a6724f13c0739be395bab4c1217bc0a65b2ee7;
const OUTPUT_WITHDRAWAL_DOMAIN: felt252 =
    0x031ff5b95d48149e26b5a946562ff5ea925eb8b3ea09d3b389b209b672a37b6e;
const DEPOSIT_NOTE_ROOT_DOMAIN: felt252 = 0x7a796c6974685f6465706f7369745f6e6f74655f726f6f745f7631;
const CONSUMED_NULLIFIER_ROOT_DOMAIN: felt252 =
    0x052259833b97a525483b8fff0635ce1f9fdfd08b5a8db2486d4a05378989b0f0;
const FEE_ROOT_DOMAIN: felt252 = 0x079a9e0b9d4a6b4cac728c0e5f6298e37533fa1348f020f3575a78c5adf7d44b;
const TEST_CHAIN_ID: felt252 = 'SN_SEPOLIA';
const WRONG_CHAIN_ID: felt252 = 'SN_MAIN';
const TEST_PRICE_BASE_SCALE: u128 = 1;
const TEST_TAKER_FEE_BPS: u128 = 4;
const TEST_MAKER_FEE_BPS: u128 = 0;
const TEST_RELAY_FEE_BPS: u128 = 2;
const TEST_PROTOCOL_FEE_RECIPIENT: felt252 =
    0x02478731e01081aa57abe958afa8c29dfa83032c10d647a63b0394c23beb6192;
const TEST_RELAY_FEE_RECIPIENT: felt252 =
    0x02c79e77ef9014bbed5e612f86f8e011b05450aa9b7821d97c281cb2ac6d29a;
const TEST_BASE_ASSET_ID: felt252 = 0x5354524b;
const TEST_QUOTE_ASSET_ID: felt252 = 0x55534443;

fn deploy_commitment_registry(admin: ContractAddress) -> ContractAddress {
    let class = declare("CommitmentRegistry").unwrap().contract_class();
    let calldata = array![admin.into()];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_mock_erc20() -> ContractAddress {
    let class = declare("MockERC20").unwrap().contract_class();
    let calldata = array![];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_shielded_asset_adapter(admin: ContractAddress) -> ContractAddress {
    let class = declare("ShieldedAssetAdapter").unwrap().contract_class();
    let calldata = array![admin.into()];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_batch_registry(
    admin: ContractAddress, batch_registrar: ContractAddress,
) -> ContractAddress {
    let class = declare("BatchRegistry").unwrap().contract_class();
    let calldata = array![admin.into(), batch_registrar.into()];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_fee_ledger(admin: ContractAddress) -> ContractAddress {
    let class = declare("FeeLedger").unwrap().contract_class();
    let calldata = array![admin.into()];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_privacy_deposit_bridge(
    commitment_registry: ContractAddress, shielded_asset_adapter: ContractAddress,
) -> ContractAddress {
    let class = declare("PrivacyDepositBridge").unwrap().contract_class();
    let calldata = array![commitment_registry.into(), shielded_asset_adapter.into(), PRIVACY_POOL];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_privacy_proof_signer(signer_public_key: felt252) -> ContractAddress {
    let class = declare("PrivacyProofSigner").unwrap().contract_class();
    let calldata = array![signer_public_key];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_auction_verifier(
    admin: ContractAddress, batch_registry: ContractAddress,
) -> ContractAddress {
    let verifier_class = declare("AuctionVerifier").unwrap().contract_class();
    let verifier_calldata = array![admin.into(), batch_registry.into()];
    let (verifier_address, _) = verifier_class.deploy(@verifier_calldata).unwrap_syscall();

    let verifier = IAuctionVerifierDispatcher { contract_address: verifier_address };
    start_cheat_caller_address(verifier_address, admin);
    verifier.set_proof_program(verifier_address, TEST_PROOF_PROGRAM_HASH);
    verifier.set_protocol_fee_recipient(TEST_PROTOCOL_FEE_RECIPIENT);
    verifier.set_relay_fee_recipient(TEST_RELAY_FEE_RECIPIENT);
    verifier.set_pair_fee_config(0x888, TEST_TAKER_FEE_BPS, TEST_MAKER_FEE_BPS, TEST_RELAY_FEE_BPS);
    verifier.set_pair_fee_config(0x889, TEST_TAKER_FEE_BPS, TEST_MAKER_FEE_BPS, TEST_RELAY_FEE_BPS);
    verifier
        .set_pair_fee_config(0x1888, TEST_TAKER_FEE_BPS, TEST_MAKER_FEE_BPS, TEST_RELAY_FEE_BPS);
    verifier
        .set_pair_fee_config(0x2888, TEST_TAKER_FEE_BPS, TEST_MAKER_FEE_BPS, TEST_RELAY_FEE_BPS);
    stop_cheat_caller_address(verifier_address);
    verifier_address
}

#[test]
fn auction_verifier_guardian_can_pause_and_admin_can_unpause() {
    let admin = as_address(0x111);
    let guardian = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_pause_guardian(guardian);
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(auction_verifier, guardian);
    verifier.pause();
    stop_cheat_caller_address(auction_verifier);
    assert(verifier.is_paused(), 'NOT_PAUSED');

    start_cheat_caller_address(auction_verifier, admin);
    verifier.unpause();
    stop_cheat_caller_address(auction_verifier);
    assert(!verifier.is_paused(), 'STILL_PAUSED');
}

#[test]
#[should_panic]
fn auction_verifier_pause_blocks_admission_recording() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    verifier.pause();
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.record_admission_root_with_proof_facts(1, 2, 3);
}

#[test]
fn auction_verifier_admin_rotation_accepts_new_admin() {
    let admin = as_address(0x111);
    let new_admin = as_address(0x222);
    let guardian = as_address(0x333);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.propose_admin(new_admin);
    stop_cheat_caller_address(auction_verifier);
    assert(verifier.admin_transfer_pending(), 'NO_TRANSFER');
    assert(verifier.pending_admin_address() == new_admin, 'BAD_PENDING_ADMIN');

    start_cheat_caller_address(auction_verifier, new_admin);
    verifier.accept_admin();
    verifier.set_pause_guardian(guardian);
    stop_cheat_caller_address(auction_verifier);

    assert(verifier.admin_address() == new_admin, 'BAD_ADMIN');
    assert(!verifier.admin_transfer_pending(), 'TRANSFER_STILL_PENDING');
    assert(verifier.pause_guardian_address() == guardian, 'BAD_GUARDIAN');
}

#[test]
#[should_panic]
fn auction_verifier_old_admin_loses_authority_after_rotation() {
    let admin = as_address(0x111);
    let new_admin = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.propose_admin(new_admin);
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(auction_verifier, new_admin);
    verifier.accept_admin();
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_pause_guardian(as_address(0x333));
}

#[test]
#[should_panic]
fn auction_verifier_rejects_fee_config_above_protocol_cap() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_pair_fee_config(0x888, 101, 0, 0);
}

#[test]
#[should_panic]
fn auction_verifier_rejects_direct_pair_fee_reconfiguration() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_pair_fee_config(0x888, 5, 0, TEST_RELAY_FEE_BPS);
}

#[test]
#[should_panic]
fn auction_verifier_rejects_early_pair_fee_execution() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    cheat_block_timestamp(auction_verifier, 1_000, CheatSpan::TargetCalls(1));
    verifier.propose_pair_fee_config(0x888, 5, 0, TEST_RELAY_FEE_BPS);
    cheat_block_timestamp(auction_verifier, 87_399, CheatSpan::TargetCalls(1));
    verifier.execute_pair_fee_config(0x888);
}

#[test]
fn auction_verifier_timelocks_pair_fee_reconfiguration() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    cheat_block_timestamp(auction_verifier, 1_000, CheatSpan::TargetCalls(1));
    verifier.propose_pair_fee_config(0x888, 5, 0, TEST_RELAY_FEE_BPS);
    stop_cheat_caller_address(auction_verifier);

    let (pending_taker, pending_maker, pending_relay, eta, active) = verifier
        .pending_pair_fee_config(0x888);
    assert(pending_taker == 5, 'BAD_PENDING_TAKER');
    assert(pending_maker == 0, 'BAD_PENDING_MAKER');
    assert(pending_relay == TEST_RELAY_FEE_BPS, 'BAD_PENDING_RELAY');
    assert(eta == 87_400, 'BAD_PAIR_FEE_ETA');
    assert(active, 'PAIR_FEE_NOT_PENDING');

    start_cheat_caller_address(auction_verifier, admin);
    cheat_block_timestamp(auction_verifier, 87_400, CheatSpan::TargetCalls(1));
    verifier.execute_pair_fee_config(0x888);
    stop_cheat_caller_address(auction_verifier);

    let (taker, maker, relay, configured) = verifier.pair_fee_config(0x888);
    assert(taker == 5, 'BAD_TAKER');
    assert(maker == 0, 'BAD_MAKER');
    assert(relay == TEST_RELAY_FEE_BPS, 'BAD_RELAY');
    assert(configured, 'PAIR_FEE_UNSET');
    let (_pending_taker, _pending_maker, _pending_relay, _eta, active_after) = verifier
        .pending_pair_fee_config(0x888);
    assert(!active_after, 'PAIR_FEE_STILL_PENDING');
}

#[test]
#[should_panic]
fn auction_verifier_rejects_direct_protocol_fee_recipient_change() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_protocol_fee_recipient(TEST_PROTOCOL_FEE_RECIPIENT + 1);
}

#[test]
#[should_panic]
fn auction_verifier_rejects_early_protocol_fee_recipient_execution() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    cheat_block_timestamp(auction_verifier, 1_000, CheatSpan::TargetCalls(1));
    verifier.propose_protocol_fee_recipient(TEST_PROTOCOL_FEE_RECIPIENT + 1);
    cheat_block_timestamp(auction_verifier, 605_799, CheatSpan::TargetCalls(1));
    verifier.execute_protocol_fee_recipient();
}

#[test]
fn auction_verifier_timelocks_protocol_fee_recipient_change() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let new_recipient = TEST_PROTOCOL_FEE_RECIPIENT + 1;

    start_cheat_caller_address(auction_verifier, admin);
    cheat_block_timestamp(auction_verifier, 1_000, CheatSpan::TargetCalls(1));
    verifier.propose_protocol_fee_recipient(new_recipient);
    stop_cheat_caller_address(auction_verifier);

    let (pending, eta, active) = verifier.pending_protocol_fee_recipient();
    assert(pending == new_recipient, 'BAD_PENDING_RECIPIENT');
    assert(eta == 605_800, 'BAD_RECIPIENT_ETA');
    assert(active, 'RECIPIENT_NOT_PENDING');

    start_cheat_caller_address(auction_verifier, admin);
    cheat_block_timestamp(auction_verifier, 605_800, CheatSpan::TargetCalls(1));
    verifier.execute_protocol_fee_recipient();
    stop_cheat_caller_address(auction_verifier);

    assert(verifier.protocol_fee_recipient() == new_recipient, 'BAD_FEE_RECIPIENT');
    let (_pending, _eta, active_after) = verifier.pending_protocol_fee_recipient();
    assert(!active_after, 'RECIPIENT_STILL_PENDING');
}

#[test]
#[should_panic]
fn auction_verifier_rejects_claim_delay_above_protocol_cap() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_output_claim_delay_seconds(604801);
}

#[test]
#[should_panic]
fn auction_verifier_rejects_proof_program_change_after_lock() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.lock_proof_program();
    assert(verifier.proof_program_is_locked(), 'NOT_LOCKED');
    verifier.set_proof_program(as_address(0x555), TEST_PROOF_PROGRAM_HASH + 1);
}

fn authorize_privacy_deposit_bridge(
    admin: ContractAddress,
    commitment_registry: ContractAddress,
    shielded_asset_adapter: ContractAddress,
    privacy_deposit_bridge: ContractAddress,
) {
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_privacy_deposit_bridge(privacy_deposit_bridge);
    stop_cheat_caller_address(commitment_registry);

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.set_privacy_deposit_bridge(privacy_deposit_bridge);
    stop_cheat_caller_address(shielded_asset_adapter);
}

fn as_address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn as_u256(value: u128) -> u256 {
    u256 { low: value, high: 0 }
}

fn poseidon_hash2(x: felt252, y: felt252) -> felt252 {
    let (result, _, _) = hades_permutation(x, y, 2);
    result
}

fn withdraw_authority_public_key(index: felt252) -> felt252 {
    0x100000 + index
}

fn withdrawal_message_hash_for_domain(
    note_commitment: felt252,
    recipient: ContractAddress,
    shielded_asset_adapter: ContractAddress,
    chain_id: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(
        0x008c9bee4df79ca43188c02c21699eee1b86520e8bbe0291c437af32d37ff0e4, chain_id,
    );
    state = poseidon_hash2(state, shielded_asset_adapter.into());
    state = poseidon_hash2(state, note_commitment);
    state = poseidon_hash2(state, recipient.into());
    state
}

fn output_note_leaf(
    note_commitment: felt252, asset_id: felt252, amount: u128, withdraw_authority: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(OUTPUT_NOTE_LEAF_DOMAIN, note_commitment);
    state = poseidon_hash2(state, asset_id);
    state = poseidon_hash2(state, amount.into());
    poseidon_hash2(state, withdraw_authority)
}

fn output_note_node(left: felt252, right: felt252) -> felt252 {
    poseidon_hash2(poseidon_hash2(OUTPUT_NOTE_NODE_DOMAIN, left), right)
}

fn output_withdrawal_message_hash_for_verifier(
    auction_verifier: ContractAddress,
    shielded_asset_adapter: ContractAddress,
    chain_id: felt252,
    batch_id: felt252,
    note_commitment: felt252,
    asset_id: felt252,
    amount: u128,
    recipient: ContractAddress,
) -> felt252 {
    let mut state = poseidon_hash2(OUTPUT_WITHDRAWAL_DOMAIN, chain_id);
    state = poseidon_hash2(state, auction_verifier.into());
    state = poseidon_hash2(state, shielded_asset_adapter.into());
    state = poseidon_hash2(state, batch_id);
    state = poseidon_hash2(state, note_commitment);
    state = poseidon_hash2(state, asset_id);
    state = poseidon_hash2(state, amount.into());
    poseidon_hash2(state, recipient.into())
}

fn setup_adapter_with_deposited_note(
    note_commitment: felt252, withdraw_authority: felt252,
) -> (ContractAddress, ContractAddress, ContractAddress, ContractAddress) {
    let admin = as_address(0x111);
    let owner = as_address(0x222);
    let token_address = deploy_mock_erc20();
    let commitment_registry = deploy_commitment_registry(admin);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let privacy_deposit_bridge = deploy_privacy_deposit_bridge(
        commitment_registry, shielded_asset_adapter,
    );
    authorize_privacy_deposit_bridge(
        admin, commitment_registry, shielded_asset_adapter, privacy_deposit_bridge,
    );

    let token = IMockERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: privacy_deposit_bridge };

    token.mint(privacy_deposit_bridge, as_u256(1_000));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    privacy_invoke_single(bridge, ASSET_ID, 500, 7, note_commitment, withdraw_authority);
    stop_cheat_caller_address(privacy_deposit_bridge);

    (token_address, shielded_asset_adapter, owner, privacy_deposit_bridge)
}

fn privacy_invoke_single(
    bridge: IPrivacyDepositBridgeDispatcher,
    asset_id: felt252,
    amount: u128,
    deposit_nonce: u64,
    note_commitment: felt252,
    withdraw_authority: felt252,
) {
    bridge
        .privacy_invoke(
            asset_id,
            amount,
            array![amount].span(),
            array![deposit_nonce].span(),
            array![note_commitment].span(),
            array![withdraw_authority].span(),
        );
}

fn native_settlement_message_hash(
    auction_verifier_address: ContractAddress, transcript_commitment: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(
        0x326c16c927e3e9e1e2cb23ce296a3e7f3d21e798e34d6cac00f9b1241fdfc3a,
        auction_verifier_address.into(),
    );
    state = poseidon_hash2(state, transcript_commitment);
    state
}

fn native_nullifier_message_hash(
    auction_verifier_address: ContractAddress,
    transcript_commitment: felt252,
    prior_nullifier_root: felt252,
    consumed_nullifier_root: felt252,
    new_nullifier_root: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(NULLIFIER_MESSAGE_DOMAIN, auction_verifier_address.into());
    state = poseidon_hash2(state, transcript_commitment);
    state = poseidon_hash2(state, prior_nullifier_root);
    state = poseidon_hash2(state, consumed_nullifier_root);
    poseidon_hash2(state, new_nullifier_root)
}

fn native_renewal_message_hash(
    auction_verifier_address: ContractAddress,
    transcript_commitment: felt252,
    prior_renewal_root: felt252,
    renewal_child_root: felt252,
    new_renewal_root: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(RENEWAL_MESSAGE_DOMAIN, auction_verifier_address.into());
    state = poseidon_hash2(state, transcript_commitment);
    state = poseidon_hash2(state, prior_renewal_root);
    state = poseidon_hash2(state, renewal_child_root);
    poseidon_hash2(state, new_renewal_root)
}

fn native_note_consolidation_message_hash(
    auction_verifier_address: ContractAddress, consolidation_commitment: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(
        NOTE_CONSOLIDATION_MESSAGE_DOMAIN, auction_verifier_address.into(),
    );
    poseidon_hash2(state, consolidation_commitment)
}

fn native_auction_result_message_hash(
    auction_verifier_address: ContractAddress,
    batch_id: felt252,
    order_commitment_root: felt252,
    admission_root: felt252,
    transcript_commitment: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(AUCTION_RESULT_MESSAGE_DOMAIN, auction_verifier_address.into());
    state = poseidon_hash2(state, batch_id);
    state = poseidon_hash2(state, order_commitment_root);
    state = poseidon_hash2(state, admission_root);
    poseidon_hash2(state, transcript_commitment)
}

fn native_admission_message_hash(
    auction_verifier_address: ContractAddress,
    batch_id: felt252,
    order_commitment_root: felt252,
    admission_root: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(ADMISSION_MESSAGE_DOMAIN, auction_verifier_address.into());
    state = poseidon_hash2(state, batch_id);
    state = poseidon_hash2(state, order_commitment_root);
    poseidon_hash2(state, admission_root)
}

fn admission_proof_message_hash(
    proof_program_address: ContractAddress, statement_message_hash: felt252,
) -> felt252 {
    let mut l1_message_data = array![proof_program_address.into(), 0];
    l1_message_data.append(2);
    l1_message_data.append(ADMISSION_MESSAGE_DOMAIN);
    l1_message_data.append(statement_message_hash);
    poseidon_hash_span(l1_message_data.span())
}

fn auction_result_proof_message_hash(
    proof_program_address: ContractAddress, statement_message_hash: felt252,
) -> felt252 {
    let mut l1_message_data = array![proof_program_address.into(), 0];
    l1_message_data.append(2);
    l1_message_data.append(AUCTION_RESULT_MESSAGE_DOMAIN);
    l1_message_data.append(statement_message_hash);
    poseidon_hash_span(l1_message_data.span())
}

fn nullifier_proof_message_hash(
    proof_program_address: ContractAddress, statement_message_hash: felt252,
) -> felt252 {
    let mut l1_message_data = array![proof_program_address.into(), 0];
    l1_message_data.append(2);
    l1_message_data.append(NULLIFIER_MESSAGE_DOMAIN);
    l1_message_data.append(statement_message_hash);
    poseidon_hash_span(l1_message_data.span())
}

fn renewal_proof_message_hash(
    proof_program_address: ContractAddress, statement_message_hash: felt252,
) -> felt252 {
    let mut l1_message_data = array![proof_program_address.into(), 0];
    l1_message_data.append(2);
    l1_message_data.append(RENEWAL_MESSAGE_DOMAIN);
    l1_message_data.append(statement_message_hash);
    poseidon_hash_span(l1_message_data.span())
}

fn note_consolidation_proof_message_hash(
    proof_program_address: ContractAddress, statement_message_hash: felt252,
) -> felt252 {
    let mut l1_message_data = array![proof_program_address.into(), 0];
    l1_message_data.append(2);
    l1_message_data.append(NOTE_CONSOLIDATION_MESSAGE_DOMAIN);
    l1_message_data.append(statement_message_hash);
    poseidon_hash_span(l1_message_data.span())
}

fn public_note_consolidation_commitment(
    consolidation_id: felt252,
    output_bundle_ref: felt252,
    prior_note_root: felt252,
    prior_nullifier_root: felt252,
    consumed_note_root: felt252,
    consumed_nullifier_root: felt252,
    output_note_root: felt252,
    new_note_root: felt252,
    new_nullifier_root: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(PUBLIC_NOTE_CONSOLIDATION_DOMAIN, consolidation_id);
    state = poseidon_hash2(state, output_bundle_ref);
    state = poseidon_hash2(state, prior_note_root);
    state = poseidon_hash2(state, prior_nullifier_root);
    state = poseidon_hash2(state, consumed_note_root);
    state = poseidon_hash2(state, consumed_nullifier_root);
    state = poseidon_hash2(state, output_note_root);
    state = poseidon_hash2(state, new_note_root);
    poseidon_hash2(state, new_nullifier_root)
}

fn record_split_auction_proofs(
    auction_verifier: ContractAddress,
    verifier: IAuctionVerifierDispatcher,
    settlement_account: ContractAddress,
    batch_id: felt252,
    order_commitment_root: felt252,
    admission_root: felt252,
    transcript_commitment: felt252,
) {
    let admission_statement = native_admission_message_hash(
        auction_verifier, batch_id, order_commitment_root, admission_root,
    );
    let admission_proof_message = admission_proof_message_hash(
        auction_verifier, admission_statement,
    );
    let admission_proof_facts = valid_proof_facts(99, admission_proof_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, admission_proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .record_admission_root_with_proof_facts(batch_id, order_commitment_root, admission_root);

    let auction_statement = native_auction_result_message_hash(
        auction_verifier, batch_id, order_commitment_root, admission_root, transcript_commitment,
    );
    let auction_proof_message = auction_result_proof_message_hash(
        auction_verifier, auction_statement,
    );
    let auction_proof_facts = valid_proof_facts(99, auction_proof_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, auction_proof_facts.span(), CheatSpan::TargetCalls(1));
    verifier
        .record_auction_result_with_proof_facts(
            batch_id, order_commitment_root, admission_root, transcript_commitment,
        );
    stop_cheat_caller_address(auction_verifier);
}

fn record_root_transition_proofs(
    auction_verifier: ContractAddress,
    verifier: IAuctionVerifierDispatcher,
    settlement_account: ContractAddress,
    batch_id: felt252,
    transcript_commitment: felt252,
    prior_nullifier_root: felt252,
    consumed_nullifier_root: felt252,
    new_nullifier_root: felt252,
    prior_renewal_root: felt252,
    renewal_child_root: felt252,
    new_renewal_root: felt252,
) {
    let nullifier_statement = native_nullifier_message_hash(
        auction_verifier,
        transcript_commitment,
        prior_nullifier_root,
        consumed_nullifier_root,
        new_nullifier_root,
    );
    let nullifier_proof_message = nullifier_proof_message_hash(
        auction_verifier, nullifier_statement,
    );
    let nullifier_proof_facts = valid_proof_facts(99, nullifier_proof_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, nullifier_proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .record_nullifier_roots_with_proof_facts(
            batch_id,
            transcript_commitment,
            prior_nullifier_root,
            consumed_nullifier_root,
            new_nullifier_root,
        );

    let renewal_statement = native_renewal_message_hash(
        auction_verifier,
        transcript_commitment,
        prior_renewal_root,
        renewal_child_root,
        new_renewal_root,
    );
    let renewal_proof_message = renewal_proof_message_hash(auction_verifier, renewal_statement);
    let renewal_proof_facts = valid_proof_facts(99, renewal_proof_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, renewal_proof_facts.span(), CheatSpan::TargetCalls(1));
    verifier
        .record_renewal_roots_with_proof_facts(
            batch_id,
            transcript_commitment,
            prior_renewal_root,
            renewal_child_root,
            new_renewal_root,
        );
    stop_cheat_caller_address(auction_verifier);
}

fn renewal_parent_cancel_marker_message_hash_for_verifier(
    auction_verifier: ContractAddress, chain_id: felt252, cancel_marker: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(RENEWAL_PARENT_CANCEL_DOMAIN, chain_id);
    state = poseidon_hash2(state, auction_verifier.into());
    poseidon_hash2(state, cancel_marker)
}

fn empty_public_settlement_commitment(
    batch_id: felt252,
    pair_id: felt252,
    batch_epoch: u64,
    order_commitment_root: felt252,
    encrypted_order_set_commitment: felt252,
    clearing_price: u128,
    output_bundle_ref: felt252,
) -> felt252 {
    let empty_nullifiers = array![];
    let empty_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, empty_nullifiers.span(),
    );
    let empty_renewal_root = empty_renewal_child_root();
    let empty_new_root = root_only_state_transition(0, 0);
    let empty_new_renewal_root = 0;
    let empty_new_nullifier_root = 0;
    root_only_public_settlement_commitment(
        batch_id,
        pair_id,
        batch_epoch,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        empty_nullifier_root,
        empty_renewal_root,
        0,
        0,
        empty_new_root,
        empty_new_nullifier_root,
        empty_new_renewal_root,
        empty_new_root,
    )
}

fn root_only_state_transition(prior_root: felt252, batch_root: felt252) -> felt252 {
    poseidon_hash2(poseidon_hash2(ROOT_ONLY_STATE_TRANSITION_DOMAIN, prior_root), batch_root)
}

fn deposit_note_root(note_commitment: felt252) -> felt252 {
    poseidon_hash2(poseidon_hash2(DEPOSIT_NOTE_ROOT_DOMAIN, note_commitment), 1)
}

fn single_field_root(domain: felt252, values: Span<felt252>) -> felt252 {
    let mut state = domain;
    let mut index = 0;
    loop {
        if index == values.len() {
            break;
        }
        state = poseidon_hash2(state, *values.at(index));
        index += 1;
    }
    poseidon_hash2(state, values.len().into())
}

fn empty_renewal_child_root() -> felt252 {
    let empty = array![];
    single_field_root(RENEWAL_CHILD_ROOT_DOMAIN, empty.span())
}

fn empty_fee_root() -> felt252 {
    poseidon_hash2(FEE_ROOT_DOMAIN, 0)
}

fn normalized_fee_root(fee_root: felt252) -> felt252 {
    if fee_root == 0 {
        return empty_fee_root();
    }
    fee_root
}

fn normalized_new_fee_root(
    prior_fee_root: felt252, fee_root: felt252, new_fee_root: felt252,
) -> felt252 {
    if fee_root == 0 && new_fee_root == root_only_state_transition(prior_fee_root, 0) {
        return root_only_state_transition(prior_fee_root, empty_fee_root());
    }
    new_fee_root
}

fn root_only_public_settlement_commitment(
    batch_id: felt252,
    pair_id: felt252,
    batch_epoch: u64,
    order_commitment_root: felt252,
    encrypted_order_set_commitment: felt252,
    clearing_price: u128,
    output_bundle_ref: felt252,
    prior_note_root: felt252,
    prior_nullifier_root: felt252,
    prior_renewal_root: felt252,
    prior_fee_root: felt252,
    consumed_note_root: felt252,
    consumed_nullifier_root: felt252,
    renewal_child_root: felt252,
    output_note_root: felt252,
    fee_root: felt252,
    new_note_root: felt252,
    new_nullifier_root: felt252,
    new_renewal_root: felt252,
    new_fee_root: felt252,
) -> felt252 {
    let bound_fee_root = normalized_fee_root(fee_root);
    let bound_new_fee_root = normalized_new_fee_root(prior_fee_root, fee_root, new_fee_root);
    let mut state = poseidon_hash2(
        0x283f626418aa97a073f64500f7e35dd8bf7c01ff8611917c3c38e5be92eb205, batch_id,
    );
    state = poseidon_hash2(state, pair_id);
    state = poseidon_hash2(state, batch_epoch.into());
    state = poseidon_hash2(state, order_commitment_root);
    state = poseidon_hash2(state, encrypted_order_set_commitment);
    state = poseidon_hash2(state, clearing_price.into());
    state = poseidon_hash2(state, TEST_PRICE_BASE_SCALE.into());
    state = poseidon_hash2(state, TEST_TAKER_FEE_BPS.into());
    state = poseidon_hash2(state, TEST_MAKER_FEE_BPS.into());
    state = poseidon_hash2(state, TEST_RELAY_FEE_BPS.into());
    state = poseidon_hash2(state, TEST_PROTOCOL_FEE_RECIPIENT);
    state = poseidon_hash2(state, TEST_RELAY_FEE_RECIPIENT);
    state = poseidon_hash2(state, output_bundle_ref);
    state = poseidon_hash2(state, prior_note_root);
    state = poseidon_hash2(state, prior_nullifier_root);
    state = poseidon_hash2(state, prior_renewal_root);
    state = poseidon_hash2(state, prior_fee_root);
    state = poseidon_hash2(state, consumed_note_root);
    state = poseidon_hash2(state, consumed_nullifier_root);
    state = poseidon_hash2(state, renewal_child_root);
    state = poseidon_hash2(state, output_note_root);
    state = poseidon_hash2(state, bound_fee_root);
    state = poseidon_hash2(state, new_note_root);
    state = poseidon_hash2(state, new_nullifier_root);
    state = poseidon_hash2(state, new_renewal_root);
    state = poseidon_hash2(state, bound_new_fee_root);
    state
}

fn submit_root_settlement(
    verifier: IAuctionVerifierDispatcher,
    batch_id: felt252,
    order_commitment_root: felt252,
    encrypted_order_set_commitment: felt252,
    transcript_commitment: felt252,
    proof_artifact_commitment: felt252,
    clearing_price: u128,
    output_bundle_ref: felt252,
    prior_note_root: felt252,
    prior_nullifier_root: felt252,
    prior_renewal_root: felt252,
    prior_fee_root: felt252,
    consumed_note_root: felt252,
    consumed_nullifier_root: felt252,
    renewal_child_root: felt252,
    output_note_root: felt252,
    fee_root: felt252,
    new_note_root: felt252,
    new_nullifier_root: felt252,
    new_renewal_root: felt252,
    new_fee_root: felt252,
) {
    let bound_fee_root = normalized_fee_root(fee_root);
    let bound_new_fee_root = normalized_new_fee_root(prior_fee_root, fee_root, new_fee_root);
    verifier
        .submit_settlement_with_proof_facts(
            batch_id,
            order_commitment_root,
            encrypted_order_set_commitment,
            transcript_commitment,
            proof_artifact_commitment,
            clearing_price,
            TEST_PRICE_BASE_SCALE,
            TEST_TAKER_FEE_BPS,
            TEST_MAKER_FEE_BPS,
            TEST_RELAY_FEE_BPS,
            TEST_PROTOCOL_FEE_RECIPIENT,
            TEST_RELAY_FEE_RECIPIENT,
            output_bundle_ref,
            prior_note_root,
            prior_nullifier_root,
            prior_renewal_root,
            prior_fee_root,
            consumed_note_root,
            consumed_nullifier_root,
            renewal_child_root,
            output_note_root,
            bound_fee_root,
            new_note_root,
            new_nullifier_root,
            new_renewal_root,
            bound_new_fee_root,
        );
}

fn submit_empty_root_settlement(
    verifier: IAuctionVerifierDispatcher,
    batch_id: felt252,
    order_commitment_root: felt252,
    encrypted_order_set_commitment: felt252,
    transcript_commitment: felt252,
    proof_artifact_commitment: felt252,
    clearing_price: u128,
    output_bundle_ref: felt252,
) {
    let empty_new_root = root_only_state_transition(0, 0);
    let empty_nullifiers = array![];
    let empty_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, empty_nullifiers.span(),
    );
    let empty_renewal_root = empty_renewal_child_root();
    let empty_new_nullifier_root = 0;
    submit_root_settlement(
        verifier,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        transcript_commitment,
        proof_artifact_commitment,
        clearing_price,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        empty_nullifier_root,
        empty_renewal_root,
        0,
        0,
        empty_new_root,
        empty_new_nullifier_root,
        0,
        empty_new_root,
    );
}

fn append_root_settlement_input(
    ref inputs: Array<felt252>,
    batch_id: felt252,
    order_commitment_root: felt252,
    encrypted_order_set_commitment: felt252,
    transcript_commitment: felt252,
    proof_artifact_commitment: felt252,
    clearing_price: u128,
    output_bundle_ref: felt252,
    prior_note_root: felt252,
    prior_nullifier_root: felt252,
    prior_renewal_root: felt252,
    prior_fee_root: felt252,
    consumed_note_root: felt252,
    consumed_nullifier_root: felt252,
    renewal_child_root: felt252,
    output_note_root: felt252,
    fee_root: felt252,
    new_note_root: felt252,
    new_nullifier_root: felt252,
    new_renewal_root: felt252,
    new_fee_root: felt252,
) {
    let bound_fee_root = normalized_fee_root(fee_root);
    let bound_new_fee_root = normalized_new_fee_root(prior_fee_root, fee_root, new_fee_root);
    inputs.append(batch_id);
    inputs.append(order_commitment_root);
    inputs.append(encrypted_order_set_commitment);
    inputs.append(transcript_commitment);
    inputs.append(proof_artifact_commitment);
    inputs.append(clearing_price.into());
    inputs.append(TEST_PRICE_BASE_SCALE.into());
    inputs.append(TEST_TAKER_FEE_BPS.into());
    inputs.append(TEST_MAKER_FEE_BPS.into());
    inputs.append(TEST_RELAY_FEE_BPS.into());
    inputs.append(TEST_PROTOCOL_FEE_RECIPIENT);
    inputs.append(TEST_RELAY_FEE_RECIPIENT);
    inputs.append(output_bundle_ref);
    inputs.append(prior_note_root);
    inputs.append(prior_nullifier_root);
    inputs.append(prior_renewal_root);
    inputs.append(prior_fee_root);
    inputs.append(consumed_note_root);
    inputs.append(consumed_nullifier_root);
    inputs.append(renewal_child_root);
    inputs.append(output_note_root);
    inputs.append(bound_fee_root);
    inputs.append(new_note_root);
    inputs.append(new_nullifier_root);
    inputs.append(new_renewal_root);
    inputs.append(bound_new_fee_root);
}

fn valid_proof_facts(base_block_number: u64, proof_message_hash: felt252) -> Array<felt252> {
    proof_facts_for_message(base_block_number, proof_message_hash, VIRTUAL_SNOS, VIRTUAL_SNOS0)
}

fn valid_aggregate_proof_facts(
    base_block_number: u64, proof_message_hashes: Span<felt252>,
) -> Array<felt252> {
    let facts = ProofFacts {
        proof_version: 0,
        program_variant: VIRTUAL_SNOS,
        virtual_program_hash: TEST_PROOF_PROGRAM_HASH,
        starknet_os_output_version: VIRTUAL_SNOS0,
        base_block_number,
        base_block_hash: 0,
        starknet_os_config_hash: 0,
        message_to_l1_hashes: proof_message_hashes,
    };
    let mut serialized = array![];
    facts.serialize(ref serialized);
    serialized
}

fn proof_facts_for_message(
    base_block_number: u64,
    proof_message_hash: felt252,
    program_variant: felt252,
    starknet_os_output_version: felt252,
) -> Array<felt252> {
    proof_facts_for_message_and_hash(
        base_block_number,
        proof_message_hash,
        program_variant,
        starknet_os_output_version,
        TEST_PROOF_PROGRAM_HASH,
    )
}

fn proof_facts_for_message_and_hash(
    base_block_number: u64,
    proof_message_hash: felt252,
    program_variant: felt252,
    starknet_os_output_version: felt252,
    virtual_program_hash: felt252,
) -> Array<felt252> {
    let messages = array![proof_message_hash];
    let facts = ProofFacts {
        proof_version: 0,
        program_variant,
        virtual_program_hash,
        starknet_os_output_version,
        base_block_number,
        base_block_hash: 0,
        starknet_os_config_hash: 0,
        message_to_l1_hashes: messages.span(),
    };
    let mut serialized = array![];
    facts.serialize(ref serialized);
    serialized
}

#[test]
fn batch_registry_registers_final_roots_as_prepared() {
    let admin = as_address(0x111);
    let batch_registry = deploy_batch_registry(admin, admin);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };

    start_cheat_caller_address(batch_registry, admin);
    batches.register_batch(0xabc, 0xdef, 1, 2, 3, 0x111, 0x222);
    stop_cheat_caller_address(batch_registry);

    let batch = batches.get_batch(0xabc);
    assert(batch.status == BatchStatus::Prepared, 'NOT_PREPARED');
    assert(batch.order_count == 3, 'BAD_ORDER_COUNT');
    assert(batch.order_commitment_root == 0x111, 'BAD_ROOT');
}

#[test]
#[should_panic]
fn batch_registry_rejects_root_mutation_after_prepared() {
    let admin = as_address(0x111);
    let batch_registry = deploy_batch_registry(admin, admin);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };

    start_cheat_caller_address(batch_registry, admin);
    batches.register_batch(0xabc, 0xdef, 1, 2, 3, 0x111, 0x222);
    batches.record_order_set_commitments(0xabc, 4, 0x333, 0x444);
}

#[test]
#[should_panic]
fn batch_registry_rejects_reopening_prepared_batches() {
    let admin = as_address(0x111);
    let batch_registry = deploy_batch_registry(admin, admin);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };

    start_cheat_caller_address(batch_registry, admin);
    batches.register_batch(0xabc, 0xdef, 1, 2, 3, 0x111, 0x222);
    batches.transition_status(0xabc, BatchStatus::Prepared, BatchStatus::Open);
}

#[test]
fn fee_ledger_accrues_valid_settlement_fees() {
    let admin = as_address(0x111);
    let auction_verifier = as_address(0x222);
    let fee_recipient = 0x333;
    let fee_ledger = deploy_fee_ledger(admin);
    let fees = IFeeLedgerDispatcher { contract_address: fee_ledger };

    start_cheat_caller_address(fee_ledger, admin);
    fees.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(fee_ledger);

    start_cheat_caller_address(fee_ledger, auction_verifier);
    fees.accrue_fees(array![ASSET_ID].span(), array![fee_recipient].span(), array![7_u128].span());
    stop_cheat_caller_address(fee_ledger);

    assert(fees.accrued_fee(ASSET_ID, fee_recipient) == 7, 'BAD_FEE');
}

#[test]
fn fee_ledger_claims_accrued_fees_from_adapter_escrow() {
    let admin = as_address(0x111);
    let auction_verifier = as_address(0x333);
    let fee_recipient = 0x444;
    let fee_claim_authority = as_address(0x666);
    let claim_recipient = as_address(0x555);
    let token_address = deploy_mock_erc20();
    let commitment_registry = deploy_commitment_registry(admin);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let privacy_deposit_bridge = deploy_privacy_deposit_bridge(
        commitment_registry, shielded_asset_adapter,
    );
    let fee_ledger = deploy_fee_ledger(admin);
    authorize_privacy_deposit_bridge(
        admin, commitment_registry, shielded_asset_adapter, privacy_deposit_bridge,
    );

    let token = IMockERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: privacy_deposit_bridge };
    let fees = IFeeLedgerDispatcher { contract_address: fee_ledger };

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    adapter.set_fee_ledger(fee_ledger);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(fee_ledger, admin);
    fees.set_auction_verifier(auction_verifier);
    fees.set_shielded_asset_adapter(shielded_asset_adapter);
    fees.set_fee_claim_authority(fee_claim_authority);
    stop_cheat_caller_address(fee_ledger);

    token.mint(privacy_deposit_bridge, as_u256(100));
    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    privacy_invoke_single(
        bridge, ASSET_ID, 100, 7, NOTE_COMMITMENT, withdraw_authority_public_key(0xabc),
    );
    stop_cheat_caller_address(privacy_deposit_bridge);

    start_cheat_caller_address(fee_ledger, auction_verifier);
    fees.accrue_fees(array![ASSET_ID].span(), array![fee_recipient].span(), array![7_u128].span());
    stop_cheat_caller_address(fee_ledger);

    start_cheat_caller_address(fee_ledger, fee_claim_authority);
    fees.claim_fees(ASSET_ID, fee_recipient, 7, claim_recipient);
    stop_cheat_caller_address(fee_ledger);

    assert(fees.accrued_fee(ASSET_ID, fee_recipient) == 0, 'FEE_NOT_CLAIMED');
    assert(adapter.escrowed_balance(ASSET_ID) == 93, 'BAD_ESCROW');
    assert(token.balance_of(claim_recipient).low == 7, 'BAD_CLAIM_BALANCE');
}

#[test]
#[should_panic]
fn fee_ledger_rejects_direct_fee_claim_authority_change() {
    let admin = as_address(0x111);
    let fee_ledger = deploy_fee_ledger(admin);
    let fees = IFeeLedgerDispatcher { contract_address: fee_ledger };

    start_cheat_caller_address(fee_ledger, admin);
    fees.set_fee_claim_authority(as_address(0x222));
    fees.set_fee_claim_authority(as_address(0x333));
}

#[test]
#[should_panic]
fn fee_ledger_rejects_early_fee_claim_authority_execution() {
    let admin = as_address(0x111);
    let fee_ledger = deploy_fee_ledger(admin);
    let fees = IFeeLedgerDispatcher { contract_address: fee_ledger };

    start_cheat_caller_address(fee_ledger, admin);
    fees.set_fee_claim_authority(as_address(0x222));
    cheat_block_timestamp(fee_ledger, 1_000, CheatSpan::TargetCalls(1));
    fees.propose_fee_claim_authority(as_address(0x333));
    cheat_block_timestamp(fee_ledger, 605_799, CheatSpan::TargetCalls(1));
    fees.execute_fee_claim_authority();
}

#[test]
fn fee_ledger_timelocks_fee_claim_authority_change() {
    let admin = as_address(0x111);
    let fee_ledger = deploy_fee_ledger(admin);
    let fees = IFeeLedgerDispatcher { contract_address: fee_ledger };
    let new_authority = as_address(0x333);

    start_cheat_caller_address(fee_ledger, admin);
    fees.set_fee_claim_authority(as_address(0x222));
    cheat_block_timestamp(fee_ledger, 1_000, CheatSpan::TargetCalls(1));
    fees.propose_fee_claim_authority(new_authority);
    stop_cheat_caller_address(fee_ledger);

    let (pending, eta, active) = fees.pending_fee_claim_authority();
    assert(pending == new_authority, 'BAD_PENDING_AUTH');
    assert(eta == 605_800, 'BAD_AUTH_ETA');
    assert(active, 'AUTH_NOT_PENDING');

    start_cheat_caller_address(fee_ledger, admin);
    cheat_block_timestamp(fee_ledger, 605_800, CheatSpan::TargetCalls(1));
    fees.execute_fee_claim_authority();
    stop_cheat_caller_address(fee_ledger);

    assert(fees.fee_claim_authority_address() == new_authority, 'BAD_AUTHORITY');
    let (_pending, _eta, active_after) = fees.pending_fee_claim_authority();
    assert(!active_after, 'AUTH_STILL_PENDING');
}

#[test]
#[should_panic]
fn fee_ledger_rejects_zero_fee_entries() {
    let admin = as_address(0x111);
    let auction_verifier = as_address(0x222);
    let fee_recipient = 0x333;
    let fee_ledger = deploy_fee_ledger(admin);
    let fees = IFeeLedgerDispatcher { contract_address: fee_ledger };

    start_cheat_caller_address(fee_ledger, admin);
    fees.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(fee_ledger);

    start_cheat_caller_address(fee_ledger, auction_verifier);
    fees.accrue_fees(array![ASSET_ID].span(), array![fee_recipient].span(), array![0_u128].span());
}

#[test]
fn shielded_asset_adapter_allows_idempotent_asset_registration() {
    let admin = as_address(0x111);
    let token_address = deploy_mock_erc20();
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    assert(adapter.asset_token(ASSET_ID) == token_address, 'BAD_TOKEN');
}

#[test]
#[should_panic]
fn shielded_asset_adapter_rejects_asset_mapping_mutation() {
    let admin = as_address(0x111);
    let token_address = deploy_mock_erc20();
    let replacement_token_address = deploy_mock_erc20();
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    adapter.register_supported_asset(ASSET_ID, replacement_token_address);
}

#[test]
fn privacy_deposit_bridge_activates_verifier_note_root_when_configured() {
    let admin = as_address(0x111);
    let token_address = deploy_mock_erc20();
    let commitment_registry = deploy_commitment_registry(admin);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let privacy_deposit_bridge = deploy_privacy_deposit_bridge(
        commitment_registry, shielded_asset_adapter,
    );
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    authorize_privacy_deposit_bridge(
        admin, commitment_registry, shielded_asset_adapter, privacy_deposit_bridge,
    );

    let token = IMockERC20Dispatcher { contract_address: token_address };
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: privacy_deposit_bridge };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(commitment_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_deposit_note_root_registrar(commitment_registry);
    stop_cheat_caller_address(auction_verifier);

    token.mint(privacy_deposit_bridge, as_u256(1_000));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    privacy_invoke_single(
        bridge, ASSET_ID, 500, 7, NOTE_COMMITMENT, withdraw_authority_public_key(0x222),
    );
    stop_cheat_caller_address(privacy_deposit_bridge);

    let (current_note_root, current_nullifier_root, current_renewal_root, current_fee_root) =
        verifier
        .current_settlement_roots();
    assert(
        current_note_root == root_only_state_transition(0, deposit_note_root(NOTE_COMMITMENT)),
        'BAD_DEPOSIT_ROOT',
    );
    assert(current_nullifier_root == 0, 'BAD_NULLIFIER_ROOT');
    assert(current_renewal_root == 0, 'BAD_RENEWAL_ROOT');
    assert(current_fee_root == 0, 'BAD_FEE_ROOT');
}

#[test]
#[should_panic]
fn auction_verifier_rejects_stale_prior_note_root_after_deposit_activation() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x777;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 4_u128;
    let output_bundle_ref = 0x999;
    let commitment_registry = deploy_commitment_registry(admin);
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    verifier.set_deposit_note_root_registrar(commitment_registry);
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(auction_verifier, commitment_registry);
    verifier.activate_deposit_note_root(NOTE_COMMITMENT);
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id, pair_id, 1, 2, 0, order_commitment_root, encrypted_order_set_commitment,
        );
    stop_cheat_caller_address(batch_registry);

    let empty_new_root = root_only_state_transition(0, 0);
    let transcript_commitment = root_only_public_settlement_commitment(
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        empty_new_root,
        empty_new_root,
        empty_new_root,
        empty_new_root,
    );
    let proof_artifact_commitment = native_settlement_message_hash(
        auction_verifier, transcript_commitment,
    );
    record_split_auction_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        order_commitment_root,
        0x333,
        transcript_commitment,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);

    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_empty_root_settlement(
        verifier,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        transcript_commitment,
        proof_artifact_commitment,
        clearing_price,
        output_bundle_ref,
    );
    stop_cheat_caller_address(auction_verifier);
}

#[test]
fn privacy_deposit_bridge_registers_privacy_funded_execution_notes() {
    let admin = as_address(0x111);
    let withdraw_authority = withdraw_authority_public_key(0x222);
    let token_address = deploy_mock_erc20();
    let commitment_registry = deploy_commitment_registry(admin);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let privacy_deposit_bridge = deploy_privacy_deposit_bridge(
        commitment_registry, shielded_asset_adapter,
    );
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    authorize_privacy_deposit_bridge(
        admin, commitment_registry, shielded_asset_adapter, privacy_deposit_bridge,
    );

    let token = IMockERC20Dispatcher { contract_address: token_address };
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: privacy_deposit_bridge };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(commitment_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_deposit_note_root_registrar(commitment_registry);
    stop_cheat_caller_address(auction_verifier);

    token.mint(privacy_deposit_bridge, as_u256(750));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    let returned_deposits = bridge
        .privacy_invoke(
            ASSET_ID,
            750,
            array![750_u128].span(),
            array![11_u64].span(),
            array![NOTE_COMMITMENT].span(),
            array![withdraw_authority].span(),
        );
    stop_cheat_caller_address(privacy_deposit_bridge);

    assert(returned_deposits.len() == 0, 'BAD_INVOKE_RETURN');
    assert(registry.is_note_commitment_registered(NOTE_COMMITMENT), 'NOTE_NOT_REGISTERED');
    assert(adapter.note_is_live(NOTE_COMMITMENT), 'NOTE_NOT_LIVE');
    assert(adapter.note_amount(NOTE_COMMITMENT) == 750, 'BAD_NOTE_AMOUNT');
    assert(adapter.note_withdraw_authority(NOTE_COMMITMENT) == withdraw_authority, 'BAD_AUTHORITY');
    let (current_note_root, current_nullifier_root, current_renewal_root, current_fee_root) =
        verifier
        .current_settlement_roots();
    assert(
        current_note_root == root_only_state_transition(0, deposit_note_root(NOTE_COMMITMENT)),
        'BAD_PRIVACY_DEPOSIT_ROOT',
    );
    assert(current_nullifier_root == 0, 'BAD_NULLIFIER_ROOT');
    assert(current_renewal_root == 0, 'BAD_RENEWAL_ROOT');
    assert(current_fee_root == 0, 'BAD_FEE_ROOT');
}

#[test]
fn privacy_deposit_bridge_registers_batched_privacy_funded_notes() {
    let admin = as_address(0x111);
    let first_withdraw_authority = withdraw_authority_public_key(0x222);
    let second_withdraw_authority = withdraw_authority_public_key(0x333);
    let second_note_commitment = NOTE_COMMITMENT + 1;
    let token_address = deploy_mock_erc20();
    let commitment_registry = deploy_commitment_registry(admin);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let privacy_deposit_bridge = deploy_privacy_deposit_bridge(
        commitment_registry, shielded_asset_adapter,
    );
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    authorize_privacy_deposit_bridge(
        admin, commitment_registry, shielded_asset_adapter, privacy_deposit_bridge,
    );

    let token = IMockERC20Dispatcher { contract_address: token_address };
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: privacy_deposit_bridge };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(commitment_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_deposit_note_root_registrar(commitment_registry);
    stop_cheat_caller_address(auction_verifier);

    token.mint(privacy_deposit_bridge, as_u256(750));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    let returned_deposits = bridge
        .privacy_invoke(
            ASSET_ID,
            750,
            array![250_u128, 500_u128].span(),
            array![11_u64, 12_u64].span(),
            array![NOTE_COMMITMENT, second_note_commitment].span(),
            array![first_withdraw_authority, second_withdraw_authority].span(),
        );
    stop_cheat_caller_address(privacy_deposit_bridge);

    assert(returned_deposits.len() == 0, 'BAD_INVOKE_RETURN');
    assert(registry.is_note_commitment_registered(NOTE_COMMITMENT), 'FIRST_NOT_REGISTERED');
    assert(registry.is_note_commitment_registered(second_note_commitment), 'SECOND_NOT_REGISTERED');
    assert(adapter.note_is_live(NOTE_COMMITMENT), 'FIRST_NOT_LIVE');
    assert(adapter.note_is_live(second_note_commitment), 'SECOND_NOT_LIVE');
    assert(adapter.note_amount(NOTE_COMMITMENT) == 250, 'BAD_FIRST_AMOUNT');
    assert(adapter.note_amount(second_note_commitment) == 500, 'BAD_SECOND_AMOUNT');
    assert(
        adapter.note_withdraw_authority(NOTE_COMMITMENT) == first_withdraw_authority,
        'BAD_FIRST_AUTHORITY',
    );
    assert(
        adapter.note_withdraw_authority(second_note_commitment) == second_withdraw_authority,
        'BAD_SECOND_AUTHORITY',
    );
    assert(adapter.escrowed_balance(ASSET_ID) == 750, 'BAD_ESCROW_BALANCE');
    assert(adapter.deposit_count() == 2, 'BAD_DEPOSIT_COUNT');
    assert(adapter.deposit_record(0).deposit_nonce == 11, 'BAD_FIRST_NONCE');
    assert(adapter.deposit_record(1).deposit_nonce == 12, 'BAD_SECOND_NONCE');

    let first_root = root_only_state_transition(0, deposit_note_root(NOTE_COMMITMENT));
    let second_root = root_only_state_transition(
        first_root, deposit_note_root(second_note_commitment),
    );
    let (current_note_root, current_nullifier_root, current_renewal_root, current_fee_root) =
        verifier
        .current_settlement_roots();
    assert(current_note_root == second_root, 'BAD_BATCH_DEPOSIT_ROOT');
    assert(current_nullifier_root == 0, 'BAD_NULLIFIER_ROOT');
    assert(current_renewal_root == 0, 'BAD_RENEWAL_ROOT');
    assert(current_fee_root == 0, 'BAD_FEE_ROOT');
}

#[test]
#[should_panic]
fn privacy_deposit_bridge_rejects_duplicate_batch_commitments() {
    let admin = as_address(0x111);
    let withdraw_authority = withdraw_authority_public_key(0x222);
    let token_address = deploy_mock_erc20();
    let commitment_registry = deploy_commitment_registry(admin);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let privacy_deposit_bridge = deploy_privacy_deposit_bridge(
        commitment_registry, shielded_asset_adapter,
    );
    authorize_privacy_deposit_bridge(
        admin, commitment_registry, shielded_asset_adapter, privacy_deposit_bridge,
    );

    let token = IMockERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: privacy_deposit_bridge };

    token.mint(privacy_deposit_bridge, as_u256(750));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    bridge
        .privacy_invoke(
            ASSET_ID,
            750,
            array![250_u128, 500_u128].span(),
            array![11_u64, 12_u64].span(),
            array![NOTE_COMMITMENT, NOTE_COMMITMENT].span(),
            array![withdraw_authority, withdraw_authority].span(),
        );
}

#[test]
#[should_panic]
fn privacy_deposit_bridge_rejects_non_privacy_pool_callers() {
    let admin = as_address(0x111);
    let withdraw_authority = withdraw_authority_public_key(0x222);
    let wrong_caller = as_address(0x333);
    let token_address = deploy_mock_erc20();
    let commitment_registry = deploy_commitment_registry(admin);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let privacy_deposit_bridge = deploy_privacy_deposit_bridge(
        commitment_registry, shielded_asset_adapter,
    );
    authorize_privacy_deposit_bridge(
        admin, commitment_registry, shielded_asset_adapter, privacy_deposit_bridge,
    );

    let token = IMockERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: privacy_deposit_bridge };

    token.mint(privacy_deposit_bridge, as_u256(750));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(privacy_deposit_bridge, wrong_caller);
    privacy_invoke_single(bridge, ASSET_ID, 750, 11, NOTE_COMMITMENT, withdraw_authority);
}

#[test]
fn privacy_proof_signer_validates_sdk_proof_signatures() {
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let proof_signer = deploy_privacy_proof_signer(key_pair.public_key);
    let signer = IPrivacyProofSignerDispatcher { contract_address: proof_signer };
    let message = 0x123456;
    let (r, s) = StarkCurveSignerImpl::sign(key_pair, message).unwrap();
    let signature = array![r, s];

    assert(signer.signer_public_key() == key_pair.public_key, 'BAD_SIGNER_KEY');
    assert(signer.is_valid_signature(message, signature) != 0, 'BAD_SDK_SIGNATURE');
}

#[test]
fn privacy_proof_signer_relays_single_token_approval() {
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let proof_signer = deploy_privacy_proof_signer(key_pair.public_key);
    let spender = as_address(0x456);
    let token_address = deploy_mock_erc20();
    let token = IERC20Dispatcher { contract_address: token_address };
    let signer = IPrivacyProofSignerDispatcher { contract_address: proof_signer };
    let calldata = array![spender.into(), 100, 0];
    let calls = array![
        Call { to: token_address, selector: selector!("approve"), calldata: calldata.span() },
    ];
    let nonce = 0x777;

    cheat_chain_id(proof_signer, TEST_CHAIN_ID, CheatSpan::TargetCalls(2));
    let relay_message = signer.relay_message_hash(calls.span(), nonce);
    let (r, s) = StarkCurveSignerImpl::sign(key_pair, relay_message).unwrap();
    signer.execute_from_relayer(calls.span(), nonce, r, s);

    assert(token.allowance(proof_signer, spender) == as_u256(100), 'BAD_RELAY_APPROVAL');
    assert(signer.relay_nonce_used(nonce), 'RELAY_NONCE_UNUSED');
}

#[test]
#[should_panic]
fn privacy_proof_signer_rejects_replayed_relay_nonce() {
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let proof_signer = deploy_privacy_proof_signer(key_pair.public_key);
    let spender = as_address(0x456);
    let token_address = deploy_mock_erc20();
    let signer = IPrivacyProofSignerDispatcher { contract_address: proof_signer };
    let calldata = array![spender.into(), 100, 0];
    let calls = array![
        Call { to: token_address, selector: selector!("approve"), calldata: calldata.span() },
    ];
    let nonce = 0x777;

    cheat_chain_id(proof_signer, TEST_CHAIN_ID, CheatSpan::TargetCalls(3));
    let relay_message = signer.relay_message_hash(calls.span(), nonce);
    let (r, s) = StarkCurveSignerImpl::sign(key_pair, relay_message).unwrap();
    signer.execute_from_relayer(calls.span(), nonce, r, s);
    signer.execute_from_relayer(calls.span(), nonce, r, s);
}

#[test]
#[should_panic]
fn shielded_asset_adapter_rejects_unauthorized_deposit_registration() {
    let admin = as_address(0x111);
    let owner = as_address(0x222);
    let attacker = as_address(0x333);
    let token_address = deploy_mock_erc20();
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);

    let token = IMockERC20Dispatcher { contract_address: token_address };
    let erc20 = IERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };

    token.mint(owner, as_u256(1_000));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(token_address, owner);
    erc20.approve(shielded_asset_adapter, as_u256(500));
    stop_cheat_caller_address(token_address);

    start_cheat_caller_address(shielded_asset_adapter, attacker);
    adapter
        .register_erc20_deposit(
            owner, ASSET_ID, 500, 7, NOTE_COMMITMENT, withdraw_authority_public_key(0x333),
        );
}

#[test]
fn auction_verifier_updates_sparse_renewal_root_during_settlement() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x781;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 0_u128;
    let output_bundle_ref = 0x999;
    let child_nullifier = 0xdef;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id, pair_id, 1, 2, 0, order_commitment_root, encrypted_order_set_commitment,
        );
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let children = array![child_nullifier];
    let renewal_child_root = single_field_root(RENEWAL_CHILD_ROOT_DOMAIN, children.span());
    let empty_nullifiers = array![];
    let empty_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, empty_nullifiers.span(),
    );
    let new_renewal_root = 0x777;
    let transcript_commitment = root_only_public_settlement_commitment(
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        empty_nullifier_root,
        renewal_child_root,
        0,
        0,
        root_only_state_transition(0, 0),
        0,
        new_renewal_root,
        root_only_state_transition(0, 0),
    );
    let proof_artifact_commitment = native_settlement_message_hash(
        auction_verifier, transcript_commitment,
    );
    record_split_auction_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        order_commitment_root,
        0x334,
        transcript_commitment,
    );
    record_root_transition_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        transcript_commitment,
        0,
        empty_nullifier_root,
        0,
        0,
        renewal_child_root,
        new_renewal_root,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);

    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_root_settlement(
        verifier,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        transcript_commitment,
        proof_artifact_commitment,
        clearing_price,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        empty_nullifier_root,
        renewal_child_root,
        0,
        0,
        root_only_state_transition(0, 0),
        0,
        new_renewal_root,
        root_only_state_transition(0, 0),
    );
    stop_cheat_caller_address(auction_verifier);

    let (_, _, current_renewal_root, _) = verifier.current_settlement_roots();
    assert(current_renewal_root == new_renewal_root, 'RENEWAL_ROOT_NOT_UPDATED');
}

#[test]
#[should_panic]
fn auction_verifier_rejects_stale_renewal_root_after_parent_cancel_marker() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x782;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 0_u128;
    let output_bundle_ref = 0x999;
    let cancel_marker = 0xdef;
    let cancel_marker_key_low: u128 = 0xdef;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let child_nullifier = 0xdef;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    let cancel_message = renewal_parent_cancel_marker_message_hash_for_verifier(
        auction_verifier, TEST_CHAIN_ID, cancel_marker,
    );
    let (cancel_r, cancel_s) = StarkCurveSignerImpl::sign(key_pair, cancel_message).unwrap();
    let empty_path = array![];
    cheat_chain_id(auction_verifier, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    verifier
        .cancel_renewal_parent_marker(
            cancel_marker,
            key_pair.public_key,
            cancel_marker_key_low,
            0,
            empty_path.span(),
            empty_path.span(),
            cancel_r,
            cancel_s,
        );

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id, pair_id, 1, 2, 0, order_commitment_root, encrypted_order_set_commitment,
        );
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let children = array![child_nullifier];
    let renewal_child_root = single_field_root(RENEWAL_CHILD_ROOT_DOMAIN, children.span());
    let empty_nullifiers = array![];
    let empty_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, empty_nullifiers.span(),
    );
    let new_renewal_root = poseidon_hash2(RENEWAL_SPARSE_LEAF_DOMAIN, child_nullifier);
    let transcript_commitment = root_only_public_settlement_commitment(
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        empty_nullifier_root,
        renewal_child_root,
        0,
        0,
        root_only_state_transition(0, 0),
        0,
        new_renewal_root,
        root_only_state_transition(0, 0),
    );
    let proof_artifact_commitment = native_settlement_message_hash(
        auction_verifier, transcript_commitment,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);

    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_root_settlement(
        verifier,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        transcript_commitment,
        proof_artifact_commitment,
        clearing_price,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        empty_nullifier_root,
        renewal_child_root,
        0,
        0,
        root_only_state_transition(0, 0),
        0,
        new_renewal_root,
        root_only_state_transition(0, 0),
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_unauthorized_submitters() {
    let admin = as_address(0x111);
    let attacker = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, attacker);
    submit_empty_root_settlement(verifier, 1, 0x111, 0x222, 2, 3, 4, 5);
}

#[test]
fn auction_verifier_accepts_native_proof_facts() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x777;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 0_u128;
    let output_bundle_ref = 0x999;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);

    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id, pair_id, 1, 2, 0, order_commitment_root, encrypted_order_set_commitment,
        );
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let transcript_commitment = empty_public_settlement_commitment(
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
    );
    let proof_artifact_commitment = native_settlement_message_hash(
        auction_verifier, transcript_commitment,
    );
    record_split_auction_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        order_commitment_root,
        0x335,
        transcript_commitment,
    );
    let empty_nullifiers = array![];
    let empty_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, empty_nullifiers.span(),
    );
    let empty_renewal_root = empty_renewal_child_root();
    record_root_transition_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        transcript_commitment,
        0,
        empty_nullifier_root,
        0,
        0,
        empty_renewal_root,
        0,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);

    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_empty_root_settlement(
        verifier,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        transcript_commitment,
        proof_artifact_commitment,
        clearing_price,
        output_bundle_ref,
    );
    stop_cheat_caller_address(auction_verifier);

    assert(verifier.is_batch_settled(batch_id), 'NOT_SETTLED');
    let (current_note_root, current_nullifier_root, current_renewal_root, current_fee_root) =
        verifier
        .current_settlement_roots();
    assert(current_note_root == root_only_state_transition(0, 0), 'BAD_CURRENT_NOTE');
    let _ = empty_nullifier_root;
    assert(current_nullifier_root == 0, 'BAD_CURRENT_NULL');
    assert(current_renewal_root == 0, 'BAD_CURRENT_RENEW');
    assert(current_fee_root == root_only_state_transition(0, empty_fee_root()), 'BAD_CURRENT_FEE');
}

#[test]
fn auction_verifier_accepts_split_auction_result_before_settlement() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x1777;
    let pair_id = 0x1888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 0_u128;
    let output_bundle_ref = 0x999;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);

    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id, pair_id, 1, 2, 0, order_commitment_root, encrypted_order_set_commitment,
        );
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let transcript_commitment = empty_public_settlement_commitment(
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
    );
    record_split_auction_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        order_commitment_root,
        0x336,
        transcript_commitment,
    );
    let empty_nullifiers = array![];
    let empty_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, empty_nullifiers.span(),
    );
    let empty_renewal_root = empty_renewal_child_root();
    record_root_transition_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        transcript_commitment,
        0,
        empty_nullifier_root,
        0,
        0,
        empty_renewal_root,
        0,
    );

    let proof_artifact_commitment = native_settlement_message_hash(
        auction_verifier, transcript_commitment,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_empty_root_settlement(
        verifier,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        transcript_commitment,
        proof_artifact_commitment,
        clearing_price,
        output_bundle_ref,
    );
    stop_cheat_caller_address(auction_verifier);

    assert(verifier.is_batch_settled(batch_id), 'NOT_SETTLED');
}

#[test]
#[should_panic]
fn auction_verifier_rejects_split_settlement_without_auction_result() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x2777;
    let pair_id = 0x2888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 0_u128;
    let output_bundle_ref = 0x999;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);

    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id, pair_id, 1, 2, 0, order_commitment_root, encrypted_order_set_commitment,
        );
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let transcript_commitment = empty_public_settlement_commitment(
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
    );
    let proof_artifact_commitment = native_settlement_message_hash(
        auction_verifier, transcript_commitment,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_empty_root_settlement(
        verifier,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        transcript_commitment,
        proof_artifact_commitment,
        clearing_price,
        output_bundle_ref,
    );
}

#[test]
fn auction_verifier_accepts_native_aggregate_proof_facts() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let pair_id_1 = 0x888;
    let pair_id_2 = 0x889;
    let batch_id_1 = 0x771;
    let batch_id_2 = 0x772;
    let order_commitment_root_1 = 0x111;
    let order_commitment_root_2 = 0x112;
    let encrypted_order_set_commitment_1 = 0x221;
    let encrypted_order_set_commitment_2 = 0x222;
    let clearing_price = 0_u128;
    let output_bundle_ref_1 = 0x991;
    let output_bundle_ref_2 = 0x992;
    let empty_batch_root = 0;
    let empty_renewal_root = empty_renewal_child_root();
    let first_new_note_root = root_only_state_transition(0, empty_batch_root);
    let first_new_nullifier_root = 0;
    let first_new_renewal_root = 0;
    let first_new_fee_root = root_only_state_transition(0, empty_fee_root());
    let second_new_note_root = root_only_state_transition(first_new_note_root, empty_batch_root);
    let second_new_renewal_root = first_new_renewal_root;
    let second_new_fee_root = root_only_state_transition(first_new_fee_root, empty_fee_root());
    let empty_nullifiers = array![];
    let empty_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, empty_nullifiers.span(),
    );

    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id_1,
            pair_id_1,
            1,
            2,
            0,
            order_commitment_root_1,
            encrypted_order_set_commitment_1,
        );
    batches
        .register_batch(
            batch_id_2,
            pair_id_2,
            2,
            2,
            0,
            order_commitment_root_2,
            encrypted_order_set_commitment_2,
        );
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let transcript_1 = root_only_public_settlement_commitment(
        batch_id_1,
        pair_id_1,
        1,
        order_commitment_root_1,
        encrypted_order_set_commitment_1,
        clearing_price,
        output_bundle_ref_1,
        0,
        0,
        0,
        0,
        0,
        empty_nullifier_root,
        empty_renewal_root,
        0,
        0,
        first_new_note_root,
        first_new_nullifier_root,
        first_new_renewal_root,
        first_new_fee_root,
    );
    let transcript_2 = root_only_public_settlement_commitment(
        batch_id_2,
        pair_id_2,
        2,
        order_commitment_root_2,
        encrypted_order_set_commitment_2,
        clearing_price,
        output_bundle_ref_2,
        first_new_note_root,
        first_new_nullifier_root,
        first_new_renewal_root,
        first_new_fee_root,
        0,
        empty_nullifier_root,
        empty_renewal_root,
        0,
        0,
        second_new_note_root,
        first_new_nullifier_root,
        second_new_renewal_root,
        second_new_fee_root,
    );
    let proof_artifact_1 = native_settlement_message_hash(auction_verifier, transcript_1);
    let proof_artifact_2 = native_settlement_message_hash(auction_verifier, transcript_2);
    record_split_auction_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id_1,
        order_commitment_root_1,
        0x337,
        transcript_1,
    );
    record_split_auction_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id_2,
        order_commitment_root_2,
        0x338,
        transcript_2,
    );
    let messages = array![
        verifier.settlement_proof_message_hash(transcript_1),
        nullifier_proof_message_hash(
            auction_verifier,
            native_nullifier_message_hash(
                auction_verifier, transcript_1, 0, empty_nullifier_root, first_new_nullifier_root,
            ),
        ),
        renewal_proof_message_hash(
            auction_verifier,
            native_renewal_message_hash(
                auction_verifier, transcript_1, 0, empty_renewal_root, first_new_renewal_root,
            ),
        ),
        verifier.settlement_proof_message_hash(transcript_2),
        nullifier_proof_message_hash(
            auction_verifier,
            native_nullifier_message_hash(
                auction_verifier,
                transcript_2,
                first_new_nullifier_root,
                empty_nullifier_root,
                first_new_nullifier_root,
            ),
        ),
        renewal_proof_message_hash(
            auction_verifier,
            native_renewal_message_hash(
                auction_verifier,
                transcript_2,
                first_new_renewal_root,
                empty_renewal_root,
                second_new_renewal_root,
            ),
        ),
    ];
    let proof_facts = valid_aggregate_proof_facts(99, messages.span());
    let mut aggregate_inputs = array![2];
    append_root_settlement_input(
        ref aggregate_inputs,
        batch_id_1,
        order_commitment_root_1,
        encrypted_order_set_commitment_1,
        transcript_1,
        proof_artifact_1,
        clearing_price,
        output_bundle_ref_1,
        0,
        0,
        0,
        0,
        0,
        empty_nullifier_root,
        empty_renewal_root,
        0,
        0,
        first_new_note_root,
        first_new_nullifier_root,
        first_new_renewal_root,
        first_new_fee_root,
    );
    append_root_settlement_input(
        ref aggregate_inputs,
        batch_id_2,
        order_commitment_root_2,
        encrypted_order_set_commitment_2,
        transcript_2,
        proof_artifact_2,
        clearing_price,
        output_bundle_ref_2,
        first_new_note_root,
        first_new_nullifier_root,
        first_new_renewal_root,
        first_new_fee_root,
        0,
        empty_nullifier_root,
        empty_renewal_root,
        0,
        0,
        second_new_note_root,
        first_new_nullifier_root,
        second_new_renewal_root,
        second_new_fee_root,
    );

    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.submit_aggregate_settlements_with_proof_facts(aggregate_inputs.span());
    stop_cheat_caller_address(auction_verifier);

    assert(verifier.is_batch_settled(batch_id_1), 'BATCH1_NOT_SETTLED');
    assert(verifier.is_batch_settled(batch_id_2), 'BATCH2_NOT_SETTLED');
    let (current_note_root, current_nullifier_root, current_renewal_root, current_fee_root) =
        verifier
        .current_settlement_roots();
    assert(current_note_root == second_new_note_root, 'BAD_AGG_NOTE_ROOT');
    assert(current_nullifier_root == first_new_nullifier_root, 'BAD_AGG_NULL_ROOT');
    assert(current_renewal_root == second_new_renewal_root, 'BAD_AGG_RENEW_ROOT');
    assert(current_fee_root == second_new_fee_root, 'BAD_AGG_FEE_ROOT');
}

#[test]
fn auction_verifier_accepts_root_only_nullifier_transition() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x778;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 0_u128;
    let output_bundle_ref = 0x999;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);

    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id, pair_id, 1, 2, 2, order_commitment_root, encrypted_order_set_commitment,
        );
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let consumed_nullifiers = array![0xabc, 0xdef];
    let consumed_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, consumed_nullifiers.span(),
    );
    let empty_renewal_root = empty_renewal_child_root();
    let sparse_new_nullifier_root = 0x4567;
    let transcript_commitment = root_only_public_settlement_commitment(
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        consumed_nullifier_root,
        empty_renewal_root,
        0,
        0,
        root_only_state_transition(0, 0),
        sparse_new_nullifier_root,
        0,
        root_only_state_transition(0, 0),
    );
    let proof_artifact_commitment = native_settlement_message_hash(
        auction_verifier, transcript_commitment,
    );
    record_split_auction_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        order_commitment_root,
        0x339,
        transcript_commitment,
    );
    record_root_transition_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        transcript_commitment,
        0,
        consumed_nullifier_root,
        sparse_new_nullifier_root,
        0,
        empty_renewal_root,
        0,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);

    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_root_settlement(
        verifier,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        transcript_commitment,
        proof_artifact_commitment,
        clearing_price,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        consumed_nullifier_root,
        empty_renewal_root,
        0,
        0,
        root_only_state_transition(0, 0),
        sparse_new_nullifier_root,
        0,
        root_only_state_transition(0, 0),
    );
    stop_cheat_caller_address(auction_verifier);

    let (_, current_nullifier_root, _, _) = verifier.current_settlement_roots();
    assert(current_nullifier_root == sparse_new_nullifier_root, 'BAD_NULLIFIER_ROOT');
}

#[test]
fn auction_verifier_accepts_note_consolidation_proof_facts() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let consolidation_id = 0x779;
    let output_bundle_ref = 0x999;
    let prior_note_root = 0;
    let prior_nullifier_root = 0;
    let consumed_note_root = 0xabc;
    let consumed_nullifier_root = 0xdef;
    let output_note_root = 0x1234;
    let new_note_root = root_only_state_transition(prior_note_root, output_note_root);
    let new_nullifier_root = 0x5678;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let consolidation_commitment = public_note_consolidation_commitment(
        consolidation_id,
        output_bundle_ref,
        prior_note_root,
        prior_nullifier_root,
        consumed_note_root,
        consumed_nullifier_root,
        output_note_root,
        new_note_root,
        new_nullifier_root,
    );
    let proof_artifact_commitment = native_note_consolidation_message_hash(
        auction_verifier, consolidation_commitment,
    );
    let proof_message_hash = note_consolidation_proof_message_hash(
        auction_verifier, proof_artifact_commitment,
    );
    let proof_facts = valid_proof_facts(99, proof_message_hash);

    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .submit_note_consolidation_with_proof_facts(
            consolidation_id,
            proof_artifact_commitment,
            output_bundle_ref,
            prior_note_root,
            prior_nullifier_root,
            consumed_note_root,
            consumed_nullifier_root,
            output_note_root,
            new_note_root,
            new_nullifier_root,
        );
    stop_cheat_caller_address(auction_verifier);

    assert(verifier.is_batch_settled(consolidation_id), 'CONSOL_NOT_SETTLED');
    let (current_note_root, current_nullifier_root, _, _) = verifier.current_settlement_roots();
    assert(current_note_root == new_note_root, 'BAD_CONSOL_NOTE_ROOT');
    assert(current_nullifier_root == new_nullifier_root, 'BAD_CONSOL_NULL_ROOT');
    let transition_id = verifier.note_root_transition_count() - 1;
    let (kind, key, batch_root, transition_new_root) = verifier.note_root_transition(transition_id);
    assert(kind == 2, 'BAD_CONSOL_KIND');
    assert(key == consolidation_id, 'BAD_CONSOL_KEY');
    assert(batch_root == output_note_root, 'BAD_CONSOL_BATCH_ROOT');
    assert(transition_new_root == new_note_root, 'BAD_CONSOL_NEW_ROOT');
}

#[test]
#[should_panic]
fn auction_verifier_rejects_invalid_new_note_root() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x777;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 4_u128;
    let output_bundle_ref = 0x999;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);

    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id, pair_id, 1, 2, 0, order_commitment_root, encrypted_order_set_commitment,
        );
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let prior_note_root = 0;
    let prior_nullifier_root = 0;
    let prior_renewal_root = 0;
    let prior_fee_root = 0;
    let consumed_note_root = 0;
    let consumed_nullifier_root = 0;
    let renewal_child_root = empty_renewal_child_root();
    let output_note_root = 0xabc;
    let fee_root = 0;
    let transcript_commitment = root_only_public_settlement_commitment(
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        prior_note_root,
        prior_nullifier_root,
        prior_renewal_root,
        prior_fee_root,
        consumed_note_root,
        consumed_nullifier_root,
        renewal_child_root,
        output_note_root,
        fee_root,
        0xdead,
        prior_nullifier_root,
        prior_renewal_root,
        root_only_state_transition(prior_fee_root, fee_root),
    );
    let proof_artifact_commitment = native_settlement_message_hash(
        auction_verifier, transcript_commitment,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);

    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_root_settlement(
        verifier,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        transcript_commitment,
        proof_artifact_commitment,
        clearing_price,
        output_bundle_ref,
        prior_note_root,
        prior_nullifier_root,
        prior_renewal_root,
        prior_fee_root,
        consumed_note_root,
        consumed_nullifier_root,
        renewal_child_root,
        output_note_root,
        fee_root,
        0xdead,
        prior_nullifier_root,
        prior_renewal_root,
        root_only_state_transition(prior_fee_root, fee_root),
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_missing_proof_facts() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_empty_root_settlement(
        verifier, 1, 0x111, 0x222, 2, native_settlement_message_hash(auction_verifier, 2), 4, 5,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_wrong_proof_message() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let transcript_commitment = 2;

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let proof_facts = valid_proof_facts(99, 0xdead);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_empty_root_settlement(
        verifier,
        1,
        0x111,
        0x222,
        transcript_commitment,
        native_settlement_message_hash(auction_verifier, transcript_commitment),
        4,
        5,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_wrong_proof_program_hash() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let transcript_commitment = 2;

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = proof_facts_for_message_and_hash(
        99, proof_message_hash, VIRTUAL_SNOS, VIRTUAL_SNOS0, TEST_PROOF_PROGRAM_HASH + 1,
    );
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_empty_root_settlement(
        verifier,
        1,
        0x111,
        0x222,
        transcript_commitment,
        native_settlement_message_hash(auction_verifier, transcript_commitment),
        4,
        5,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_expired_proof_facts() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let transcript_commitment = 2;

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    verifier.set_proof_validity_blocks(2);
    stop_cheat_caller_address(auction_verifier);

    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(10, proof_message_hash);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_empty_root_settlement(
        verifier,
        1,
        0x111,
        0x222,
        transcript_commitment,
        native_settlement_message_hash(auction_verifier, transcript_commitment),
        4,
        5,
    );
}

#[test]
fn auction_verifier_withdraws_merkle_proven_settlement_output() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x333);
    let recipient = as_address(0x444);
    let batch_id = 0x777;
    let pair_id = 0x888;
    let output_note_commitment = 0xabc123;
    let output_amount = 200_u128;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let withdraw_authority = key_pair.public_key;
    let (token_address, shielded_asset_adapter, _, _) = setup_adapter_with_deposited_note(
        NOTE_COMMITMENT, withdraw_authority,
    );
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let token = IMockERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches.register_batch(batch_id, pair_id, 1, 2, 0, 0x111, 0x222);
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    verifier.set_shielded_asset_adapter(shielded_asset_adapter);
    stop_cheat_caller_address(auction_verifier);

    let output_note_root = output_note_leaf(
        output_note_commitment, ASSET_ID, output_amount, withdraw_authority,
    );
    let empty_nullifiers = array![];
    let empty_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, empty_nullifiers.span(),
    );
    let empty_renewal_root = empty_renewal_child_root();
    let transcript_commitment = root_only_public_settlement_commitment(
        batch_id,
        pair_id,
        1,
        0x111,
        0x222,
        4,
        0x999,
        0,
        0,
        0,
        0,
        0,
        empty_nullifier_root,
        empty_renewal_root,
        output_note_root,
        0,
        root_only_state_transition(0, output_note_root),
        0,
        0,
        root_only_state_transition(0, 0),
    );
    let proof_artifact_commitment = native_settlement_message_hash(
        auction_verifier, transcript_commitment,
    );
    record_split_auction_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        0x111,
        0x33a,
        transcript_commitment,
    );
    record_root_transition_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        transcript_commitment,
        0,
        empty_nullifier_root,
        0,
        0,
        empty_renewal_root,
        0,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_root_settlement(
        verifier,
        batch_id,
        0x111,
        0x222,
        transcript_commitment,
        proof_artifact_commitment,
        4,
        0x999,
        0,
        0,
        0,
        0,
        0,
        empty_nullifier_root,
        empty_renewal_root,
        output_note_root,
        0,
        root_only_state_transition(0, output_note_root),
        0,
        0,
        root_only_state_transition(0, 0),
    );
    stop_cheat_caller_address(auction_verifier);

    let message = output_withdrawal_message_hash_for_verifier(
        auction_verifier,
        shielded_asset_adapter,
        TEST_CHAIN_ID,
        batch_id,
        output_note_commitment,
        ASSET_ID,
        output_amount,
        recipient,
    );
    let (r, s) = StarkCurveSignerImpl::sign(key_pair, message).unwrap();
    let path = array![];
    let directions = array![];
    cheat_chain_id(auction_verifier, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    let (asset_id, amount) = verifier
        .withdraw_settlement_output_to_l2(
            batch_id,
            output_note_commitment,
            ASSET_ID,
            output_amount,
            withdraw_authority,
            path.span(),
            directions.span(),
            r,
            s,
            recipient,
        );

    let recipient_balance = token.balance_of(recipient);
    assert(asset_id == ASSET_ID, 'BAD_OUTPUT_ASSET');
    assert(amount == output_amount, 'BAD_OUTPUT_AMOUNT');
    assert(recipient_balance.low == output_amount, 'BAD_OUTPUT_BALANCE');
    assert(adapter.escrowed_balance(ASSET_ID) == 300, 'BAD_OUTPUT_ESCROW');
    assert(adapter.withdrawal_recipient(output_note_commitment) == recipient, 'BAD_OUT_RECIPIENT');
}

#[test]
#[should_panic]
fn auction_verifier_rejects_settlement_output_withdrawal_before_claim_delay() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x333);
    let recipient = as_address(0x444);
    let batch_id = 0x778;
    let pair_id = 0x888;
    let output_note_commitment = 0xabc124;
    let output_amount = 200_u128;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let withdraw_authority = key_pair.public_key;
    let (_, shielded_asset_adapter, _, _) = setup_adapter_with_deposited_note(
        NOTE_COMMITMENT, withdraw_authority,
    );
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches.register_batch(batch_id, pair_id, 1, 2, 0, 0x111, 0x222);
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    verifier.set_shielded_asset_adapter(shielded_asset_adapter);
    verifier.set_output_claim_delay_seconds(60);
    stop_cheat_caller_address(auction_verifier);

    let output_note_root = output_note_leaf(
        output_note_commitment, ASSET_ID, output_amount, withdraw_authority,
    );
    let empty_nullifiers = array![];
    let empty_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, empty_nullifiers.span(),
    );
    let empty_renewal_root = empty_renewal_child_root();
    let transcript_commitment = root_only_public_settlement_commitment(
        batch_id,
        pair_id,
        1,
        0x111,
        0x222,
        4,
        0x999,
        0,
        0,
        0,
        0,
        0,
        empty_nullifier_root,
        empty_renewal_root,
        output_note_root,
        0,
        root_only_state_transition(0, output_note_root),
        0,
        0,
        root_only_state_transition(0, 0),
    );
    let proof_artifact_commitment = native_settlement_message_hash(
        auction_verifier, transcript_commitment,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(auction_verifier, 1_000, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_root_settlement(
        verifier,
        batch_id,
        0x111,
        0x222,
        transcript_commitment,
        proof_artifact_commitment,
        4,
        0x999,
        0,
        0,
        0,
        0,
        0,
        empty_nullifier_root,
        empty_renewal_root,
        output_note_root,
        0,
        root_only_state_transition(0, output_note_root),
        0,
        0,
        root_only_state_transition(0, 0),
    );
    stop_cheat_caller_address(auction_verifier);

    let message = output_withdrawal_message_hash_for_verifier(
        auction_verifier,
        shielded_asset_adapter,
        TEST_CHAIN_ID,
        batch_id,
        output_note_commitment,
        ASSET_ID,
        output_amount,
        recipient,
    );
    let (r, s) = StarkCurveSignerImpl::sign(key_pair, message).unwrap();
    let path = array![];
    let directions = array![];
    cheat_chain_id(auction_verifier, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(auction_verifier, 1_020, CheatSpan::TargetCalls(1));
    verifier
        .withdraw_settlement_output_to_l2(
            batch_id,
            output_note_commitment,
            ASSET_ID,
            output_amount,
            withdraw_authority,
            path.span(),
            directions.span(),
            r,
            s,
            recipient,
        );
}

#[test]
fn shielded_asset_adapter_accepts_domain_bound_withdraw_signature() {
    let recipient = as_address(0x444);
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let (token_address, shielded_asset_adapter, owner, _) = setup_adapter_with_deposited_note(
        NOTE_COMMITMENT, key_pair.public_key,
    );
    let token = IMockERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let message = withdrawal_message_hash_for_domain(
        NOTE_COMMITMENT, recipient, shielded_asset_adapter, TEST_CHAIN_ID,
    );
    let (r, s) = StarkCurveSignerImpl::sign(key_pair, message).unwrap();

    cheat_chain_id(shielded_asset_adapter, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    start_cheat_caller_address(shielded_asset_adapter, owner);
    let (asset_id, amount) = adapter.withdraw_to_l2(NOTE_COMMITMENT, r, s, recipient);
    stop_cheat_caller_address(shielded_asset_adapter);

    let recipient_balance = token.balance_of(recipient);
    assert(asset_id == ASSET_ID, 'BAD_WITHDRAW_ASSET');
    assert(amount == 500, 'BAD_WITHDRAW_AMOUNT');
    assert(recipient_balance.low == 500, 'BAD_RECIP_BALANCE');
    assert(recipient_balance.high == 0, 'BAD_RECIP_HIGH');
    assert(adapter.note_is_live(NOTE_COMMITMENT) == false, 'NOTE_STILL_LIVE');
    assert(adapter.withdrawal_recipient(NOTE_COMMITMENT) == recipient, 'BAD_WITHDRAW_RECIPIENT');
}

#[test]
#[should_panic]
fn shielded_asset_adapter_rejects_withdraw_signature_for_wrong_chain() {
    let recipient = as_address(0x444);
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let (_, shielded_asset_adapter, owner, _) = setup_adapter_with_deposited_note(
        NOTE_COMMITMENT, key_pair.public_key,
    );
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let message = withdrawal_message_hash_for_domain(
        NOTE_COMMITMENT, recipient, shielded_asset_adapter, WRONG_CHAIN_ID,
    );
    let (r, s) = StarkCurveSignerImpl::sign(key_pair, message).unwrap();

    cheat_chain_id(shielded_asset_adapter, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    start_cheat_caller_address(shielded_asset_adapter, owner);
    adapter.withdraw_to_l2(NOTE_COMMITMENT, r, s, recipient);
}

#[test]
#[should_panic]
fn shielded_asset_adapter_rejects_withdraw_signature_for_wrong_adapter() {
    let recipient = as_address(0x444);
    let wrong_adapter = as_address(0x777);
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let (_, shielded_asset_adapter, owner, _) = setup_adapter_with_deposited_note(
        NOTE_COMMITMENT, key_pair.public_key,
    );
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let message = withdrawal_message_hash_for_domain(
        NOTE_COMMITMENT, recipient, wrong_adapter, TEST_CHAIN_ID,
    );
    let (r, s) = StarkCurveSignerImpl::sign(key_pair, message).unwrap();

    cheat_chain_id(shielded_asset_adapter, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    start_cheat_caller_address(shielded_asset_adapter, owner);
    adapter.withdraw_to_l2(NOTE_COMMITMENT, r, s, recipient);
}

#[test]
#[should_panic]
fn shielded_asset_adapter_rejects_wrong_withdraw_signature() {
    let wrong_caller = as_address(0x333);
    let recipient = as_address(0x444);
    let (_, shielded_asset_adapter, _, _) = setup_adapter_with_deposited_note(
        NOTE_COMMITMENT, withdraw_authority_public_key(0x222),
    );
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };

    start_cheat_caller_address(shielded_asset_adapter, wrong_caller);
    adapter.withdraw_to_l2(NOTE_COMMITMENT, 0x333, 0x444, recipient);
}

#[test]
#[should_panic]
fn privacy_deposit_bridge_rejects_zero_withdraw_authority() {
    let admin = as_address(0x111);
    let token_address = deploy_mock_erc20();
    let commitment_registry = deploy_commitment_registry(admin);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let privacy_deposit_bridge = deploy_privacy_deposit_bridge(
        commitment_registry, shielded_asset_adapter,
    );
    authorize_privacy_deposit_bridge(
        admin, commitment_registry, shielded_asset_adapter, privacy_deposit_bridge,
    );

    let token = IMockERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: privacy_deposit_bridge };

    token.mint(privacy_deposit_bridge, as_u256(1_000));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    privacy_invoke_single(bridge, ASSET_ID, 500, 7, NOTE_COMMITMENT, 0);
}
