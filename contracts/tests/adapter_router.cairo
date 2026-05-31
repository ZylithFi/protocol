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
use crate::mock_erc20::{
    IConfigurableMockERC20Dispatcher, IConfigurableMockERC20DispatcherTrait, IMockERC20Dispatcher,
    IMockERC20DispatcherTrait,
};

const ASSET_ID: felt252 = 'USDC';
const NOTE_COMMITMENT: felt252 = 0x12345;
const PRIVACY_POOL: felt252 = 0x999;
const VIRTUAL_SNOS: felt252 = 'VIRTUAL_SNOS';
const VIRTUAL_SNOS0: felt252 = 'VIRTUAL_SNOS0';
const TEST_PROOF_VERSION: felt252 = 'PROOF0';
const TEST_PROOF_PROGRAM_HASH: felt252 = 0x987654321;
const TEST_BASE_BLOCK_HASH: felt252 = 0xabcdef123;
const TEST_OS_CONFIG_HASH: felt252 = 0x123456789abcdef;
const ADMISSION_MESSAGE_DOMAIN: felt252 = 'zylith_admit_v1';
const AUCTION_RESULT_MESSAGE_DOMAIN: felt252 = 'zylith_aucres_v1';
const NULLIFIER_MESSAGE_DOMAIN: felt252 = 'zylith_null_v1';
const RENEWAL_MESSAGE_DOMAIN: felt252 = 'zylith_renew_v1';
const NOTE_CONSOLIDATION_MESSAGE_DOMAIN: felt252 = 'zylith_consol_v1';
const WITHDRAWAL_MESSAGE_DOMAIN: felt252 = 'zylith_withdraw_v1';
const PUBLIC_NOTE_CONSOLIDATION_DOMAIN: felt252 = 0x7a796c6974685f6e6f74655f636f6e736f6c5f7631;
const PUBLIC_NOTE_WITHDRAWAL_DOMAIN: felt252 = 0x7a796c6974685f6e6f74655f77697468647261775f7631;
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
const FUNDING_COMMITMENT: felt252 = 0x461001;
const SECOND_FUNDING_COMMITMENT: felt252 = 0x461002;
const ENCRYPTED_NOTE_ACTIVATION: felt252 = 0x463001;
const SECOND_ENCRYPTED_NOTE_ACTIVATION: felt252 = 0x463002;
const DEPOSIT_AMOUNT: u128 = 100;
const SECOND_DEPOSIT_AMOUNT: u128 = 200;
const DEPOSIT_WITHDRAW_AUTHORITY: felt252 = 0x464001;
const SECOND_NOTE_COMMITMENT: felt252 = 0x12346;
const SECOND_DEPOSIT_WITHDRAW_AUTHORITY: felt252 = 0x464002;

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

fn deploy_configurable_mock_erc20() -> ContractAddress {
    let class = declare("ConfigurableMockERC20").unwrap().contract_class();
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

fn deploy_privacy_deposit_bridge(
    commitment_registry: ContractAddress, _shielded_asset_adapter: ContractAddress,
) -> ContractAddress {
    let class = declare("PrivacyDepositBridge").unwrap().contract_class();
    let calldata = array![commitment_registry.into(), PRIVACY_POOL];
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
    verifier.set_expected_starknet_os_config_hash(TEST_OS_CONFIG_HASH);
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

fn deploy_auction_verifier_without_defaults(
    admin: ContractAddress, batch_registry: ContractAddress,
) -> ContractAddress {
    let verifier_class = declare("AuctionVerifier").unwrap().contract_class();
    let verifier_calldata = array![admin.into(), batch_registry.into()];
    let (verifier_address, _) = verifier_class.deploy(@verifier_calldata).unwrap_syscall();
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
#[should_panic]
fn auction_verifier_pause_blocks_renewal_parent_cancellation() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let cancel_marker = 0xdef;
    let cancel_marker_key_low: u128 = 0xdef;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let cancel_message = renewal_parent_cancel_marker_message_hash_for_verifier(
        auction_verifier, TEST_CHAIN_ID, cancel_marker,
    );
    let (cancel_r, cancel_s) = StarkCurveSignerImpl::sign(key_pair, cancel_message).unwrap();
    let empty_path = array![];

    start_cheat_caller_address(auction_verifier, admin);
    verifier.pause();
    stop_cheat_caller_address(auction_verifier);

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
fn batch_registry_old_admin_loses_authority_after_rotation() {
    let admin = as_address(0x111);
    let new_admin = as_address(0x222);
    let batch_registry = deploy_batch_registry(admin, admin);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };

    start_cheat_caller_address(batch_registry, admin);
    batches.propose_admin(new_admin);
    stop_cheat_caller_address(batch_registry);
    start_cheat_caller_address(batch_registry, new_admin);
    batches.accept_admin();
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(batch_registry, admin);
    batches.set_batch_registrar(as_address(0x333));
}

#[test]
#[should_panic]
fn commitment_registry_old_admin_loses_authority_after_rotation() {
    let admin = as_address(0x111);
    let new_admin = as_address(0x222);
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };

    start_cheat_caller_address(commitment_registry, admin);
    registry.propose_admin(new_admin);
    stop_cheat_caller_address(commitment_registry);
    start_cheat_caller_address(commitment_registry, new_admin);
    registry.accept_admin();
    stop_cheat_caller_address(commitment_registry);

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_batch_registrar(as_address(0x333));
}

#[test]
#[should_panic]
fn shielded_asset_adapter_old_admin_loses_authority_after_rotation() {
    let admin = as_address(0x111);
    let new_admin = as_address(0x222);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.propose_admin(new_admin);
    stop_cheat_caller_address(shielded_asset_adapter);
    start_cheat_caller_address(shielded_asset_adapter, new_admin);
    adapter.accept_admin();
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.set_auction_verifier(as_address(0x333));
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

#[test]
#[should_panic]
fn auction_verifier_rejects_operational_lock_without_os_config() {
    let admin = as_address(0x111);
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier_without_defaults(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.lock_operational_config();
}

#[test]
#[should_panic]
fn auction_verifier_operational_lock_blocks_settlement_account_change() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.lock_operational_config();
    verifier.set_authorized_settlement_account(as_address(0x333));
}

#[test]
#[should_panic]
fn auction_verifier_operational_lock_blocks_adapter_change() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.lock_operational_config();
    verifier.set_shielded_asset_adapter(as_address(0x333));
}

#[test]
#[should_panic]
fn auction_verifier_operational_lock_blocks_pair_fee_reconfiguration() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.lock_operational_config();
    verifier
        .propose_pair_fee_config(
            0x888, TEST_TAKER_FEE_BPS + 1, TEST_MAKER_FEE_BPS, TEST_RELAY_FEE_BPS,
        );
}

#[test]
#[should_panic]
fn auction_verifier_operational_lock_blocks_fee_recipient_reconfiguration() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.lock_operational_config();
    verifier.propose_protocol_fee_recipient(TEST_PROTOCOL_FEE_RECIPIENT + 1);
}

fn authorize_privacy_deposit_bridge(
    admin: ContractAddress,
    commitment_registry: ContractAddress,
    _shielded_asset_adapter: ContractAddress,
    privacy_deposit_bridge: ContractAddress,
) {
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_privacy_deposit_bridge(privacy_deposit_bridge);
    stop_cheat_caller_address(commitment_registry);
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
    _note_commitment: felt252, _withdraw_authority: felt252,
) -> (ContractAddress, ContractAddress, ContractAddress, ContractAddress) {
    let admin = as_address(0x111);
    let owner = as_address(0x222);
    let token_address = deploy_mock_erc20();
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let privacy_deposit_bridge = as_address(PRIVACY_POOL);
    let token = IMockERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };

    token.mint(shielded_asset_adapter, as_u256(1_000));
    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    (token_address, shielded_asset_adapter, owner, privacy_deposit_bridge)
}

fn setup_privacy_activation_stack(
    admin: ContractAddress,
) -> (
    ContractAddress,
    ContractAddress,
    ContractAddress,
    ICommitmentRegistryDispatcher,
    IPrivacyDepositBridgeDispatcher,
    IAuctionVerifierDispatcher,
) {
    let commitment_registry = deploy_commitment_registry(admin);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let token_address = deploy_mock_erc20();
    let privacy_deposit_bridge = deploy_privacy_deposit_bridge(
        commitment_registry, shielded_asset_adapter,
    );
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let token = IMockERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    authorize_privacy_deposit_bridge(
        admin, commitment_registry, shielded_asset_adapter, privacy_deposit_bridge,
    );
    token.mint(privacy_deposit_bridge, as_u256(10_000));
    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: privacy_deposit_bridge };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_deposit_root_registrar(commitment_registry);
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(commitment_registry);

    (
        commitment_registry,
        shielded_asset_adapter,
        privacy_deposit_bridge,
        registry,
        bridge,
        verifier,
    )
}

fn privacy_invoke_single(
    bridge: IPrivacyDepositBridgeDispatcher,
    funding_commitment: felt252,
    deposit_root: felt252,
    encrypted_note_activation: felt252,
) {
    privacy_invoke_single_with_note(
        bridge,
        funding_commitment,
        deposit_root,
        encrypted_note_activation,
        NOTE_COMMITMENT,
        DEPOSIT_AMOUNT,
        DEPOSIT_WITHDRAW_AUTHORITY,
    );
}

fn privacy_invoke_single_with_note(
    bridge: IPrivacyDepositBridgeDispatcher,
    funding_commitment: felt252,
    deposit_root: felt252,
    encrypted_note_activation: felt252,
    _note_commitment: felt252,
    _amount: u128,
    _withdraw_authority: felt252,
) {
    let open_deposits = bridge
        .privacy_invoke(
            array![funding_commitment].span(),
            array![deposit_root].span(),
            array![encrypted_note_activation].span(),
        );
    assert(open_deposits.len() == 0, 'OPEN_DEPOSITS_RETURNED');
}

fn deposit_root() -> felt252 {
    output_note_leaf(NOTE_COMMITMENT, ASSET_ID, DEPOSIT_AMOUNT, DEPOSIT_WITHDRAW_AUTHORITY)
}

fn second_deposit_root() -> felt252 {
    output_note_leaf(
        SECOND_NOTE_COMMITMENT, ASSET_ID, SECOND_DEPOSIT_AMOUNT, SECOND_DEPOSIT_WITHDRAW_AUTHORITY,
    )
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

fn native_withdrawal_message_hash(
    auction_verifier_address: ContractAddress, withdrawal_commitment: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(WITHDRAWAL_MESSAGE_DOMAIN, auction_verifier_address.into());
    poseidon_hash2(state, withdrawal_commitment)
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

fn withdrawal_proof_message_hash(
    proof_program_address: ContractAddress, statement_message_hash: felt252,
) -> felt252 {
    let mut l1_message_data = array![proof_program_address.into(), 0];
    l1_message_data.append(2);
    l1_message_data.append(WITHDRAWAL_MESSAGE_DOMAIN);
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

fn submit_note_consolidation_with_matching_proof(
    verifier: IAuctionVerifierDispatcher,
    auction_verifier: ContractAddress,
    consolidation_id: felt252,
    output_bundle_ref: felt252,
    prior_note_root: felt252,
    prior_nullifier_root: felt252,
    consumed_note_root: felt252,
    consumed_nullifier_root: felt252,
    output_note_root: felt252,
    new_note_root: felt252,
    new_nullifier_root: felt252,
) {
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
}

fn public_note_withdrawal_commitment(
    batch_id: felt252,
    note_commitment: felt252,
    asset_id: felt252,
    amount: u128,
    withdraw_authority: felt252,
    prior_nullifier_root: felt252,
    consumed_nullifier_root: felt252,
    new_nullifier_root: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(PUBLIC_NOTE_WITHDRAWAL_DOMAIN, batch_id);
    state = poseidon_hash2(state, note_commitment);
    state = poseidon_hash2(state, asset_id);
    state = poseidon_hash2(state, amount.into());
    state = poseidon_hash2(state, withdraw_authority);
    state = poseidon_hash2(state, prior_nullifier_root);
    state = poseidon_hash2(state, consumed_nullifier_root);
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

fn settle_single_output_note_for_withdrawal(
    admin: ContractAddress,
    settlement_account: ContractAddress,
    batch_id: felt252,
    pair_id: felt252,
    output_note_commitment: felt252,
    output_amount: u128,
    withdraw_authority: felt252,
) -> (ContractAddress, ContractAddress, ContractAddress) {
    let (token_address, shielded_asset_adapter, _, _) = setup_adapter_with_deposited_note(
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
    (token_address, shielded_asset_adapter, auction_verifier)
}

fn submit_output_withdrawal_attempt(
    verifier: IAuctionVerifierDispatcher,
    auction_verifier: ContractAddress,
    proof_verifier: ContractAddress,
    _shielded_asset_adapter: ContractAddress,
    signed_adapter: ContractAddress,
    runtime_chain_id: felt252,
    signed_chain_id: felt252,
    batch_id: felt252,
    note_commitment: felt252,
    asset_id: felt252,
    amount: u128,
    withdraw_secret: felt252,
    withdraw_authority: felt252,
    recipient: ContractAddress,
    signed_recipient: ContractAddress,
    prior_nullifier_root: felt252,
    consumed_nullifier_root: felt252,
    new_nullifier_root: felt252,
) {
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(withdraw_secret);
    let message = output_withdrawal_message_hash_for_verifier(
        auction_verifier,
        signed_adapter,
        signed_chain_id,
        batch_id,
        note_commitment,
        asset_id,
        amount,
        signed_recipient,
    );
    let (r, s) = StarkCurveSignerImpl::sign(key_pair, message).unwrap();
    let path = array![];
    let directions = array![];
    let withdrawal_commitment = public_note_withdrawal_commitment(
        batch_id,
        note_commitment,
        asset_id,
        amount,
        withdraw_authority,
        prior_nullifier_root,
        consumed_nullifier_root,
        new_nullifier_root,
    );
    let withdrawal_statement = native_withdrawal_message_hash(
        proof_verifier, withdrawal_commitment,
    );
    let withdrawal_proof_message = withdrawal_proof_message_hash(
        auction_verifier, withdrawal_statement,
    );
    let withdrawal_proof_facts = valid_proof_facts(99, withdrawal_proof_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_chain_id(auction_verifier, runtime_chain_id, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, withdrawal_proof_facts.span(), CheatSpan::TargetCalls(1));
    verifier
        .withdraw_settlement_output_with_proof_facts(
            batch_id,
            withdrawal_statement,
            prior_nullifier_root,
            consumed_nullifier_root,
            new_nullifier_root,
            note_commitment,
            asset_id,
            amount,
            withdraw_authority,
            path.span(),
            directions.span(),
            r,
            s,
            recipient,
        );
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

fn submit_root_settlement_with_fee_config(
    verifier: IAuctionVerifierDispatcher,
    batch_id: felt252,
    order_commitment_root: felt252,
    encrypted_order_set_commitment: felt252,
    transcript_commitment: felt252,
    proof_artifact_commitment: felt252,
    clearing_price: u128,
    price_base_scale: u128,
    taker_fee_bps: u128,
    maker_fee_bps: u128,
    relay_fee_bps: u128,
    protocol_fee_recipient: felt252,
    relay_fee_recipient: felt252,
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
    verifier
        .submit_settlement_with_proof_facts(
            batch_id,
            order_commitment_root,
            encrypted_order_set_commitment,
            transcript_commitment,
            proof_artifact_commitment,
            clearing_price,
            price_base_scale,
            taker_fee_bps,
            maker_fee_bps,
            relay_fee_bps,
            protocol_fee_recipient,
            relay_fee_recipient,
            output_bundle_ref,
            prior_note_root,
            prior_nullifier_root,
            prior_renewal_root,
            prior_fee_root,
            consumed_note_root,
            consumed_nullifier_root,
            renewal_child_root,
            output_note_root,
            normalized_fee_root(fee_root),
            new_note_root,
            new_nullifier_root,
            new_renewal_root,
            normalized_new_fee_root(prior_fee_root, fee_root, new_fee_root),
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

fn register_prepared_batch(
    batch_registry: ContractAddress,
    admin: ContractAddress,
    auction_verifier: ContractAddress,
    batch_id: felt252,
    pair_id: felt252,
    batch_epoch: u64,
    order_commitment_root: felt252,
    encrypted_order_set_commitment: felt252,
) {
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id,
            pair_id,
            batch_epoch,
            2,
            0,
            order_commitment_root,
            encrypted_order_set_commitment,
        );
    stop_cheat_caller_address(batch_registry);
}

fn prepare_empty_root_transition(
    auction_verifier: ContractAddress,
    verifier: IAuctionVerifierDispatcher,
    settlement_account: ContractAddress,
    batch_id: felt252,
    pair_id: felt252,
    batch_epoch: u64,
    order_commitment_root: felt252,
    encrypted_order_set_commitment: felt252,
    clearing_price: u128,
    output_bundle_ref: felt252,
    admission_root: felt252,
) -> felt252 {
    let transcript_commitment = empty_public_settlement_commitment(
        batch_id,
        pair_id,
        batch_epoch,
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
        admission_root,
        transcript_commitment,
    );
    let empty_nullifiers = array![];
    let empty_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, empty_nullifiers.span(),
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
        empty_renewal_child_root(),
        0,
    );
    transcript_commitment
}

fn sample_single_aggregate_inputs(
    auction_verifier: ContractAddress, verifier: IAuctionVerifierDispatcher,
) -> (Array<felt252>, Array<felt252>) {
    let batch_id = 0xabc01;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 0_u128;
    let output_bundle_ref = 0x999;
    let empty_nullifiers = array![];
    let empty_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, empty_nullifiers.span(),
    );
    let empty_renewal_root = empty_renewal_child_root();
    let new_note_root = root_only_state_transition(0, 0);
    let new_fee_root = root_only_state_transition(0, empty_fee_root());
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
        empty_renewal_root,
        0,
        0,
        new_note_root,
        0,
        0,
        new_fee_root,
    );
    let mut inputs = array![1];
    append_root_settlement_input(
        ref inputs,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        transcript_commitment,
        native_settlement_message_hash(auction_verifier, transcript_commitment),
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
        new_note_root,
        0,
        0,
        new_fee_root,
    );
    let messages = array![
        verifier.settlement_proof_message_hash(transcript_commitment),
        nullifier_proof_message_hash(
            auction_verifier,
            native_nullifier_message_hash(
                auction_verifier, transcript_commitment, 0, empty_nullifier_root, 0,
            ),
        ),
        renewal_proof_message_hash(
            auction_verifier,
            native_renewal_message_hash(
                auction_verifier, transcript_commitment, 0, empty_renewal_root, 0,
            ),
        ),
    ];
    (inputs, messages)
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

fn append_aggregate_record_copy(ref inputs: Array<felt252>, source: Span<felt252>) {
    let mut index = 1;
    loop {
        if index == source.len() {
            break;
        }
        inputs.append(*source.at(index));
        index += 1;
    };
}

fn submit_two_batch_aggregate_with_roots(
    second_prior_note_root: felt252,
    first_new_nullifier_root: felt252,
    second_prior_nullifier_root: felt252,
    first_new_renewal_root: felt252,
    second_prior_renewal_root: felt252,
    first_new_fee_root: felt252,
    second_prior_fee_root: felt252,
) {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let pair_id_1 = 0x888;
    let pair_id_2 = 0x889;
    let batch_id_1 = 0x7811;
    let batch_id_2 = 0x7812;
    let order_commitment_root_1 = 0x111;
    let order_commitment_root_2 = 0x112;
    let encrypted_order_set_commitment_1 = 0x221;
    let encrypted_order_set_commitment_2 = 0x222;
    let clearing_price = 0_u128;
    let output_bundle_ref_1 = 0x991;
    let output_bundle_ref_2 = 0x992;
    let empty_batch_root = 0;
    let empty_renewal_root = empty_renewal_child_root();
    let empty_nullifier_root = single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, array![].span());
    let first_new_note_root = root_only_state_transition(0, empty_batch_root);
    let second_new_note_root = root_only_state_transition(second_prior_note_root, empty_batch_root);
    let second_new_nullifier_root = second_prior_nullifier_root;
    let second_new_renewal_root = second_prior_renewal_root;
    let second_new_fee_root = root_only_state_transition(second_prior_fee_root, empty_fee_root());

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
        second_prior_note_root,
        second_prior_nullifier_root,
        second_prior_renewal_root,
        second_prior_fee_root,
        0,
        empty_nullifier_root,
        empty_renewal_root,
        0,
        0,
        second_new_note_root,
        second_new_nullifier_root,
        second_new_renewal_root,
        second_new_fee_root,
    );
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
                second_prior_nullifier_root,
                empty_nullifier_root,
                second_new_nullifier_root,
            ),
        ),
        renewal_proof_message_hash(
            auction_verifier,
            native_renewal_message_hash(
                auction_verifier,
                transcript_2,
                second_prior_renewal_root,
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
        native_settlement_message_hash(auction_verifier, transcript_1),
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
        native_settlement_message_hash(auction_verifier, transcript_2),
        clearing_price,
        output_bundle_ref_2,
        second_prior_note_root,
        second_prior_nullifier_root,
        second_prior_renewal_root,
        second_prior_fee_root,
        0,
        empty_nullifier_root,
        empty_renewal_root,
        0,
        0,
        second_new_note_root,
        second_new_nullifier_root,
        second_new_renewal_root,
        second_new_fee_root,
    );

    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.submit_aggregate_settlements_with_proof_facts(aggregate_inputs.span());
}

fn valid_proof_facts(base_block_number: u64, proof_message_hash: felt252) -> Array<felt252> {
    proof_facts_for_message(base_block_number, proof_message_hash, VIRTUAL_SNOS, VIRTUAL_SNOS0)
}

fn valid_aggregate_proof_facts(
    base_block_number: u64, proof_message_hashes: Span<felt252>,
) -> Array<felt252> {
    let facts = ProofFacts {
        proof_version: TEST_PROOF_VERSION,
        program_variant: VIRTUAL_SNOS,
        virtual_program_hash: TEST_PROOF_PROGRAM_HASH,
        starknet_os_output_version: VIRTUAL_SNOS0,
        base_block_number,
        base_block_hash: TEST_BASE_BLOCK_HASH,
        starknet_os_config_hash: TEST_OS_CONFIG_HASH,
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
    proof_facts_for_message_and_context(
        base_block_number,
        proof_message_hash,
        program_variant,
        starknet_os_output_version,
        virtual_program_hash,
        TEST_BASE_BLOCK_HASH,
        TEST_OS_CONFIG_HASH,
    )
}

fn proof_facts_for_message_and_context(
    base_block_number: u64,
    proof_message_hash: felt252,
    program_variant: felt252,
    starknet_os_output_version: felt252,
    virtual_program_hash: felt252,
    base_block_hash: felt252,
    starknet_os_config_hash: felt252,
) -> Array<felt252> {
    let messages = array![proof_message_hash];
    let facts = ProofFacts {
        proof_version: TEST_PROOF_VERSION,
        program_variant,
        virtual_program_hash,
        starknet_os_output_version,
        base_block_number,
        base_block_hash,
        starknet_os_config_hash,
        message_to_l1_hashes: messages.span(),
    };
    let mut serialized = array![];
    facts.serialize(ref serialized);
    serialized
}

fn proof_facts_for_message_with_version(
    base_block_number: u64, proof_message_hash: felt252, proof_version: felt252,
) -> Array<felt252> {
    let messages = array![proof_message_hash];
    let facts = ProofFacts {
        proof_version,
        program_variant: VIRTUAL_SNOS,
        virtual_program_hash: TEST_PROOF_PROGRAM_HASH,
        starknet_os_output_version: VIRTUAL_SNOS0,
        base_block_number,
        base_block_hash: TEST_BASE_BLOCK_HASH,
        starknet_os_config_hash: TEST_OS_CONFIG_HASH,
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
#[should_panic]
fn batch_registry_rejects_duplicate_batch_id() {
    let admin = as_address(0x111);
    let batch_registry = deploy_batch_registry(admin, admin);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };

    start_cheat_caller_address(batch_registry, admin);
    batches.register_batch(0xabc, 0xdef, 1, 2, 3, 0x111, 0x222);
    batches.register_batch(0xabc, 0xdef, 1, 2, 3, 0x112, 0x223);
}

#[test]
#[should_panic]
fn batch_registry_rejects_zero_encrypted_order_set_commitment() {
    let admin = as_address(0x111);
    let batch_registry = deploy_batch_registry(admin, admin);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };

    start_cheat_caller_address(batch_registry, admin);
    batches.register_batch(0xabc, 0xdef, 1, 2, 3, 0x111, 0);
}

#[test]
#[should_panic]
fn batch_registry_rejects_zero_order_commitment_root() {
    let admin = as_address(0x111);
    let batch_registry = deploy_batch_registry(admin, admin);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };

    start_cheat_caller_address(batch_registry, admin);
    batches.register_batch(0xabc, 0xdef, 1, 2, 3, 0, 0x222);
}

#[test]
#[should_panic]
fn commitment_registry_rejects_wrong_order_registrar() {
    let admin = as_address(0x111);
    let wrong_registrar = as_address(0x222);
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };

    start_cheat_caller_address(commitment_registry, wrong_registrar);
    registry.register_order_commitments(0x777, array![0xabc].span());
}

#[test]
#[should_panic]
fn commitment_registry_rejects_zero_order_batch_id() {
    let admin = as_address(0x111);
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_batch_registrar(admin);
    registry.register_order_commitments(0, array![0xabc].span());
}

#[test]
#[should_panic]
fn commitment_registry_rejects_zero_order_commitment() {
    let admin = as_address(0x111);
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_batch_registrar(admin);
    registry.register_order_commitments(0x777, array![0].span());
}

#[test]
#[should_panic]
fn commitment_registry_rejects_duplicate_order_commitment_inside_batch() {
    let admin = as_address(0x111);
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_batch_registrar(admin);
    registry.register_order_commitments(0x777, array![0xabc, 0xabc].span());
}

#[test]
#[should_panic]
fn commitment_registry_rejects_duplicate_order_commitment_across_batches() {
    let admin = as_address(0x111);
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_batch_registrar(admin);
    registry.register_order_commitments(0x777, array![0xabc].span());
    registry.register_order_commitments(0x778, array![0xabc].span());
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
    let (
        _commitment_registry,
        _shielded_asset_adapter,
        privacy_deposit_bridge,
        registry,
        bridge,
        verifier,
    ) =
        setup_privacy_activation_stack(
        admin,
    );

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    privacy_invoke_single(bridge, FUNDING_COMMITMENT, deposit_root(), ENCRYPTED_NOTE_ACTIVATION);
    stop_cheat_caller_address(privacy_deposit_bridge);

    assert(registry.is_funding_commitment_registered(FUNDING_COMMITMENT), 'FUNDING_MISSING');
    assert(registry.funding_activation_root(FUNDING_COMMITMENT) == deposit_root(), 'BAD_ROOT');
    assert(
        registry.funding_activation_ciphertext(FUNDING_COMMITMENT) == ENCRYPTED_NOTE_ACTIVATION,
        'BAD_ACTIVATION',
    );
    assert(registry.funding_activation_count() == 1, 'BAD_ACTIVATION_COUNT');
    let record = registry.funding_activation_record(0);
    assert(record.activation_id == 0, 'BAD_ACTIVATION_ID');
    assert(record.funding_commitment == FUNDING_COMMITMENT, 'BAD_FUNDING_RECORD');
    assert(record.deposit_root == deposit_root(), 'BAD_RECORD_ROOT');
    assert(record.encrypted_note_activation == ENCRYPTED_NOTE_ACTIVATION, 'BAD_RECORD_ACT');
    let (current_note_root, current_nullifier_root, current_renewal_root, current_fee_root) =
        verifier
        .current_settlement_roots();
    assert(current_note_root == root_only_state_transition(0, deposit_root()), 'BAD_DEPOSIT_ROOT');
    assert(current_nullifier_root == 0, 'BAD_NULLIFIER_ROOT');
    assert(current_renewal_root == 0, 'BAD_RENEWAL_ROOT');
    assert(current_fee_root == 0, 'BAD_FEE_ROOT');
}

#[test]
#[should_panic]
fn commitment_registry_rejects_deposit_activation_without_auction_verifier() {
    let admin = as_address(0x111);
    let privacy_deposit_bridge = as_address(0x222);
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_privacy_deposit_bridge(privacy_deposit_bridge);
    stop_cheat_caller_address(commitment_registry);

    start_cheat_caller_address(commitment_registry, privacy_deposit_bridge);
    registry
        .register_funding_activation(FUNDING_COMMITMENT, deposit_root(), ENCRYPTED_NOTE_ACTIVATION);
}

#[test]
#[should_panic]
fn commitment_registry_rejects_duplicate_single_deposit_commitment() {
    let admin = as_address(0x111);
    let privacy_deposit_bridge = as_address(0x222);
    let commitment_registry = deploy_commitment_registry(admin);
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_privacy_deposit_bridge(privacy_deposit_bridge);
    registry.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(commitment_registry);
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_deposit_root_registrar(commitment_registry);
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(commitment_registry, privacy_deposit_bridge);
    registry
        .register_funding_activation(FUNDING_COMMITMENT, deposit_root(), ENCRYPTED_NOTE_ACTIVATION);
    registry
        .register_funding_activation(
            FUNDING_COMMITMENT, second_deposit_root(), SECOND_ENCRYPTED_NOTE_ACTIVATION,
        );
}

#[test]
#[should_panic]
fn privacy_deposit_bridge_rejects_duplicate_single_funding_after_success() {
    let admin = as_address(0x111);
    let (_, _, privacy_deposit_bridge, _, bridge, _) = setup_privacy_activation_stack(admin);

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    privacy_invoke_single(bridge, FUNDING_COMMITMENT, deposit_root(), ENCRYPTED_NOTE_ACTIVATION);
    privacy_invoke_single_with_note(
        bridge,
        FUNDING_COMMITMENT,
        second_deposit_root(),
        SECOND_ENCRYPTED_NOTE_ACTIVATION,
        SECOND_NOTE_COMMITMENT,
        SECOND_DEPOSIT_AMOUNT,
        SECOND_DEPOSIT_WITHDRAW_AUTHORITY,
    );
}

#[test]
#[should_panic]
fn privacy_deposit_bridge_rejects_zero_funding_commitment() {
    let admin = as_address(0x111);
    let (_, _, privacy_deposit_bridge, _, bridge, _) = setup_privacy_activation_stack(admin);

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    privacy_invoke_single(bridge, 0, deposit_root(), ENCRYPTED_NOTE_ACTIVATION);
}

#[test]
#[should_panic]
fn privacy_deposit_bridge_rejects_zero_deposit_root() {
    let admin = as_address(0x111);
    let (_, _, privacy_deposit_bridge, _, bridge, _) = setup_privacy_activation_stack(admin);

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    privacy_invoke_single(bridge, FUNDING_COMMITMENT, 0, ENCRYPTED_NOTE_ACTIVATION);
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
    verifier.set_deposit_root_registrar(commitment_registry);
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(auction_verifier, commitment_registry);
    verifier.activate_deposit_root(FUNDING_COMMITMENT, deposit_root());
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
    let (_, _, privacy_deposit_bridge, registry, bridge, verifier) = setup_privacy_activation_stack(
        admin,
    );

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    privacy_invoke_single(bridge, FUNDING_COMMITMENT, deposit_root(), ENCRYPTED_NOTE_ACTIVATION);
    stop_cheat_caller_address(privacy_deposit_bridge);

    assert(registry.is_funding_commitment_registered(FUNDING_COMMITMENT), 'NOTE_NOT_REGISTERED');
    assert(registry.funding_activation_root(FUNDING_COMMITMENT) == deposit_root(), 'BAD_ROOT');
    let (current_note_root, current_nullifier_root, current_renewal_root, current_fee_root) =
        verifier
        .current_settlement_roots();
    assert(
        current_note_root == root_only_state_transition(0, deposit_root()), 'BAD_PRIV_DEPOSIT_ROOT',
    );
    assert(current_nullifier_root == 0, 'BAD_NULLIFIER_ROOT');
    assert(current_renewal_root == 0, 'BAD_RENEWAL_ROOT');
    assert(current_fee_root == 0, 'BAD_FEE_ROOT');
}

#[test]
fn privacy_deposit_bridge_registers_batched_privacy_funded_notes() {
    let admin = as_address(0x111);
    let (_, _, privacy_deposit_bridge, registry, bridge, verifier) = setup_privacy_activation_stack(
        admin,
    );
    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    let open_deposits = bridge
        .privacy_invoke(
            array![FUNDING_COMMITMENT, SECOND_FUNDING_COMMITMENT].span(),
            array![deposit_root(), second_deposit_root()].span(),
            array![ENCRYPTED_NOTE_ACTIVATION, SECOND_ENCRYPTED_NOTE_ACTIVATION].span(),
        );
    assert(open_deposits.len() == 0, 'OPEN_DEPOSITS_RETURNED');
    stop_cheat_caller_address(privacy_deposit_bridge);

    assert(registry.is_funding_commitment_registered(FUNDING_COMMITMENT), 'FIRST_NOT_REGISTERED');
    assert(
        registry.is_funding_commitment_registered(SECOND_FUNDING_COMMITMENT),
        'SECOND_NOT_REGISTERED',
    );
    assert(registry.funding_activation_count() == 2, 'BAD_DEPOSIT_COUNT');
    assert(registry.funding_activation_record(0).funding_commitment == FUNDING_COMMITMENT, 'BAD_0');
    assert(
        registry.funding_activation_record(1).funding_commitment == SECOND_FUNDING_COMMITMENT,
        'BAD_1',
    );

    let first_root = root_only_state_transition(0, deposit_root());
    let second_root = root_only_state_transition(first_root, second_deposit_root());
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
fn privacy_deposit_bridge_rejects_duplicate_batch_funding_commitments() {
    let admin = as_address(0x111);
    let (_, _, privacy_deposit_bridge, _, bridge, _) = setup_privacy_activation_stack(admin);
    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    bridge
        .privacy_invoke(
            array![FUNDING_COMMITMENT, FUNDING_COMMITMENT].span(),
            array![deposit_root(), second_deposit_root()].span(),
            array![ENCRYPTED_NOTE_ACTIVATION, SECOND_ENCRYPTED_NOTE_ACTIVATION].span(),
        );
}

#[test]
#[should_panic]
fn privacy_deposit_bridge_rejects_duplicate_batch_deposit_roots() {
    let admin = as_address(0x111);
    let (_, _, privacy_deposit_bridge, _, bridge, _) = setup_privacy_activation_stack(admin);
    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    bridge
        .privacy_invoke(
            array![FUNDING_COMMITMENT, SECOND_FUNDING_COMMITMENT].span(),
            array![deposit_root(), deposit_root()].span(),
            array![ENCRYPTED_NOTE_ACTIVATION, SECOND_ENCRYPTED_NOTE_ACTIVATION].span(),
        );
}

#[test]
#[should_panic]
fn privacy_deposit_bridge_rejects_non_privacy_pool_callers() {
    let admin = as_address(0x111);
    let wrong_caller = as_address(0x333);
    let (_, _, privacy_deposit_bridge, _, bridge, _) = setup_privacy_activation_stack(admin);

    start_cheat_caller_address(privacy_deposit_bridge, wrong_caller);
    privacy_invoke_single(bridge, FUNDING_COMMITMENT, deposit_root(), ENCRYPTED_NOTE_ACTIVATION);
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
fn privacy_proof_signer_rejects_replayed_relay_nonce_with_different_calldata() {
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let proof_signer = deploy_privacy_proof_signer(key_pair.public_key);
    let spender = as_address(0x456);
    let token_address = deploy_mock_erc20();
    let signer = IPrivacyProofSignerDispatcher { contract_address: proof_signer };
    let first_calldata = array![spender.into(), 100, 0];
    let first_calls = array![
        Call { to: token_address, selector: selector!("approve"), calldata: first_calldata.span() },
    ];
    let second_calldata = array![spender.into(), 200, 0];
    let second_calls = array![
        Call {
            to: token_address, selector: selector!("approve"), calldata: second_calldata.span(),
        },
    ];
    let nonce = 0x777;

    cheat_chain_id(proof_signer, TEST_CHAIN_ID, CheatSpan::TargetCalls(4));
    let first_message = signer.relay_message_hash(first_calls.span(), nonce);
    let (first_r, first_s) = StarkCurveSignerImpl::sign(key_pair, first_message).unwrap();
    signer.execute_from_relayer(first_calls.span(), nonce, first_r, first_s);

    let second_message = signer.relay_message_hash(second_calls.span(), nonce);
    let (second_r, second_s) = StarkCurveSignerImpl::sign(key_pair, second_message).unwrap();
    signer.execute_from_relayer(second_calls.span(), nonce, second_r, second_s);
}

#[test]
#[should_panic]
fn shielded_asset_adapter_rejects_short_transfer_verified_withdrawal() {
    let admin = as_address(0x111);
    let auction_verifier = as_address(0x444);
    let recipient = as_address(0x555);
    let token_address = deploy_configurable_mock_erc20();
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let token = IConfigurableMockERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };

    token.mint(shielded_asset_adapter, as_u256(500));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.set_auction_verifier(auction_verifier);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    token.set_short_transfer(true);
    start_cheat_caller_address(shielded_asset_adapter, auction_verifier);
    adapter.withdraw_verified_note(ASSET_ID, 200, NOTE_COMMITMENT + 0x100, recipient);
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
fn auction_verifier_rejects_duplicate_renewal_parent_cancel_marker() {
    let admin = as_address(0x111);
    let cancel_marker = 0xdea;
    let cancel_marker_key_low: u128 = 0xdea;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let cancel_message = renewal_parent_cancel_marker_message_hash_for_verifier(
        auction_verifier, TEST_CHAIN_ID, cancel_marker,
    );
    let (cancel_r, cancel_s) = StarkCurveSignerImpl::sign(key_pair, cancel_message).unwrap();
    let empty_path = array![];

    cheat_chain_id(auction_verifier, TEST_CHAIN_ID, CheatSpan::TargetCalls(2));
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
#[should_panic]
fn auction_verifier_rejects_unauthorized_admission_recording() {
    let admin = as_address(0x111);
    let attacker = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, attacker);
    verifier.record_admission_root_with_proof_facts(1, 2, 3);
}

#[test]
#[should_panic]
fn auction_verifier_rejects_unauthorized_auction_recording() {
    let admin = as_address(0x111);
    let attacker = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, attacker);
    verifier.record_auction_result_with_proof_facts(1, 2, 3, 4);
}

#[test]
#[should_panic]
fn auction_verifier_rejects_unauthorized_nullifier_recording() {
    let admin = as_address(0x111);
    let attacker = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, attacker);
    verifier.record_nullifier_roots_with_proof_facts(1, 2, 3, 4, 5);
}

#[test]
#[should_panic]
fn auction_verifier_rejects_unauthorized_renewal_recording() {
    let admin = as_address(0x111);
    let attacker = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, attacker);
    verifier.record_renewal_roots_with_proof_facts(1, 2, 3, 4, 5);
}

#[test]
#[should_panic]
fn auction_verifier_rejects_unauthorized_aggregate_settlement() {
    let admin = as_address(0x111);
    let attacker = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let inputs = array![0];

    start_cheat_caller_address(auction_verifier, attacker);
    verifier.submit_aggregate_settlements_with_proof_facts(inputs.span());
}

#[test]
#[should_panic]
fn auction_verifier_pause_blocks_nullifier_recording() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    verifier.pause();
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.record_nullifier_roots_with_proof_facts(1, 2, 3, 4, 5);
}

#[test]
#[should_panic]
fn auction_verifier_pause_blocks_renewal_recording() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    verifier.pause();
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.record_renewal_roots_with_proof_facts(1, 2, 3, 4, 5);
}

#[test]
#[should_panic]
fn auction_verifier_pause_blocks_aggregate_settlement() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let inputs = array![0];

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    verifier.pause();
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.submit_aggregate_settlements_with_proof_facts(inputs.span());
}

#[test]
#[should_panic]
fn auction_verifier_pause_blocks_note_consolidation() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.pause();
    stop_cheat_caller_address(auction_verifier);

    verifier.submit_note_consolidation_with_proof_facts(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
}

#[test]
#[should_panic]
fn auction_verifier_pause_blocks_withdrawal() {
    let admin = as_address(0x111);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let empty_path = array![];

    start_cheat_caller_address(auction_verifier, admin);
    verifier.pause();
    stop_cheat_caller_address(auction_verifier);

    verifier
        .withdraw_settlement_output_with_proof_facts(
            1,
            2,
            3,
            4,
            5,
            6,
            ASSET_ID,
            7,
            8,
            empty_path.span(),
            empty_path.span(),
            9,
            10,
            as_address(0x333),
        );
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
#[should_panic]
fn auction_verifier_rejects_empty_aggregate() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let inputs = array![0];
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.submit_aggregate_settlements_with_proof_facts(inputs.span());
}

#[test]
#[should_panic]
fn auction_verifier_rejects_truncated_aggregate_calldata() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let inputs = array![1, 0xabc];
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.submit_aggregate_settlements_with_proof_facts(inputs.span());
}

#[test]
#[should_panic]
fn auction_verifier_rejects_trailing_aggregate_calldata() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let (mut inputs, messages) = sample_single_aggregate_inputs(auction_verifier, verifier);
    inputs.append(0xdead);
    let proof_facts = valid_aggregate_proof_facts(99, messages.span());
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.submit_aggregate_settlements_with_proof_facts(inputs.span());
}

#[test]
#[should_panic]
fn auction_verifier_rejects_aggregate_missing_proof_messages() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let (inputs, messages) = sample_single_aggregate_inputs(auction_verifier, verifier);
    let short_messages = array![*messages.at(0), *messages.at(1)];
    let proof_facts = valid_aggregate_proof_facts(99, short_messages.span());
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.submit_aggregate_settlements_with_proof_facts(inputs.span());
}

#[test]
#[should_panic]
fn auction_verifier_rejects_aggregate_extra_proof_messages() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let (inputs, messages) = sample_single_aggregate_inputs(auction_verifier, verifier);
    let extra_messages = array![*messages.at(0), *messages.at(1), *messages.at(2), 0xdead];
    let proof_facts = valid_aggregate_proof_facts(99, extra_messages.span());
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.submit_aggregate_settlements_with_proof_facts(inputs.span());
}

#[test]
#[should_panic]
fn auction_verifier_rejects_aggregate_wrong_proof_message_order() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let (inputs, messages) = sample_single_aggregate_inputs(auction_verifier, verifier);
    let reordered_messages = array![*messages.at(2), *messages.at(1), *messages.at(0)];
    let proof_facts = valid_aggregate_proof_facts(99, reordered_messages.span());
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.submit_aggregate_settlements_with_proof_facts(inputs.span());
}

#[test]
#[should_panic]
fn auction_verifier_rejects_aggregate_duplicate_proof_messages() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let (inputs, messages) = sample_single_aggregate_inputs(auction_verifier, verifier);
    let duplicate_messages = array![*messages.at(0), *messages.at(1), *messages.at(1)];
    let proof_facts = valid_aggregate_proof_facts(99, duplicate_messages.span());
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.submit_aggregate_settlements_with_proof_facts(inputs.span());
}

#[test]
#[should_panic]
fn auction_verifier_rejects_aggregate_duplicate_batch_record() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches.register_batch(0xabc01, 0x888, 1, 2, 0, 0x111, 0x222);
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let (single_inputs, messages) = sample_single_aggregate_inputs(auction_verifier, verifier);
    let transcript_commitment = *single_inputs.at(4);
    record_split_auction_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        0xabc01,
        0x111,
        0x337,
        transcript_commitment,
    );

    let mut duplicate_inputs = array![2];
    append_aggregate_record_copy(ref duplicate_inputs, single_inputs.span());
    append_aggregate_record_copy(ref duplicate_inputs, single_inputs.span());
    let duplicate_messages = array![
        *messages.at(0), *messages.at(1), *messages.at(2), *messages.at(0), *messages.at(1),
        *messages.at(2),
    ];
    let proof_facts = valid_aggregate_proof_facts(99, duplicate_messages.span());
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.submit_aggregate_settlements_with_proof_facts(duplicate_inputs.span());
}

#[test]
#[should_panic]
fn auction_verifier_rejects_aggregate_stale_member_note_root() {
    let first_new_fee_root = root_only_state_transition(0, empty_fee_root());
    submit_two_batch_aggregate_with_roots(0, 0, 0, 0, 0, first_new_fee_root, first_new_fee_root);
}

#[test]
#[should_panic]
fn auction_verifier_rejects_aggregate_duplicate_nullifier_transition() {
    let first_new_note_root = root_only_state_transition(0, 0);
    let first_new_fee_root = root_only_state_transition(0, empty_fee_root());
    submit_two_batch_aggregate_with_roots(
        first_new_note_root, 0x1234, 0, 0, 0, first_new_fee_root, first_new_fee_root,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_aggregate_mismatched_renewal_transition() {
    let first_new_note_root = root_only_state_transition(0, 0);
    let first_new_fee_root = root_only_state_transition(0, empty_fee_root());
    submit_two_batch_aggregate_with_roots(
        first_new_note_root, 0, 0, 0x5678, 0, first_new_fee_root, first_new_fee_root,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_aggregate_mismatched_fee_root() {
    let first_new_note_root = root_only_state_transition(0, 0);
    let first_new_fee_root = root_only_state_transition(0, empty_fee_root());
    submit_two_batch_aggregate_with_roots(first_new_note_root, 0, 0, 0, 0, first_new_fee_root, 0);
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
fn auction_verifier_refreshes_unsettled_split_root_proofs() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x77a;
    let pair_id = 0x888;
    let order_commitment_root = 0x1111;
    let encrypted_order_set_commitment = 0x2222;
    let clearing_price = 4_u128;
    let output_bundle_ref = 0x3333;
    let batch_registry = deploy_batch_registry(admin, admin);
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id, pair_id, 1, 2, 3, order_commitment_root, encrypted_order_set_commitment,
        );
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let first_consumed_nullifier_root = 0x101;
    let first_new_nullifier_root = 0x201;
    let first_renewal_child_root = 0x301;
    let first_new_renewal_root = 0x401;
    let first_transcript_commitment = root_only_public_settlement_commitment(
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
        first_consumed_nullifier_root,
        first_renewal_child_root,
        0,
        0,
        root_only_state_transition(0, 0),
        first_new_nullifier_root,
        first_new_renewal_root,
        root_only_state_transition(0, 0),
    );
    record_split_auction_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        order_commitment_root,
        0x339,
        first_transcript_commitment,
    );
    record_root_transition_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        first_transcript_commitment,
        0,
        first_consumed_nullifier_root,
        first_new_nullifier_root,
        0,
        first_renewal_child_root,
        first_new_renewal_root,
    );

    let second_consumed_nullifier_root = 0x102;
    let second_new_nullifier_root = 0x202;
    let second_renewal_child_root = 0x302;
    let second_new_renewal_root = 0x402;
    let second_transcript_commitment = root_only_public_settlement_commitment(
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
        second_consumed_nullifier_root,
        second_renewal_child_root,
        0,
        0,
        root_only_state_transition(0, 0),
        second_new_nullifier_root,
        second_new_renewal_root,
        root_only_state_transition(0, 0),
    );
    let auction_statement = native_auction_result_message_hash(
        auction_verifier, batch_id, order_commitment_root, 0x339, second_transcript_commitment,
    );
    let auction_proof_message = auction_result_proof_message_hash(
        auction_verifier, auction_statement,
    );
    let auction_proof_facts = valid_proof_facts(99, auction_proof_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, auction_proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .record_auction_result_with_proof_facts(
            batch_id, order_commitment_root, 0x339, second_transcript_commitment,
        );
    stop_cheat_caller_address(auction_verifier);
    record_root_transition_proofs(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        second_transcript_commitment,
        0,
        second_consumed_nullifier_root,
        second_new_nullifier_root,
        0,
        second_renewal_child_root,
        second_new_renewal_root,
    );

    let settlement_proof_message = verifier
        .settlement_proof_message_hash(second_transcript_commitment);
    let settlement_proof_facts = valid_proof_facts(99, settlement_proof_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, settlement_proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_root_settlement(
        verifier,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        second_transcript_commitment,
        native_settlement_message_hash(auction_verifier, second_transcript_commitment),
        clearing_price,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        second_consumed_nullifier_root,
        second_renewal_child_root,
        0,
        0,
        root_only_state_transition(0, 0),
        second_new_nullifier_root,
        second_new_renewal_root,
        root_only_state_transition(0, 0),
    );
    stop_cheat_caller_address(auction_verifier);

    let (_, current_nullifier_root, current_renewal_root, _) = verifier.current_settlement_roots();
    assert(current_nullifier_root == second_new_nullifier_root, 'BAD_REFRESH_NULL_ROOT');
    assert(current_renewal_root == second_new_renewal_root, 'BAD_REFRESH_RENEW_ROOT');
}

#[test]
#[should_panic]
fn auction_verifier_blocks_second_batch_root_transition_while_first_is_unsettled() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(batch_registry, admin, auction_verifier, 0x7a1, 0x888, 1, 0x111, 0x221);
    register_prepared_batch(batch_registry, admin, auction_verifier, 0x7a2, 0x889, 2, 0x112, 0x222);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    prepare_empty_root_transition(
        auction_verifier,
        verifier,
        settlement_account,
        0x7a1,
        0x888,
        1,
        0x111,
        0x221,
        0,
        0x991,
        0x341,
    );
    prepare_empty_root_transition(
        auction_verifier,
        verifier,
        settlement_account,
        0x7a2,
        0x889,
        2,
        0x112,
        0x222,
        0,
        0x992,
        0x342,
    );
}

#[test]
#[should_panic]
fn auction_verifier_blocks_unauthorized_root_transition_clear() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let attacker = as_address(0x333);
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(batch_registry, admin, auction_verifier, 0x7b1, 0x888, 1, 0x111, 0x221);
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);
    prepare_empty_root_transition(
        auction_verifier,
        verifier,
        settlement_account,
        0x7b1,
        0x888,
        1,
        0x111,
        0x221,
        0,
        0x991,
        0x343,
    );

    start_cheat_caller_address(auction_verifier, attacker);
    verifier.clear_unsettled_root_transition(0x7b1);
}

#[test]
#[should_panic]
fn auction_verifier_blocks_wrong_batch_root_transition_clear() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(batch_registry, admin, auction_verifier, 0x7c1, 0x888, 1, 0x111, 0x221);
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);
    prepare_empty_root_transition(
        auction_verifier,
        verifier,
        settlement_account,
        0x7c1,
        0x888,
        1,
        0x111,
        0x221,
        0,
        0x991,
        0x344,
    );

    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.clear_unsettled_root_transition(0x7c2);
}

#[test]
#[should_panic]
fn auction_verifier_pause_blocks_root_transition_clear() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(batch_registry, admin, auction_verifier, 0x7c3, 0x888, 1, 0x111, 0x221);
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);
    prepare_empty_root_transition(
        auction_verifier,
        verifier,
        settlement_account,
        0x7c3,
        0x888,
        1,
        0x111,
        0x221,
        0,
        0x991,
        0x344,
    );

    start_cheat_caller_address(auction_verifier, admin);
    verifier.pause();
    stop_cheat_caller_address(auction_verifier);
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.clear_unsettled_root_transition(0x7c3);
}

#[test]
fn auction_verifier_allows_authorized_root_transition_clear_before_refreshing_another_batch() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(batch_registry, admin, auction_verifier, 0x7d1, 0x888, 1, 0x111, 0x221);
    register_prepared_batch(batch_registry, admin, auction_verifier, 0x7d2, 0x889, 2, 0x112, 0x222);
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);
    prepare_empty_root_transition(
        auction_verifier,
        verifier,
        settlement_account,
        0x7d1,
        0x888,
        1,
        0x111,
        0x221,
        0,
        0x991,
        0x345,
    );

    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier.clear_unsettled_root_transition(0x7d1);
    stop_cheat_caller_address(auction_verifier);

    prepare_empty_root_transition(
        auction_verifier,
        verifier,
        settlement_account,
        0x7d2,
        0x889,
        2,
        0x112,
        0x222,
        0,
        0x992,
        0x346,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_stale_fee_bps_at_settlement() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let batch_id = 0x7e1;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 0_u128;
    let output_bundle_ref = 0x999;

    register_prepared_batch(
        batch_registry,
        admin,
        auction_verifier,
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
    );
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);
    let transcript_commitment = prepare_empty_root_transition(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        0x347,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_root_settlement_with_fee_config(
        verifier,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        transcript_commitment,
        native_settlement_message_hash(auction_verifier, transcript_commitment),
        clearing_price,
        TEST_PRICE_BASE_SCALE,
        TEST_TAKER_FEE_BPS + 1,
        TEST_MAKER_FEE_BPS,
        TEST_RELAY_FEE_BPS,
        TEST_PROTOCOL_FEE_RECIPIENT,
        TEST_RELAY_FEE_RECIPIENT,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, array![].span()),
        empty_renewal_child_root(),
        0,
        0,
        root_only_state_transition(0, 0),
        0,
        0,
        root_only_state_transition(0, 0),
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_stale_fee_recipient_at_settlement() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let batch_id = 0x7e2;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 0_u128;
    let output_bundle_ref = 0x999;

    register_prepared_batch(
        batch_registry,
        admin,
        auction_verifier,
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
    );
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);
    let transcript_commitment = prepare_empty_root_transition(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        0x348,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    submit_root_settlement_with_fee_config(
        verifier,
        batch_id,
        order_commitment_root,
        encrypted_order_set_commitment,
        transcript_commitment,
        native_settlement_message_hash(auction_verifier, transcript_commitment),
        clearing_price,
        TEST_PRICE_BASE_SCALE,
        TEST_TAKER_FEE_BPS,
        TEST_MAKER_FEE_BPS,
        TEST_RELAY_FEE_BPS,
        TEST_PROTOCOL_FEE_RECIPIENT + 1,
        TEST_RELAY_FEE_RECIPIENT,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, array![].span()),
        empty_renewal_child_root(),
        0,
        0,
        root_only_state_transition(0, 0),
        0,
        0,
        root_only_state_transition(0, 0),
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_wrong_fee_root_at_settlement() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let batch_id = 0x7e3;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 0_u128;
    let output_bundle_ref = 0x999;

    register_prepared_batch(
        batch_registry,
        admin,
        auction_verifier,
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
    );
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);
    let transcript_commitment = prepare_empty_root_transition(
        auction_verifier,
        verifier,
        settlement_account,
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        0x349,
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
        native_settlement_message_hash(auction_verifier, transcript_commitment),
        clearing_price,
        output_bundle_ref,
        0,
        0,
        0,
        0,
        0,
        single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, array![].span()),
        empty_renewal_child_root(),
        0,
        empty_fee_root() + 1,
        root_only_state_transition(0, 0),
        0,
        0,
        root_only_state_transition(0, empty_fee_root() + 1),
    );
}

#[test]
fn auction_verifier_accepts_permissionless_note_consolidation_proof_facts() {
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
    start_cheat_caller_address(auction_verifier, as_address(0x333));
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

    assert(!verifier.is_batch_settled(consolidation_id), 'CONSOL_IS_BATCH');
    assert(verifier.is_consolidation_settled(consolidation_id), 'CONSOL_NOT_SETTLED');
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
fn auction_verifier_rejects_duplicate_note_consolidation_id() {
    let admin = as_address(0x111);
    let consolidation_id = 0x783;
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

    start_cheat_caller_address(auction_verifier, as_address(0x333));
    submit_note_consolidation_with_matching_proof(
        verifier,
        auction_verifier,
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
    submit_note_consolidation_with_matching_proof(
        verifier,
        auction_verifier,
        consolidation_id,
        output_bundle_ref,
        new_note_root,
        new_nullifier_root,
        consumed_note_root,
        consumed_nullifier_root + 1,
        output_note_root + 1,
        root_only_state_transition(new_note_root, output_note_root + 1),
        new_nullifier_root + 1,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_note_consolidation_stale_roots() {
    let admin = as_address(0x111);
    let first_consolidation_id = 0x784;
    let stale_consolidation_id = 0x785;
    let output_bundle_ref = 0x999;
    let first_output_root = 0x1234;
    let first_new_note_root = root_only_state_transition(0, first_output_root);
    let first_new_nullifier_root = 0x5678;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, as_address(0x333));
    submit_note_consolidation_with_matching_proof(
        verifier,
        auction_verifier,
        first_consolidation_id,
        output_bundle_ref,
        0,
        0,
        0xabc,
        0xdef,
        first_output_root,
        first_new_note_root,
        first_new_nullifier_root,
    );
    submit_note_consolidation_with_matching_proof(
        verifier,
        auction_verifier,
        stale_consolidation_id,
        output_bundle_ref,
        0,
        0,
        0xabc + 1,
        0xdef + 1,
        0x2234,
        root_only_state_transition(0, 0x2234),
        0x6678,
    );
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
fn auction_verifier_rejects_zero_base_block_hash() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let transcript_commitment = 2;

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = proof_facts_for_message_and_context(
        99,
        proof_message_hash,
        VIRTUAL_SNOS,
        VIRTUAL_SNOS0,
        TEST_PROOF_PROGRAM_HASH,
        0,
        TEST_OS_CONFIG_HASH,
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
fn auction_verifier_rejects_wrong_os_config_hash() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(admin, as_address(0x444));
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let transcript_commitment = 2;

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = proof_facts_for_message_and_context(
        99,
        proof_message_hash,
        VIRTUAL_SNOS,
        VIRTUAL_SNOS0,
        TEST_PROOF_PROGRAM_HASH,
        TEST_BASE_BLOCK_HASH,
        TEST_OS_CONFIG_HASH + 1,
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
fn auction_verifier_rejects_wrong_proof_version() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x7f1;
    let order_commitment_root = 0x111;
    let admission_root = 0x333;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(
        batch_registry, admin, auction_verifier, batch_id, 0x888, 1, order_commitment_root, 0x222,
    );
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let admission_statement = native_admission_message_hash(
        auction_verifier, batch_id, order_commitment_root, admission_root,
    );
    let admission_message = admission_proof_message_hash(auction_verifier, admission_statement);
    let proof_facts = proof_facts_for_message_with_version(99, admission_message, 1);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .record_admission_root_with_proof_facts(batch_id, order_commitment_root, admission_root);
}

#[test]
#[should_panic]
fn auction_verifier_rejects_wrong_program_variant() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x7f2;
    let order_commitment_root = 0x111;
    let admission_root = 0x333;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(
        batch_registry, admin, auction_verifier, batch_id, 0x888, 1, order_commitment_root, 0x222,
    );
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let admission_statement = native_admission_message_hash(
        auction_verifier, batch_id, order_commitment_root, admission_root,
    );
    let admission_message = admission_proof_message_hash(auction_verifier, admission_statement);
    let proof_facts = proof_facts_for_message(
        99, admission_message, VIRTUAL_SNOS + 1, VIRTUAL_SNOS0,
    );
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .record_admission_root_with_proof_facts(batch_id, order_commitment_root, admission_root);
}

#[test]
#[should_panic]
fn auction_verifier_rejects_extra_single_statement_proof_messages() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x7f3;
    let order_commitment_root = 0x111;
    let admission_root = 0x333;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(
        batch_registry, admin, auction_verifier, batch_id, 0x888, 1, order_commitment_root, 0x222,
    );
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let admission_statement = native_admission_message_hash(
        auction_verifier, batch_id, order_commitment_root, admission_root,
    );
    let admission_message = admission_proof_message_hash(auction_verifier, admission_statement);
    let extra_messages = array![admission_message, admission_message];
    let proof_facts = valid_aggregate_proof_facts(99, extra_messages.span());
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .record_admission_root_with_proof_facts(batch_id, order_commitment_root, admission_root);
}

#[test]
#[should_panic]
fn auction_verifier_rejects_admission_proof_for_wrong_batch() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x7f4;
    let wrong_batch_id = 0x7f5;
    let order_commitment_root = 0x111;
    let admission_root = 0x333;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(
        batch_registry, admin, auction_verifier, batch_id, 0x888, 1, order_commitment_root, 0x222,
    );
    register_prepared_batch(
        batch_registry,
        admin,
        auction_verifier,
        wrong_batch_id,
        0x888,
        1,
        order_commitment_root,
        0x223,
    );
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let admission_statement = native_admission_message_hash(
        auction_verifier, batch_id, order_commitment_root, admission_root,
    );
    let admission_message = admission_proof_message_hash(auction_verifier, admission_statement);
    let proof_facts = valid_proof_facts(99, admission_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .record_admission_root_with_proof_facts(
            wrong_batch_id, order_commitment_root, admission_root,
        );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_admission_proof_for_wrong_order_root() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x7f6;
    let order_commitment_root = 0x111;
    let wrong_order_commitment_root = 0x112;
    let admission_root = 0x333;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(
        batch_registry, admin, auction_verifier, batch_id, 0x888, 1, order_commitment_root, 0x222,
    );
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let admission_statement = native_admission_message_hash(
        auction_verifier, batch_id, order_commitment_root, admission_root,
    );
    let admission_message = admission_proof_message_hash(auction_verifier, admission_statement);
    let proof_facts = valid_proof_facts(99, admission_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .record_admission_root_with_proof_facts(
            batch_id, wrong_order_commitment_root, admission_root,
        );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_admission_proof_for_wrong_admission_root() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x7f7;
    let order_commitment_root = 0x111;
    let admission_root = 0x333;
    let wrong_admission_root = 0x334;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(
        batch_registry, admin, auction_verifier, batch_id, 0x888, 1, order_commitment_root, 0x222,
    );
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let admission_statement = native_admission_message_hash(
        auction_verifier, batch_id, order_commitment_root, admission_root,
    );
    let admission_message = admission_proof_message_hash(auction_verifier, admission_statement);
    let proof_facts = valid_proof_facts(99, admission_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .record_admission_root_with_proof_facts(
            batch_id, order_commitment_root, wrong_admission_root,
        );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_auction_result_for_wrong_admission_root() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x7f8;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let admission_root = 0x333;
    let wrong_admission_root = 0x334;
    let transcript_commitment = 0x444;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(
        batch_registry, admin, auction_verifier, batch_id, pair_id, 1, order_commitment_root, 0x222,
    );
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let admission_statement = native_admission_message_hash(
        auction_verifier, batch_id, order_commitment_root, admission_root,
    );
    let admission_message = admission_proof_message_hash(auction_verifier, admission_statement);
    let admission_proof_facts = valid_proof_facts(99, admission_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, admission_proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .record_admission_root_with_proof_facts(batch_id, order_commitment_root, admission_root);

    let auction_statement = native_auction_result_message_hash(
        auction_verifier, batch_id, order_commitment_root, admission_root, transcript_commitment,
    );
    let auction_message = auction_result_proof_message_hash(auction_verifier, auction_statement);
    let auction_proof_facts = valid_proof_facts(99, auction_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, auction_proof_facts.span(), CheatSpan::TargetCalls(1));
    verifier
        .record_auction_result_with_proof_facts(
            batch_id, order_commitment_root, wrong_admission_root, transcript_commitment,
        );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_auction_result_for_wrong_transcript_commitment() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let batch_id = 0x7f9;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let admission_root = 0x333;
    let transcript_commitment = 0x444;
    let wrong_transcript_commitment = 0x445;
    let batch_registry = deploy_batch_registry(admin, admin);
    let auction_verifier = deploy_auction_verifier(admin, batch_registry);
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    register_prepared_batch(
        batch_registry, admin, auction_verifier, batch_id, pair_id, 1, order_commitment_root, 0x222,
    );
    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let admission_statement = native_admission_message_hash(
        auction_verifier, batch_id, order_commitment_root, admission_root,
    );
    let admission_message = admission_proof_message_hash(auction_verifier, admission_statement);
    let admission_proof_facts = valid_proof_facts(99, admission_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, admission_proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .record_admission_root_with_proof_facts(batch_id, order_commitment_root, admission_root);

    let auction_statement = native_auction_result_message_hash(
        auction_verifier, batch_id, order_commitment_root, admission_root, transcript_commitment,
    );
    let auction_message = auction_result_proof_message_hash(auction_verifier, auction_statement);
    let auction_proof_facts = valid_proof_facts(99, auction_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, auction_proof_facts.span(), CheatSpan::TargetCalls(1));
    verifier
        .record_auction_result_with_proof_facts(
            batch_id, order_commitment_root, admission_root, wrong_transcript_commitment,
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
fn auction_verifier_withdraws_settlement_output_with_nullifier_proof_facts() {
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
    let token = IERC20Dispatcher { contract_address: token_address };
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
    let consumed_nullifiers = array![0xdeadbeef];
    let consumed_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, consumed_nullifiers.span(),
    );
    let new_nullifier_root = 0x5678;
    let withdrawal_commitment = public_note_withdrawal_commitment(
        batch_id,
        output_note_commitment,
        ASSET_ID,
        output_amount,
        withdraw_authority,
        0,
        consumed_nullifier_root,
        new_nullifier_root,
    );
    let withdrawal_statement = native_withdrawal_message_hash(
        auction_verifier, withdrawal_commitment,
    );
    let withdrawal_proof_message = withdrawal_proof_message_hash(
        auction_verifier, withdrawal_statement,
    );
    let withdrawal_proof_facts = valid_proof_facts(99, withdrawal_proof_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_chain_id(auction_verifier, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, withdrawal_proof_facts.span(), CheatSpan::TargetCalls(1));
    let (asset_id, amount) = verifier
        .withdraw_settlement_output_with_proof_facts(
            batch_id,
            withdrawal_statement,
            0,
            consumed_nullifier_root,
            new_nullifier_root,
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
    assert(adapter.withdrawal_recipient(output_note_commitment) == recipient, 'BAD_OUT_RECIPIENT');
    let (_, current_nullifier_root, _, _) = verifier.current_settlement_roots();
    assert(current_nullifier_root == new_nullifier_root, 'BAD_WITHDRAW_NULL_ROOT');
}

#[test]
#[should_panic]
fn auction_verifier_rejects_duplicate_settlement_output_withdrawal_replay() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x333);
    let recipient = as_address(0x444);
    let batch_id = 0x779;
    let pair_id = 0x888;
    let output_note_commitment = 0xabc125;
    let output_amount = 200_u128;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let withdraw_authority = key_pair.public_key;
    let (_, shielded_asset_adapter, auction_verifier) = settle_single_output_note_for_withdrawal(
        admin,
        settlement_account,
        batch_id,
        pair_id,
        output_note_commitment,
        output_amount,
        withdraw_authority,
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
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
    let first_consumed_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, array![0xdeadbeef].span(),
    );
    let first_new_nullifier_root = 0x5678;
    let first_withdrawal_commitment = public_note_withdrawal_commitment(
        batch_id,
        output_note_commitment,
        ASSET_ID,
        output_amount,
        withdraw_authority,
        0,
        first_consumed_root,
        first_new_nullifier_root,
    );
    let first_withdrawal_statement = native_withdrawal_message_hash(
        auction_verifier, first_withdrawal_commitment,
    );
    let first_withdrawal_proof_message = withdrawal_proof_message_hash(
        auction_verifier, first_withdrawal_statement,
    );
    let first_withdrawal_proof_facts = valid_proof_facts(99, first_withdrawal_proof_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_chain_id(auction_verifier, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    cheat_proof_facts(
        auction_verifier, first_withdrawal_proof_facts.span(), CheatSpan::TargetCalls(1),
    );
    verifier
        .withdraw_settlement_output_with_proof_facts(
            batch_id,
            first_withdrawal_statement,
            0,
            first_consumed_root,
            first_new_nullifier_root,
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

    let second_consumed_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, array![0xcafebabe].span(),
    );
    let second_new_nullifier_root = 0x6789;
    let second_withdrawal_commitment = public_note_withdrawal_commitment(
        batch_id,
        output_note_commitment,
        ASSET_ID,
        output_amount,
        withdraw_authority,
        first_new_nullifier_root,
        second_consumed_root,
        second_new_nullifier_root,
    );
    let second_withdrawal_statement = native_withdrawal_message_hash(
        auction_verifier, second_withdrawal_commitment,
    );
    let second_withdrawal_proof_message = withdrawal_proof_message_hash(
        auction_verifier, second_withdrawal_statement,
    );
    let second_withdrawal_proof_facts = valid_proof_facts(99, second_withdrawal_proof_message);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_chain_id(auction_verifier, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    cheat_proof_facts(
        auction_verifier, second_withdrawal_proof_facts.span(), CheatSpan::TargetCalls(1),
    );
    verifier
        .withdraw_settlement_output_with_proof_facts(
            batch_id,
            second_withdrawal_statement,
            first_new_nullifier_root,
            second_consumed_root,
            second_new_nullifier_root,
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
#[should_panic]
fn auction_verifier_rejects_withdrawal_for_wrong_verifier_statement() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x333);
    let recipient = as_address(0x444);
    let batch_id = 0x77a;
    let output_note_commitment = 0xabc126;
    let output_amount = 200_u128;
    let withdraw_secret = 0xabcdef;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(withdraw_secret);
    let withdraw_authority = key_pair.public_key;
    let (_, shielded_asset_adapter, auction_verifier) = settle_single_output_note_for_withdrawal(
        admin,
        settlement_account,
        batch_id,
        0x888,
        output_note_commitment,
        output_amount,
        withdraw_authority,
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let consumed_root = single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, array![0xaaa1].span());
    submit_output_withdrawal_attempt(
        verifier,
        auction_verifier,
        as_address(0x999999),
        shielded_asset_adapter,
        shielded_asset_adapter,
        TEST_CHAIN_ID,
        TEST_CHAIN_ID,
        batch_id,
        output_note_commitment,
        ASSET_ID,
        output_amount,
        withdraw_secret,
        withdraw_authority,
        recipient,
        recipient,
        0,
        consumed_root,
        0x5679,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_withdrawal_signature_for_wrong_adapter() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x333);
    let recipient = as_address(0x444);
    let batch_id = 0x77b;
    let output_note_commitment = 0xabc127;
    let output_amount = 200_u128;
    let withdraw_secret = 0xabcdef;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(withdraw_secret);
    let withdraw_authority = key_pair.public_key;
    let (_, shielded_asset_adapter, auction_verifier) = settle_single_output_note_for_withdrawal(
        admin,
        settlement_account,
        batch_id,
        0x888,
        output_note_commitment,
        output_amount,
        withdraw_authority,
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let consumed_root = single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, array![0xaaa2].span());
    submit_output_withdrawal_attempt(
        verifier,
        auction_verifier,
        auction_verifier,
        shielded_asset_adapter,
        as_address(0x999999),
        TEST_CHAIN_ID,
        TEST_CHAIN_ID,
        batch_id,
        output_note_commitment,
        ASSET_ID,
        output_amount,
        withdraw_secret,
        withdraw_authority,
        recipient,
        recipient,
        0,
        consumed_root,
        0x5680,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_withdrawal_signature_for_wrong_chain() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x333);
    let recipient = as_address(0x444);
    let batch_id = 0x77c;
    let output_note_commitment = 0xabc128;
    let output_amount = 200_u128;
    let withdraw_secret = 0xabcdef;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(withdraw_secret);
    let withdraw_authority = key_pair.public_key;
    let (_, shielded_asset_adapter, auction_verifier) = settle_single_output_note_for_withdrawal(
        admin,
        settlement_account,
        batch_id,
        0x888,
        output_note_commitment,
        output_amount,
        withdraw_authority,
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let consumed_root = single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, array![0xaaa3].span());
    submit_output_withdrawal_attempt(
        verifier,
        auction_verifier,
        auction_verifier,
        shielded_asset_adapter,
        shielded_asset_adapter,
        TEST_CHAIN_ID,
        WRONG_CHAIN_ID,
        batch_id,
        output_note_commitment,
        ASSET_ID,
        output_amount,
        withdraw_secret,
        withdraw_authority,
        recipient,
        recipient,
        0,
        consumed_root,
        0x5681,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_withdrawal_signature_for_wrong_recipient() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x333);
    let recipient = as_address(0x444);
    let batch_id = 0x77d;
    let output_note_commitment = 0xabc129;
    let output_amount = 200_u128;
    let withdraw_secret = 0xabcdef;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(withdraw_secret);
    let withdraw_authority = key_pair.public_key;
    let (_, shielded_asset_adapter, auction_verifier) = settle_single_output_note_for_withdrawal(
        admin,
        settlement_account,
        batch_id,
        0x888,
        output_note_commitment,
        output_amount,
        withdraw_authority,
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let consumed_root = single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, array![0xaaa4].span());
    submit_output_withdrawal_attempt(
        verifier,
        auction_verifier,
        auction_verifier,
        shielded_asset_adapter,
        shielded_asset_adapter,
        TEST_CHAIN_ID,
        TEST_CHAIN_ID,
        batch_id,
        output_note_commitment,
        ASSET_ID,
        output_amount,
        withdraw_secret,
        withdraw_authority,
        recipient,
        as_address(0x445),
        0,
        consumed_root,
        0x5682,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_withdrawal_for_wrong_batch() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x333);
    let recipient = as_address(0x444);
    let batch_id = 0x77e;
    let output_note_commitment = 0xabc12a;
    let output_amount = 200_u128;
    let withdraw_secret = 0xabcdef;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(withdraw_secret);
    let withdraw_authority = key_pair.public_key;
    let (_, shielded_asset_adapter, auction_verifier) = settle_single_output_note_for_withdrawal(
        admin,
        settlement_account,
        batch_id,
        0x888,
        output_note_commitment,
        output_amount,
        withdraw_authority,
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let consumed_root = single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, array![0xaaa5].span());
    submit_output_withdrawal_attempt(
        verifier,
        auction_verifier,
        auction_verifier,
        shielded_asset_adapter,
        shielded_asset_adapter,
        TEST_CHAIN_ID,
        TEST_CHAIN_ID,
        batch_id + 1,
        output_note_commitment,
        ASSET_ID,
        output_amount,
        withdraw_secret,
        withdraw_authority,
        recipient,
        recipient,
        0,
        consumed_root,
        0x5683,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_withdrawal_for_wrong_note_commitment() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x333);
    let recipient = as_address(0x444);
    let batch_id = 0x77f;
    let output_note_commitment = 0xabc12b;
    let output_amount = 200_u128;
    let withdraw_secret = 0xabcdef;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(withdraw_secret);
    let withdraw_authority = key_pair.public_key;
    let (_, shielded_asset_adapter, auction_verifier) = settle_single_output_note_for_withdrawal(
        admin,
        settlement_account,
        batch_id,
        0x888,
        output_note_commitment,
        output_amount,
        withdraw_authority,
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let consumed_root = single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, array![0xaaa6].span());
    submit_output_withdrawal_attempt(
        verifier,
        auction_verifier,
        auction_verifier,
        shielded_asset_adapter,
        shielded_asset_adapter,
        TEST_CHAIN_ID,
        TEST_CHAIN_ID,
        batch_id,
        output_note_commitment + 1,
        ASSET_ID,
        output_amount,
        withdraw_secret,
        withdraw_authority,
        recipient,
        recipient,
        0,
        consumed_root,
        0x5684,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_withdrawal_for_wrong_asset() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x333);
    let recipient = as_address(0x444);
    let batch_id = 0x780;
    let output_note_commitment = 0xabc12c;
    let output_amount = 200_u128;
    let withdraw_secret = 0xabcdef;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(withdraw_secret);
    let withdraw_authority = key_pair.public_key;
    let (_, shielded_asset_adapter, auction_verifier) = settle_single_output_note_for_withdrawal(
        admin,
        settlement_account,
        batch_id,
        0x888,
        output_note_commitment,
        output_amount,
        withdraw_authority,
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let consumed_root = single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, array![0xaaa7].span());
    submit_output_withdrawal_attempt(
        verifier,
        auction_verifier,
        auction_verifier,
        shielded_asset_adapter,
        shielded_asset_adapter,
        TEST_CHAIN_ID,
        TEST_CHAIN_ID,
        batch_id,
        output_note_commitment,
        'ETH',
        output_amount,
        withdraw_secret,
        withdraw_authority,
        recipient,
        recipient,
        0,
        consumed_root,
        0x5685,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_withdrawal_for_wrong_amount() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x333);
    let recipient = as_address(0x444);
    let batch_id = 0x781;
    let output_note_commitment = 0xabc12d;
    let output_amount = 200_u128;
    let withdraw_secret = 0xabcdef;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(withdraw_secret);
    let withdraw_authority = key_pair.public_key;
    let (_, shielded_asset_adapter, auction_verifier) = settle_single_output_note_for_withdrawal(
        admin,
        settlement_account,
        batch_id,
        0x888,
        output_note_commitment,
        output_amount,
        withdraw_authority,
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let consumed_root = single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, array![0xaaa8].span());
    submit_output_withdrawal_attempt(
        verifier,
        auction_verifier,
        auction_verifier,
        shielded_asset_adapter,
        shielded_asset_adapter,
        TEST_CHAIN_ID,
        TEST_CHAIN_ID,
        batch_id,
        output_note_commitment,
        ASSET_ID,
        output_amount + 1,
        withdraw_secret,
        withdraw_authority,
        recipient,
        recipient,
        0,
        consumed_root,
        0x5686,
    );
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
    let consumed_nullifiers = array![0xdeadbeef];
    let consumed_nullifier_root = single_field_root(
        CONSUMED_NULLIFIER_ROOT_DOMAIN, consumed_nullifiers.span(),
    );
    let new_nullifier_root = 0x5678;
    let withdrawal_commitment = public_note_withdrawal_commitment(
        batch_id,
        output_note_commitment,
        ASSET_ID,
        output_amount,
        withdraw_authority,
        0,
        consumed_nullifier_root,
        new_nullifier_root,
    );
    let withdrawal_statement = native_withdrawal_message_hash(
        auction_verifier, withdrawal_commitment,
    );
    let withdrawal_proof_message = withdrawal_proof_message_hash(
        auction_verifier, withdrawal_statement,
    );
    let withdrawal_proof_facts = valid_proof_facts(99, withdrawal_proof_message);
    cheat_chain_id(auction_verifier, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(auction_verifier, 1_020, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, withdrawal_proof_facts.span(), CheatSpan::TargetCalls(1));
    verifier
        .withdraw_settlement_output_with_proof_facts(
            batch_id,
            withdrawal_statement,
            0,
            consumed_nullifier_root,
            new_nullifier_root,
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
#[should_panic]
fn shielded_asset_adapter_rejects_direct_verified_withdrawal_caller() {
    let admin = as_address(0x111);
    let verifier = as_address(0x222);
    let attacker = as_address(0x333);
    let recipient = as_address(0x444);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.set_auction_verifier(verifier);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(shielded_asset_adapter, attacker);
    adapter.withdraw_verified_note(ASSET_ID, 1, NOTE_COMMITMENT, recipient);
}

#[test]
#[should_panic]
fn shielded_asset_adapter_rejects_verified_withdrawal_replay() {
    let admin = as_address(0x111);
    let auction_verifier = as_address(0x444);
    let recipient = as_address(0x555);
    let token_address = deploy_configurable_mock_erc20();
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let token = IConfigurableMockERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };

    token.mint(shielded_asset_adapter, as_u256(500));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.set_auction_verifier(auction_verifier);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(shielded_asset_adapter, auction_verifier);
    adapter.withdraw_verified_note(ASSET_ID, 200, NOTE_COMMITMENT + 0x100, recipient);
    adapter.withdraw_verified_note(ASSET_ID, 200, NOTE_COMMITMENT + 0x100, recipient);
}

#[test]
#[should_panic]
fn privacy_deposit_bridge_rejects_zero_encrypted_note_activation() {
    let admin = as_address(0x111);
    let (_, _, privacy_deposit_bridge, _, bridge, _) = setup_privacy_activation_stack(admin);

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    privacy_invoke_single(bridge, FUNDING_COMMITMENT, deposit_root(), 0);
}
