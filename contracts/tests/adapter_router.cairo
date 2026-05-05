use core::integer::u256;
use core::poseidon::hades_permutation;
use core::traits::TryInto;
use snforge_std::signature::stark_curve::{
    StarkCurveKeyPair, StarkCurveKeyPairImpl, StarkCurveSignerImpl,
};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_block_number, cheat_chain_id,
    cheat_proof_facts, declare, start_cheat_caller_address, stop_cheat_caller_address,
};
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
const RENEWAL_PARENT_CANCEL_DOMAIN: felt252 =
    0x26f84b60309c08d4030876815edb467f89f78e5a5f62823af4521f1be502ca3;
const RENEWAL_PARENT_DOMAIN: felt252 =
    0x3c16da1b34d6fcc6f6ea27674de3b6cead275b20c1dfafa4abb43515a8974b4;
const TEST_CHAIN_ID: felt252 = 'SN_SEPOLIA';
const WRONG_CHAIN_ID: felt252 = 'SN_MAIN';

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

fn deploy_auction_verifier(
    admin: ContractAddress,
    commitment_registry: ContractAddress,
    batch_registry: ContractAddress,
    fee_ledger: ContractAddress,
    shielded_asset_adapter: ContractAddress,
) -> ContractAddress {
    let class = declare("AuctionVerifier").unwrap().contract_class();
    let calldata = array![
        admin.into(), commitment_registry.into(), batch_registry.into(), fee_ledger.into(),
        shielded_asset_adapter.into(),
    ];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
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
    bridge.privacy_invoke(ASSET_ID, 500, 7, note_commitment, withdraw_authority);
    stop_cheat_caller_address(privacy_deposit_bridge);

    (token_address, shielded_asset_adapter, owner, privacy_deposit_bridge)
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

fn renewal_parent_cancel_message_hash_for_registry(
    commitment_registry: ContractAddress,
    chain_id: felt252,
    parent_order_commitment: felt252,
    parent_secret_commitment: felt252,
    cancellation_nullifier: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(RENEWAL_PARENT_CANCEL_DOMAIN, chain_id);
    state = poseidon_hash2(state, commitment_registry.into());
    state = poseidon_hash2(state, parent_order_commitment);
    state = poseidon_hash2(state, parent_secret_commitment);
    poseidon_hash2(state, cancellation_nullifier)
}

fn renewal_parent_commitment(
    parent_secret_commitment: felt252, cancel_authority: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(RENEWAL_PARENT_DOMAIN, parent_secret_commitment);
    poseidon_hash2(state, cancel_authority)
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
    public_settlement_commitment(
        batch_id,
        pair_id,
        batch_epoch,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        array![].span(),
        array![].span(),
        array![].span(),
        array![].span(),
        array![].span(),
        array![].span(),
        array![].span(),
        array![].span(),
        array![].span(),
        array![].span(),
        array![].span(),
    )
}

fn public_settlement_commitment(
    batch_id: felt252,
    pair_id: felt252,
    batch_epoch: u64,
    order_commitment_root: felt252,
    encrypted_order_set_commitment: felt252,
    clearing_price: u128,
    output_bundle_ref: felt252,
    consumed_note_commitments: Span<felt252>,
    consumed_nullifiers: Span<felt252>,
    renewal_parent_order_commitments: Span<felt252>,
    renewal_child_nullifiers: Span<felt252>,
    output_note_commitments: Span<felt252>,
    output_note_asset_ids: Span<felt252>,
    output_note_amounts: Span<u128>,
    output_note_withdraw_authorities: Span<felt252>,
    fee_asset_ids: Span<felt252>,
    fee_recipients: Span<felt252>,
    fee_amounts: Span<u128>,
) -> felt252 {
    let mut state = poseidon_hash2(
        0x283f626418aa97a073f64500f7e35dd8bf7c01ff8611917c3c38e5be92eb205, batch_id,
    );
    state = poseidon_hash2(state, pair_id);
    state = poseidon_hash2(state, batch_epoch.into());
    state = poseidon_hash2(state, order_commitment_root);
    state = poseidon_hash2(state, encrypted_order_set_commitment);
    state = poseidon_hash2(state, clearing_price.into());
    state = poseidon_hash2(state, output_bundle_ref);

    state = poseidon_hash2(state, consumed_note_commitments.len().into());
    let mut index = 0;
    loop {
        if index == consumed_note_commitments.len() {
            break;
        }
        state = poseidon_hash2(state, *consumed_note_commitments.at(index));
        state = poseidon_hash2(state, *consumed_nullifiers.at(index));
        index += 1;
    }

    state = poseidon_hash2(state, renewal_child_nullifiers.len().into());
    index = 0;
    loop {
        if index == renewal_child_nullifiers.len() {
            break;
        }
        state = poseidon_hash2(state, *renewal_parent_order_commitments.at(index));
        state = poseidon_hash2(state, *renewal_child_nullifiers.at(index));
        index += 1;
    }

    state = poseidon_hash2(state, output_note_commitments.len().into());
    index = 0;
    loop {
        if index == output_note_commitments.len() {
            break;
        }
        state = poseidon_hash2(state, *output_note_commitments.at(index));
        state = poseidon_hash2(state, *output_note_asset_ids.at(index));
        state = poseidon_hash2(state, (*output_note_amounts.at(index)).into());
        state = poseidon_hash2(state, *output_note_withdraw_authorities.at(index));
        index += 1;
    }

    state = poseidon_hash2(state, fee_asset_ids.len().into());
    index = 0;
    loop {
        if index == fee_asset_ids.len() {
            break;
        }
        state = poseidon_hash2(state, *fee_asset_ids.at(index));
        state = poseidon_hash2(state, *fee_recipients.at(index));
        state = poseidon_hash2(state, (*fee_amounts.at(index)).into());
        index += 1;
    }

    state
}

fn valid_proof_facts(base_block_number: u64, proof_message_hash: felt252) -> Array<felt252> {
    proof_facts_for_message(base_block_number, proof_message_hash, VIRTUAL_SNOS, VIRTUAL_SNOS0)
}

fn proof_facts_for_message(
    base_block_number: u64,
    proof_message_hash: felt252,
    program_variant: felt252,
    starknet_os_output_version: felt252,
) -> Array<felt252> {
    let messages = array![proof_message_hash];
    let facts = ProofFacts {
        proof_version: 0,
        program_variant,
        virtual_program_hash: 0,
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
    stop_cheat_caller_address(fee_ledger);

    token.mint(privacy_deposit_bridge, as_u256(100));
    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    bridge.privacy_invoke(ASSET_ID, 100, 7, NOTE_COMMITMENT, withdraw_authority_public_key(0xabc));
    stop_cheat_caller_address(privacy_deposit_bridge);

    start_cheat_caller_address(fee_ledger, auction_verifier);
    fees.accrue_fees(array![ASSET_ID].span(), array![fee_recipient].span(), array![7_u128].span());
    stop_cheat_caller_address(fee_ledger);

    start_cheat_caller_address(fee_ledger, admin);
    fees.claim_fees(ASSET_ID, fee_recipient, 7, claim_recipient);
    stop_cheat_caller_address(fee_ledger);

    assert(fees.accrued_fee(ASSET_ID, fee_recipient) == 0, 'FEE_NOT_CLAIMED');
    assert(adapter.escrowed_balance(ASSET_ID) == 93, 'BAD_ESCROW');
    assert(token.balance_of(claim_recipient).low == 7, 'BAD_CLAIM_BALANCE');
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
fn privacy_deposit_bridge_registers_privacy_funded_execution_notes() {
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
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: privacy_deposit_bridge };

    token.mint(privacy_deposit_bridge, as_u256(750));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    let returned_deposits = bridge
        .privacy_invoke(ASSET_ID, 750, 11, NOTE_COMMITMENT, withdraw_authority);
    stop_cheat_caller_address(privacy_deposit_bridge);

    assert(returned_deposits.len() == 0, 'BAD_INVOKE_RETURN');
    assert(registry.is_note_commitment_registered(NOTE_COMMITMENT), 'NOTE_NOT_REGISTERED');
    assert(adapter.note_is_live(NOTE_COMMITMENT), 'NOTE_NOT_LIVE');
    assert(adapter.note_amount(NOTE_COMMITMENT) == 750, 'BAD_NOTE_AMOUNT');
    assert(adapter.note_withdraw_authority(NOTE_COMMITMENT) == withdraw_authority, 'BAD_AUTHORITY');
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
    bridge.privacy_invoke(ASSET_ID, 750, 11, NOTE_COMMITMENT, withdraw_authority);
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
fn commitment_registry_consumes_renewal_child_once() {
    let admin = as_address(0x111);
    let auction_verifier = as_address(0x222);
    let parent_order_commitment = 0xabc;
    let child_nullifier = 0xdef;
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(commitment_registry);

    start_cheat_caller_address(commitment_registry, auction_verifier);
    registry.consume_renewal_children(
        array![parent_order_commitment].span(), array![child_nullifier].span(),
    );
    stop_cheat_caller_address(commitment_registry);

    assert(registry.is_renewal_child_consumed(child_nullifier), 'CHILD_NOT_CONSUMED');
}

#[test]
#[should_panic]
fn commitment_registry_rejects_reused_renewal_child() {
    let admin = as_address(0x111);
    let auction_verifier = as_address(0x222);
    let parent_order_commitment = 0xabc;
    let child_nullifier = 0xdef;
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(commitment_registry);

    start_cheat_caller_address(commitment_registry, auction_verifier);
    registry.consume_renewal_children(
        array![parent_order_commitment].span(), array![child_nullifier].span(),
    );
    registry.consume_renewal_children(
        array![parent_order_commitment].span(), array![child_nullifier].span(),
    );
}

#[test]
fn commitment_registry_accepts_domain_bound_parent_cancel_signature() {
    let admin = as_address(0x111);
    let parent_secret_commitment = 0x555;
    let cancellation_nullifier = 0x987;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let parent_order_commitment = renewal_parent_commitment(
        parent_secret_commitment, key_pair.public_key,
    );
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let message = renewal_parent_cancel_message_hash_for_registry(
        commitment_registry,
        TEST_CHAIN_ID,
        parent_order_commitment,
        parent_secret_commitment,
        cancellation_nullifier,
    );
    let (r, s) = StarkCurveSignerImpl::sign(key_pair, message).unwrap();

    cheat_chain_id(commitment_registry, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    registry.cancel_renewal_parent(
        parent_order_commitment,
        parent_secret_commitment,
        cancellation_nullifier,
        key_pair.public_key,
        r,
        s,
    );

    assert(
        registry.is_renewal_parent_cancelled(parent_order_commitment), 'PARENT_NOT_CANCELLED',
    );
}

#[test]
#[should_panic]
fn commitment_registry_rejects_cancel_with_uncommitted_authority() {
    let admin = as_address(0x111);
    let parent_secret_commitment = 0x555;
    let cancellation_nullifier = 0x987;
    let owner_key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let attacker_key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0x123456);
    let parent_order_commitment = renewal_parent_commitment(
        parent_secret_commitment, owner_key_pair.public_key,
    );
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let message = renewal_parent_cancel_message_hash_for_registry(
        commitment_registry,
        TEST_CHAIN_ID,
        parent_order_commitment,
        parent_secret_commitment,
        cancellation_nullifier,
    );
    let (r, s) = StarkCurveSignerImpl::sign(attacker_key_pair, message).unwrap();

    cheat_chain_id(commitment_registry, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    registry.cancel_renewal_parent(
        parent_order_commitment,
        parent_secret_commitment,
        cancellation_nullifier,
        attacker_key_pair.public_key,
        r,
        s,
    );
}

#[test]
#[should_panic]
fn commitment_registry_rejects_renewal_child_after_parent_cancel() {
    let admin = as_address(0x111);
    let auction_verifier = as_address(0x222);
    let parent_secret_commitment = 0x555;
    let cancellation_nullifier = 0x987;
    let child_nullifier = 0xdef;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let parent_order_commitment = renewal_parent_commitment(
        parent_secret_commitment, key_pair.public_key,
    );
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let message = renewal_parent_cancel_message_hash_for_registry(
        commitment_registry,
        TEST_CHAIN_ID,
        parent_order_commitment,
        parent_secret_commitment,
        cancellation_nullifier,
    );
    let (r, s) = StarkCurveSignerImpl::sign(key_pair, message).unwrap();

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(commitment_registry);

    cheat_chain_id(commitment_registry, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    registry.cancel_renewal_parent(
        parent_order_commitment,
        parent_secret_commitment,
        cancellation_nullifier,
        key_pair.public_key,
        r,
        s,
    );

    start_cheat_caller_address(commitment_registry, auction_verifier);
    registry.consume_renewal_children(
        array![parent_order_commitment].span(), array![child_nullifier].span(),
    );
}

#[test]
#[should_panic]
fn commitment_registry_rejects_parent_cancel_signature_for_wrong_chain() {
    let admin = as_address(0x111);
    let parent_secret_commitment = 0x555;
    let cancellation_nullifier = 0x987;
    let key_pair: StarkCurveKeyPair = StarkCurveKeyPairImpl::from_secret_key(0xabcdef);
    let parent_order_commitment = renewal_parent_commitment(
        parent_secret_commitment, key_pair.public_key,
    );
    let commitment_registry = deploy_commitment_registry(admin);
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let message = renewal_parent_cancel_message_hash_for_registry(
        commitment_registry,
        WRONG_CHAIN_ID,
        parent_order_commitment,
        parent_secret_commitment,
        cancellation_nullifier,
    );
    let (r, s) = StarkCurveSignerImpl::sign(key_pair, message).unwrap();

    cheat_chain_id(commitment_registry, TEST_CHAIN_ID, CheatSpan::TargetCalls(1));
    registry.cancel_renewal_parent(
        parent_order_commitment,
        parent_secret_commitment,
        cancellation_nullifier,
        key_pair.public_key,
        r,
        s,
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_unauthorized_submitters() {
    let admin = as_address(0x111);
    let attacker = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(
        admin, as_address(0x333), as_address(0x444), as_address(0x555), as_address(0x666),
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, attacker);
    verifier
        .submit_settlement_with_proof_facts(
            1,
            0x111,
            0x222,
            2,
            3,
            4,
            0,
            5,
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
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
    let commitment_registry = deploy_commitment_registry(admin);
    let batch_registry = deploy_batch_registry(admin, admin);
    let fee_ledger = deploy_fee_ledger(admin);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let auction_verifier = deploy_auction_verifier(
        admin, commitment_registry, batch_registry, fee_ledger, shielded_asset_adapter,
    );

    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let fees = IFeeLedgerDispatcher { contract_address: fee_ledger };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(commitment_registry);

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id, pair_id, 1, 2, 0, order_commitment_root, encrypted_order_set_commitment,
        );
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(fee_ledger, admin);
    fees.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(fee_ledger);

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(shielded_asset_adapter);

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
    verifier
        .submit_settlement_with_proof_facts(
            batch_id,
            order_commitment_root,
            encrypted_order_set_commitment,
            transcript_commitment,
            proof_artifact_commitment,
            clearing_price,
            0,
            output_bundle_ref,
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
        );
    stop_cheat_caller_address(auction_verifier);

    assert(verifier.is_batch_settled(batch_id), 'NOT_SETTLED');
    let record = verifier.settlement_record(batch_id);
    assert(record.proof_artifact_commitment == proof_artifact_commitment, 'BAD_PROOF_COMMIT');
}

#[test]
#[should_panic]
fn settlement_rejects_output_amount_larger_than_deposited_input_amount() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x444);
    let batch_id = 0x777;
    let pair_id = 0x888;
    let order_commitment_root = 0x111;
    let encrypted_order_set_commitment = 0x222;
    let clearing_price = 4_u128;
    let output_bundle_ref = 0x999;
    let attacker_input_note = 0xaaaa;
    let victim_liquidity_note = 0xbbbb;
    let inflated_output_note = 0xcccc;
    let consumed_nullifier = 0xdddd;
    let inflated_output_amount = 1_000_u128;

    let token_address = deploy_mock_erc20();
    let commitment_registry = deploy_commitment_registry(admin);
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let privacy_deposit_bridge = deploy_privacy_deposit_bridge(
        commitment_registry, shielded_asset_adapter,
    );
    let batch_registry = deploy_batch_registry(admin, admin);
    let fee_ledger = deploy_fee_ledger(admin);
    let auction_verifier = deploy_auction_verifier(
        admin, commitment_registry, batch_registry, fee_ledger, shielded_asset_adapter,
    );

    authorize_privacy_deposit_bridge(
        admin, commitment_registry, shielded_asset_adapter, privacy_deposit_bridge,
    );
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let batches = IBatchRegistryDispatcher { contract_address: batch_registry };
    let fees = IFeeLedgerDispatcher { contract_address: fee_ledger };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: privacy_deposit_bridge };
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let token = IMockERC20Dispatcher { contract_address: token_address };

    start_cheat_caller_address(commitment_registry, admin);
    registry.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(commitment_registry);

    start_cheat_caller_address(batch_registry, admin);
    batches.set_auction_verifier(auction_verifier);
    batches
        .register_batch(
            batch_id, pair_id, 1, 2, 1, order_commitment_root, encrypted_order_set_commitment,
        );
    stop_cheat_caller_address(batch_registry);

    start_cheat_caller_address(fee_ledger, admin);
    fees.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(fee_ledger);

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    adapter.set_auction_verifier(auction_verifier);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    token.mint(privacy_deposit_bridge, as_u256(inflated_output_amount + 1));

    start_cheat_caller_address(privacy_deposit_bridge, as_address(PRIVACY_POOL));
    bridge
        .privacy_invoke(
            ASSET_ID, 1, 7, attacker_input_note, withdraw_authority_public_key(0x101),
        );
    bridge
        .privacy_invoke(
            ASSET_ID,
            inflated_output_amount,
            8,
            victim_liquidity_note,
            withdraw_authority_public_key(0x202),
        );
    stop_cheat_caller_address(privacy_deposit_bridge);

    assert(adapter.note_amount(attacker_input_note) == 1, 'BAD_INPUT_AMOUNT');
    assert(adapter.escrowed_balance(ASSET_ID) == inflated_output_amount + 1, 'BAD_ESCROW');

    let transcript_commitment = public_settlement_commitment(
        batch_id,
        pair_id,
        1,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        array![attacker_input_note].span(),
        array![consumed_nullifier].span(),
        array![].span(),
        array![].span(),
        array![inflated_output_note].span(),
        array![ASSET_ID].span(),
        array![inflated_output_amount].span(),
        array![withdraw_authority_public_key(0x303)].span(),
        array![].span(),
        array![].span(),
        array![].span(),
    );
    let proof_artifact_commitment = native_settlement_message_hash(
        auction_verifier, transcript_commitment,
    );
    let proof_message_hash = verifier.settlement_proof_message_hash(transcript_commitment);
    let proof_facts = valid_proof_facts(99, proof_message_hash);

    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .submit_settlement_with_proof_facts(
            batch_id,
            order_commitment_root,
            encrypted_order_set_commitment,
            transcript_commitment,
            proof_artifact_commitment,
            clearing_price,
            1,
            output_bundle_ref,
            array![attacker_input_note].span(),
            array![consumed_nullifier].span(),
            array![].span(),
            array![].span(),
            array![inflated_output_note].span(),
            array![ASSET_ID].span(),
            array![inflated_output_amount].span(),
            array![withdraw_authority_public_key(0x303)].span(),
            array![].span(),
            array![].span(),
            array![].span(),
        );
    stop_cheat_caller_address(auction_verifier);

    assert(!adapter.note_is_live(attacker_input_note), 'INPUT_STILL_LIVE');
    assert(adapter.note_is_live(inflated_output_note), 'OUTPUT_NOT_LIVE');
    assert(
        adapter.note_amount(inflated_output_note) == inflated_output_amount, 'BAD_OUTPUT_AMOUNT',
    );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_missing_proof_facts() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(
        admin, as_address(0x333), as_address(0x444), as_address(0x555), as_address(0x666),
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .submit_settlement_with_proof_facts(
            1,
            0x111,
            0x222,
            2,
            native_settlement_message_hash(auction_verifier, 2),
            4,
            0,
            5,
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
        );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_wrong_proof_message() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(
        admin, as_address(0x333), as_address(0x444), as_address(0x555), as_address(0x666),
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
    let transcript_commitment = 2;

    start_cheat_caller_address(auction_verifier, admin);
    verifier.set_authorized_settlement_account(settlement_account);
    stop_cheat_caller_address(auction_verifier);

    let proof_facts = valid_proof_facts(99, 0xdead);
    cheat_block_number(auction_verifier, 100, CheatSpan::TargetCalls(1));
    cheat_proof_facts(auction_verifier, proof_facts.span(), CheatSpan::TargetCalls(1));
    start_cheat_caller_address(auction_verifier, settlement_account);
    verifier
        .submit_settlement_with_proof_facts(
            1,
            0x111,
            0x222,
            transcript_commitment,
            native_settlement_message_hash(auction_verifier, transcript_commitment),
            4,
            0,
            5,
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
        );
}

#[test]
#[should_panic]
fn auction_verifier_rejects_expired_proof_facts() {
    let admin = as_address(0x111);
    let settlement_account = as_address(0x222);
    let auction_verifier = deploy_auction_verifier(
        admin, as_address(0x333), as_address(0x444), as_address(0x555), as_address(0x666),
    );
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
    verifier
        .submit_settlement_with_proof_facts(
            1,
            0x111,
            0x222,
            transcript_commitment,
            native_settlement_message_hash(auction_verifier, transcript_commitment),
            4,
            0,
            5,
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
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
    bridge.privacy_invoke(ASSET_ID, 500, 7, NOTE_COMMITMENT, 0);
}
