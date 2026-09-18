use core::integer::u256;
use core::poseidon::hades_permutation;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, cheat_block_timestamp, declare,
    start_cheat_caller_address, stop_cheat_caller_address,
};
use starknet::{ContractAddress, SyscallResultTrait};
use zylith_protocol::auction_verifier::{
    IAuctionVerifierDispatcher, IAuctionVerifierDispatcherTrait,
};
use zylith_protocol::commitment_registry::{
    ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
};
use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
use zylith_protocol::external_match_executor::{
    IExternalMatchExecutorDispatcher, IExternalMatchExecutorDispatcherTrait,
};
use zylith_protocol::privacy_deposit_bridge::{
    IPrivacyDepositBridgeDispatcher, IPrivacyDepositBridgeDispatcherTrait,
};
use crate::mock_erc20::{
    IConfigurableMockERC20Dispatcher, IConfigurableMockERC20DispatcherTrait, IMockERC20Dispatcher,
    IMockERC20DispatcherTrait,
};

const BASE_ASSET_ID: felt252 = 'ETH';
const QUOTE_ASSET_ID: felt252 = 'USDC';
const BUY_SIDE: felt252 = 0;
const SELL_SIDE: felt252 = 1;
const BATCH_ID: felt252 = 0x4241544348;
const PAIR_ID: felt252 = 0x45544855534443;
const OUTPUT_NOTE_LEAF_DOMAIN: felt252 =
    0x0f0c89949c6cba4ac7f170f7f00809b458b997f2e394481c7ab58cc68aa49b3;
const EXTERNAL_MATCH_AUTHORIZATION_DOMAIN: felt252 =
    0x4944e3edf8c94cdca9ba99f3c9c626587e0f5108b1d4428ff2c8f23ceb69ed7;
const EXTERNAL_MATCH_REQUEST_LEAF_DOMAIN: felt252 =
    0x20fb26bf6509d9087ab80295aca27ea56e22e440ffb6b50d276fc8d2fcf51d2;

#[starknet::interface]
pub trait IMockEkuboLock<TContractState> {
    fn lock_and_callback(
        ref self: TContractState,
        callback: ContractAddress,
        executor: ContractAddress,
        request_id: felt252,
        fill_base_amount: u128,
        borrowed_base: u128,
        repaid_base: u128,
        borrowed_quote: u128,
        repaid_quote: u128,
    ) -> u128;
}

#[starknet::interface]
pub trait IExternalMatchLockCallback<TContractState> {
    fn on_mock_ekubo_lock(
        ref self: TContractState,
        executor: ContractAddress,
        request_id: felt252,
        fill_base_amount: u128,
    ) -> u128;
}

#[starknet::contract]
pub mod MockEkuboLock {
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use super::IExternalMatchLockCallbackDispatcherTrait;

    #[storage]
    struct Storage {
        locked: bool,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl MockEkuboLockImpl of super::IMockEkuboLock<ContractState> {
        fn lock_and_callback(
            ref self: ContractState,
            callback: ContractAddress,
            executor: ContractAddress,
            request_id: felt252,
            fill_base_amount: u128,
            borrowed_base: u128,
            repaid_base: u128,
            borrowed_quote: u128,
            repaid_quote: u128,
        ) -> u128 {
            assert(self.locked.read() == false, 'LOCK_REENTRANT');
            self.locked.write(true);
            let callback_dispatcher = super::IExternalMatchLockCallbackDispatcher {
                contract_address: callback,
            };
            let consumed = callback_dispatcher
                .on_mock_ekubo_lock(executor, request_id, fill_base_amount);
            assert(borrowed_base == repaid_base, 'BASE_DELTA_OPEN');
            assert(borrowed_quote == repaid_quote, 'QUOTE_DELTA_OPEN');
            self.locked.write(false);
            consumed
        }
    }
}

#[starknet::contract]
pub mod ExternalMatchLockCallback {
    use starknet::ContractAddress;
    use zylith_protocol::external_match_executor::{
        IExternalMatchExecutorDispatcher, IExternalMatchExecutorDispatcherTrait,
    };

    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl ExternalMatchLockCallbackImpl of super::IExternalMatchLockCallback<ContractState> {
        fn on_mock_ekubo_lock(
            ref self: ContractState,
            executor: ContractAddress,
            request_id: felt252,
            fill_base_amount: u128,
        ) -> u128 {
            IExternalMatchExecutorDispatcher { contract_address: executor }
                .settle_external_match_fill(request_id, fill_base_amount)
        }
    }
}

#[derive(Copy, Drop)]
struct ExternalMatchFixture {
    admin: ContractAddress,
    registrar: ContractAddress,
    matcher: ContractAddress,
    settlement_verifier: ContractAddress,
    bridge: IPrivacyDepositBridgeDispatcher,
    executor: IExternalMatchExecutorDispatcher,
    base_token: IMockERC20Dispatcher,
    quote_token: IMockERC20Dispatcher,
    base_erc20: IERC20Dispatcher,
    quote_erc20: IERC20Dispatcher,
}

fn deploy_external_match_fixture() -> ExternalMatchFixture {
    let admin = as_address(0x111);
    let registrar = as_address(0x222);
    let matcher = as_address(0x777);
    let settlement_verifier = as_address(0x778);
    let privacy_pool = deploy_mock_privacy_pool();
    let commitment_registry = deploy_commitment_registry(admin);
    let bridge_address = deploy_privacy_deposit_bridge(admin, commitment_registry, privacy_pool);
    let base_token_address = deploy_mock_erc20();
    let quote_token_address = deploy_mock_erc20();
    let executor = deploy_external_match_executor(
        admin, bridge_address, registrar, settlement_verifier,
    );
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: bridge_address };

    start_cheat_caller_address(bridge_address, admin);
    bridge.set_external_match_executor(executor.contract_address);
    bridge.register_supported_asset(BASE_ASSET_ID, base_token_address);
    bridge.register_supported_asset(QUOTE_ASSET_ID, quote_token_address);
    stop_cheat_caller_address(bridge_address);

    ExternalMatchFixture {
        admin,
        registrar,
        matcher,
        settlement_verifier,
        bridge,
        executor,
        base_token: IMockERC20Dispatcher { contract_address: base_token_address },
        quote_token: IMockERC20Dispatcher { contract_address: quote_token_address },
        base_erc20: IERC20Dispatcher { contract_address: base_token_address },
        quote_erc20: IERC20Dispatcher { contract_address: quote_token_address },
    }
}

fn register_buy_request(fixture: ExternalMatchFixture, request_id: felt252) {
    register_authorized_request(fixture.executor, fixture.registrar, request_id, BUY_SIDE);
}

fn register_authorized_request(
    executor: IExternalMatchExecutorDispatcher,
    registrar: ContractAddress,
    request_id: felt252,
    side: felt252,
) {
    let request_root = test_authorization_root(request_id, side);
    start_cheat_caller_address(executor.contract_address, registrar);
    executor
        .register_authorized_external_match_requests(
            BATCH_ID,
            request_root,
            array![request_id].span(),
            array![PAIR_ID].span(),
            array![BASE_ASSET_ID].span(),
            array![QUOTE_ASSET_ID].span(),
            array![side].span(),
            array![100].span(),
            array![4000].span(),
            array![1].span(),
            array![100000].span(),
        );
    stop_cheat_caller_address(executor.contract_address);
}

fn test_authorization_root(request_id: felt252, side: felt252) -> felt252 {
    let mut leaf = poseidon_hash2(EXTERNAL_MATCH_REQUEST_LEAF_DOMAIN, request_id);
    leaf = poseidon_hash2(leaf, BATCH_ID);
    leaf = poseidon_hash2(leaf, PAIR_ID);
    leaf = poseidon_hash2(leaf, BASE_ASSET_ID);
    leaf = poseidon_hash2(leaf, QUOTE_ASSET_ID);
    leaf = poseidon_hash2(leaf, side);
    leaf = poseidon_hash2(leaf, 100);
    leaf = poseidon_hash2(leaf, 4000);
    leaf = poseidon_hash2(leaf, 1);
    leaf = poseidon_hash2(leaf, 100000);
    poseidon_hash2(poseidon_hash2(EXTERNAL_MATCH_AUTHORIZATION_DOMAIN, 1), leaf)
}

fn poseidon_hash2(left: felt252, right: felt252) -> felt252 {
    let (result, _, _) = hades_permutation(left, right, 2);
    result
}

#[test]
fn external_match_executor_registers_proof_authorized_request_batch_from_rust_root() {
    let fixture = deploy_external_match_fixture();
    let batch_id = 0x25dffbccee5972454ed36ad85a2990a6709d8304043e0f6cc94a80164bf4c92;
    let request_id = 0x78c6d3745678b0a3a9b1d99856b3f4cef76313e8f72debf26afe846d0196618;
    start_cheat_caller_address(fixture.executor.contract_address, fixture.registrar);
    fixture
        .executor
        .register_authorized_external_match_requests(
            batch_id,
            0xe49400e89dac15c1cfc3ef426fa5753508fa8b90a7ba3ac99ff97547bfb8ec,
            array![request_id].span(),
            array![0x2cbcdace0891f8e930c42d95e41029a4b97dbefe3c7ab4fc1624e094b2c8b5].span(),
            array![0x83191fc191d03c3f6f70ea7a1420780d860230dda0edfc2ae9ab762c72b2fe].span(),
            array![0x1e565426a7cff134da7e67f4587da64258d8e50b249f60444b53d8aebb4987c].span(),
            array![BUY_SIDE].span(),
            array![0xde0b6b3a7640000].span(),
            array![0xee6b2800].span(),
            array![0xde0b6b3a7640000].span(),
            array![0x1770].span(),
        );
    stop_cheat_caller_address(fixture.executor.contract_address);

    let request = fixture.executor.external_match_request(request_id);
    assert(request.batch_id == batch_id, 'BATCH');
    assert(
        request.input_asset_id == 0x1e565426a7cff134da7e67f4587da64258d8e50b249f60444b53d8aebb4987c,
        'BUY_INPUT',
    );
    assert(
        request.output_asset_id == 0x83191fc191d03c3f6f70ea7a1420780d860230dda0edfc2ae9ab762c72b2fe,
        'BUY_OUTPUT',
    );
}

#[test]
#[should_panic(expected: 'BAD_REQUEST_ROOT')]
fn external_match_executor_rejects_tampered_authorization_root() {
    let fixture = deploy_external_match_fixture();
    start_cheat_caller_address(fixture.executor.contract_address, fixture.registrar);
    fixture
        .executor
        .register_authorized_external_match_requests(
            0x25dffbccee5972454ed36ad85a2990a6709d8304043e0f6cc94a80164bf4c92,
            0x123,
            array![0x78c6d3745678b0a3a9b1d99856b3f4cef76313e8f72debf26afe846d0196618].span(),
            array![0x2cbcdace0891f8e930c42d95e41029a4b97dbefe3c7ab4fc1624e094b2c8b5].span(),
            array![0x83191fc191d03c3f6f70ea7a1420780d860230dda0edfc2ae9ab762c72b2fe].span(),
            array![0x1e565426a7cff134da7e67f4587da64258d8e50b249f60444b53d8aebb4987c].span(),
            array![BUY_SIDE].span(),
            array![0xde0b6b3a7640000].span(),
            array![0xee6b2800].span(),
            array![0xde0b6b3a7640000].span(),
            array![0x1770].span(),
        );
}

#[test]
fn external_match_executor_indexes_registered_requests_and_exposes_remaining_state() {
    let fixture = deploy_external_match_fixture();
    seed_quote_escrow(fixture, 1_000_000);
    approve_base_from(fixture.matcher, fixture, 40);
    register_buy_request(fixture, 0xabc);
    cheat_block_timestamp(
        fixture.executor.contract_address, 10, snforge_std::CheatSpan::TargetCalls(1),
    );

    start_cheat_caller_address(fixture.executor.contract_address, fixture.matcher);
    fixture.executor.settle_external_match_fill(0xabc, 40);
    stop_cheat_caller_address(fixture.executor.contract_address);

    assert(fixture.executor.request_count() == 1, 'BAD_REQUEST_COUNT');
    assert(fixture.executor.request_id_at(0) == 0xabc, 'BAD_REQUEST_INDEX');
    let request_ids = fixture.executor.request_ids(0, 64);
    assert(request_ids.len() == 1, 'BAD_REQUEST_PAGE_LEN');
    assert(*request_ids.at(0) == 0xabc, 'BAD_REQUEST_PAGE_ID');
    let request = fixture.executor.external_match_request(0xabc);
    assert(request.side == BUY_SIDE, 'BAD_REQUEST_SIDE');
    assert(request.batch_id == BATCH_ID, 'BAD_REQUEST_BATCH');
    assert(request.pair_id == PAIR_ID, 'BAD_REQUEST_PAIR');
    assert(request.input_asset_id == QUOTE_ASSET_ID, 'BAD_REQUEST_INPUT');
    assert(request.output_asset_id == BASE_ASSET_ID, 'BAD_REQUEST_OUTPUT');
    assert(request.max_base_amount == 100, 'BAD_REQUEST_MAX');
    assert(request.reference_midpoint_price == 4000, 'BAD_REQUEST_MID');
    assert(request.price_base_scale == 1, 'BAD_REQUEST_SCALE');
    assert(request.valid_until_unix_ms == 100000, 'BAD_REQUEST_EXPIRY');
    assert(request.match_deadline_unix_ms == 10000, 'BAD_MATCH_DEADLINE');
    assert(request.consumed_base_amount == 40, 'BAD_REQUEST_CONSUMED');
    assert(request.closed == false, 'REQUEST_CLOSED');
    assert(request.settlement_consumed == false, 'REQUEST_SETTLED');
}

#[test]
fn external_match_window_starts_when_authorized_request_is_registered() {
    let fixture = deploy_external_match_fixture();
    seed_quote_escrow(fixture, 1_000_000);
    approve_base_from(fixture.matcher, fixture, 40);
    cheat_block_timestamp(
        fixture.executor.contract_address, 200, snforge_std::CheatSpan::TargetCalls(1),
    );
    register_buy_request(fixture, 0xabc);
    let request = fixture.executor.external_match_request(0xabc);
    assert(request.valid_until_unix_ms == 100000, 'SIGNED_EXPIRY_CHANGED');
    assert(request.match_deadline_unix_ms == 210000, 'BAD_MATCH_DEADLINE');

    cheat_block_timestamp(
        fixture.executor.contract_address, 205, snforge_std::CheatSpan::TargetCalls(1),
    );
    start_cheat_caller_address(fixture.executor.contract_address, fixture.matcher);
    fixture.executor.settle_external_match_fill(0xabc, 40);
    stop_cheat_caller_address(fixture.executor.contract_address);
    assert(fixture.executor.consumed_base_amount(0xabc) == 40, 'MATCH_NOT_FILLED');
}

#[test]
fn external_match_request_closes_after_expiry_and_is_consumed_once_by_settlement() {
    let fixture = deploy_external_match_fixture();
    seed_quote_escrow(fixture, 1_000_000);
    approve_base_from(fixture.matcher, fixture, 40);
    register_buy_request(fixture, 0xabc);
    cheat_block_timestamp(
        fixture.executor.contract_address, 10, snforge_std::CheatSpan::TargetCalls(1),
    );
    start_cheat_caller_address(fixture.executor.contract_address, fixture.matcher);
    fixture.executor.settle_external_match_fill(0xabc, 40);
    stop_cheat_caller_address(fixture.executor.contract_address);

    cheat_block_timestamp(
        fixture.executor.contract_address, 101, snforge_std::CheatSpan::TargetCalls(1),
    );
    start_cheat_caller_address(fixture.executor.contract_address, fixture.registrar);
    let frozen = fixture.executor.close_external_match_request(0xabc);
    stop_cheat_caller_address(fixture.executor.contract_address);
    assert(frozen == 40, 'BAD_FROZEN_AMOUNT');

    start_cheat_caller_address(fixture.executor.contract_address, fixture.settlement_verifier);
    let request = fixture.executor.consume_closed_external_match_request(0xabc, 40);
    stop_cheat_caller_address(fixture.executor.contract_address);
    assert(request.closed, 'REQUEST_OPEN');
    assert(request.consumed_base_amount == 40, 'BAD_CONSUMED');
    assert(request.settlement_consumed, 'NOT_SETTLED');
}

#[test]
#[should_panic(expected: ('REQUEST_ACTIVE',))]
fn external_match_request_cannot_close_while_partially_filled_and_active() {
    let fixture = deploy_external_match_fixture();
    register_buy_request(fixture, 0xabc);
    cheat_block_timestamp(
        fixture.executor.contract_address, 10, snforge_std::CheatSpan::TargetCalls(1),
    );
    start_cheat_caller_address(fixture.executor.contract_address, fixture.registrar);
    fixture.executor.close_external_match_request(0xabc);
}

#[test]
#[should_panic(expected: ('REQUEST_CLOSED',))]
fn external_match_request_rejects_fill_after_close() {
    let fixture = deploy_external_match_fixture();
    register_buy_request(fixture, 0xabc);
    cheat_block_timestamp(
        fixture.executor.contract_address, 101, snforge_std::CheatSpan::TargetCalls(1),
    );
    start_cheat_caller_address(fixture.executor.contract_address, fixture.registrar);
    fixture.executor.close_external_match_request(0xabc);
    stop_cheat_caller_address(fixture.executor.contract_address);
    start_cheat_caller_address(fixture.executor.contract_address, fixture.matcher);
    fixture.executor.settle_external_match_fill(0xabc, 1);
}

#[test]
#[should_panic(expected: ('REQUEST_SETTLED',))]
fn external_match_request_cannot_be_consumed_twice_by_settlement() {
    let fixture = deploy_external_match_fixture();
    register_buy_request(fixture, 0xabc);
    cheat_block_timestamp(
        fixture.executor.contract_address, 101, snforge_std::CheatSpan::TargetCalls(1),
    );
    start_cheat_caller_address(fixture.executor.contract_address, fixture.registrar);
    fixture.executor.close_external_match_request(0xabc);
    stop_cheat_caller_address(fixture.executor.contract_address);
    start_cheat_caller_address(fixture.executor.contract_address, fixture.settlement_verifier);
    fixture.executor.consume_closed_external_match_request(0xabc, 0);
    fixture.executor.consume_closed_external_match_request(0xabc, 0);
}

#[test]
#[should_panic(expected: ('BAD_REQUEST_INDEX',))]
fn external_match_executor_rejects_request_index_out_of_bounds() {
    let fixture = deploy_external_match_fixture();
    fixture.executor.request_id_at(0);
}

#[test]
#[should_panic(expected: ('UNKNOWN_REQUEST',))]
fn external_match_executor_rejects_unknown_request_view() {
    let fixture = deploy_external_match_fixture();
    fixture.executor.external_match_request(0xabc);
}

fn seed_quote_escrow(fixture: ExternalMatchFixture, amount: u128) {
    fixture.quote_token.mint(fixture.bridge.contract_address, as_u256(amount));
    seed_bridge_escrow(
        fixture.admin,
        fixture.bridge.contract_address,
        QUOTE_ASSET_ID,
        amount,
        0x460001 + amount.into(),
        0x120001 + amount.into(),
    );
}

fn approve_base_from(owner: ContractAddress, fixture: ExternalMatchFixture, amount: u128) {
    fixture.base_token.mint(owner, as_u256(amount));
    start_cheat_caller_address(fixture.base_erc20.contract_address, owner);
    fixture.base_erc20.approve(fixture.bridge.contract_address, as_u256(amount));
    stop_cheat_caller_address(fixture.base_erc20.contract_address);
}

#[test]
fn external_match_executor_settles_registered_buy_request_into_bridge_escrow() {
    let fixture = deploy_external_match_fixture();
    let request_id = 0xabc;
    seed_quote_escrow(fixture, 1_000_000);
    approve_base_from(fixture.matcher, fixture, 40);
    register_buy_request(fixture, request_id);
    cheat_block_timestamp(
        fixture.executor.contract_address, 10, snforge_std::CheatSpan::TargetCalls(1),
    );

    start_cheat_caller_address(fixture.executor.contract_address, fixture.matcher);
    let consumed = fixture.executor.settle_external_match_fill(request_id, 40);
    stop_cheat_caller_address(fixture.executor.contract_address);

    assert(consumed == 40, 'BAD_CONSUMED');
    assert(fixture.executor.consumed_base_amount(request_id) == 40, 'BAD_REQUEST_TOTAL');
    assert(fixture.bridge.escrowed_asset_amount(QUOTE_ASSET_ID) == 840000, 'BAD_QUOTE_ESCROW');
    assert(fixture.bridge.escrowed_asset_amount(BASE_ASSET_ID) == 40, 'BAD_BASE_ESCROW');
    assert(fixture.quote_erc20.balance_of(fixture.matcher).low == 160000, 'BAD_MATCHER_QUOTE');
    assert(fixture.base_erc20.balance_of(fixture.bridge.contract_address).low == 40, 'BAD_BASE');
}

#[test]
#[should_panic(expected: ('UNKNOWN_REQUEST',))]
fn external_match_executor_rejects_unregistered_request() {
    let fixture = deploy_external_match_fixture();
    cheat_block_timestamp(
        fixture.executor.contract_address, 10, snforge_std::CheatSpan::TargetCalls(1),
    );

    start_cheat_caller_address(fixture.executor.contract_address, fixture.matcher);
    fixture.executor.settle_external_match_fill(0xabc, 1);
}

#[test]
#[should_panic(expected: ('UNAUTHORIZED',))]
fn external_match_executor_rejects_unauthorized_request_registration() {
    let fixture = deploy_external_match_fixture();

    start_cheat_caller_address(fixture.executor.contract_address, fixture.matcher);
    fixture
        .executor
        .register_authorized_external_match_requests(
            BATCH_ID,
            test_authorization_root(0xabc, BUY_SIDE),
            array![0xabc].span(),
            array![PAIR_ID].span(),
            array![BASE_ASSET_ID].span(),
            array![QUOTE_ASSET_ID].span(),
            array![BUY_SIDE].span(),
            array![100].span(),
            array![4000].span(),
            array![1].span(),
            array![100000].span(),
        );
}

#[test]
#[should_panic(expected: ('REQUEST_OVERFILLED',))]
fn external_match_executor_rejects_overfill_replay() {
    let fixture = deploy_external_match_fixture();
    let request_id = 0xabc;
    seed_quote_escrow(fixture, 1_000_000);
    approve_base_from(fixture.matcher, fixture, 101);
    register_buy_request(fixture, request_id);
    cheat_block_timestamp(
        fixture.executor.contract_address, 10, snforge_std::CheatSpan::TargetCalls(2),
    );

    start_cheat_caller_address(fixture.executor.contract_address, fixture.matcher);
    fixture.executor.settle_external_match_fill(request_id, 100);
    fixture.executor.settle_external_match_fill(request_id, 1);
}

#[test]
#[should_panic(expected: ('REQUEST_EXPIRED',))]
fn external_match_executor_rejects_expired_request() {
    let fixture = deploy_external_match_fixture();
    let request_id = 0xabc;
    register_buy_request(fixture, request_id);
    cheat_block_timestamp(
        fixture.executor.contract_address, 101, snforge_std::CheatSpan::TargetCalls(1),
    );

    start_cheat_caller_address(fixture.executor.contract_address, fixture.matcher);
    fixture.executor.settle_external_match_fill(request_id, 1);
}

#[test]
#[should_panic(expected: ('UNAUTHORIZED',))]
fn bridge_rejects_direct_external_match_swap_not_from_executor() {
    let fixture = deploy_external_match_fixture();

    start_cheat_caller_address(fixture.bridge.contract_address, fixture.matcher);
    fixture
        .bridge
        .settle_external_match_asset_swap(
            fixture.matcher, QUOTE_ASSET_ID, BASE_ASSET_ID, 160000, 40,
        );
}

#[test]
#[should_panic(expected: ('OUTPUT_DELTA',))]
fn bridge_rejects_short_transfer_from_during_external_match() {
    let admin = as_address(0x111);
    let registrar = as_address(0x222);
    let matcher = as_address(0x777);
    let privacy_pool = deploy_mock_privacy_pool();
    let commitment_registry = deploy_commitment_registry(admin);
    let bridge_address = deploy_privacy_deposit_bridge(admin, commitment_registry, privacy_pool);
    let base_token_address = deploy_configurable_mock_erc20();
    let quote_token_address = deploy_mock_erc20();
    let executor = deploy_external_match_executor(admin, bridge_address, registrar, admin);
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: bridge_address };
    let base_token = IConfigurableMockERC20Dispatcher { contract_address: base_token_address };
    let base_erc20 = IERC20Dispatcher { contract_address: base_token_address };
    let quote_token = IMockERC20Dispatcher { contract_address: quote_token_address };

    start_cheat_caller_address(bridge_address, admin);
    bridge.set_external_match_executor(executor.contract_address);
    bridge.register_supported_asset(BASE_ASSET_ID, base_token_address);
    bridge.register_supported_asset(QUOTE_ASSET_ID, quote_token_address);
    stop_cheat_caller_address(bridge_address);
    quote_token.mint(bridge_address, as_u256(1_000_000));
    seed_bridge_escrow(admin, bridge_address, QUOTE_ASSET_ID, 1_000_000, 0x460111, 0x120111);
    base_token.mint(matcher, as_u256(40));
    base_token.set_short_transfer_from(true);
    start_cheat_caller_address(base_token_address, matcher);
    base_erc20.approve(bridge_address, as_u256(40));
    stop_cheat_caller_address(base_token_address);
    register_authorized_request(executor, registrar, 0xabc, BUY_SIDE);
    cheat_block_timestamp(executor.contract_address, 10, snforge_std::CheatSpan::TargetCalls(1));

    start_cheat_caller_address(executor.contract_address, matcher);
    executor.settle_external_match_fill(0xabc, 40);
}

#[test]
fn external_match_fill_can_settle_inside_lock_callback() {
    let fixture = deploy_external_match_fixture();
    let request_id = 0xbeef;
    let lock = deploy_mock_ekubo_lock();
    let callback = deploy_external_match_lock_callback();
    seed_quote_escrow(fixture, 1_000_000);
    approve_base_from(callback, fixture, 40);
    register_buy_request(fixture, request_id);
    cheat_block_timestamp(
        fixture.executor.contract_address, 10, snforge_std::CheatSpan::TargetCalls(1),
    );

    let consumed = lock
        .lock_and_callback(
            callback, fixture.executor.contract_address, request_id, 40, 40, 40, 160000, 160000,
        );

    assert(consumed == 40, 'LOCK_CONSUMED');
    assert(fixture.executor.consumed_base_amount(request_id) == 40, 'EXEC_CONSUMED');
    assert(fixture.bridge.escrowed_asset_amount(BASE_ASSET_ID) == 40, 'BAD_BASE_ESCROW');
    assert(fixture.quote_erc20.balance_of(callback).low == 160000, 'BAD_CALLBACK_QUOTE');
}

fn deploy_external_match_executor(
    admin: ContractAddress,
    bridge: ContractAddress,
    registrar: ContractAddress,
    settlement_verifier: ContractAddress,
) -> IExternalMatchExecutorDispatcher {
    let class = declare("ExternalMatchExecutor").unwrap().contract_class();
    let calldata = array![
        admin.into(), bridge.into(), registrar.into(), settlement_verifier.into(),
    ];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    IExternalMatchExecutorDispatcher { contract_address: address }
}

fn deploy_mock_ekubo_lock() -> IMockEkuboLockDispatcher {
    let class = declare("MockEkuboLock").unwrap().contract_class();
    let calldata = array![];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    IMockEkuboLockDispatcher { contract_address: address }
}

fn deploy_external_match_lock_callback() -> ContractAddress {
    let class = declare("ExternalMatchLockCallback").unwrap().contract_class();
    let calldata = array![];
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

fn deploy_mock_privacy_pool() -> ContractAddress {
    let class = declare("MockPrivacyPool").unwrap().contract_class();
    let calldata = array![];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_commitment_registry(admin: ContractAddress) -> ContractAddress {
    let class = declare("CommitmentRegistry").unwrap().contract_class();
    let calldata = array![admin.into()];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_privacy_deposit_bridge(
    admin: ContractAddress, commitment_registry: ContractAddress, privacy_pool: ContractAddress,
) -> ContractAddress {
    let class = declare("PrivacyDepositBridge").unwrap().contract_class();
    let calldata = array![admin.into(), commitment_registry.into(), privacy_pool.into()];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_activation_verifier(admin: ContractAddress, deposit_registrar: ContractAddress) {
    let class = declare("AuctionVerifier").unwrap().contract_class();
    let calldata = array![admin.into(), as_address(0x444).into(), 0, 0, 0, 0];
    let (verifier_address, _) = class.deploy(@calldata).unwrap_syscall();
    let verifier = IAuctionVerifierDispatcher { contract_address: verifier_address };
    start_cheat_caller_address(verifier_address, admin);
    verifier.set_deposit_root_registrar(deposit_registrar);
    stop_cheat_caller_address(verifier_address);

    let registry = ICommitmentRegistryDispatcher { contract_address: deposit_registrar };
    start_cheat_caller_address(deposit_registrar, admin);
    registry.set_auction_verifier(verifier_address);
    stop_cheat_caller_address(deposit_registrar);
}

fn seed_bridge_escrow(
    admin: ContractAddress,
    bridge_address: ContractAddress,
    asset_id: felt252,
    amount: u128,
    funding_commitment: felt252,
    note_commitment: felt252,
) {
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: bridge_address };
    let commitment_registry = bridge.commitment_registry_address();
    let privacy_pool = bridge.privacy_pool_address();
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    deploy_activation_verifier(admin, commitment_registry);
    start_cheat_caller_address(commitment_registry, admin);
    registry.set_privacy_deposit_bridge(bridge_address);
    stop_cheat_caller_address(commitment_registry);

    let root = output_note_leaf(note_commitment, asset_id, amount, 0x464001);
    start_cheat_caller_address(bridge_address, privacy_pool);
    let open_deposits = bridge
        .privacy_invoke(
            array![funding_commitment].span(),
            array![root].span(),
            array![0x463001 + funding_commitment].span(),
            array![note_commitment].span(),
            array![asset_id].span(),
            array![amount].span(),
            array![0x464001].span(),
        );
    stop_cheat_caller_address(bridge_address);
    assert(open_deposits.len() == 0, 'OPEN_DEPOSITS_RETURNED');
}

fn output_note_leaf(
    note_commitment: felt252, asset_id: felt252, amount: u128, withdraw_authority: felt252,
) -> felt252 {
    let (first, _, _) = hades_permutation(OUTPUT_NOTE_LEAF_DOMAIN, note_commitment, 2);
    let (second, _, _) = hades_permutation(first, asset_id, 2);
    let (third, _, _) = hades_permutation(second, amount.into(), 2);
    let (fourth, _, _) = hades_permutation(third, withdraw_authority, 2);
    fourth
}

fn as_address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn as_u256(value: u128) -> u256 {
    u256 { low: value, high: 0 }
}
