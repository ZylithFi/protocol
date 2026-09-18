use core::integer::u256;
use core::poseidon::hades_permutation;
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_block_timestamp, cheat_caller_address,
    declare, start_cheat_caller_address, stop_cheat_caller_address,
};
use starknet::{ContractAddress, SyscallResultTrait};
use zylith_protocol::auction_verifier::{
    IAuctionVerifierDispatcher, IAuctionVerifierDispatcherTrait,
};
use zylith_protocol::commitment_registry::{
    ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
};
use zylith_protocol::ekubo_abi::{Delta, PoolKey, RouteNode, SignedAmount, Swap, TokenAmount};
use zylith_protocol::ekubo_external_match_router::{
    IEkuboExternalMatchRouterDispatcher, IEkuboExternalMatchRouterDispatcherTrait,
};
use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
use zylith_protocol::external_match_executor::{
    IExternalMatchExecutorDispatcher, IExternalMatchExecutorDispatcherTrait,
};
use zylith_protocol::privacy_deposit_bridge::{
    IPrivacyDepositBridgeDispatcher, IPrivacyDepositBridgeDispatcherTrait,
};
use crate::mock_erc20::{IMockERC20Dispatcher, IMockERC20DispatcherTrait};

const BASE_ASSET_ID: felt252 = 'ETH';
const QUOTE_ASSET_ID: felt252 = 'USDC';
const BUY_SIDE: felt252 = 0;
const SELL_SIDE: felt252 = 1;
const OUTPUT_NOTE_LEAF_DOMAIN: felt252 =
    0x0f0c89949c6cba4ac7f170f7f00809b458b997f2e394481c7ab58cc68aa49b3;
const EXTERNAL_MATCH_AUTHORIZATION_DOMAIN: felt252 =
    0x4944e3edf8c94cdca9ba99f3c9c626587e0f5108b1d4428ff2c8f23ceb69ed7;
const EXTERNAL_MATCH_REQUEST_LEAF_DOMAIN: felt252 =
    0x20fb26bf6509d9087ab80295aca27ea56e22e440ffb6b50d276fc8d2fcf51d2;

#[starknet::interface]
trait IMockEkuboCore<TContractState> {
    fn lock(ref self: TContractState, data: Span<felt252>) -> Span<felt252>;
    fn withdraw(
        ref self: TContractState,
        token_address: ContractAddress,
        recipient: ContractAddress,
        amount: u128,
    );
    fn pay(ref self: TContractState, token_address: ContractAddress);
}

#[starknet::interface]
trait IMockEkuboRouter<TContractState> {
    fn multi_multihop_swap(ref self: TContractState, swaps: Array<Swap>) -> Array<Array<Delta>>;
    fn clear(ref self: TContractState, token: ContractAddress) -> u256;
    fn clear_minimum(ref self: TContractState, token: ContractAddress, minimum: u256) -> u256;
}

#[starknet::contract]
mod MockEkuboCore {
    use core::num::traits::Zero;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use zylith_protocol::ekubo_abi::{IEkuboLockerDispatcher, IEkuboLockerDispatcherTrait};
    use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};

    #[storage]
    struct Storage {
        active_locker: ContractAddress,
        debt_token: ContractAddress,
        debt_amount: u128,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl MockEkuboCoreImpl of super::IMockEkuboCore<ContractState> {
        fn lock(ref self: ContractState, data: Span<felt252>) -> Span<felt252> {
            assert(self.active_locker.read().is_zero(), 'ALREADY_LOCKED');
            let locker = get_caller_address();
            self.active_locker.write(locker);
            let result = IEkuboLockerDispatcher { contract_address: locker }.locked(1, data);
            assert(self.debt_amount.read() == 0, 'OPEN_DEBT');
            self.active_locker.write(Zero::zero());
            result
        }

        fn withdraw(
            ref self: ContractState,
            token_address: ContractAddress,
            recipient: ContractAddress,
            amount: u128,
        ) {
            assert(get_caller_address() == self.active_locker.read(), 'NOT_LOCKER');
            assert(self.debt_amount.read() == 0, 'DEBT_EXISTS');
            self.debt_token.write(token_address);
            self.debt_amount.write(amount);
            IERC20Dispatcher { contract_address: token_address }.transfer(recipient, amount.into());
        }

        fn pay(ref self: ContractState, token_address: ContractAddress) {
            let locker = self.active_locker.read();
            assert(get_caller_address() == locker, 'NOT_LOCKER');
            assert(token_address == self.debt_token.read(), 'BAD_DEBT_TOKEN');
            let amount = self.debt_amount.read();
            assert(amount != 0, 'NO_DEBT');
            IERC20Dispatcher { contract_address: token_address }
                .transfer_from(locker, get_contract_address(), amount.into());
            self.debt_amount.write(0);
        }
    }
}

#[starknet::contract]
mod MockEkuboRouter {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use zylith_protocol::ekubo_abi::{Delta, Swap};
    use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
    use crate::mock_erc20::{IMockERC20Dispatcher, IMockERC20DispatcherTrait};

    #[storage]
    struct Storage {
        base_token: ContractAddress,
        quote_token: ContractAddress,
        buy_quote_cost: u128,
        sell_quote_proceeds: u128,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        base_token: ContractAddress,
        quote_token: ContractAddress,
        buy_quote_cost: u128,
        sell_quote_proceeds: u128,
    ) {
        self.base_token.write(base_token);
        self.quote_token.write(quote_token);
        self.buy_quote_cost.write(buy_quote_cost);
        self.sell_quote_proceeds.write(sell_quote_proceeds);
    }

    #[abi(embed_v0)]
    impl MockEkuboRouterImpl of super::IMockEkuboRouter<ContractState> {
        fn multi_multihop_swap(ref self: ContractState, swaps: Array<Swap>) -> Array<Array<Delta>> {
            assert(!swaps.is_empty(), 'NO_SWAPS');
            let mut total = 0_u128;
            let sign = *swaps.at(0).token_amount.amount.sign;
            let mut index = 0;
            while index < swaps.len() {
                let swap = swaps.at(index);
                assert(*swap.token_amount.amount.sign == sign, 'MIXED_SIDE');
                total += *swap.token_amount.amount.mag;
                index += 1;
            }
            let self_address = get_contract_address();
            let sink: ContractAddress = 0xdead.try_into().unwrap();
            if sign {
                let cost = self.buy_quote_cost.read();
                IERC20Dispatcher { contract_address: self.quote_token.read() }
                    .transfer(sink, cost.into());
                IMockERC20Dispatcher { contract_address: self.base_token.read() }
                    .mint(self_address, total.into());
            } else {
                IERC20Dispatcher { contract_address: self.base_token.read() }
                    .transfer(sink, total.into());
                IMockERC20Dispatcher { contract_address: self.quote_token.read() }
                    .mint(self_address, self.sell_quote_proceeds.read().into());
            }
            array![]
        }

        fn clear(ref self: ContractState, token: ContractAddress) -> u256 {
            clear_to_caller(token, 0)
        }

        fn clear_minimum(ref self: ContractState, token: ContractAddress, minimum: u256) -> u256 {
            clear_to_caller(token, minimum.low)
        }
    }

    fn clear_to_caller(token: ContractAddress, minimum: u128) -> u256 {
        let token = IERC20Dispatcher { contract_address: token };
        let balance = token.balance_of(get_contract_address());
        assert(balance.high == 0, 'BALANCE_OVERFLOW');
        assert(balance.low >= minimum, 'CLEAR_MINIMUM');
        if balance.low != 0 {
            token.transfer(get_caller_address(), balance);
        }
        balance
    }
}

#[derive(Copy, Drop)]
struct Fixture {
    admin: ContractAddress,
    registrar: ContractAddress,
    matcher: ContractAddress,
    bridge: IPrivacyDepositBridgeDispatcher,
    executor: IExternalMatchExecutorDispatcher,
    external_router: IEkuboExternalMatchRouterDispatcher,
    core: ContractAddress,
    base_token: IMockERC20Dispatcher,
    quote_token: IMockERC20Dispatcher,
    base_erc20: IERC20Dispatcher,
    quote_erc20: IERC20Dispatcher,
}

#[test]
fn buy_residual_executes_inside_flash_lock_and_returns_quote_profit() {
    let fixture = deploy_fixture();
    seed_bridge(fixture, QUOTE_ASSET_ID, fixture.quote_token, 1_000_000);
    fixture.base_token.mint(fixture.core, as_u256(40));
    register_request(fixture, 0xb01, BUY_SIDE);
    let matcher_quote_before = fixture.quote_erc20.balance_of(fixture.matcher).low;

    cheat_caller_address(
        fixture.external_router.contract_address, fixture.matcher, CheatSpan::TargetCalls(1),
    );
    let profit = fixture
        .external_router
        .execute_external_match(
            fixture.executor.contract_address, 0xb01, 40, 10_000, buy_swaps(fixture),
        );

    assert(profit == 10_000, 'BAD_PROFIT');
    assert(
        fixture.quote_erc20.balance_of(fixture.matcher).low == matcher_quote_before + 10_000,
        'PROFIT_NOT_PAID',
    );
    assert(fixture.executor.consumed_base_amount(0xb01) == 40, 'BAD_CONSUMED');
    assert(fixture.bridge.escrowed_asset_amount(BASE_ASSET_ID) == 40, 'BAD_BASE_ESCROW');
}

#[test]
fn sell_residual_executes_inside_flash_lock_and_returns_quote_profit() {
    let fixture = deploy_fixture();
    seed_bridge(fixture, BASE_ASSET_ID, fixture.base_token, 100);
    fixture.quote_token.mint(fixture.core, as_u256(160_000));
    register_request(fixture, 0x5e11, SELL_SIDE);

    cheat_caller_address(
        fixture.external_router.contract_address, fixture.matcher, CheatSpan::TargetCalls(1),
    );
    let profit = fixture
        .external_router
        .execute_external_match(
            fixture.executor.contract_address, 0x5e11, 40, 10_000, sell_swaps(fixture),
        );

    assert(profit == 10_000, 'BAD_PROFIT');
    assert(fixture.quote_erc20.balance_of(fixture.matcher).low == 10_000, 'PROFIT_NOT_PAID');
    assert(fixture.executor.consumed_base_amount(0x5e11) == 40, 'BAD_CONSUMED');
    assert(fixture.bridge.escrowed_asset_amount(QUOTE_ASSET_ID) == 160_000, 'BAD_QUOTE_ESCROW');
}

#[test]
#[should_panic(expected: 'PROFIT_TOO_LOW')]
fn atomic_external_match_rejects_profit_below_matcher_floor() {
    let fixture = deploy_fixture();
    seed_bridge(fixture, QUOTE_ASSET_ID, fixture.quote_token, 1_000_000);
    fixture.base_token.mint(fixture.core, as_u256(40));
    register_request(fixture, 0xb02, BUY_SIDE);
    fixture
        .external_router
        .execute_external_match(
            fixture.executor.contract_address, 0xb02, 40, 10_001, buy_swaps(fixture),
        );
}

fn deploy_fixture() -> Fixture {
    let admin = as_address(0x111);
    let registrar = as_address(0x222);
    let matcher = as_address(0x777);
    let privacy_pool = deploy("MockPrivacyPool", @array![]);
    let commitment_registry = deploy_commitment_registry(admin);
    let bridge_address = deploy(
        "PrivacyDepositBridge",
        @array![admin.into(), commitment_registry.into(), privacy_pool.into()],
    );
    let base_token_address = deploy("MockERC20", @array![]);
    let quote_token_address = deploy("MockERC20", @array![]);
    let executor_address = deploy(
        "ExternalMatchExecutor",
        @array![admin.into(), bridge_address.into(), registrar.into(), admin.into()],
    );
    let core = deploy("MockEkuboCore", @array![]);
    let router = deploy(
        "MockEkuboRouter",
        @array![base_token_address.into(), quote_token_address.into(), 150000, 170000],
    );
    let external_router_address = deploy(
        "EkuboExternalMatchRouter", @array![core.into(), router.into(), executor_address.into()],
    );
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: bridge_address };
    start_cheat_caller_address(bridge_address, admin);
    bridge.set_external_match_executor(executor_address);
    bridge.register_supported_asset(BASE_ASSET_ID, base_token_address);
    bridge.register_supported_asset(QUOTE_ASSET_ID, quote_token_address);
    stop_cheat_caller_address(bridge_address);
    Fixture {
        admin,
        registrar,
        matcher,
        bridge,
        executor: IExternalMatchExecutorDispatcher { contract_address: executor_address },
        external_router: IEkuboExternalMatchRouterDispatcher {
            contract_address: external_router_address,
        },
        core,
        base_token: IMockERC20Dispatcher { contract_address: base_token_address },
        quote_token: IMockERC20Dispatcher { contract_address: quote_token_address },
        base_erc20: IERC20Dispatcher { contract_address: base_token_address },
        quote_erc20: IERC20Dispatcher { contract_address: quote_token_address },
    }
}

fn register_request(fixture: Fixture, request_id: felt252, side: felt252) {
    let batch_id = 0x4241544348;
    let pair_id = 0x45544855534443;
    let mut leaf = poseidon_hash2(EXTERNAL_MATCH_REQUEST_LEAF_DOMAIN, request_id);
    leaf = poseidon_hash2(leaf, batch_id);
    leaf = poseidon_hash2(leaf, pair_id);
    leaf = poseidon_hash2(leaf, BASE_ASSET_ID);
    leaf = poseidon_hash2(leaf, QUOTE_ASSET_ID);
    leaf = poseidon_hash2(leaf, side);
    leaf = poseidon_hash2(leaf, 100);
    leaf = poseidon_hash2(leaf, 4000);
    leaf = poseidon_hash2(leaf, 1);
    leaf = poseidon_hash2(leaf, 100000);
    let request_root = poseidon_hash2(poseidon_hash2(EXTERNAL_MATCH_AUTHORIZATION_DOMAIN, 1), leaf);
    start_cheat_caller_address(fixture.executor.contract_address, fixture.registrar);
    fixture
        .executor
        .register_authorized_external_match_requests(
            batch_id,
            request_root,
            array![request_id].span(),
            array![pair_id].span(),
            array![BASE_ASSET_ID].span(),
            array![QUOTE_ASSET_ID].span(),
            array![side].span(),
            array![100].span(),
            array![4000].span(),
            array![1].span(),
            array![100000].span(),
        );
    stop_cheat_caller_address(fixture.executor.contract_address);
    cheat_block_timestamp(
        fixture.executor.contract_address, 10, snforge_std::CheatSpan::TargetCalls(1),
    );
}

fn poseidon_hash2(left: felt252, right: felt252) -> felt252 {
    let (result, _, _) = hades_permutation(left, right, 2);
    result
}

fn seed_bridge(fixture: Fixture, asset_id: felt252, token: IMockERC20Dispatcher, amount: u128) {
    token.mint(fixture.bridge.contract_address, as_u256(amount));
    let commitment_registry = fixture.bridge.commitment_registry_address();
    let privacy_pool = fixture.bridge.privacy_pool_address();
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    deploy_activation_verifier(fixture.admin, commitment_registry);
    start_cheat_caller_address(commitment_registry, fixture.admin);
    registry.set_privacy_deposit_bridge(fixture.bridge.contract_address);
    stop_cheat_caller_address(commitment_registry);
    let note_commitment: felt252 = 0x510000 + amount.into();
    let funding_commitment: felt252 = 0x520000 + amount.into();
    let withdraw_authority = 0x530001;
    let root = output_note_leaf(note_commitment, asset_id, amount, withdraw_authority);
    start_cheat_caller_address(fixture.bridge.contract_address, privacy_pool);
    let deposits = fixture
        .bridge
        .privacy_invoke(
            array![funding_commitment].span(),
            array![root].span(),
            array![0x540001 + amount.into()].span(),
            array![note_commitment].span(),
            array![asset_id].span(),
            array![amount].span(),
            array![withdraw_authority].span(),
        );
    stop_cheat_caller_address(fixture.bridge.contract_address);
    assert(deposits.is_empty(), 'OPEN_DEPOSITS_RETURNED');
}

fn buy_swaps(fixture: Fixture) -> Array<Swap> {
    array![
        Swap {
            route: array![route_node(fixture)],
            token_amount: TokenAmount {
                token: fixture.base_erc20.contract_address,
                amount: SignedAmount { mag: 40, sign: true },
            },
        },
    ]
}

fn sell_swaps(fixture: Fixture) -> Array<Swap> {
    array![
        Swap {
            route: array![route_node(fixture)],
            token_amount: TokenAmount {
                token: fixture.base_erc20.contract_address,
                amount: SignedAmount { mag: 40, sign: false },
            },
        },
    ]
}

fn route_node(fixture: Fixture) -> RouteNode {
    let base = fixture.base_erc20.contract_address;
    let quote = fixture.quote_erc20.contract_address;
    let (token0, token1) = if base < quote {
        (base, quote)
    } else {
        (quote, base)
    };
    RouteNode {
        pool_key: PoolKey {
            token0, token1, fee: 0, tick_spacing: 1, extension: 0.try_into().unwrap(),
        },
        sqrt_ratio_limit: 0,
        skip_ahead: 0,
    }
}

fn deploy(name: ByteArray, calldata: @Array<felt252>) -> ContractAddress {
    let class = declare(name).unwrap().contract_class();
    let (address, _) = class.deploy(calldata).unwrap_syscall();
    address
}

fn deploy_commitment_registry(admin: ContractAddress) -> ContractAddress {
    deploy("CommitmentRegistry", @array![admin.into()])
}

fn deploy_activation_verifier(admin: ContractAddress, deposit_registrar: ContractAddress) {
    let verifier_address = deploy(
        "AuctionVerifier", @array![admin.into(), as_address(0x444).into(), 0, 0, 0, 0],
    );
    let verifier = IAuctionVerifierDispatcher { contract_address: verifier_address };
    start_cheat_caller_address(verifier_address, admin);
    verifier.set_deposit_root_registrar(deposit_registrar);
    stop_cheat_caller_address(verifier_address);
    let registry = ICommitmentRegistryDispatcher { contract_address: deposit_registrar };
    start_cheat_caller_address(deposit_registrar, admin);
    registry.set_auction_verifier(verifier_address);
    stop_cheat_caller_address(deposit_registrar);
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
