//! the searcher leg against the real ekubo on mainnet forks, both directions.
//!
//! a 1000 strk external sell rests at a 0.040 usdc limit, and the router fills it at an m1 of
//! 0.0405 inside one ekubo lock (borrow the usdc the escrow is paid, take the strk from the
//! escrow, sell it along ekubo's two-hop route, repay) and keeps the surplus.
//!
//! a 1000 strk external buy rests at 0.042, and the router fills it at 0.0415 (borrow the strk
//! the escrow receives, take the usdc it pays, buy exactly 1000 strk back over ekubo's two
//! exact-output splits, repay) and keeps the surplus.
//!
//! in both, the next transition applies the filled outcome. run the pinned network test with
//! `contracts/scripts/run_ekubo_mainnet_fork_tests.sh` from the repository root.

use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_block_number, cheat_block_timestamp,
    cheat_caller_address, cheat_proof_facts, declare, start_cheat_block_timestamp,
    stop_cheat_block_timestamp,
};
use starknet::ContractAddress;
use zylith_protocol::commitment_registry::{
    ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
};
use zylith_protocol::ekubo_abi::{PoolKey, RouteNode, SignedAmount, Swap, TokenAmount};
use zylith_protocol::ekubo_external_match_router::{
    IEkuboExternalMatchRouterDispatcher, IEkuboExternalMatchRouterDispatcherTrait,
};
use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
use zylith_protocol::exchange::{
    CapacityEntry, IExchangeDispatcher, IExchangeDispatcherTrait, MarketAttestation, OutcomeRecord,
    OutputRecord, ProofFacts, TransitionHeader,
};
use zylith_protocol::privacy_deposit_bridge::{
    IPrivacyDepositBridgeDispatcher, IPrivacyDepositBridgeDispatcherTrait,
};

const ADMIN: felt252 = 0xad;
const SETTLEMENT: felt252 = 0x5e77;
const POOL: felt252 = 0x9001;
const PAIR: felt252 = 0x9a1;
const BASE: felt252 = 0xba5e;
const QUOTE: felt252 = 0x9a07e;
const FEE_RECIPIENT: felt252 = 0xfee;
const STRK: felt252 = 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d;
const USDC: felt252 = 0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8;
const HOP: felt252 = 0x033068f6539f8e6e6b131e6b2b814e6c34a5224bc66947c47dab9dfee93b35fb;
const EKUBO_CORE: felt252 = 0x00000005dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b;
const EKUBO_ROUTER: felt252 = 0x0199741822c2dc722f6f605204f35e56dbc23bceed54818168c4c49e4fb8737e;
const SCALE: u128 = 1_000_000_000_000_000_000;
const SIZE: u128 = 1_000_000_000_000_000_000_000;

fn address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

#[derive(Drop, Serde)]
struct TransitionCall {
    header: TransitionHeader,
    markets: Span<MarketAttestation>,
    outcomes: Span<OutcomeRecord>,
    capacities: Span<CapacityEntry>,
    nullifiers: Span<felt252>,
    retired_nullifiers: Span<felt252>,
    outputs: Span<OutputRecord>,
}

fn next(ref data: Span<felt252>) -> felt252 {
    *data.pop_front().unwrap()
}

fn read_transition(ref data: Span<felt252>) -> (felt252, TransitionCall) {
    let _commitment = next(ref data);
    let message = next(ref data);
    let length: u32 = next(ref data).try_into().unwrap();
    let mut calldata = array![];
    for _ in 0..length {
        calldata.append(next(ref data));
    }
    let mut span = calldata.span();
    (message, Serde::deserialize(ref span).unwrap())
}

fn proof_facts(message: felt252) -> Span<felt252> {
    let facts = ProofFacts {
        proof_version: 'PROOF2',
        program_variant: 'VIRTUAL_SNOS',
        virtual_program_hash: 0xabc,
        starknet_os_output_version: 'VIRTUAL_SNOS0',
        base_block_number: 99,
        base_block_hash: 0xb10c,
        starknet_os_config_hash: 0xc0f,
        message_to_l1_hashes: array![message].span(),
    };
    let mut serialized = array![];
    facts.serialize(ref serialized);
    serialized.span()
}

fn submit(exchange: IExchangeDispatcher, message: felt252, call: @TransitionCall, timestamp: u64) {
    cheat_block_number(exchange.contract_address, 100, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(exchange.contract_address, timestamp, CheatSpan::TargetCalls(1));
    cheat_proof_facts(exchange.contract_address, proof_facts(message), CheatSpan::TargetCalls(1));
    cheat_caller_address(exchange.contract_address, address(SETTLEMENT), CheatSpan::TargetCalls(1));
    exchange
        .submit_transition(
            *call.header,
            *call.markets,
            *call.outcomes,
            *call.capacities,
            *call.nullifiers,
            *call.retired_nullifiers,
            *call.outputs,
        );
}

fn pool(token0: felt252, token1: felt252, fee: u128, tick_spacing: u128) -> PoolKey {
    PoolKey {
        token0: address(token0), token1: address(token1), fee, tick_spacing, extension: address(0),
    }
}

/// ekubo's exact-output route at the buy fork block for buying `amount` strk with usdc: half
/// directly, half through the hop token (quoted for 1000 strk; the price limits hold for less).
fn buy_route(amount: u128) -> Array<Swap> {
    let half = SignedAmount { mag: amount / 2, sign: true };
    array![
        Swap {
            route: array![
                RouteNode {
                    pool_key: pool(STRK, USDC, 170141183460469235273462165868118016, 1000),
                    sqrt_ratio_limit: 0x3df0d6dcac12c8f381c006c3fb1,
                    skip_ahead: 0,
                },
            ],
            token_amount: TokenAmount { token: address(STRK), amount: half },
        },
        Swap {
            route: array![
                RouteNode {
                    pool_key: pool(HOP, STRK, 170141183460469235273462165868118016, 1000),
                    sqrt_ratio_limit: 0x423183a6ef24922dd53e40cf88c12f84121546,
                    skip_ahead: 0,
                },
                RouteNode {
                    pool_key: pool(HOP, USDC, 0, 101),
                    sqrt_ratio_limit: 0x10357ccd65942779c0f320aa14537c012,
                    skip_ahead: 0,
                },
            ],
            token_amount: TokenAmount { token: address(STRK), amount: half },
        },
    ]
}

/// ekubo's route at the sell fork block for selling `amount` strk into usdc through the hop
/// token (quoted for 1000 strk; the price limits hold for less).
fn route(amount: u128) -> Array<Swap> {
    array![
        Swap {
            route: array![
                RouteNode {
                    pool_key: PoolKey {
                        token0: address(HOP),
                        token1: address(STRK),
                        fee: 170141183460469235273462165868118016,
                        tick_spacing: 1000,
                        extension: address(0),
                    },
                    sqrt_ratio_limit: 0x5573be4872f910695227261743b1b80e003f03,
                    skip_ahead: 0,
                },
                RouteNode {
                    pool_key: PoolKey {
                        token0: address(HOP),
                        token1: address(USDC),
                        fee: 0,
                        tick_spacing: 101,
                        extension: address(0),
                    },
                    sqrt_ratio_limit: 0xfcb8fb6cb7804666378f59d2e9bc133a,
                    skip_ahead: 0,
                },
            ],
            token_amount: TokenAmount {
                token: address(STRK), amount: SignedAmount { mag: amount, sign: false },
            },
        },
    ]
}

#[test]
#[fork(url: "https://api.cartridge.gg/x/starknet/mainnet", block_number: 15489308)]
fn a_real_ekubo_hedge_fills_an_external_capacity_for_profit() {
    fill("tests/fixtures/exchange_fork.txt", true, 1, 600_000, 40_500_000);
}

#[test]
#[fork(url: "https://api.cartridge.gg/x/starknet/mainnet", block_number: 15489308)]
fn two_real_ekubo_hedges_fill_one_sell_capacity_in_halves() {
    fill("tests/fixtures/exchange_fork.txt", true, 2, 600_000, 40_500_000);
}

#[test]
#[fork(url: "https://api.cartridge.gg/x/starknet/mainnet", block_number: 15513293)]
fn a_real_ekubo_exact_output_hedge_fills_an_external_buy_for_profit() {
    fill("tests/fixtures/exchange_fork_buy.txt", false, 1, 300_000, 41_500_000);
}

#[test]
#[fork(url: "https://api.cartridge.gg/x/starknet/mainnet", block_number: 15513293)]
fn two_real_ekubo_hedges_fill_one_buy_capacity_in_halves() {
    fill("tests/fixtures/exchange_fork_buy.txt", false, 2, 300_000, 41_500_000);
}

/// deploys the exchange against the forked ekubo, rests the fixture's external order, fills its
/// capacity through the router in `parts` equal fills and applies the outcome. `pool_quote` is
/// the escrow's side at m1 over all the fills.
fn fill(fixture: ByteArray, sell: bool, parts: u128, min_profit: u128, pool_quote: u128) {
    let mut data = read_txt(@FileTrait::new(fixture)).span();
    let chain_context = next(ref data);
    let signer = next(ref data);
    let proof_program = next(ref data);

    let (registry_address, _) = declare("CommitmentRegistry")
        .unwrap()
        .contract_class()
        .deploy(@array![ADMIN])
        .unwrap();
    let (bridge_address, _) = declare("PrivacyDepositBridge")
        .unwrap()
        .contract_class()
        .deploy(@array![ADMIN, registry_address.into(), POOL])
        .unwrap();
    let (exchange_address, _) = declare("Exchange")
        .unwrap()
        .contract_class()
        .deploy_at(@array![ADMIN], address(chain_context))
        .unwrap();
    let (router_address, _) = declare("EkuboExternalMatchRouter")
        .unwrap()
        .contract_class()
        .deploy(@array![EKUBO_CORE, EKUBO_ROUTER, exchange_address.into(), bridge_address.into()])
        .unwrap();
    let exchange = IExchangeDispatcher { contract_address: exchange_address };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: bridge_address };
    let registry = ICommitmentRegistryDispatcher { contract_address: registry_address };
    let (strk, usdc) = (
        IERC20Dispatcher { contract_address: address(STRK) },
        IERC20Dispatcher { contract_address: address(USDC) },
    );

    cheat_caller_address(registry_address, address(ADMIN), CheatSpan::TargetCalls(2));
    registry.set_privacy_deposit_bridge(bridge_address);
    registry.set_exchange(exchange_address);
    cheat_caller_address(bridge_address, address(ADMIN), CheatSpan::TargetCalls(3));
    bridge.set_exchange(exchange_address);
    bridge.register_supported_asset(BASE, address(STRK));
    bridge.register_supported_asset(QUOTE, address(USDC));
    cheat_caller_address(exchange_address, address(ADMIN), CheatSpan::TargetCalls(10));
    exchange.set_settlement_account(address(SETTLEMENT));
    exchange
        .set_proof_programs(
            address(proof_program), address(proof_program), address(proof_program), 0xabc,
        );
    exchange.set_proof_validation('PROOF2', 0xc0f, 450);
    exchange.set_custody(bridge_address, registry_address, router_address);
    exchange.set_reference_signer(signer);
    exchange.set_objective_numeraire(QUOTE);
    exchange.register_pair(PAIR, BASE, QUOTE, SCALE, 30, 1, 0, 0, 0, 0);
    exchange.set_pair_external_support(PAIR, 1);
    exchange.set_protocol_fee_recipient(FEE_RECIPIENT);
    exchange.set_timing(1, 60000, 120, 30);

    // the trader's deposit (strk for a sell, usdc for a buy), funded from ekubo core's balance.
    let deposit_count: u32 = next(ref data).try_into().unwrap();
    assert(deposit_count == 1, 'one deposit');
    let funding = next(ref data);
    let deposit_root = next(ref data);
    let note_commitment = next(ref data);
    let asset_id = next(ref data);
    let amount: u128 = next(ref data).try_into().unwrap();
    let withdraw_authority = next(ref data);
    let (input, output) = if sell {
        (strk, usdc)
    } else {
        (usdc, strk)
    };
    cheat_caller_address(input.contract_address, address(EKUBO_CORE), CheatSpan::TargetCalls(1));
    input.transfer(bridge_address, amount.into());
    cheat_caller_address(bridge_address, address(POOL), CheatSpan::TargetCalls(1));
    bridge
        .privacy_invoke(
            array![funding].span(),
            array![deposit_root].span(),
            array![1].span(),
            array![note_commitment].span(),
            array![asset_id].span(),
            array![amount].span(),
            array![withdraw_authority].span(),
        );

    let (reserve_message, reserve) = read_transition(ref data);
    let (apply_message, apply) = read_transition(ref data);
    let mut m1_fields = array![];
    for _ in 0..21_u32 {
        m1_fields.append(next(ref data));
    }
    let mut m1_span = m1_fields.span();
    let m1: MarketAttestation = Serde::deserialize(ref m1_span).unwrap();

    submit(exchange, reserve_message, @reserve, 11);
    let capacity = exchange.capacity(1, PAIR, sell);
    assert(capacity.status == 1 && capacity.total == SIZE, 'capacity open');

    // the searcher legs: each one ekubo lock, the escrow trading its part of the 1000 strk at
    // m1. the capacity stays open while strk is left.
    let searcher = starknet::get_contract_address();
    let usdc_before = usdc.balance_of(searcher);
    let support_before = usdc.balance_of(address(SETTLEMENT));
    let base_surplus_before = strk.balance_of(address(SETTLEMENT));
    let router = IEkuboExternalMatchRouterDispatcher { contract_address: router_address };
    // arbitrary dust at ekubo's shared router must be swept to settlement, not make the fill
    // revert or become searcher profit.
    cheat_caller_address(strk.contract_address, address(EKUBO_CORE), CheatSpan::TargetCalls(1));
    strk.transfer(address(EKUBO_ROUTER), 1_u128.into());
    let part = SIZE / parts;
    let mut profit = 0_u128;
    // the legs run while the capacity's window is open, at its timestamp.
    start_cheat_block_timestamp(exchange_address, 11);
    for index in 0..parts {
        let swaps = if sell {
            route(part)
        } else {
            buy_route(part)
        };
        profit += router
            .execute_external_fill(exchange_address, 1, PAIR, sell, part, 100_000, m1, swaps);
        let capacity = exchange.capacity(1, PAIR, sell);
        assert(capacity.consumed_base == part * (index + 1), 'fills accumulate');
        assert(capacity.status == if index + 1 == parts {
            2
        } else {
            1
        }, 'open until used up');
    }
    stop_cheat_block_timestamp(exchange_address);
    assert(profit >= min_profit, 'hedge profit');
    assert(usdc.balance_of(searcher) - usdc_before == profit.into(), 'profit paid out');
    assert(
        usdc.balance_of(address(SETTLEMENT)) - support_before == parts.into(),
        'settlement support paid',
    );
    assert(
        strk.balance_of(address(SETTLEMENT)) - base_surplus_before == 1_u128.into(),
        'base surplus swept',
    );
    let filled = exchange.capacity(1, PAIR, sell);
    assert(filled.status == 2 && filled.consumed_base == SIZE, 'capacity filled');
    assert(filled.pool_quote == pool_quote, 'escrow traded at m1');
    // the escrow now holds the other side: quote for a sell, base for a buy, and nothing of
    // what it gave up beyond the unspent limit headroom.
    if sell {
        assert(bridge.escrowed_asset_amount(QUOTE) == pool_quote, 'quote escrowed');
        assert(bridge.escrowed_asset_amount(BASE) == 0, 'base left the escrow');
    } else {
        assert(bridge.escrowed_asset_amount(BASE) == SIZE, 'base escrowed');
        assert(bridge.escrowed_asset_amount(QUOTE) == amount - pool_quote, 'quote paid at m1');
    }
    assert(input.balance_of(router_address) == 0, 'router holds no input');
    assert(output.balance_of(router_address) == 0, 'router holds no output');

    // the next transition applies the filled outcome and pays the trader from the escrow.
    submit(exchange, apply_message, @apply, 12);
    assert(exchange.capacity(1, PAIR, sell).status == 3, 'outcome applied');
    assert(exchange.transition_seq() == 2, 'seq');
}
