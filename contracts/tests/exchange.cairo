//! the exchange against the rust reference: every transition and withdrawal below was built by
//! `zylith_core::exchange` (`core/examples/exchange_contract_fixtures.rs`), and the contract must
//! accept its exact calldata, commitments and proof messages through the real deposit path.

use core::poseidon::hades_permutation;
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_block_number, cheat_block_timestamp,
    cheat_caller_address, cheat_proof_facts, declare,
};
use starknet::ContractAddress;
use zylith_protocol::commitment_registry::{
    ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
};
use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
use zylith_protocol::exchange::{
    CapacityEntry, IExchangeDispatcher, IExchangeDispatcherTrait, MarketAttestation, OutcomeRecord,
    OutputRecord, ProofFacts, TransitionHeader,
};
use zylith_protocol::privacy_deposit_bridge::{
    IPrivacyDepositBridgeDispatcher, IPrivacyDepositBridgeDispatcherTrait,
};
use crate::mock_erc20::{IMockERC20Dispatcher, IMockERC20DispatcherTrait};

const ADMIN: felt252 = 0xad;
const SETTLEMENT: felt252 = 0x5e77;
const ROUTER: felt252 = 0x7007;
const PAIR: felt252 = 0x9a1;
const BASE: felt252 = 0xba5e;
const QUOTE: felt252 = 0x9a07e;
const FEE_RECIPIENT: felt252 = 0xfee;
const PROOF_VERSION: felt252 = 'PROOF1';
const VIRTUAL_PROGRAM_HASH: felt252 = 0xabc;
const OS_CONFIG_HASH: felt252 = 0xc0f;
const BASE_BLOCK_HASH: felt252 = 0xb10c;
const OUTPUT_NOTE_LEAF_DOMAIN: felt252 =
    0x0f0c89949c6cba4ac7f170f7f00809b458b997f2e394481c7ab58cc68aa49b3;

fn address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

#[derive(Drop)]
struct Setup {
    exchange: IExchangeDispatcher,
    bridge: IPrivacyDepositBridgeDispatcher,
    pool: ContractAddress,
    base_token: ContractAddress,
    quote_token: ContractAddress,
}

#[derive(Drop)]
struct Fixture {
    data: Span<felt252>,
}

#[generate_trait]
impl FixtureImpl of FixtureTrait {
    fn load(name: ByteArray) -> Fixture {
        let path = format!("tests/fixtures/{name}.txt");
        Fixture { data: read_txt(@FileTrait::new(path)).span() }
    }

    fn next(ref self: Fixture) -> felt252 {
        *self.data.pop_front().unwrap()
    }
}

#[derive(Drop, Serde)]
struct TransitionCall {
    header: TransitionHeader,
    markets: Span<MarketAttestation>,
    outcomes: Span<OutcomeRecord>,
    capacities: Span<CapacityEntry>,
    nullifiers: Span<felt252>,
    outputs: Span<OutputRecord>,
}

#[derive(Drop, Copy)]
struct WithdrawalCall {
    commitment: felt252,
    message: felt252,
    note_root: felt252,
    nullifier: felt252,
    asset_id: felt252,
    amount: u128,
    exit_commitment: felt252,
    exit_authority: felt252,
}

fn read_transition(ref fixture: Fixture) -> (felt252, felt252, TransitionCall) {
    let commitment = fixture.next();
    let message = fixture.next();
    let length: u32 = fixture.next().try_into().unwrap();
    let mut calldata = array![];
    for _ in 0..length {
        calldata.append(fixture.next());
    }
    let mut span = calldata.span();
    let call: TransitionCall = Serde::deserialize(ref span).unwrap();
    assert(span.is_empty(), 'fixture calldata trailing');
    (commitment, message, call)
}

fn read_withdrawal(ref fixture: Fixture) -> WithdrawalCall {
    WithdrawalCall {
        commitment: fixture.next(),
        message: fixture.next(),
        note_root: fixture.next(),
        nullifier: fixture.next(),
        asset_id: fixture.next(),
        amount: fixture.next().try_into().unwrap(),
        exit_commitment: fixture.next(),
        exit_authority: fixture.next(),
    }
}

fn proof_facts(message: felt252) -> Span<felt252> {
    let facts = ProofFacts {
        proof_version: PROOF_VERSION,
        program_variant: 'VIRTUAL_SNOS',
        virtual_program_hash: VIRTUAL_PROGRAM_HASH,
        starknet_os_output_version: 'VIRTUAL_SNOS0',
        base_block_number: 99,
        base_block_hash: BASE_BLOCK_HASH,
        starknet_os_config_hash: OS_CONFIG_HASH,
        message_to_l1_hashes: array![message].span(),
    };
    let mut serialized = array![];
    facts.serialize(ref serialized);
    serialized.span()
}

/// deploys the exchange at the fixture's chain context with the real bridge and registry, and
/// replays the fixture's deposits through the privacy pool.
fn setup(ref fixture: Fixture) -> Setup {
    setup_with_window(ref fixture, 0)
}

/// deploys and wires the exchange with an external window of `window` seconds.
fn setup_with_window(ref fixture: Fixture, window: u64) -> Setup {
    let chain_context = fixture.next();
    let signer = fixture.next();
    let proof_program = fixture.next();
    let (pool, _) = declare("MockPrivacyPool").unwrap().contract_class().deploy(@array![]).unwrap();
    let token_class = declare("MockERC20").unwrap().contract_class();
    let (base_token, _) = token_class.deploy(@array![]).unwrap();
    let (quote_token, _) = token_class.deploy(@array![]).unwrap();
    let (registry_address, _) = declare("CommitmentRegistry")
        .unwrap()
        .contract_class()
        .deploy(@array![ADMIN])
        .unwrap();
    let (bridge_address, _) = declare("PrivacyDepositBridge")
        .unwrap()
        .contract_class()
        .deploy(@array![ADMIN, registry_address.into(), pool.into()])
        .unwrap();
    let (exchange_address, _) = declare("Exchange")
        .unwrap()
        .contract_class()
        .deploy_at(@array![ADMIN], address(chain_context))
        .unwrap();
    let exchange = IExchangeDispatcher { contract_address: exchange_address };
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: bridge_address };
    let registry = ICommitmentRegistryDispatcher { contract_address: registry_address };

    cheat_caller_address(registry_address, address(ADMIN), CheatSpan::TargetCalls(2));
    registry.set_privacy_deposit_bridge(bridge_address);
    registry.set_exchange(exchange_address);
    cheat_caller_address(bridge_address, address(ADMIN), CheatSpan::TargetCalls(3));
    bridge.set_exchange(exchange_address);
    bridge.register_supported_asset(BASE, base_token);
    bridge.register_supported_asset(QUOTE, quote_token);
    cheat_caller_address(exchange_address, address(ADMIN), CheatSpan::TargetCalls(10));
    exchange.set_settlement_account(address(SETTLEMENT));
    exchange.set_proof_program(address(proof_program), VIRTUAL_PROGRAM_HASH);
    exchange.set_proof_validation(PROOF_VERSION, OS_CONFIG_HASH, 450);
    exchange.set_custody(bridge_address, registry_address, address(ROUTER));
    exchange.set_reference_signer(signer);
    exchange.set_objective_numeraire(QUOTE);
    exchange.register_pair(PAIR, BASE, QUOTE, 30);
    exchange.set_protocol_fee_recipient(FEE_RECIPIENT);
    exchange.set_timing(60000, 120, window);
    exchange.lock_config();

    let deposit_count: u32 = fixture.next().try_into().unwrap();
    for _ in 0..deposit_count {
        let funding = fixture.next();
        let deposit_root = fixture.next();
        let note_commitment = fixture.next();
        let asset_id = fixture.next();
        let amount: u128 = fixture.next().try_into().unwrap();
        let withdraw_authority = fixture.next();
        let token = if asset_id == BASE {
            base_token
        } else {
            quote_token
        };
        IMockERC20Dispatcher { contract_address: token }.mint(bridge_address, amount.into());
        cheat_caller_address(bridge_address, pool, CheatSpan::TargetCalls(1));
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
    }
    Setup { exchange, bridge, pool, base_token, quote_token }
}

fn submit(setup: @Setup, message: felt252, call: @TransitionCall, timestamp: u64) {
    let exchange = *setup.exchange;
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
            *call.outputs,
        );
}

fn request(setup: @Setup, withdrawal: WithdrawalCall, timestamp: u64) {
    let exchange = *setup.exchange;
    cheat_block_number(exchange.contract_address, 100, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(exchange.contract_address, timestamp, CheatSpan::TargetCalls(1));
    cheat_proof_facts(
        exchange.contract_address, proof_facts(withdrawal.message), CheatSpan::TargetCalls(1),
    );
    exchange
        .request_withdrawal(
            withdrawal.note_root,
            withdrawal.nullifier,
            withdrawal.asset_id,
            withdrawal.amount,
            withdrawal.exit_commitment,
            withdrawal.exit_authority,
        );
}

fn output_note_leaf(
    note_commitment: felt252, asset_id: felt252, amount: u128, withdraw_authority: felt252,
) -> felt252 {
    let (state, _, _) = hades_permutation(OUTPUT_NOTE_LEAF_DOMAIN, note_commitment, 2);
    let (state, _, _) = hades_permutation(state, asset_id, 2);
    let (state, _, _) = hades_permutation(state, amount.into(), 2);
    let (leaf, _, _) = hades_permutation(state, withdraw_authority, 2);
    leaf
}

#[test]
#[should_panic(expected: 'TOKEN_CUSTODY_LOW')]
fn a_pending_exit_cannot_back_a_new_shielded_deposit() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let asset_id = BASE;
    let amount = 1_u128;
    let exit_commitment = 0xe117;
    let note_commitment = 0xc011;
    let withdraw_authority = 0xa117;

    cheat_caller_address(
        setup.bridge.contract_address, setup.exchange.contract_address, CheatSpan::TargetCalls(1),
    );
    setup
        .bridge
        .stage_verified_note_strk20_exit(
            asset_id, amount, 0x51a9, withdraw_authority, exit_commitment,
        );
    assert(setup.bridge.pending_exit_asset_amount(asset_id) == amount, 'pending liability');

    let deposit_root = output_note_leaf(note_commitment, asset_id, amount, withdraw_authority);
    cheat_caller_address(setup.bridge.contract_address, setup.pool, CheatSpan::TargetCalls(1));
    setup
        .bridge
        .privacy_invoke(
            array![0xf011].span(),
            array![deposit_root].span(),
            array![0xeac].span(),
            array![note_commitment].span(),
            array![asset_id].span(),
            array![amount].span(),
            array![withdraw_authority].span(),
        );
}

#[test]
#[should_panic(expected: 'CONFIG_LOCKED')]
fn a_locked_exchange_cannot_silently_add_a_market() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    cheat_caller_address(
        setup.exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(1),
    );
    setup.exchange.register_pair(0x999, BASE, QUOTE, 30);
}

#[test]
fn a_locked_exchange_rotates_its_online_reference_signer_only_after_pause_and_timelock() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let exchange = setup.exchange;
    let replacement = 0x987654;
    assert(exchange.reference_signer() != replacement, 'old signer');
    cheat_caller_address(exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(2));
    exchange.propose_reference_signer(replacement);
    exchange.pause();
    cheat_block_timestamp(exchange.contract_address, 86400, CheatSpan::TargetCalls(1));
    cheat_caller_address(exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(1));
    exchange.execute_reference_signer();
    assert(exchange.reference_signer() == replacement, 'new signer');
}

#[test]
fn a_cross_settles_and_its_output_withdraws_after_the_delay() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let exchange = setup.exchange;
    let raced = read_withdrawal(ref fixture);
    let (commitment, message, call) = read_transition(ref fixture);
    let withdrawal = read_withdrawal(ref fixture);
    // the contract and the rust reference agree on the proof message.
    assert(exchange.transition_message_hash(commitment) == message, 'transition message');
    assert(
        exchange.withdrawal_message_hash(withdrawal.commitment) == withdrawal.message,
        'withdrawal message',
    );

    // the seller asks to withdraw the note its order spends; the transition wins.
    request(@setup, raced, 11);
    assert(exchange.nullifier_state(raced.nullifier) == 2, 'exit pending');
    submit(@setup, message, @call, 11);
    assert(exchange.transition_seq() == 1, 'seq');
    assert(exchange.book_root() == call.header.new_book_root, 'book root');
    assert(exchange.nullifier_state(raced.nullifier) == 1, 'transition won');
    for nullifier in call.nullifiers {
        assert(exchange.nullifier_state(*nullifier) == 1, 'nullifier spent');
    }
    assert(exchange.is_known_note_root(withdrawal.note_root), 'output root known');

    // the proceeds note withdraws once, after the delay, into a staged strk20 exit.
    request(@setup, withdrawal, 12);
    assert(exchange.nullifier_state(withdrawal.nullifier) == 2, 'exit pending');
    let escrow_before = setup.bridge.escrowed_asset_amount(withdrawal.asset_id);
    cheat_block_timestamp(exchange.contract_address, 12 + 120, CheatSpan::TargetCalls(1));
    exchange.finalize_withdrawal(withdrawal.nullifier);
    assert(exchange.nullifier_state(withdrawal.nullifier) == 3, 'exited');
    assert(
        setup.bridge.escrowed_asset_amount(withdrawal.asset_id) == escrow_before
            - withdrawal.amount,
        'escrow released',
    );
    assert(
        setup.bridge.pending_exit_asset_amount(withdrawal.asset_id) == withdrawal.amount,
        'exit remains a liability',
    );
}

#[test]
#[should_panic(expected: 'NO_PENDING_EXIT')]
fn a_voided_exit_cannot_finalize() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let raced = read_withdrawal(ref fixture);
    let (_, message, call) = read_transition(ref fixture);
    request(@setup, raced, 11);
    submit(@setup, message, @call, 11);
    cheat_block_timestamp(setup.exchange.contract_address, 500, CheatSpan::TargetCalls(1));
    setup.exchange.finalize_withdrawal(raced.nullifier);
}

#[test]
#[should_panic(expected: 'EXIT_NOT_MATURE')]
fn an_exit_waits_for_the_delay() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let raced = read_withdrawal(ref fixture);
    request(@setup, raced, 11);
    cheat_block_timestamp(setup.exchange.contract_address, 11 + 119, CheatSpan::TargetCalls(1));
    setup.exchange.finalize_withdrawal(raced.nullifier);
}

#[test]
#[should_panic(expected: 'BAD_SEQ')]
fn a_transition_cannot_replay() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let _ = read_withdrawal(ref fixture);
    let (_, message, call) = read_transition(ref fixture);
    submit(@setup, message, @call, 11);
    submit(@setup, message, @call, 12);
}

#[test]
#[should_panic(expected: 'BAD_PROOF_MSG')]
fn a_changed_output_is_not_the_proven_transition() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let _ = read_withdrawal(ref fixture);
    let (_, message, call) = read_transition(ref fixture);
    let mut outputs = array![];
    for output in call.outputs {
        outputs.append(*output);
    }
    let first = *outputs.at(0);
    let mut changed = array![OutputRecord { leaf: first.leaf + 1, enc: first.enc }];
    for index in 1..outputs.len() {
        changed.append(*outputs.at(index));
    }
    let call = TransitionCall { outputs: changed.span(), ..call };
    submit(@setup, message, @call, 11);
}

#[test]
#[should_panic(expected: 'LATE_CLOSE')]
fn a_late_transition_is_rejected() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let _ = read_withdrawal(ref fixture);
    let (_, message, call) = read_transition(ref fixture);
    submit(@setup, message, @call, 71);
}

#[test]
#[should_panic(expected: 'NULLIFIER_USED')]
fn a_spent_note_cannot_withdraw() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let raced = read_withdrawal(ref fixture);
    let (_, message, call) = read_transition(ref fixture);
    submit(@setup, message, @call, 11);
    request(@setup, raced, 12);
}

#[test]
fn an_external_capacity_opens_and_its_outcome_applies_next() {
    let mut fixture = FixtureTrait::load("exchange_external");
    let setup = setup(ref fixture);
    let exchange = setup.exchange;
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let (_, apply_message, apply) = read_transition(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);
    let capacity = exchange.capacity(1, PAIR, true);
    assert(
        capacity.status == 1
            && capacity.generation == 0
            && capacity.bound == 95
            && capacity.total == 10,
        'capacity open',
    );
    submit(@setup, apply_message, @apply, 12);
    assert(exchange.capacity(1, PAIR, true).status == 3, 'outcome applied');
    assert(exchange.transition_seq() == 2, 'seq');
}

#[test]
fn a_freeze_is_a_versioned_cutoff_and_releases_the_remainder_to_the_next_transition() {
    let mut fixture = FixtureTrait::load("exchange_external_parts");
    let setup = setup_with_window(ref fixture, 60);
    let exchange = setup.exchange;
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let (_, apply_message, apply) = read_transition(ref fixture);
    let m1 = read_attestation(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);

    fill(@setup, 6, m1);
    fill(@setup, 3, m1);
    let filled = exchange.capacity(1, PAIR, true);
    assert(filled.generation == 2 && filled.consumed_base == 9, 'fill version');

    cheat_caller_address(exchange.contract_address, address(SETTLEMENT), CheatSpan::TargetCalls(1));
    exchange.freeze_capacity(1, PAIR, true, 2);
    let frozen = exchange.capacity(1, PAIR, true);
    assert(frozen.status == 4 && frozen.generation == 3, 'frozen cutoff');
    assert(frozen.total == frozen.consumed_base + 1, 'capacity partition');

    // the fixture applies the firm nine-base fill. it may do so before the 60-second window,
    // while the one-base remainder has returned to the private book for this same auction.
    submit(@setup, apply_message, @apply, 12);
    assert(exchange.capacity(1, PAIR, true).status == 3, 'outcome applied');
}

#[test]
#[should_panic(expected: 'STALE_CAPACITY')]
fn a_fill_that_wins_chain_order_invalidates_a_stale_freeze() {
    let mut fixture = FixtureTrait::load("exchange_external_parts");
    let setup = setup_with_window(ref fixture, 60);
    let exchange = setup.exchange;
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let (_, _, _) = read_transition(ref fixture);
    let m1 = read_attestation(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);
    fill(@setup, 1, m1);

    cheat_caller_address(exchange.contract_address, address(SETTLEMENT), CheatSpan::TargetCalls(1));
    exchange.freeze_capacity(1, PAIR, true, 0);
}

#[test]
#[should_panic(expected: 'CAPACITY_CLOSED')]
fn no_fill_can_land_after_the_freeze_cutoff() {
    let mut fixture = FixtureTrait::load("exchange_external_parts");
    let setup = setup_with_window(ref fixture, 60);
    let exchange = setup.exchange;
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let (_, _, _) = read_transition(ref fixture);
    let m1 = read_attestation(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);

    cheat_caller_address(exchange.contract_address, address(SETTLEMENT), CheatSpan::TargetCalls(1));
    exchange.freeze_capacity(1, PAIR, true, 0);
    fill(@setup, 1, m1);
}

#[test]
#[should_panic(expected: 'OUTCOME_WINDOW_OPEN')]
fn an_outcome_waits_for_its_window() {
    let mut fixture = FixtureTrait::load("exchange_external");
    let setup = setup(ref fixture);
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let (_, apply_message, apply) = read_transition(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);
    submit(@setup, apply_message, @apply, 11);
}

fn read_attestation(ref fixture: Fixture) -> MarketAttestation {
    let mut values = array![];
    for _ in 0..13_u32 {
        values.append(fixture.next());
    }
    let mut span = values.span();
    Serde::deserialize(ref span).unwrap()
}

#[test]
#[should_panic(expected: 'OUTCOME_MISMATCH')]
fn a_filled_capacity_changes_the_outcome_the_next_transition_must_apply() {
    let mut fixture = FixtureTrait::load("exchange_external");
    let setup = setup(ref fixture);
    let exchange = setup.exchange;
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let (_, apply_message, apply) = read_transition(ref fixture);
    let m1 = read_attestation(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);

    // the searcher's router takes 6 base from the escrow at m1 = 101 and pays 606 quote.
    fill(@setup, 6, m1);
    let capacity = exchange.capacity(1, PAIR, true);
    assert(capacity.status == 1 && capacity.consumed_base == 6, 'partly filled, still open');
    assert(capacity.pool_quote == 606 && capacity.m1 == 101, 'priced at m1');
    assert(setup.bridge.escrowed_asset_amount(QUOTE) == 606, 'quote escrowed');

    // the zero outcome built before the fill no longer matches the chain.
    submit(@setup, apply_message, @apply, 12);
}

/// the router's side of one fill of the sell capacity at m1 = 101: it pays the quote and the
/// escrow hands it the base.
fn fill(setup: @Setup, base: u128, m1: MarketAttestation) {
    fill_at(setup, base, m1, 11);
}

fn fill_at(setup: @Setup, base: u128, m1: MarketAttestation, timestamp: u64) {
    let router = address(ROUTER);
    let quote = base * 101;
    IMockERC20Dispatcher { contract_address: *setup.quote_token }.mint(router, quote.into());
    cheat_caller_address(*setup.quote_token, router, CheatSpan::TargetCalls(1));
    IERC20Dispatcher { contract_address: *setup.quote_token }
        .approve(*setup.bridge.contract_address, quote.into());
    let exchange = *setup.exchange;
    cheat_block_timestamp(exchange.contract_address, timestamp, CheatSpan::TargetCalls(1));
    cheat_caller_address(exchange.contract_address, router, CheatSpan::TargetCalls(1));
    exchange.settle_external_fill(1, PAIR, true, base, m1);
}

#[test]
#[should_panic(expected: 'FUTURE_M1')]
fn an_external_fill_rejects_a_future_dated_midpoint() {
    let mut fixture = FixtureTrait::load("exchange_external_parts");
    let setup = setup_with_window(ref fixture, 60);
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let (_, _, _) = read_transition(ref fixture);
    let m1 = read_attestation(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);
    fill_at(@setup, 1, m1, 0);
}

#[test]
fn a_capacity_fills_in_parts_and_its_orders_share_the_average_price() {
    let mut fixture = FixtureTrait::load("exchange_external_parts");
    let setup = setup(ref fixture);
    let exchange = setup.exchange;
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let (_, apply_message, apply) = read_transition(ref fixture);
    let m1 = read_attestation(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);

    // two searchers fill 6 and then 3 of the 10; the last base stays unfilled.
    fill(@setup, 6, m1);
    fill(@setup, 3, m1);
    let capacity = exchange.capacity(1, PAIR, true);
    assert(capacity.status == 1, 'open while base is left');
    assert(capacity.consumed_base == 9 && capacity.pool_quote == 909, 'fills accumulate');
    assert(setup.bridge.escrowed_asset_amount(QUOTE) == 909, 'quote escrowed');
    assert(setup.bridge.escrowed_asset_amount(BASE) == 1, 'unfilled base kept');

    // after the window the next transition applies the totals at their average price.
    submit(@setup, apply_message, @apply, 12);
    assert(exchange.capacity(1, PAIR, true).status == 3, 'outcome applied');
    assert(exchange.transition_seq() == 2, 'seq');
}

#[test]
#[should_panic(expected: 'BAD_FILL')]
fn a_fill_cannot_take_more_than_is_left() {
    let mut fixture = FixtureTrait::load("exchange_external_parts");
    let setup = setup(ref fixture);
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let (_, _, _) = read_transition(ref fixture);
    let m1 = read_attestation(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);
    fill(@setup, 6, m1);
    fill(@setup, 5, m1);
}

#[test]
#[should_panic(expected: 'CAPACITY_CLOSED')]
fn a_used_up_capacity_takes_no_more_fills() {
    let mut fixture = FixtureTrait::load("exchange_external_parts");
    let setup = setup(ref fixture);
    let exchange = setup.exchange;
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let (_, _, _) = read_transition(ref fixture);
    let m1 = read_attestation(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);
    fill(@setup, 10, m1);
    assert(exchange.capacity(1, PAIR, true).status == 2, 'used up');
    fill(@setup, 1, m1);
}

#[test]
fn a_used_up_capacity_settles_at_the_next_transition_without_waiting_for_its_window() {
    let mut fixture = FixtureTrait::load("exchange_external_full");
    let setup = setup_with_window(ref fixture, 60);
    let exchange = setup.exchange;
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let (_, apply_message, apply) = read_transition(ref fixture);
    let m1 = read_attestation(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);
    fill(@setup, 10, m1);
    assert(exchange.capacity(1, PAIR, true).status == 2, 'used up');
    // a second later, well inside the 60 second window.
    submit(@setup, apply_message, @apply, 12);
    assert(exchange.capacity(1, PAIR, true).status == 3, 'outcome applied');
}

#[test]
#[should_panic(expected: 'OUTCOME_WINDOW_OPEN')]
fn a_capacity_with_base_left_settles_only_after_its_window() {
    let mut fixture = FixtureTrait::load("exchange_external_parts");
    let setup = setup_with_window(ref fixture, 60);
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let (_, apply_message, apply) = read_transition(ref fixture);
    let m1 = read_attestation(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);
    fill(@setup, 6, m1);
    fill(@setup, 3, m1);
    // more base could still be filled, so the totals are not final yet.
    submit(@setup, apply_message, @apply, 12);
}
