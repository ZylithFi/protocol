//! the exchange against the rust reference: every transition and withdrawal below was built by
//! `zylith_core::exchange` (`core/examples/exchange_contract_fixtures.rs`), and the contract must
//! accept its exact calldata, commitments and proof messages through the real deposit path.

use core::ecdsa::check_ecdsa_signature;
use core::poseidon::{hades_permutation, poseidon_hash_span};
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, cheat_account_contract_address,
    cheat_block_number, cheat_block_timestamp, cheat_caller_address, cheat_chain_id,
    cheat_proof_facts, declare,
};
use starknet::ContractAddress;
use zylith_protocol::commitment_registry::{
    ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
};
use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
use zylith_protocol::exchange::{
    CapacityEntry, IExchangeDispatcher, IExchangeDispatcherTrait, MarketAttestation, OutcomeRecord,
    OutputRecord, ProofFacts, ResidualRecovery, TransitionHeader,
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
const PROOF_VERSION: felt252 = 'PROOF2';
const VIRTUAL_PROGRAM_HASH: felt252 = 0xabc;
const OS_CONFIG_HASH: felt252 = 0xc0f;
const BASE_BLOCK_HASH: felt252 = 0xb10c;
const TRANSITION_MESSAGE_DOMAIN: felt252 = 'zylith_transition_msg_v1';
const WITHDRAWAL_MESSAGE_DOMAIN: felt252 = 'zylith_withdraw_msg_v1';
const RESIDUAL_RECOVERY_MESSAGE_DOMAIN: felt252 = 'zylith_res_recover_msg_v1';
const OUTPUT_NOTE_LEAF_DOMAIN: felt252 =
    0x0f0c89949c6cba4ac7f170f7f00809b458b997f2e394481c7ab58cc68aa49b3;
const STRK20_EXIT_CLAIM_DOMAIN: felt252 = 0x7a796c6974685f7374726b32305f636c61696d5f7633;

fn address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn bound_proof_message(
    program: felt252, domain: felt252, exchange: felt252, commitment: felt252,
) -> felt252 {
    let (inner, _, _) = hades_permutation(domain, exchange, 2);
    let (statement, _, _) = hades_permutation(inner, commitment, 2);
    poseidon_hash_span(array![program, 0, 2, domain, statement].span())
}

#[test]
fn strk20_exit_claim_signature_vector_matches_the_wallet() {
    let values = array![
        0x123_felt252, 0x111_felt252, 0x222_felt252, 0x444_felt252, 0x555_felt252, 0x333_felt252,
        0x7_felt252, 0x666_felt252, 0x777_felt252, 0x999_felt252, 0x888_felt252,
    ];
    let mut state = STRK20_EXIT_CLAIM_DOMAIN;
    for value in values {
        let (next, _, _) = hades_permutation(state, value, 2);
        state = next;
    }
    assert(
        check_ecdsa_signature(
            state,
            0x3f5c95cca3facbedfcea5994bd53cb39f2c2a5eef6d121c2c2f032c0ebcde4e,
            0xde23af5851fcec6d88ce6f0f3cf8b777ee2d231c77f79dc4d4298ef7b3724d,
            0x435792e70521a880ac71b5d4117e95a200ab8635bcca141dff026e1700b41f8,
        ),
        'claim signature',
    );
}

#[test]
fn each_statement_is_bound_to_its_single_purpose_program() {
    let exchange_address = address(0x12345);
    let (deployed, _) = declare("Exchange")
        .unwrap()
        .contract_class()
        .deploy_at(@array![ADMIN], exchange_address)
        .unwrap();
    let exchange = IExchangeDispatcher { contract_address: deployed };
    cheat_caller_address(deployed, address(ADMIN), CheatSpan::TargetCalls(1));
    exchange.set_proof_programs(address(0x111), address(0x222), address(0x333), 0x444);
    assert(exchange.transition_proof_program() == address(0x111), 'transition program');
    assert(exchange.withdrawal_proof_program() == address(0x222), 'withdrawal program');
    assert(exchange.residual_recovery_proof_program() == address(0x333), 'residual program');
    assert(
        exchange
            .transition_message_hash(
                0x555,
            ) == bound_proof_message(0x111, TRANSITION_MESSAGE_DOMAIN, deployed.into(), 0x555),
        'transition binding',
    );
    assert(
        exchange
            .withdrawal_message_hash(
                0x666,
            ) == bound_proof_message(0x222, WITHDRAWAL_MESSAGE_DOMAIN, deployed.into(), 0x666),
        'withdrawal binding',
    );
    assert(
        exchange
            .residual_recovery_message_hash(
                0x777,
            ) == bound_proof_message(
                0x333, RESIDUAL_RECOVERY_MESSAGE_DOMAIN, deployed.into(), 0x777,
            ),
        'residual binding',
    );
}

#[test]
#[should_panic(expected: 'BAD_EXIT_DELAY')]
fn withdrawal_delay_must_outlast_the_transition_close_window() {
    let exchange_address = address(0x12346);
    let (deployed, _) = declare("Exchange")
        .unwrap()
        .contract_class()
        .deploy_at(@array![ADMIN], exchange_address)
        .unwrap();
    let exchange = IExchangeDispatcher { contract_address: deployed };
    cheat_caller_address(deployed, address(ADMIN), CheatSpan::TargetCalls(1));
    exchange.set_timing(6000, 60000, 60, 1);
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
    retired_nullifiers: Span<felt252>,
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

fn read_residual_recovery(ref fixture: Fixture) -> (felt252, felt252, ResidualRecovery) {
    let commitment = fixture.next();
    let message = fixture.next();
    let length: u32 = fixture.next().try_into().unwrap();
    let mut calldata = array![];
    for _ in 0..length {
        calldata.append(fixture.next());
    }
    let mut span = calldata.span();
    let recovery: ResidualRecovery = Serde::deserialize(ref span).unwrap();
    assert(span.is_empty(), 'recovery calldata trailing');
    (commitment, message, recovery)
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
    setup_with_window(ref fixture, 1)
}

/// deploys and wires the exchange with an external window of `window` seconds.
fn setup_with_window(ref fixture: Fixture, window: u64) -> Setup {
    setup_with_timing(ref fixture, 1, window)
}

fn setup_with_timing(ref fixture: Fixture, epoch_ms: u64, window: u64) -> Setup {
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
    cheat_caller_address(exchange_address, address(ADMIN), CheatSpan::TargetCalls(12));
    exchange.set_settlement_account(address(SETTLEMENT));
    exchange
        .set_proof_programs(
            address(proof_program),
            address(proof_program),
            address(proof_program),
            VIRTUAL_PROGRAM_HASH,
        );
    exchange.set_proof_validation(PROOF_VERSION, OS_CONFIG_HASH, 450);
    exchange.set_custody(bridge_address, registry_address, address(ROUTER));
    exchange.set_reference_signer(signer);
    exchange.set_objective_numeraire(QUOTE);
    exchange.set_market_registry_hash(1, 2);
    exchange.register_pair(PAIR, BASE, QUOTE, 1, 30, 1, 0, 0, 0, 0);
    exchange.set_pair_external_support(PAIR, if window == 0 {
        0
    } else {
        1
    });
    exchange.set_protocol_fee_recipient(FEE_RECIPIENT);
    exchange.set_timing(epoch_ms, 60000, 120, window);
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

#[test]
#[should_panic(expected: 'UNALIGNED_CLOSE')]
fn a_transition_close_must_be_on_the_configured_epoch_boundary() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup_with_timing(ref fixture, 6, 0);
    let _ = read_withdrawal(ref fixture);
    let (_, message, call) = read_transition(ref fixture);
    submit(@setup, message, @call, 11);
}

#[test]
#[should_panic(expected: 'FUTURE_CLOSE')]
fn a_transition_cannot_settle_before_its_declared_close() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let _ = read_withdrawal(ref fixture);
    let (_, message, call) = read_transition(ref fixture);
    submit(@setup, message, @call, 10);
}

#[test]
fn withdrawals_remain_available_while_trading_is_paused() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let withdrawal = read_withdrawal(ref fixture);
    cheat_caller_address(
        setup.exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(1),
    );
    setup.exchange.pause();
    request(@setup, withdrawal, 11);
    cheat_block_timestamp(setup.exchange.contract_address, 131, CheatSpan::TargetCalls(1));
    setup.exchange.finalize_withdrawal(withdrawal.nullifier);
    assert(setup.exchange.nullifier_state(withdrawal.nullifier) == 3, 'exit completed');
}

#[test]
#[should_panic(expected: 'NO_PENDING_RECOVERY')]
fn a_regular_withdrawal_cannot_be_consumed_by_the_residual_finalizer() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let withdrawal = read_withdrawal(ref fixture);
    request(@setup, withdrawal, 11);
    cheat_block_timestamp(setup.exchange.contract_address, 131, CheatSpan::TargetCalls(1));
    setup.exchange.finalize_residual_recovery(withdrawal.nullifier);
}

#[test]
#[should_panic(expected: 'NO_PENDING_WITHDRAWAL')]
fn a_residual_recovery_cannot_be_consumed_by_the_regular_finalizer() {
    let mut fixture = FixtureTrait::load("exchange_residual_recovery");
    let setup = setup(ref fixture);
    let (_, transition_message, transition) = read_transition(ref fixture);
    submit(@setup, transition_message, @transition, 11);
    let (_, recovery_message, recovery) = read_residual_recovery(ref fixture);
    cheat_proof_facts(
        setup.exchange.contract_address, proof_facts(recovery_message), CheatSpan::TargetCalls(1),
    );
    cheat_block_number(setup.exchange.contract_address, 100, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(setup.exchange.contract_address, 12, CheatSpan::TargetCalls(1));
    setup.exchange.request_residual_recovery(recovery);
    cheat_block_timestamp(setup.exchange.contract_address, 132, CheatSpan::TargetCalls(1));
    setup.exchange.finalize_withdrawal(recovery.nullifier);
}

#[test]
fn a_resting_order_recovers_permissionlessly_and_only_once() {
    let mut fixture = FixtureTrait::load("exchange_residual_recovery");
    let setup = setup(ref fixture);
    let (_, transition_message, transition) = read_transition(ref fixture);
    submit(@setup, transition_message, @transition, 11);
    let (commitment, recovery_message, recovery) = read_residual_recovery(ref fixture);
    assert(
        setup.exchange.residual_recovery_message_hash(commitment) == recovery_message,
        'recovery message',
    );
    cheat_proof_facts(
        setup.exchange.contract_address, proof_facts(recovery_message), CheatSpan::TargetCalls(1),
    );
    cheat_block_number(setup.exchange.contract_address, 100, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(setup.exchange.contract_address, 12, CheatSpan::TargetCalls(1));
    setup.exchange.request_residual_recovery(recovery);
    assert(setup.exchange.nullifier_state(recovery.nullifier) == 2, 'recovery pending');
    let escrow_before = setup.bridge.escrowed_asset_amount(recovery.input_asset_id);
    let _ = read_transition(ref fixture);
    let (_, retirement_message, retirement) = read_transition(ref fixture);
    submit(@setup, retirement_message, @retirement, 133);
    assert(setup.exchange.book_root() == retirement.header.new_book_root, 'recovery retired');
    assert(setup.exchange.nullifier_state(recovery.nullifier) == 2, 'recovery still pending');
    cheat_block_timestamp(setup.exchange.contract_address, 133, CheatSpan::TargetCalls(1));
    setup.exchange.finalize_residual_recovery(recovery.nullifier);
    assert(setup.exchange.nullifier_state(recovery.nullifier) == 3, 'recovery exited');
    assert(
        setup.bridge.escrowed_asset_amount(recovery.input_asset_id) == escrow_before
            - recovery.input_amount,
        'recovery escrow released',
    );
    assert(
        setup.bridge.pending_exit_asset_amount(recovery.input_asset_id) == recovery.input_amount,
        'recovery remains a liability',
    );
}

#[test]
#[should_panic(expected: 'NULLIFIER_USED')]
fn duplicate_residual_recovery_submission_is_rejected() {
    let mut fixture = FixtureTrait::load("exchange_residual_recovery");
    let setup = setup(ref fixture);
    let (_, transition_message, transition) = read_transition(ref fixture);
    submit(@setup, transition_message, @transition, 11);
    let (_, recovery_message, recovery) = read_residual_recovery(ref fixture);
    cheat_proof_facts(
        setup.exchange.contract_address, proof_facts(recovery_message), CheatSpan::TargetCalls(1),
    );
    cheat_block_number(setup.exchange.contract_address, 100, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(setup.exchange.contract_address, 12, CheatSpan::TargetCalls(1));
    setup.exchange.request_residual_recovery(recovery);
    setup.exchange.request_residual_recovery(recovery);
}

#[test]
#[should_panic(expected: 'EXIT_COMMITMENT_USED')]
fn an_exit_commitment_is_reserved_across_recovery_and_withdrawal_paths() {
    let mut fixture = FixtureTrait::load("exchange_residual_recovery");
    let setup = setup(ref fixture);
    let (_, transition_message, transition) = read_transition(ref fixture);
    submit(@setup, transition_message, @transition, 11);
    let (_, recovery_message, recovery) = read_residual_recovery(ref fixture);
    cheat_proof_facts(
        setup.exchange.contract_address, proof_facts(recovery_message), CheatSpan::TargetCalls(1),
    );
    cheat_block_number(setup.exchange.contract_address, 100, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(setup.exchange.contract_address, 12, CheatSpan::TargetCalls(1));
    setup.exchange.request_residual_recovery(recovery);
    let _ = read_transition(ref fixture);
    let _ = read_transition(ref fixture);
    let colliding_withdrawal = read_withdrawal(ref fixture);
    request(@setup, colliding_withdrawal, 13);
}

#[test]
#[should_panic(expected: 'BAD_PROOF_MSG')]
fn a_changed_residual_recovery_fee_is_not_the_proven_recovery() {
    let mut fixture = FixtureTrait::load("exchange_residual_recovery");
    let setup = setup(ref fixture);
    let (_, transition_message, transition) = read_transition(ref fixture);
    submit(@setup, transition_message, @transition, 11);
    let (_, recovery_message, recovery) = read_residual_recovery(ref fixture);
    let recovery = ResidualRecovery { fee_amount: recovery.fee_amount + 1, ..recovery };
    cheat_proof_facts(
        setup.exchange.contract_address, proof_facts(recovery_message), CheatSpan::TargetCalls(1),
    );
    cheat_block_number(setup.exchange.contract_address, 100, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(setup.exchange.contract_address, 12, CheatSpan::TargetCalls(1));
    setup.exchange.request_residual_recovery(recovery);
}

#[test]
#[should_panic(expected: 'NO_PENDING_EXIT')]
fn a_transition_winning_the_race_voids_a_pending_residual_recovery() {
    let mut fixture = FixtureTrait::load("exchange_residual_recovery");
    let setup = setup(ref fixture);
    let (_, transition_message, transition) = read_transition(ref fixture);
    submit(@setup, transition_message, @transition, 11);
    let (_, recovery_message, recovery) = read_residual_recovery(ref fixture);
    cheat_proof_facts(
        setup.exchange.contract_address, proof_facts(recovery_message), CheatSpan::TargetCalls(1),
    );
    cheat_block_number(setup.exchange.contract_address, 100, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(setup.exchange.contract_address, 12, CheatSpan::TargetCalls(1));
    setup.exchange.request_residual_recovery(recovery);
    let (_, cancellation_message, cancellation) = read_transition(ref fixture);
    submit(@setup, cancellation_message, @cancellation, 13);
    assert(setup.exchange.nullifier_state(recovery.nullifier) == 1, 'recovery preempted');
    cheat_block_timestamp(setup.exchange.contract_address, 133, CheatSpan::TargetCalls(1));
    setup.exchange.finalize_residual_recovery(recovery.nullifier);
}

#[test]
#[should_panic(expected: 'EXIT_AFTER_CUTOFF')]
fn an_epoch_closing_after_a_residual_recovery_request_cannot_preempt_it() {
    let mut fixture = FixtureTrait::load("exchange_residual_recovery");
    let setup = setup(ref fixture);
    let (_, transition_message, transition) = read_transition(ref fixture);
    submit(@setup, transition_message, @transition, 11);
    let (_, recovery_message, recovery) = read_residual_recovery(ref fixture);
    cheat_proof_facts(
        setup.exchange.contract_address, proof_facts(recovery_message), CheatSpan::TargetCalls(1),
    );
    cheat_block_number(setup.exchange.contract_address, 100, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(setup.exchange.contract_address, 11, CheatSpan::TargetCalls(1));
    setup.exchange.request_residual_recovery(recovery);
    let (_, cancellation_message, cancellation) = read_transition(ref fixture);
    submit(@setup, cancellation_message, @cancellation, 13);
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
            *call.retired_nullifiers,
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
#[should_panic(expected: 'TOKEN_CUSTODY_LOW')]
fn an_unconsumed_pool_allowance_cannot_back_a_new_shielded_deposit() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let asset_id = BASE;
    let amount = 1_u128;
    let note_commitment = 0xc012;
    let withdraw_authority = 0xa118;
    let token = IERC20Dispatcher { contract_address: setup.base_token };

    IMockERC20Dispatcher { contract_address: setup.base_token }
        .mint(setup.bridge.contract_address, amount.into());
    cheat_caller_address(
        setup.base_token, setup.bridge.contract_address, CheatSpan::TargetCalls(1),
    );
    token.approve(setup.pool, amount.into());

    let deposit_root = output_note_leaf(note_commitment, asset_id, amount, withdraw_authority);
    cheat_caller_address(setup.bridge.contract_address, setup.pool, CheatSpan::TargetCalls(1));
    setup
        .bridge
        .privacy_invoke(
            array![0xf012].span(),
            array![deposit_root].span(),
            array![0xead].span(),
            array![note_commitment].span(),
            array![asset_id].span(),
            array![amount].span(),
            array![withdraw_authority].span(),
        );
}

fn setup_exit_claim_bridge() -> IPrivacyDepositBridgeDispatcher {
    let exchange_address = address(0x444);
    let registry_address = address(0x445);
    let pool = address(0x222);
    let token = address(0x333);
    let bridge_address = address(0x111);
    declare("MockPrivacyPool").unwrap().contract_class().deploy_at(@array![], pool).unwrap();
    declare("MockERC20").unwrap().contract_class().deploy_at(@array![], token).unwrap();
    declare("CommitmentRegistry")
        .unwrap()
        .contract_class()
        .deploy_at(@array![ADMIN], registry_address)
        .unwrap();
    declare("Exchange")
        .unwrap()
        .contract_class()
        .deploy_at(@array![ADMIN], exchange_address)
        .unwrap();
    declare("PrivacyDepositBridge")
        .unwrap()
        .contract_class()
        .deploy_at(@array![ADMIN, registry_address.into(), pool.into()], bridge_address)
        .unwrap();
    let bridge = IPrivacyDepositBridgeDispatcher { contract_address: bridge_address };
    let registry = ICommitmentRegistryDispatcher { contract_address: registry_address };
    let exchange = IExchangeDispatcher { contract_address: exchange_address };
    cheat_caller_address(registry_address, address(ADMIN), CheatSpan::TargetCalls(2));
    registry.set_privacy_deposit_bridge(bridge_address);
    registry.set_exchange(exchange_address);
    cheat_caller_address(exchange_address, address(ADMIN), CheatSpan::TargetCalls(1));
    exchange.set_custody(bridge_address, registry_address, address(0));
    cheat_caller_address(bridge_address, address(ADMIN), CheatSpan::TargetCalls(2));
    bridge.set_exchange(exchange_address);
    bridge.register_supported_asset(0x555, token);
    IMockERC20Dispatcher { contract_address: token }.mint(bridge_address, 7);
    let withdraw_authority = 0x3f5c95cca3facbedfcea5994bd53cb39f2c2a5eef6d121c2c2f032c0ebcde4e;
    let deposit_root = output_note_leaf(0xc00, 0x555, 7, withdraw_authority);
    cheat_caller_address(bridge_address, pool, CheatSpan::TargetCalls(1));
    bridge
        .privacy_invoke(
            array![0xf00].span(),
            array![deposit_root].span(),
            array![0xe00].span(),
            array![0xc00].span(),
            array![0x555].span(),
            array![7].span(),
            array![withdraw_authority].span(),
        );
    cheat_caller_address(bridge_address, exchange_address, CheatSpan::TargetCalls(1));
    bridge.stage_verified_note_strk20_exit(0x555, 7, 0x51a9, withdraw_authority, 0x666);
    bridge
}

#[test]
fn a_strk20_exit_claim_is_bound_to_the_transaction_account() {
    let bridge = setup_exit_claim_bridge();
    cheat_caller_address(bridge.contract_address, address(0x777), CheatSpan::TargetCalls(1));
    cheat_chain_id(bridge.contract_address, 0x123, CheatSpan::TargetCalls(1));
    bridge
        .authorize_strk20_exit_claim(
            0x666,
            0x999,
            0x888,
            0xde23af5851fcec6d88ce6f0f3cf8b777ee2d231c77f79dc4d4298ef7b3724d,
            0x435792e70521a880ac71b5d4117e95a200ab8635bcca141dff026e1700b41f8,
        );
    cheat_caller_address(bridge.contract_address, address(0x222), CheatSpan::TargetCalls(1));
    cheat_account_contract_address(
        bridge.contract_address, address(0x777), CheatSpan::TargetCalls(1),
    );
    cheat_chain_id(bridge.contract_address, 0x123, CheatSpan::TargetCalls(1));
    bridge
        .privacy_invoke(
            array![].span(),
            array![0x666, 0x999, 0x888].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
        );
    assert(bridge.strk20_exit_claimed_open_note_id(0x666) == 0x999, 'claim recorded');
}

#[test]
#[should_panic(expected: 'BAD_EXIT_AUTH')]
fn another_transaction_account_cannot_take_a_strk20_exit_claim() {
    let bridge = setup_exit_claim_bridge();
    cheat_caller_address(bridge.contract_address, address(0x777), CheatSpan::TargetCalls(1));
    cheat_chain_id(bridge.contract_address, 0x123, CheatSpan::TargetCalls(1));
    bridge
        .authorize_strk20_exit_claim(
            0x666,
            0x999,
            0x888,
            0xde23af5851fcec6d88ce6f0f3cf8b777ee2d231c77f79dc4d4298ef7b3724d,
            0x435792e70521a880ac71b5d4117e95a200ab8635bcca141dff026e1700b41f8,
        );
    cheat_caller_address(bridge.contract_address, address(0x222), CheatSpan::TargetCalls(1));
    cheat_account_contract_address(
        bridge.contract_address, address(0x778), CheatSpan::TargetCalls(1),
    );
    cheat_chain_id(bridge.contract_address, 0x123, CheatSpan::TargetCalls(1));
    bridge
        .privacy_invoke(
            array![].span(),
            array![0x666, 0x999, 0x888].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
        );
}

#[test]
#[should_panic(expected: 'BAD_EXIT_AUTH')]
fn a_claim_cannot_replace_the_authorized_private_output() {
    let bridge = setup_exit_claim_bridge();
    cheat_caller_address(bridge.contract_address, address(0x777), CheatSpan::TargetCalls(1));
    cheat_chain_id(bridge.contract_address, 0x123, CheatSpan::TargetCalls(1));
    bridge
        .authorize_strk20_exit_claim(
            0x666,
            0x999,
            0x888,
            0xde23af5851fcec6d88ce6f0f3cf8b777ee2d231c77f79dc4d4298ef7b3724d,
            0x435792e70521a880ac71b5d4117e95a200ab8635bcca141dff026e1700b41f8,
        );
    cheat_caller_address(bridge.contract_address, address(0x222), CheatSpan::TargetCalls(1));
    cheat_account_contract_address(
        bridge.contract_address, address(0x777), CheatSpan::TargetCalls(1),
    );
    bridge
        .privacy_invoke(
            array![].span(),
            array![0x666, 0x998, 0x888].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
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
    setup.exchange.register_pair(0x999, BASE, QUOTE, 1, 30, 1, 0, 0, 0, 0);
}

#[test]
#[should_panic(expected: 'CONFIG_LOCKED')]
fn a_locked_exchange_cannot_change_the_registry_identity() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    cheat_caller_address(
        setup.exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(1),
    );
    setup.exchange.set_market_registry_hash(3, 4);
}

#[test]
fn configured_markets_and_assets_are_enumerable_without_hidden_extras() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    assert(setup.exchange.pair_count() == 1, 'pair count');
    assert(setup.exchange.pair_id_at(0) == PAIR, 'pair id');
    assert(setup.exchange.objective_numeraire() == QUOTE, 'numeraire');
    assert(setup.bridge.supported_asset_count() == 2, 'asset count');
    assert(setup.bridge.supported_asset_id_at(0) == BASE, 'base asset');
    assert(setup.bridge.supported_asset_id_at(1) == QUOTE, 'quote asset');
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
fn a_locked_exchange_rotates_its_settlement_account_only_after_pause_and_timelock() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let exchange = setup.exchange;
    let replacement = address(0x987655);
    cheat_caller_address(exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(2));
    exchange.propose_settlement_account(replacement);
    exchange.pause();
    cheat_block_timestamp(exchange.contract_address, 86400, CheatSpan::TargetCalls(1));
    cheat_caller_address(exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(1));
    exchange.execute_settlement_account();
    assert(exchange.settlement_account() == replacement, 'new settlement');
}

#[test]
#[should_panic(expected: 'SETTLEMENT_TIMELOCK')]
fn a_locked_exchange_rejects_an_early_settlement_rotation() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let exchange = setup.exchange;
    cheat_caller_address(exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(3));
    exchange.propose_settlement_account(address(0x987655));
    exchange.pause();
    exchange.execute_settlement_account();
}

#[test]
#[should_panic(expected: 'NOT_PAUSED')]
fn a_locked_exchange_requires_pause_for_a_settlement_rotation() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let exchange = setup.exchange;
    cheat_caller_address(exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(1));
    exchange.propose_settlement_account(address(0x987655));
    cheat_block_timestamp(exchange.contract_address, 86400, CheatSpan::TargetCalls(1));
    cheat_caller_address(exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(1));
    exchange.execute_settlement_account();
}

#[test]
#[should_panic(expected: 'CONFIG_LOCKED')]
fn a_locked_exchange_cannot_change_its_settlement_account_immediately() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    cheat_caller_address(
        setup.exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(1),
    );
    setup.exchange.set_settlement_account(address(0x987655));
}

#[test]
fn an_admin_transfer_waits_for_its_timelock() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let exchange = setup.exchange;
    let replacement = address(0x987656);
    cheat_caller_address(exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(1));
    exchange.propose_admin(replacement);
    cheat_block_timestamp(exchange.contract_address, 86400, CheatSpan::TargetCalls(1));
    cheat_caller_address(exchange.contract_address, replacement, CheatSpan::TargetCalls(1));
    exchange.accept_admin();
    assert(exchange.admin_address() == replacement, 'new admin');
}

#[test]
#[should_panic(expected: 'ADMIN_TIMELOCK')]
fn an_admin_transfer_cannot_be_accepted_early() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let exchange = setup.exchange;
    let replacement = address(0x987656);
    cheat_caller_address(exchange.contract_address, address(ADMIN), CheatSpan::TargetCalls(1));
    exchange.propose_admin(replacement);
    cheat_caller_address(exchange.contract_address, replacement, CheatSpan::TargetCalls(1));
    exchange.accept_admin();
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
    assert(exchange.note_batch_count() == 3, 'note batches');
    assert(exchange.note_batch_root(2) == call.header.output_root, 'transition output root');
    let roots = exchange.note_batch_roots(0, 2);
    assert(roots.len() == 3, 'note root range');
    assert(*roots.at(2) == call.header.output_root, 'range output root');
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
#[should_panic(expected: 'EXIT_COMMITMENT_USED')]
fn an_exit_commitment_cannot_be_reserved_by_two_withdrawals() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let first = read_withdrawal(ref fixture);
    let (_, _, _) = read_transition(ref fixture);
    let _ = read_withdrawal(ref fixture);
    let duplicate = read_withdrawal(ref fixture);
    request(@setup, first, 11);
    request(@setup, duplicate, 12);
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
#[should_panic(expected: 'EXIT_AFTER_CUTOFF')]
fn an_epoch_closing_after_a_note_withdrawal_request_cannot_admit_it() {
    let mut fixture = FixtureTrait::load("exchange_cross");
    let setup = setup(ref fixture);
    let raced = read_withdrawal(ref fixture);
    let (_, message, call) = read_transition(ref fixture);
    request(@setup, raced, 5);
    submit(@setup, message, @call, 11);
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
    let mut changed = array![
        OutputRecord {
            leaf: first.leaf + 1,
            enc: first.enc,
            enc_remaining: first.enc_remaining,
            enc_reserved: first.enc_reserved,
            enc_reserved_offset: first.enc_reserved_offset,
        },
    ];
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
    submit(@setup, apply_message, @apply, 13);
    assert(exchange.capacity(1, PAIR, true).status == 3, 'outcome applied');
    assert(exchange.transition_seq() == 2, 'seq');
}

#[test]
#[should_panic(expected: 'EXTERNAL_DISABLED')]
fn an_external_capacity_needs_a_window_and_settlement_support() {
    let mut fixture = FixtureTrait::load("exchange_external");
    let setup = setup_with_timing(ref fixture, 1, 0);
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);
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
    submit(@setup, apply_message, @apply, 13);
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
    for _ in 0..21_u32 {
        values.append(fixture.next());
    }
    let mut span = values.span();
    Serde::deserialize(ref span).unwrap()
}

#[test]
fn synthetic_pair_configuration_is_explicit_and_queryable() {
    let (exchange_address, _) = declare("Exchange")
        .unwrap()
        .contract_class()
        .deploy_at(@array![ADMIN], address(0x5151))
        .unwrap();
    let exchange = IExchangeDispatcher { contract_address: exchange_address };
    cheat_caller_address(exchange_address, address(ADMIN), CheatSpan::TargetCalls(4));
    exchange.set_objective_numeraire(QUOTE);
    exchange.register_pair(0x901, BASE, QUOTE, 1, 2, 1, 0, 0, 0, 0);
    exchange.register_pair(0x902, 0xbeef, QUOTE, 1, 2, 1, 0, 0, 0, 0);
    exchange.register_pair(0x903, BASE, 0xbeef, 1, 2, 1, 1, 0x901, 0x902, 1500);
    let pair = exchange.pair_config(0x903);
    assert(pair.base_asset_id == BASE && pair.quote_asset_id == 0xbeef, 'BAD_PAIR');
    assert(pair.price_base_scale == 1, 'BAD_SCALE');
    assert(pair.reference_methodology == 1, 'BAD_REF_METHOD');
    assert(
        pair.derivation_base_market_id == 0x901
            && pair.derivation_quote_market_id == 0x902
            && pair.max_leg_skew_ms == 1500,
        'BAD_SYNTH_CONFIG',
    );
}

#[test]
fn a_synthetic_pair_can_enable_residual_external_matching() {
    let (exchange_address, _) = declare("Exchange")
        .unwrap()
        .contract_class()
        .deploy_at(@array![ADMIN], address(0x5152))
        .unwrap();
    let exchange = IExchangeDispatcher { contract_address: exchange_address };
    cheat_caller_address(exchange_address, address(ADMIN), CheatSpan::TargetCalls(5));
    exchange.set_objective_numeraire(QUOTE);
    exchange.register_pair(0x901, BASE, QUOTE, 1, 2, 1, 0, 0, 0, 0);
    exchange.register_pair(0x902, 0xbeef, QUOTE, 1, 2, 1, 0, 0, 0, 0);
    exchange.register_pair(0x903, BASE, 0xbeef, 1, 2, 1, 1, 0x901, 0x902, 1500);
    exchange.set_pair_external_support(0x903, 1);
    assert(exchange.pair_config(0x903).external_settlement_support_quote == 1, 'BAD_SUPPORT');
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
    submit(@setup, apply_message, @apply, 13);
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
    submit(@setup, apply_message, @apply, 13);
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
fn external_recovery_stages_both_the_user_output_and_the_protocol_fee() {
    let mut fixture = FixtureTrait::load("exchange_external_full");
    let setup = setup_with_window(ref fixture, 60);
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let _ = read_transition(ref fixture);
    let m1 = read_attestation(ref fixture);
    let (_, recovery_message, recovery) = read_residual_recovery(ref fixture);
    let (_, retire_message, retire) = read_transition(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);
    fill(@setup, 10, m1);

    cheat_proof_facts(
        setup.exchange.contract_address, proof_facts(recovery_message), CheatSpan::TargetCalls(1),
    );
    cheat_block_number(setup.exchange.contract_address, 100, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(setup.exchange.contract_address, 12, CheatSpan::TargetCalls(1));
    setup.exchange.request_residual_recovery(recovery);
    let pending = setup.exchange.pending_residual_exit(recovery.nullifier);
    assert(recovery.output_amount == 1006 && recovery.fee_amount == 4, 'recovery split');
    assert(pending.fee_amount == recovery.fee_amount, 'fee liability recorded');

    submit(@setup, retire_message, @retire, 133);
    assert(setup.exchange.capacity(1, PAIR, true).status == 3, 'outcome retired');
    assert(setup.exchange.nullifier_state(recovery.nullifier) == 2, 'recovery still pending');
    cheat_block_timestamp(setup.exchange.contract_address, 133, CheatSpan::TargetCalls(1));
    setup.exchange.finalize_residual_recovery(recovery.nullifier);
    assert(setup.bridge.escrowed_asset_amount(QUOTE) == 0, 'quote fully allocated');
    assert(setup.bridge.pending_exit_asset_amount(QUOTE) == 1010, 'no duplicate allocation');
}

#[test]
#[should_panic(expected: 'DUPLICATE_RECOVERY_EXIT')]
fn residual_recovery_exit_legs_cannot_share_an_exit_commitment() {
    let mut fixture = FixtureTrait::load("exchange_external_full");
    let setup = setup_with_window(ref fixture, 60);
    let (_, reserve_message, reserve) = read_transition(ref fixture);
    let _ = read_transition(ref fixture);
    let m1 = read_attestation(ref fixture);
    let _ = read_residual_recovery(ref fixture);
    let _ = read_transition(ref fixture);
    let (_, recovery_message, recovery) = read_residual_recovery(ref fixture);
    submit(@setup, reserve_message, @reserve, 11);
    fill(@setup, 10, m1);
    cheat_proof_facts(
        setup.exchange.contract_address, proof_facts(recovery_message), CheatSpan::TargetCalls(1),
    );
    cheat_block_number(setup.exchange.contract_address, 100, CheatSpan::TargetCalls(1));
    cheat_block_timestamp(setup.exchange.contract_address, 12, CheatSpan::TargetCalls(1));
    setup.exchange.request_residual_recovery(recovery);
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
