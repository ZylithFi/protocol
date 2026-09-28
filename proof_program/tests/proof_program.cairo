//! the proof program runs the rust-built statements and emits exactly the message the exchange
//! contract expects in the proof facts.

use core::poseidon::{hades_permutation, poseidon_hash_span};
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use zylith_proof_program::{IExchangeProofProgramDispatcher, IExchangeProofProgramDispatcherTrait};

const TRANSITION_MESSAGE_DOMAIN: felt252 = 'zylith_transition_msg_v1';
const WITHDRAWAL_MESSAGE_DOMAIN: felt252 = 'zylith_withdraw_msg_v1';

fn poseidon2(x: felt252, y: felt252) -> felt252 {
    let (result, _, _) = hades_permutation(x, y, 2);
    result
}

fn deploy() -> IExchangeProofProgramDispatcher {
    let (address, _) = declare("ExchangeProofProgram")
        .unwrap()
        .contract_class()
        .deploy(@array![])
        .unwrap();
    IExchangeProofProgramDispatcher { contract_address: address }
}

/// `(exchange, commitment, witness)` from a fixture.
fn fixture(name: ByteArray) -> (ContractAddress, felt252, Span<felt252>) {
    let mut data = read_txt(@FileTrait::new(format!("tests/fixtures/{name}.txt"))).span();
    let exchange: ContractAddress = (*data.pop_front().unwrap()).try_into().unwrap();
    let commitment = *data.pop_front().unwrap();
    let length: u32 = (*data.pop_front().unwrap()).try_into().unwrap();
    assert(data.len() == length, 'fixture length');
    (exchange, commitment, data)
}

fn expected_message(
    program: ContractAddress, domain: felt252, exchange: ContractAddress, commitment: felt252,
) -> felt252 {
    let statement = poseidon2(poseidon2(domain, exchange.into()), commitment);
    poseidon_hash_span(array![program.into(), 0, 2, domain, statement].span())
}

#[test]
fn a_transition_emits_its_bound_message() {
    let program = deploy();
    let (exchange, commitment, witness) = fixture("transition_cross");
    let message = program.compile_transition_proof(exchange, witness);
    assert(
        message == expected_message(
            program.contract_address, TRANSITION_MESSAGE_DOMAIN, exchange, commitment,
        ),
        'transition message',
    );
}

#[test]
fn a_withdrawal_emits_its_bound_message() {
    let program = deploy();
    let (exchange, commitment, witness) = fixture("withdrawal_output");
    let message = program.compile_withdrawal_proof(exchange, witness);
    assert(
        message == expected_message(
            program.contract_address, WITHDRAWAL_MESSAGE_DOMAIN, exchange, commitment,
        ),
        'withdrawal message',
    );
}

fn with_felt_changed(witness: Span<felt252>, target: u32) -> Span<felt252> {
    let mut changed = array![];
    let mut index: u32 = 0;
    for value in witness {
        changed.append(if index == target {
            *value + 1
        } else {
            *value
        });
        index += 1;
    }
    changed.span()
}

#[test]
fn a_changed_padding_is_a_different_transition() {
    let program = deploy();
    let (exchange, commitment, witness) = fixture("transition_cross");
    let message = program
        .compile_transition_proof(exchange, with_felt_changed(witness, witness.len() - 1));
    assert(
        message != expected_message(
            program.contract_address, TRANSITION_MESSAGE_DOMAIN, exchange, commitment,
        ),
        'padding is committed',
    );
}

#[test]
#[should_panic]
fn a_malformed_witness_is_rejected() {
    let program = deploy();
    let (exchange, _, witness) = fixture("transition_cross");
    program.compile_transition_proof(exchange, with_felt_changed(witness, 0));
}
