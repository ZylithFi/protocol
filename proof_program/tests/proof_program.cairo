//! the proof program runs the rust-built statements and emits exactly the message the exchange
//! contract expects in the proof facts.

use core::poseidon::{hades_permutation, poseidon_hash_span};
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use starknet::account::Call;
use zylith_proof_program::{
    IProofAccountDispatcher, IProofAccountDispatcherTrait, IResidualRecoveryProofProgramDispatcher,
    IResidualRecoveryProofProgramDispatcherTrait, ITransitionProofProgramDispatcher,
    ITransitionProofProgramDispatcherTrait, IWithdrawalProofProgramDispatcher,
    IWithdrawalProofProgramDispatcherTrait,
};

const TRANSITION_MESSAGE_DOMAIN: felt252 = 'zylith_transition_msg_v1';
const WITHDRAWAL_MESSAGE_DOMAIN: felt252 = 'zylith_withdraw_msg_v1';
const RESIDUAL_RECOVERY_MESSAGE_DOMAIN: felt252 = 'zylith_res_recover_msg_v1';

#[starknet::interface]
trait IProofAccountTest<TContractState> {
    fn __execute__(ref self: TContractState, calls: Array<Call>) -> Array<Span<felt252>>;
}

fn poseidon2(x: felt252, y: felt252) -> felt252 {
    let (result, _, _) = hades_permutation(x, y, 2);
    result
}

fn deploy_transition() -> ITransitionProofProgramDispatcher {
    let (address, _) = declare("TransitionProofProgram")
        .unwrap()
        .contract_class()
        .deploy(@array![])
        .unwrap();
    ITransitionProofProgramDispatcher { contract_address: address }
}

fn deploy_withdrawal() -> IWithdrawalProofProgramDispatcher {
    let (address, _) = declare("WithdrawalProofProgram")
        .unwrap()
        .contract_class()
        .deploy(@array![])
        .unwrap();
    IWithdrawalProofProgramDispatcher { contract_address: address }
}

fn deploy_residual_recovery() -> IResidualRecoveryProofProgramDispatcher {
    let (address, _) = declare("ResidualRecoveryProofProgram")
        .unwrap()
        .contract_class()
        .deploy(@array![])
        .unwrap();
    IResidualRecoveryProofProgramDispatcher { contract_address: address }
}

fn deploy_proof_account() -> IProofAccountTestDispatcher {
    let transition = deploy_transition().contract_address;
    let withdrawal = deploy_withdrawal().contract_address;
    let residual_recovery = deploy_residual_recovery().contract_address;
    let (address, _) = declare("ProofAccount")
        .unwrap()
        .contract_class()
        .deploy(@array![0x123, transition.into(), withdrawal.into(), residual_recovery.into()])
        .unwrap();
    IProofAccountTestDispatcher { contract_address: address }
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
    let program = deploy_transition();
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
    let program = deploy_withdrawal();
    let (exchange, commitment, witness) = fixture("withdrawal_output");
    let message = program.compile_withdrawal_proof(exchange, witness);
    assert(
        message == expected_message(
            program.contract_address, WITHDRAWAL_MESSAGE_DOMAIN, exchange, commitment,
        ),
        'withdrawal message',
    );
}

#[test]
fn a_residual_recovery_emits_its_bound_message() {
    let program = deploy_residual_recovery();
    let (exchange, commitment, witness) = fixture("residual_recovery");
    let message = program.compile_residual_recovery_proof(exchange, witness);
    assert(
        message == expected_message(
            program.contract_address, RESIDUAL_RECOVERY_MESSAGE_DOMAIN, exchange, commitment,
        ),
        'recovery message',
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
#[should_panic]
fn attacker_chosen_padding_is_rejected() {
    let program = deploy_transition();
    let (exchange, _, witness) = fixture("transition_cross");
    // padding is no longer accepted as witness input; an appended attacker value is trailing data.
    let mut changed = array![];
    for value in witness {
        changed.append(*value);
    }
    changed.append(0x1234);
    program.compile_transition_proof(exchange, changed.span());
}

#[test]
#[should_panic]
fn a_malformed_witness_is_rejected() {
    let program = deploy_transition();
    let (exchange, _, witness) = fixture("transition_cross");
    program.compile_transition_proof(exchange, with_felt_changed(witness, 0));
}

#[test]
#[should_panic]
fn proof_account_rejects_an_unapproved_target() {
    let account = deploy_proof_account();
    account
        .__execute__(
            array![
                Call {
                    to: 0x456.try_into().unwrap(),
                    selector: selector!("compile_transition_proof"),
                    calldata: array![].span(),
                },
            ],
        );
}

#[test]
#[should_panic]
fn proof_account_rejects_an_unapproved_selector() {
    let transition = deploy_transition().contract_address;
    let withdrawal = deploy_withdrawal().contract_address;
    let residual_recovery = deploy_residual_recovery().contract_address;
    let (address, _) = declare("ProofAccount")
        .unwrap()
        .contract_class()
        .deploy(@array![0x123, transition.into(), withdrawal.into(), residual_recovery.into()])
        .unwrap();
    IProofAccountTestDispatcher { contract_address: address }
        .__execute__(
            array![
                Call {
                    to: transition, selector: selector!("set_program"), calldata: array![].span(),
                },
            ],
        );
}

#[test]
#[should_panic]
fn proof_account_rejects_a_batch() {
    let account = deploy_proof_account();
    account
        .__execute__(
            array![
                Call {
                    to: 0x456.try_into().unwrap(),
                    selector: selector!("compile_transition_proof"),
                    calldata: array![].span(),
                },
                Call {
                    to: 0x789.try_into().unwrap(),
                    selector: selector!("compile_withdrawal_proof"),
                    calldata: array![].span(),
                },
            ],
        );
}

#[test]
fn proof_account_pins_its_key_and_all_three_programs() {
    let transition = deploy_transition().contract_address;
    let withdrawal = deploy_withdrawal().contract_address;
    let residual_recovery = deploy_residual_recovery().contract_address;
    let (address, _) = declare("ProofAccount")
        .unwrap()
        .contract_class()
        .deploy(@array![0x123, transition.into(), withdrawal.into(), residual_recovery.into()])
        .unwrap();
    let account = IProofAccountDispatcher { contract_address: address };
    assert(account.public_key() == 0x123, 'wrong public key');
    assert(account.transition_program() == transition, 'wrong transition program');
    assert(account.withdrawal_program() == withdrawal, 'wrong withdrawal program');
    assert(account.residual_recovery_program() == residual_recovery, 'wrong residual program');
}
