//! the proof program runs the rust-built statements and emits exactly the message the exchange
//! contract expects in the proof facts.

use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, MessageToL1, MessageToL1SpyAssertionsTrait,
    cheat_caller_address, declare, spy_messages_to_l1,
};
use starknet::account::Call;
use zylith_exchange_statement::exchange::common::{
    nullifier_padding_value, order_output_blindings, order_output_blindings_head,
    output_aux_blindings, output_padding_record,
};
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

/// `(commitment, witness)` from a fixture.
fn fixture(name: ByteArray) -> (felt252, Span<felt252>) {
    let mut data = read_txt(@FileTrait::new(format!("tests/fixtures/{name}.txt"))).span();
    let commitment = *data.pop_front().unwrap();
    let length: u32 = (*data.pop_front().unwrap()).try_into().unwrap();
    assert(data.len() == length, 'fixture length');
    (commitment, data)
}

#[test]
#[should_panic(expected: ('EX_BATCH_ORDER',))]
fn full_path_transition_witness_is_not_reinterpreted_as_a_frontier() {
    let (_, witness) = fixture("transition_full_paths");
    deploy_transition().compile_transition_proof(witness);
}

#[test]
fn prg_vectors_are_frozen_across_rust_and_cairo() {
    let seed = 0x5a17;
    assert(
        output_padding_record(
            seed, 7,
        ) == (
            0x38d63a22d32a333bd5f69bc2736d98a5543406ac7471e7c7330cab014ab8534,
            0x269836ee9da9baee712ff61a48ff880f00fa607a4ecb646b358d5b85815a7d5,
            0x5cd8336af3c364e3fc6bb5359d4d2bbf128f38649889713b0d9187d896bf1c9,
            0x4a30e81307e5f8f2c9540cfe1a8a349621bc4221dbe7104277b27a1e7cf8962,
            0x7472c276275ac5253e6d6e6365a8c64ab14cb5b6d95b62f6c6b70b3c511fbb6,
        ),
        'padding prg drift',
    );
    assert(
        output_aux_blindings(
            seed,
        ) == (
            0x22ee2763316052c532ad3dab4020166d638d3000678b1fe5f4fe808677c12dd,
            0x1b2919e1441904ee00dc376333786cf783efa67e47945499301db3be4a43f08,
            0x43cf5f4ee18207f9b08c7fdbe5bd6550d7af0662e90c71d8a1e4659abcd094d,
        ),
        'aux prg drift',
    );
    assert(
        order_output_blindings(
            seed, 7,
        ) == (
            0x38111f0c2200112b0c987deca5a2b2e07810ab2b2e0aa9b79e844796ce4adc,
            0x1604f6032d9c5697bc35f6e6e259b1c830c3c69a7fa95ce068c9c8d95db700e,
            0x479fd5fd0c3cef943888ddee24f45f507a70c0f6c1572868117d35d0c4251f6,
        ),
        'order prg drift',
    );
    assert(
        order_output_blindings_head(
            seed, 7,
        ) == (
            0x38111f0c2200112b0c987deca5a2b2e07810ab2b2e0aa9b79e844796ce4adc,
            0x1604f6032d9c5697bc35f6e6e259b1c830c3c69a7fa95ce068c9c8d95db700e,
        ),
        'order prg head drift',
    );
    assert(
        nullifier_padding_value(
            seed, 7,
        ) == 0x2fd5b28dd91b254115daaa068bf0fb2aa8d6e3618aeec770fa495756dec85ba,
        'nullifier prg drift',
    );
}

#[test]
fn a_transition_returns_its_bound_statement() {
    let program = deploy_transition();
    let (commitment, witness) = fixture("transition_cross");
    let mut messages = spy_messages_to_l1();
    program.compile_transition_proof(witness);
    messages
        .assert_sent(
            @array![
                (
                    program.contract_address,
                    MessageToL1 {
                        to_address: 0.try_into().unwrap(),
                        payload: array![TRANSITION_MESSAGE_DOMAIN, commitment],
                    },
                ),
            ],
        );
}

#[test]
#[should_panic(expected: ('EX_BATCH_ORDER',))]
fn unpacked_frontier_witness_is_not_reinterpreted_as_a_packed_note() {
    let program = deploy_transition();
    let (_, witness) = fixture("transition_frontier_unpacked");
    program.compile_transition_proof(witness);
}

#[test]
#[should_panic(expected: ('EX_TYPE',))]
fn legacy_transition_witnesses_are_not_reinterpreted() {
    let program = deploy_transition();
    let (_, mut witness) = fixture("transition_cross");
    witness.pop_front().unwrap();
    let mut legacy = array![14];
    legacy.append_span(witness);
    program.compile_transition_proof(legacy.span());
}

#[test]
fn a_withdrawal_returns_its_bound_statement() {
    let program = deploy_withdrawal();
    let (commitment, witness) = fixture("withdrawal_output");
    let mut messages = spy_messages_to_l1();
    program.compile_withdrawal_proof(witness);
    messages
        .assert_sent(
            @array![
                (
                    program.contract_address,
                    MessageToL1 {
                        to_address: 0.try_into().unwrap(),
                        payload: array![WITHDRAWAL_MESSAGE_DOMAIN, commitment],
                    },
                ),
            ],
        );
}

#[test]
fn a_residual_recovery_returns_its_bound_statement() {
    let program = deploy_residual_recovery();
    let (commitment, witness) = fixture("residual_recovery");
    let mut messages = spy_messages_to_l1();
    program.compile_residual_recovery_proof(witness);
    messages
        .assert_sent(
            @array![
                (
                    program.contract_address,
                    MessageToL1 {
                        to_address: 0.try_into().unwrap(),
                        payload: array![RESIDUAL_RECOVERY_MESSAGE_DOMAIN, commitment],
                    },
                ),
            ],
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

fn with_legacy_direct_market_zeroes(witness: Span<felt252>) -> Span<felt252> {
    let mut legacy = array![];
    let mut index: u32 = 0;
    for value in witness {
        // The compact direct market begins at index 19 in this fixture. After methodology (28),
        // current witnesses contain only base bid/ask (29/30); the five fixed zero fields from
        // the retired layout must not be accepted as an alternate encoding.
        if index == 29 {
            legacy.append(0);
            legacy.append(0);
        }
        legacy.append(*value);
        if index == 30 {
            legacy.append(0);
            legacy.append(0);
            legacy.append(0);
        }
        index += 1;
    }
    legacy.span()
}

#[test]
#[should_panic(expected: 'EX_DIRECT_REF')]
fn the_retired_direct_market_witness_shape_is_rejected() {
    let program = deploy_transition();
    let (_, witness) = fixture("transition_cross");
    program.compile_transition_proof(with_legacy_direct_market_zeroes(witness));
}

#[test]
#[should_panic]
fn attacker_chosen_padding_is_rejected() {
    let program = deploy_transition();
    let (_, witness) = fixture("transition_cross");
    // padding is no longer accepted as witness input; an appended attacker value is trailing data.
    let mut changed = array![];
    for value in witness {
        changed.append(*value);
    }
    changed.append(0x1234);
    program.compile_transition_proof(changed.span());
}

#[test]
#[should_panic]
fn a_malformed_witness_is_rejected() {
    let program = deploy_transition();
    let (_, witness) = fixture("transition_cross");
    program.compile_transition_proof(with_felt_changed(witness, 0));
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

#[test]
fn proof_account_executes_the_pinned_withdrawal_program_without_return_data() {
    let withdrawal = deploy_withdrawal();
    let (address, _) = declare("ProofAccount")
        .unwrap()
        .contract_class()
        .deploy(@array![0x123, 0x111, withdrawal.contract_address.into(), 0x222])
        .unwrap();
    let account = IProofAccountTestDispatcher { contract_address: address };
    let (commitment, witness) = fixture("withdrawal_output");
    let mut calldata = array![witness.len().into()];
    for value in witness {
        calldata.append(*value);
    }
    let mut messages = spy_messages_to_l1();
    cheat_caller_address(address, 0.try_into().unwrap(), CheatSpan::TargetCalls(1));
    let results = account
        .__execute__(
            array![
                Call {
                    to: withdrawal.contract_address,
                    selector: selector!("compile_withdrawal_proof"),
                    calldata: calldata.span(),
                },
            ],
        );
    assert(results.is_empty(), 'no account retdata');
    messages
        .assert_sent(
            @array![
                (
                    withdrawal.contract_address,
                    MessageToL1 {
                        to_address: 0.try_into().unwrap(),
                        payload: array![WITHDRAWAL_MESSAGE_DOMAIN, commitment],
                    },
                ),
            ],
        );
}
