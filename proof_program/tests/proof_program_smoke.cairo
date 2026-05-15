use core::poseidon::{hades_permutation, poseidon_hash_span};
use core::traits::TryInto;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::{ContractAddress, SyscallResultTrait};
use zylith_proof_program::{IAuctionProofProgramDispatcher, IAuctionProofProgramDispatcherTrait};

const SETTLEMENT_MESSAGE_DOMAIN: felt252 = 'zylith_settle_v1';
const SETTLEMENT_PROOF_MESSAGE_TO: felt252 = 0;
const NATIVE_SETTLEMENT_DOMAIN: felt252 =
    0x326c16c927e3e9e1e2cb23ce296a3e7f3d21e798e34d6cac00f9b1241fdfc3a;

fn as_address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn poseidon_hash2(x: felt252, y: felt252) -> felt252 {
    let (result, _, _) = hades_permutation(x, y, 2);
    result
}

fn deploy_auction_proof_program(statement_program: ContractAddress) -> ContractAddress {
    let class = declare("AuctionProofProgram").unwrap().contract_class();
    let calldata = array![
        statement_program.into(), statement_program.into(), statement_program.into(),
    ];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn expected_settlement_proof_message_hash(
    proof_program_address: ContractAddress,
    auction_verifier: ContractAddress,
    transcript_commitment: felt252,
) -> felt252 {
    let mut statement_hash = poseidon_hash2(NATIVE_SETTLEMENT_DOMAIN, auction_verifier.into());
    statement_hash = poseidon_hash2(statement_hash, transcript_commitment);

    let payload = array![SETTLEMENT_MESSAGE_DOMAIN, statement_hash];
    let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
    payload.serialize(ref l1_message_data);
    poseidon_hash_span(l1_message_data.span())
}

#[test]
fn settlement_message_hash_matches_native_payload_binding() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let transcript_commitment = 0x789;

    let actual = proof_program
        .settlement_proof_message_hash(auction_verifier, transcript_commitment);
    let expected = expected_settlement_proof_message_hash(
        proof_program_address, auction_verifier, transcript_commitment,
    );
    assert(actual == expected, 'BAD_MESSAGE_HASH');
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_statement_program() {
    deploy_auction_proof_program(as_address(0));
}

#[test]
#[should_panic]
fn settlement_message_hash_rejects_zero_verifier() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };

    proof_program.settlement_proof_message_hash(as_address(0), 0x789);
}
