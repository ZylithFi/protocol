use core::poseidon::{hades_permutation, poseidon_hash_span};
use core::traits::TryInto;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::{ContractAddress, SyscallResultTrait};
use zylith_proof_program::{IAuctionProofProgramDispatcher, IAuctionProofProgramDispatcherTrait};

const SETTLEMENT_MESSAGE_DOMAIN: felt252 = 'zylith_settle_v1';
const NULLIFIER_MESSAGE_DOMAIN: felt252 = 'zylith_null_v1';
const RENEWAL_MESSAGE_DOMAIN: felt252 = 'zylith_renew_v1';
const NOTE_CONSOLIDATION_MESSAGE_DOMAIN: felt252 = 'zylith_consol_v1';
const WITHDRAWAL_MESSAGE_DOMAIN: felt252 = 'zylith_withdraw_v1';
const SETTLEMENT_PROOF_MESSAGE_TO: felt252 = 0;
const AGGREGATE_RETURN_DOMAIN: felt252 = 'zylith_agg_v1';
const NATIVE_SETTLEMENT_DOMAIN: felt252 =
    0x326c16c927e3e9e1e2cb23ce296a3e7f3d21e798e34d6cac00f9b1241fdfc3a;
const WITHDRAWAL_MESSAGE_DOMAIN_NATIVE: felt252 = 'zylith_withdraw_v1';

fn as_address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn poseidon_hash2(x: felt252, y: felt252) -> felt252 {
    let (result, _, _) = hades_permutation(x, y, 2);
    result
}

fn deploy_auction_proof_program(statement_program: ContractAddress) -> ContractAddress {
    deploy_auction_proof_program_with(
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
    )
}

fn deploy_mock_statement_programs() -> (
    ContractAddress, ContractAddress, ContractAddress, ContractAddress, ContractAddress,
) {
    let settlement = declare("MockSettlementStatementProgram").unwrap().contract_class();
    let nullifier = declare("MockNullifierStatementProgram").unwrap().contract_class();
    let renewal = declare("MockRenewalStatementProgram").unwrap().contract_class();
    let consolidation = declare("MockNoteConsolidationStatementProgram").unwrap().contract_class();
    let withdrawal = declare("MockWithdrawalStatementProgram").unwrap().contract_class();
    let calldata = array![];
    let (settlement_address, _) = settlement.deploy(@calldata).unwrap_syscall();
    let (nullifier_address, _) = nullifier.deploy(@calldata).unwrap_syscall();
    let (renewal_address, _) = renewal.deploy(@calldata).unwrap_syscall();
    let (consolidation_address, _) = consolidation.deploy(@calldata).unwrap_syscall();
    let (withdrawal_address, _) = withdrawal.deploy(@calldata).unwrap_syscall();
    (
        settlement_address, nullifier_address, renewal_address, consolidation_address,
        withdrawal_address,
    )
}

fn deploy_auction_proof_program_with(
    settlement_statement_program: ContractAddress,
    nullifier_statement_program: ContractAddress,
    renewal_statement_program: ContractAddress,
    note_consolidation_statement_program: ContractAddress,
    withdrawal_statement_program: ContractAddress,
) -> ContractAddress {
    let class = declare("AuctionProofProgram").unwrap().contract_class();
    let calldata = array![
        settlement_statement_program.into(), nullifier_statement_program.into(),
        renewal_statement_program.into(), note_consolidation_statement_program.into(),
        withdrawal_statement_program.into(),
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

fn expected_withdrawal_proof_message_hash(
    proof_program_address: ContractAddress,
    auction_verifier: ContractAddress,
    withdrawal_commitment: felt252,
) -> felt252 {
    let mut statement_hash = poseidon_hash2(
        WITHDRAWAL_MESSAGE_DOMAIN_NATIVE, auction_verifier.into(),
    );
    statement_hash = poseidon_hash2(statement_hash, withdrawal_commitment);

    let payload = array![WITHDRAWAL_MESSAGE_DOMAIN, statement_hash];
    let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
    payload.serialize(ref l1_message_data);
    poseidon_hash_span(l1_message_data.span())
}

fn expected_nullifier_proof_message_hash(
    proof_program_address: ContractAddress,
    auction_verifier: ContractAddress,
    transcript_commitment: felt252,
    prior_nullifier_root: felt252,
    consumed_nullifier_root: felt252,
    new_nullifier_root: felt252,
) -> felt252 {
    let mut statement_hash = poseidon_hash2(NULLIFIER_MESSAGE_DOMAIN, auction_verifier.into());
    statement_hash = poseidon_hash2(statement_hash, transcript_commitment);
    statement_hash = poseidon_hash2(statement_hash, prior_nullifier_root);
    statement_hash = poseidon_hash2(statement_hash, consumed_nullifier_root);
    statement_hash = poseidon_hash2(statement_hash, new_nullifier_root);
    expected_l1_message_hash(proof_program_address, NULLIFIER_MESSAGE_DOMAIN, statement_hash)
}

fn expected_renewal_proof_message_hash(
    proof_program_address: ContractAddress,
    auction_verifier: ContractAddress,
    transcript_commitment: felt252,
    prior_renewal_root: felt252,
    renewal_child_root: felt252,
    new_renewal_root: felt252,
) -> felt252 {
    let mut statement_hash = poseidon_hash2(RENEWAL_MESSAGE_DOMAIN, auction_verifier.into());
    statement_hash = poseidon_hash2(statement_hash, transcript_commitment);
    statement_hash = poseidon_hash2(statement_hash, prior_renewal_root);
    statement_hash = poseidon_hash2(statement_hash, renewal_child_root);
    statement_hash = poseidon_hash2(statement_hash, new_renewal_root);
    expected_l1_message_hash(proof_program_address, RENEWAL_MESSAGE_DOMAIN, statement_hash)
}

fn expected_note_consolidation_proof_message_hash(
    proof_program_address: ContractAddress,
    auction_verifier: ContractAddress,
    consolidation_commitment: felt252,
) -> felt252 {
    let mut statement_hash =
        poseidon_hash2(NOTE_CONSOLIDATION_MESSAGE_DOMAIN, auction_verifier.into());
    statement_hash = poseidon_hash2(statement_hash, consolidation_commitment);
    expected_l1_message_hash(
        proof_program_address, NOTE_CONSOLIDATION_MESSAGE_DOMAIN, statement_hash,
    )
}

fn expected_l1_message_hash(
    proof_program_address: ContractAddress, payload_domain: felt252, statement_message_hash: felt252,
) -> felt252 {
    let payload = array![payload_domain, statement_message_hash];
    let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
    payload.serialize(ref l1_message_data);
    poseidon_hash_span(l1_message_data.span())
}

fn deploy_proof_program_with_mock_statements() -> ContractAddress {
    let (settlement, nullifier, renewal, consolidation, withdrawal) =
        deploy_mock_statement_programs();
    deploy_auction_proof_program_with(settlement, nullifier, renewal, consolidation, withdrawal)
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
fn withdrawal_message_hash_matches_native_payload_binding() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let withdrawal_commitment = 0x789;

    let actual = proof_program
        .withdrawal_proof_message_hash(auction_verifier, withdrawal_commitment);
    let expected = expected_withdrawal_proof_message_hash(
        proof_program_address, auction_verifier, withdrawal_commitment,
    );
    assert(actual == expected, 'BAD_WITHDRAW_HASH');
}

#[test]
fn compile_settlement_proof_accepts_known_good_statement_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let empty_witness = array![];

    let actual = proof_program.compile_settlement_proof(auction_verifier, empty_witness.span());
    let expected = expected_settlement_proof_message_hash(
        proof_program_address, auction_verifier, 0xaaa,
    );
    assert(actual == expected, 'BAD_COMPILE_SETTLE');
}

#[test]
fn compile_nullifier_proof_accepts_known_good_statement_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let empty_witness = array![];

    let actual = proof_program.compile_nullifier_proof(auction_verifier, empty_witness.span());
    let expected = expected_nullifier_proof_message_hash(
        proof_program_address, auction_verifier, 0xaaa, 0x101, 0x102, 0x103,
    );
    assert(actual == expected, 'BAD_COMPILE_NULL');
}

#[test]
fn compile_renewal_proof_accepts_known_good_statement_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let empty_witness = array![];

    let actual = proof_program.compile_renewal_proof(auction_verifier, empty_witness.span());
    let expected = expected_renewal_proof_message_hash(
        proof_program_address, auction_verifier, 0xaaa, 0x201, 0x202, 0x203,
    );
    assert(actual == expected, 'BAD_COMPILE_RENEW');
}

#[test]
fn compile_note_consolidation_proof_accepts_known_good_statement_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let empty_witness = array![];

    let actual = proof_program
        .compile_note_consolidation_proof(auction_verifier, empty_witness.span());
    let expected = expected_note_consolidation_proof_message_hash(
        proof_program_address, auction_verifier, 0xbbb,
    );
    assert(actual == expected, 'BAD_COMPILE_CONSOL');
}

#[test]
fn compile_withdrawal_proof_accepts_known_good_statement_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let empty_witness = array![];

    let actual = proof_program.compile_withdrawal_proof(auction_verifier, empty_witness.span());
    let expected = expected_withdrawal_proof_message_hash(
        proof_program_address, auction_verifier, 0xccc,
    );
    assert(actual == expected, 'BAD_COMPILE_WITHDRAW');
}

#[test]
fn compile_settlement_aggregate_proof_accepts_known_good_statement_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let empty_witnesses = array![1, 0];

    let settlement_message =
        expected_settlement_proof_message_hash(proof_program_address, auction_verifier, 0xaaa);
    let nullifier_message = expected_nullifier_proof_message_hash(
        proof_program_address, auction_verifier, 0xaaa, 0x101, 0x102, 0x103,
    );
    let renewal_message = expected_renewal_proof_message_hash(
        proof_program_address, auction_verifier, 0xaaa, 0x201, 0x202, 0x203,
    );
    let mut expected = poseidon_hash2(AGGREGATE_RETURN_DOMAIN, 1);
    expected = poseidon_hash2(expected, settlement_message);
    expected = poseidon_hash2(expected, nullifier_message);
    expected = poseidon_hash2(expected, renewal_message);

    let actual = proof_program
        .compile_settlement_aggregate_proof(auction_verifier, empty_witnesses.span());
    assert(actual == expected, 'BAD_COMPILE_AGG');
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_settlement_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        as_address(0), statement_program, statement_program, statement_program, statement_program,
    );
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_nullifier_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        statement_program, as_address(0), statement_program, statement_program, statement_program,
    );
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_renewal_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        statement_program, statement_program, as_address(0), statement_program, statement_program,
    );
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_consolidation_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        statement_program, statement_program, statement_program, as_address(0), statement_program,
    );
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_withdrawal_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        statement_program, statement_program, statement_program, statement_program, as_address(0),
    );
}

#[test]
#[should_panic]
fn settlement_message_hash_rejects_zero_verifier() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };

    proof_program.settlement_proof_message_hash(as_address(0), 0x789);
}

#[test]
#[should_panic]
fn withdrawal_message_hash_rejects_zero_verifier() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };

    proof_program.withdrawal_proof_message_hash(as_address(0), 0x789);
}

#[test]
#[should_panic]
fn compile_settlement_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witness = array![];

    proof_program.compile_settlement_proof(as_address(0), empty_witness.span());
}

#[test]
#[should_panic]
fn compile_nullifier_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witness = array![];

    proof_program.compile_nullifier_proof(as_address(0), empty_witness.span());
}

#[test]
#[should_panic]
fn compile_renewal_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witness = array![];

    proof_program.compile_renewal_proof(as_address(0), empty_witness.span());
}

#[test]
#[should_panic]
fn compile_note_consolidation_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witness = array![];

    proof_program.compile_note_consolidation_proof(as_address(0), empty_witness.span());
}

#[test]
#[should_panic]
fn compile_withdrawal_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witness = array![];

    proof_program.compile_withdrawal_proof(as_address(0), empty_witness.span());
}

#[test]
#[should_panic]
fn compile_admission_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witness = array![];

    proof_program.compile_admission_proof(as_address(0), empty_witness.span());
}

#[test]
#[should_panic]
fn compile_auction_result_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witness = array![];

    proof_program.compile_auction_result_proof(as_address(0), empty_witness.span());
}

#[test]
#[should_panic]
fn compile_settlement_aggregate_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witnesses = array![];

    proof_program.compile_settlement_aggregate_proof(as_address(0), empty_witnesses.span());
}

#[starknet::contract]
mod MockSettlementStatementProgram {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn verify_settlement_statement(
        self: @ContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252 {
        let _ = self;
        let _ = serialized_settlement_witness;
        0xaaa
    }
}

#[starknet::contract]
mod MockNullifierStatementProgram {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn verify_nullifier_statement(
        self: @ContractState, serialized_settlement_witness: Span<felt252>,
    ) -> (felt252, felt252, felt252, felt252) {
        let _ = self;
        let _ = serialized_settlement_witness;
        (0xaaa, 0x101, 0x102, 0x103)
    }
}

#[starknet::contract]
mod MockRenewalStatementProgram {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn verify_renewal_statement(
        self: @ContractState, serialized_settlement_witness: Span<felt252>,
    ) -> (felt252, felt252, felt252, felt252) {
        let _ = self;
        let _ = serialized_settlement_witness;
        (0xaaa, 0x201, 0x202, 0x203)
    }
}

#[starknet::contract]
mod MockNoteConsolidationStatementProgram {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn verify_note_consolidation_statement(
        self: @ContractState, serialized_note_consolidation_witness: Span<felt252>,
    ) -> felt252 {
        let _ = self;
        let _ = serialized_note_consolidation_witness;
        0xbbb
    }
}

#[starknet::contract]
mod MockWithdrawalStatementProgram {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn verify_withdrawal_statement(
        self: @ContractState, serialized_withdrawal_witness: Span<felt252>,
    ) -> felt252 {
        let _ = self;
        let _ = serialized_withdrawal_witness;
        0xccc
    }
}
