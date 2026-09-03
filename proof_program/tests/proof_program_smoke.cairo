use core::poseidon::{hades_permutation, poseidon_hash_span};
use core::traits::TryInto;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::{ContractAddress, SyscallResultTrait};
use zylith_proof_program::{IAuctionProofProgramDispatcher, IAuctionProofProgramDispatcherTrait};

const SETTLEMENT_MESSAGE_DOMAIN: felt252 = 'zylith_settle_v1';
const NULLIFIER_MESSAGE_DOMAIN: felt252 = 'zylith_null_v1';
const RENEWAL_MESSAGE_DOMAIN: felt252 = 'zylith_renew_v1';
const LIQUIDITY_POSITION_MESSAGE_DOMAIN: felt252 = 'zylith_lp_v1';
const SETTLEMENT_ORDER_MESSAGE_DOMAIN: felt252 = 'zylith_ord_v1';
const SETTLEMENT_INPUT_MEMBERSHIP_MESSAGE_DOMAIN: felt252 = 'zylith_inmem_v1';
const SETTLEMENT_OUTPUT_RECOVERY_MESSAGE_DOMAIN: felt252 = 'zylith_outrec_v1';
const NOTE_CONSOLIDATION_MESSAGE_DOMAIN: felt252 = 'zylith_consol_v1';
const WITHDRAWAL_MESSAGE_DOMAIN: felt252 = 'zylith_withdraw_v1';
const SETTLEMENT_PROOF_MESSAGE_TO: felt252 = 0;
const AGGREGATE_RETURN_DOMAIN: felt252 = 'zylith_agg_v1';
const MULTI_PAIR_MESSAGE_DOMAIN: felt252 = 'zylith_mpair_v1';
const NATIVE_SETTLEMENT_DOMAIN: felt252 =
    0x326c16c927e3e9e1e2cb23ce296a3e7f3d21e798e34d6cac00f9b1241fdfc3a;
const WITHDRAWAL_MESSAGE_DOMAIN_NATIVE: felt252 = 'zylith_withdraw_v1';
const LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN: felt252 =
    0x0301dfad9cc240f421fd32f6b74d72002abc7f4056b885950bc5bc779213e5f7;
const STATE_TRANSITION_ROOT_DOMAIN: felt252 =
    0x01f14f0555b0b80fd6af9553623a021c472d8c930dfcb5b204b35b26f0d2b1b2;
const STATEMENT_TYPE_SETTLEMENT: felt252 = 1;
const NOTE_COMMITMENT_DOMAIN: felt252 =
    0x43aeae569e031a74671a28c60a017d2a53bbb5ffa6f6a7711c076348fb186c;
const SPEND_AUTHORITY_DOMAIN: felt252 =
    0x21b92fb580b0e2cb7898509d56df3d7b51d6f68f17b50aa02e93e0227b15f3b;
const NULLIFIER_DOMAIN: felt252 = 0x6cd79aee4dd094aadf944f50e83fad66ce717a58d59d73a92df351aac6d14e3;
const ORDER_COMMITMENT_DOMAIN: felt252 =
    0x7cd5dda33869da7da5ccb3afbc70fc766fb0cbe3d560c2bfb3bdbab8a4b844d;
const LIQUIDITY_SLICE_DOMAIN: felt252 =
    0x2bc4890bf4accafb4b8f647c96e53cdd702a9b2e8b405a4d4b83b87ef46c69a;
const PUBLIC_SETTLEMENT_DOMAIN: felt252 =
    0x0283f626418aa97a073f64500f7e35dd8bf7c01ff8611917c3c38e5be92eb205;
const CONSUMED_NOTE_ROOT_DOMAIN: felt252 =
    0x5ca3bbd6a01ed8e6017182aa4b43ec8d9e4055d9d4133b008c3ea9916b347dd;
const CONSUMED_NULLIFIER_ROOT_DOMAIN: felt252 =
    0x52259833b97a525483b8fff0635ce1f9fdfd08b5a8db2486d4a05378989b0f0;
const RENEWAL_CHILD_ROOT_DOMAIN: felt252 =
    0x7fa9bd33f1b9cd81a22d77d4dc7ea4d33abd249f7585d0e451b0fafa39dfc3d;
const OUTPUT_NOTE_ROOT_DOMAIN: felt252 =
    0x322d8a4d6fe2953496989824ec66bcb9d011aa052bb4be4593670c1ea7908dc;
const FEE_ROOT_DOMAIN: felt252 = 0x79a9e0b9d4a6b4cac728c0e5f6298e37533fa1348f020f3575a78c5adf7d44b;
const NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL: felt252 =
    0x03fd7c748b95292c230aa528dc391912cd4557ad3e157e94ab06b22af433f967;
const NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL: felt252 =
    0x02de7e98b8f1ba580329d7cfcf51a36f6eb4f8611cae6f82b34e116bb9c2588c;
const OUTPUT_RECOVERY_BUNDLE_DOMAIN: felt252 = 0x7a796c6974685f6f75745f62756e646c655f7631;
const PAIR_ID_STRK_USDC: felt252 =
    0x116ee836b759d809a28dfcf84de04ce4d7ba6aca96741019ffcbbbbcaa8b29e;
const ASSET_ID_STRK: felt252 = 0x8926041840302bbb1edfd15c98ffaf0f2a9e8ba0ac43bfd446942d708b7b7c;
const ASSET_ID_USDC: felt252 = 0x1e565426a7cff134da7e67f4587da64258d8e50b249f60444b53d8aebb4987c;
const ASSET_SCALE_18: felt252 = 1000000000000000000;

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
        statement_program,
        statement_program,
        statement_program,
        statement_program,
    )
}

fn deploy_mock_statement_programs() -> (
    ContractAddress,
    ContractAddress,
    ContractAddress,
    ContractAddress,
    ContractAddress,
    ContractAddress,
    ContractAddress,
    ContractAddress,
    ContractAddress,
) {
    let settlement = declare("MockSettlementStatementProgram").unwrap().contract_class();
    let nullifier = declare("MockNullifierStatementProgram").unwrap().contract_class();
    let renewal = declare("MockRenewalStatementProgram").unwrap().contract_class();
    let liquidity_position = declare("MockLiquidityPositionStatementProgram")
        .unwrap()
        .contract_class();
    let consolidation = declare("MockNoteConsolidationStatementProgram").unwrap().contract_class();
    let withdrawal = declare("MockWithdrawalStatementProgram").unwrap().contract_class();
    let admission = declare("MockAdmissionStatementProgram").unwrap().contract_class();
    let auction_result = declare("MockAuctionResultStatementProgram").unwrap().contract_class();
    let multi_pair = declare("MockMultiPairStatementProgram").unwrap().contract_class();
    let calldata = array![];
    let (settlement_address, _) = settlement.deploy(@calldata).unwrap_syscall();
    let (nullifier_address, _) = nullifier.deploy(@calldata).unwrap_syscall();
    let (renewal_address, _) = renewal.deploy(@calldata).unwrap_syscall();
    let (liquidity_position_address, _) = liquidity_position.deploy(@calldata).unwrap_syscall();
    let (consolidation_address, _) = consolidation.deploy(@calldata).unwrap_syscall();
    let (withdrawal_address, _) = withdrawal.deploy(@calldata).unwrap_syscall();
    let (admission_address, _) = admission.deploy(@calldata).unwrap_syscall();
    let (auction_result_address, _) = auction_result.deploy(@calldata).unwrap_syscall();
    let (multi_pair_address, _) = multi_pair.deploy(@calldata).unwrap_syscall();
    (
        settlement_address,
        nullifier_address,
        renewal_address,
        liquidity_position_address,
        consolidation_address,
        withdrawal_address,
        admission_address,
        auction_result_address,
        multi_pair_address,
    )
}

fn deploy_auction_proof_program_with(
    settlement_statement_program: ContractAddress,
    nullifier_statement_program: ContractAddress,
    renewal_statement_program: ContractAddress,
    liquidity_position_statement_program: ContractAddress,
    note_consolidation_statement_program: ContractAddress,
    withdrawal_statement_program: ContractAddress,
    admission_statement_program: ContractAddress,
    auction_result_statement_program: ContractAddress,
    multi_pair_statement_program: ContractAddress,
) -> ContractAddress {
    let class = declare("AuctionProofProgram").unwrap().contract_class();
    let calldata = array![
        settlement_statement_program.into(), nullifier_statement_program.into(),
        renewal_statement_program.into(), liquidity_position_statement_program.into(),
        note_consolidation_statement_program.into(), withdrawal_statement_program.into(),
        admission_statement_program.into(), auction_result_statement_program.into(),
        multi_pair_statement_program.into(),
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

fn expected_liquidity_position_proof_message_hash(
    proof_program_address: ContractAddress,
    auction_verifier: ContractAddress,
    transcript_commitment: felt252,
    prior_root: felt252,
    transition_root: felt252,
    new_root: felt252,
) -> felt252 {
    let mut statement_hash = poseidon_hash2(
        LIQUIDITY_POSITION_MESSAGE_DOMAIN, auction_verifier.into(),
    );
    statement_hash = poseidon_hash2(statement_hash, transcript_commitment);
    statement_hash = poseidon_hash2(statement_hash, prior_root);
    statement_hash = poseidon_hash2(statement_hash, transition_root);
    statement_hash = poseidon_hash2(statement_hash, new_root);
    expected_l1_message_hash(
        proof_program_address, LIQUIDITY_POSITION_MESSAGE_DOMAIN, statement_hash,
    )
}

fn expected_multi_pair_proof_message_hash(
    proof_program_address: ContractAddress,
    auction_verifier: ContractAddress,
    multi_pair_commitment: felt252,
) -> felt252 {
    let mut statement_hash = poseidon_hash2(MULTI_PAIR_MESSAGE_DOMAIN, auction_verifier.into());
    statement_hash = poseidon_hash2(statement_hash, multi_pair_commitment);
    expected_l1_message_hash(proof_program_address, MULTI_PAIR_MESSAGE_DOMAIN, statement_hash)
}

fn expected_settlement_component_proof_message_hash(
    proof_program_address: ContractAddress,
    auction_verifier: ContractAddress,
    transcript_commitment: felt252,
    domain: felt252,
) -> felt252 {
    let mut statement_hash = poseidon_hash2(domain, auction_verifier.into());
    statement_hash = poseidon_hash2(statement_hash, transcript_commitment);
    expected_l1_message_hash(proof_program_address, domain, statement_hash)
}

fn empty_liquidity_position_witness(transcript_commitment: felt252) -> Array<felt252> {
    let output_bundle_ref = poseidon_hash2(OUTPUT_RECOVERY_BUNDLE_DOMAIN, 0);
    let transition_root = poseidon_hash2(LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN, 0);
    let mut payload = array![
        STATEMENT_TYPE_SETTLEMENT, NOTE_COMMITMENT_DOMAIN, SPEND_AUTHORITY_DOMAIN, NULLIFIER_DOMAIN,
        ORDER_COMMITMENT_DOMAIN, LIQUIDITY_SLICE_DOMAIN, PUBLIC_SETTLEMENT_DOMAIN, 0x2001,
        PAIR_ID_STRK_USDC, 0x2003, 0x2004, 0x2005, transcript_commitment, ASSET_ID_STRK,
        ASSET_ID_USDC, 0, ASSET_SCALE_18, 4, 0, 0, 0x4010, 0x4020, 0, output_bundle_ref, 0, 0, 0, 0,
        0, transition_root, CONSUMED_NOTE_ROOT_DOMAIN, CONSUMED_NULLIFIER_ROOT_DOMAIN,
        RENEWAL_CHILD_ROOT_DOMAIN, LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN,
        OUTPUT_NOTE_ROOT_DOMAIN, FEE_ROOT_DOMAIN, STATE_TRANSITION_ROOT_DOMAIN,
        NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL, NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL,
    ];
    append_empty_vectors(ref payload, 143);
    payload
}

fn append_empty_vectors(ref payload: Array<felt252>, count: usize) {
    let mut index: usize = 0;
    loop {
        if index == count {
            break;
        }
        payload.append(0);
        index += 1;
    };
}

fn expected_note_consolidation_proof_message_hash(
    proof_program_address: ContractAddress,
    auction_verifier: ContractAddress,
    consolidation_commitment: felt252,
) -> felt252 {
    let mut statement_hash = poseidon_hash2(
        NOTE_CONSOLIDATION_MESSAGE_DOMAIN, auction_verifier.into(),
    );
    statement_hash = poseidon_hash2(statement_hash, consolidation_commitment);
    expected_l1_message_hash(
        proof_program_address, NOTE_CONSOLIDATION_MESSAGE_DOMAIN, statement_hash,
    )
}

fn expected_l1_message_hash(
    proof_program_address: ContractAddress,
    payload_domain: felt252,
    statement_message_hash: felt252,
) -> felt252 {
    let payload = array![payload_domain, statement_message_hash];
    let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
    payload.serialize(ref l1_message_data);
    poseidon_hash_span(l1_message_data.span())
}

fn deploy_proof_program_with_mock_statements() -> ContractAddress {
    let (
        settlement,
        nullifier,
        renewal,
        liquidity_position,
        consolidation,
        withdrawal,
        admission,
        auction_result,
        multi_pair,
    ) =
        deploy_mock_statement_programs();
    deploy_auction_proof_program_with(
        settlement,
        nullifier,
        renewal,
        liquidity_position,
        consolidation,
        withdrawal,
        admission,
        auction_result,
        multi_pair,
    )
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
fn compile_liquidity_position_proof_accepts_known_good_statement_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let witness = empty_liquidity_position_witness(0xaaa);
    let transition_root = poseidon_hash2(LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN, 0);

    let actual = proof_program.compile_liquidity_position_proof(auction_verifier, witness.span());
    let expected = expected_liquidity_position_proof_message_hash(
        proof_program_address, auction_verifier, 0xaaa, 0, transition_root, 0,
    );
    assert(actual == expected, 'BAD_COMPILE_LP');
}

#[test]
fn compile_settlement_order_proof_accepts_known_good_statement_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let empty_witness = array![];

    let actual = proof_program
        .compile_settlement_order_proof(auction_verifier, empty_witness.span());
    let expected = expected_settlement_component_proof_message_hash(
        proof_program_address, auction_verifier, 0xaaa, SETTLEMENT_ORDER_MESSAGE_DOMAIN,
    );
    assert(actual == expected, 'BAD_COMPILE_ORDER');
}

#[test]
fn compile_settlement_input_membership_proof_accepts_known_good_statement_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let empty_witness = array![];

    let actual = proof_program
        .compile_settlement_input_membership_proof(auction_verifier, empty_witness.span());
    let expected = expected_settlement_component_proof_message_hash(
        proof_program_address, auction_verifier, 0xaaa, SETTLEMENT_INPUT_MEMBERSHIP_MESSAGE_DOMAIN,
    );
    assert(actual == expected, 'BAD_COMPILE_MEM');
}

#[test]
fn compile_settlement_output_recovery_proof_accepts_known_good_statement_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let empty_witness = array![];

    let actual = proof_program
        .compile_settlement_output_recovery_proof(auction_verifier, empty_witness.span());
    let expected = expected_settlement_component_proof_message_hash(
        proof_program_address, auction_verifier, 0xaaa, SETTLEMENT_OUTPUT_RECOVERY_MESSAGE_DOMAIN,
    );
    assert(actual == expected, 'BAD_COMPILE_REC');
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
fn compile_multi_pair_proof_accepts_known_good_statement_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let empty_witness = array![];

    let actual = proof_program.compile_multi_pair_proof(auction_verifier, empty_witness.span());
    let expected = expected_multi_pair_proof_message_hash(
        proof_program_address, auction_verifier, 0xddd,
    );
    assert(actual == expected, 'BAD_COMPILE_MPAIR');
}

#[test]
fn compile_settlement_aggregate_proof_accepts_known_good_statement_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let witness = empty_liquidity_position_witness(0xaaa);
    let mut empty_witnesses = array![1, witness.len().into()];
    let mut index: usize = 0;
    while index < witness.len() {
        empty_witnesses.append(*witness.at(index));
        index += 1;
    }

    let settlement_message = expected_settlement_proof_message_hash(
        proof_program_address, auction_verifier, 0xaaa,
    );
    let nullifier_message = expected_nullifier_proof_message_hash(
        proof_program_address, auction_verifier, 0xaaa, 0x101, 0x102, 0x103,
    );
    let renewal_message = expected_renewal_proof_message_hash(
        proof_program_address, auction_verifier, 0xaaa, 0x201, 0x202, 0x203,
    );
    let liquidity_message = expected_liquidity_position_proof_message_hash(
        proof_program_address,
        auction_verifier,
        0xaaa,
        0,
        poseidon_hash2(LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN, 0),
        0,
    );
    let mut expected = poseidon_hash2(AGGREGATE_RETURN_DOMAIN, 1);
    expected = poseidon_hash2(expected, settlement_message);
    expected = poseidon_hash2(expected, nullifier_message);
    expected = poseidon_hash2(expected, renewal_message);
    expected = poseidon_hash2(expected, liquidity_message);

    let actual = proof_program
        .compile_settlement_aggregate_proof(auction_verifier, empty_witnesses.span());
    assert(actual == expected, 'BAD_COMPILE_AGG');
}

#[test]
#[should_panic]
fn compile_settlement_aggregate_proof_rejects_empty_native_fixture() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let empty_witnesses = array![0];

    proof_program.compile_settlement_aggregate_proof(auction_verifier, empty_witnesses.span());
}

#[test]
#[should_panic]
fn compile_settlement_aggregate_proof_rejects_trailing_native_fixture_data() {
    let proof_program_address = deploy_proof_program_with_mock_statements();
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let auction_verifier = as_address(0x456);
    let padded_witnesses = array![1, 0, 0xdead];

    proof_program.compile_settlement_aggregate_proof(auction_verifier, padded_witnesses.span());
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_settlement_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        as_address(0),
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
    );
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_nullifier_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        statement_program,
        as_address(0),
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
    );
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_renewal_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        statement_program,
        statement_program,
        as_address(0),
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
    );
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_liquidity_position_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        statement_program,
        statement_program,
        statement_program,
        as_address(0),
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
    );
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_consolidation_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        as_address(0),
        statement_program,
        statement_program,
        statement_program,
        statement_program,
    );
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_withdrawal_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        as_address(0),
        statement_program,
        statement_program,
        statement_program,
    );
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_admission_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        as_address(0),
        statement_program,
        statement_program,
    );
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_auction_result_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        as_address(0),
        statement_program,
    );
}

#[test]
#[should_panic]
fn auction_proof_program_rejects_zero_multi_pair_statement_program() {
    let statement_program = as_address(0x123);
    deploy_auction_proof_program_with(
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        statement_program,
        as_address(0),
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
fn compile_liquidity_position_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witness = array![];

    proof_program.compile_liquidity_position_proof(as_address(0), empty_witness.span());
}

#[test]
#[should_panic]
fn compile_settlement_order_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witness = array![];

    proof_program.compile_settlement_order_proof(as_address(0), empty_witness.span());
}

#[test]
#[should_panic]
fn compile_settlement_input_membership_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witness = array![];

    proof_program.compile_settlement_input_membership_proof(as_address(0), empty_witness.span());
}

#[test]
#[should_panic]
fn compile_settlement_output_recovery_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witness = array![];

    proof_program.compile_settlement_output_recovery_proof(as_address(0), empty_witness.span());
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
fn compile_multi_pair_proof_rejects_zero_verifier_before_statement_dispatch() {
    let statement_program = as_address(0x123);
    let proof_program_address = deploy_auction_proof_program(statement_program);
    let proof_program = IAuctionProofProgramDispatcher { contract_address: proof_program_address };
    let empty_witness = array![];

    proof_program.compile_multi_pair_proof(as_address(0), empty_witness.span());
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

    #[external(v0)]
    fn verify_settlement_note_fee_statement(
        self: @ContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252 {
        let _ = self;
        let _ = serialized_settlement_witness;
        0xaaa
    }

    #[external(v0)]
    fn verify_settlement_order_statement(
        self: @ContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252 {
        let _ = self;
        let _ = serialized_settlement_witness;
        0xaaa
    }

    #[external(v0)]
    fn verify_settlement_output_recovery_statement(
        self: @ContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252 {
        let _ = self;
        let _ = serialized_settlement_witness;
        0xaaa
    }

    #[external(v0)]
    fn verify_settlement_input_membership_statement(
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
mod MockLiquidityPositionStatementProgram {
    const LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN: felt252 =
        0x0301dfad9cc240f421fd32f6b74d72002abc7f4056b885950bc5bc779213e5f7;

    #[storage]
    struct Storage {}

    #[external(v0)]
    fn verify_liquidity_position_statement(
        self: @ContractState, serialized_settlement_witness: Span<felt252>,
    ) -> (felt252, felt252, felt252, felt252) {
        let _ = self;
        let _ = serialized_settlement_witness;
        (0xaaa, 0, super::poseidon_hash2(LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN, 0), 0)
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
mod MockAdmissionStatementProgram {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn verify_admission_statement(
        self: @ContractState, serialized_admission_witness: Span<felt252>,
    ) -> (felt252, felt252, felt252) {
        let _ = self;
        let _ = serialized_admission_witness;
        (0x111, 0x222, 0x333)
    }
}

#[starknet::contract]
mod MockAuctionResultStatementProgram {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn verify_auction_result_statement(
        self: @ContractState, serialized_private_auction_witness: Span<felt252>,
    ) -> (felt252, felt252, felt252, felt252) {
        let _ = self;
        let _ = serialized_private_auction_witness;
        (0x111, 0x222, 0x333, 0xaaa)
    }
}

#[starknet::contract]
mod MockMultiPairStatementProgram {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn verify_multi_pair_statement(
        self: @ContractState, serialized_multi_pair_witness: Span<felt252>,
    ) -> felt252 {
        let _ = self;
        let _ = serialized_multi_pair_witness;
        0xddd
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
