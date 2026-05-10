use starknet::ContractAddress;

#[starknet::interface]
pub trait ISettlementStatementProgram<TContractState> {
    fn verify_settlement_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait IAuctionProofProgram<TContractState> {
    fn compile_settlement_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
    fn compile_admission_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_admission_witness: Span<felt252>,
    ) -> felt252;
    fn compile_auction_result_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_private_auction_witness: Span<felt252>,
    ) -> felt252;
    fn compile_settlement_aggregate_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_settlement_witnesses: Span<felt252>,
    ) -> felt252;
    fn settlement_proof_message_hash(
        self: @TContractState, auction_verifier: ContractAddress, transcript_commitment: felt252,
    ) -> felt252;
}

#[starknet::contract]
pub mod SettlementStatementProgram {
    use zylith_settlement_statement::verify_settlement_statement as verify_settlement_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl SettlementStatementProgramImpl of super::ISettlementStatementProgram<ContractState> {
        fn verify_settlement_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            verify_settlement_statement_impl(serialized_settlement_witness)
        }
    }
}

#[starknet::contract]
pub mod AuctionProofProgram {
    use core::array::{Array, ArrayTrait, SpanTrait};
    use core::num::traits::Zero;
    use core::poseidon::{hades_permutation, poseidon_hash_span};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::syscalls::send_message_to_l1_syscall;
    use starknet::{ContractAddress, SyscallResultTrait, get_contract_address};
    use zylith_settlement_statement::{verify_admission_statement, verify_auction_result_statement};
    use super::{ISettlementStatementProgramDispatcher, ISettlementStatementProgramDispatcherTrait};

    const SETTLEMENT_MESSAGE_DOMAIN: felt252 = 'zylith_settle_v1';
    const ADMISSION_MESSAGE_DOMAIN: felt252 = 'zylith_admit_v1';
    const AUCTION_RESULT_MESSAGE_DOMAIN: felt252 = 'zylith_aucres_v1';
    const SETTLEMENT_PROOF_MESSAGE_TO: felt252 = 0;
    const AGGREGATE_RETURN_DOMAIN: felt252 = 'zylith_agg_v1';

    #[storage]
    struct Storage {
        settlement_statement_program: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState, settlement_statement_program: ContractAddress) {
        assert(!settlement_statement_program.is_zero(), 'BAD_STMT_PROGRAM');
        self.settlement_statement_program.write(settlement_statement_program);
    }

    #[abi(embed_v0)]
    impl AuctionProofProgramImpl of super::IAuctionProofProgram<ContractState> {
        fn compile_settlement_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let settlement_statement_program = ISettlementStatementProgramDispatcher {
                contract_address: self.settlement_statement_program.read(),
            };
            let transcript_commitment = settlement_statement_program
                .verify_settlement_statement(serialized_settlement_witness);
            emit_settlement_proof_message(auction_verifier, transcript_commitment)
        }

        fn compile_admission_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_admission_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let (batch_id, order_commitment_root, admission_root) = verify_admission_statement(
                serialized_admission_witness,
            );
            emit_admission_proof_message(
                auction_verifier, batch_id, order_commitment_root, admission_root,
            )
        }

        fn compile_auction_result_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_private_auction_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let (batch_id, order_commitment_root, admission_root, transcript_commitment) =
                verify_auction_result_statement(
                serialized_private_auction_witness,
            );
            emit_auction_result_proof_message(
                auction_verifier,
                batch_id,
                order_commitment_root,
                admission_root,
                transcript_commitment,
            )
        }

        fn compile_settlement_aggregate_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_settlement_witnesses: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let mut index: usize = 0;
            let witness_count_felt = read_next(serialized_settlement_witnesses, ref index);
            let witness_count: usize = witness_count_felt.try_into().expect('BAD_AGG_COUNT');
            assert(witness_count != 0, 'EMPTY_AGGREGATE');
            let settlement_statement_program = ISettlementStatementProgramDispatcher {
                contract_address: self.settlement_statement_program.read(),
            };
            let mut aggregate = poseidon_hash2(AGGREGATE_RETURN_DOMAIN, witness_count_felt);
            let mut cursor: usize = 0;
            loop {
                if cursor == witness_count {
                    break;
                }
                let witness = read_vector(serialized_settlement_witnesses, ref index);
                let transcript_commitment = settlement_statement_program
                    .verify_settlement_statement(witness.span());
                let proof_message = emit_settlement_proof_message(
                    auction_verifier, transcript_commitment,
                );
                aggregate = poseidon_hash2(aggregate, proof_message);
                cursor += 1;
            }
            assert(index == serialized_settlement_witnesses.len(), 'TRAILING_AGG_INPUT');
            aggregate
        }

        fn settlement_proof_message_hash(
            self: @ContractState, auction_verifier: ContractAddress, transcript_commitment: felt252,
        ) -> felt252 {
            let _ = self;
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let statement_message_hash = native_settlement_message_hash(
                auction_verifier, transcript_commitment,
            );
            settlement_proof_message_hash_from_statement(
                get_contract_address(), statement_message_hash,
            )
        }
    }

    fn emit_settlement_proof_message(
        auction_verifier: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let statement_message_hash = native_settlement_message_hash(
            auction_verifier, transcript_commitment,
        );
        let payload = settlement_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        settlement_proof_message_hash_from_statement(get_contract_address(), statement_message_hash)
    }

    fn emit_admission_proof_message(
        auction_verifier: ContractAddress,
        batch_id: felt252,
        order_commitment_root: felt252,
        admission_root: felt252,
    ) -> felt252 {
        let statement_message_hash = native_admission_message_hash(
            auction_verifier, batch_id, order_commitment_root, admission_root,
        );
        let payload = admission_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        admission_proof_message_hash_from_statement(get_contract_address(), statement_message_hash)
    }

    fn emit_auction_result_proof_message(
        auction_verifier: ContractAddress,
        batch_id: felt252,
        order_commitment_root: felt252,
        admission_root: felt252,
        transcript_commitment: felt252,
    ) -> felt252 {
        let statement_message_hash = native_auction_result_message_hash(
            auction_verifier,
            batch_id,
            order_commitment_root,
            admission_root,
            transcript_commitment,
        );
        let payload = auction_result_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        auction_result_proof_message_hash_from_statement(
            get_contract_address(), statement_message_hash,
        )
    }

    fn read_next(data: Span<felt252>, ref index: usize) -> felt252 {
        assert(index < data.len(), 'INPUT_TOO_SHORT');
        let value = *data.at(index);
        index += 1;
        value
    }

    fn read_vector(data: Span<felt252>, ref index: usize) -> Array<felt252> {
        let len_felt = read_next(data, ref index);
        let len: usize = len_felt.try_into().expect('BAD_VECTOR_LEN');
        let mut values = array![];
        let mut cursor: usize = 0;
        loop {
            if cursor == len {
                break;
            }
            values.append(read_next(data, ref index));
            cursor += 1;
        }
        values
    }

    fn settlement_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![SETTLEMENT_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn admission_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![ADMISSION_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn auction_result_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![AUCTION_RESULT_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn settlement_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = settlement_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn admission_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = admission_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn auction_result_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = auction_result_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn poseidon_hash2(x: felt252, y: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(x, y, 2);
        result
    }

    fn native_settlement_message_hash(
        auction_verifier_address: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            0x326c16c927e3e9e1e2cb23ce296a3e7f3d21e798e34d6cac00f9b1241fdfc3a,
            auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, transcript_commitment);
        state
    }

    fn native_admission_message_hash(
        auction_verifier_address: ContractAddress,
        batch_id: felt252,
        order_commitment_root: felt252,
        admission_root: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(ADMISSION_MESSAGE_DOMAIN, auction_verifier_address.into());
        state = poseidon_hash2(state, batch_id);
        state = poseidon_hash2(state, order_commitment_root);
        state = poseidon_hash2(state, admission_root);
        state
    }

    fn native_auction_result_message_hash(
        auction_verifier_address: ContractAddress,
        batch_id: felt252,
        order_commitment_root: felt252,
        admission_root: felt252,
        transcript_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            AUCTION_RESULT_MESSAGE_DOMAIN, auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, batch_id);
        state = poseidon_hash2(state, order_commitment_root);
        state = poseidon_hash2(state, admission_root);
        state = poseidon_hash2(state, transcript_commitment);
        state
    }
}
