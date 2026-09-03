use starknet::ContractAddress;

#[starknet::interface]
pub trait ISettlementStatementProgram<TContractState> {
    fn verify_settlement_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
    fn verify_settlement_note_fee_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
    fn verify_settlement_order_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
    fn verify_settlement_output_recovery_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
    fn verify_settlement_input_membership_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait ISettlementNoteFeeStatementProgram<TContractState> {
    fn verify_settlement_note_fee_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait ISettlementOrderStatementProgram<TContractState> {
    fn verify_settlement_order_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait ISettlementOutputRecoveryStatementProgram<TContractState> {
    fn verify_settlement_output_recovery_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait ISettlementInputMembershipStatementProgram<TContractState> {
    fn verify_settlement_input_membership_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait INullifierStatementProgram<TContractState> {
    fn verify_nullifier_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> (felt252, felt252, felt252, felt252);
}

#[starknet::interface]
pub trait IRenewalStatementProgram<TContractState> {
    fn verify_renewal_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> (felt252, felt252, felt252, felt252);
}

#[starknet::interface]
pub trait ILiquidityPositionStatementProgram<TContractState> {
    fn verify_liquidity_position_statement(
        ref self: TContractState, serialized_settlement_witness: Span<felt252>,
    ) -> (felt252, felt252, felt252, felt252);
}

#[starknet::interface]
pub trait IMultiPairStatementProgram<TContractState> {
    fn verify_multi_pair_statement(
        ref self: TContractState, serialized_multi_pair_witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait INoteConsolidationStatementProgram<TContractState> {
    fn verify_note_consolidation_statement(
        ref self: TContractState, serialized_note_consolidation_witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait IWithdrawalStatementProgram<TContractState> {
    fn verify_withdrawal_statement(
        ref self: TContractState, serialized_withdrawal_witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait IAdmissionStatementProgram<TContractState> {
    fn verify_admission_statement(
        ref self: TContractState, serialized_admission_witness: Span<felt252>,
    ) -> (felt252, felt252, felt252);
}

#[starknet::interface]
pub trait IAuctionResultStatementProgram<TContractState> {
    fn verify_auction_result_statement(
        ref self: TContractState, serialized_private_auction_witness: Span<felt252>,
    ) -> (felt252, felt252, felt252, felt252);
}

#[starknet::interface]
pub trait IAuctionProofProgram<TContractState> {
    fn compile_settlement_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
    fn compile_nullifier_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
    fn compile_renewal_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
    fn compile_liquidity_position_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
    fn compile_settlement_order_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
    fn compile_settlement_input_membership_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
    fn compile_settlement_output_recovery_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_settlement_witness: Span<felt252>,
    ) -> felt252;
    fn compile_note_consolidation_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_note_consolidation_witness: Span<felt252>,
    ) -> felt252;
    fn compile_withdrawal_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_withdrawal_witness: Span<felt252>,
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
    fn compile_multi_pair_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_multi_pair_witness: Span<felt252>,
    ) -> felt252;
    fn compile_settlement_aggregate_proof(
        ref self: TContractState,
        auction_verifier: ContractAddress,
        serialized_settlement_witnesses: Span<felt252>,
    ) -> felt252;
    fn settlement_proof_message_hash(
        self: @TContractState, auction_verifier: ContractAddress, transcript_commitment: felt252,
    ) -> felt252;
    fn withdrawal_proof_message_hash(
        self: @TContractState, auction_verifier: ContractAddress, withdrawal_commitment: felt252,
    ) -> felt252;
}

#[starknet::contract]
pub mod SettlementNoteFeeStatementProgram {
    use zylith_settlement_statement::verify_settlement_note_fee_statement as verify_settlement_note_fee_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl SettlementNoteFeeStatementProgramImpl of super::ISettlementNoteFeeStatementProgram<
        ContractState,
    > {
        fn verify_settlement_note_fee_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            verify_settlement_note_fee_statement_impl(serialized_settlement_witness)
        }
    }
}

#[starknet::contract]
pub mod SettlementOrderStatementProgram {
    use zylith_settlement_statement::verify_settlement_order_statement as verify_settlement_order_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl SettlementOrderStatementProgramImpl of super::ISettlementOrderStatementProgram<
        ContractState,
    > {
        fn verify_settlement_order_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            verify_settlement_order_statement_impl(serialized_settlement_witness)
        }
    }
}

#[starknet::contract]
pub mod SettlementOutputRecoveryStatementProgram {
    use zylith_settlement_statement::verify_settlement_output_recovery_statement as verify_settlement_output_recovery_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl SettlementOutputRecoveryStatementProgramImpl of super::ISettlementOutputRecoveryStatementProgram<
        ContractState,
    > {
        fn verify_settlement_output_recovery_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            verify_settlement_output_recovery_statement_impl(serialized_settlement_witness)
        }
    }
}

#[starknet::contract]
pub mod SettlementInputMembershipStatementProgram {
    use zylith_settlement_statement::verify_settlement_input_membership_statement as verify_settlement_input_membership_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl SettlementInputMembershipStatementProgramImpl of super::ISettlementInputMembershipStatementProgram<
        ContractState,
    > {
        fn verify_settlement_input_membership_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            verify_settlement_input_membership_statement_impl(serialized_settlement_witness)
        }
    }
}

#[starknet::contract]
pub mod SettlementStatementProgram {
    use core::num::traits::Zero;
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use zylith_settlement_statement::{
        verify_settlement_input_membership_statement as verify_settlement_input_membership_statement_impl,
        verify_settlement_note_fee_statement as verify_settlement_note_fee_statement_impl,
        verify_settlement_order_statement as verify_settlement_order_statement_impl,
        verify_settlement_output_recovery_statement as verify_settlement_output_recovery_statement_impl,
    };
    use super::{
        ILiquidityPositionStatementProgramDispatcher,
        ILiquidityPositionStatementProgramDispatcherTrait,
        ISettlementInputMembershipStatementProgramDispatcher,
        ISettlementInputMembershipStatementProgramDispatcherTrait,
        ISettlementNoteFeeStatementProgramDispatcher,
        ISettlementNoteFeeStatementProgramDispatcherTrait,
        ISettlementOrderStatementProgramDispatcher, ISettlementOrderStatementProgramDispatcherTrait,
        ISettlementOutputRecoveryStatementProgramDispatcher,
        ISettlementOutputRecoveryStatementProgramDispatcherTrait,
    };

    #[storage]
    struct Storage {
        settlement_note_fee_statement_program: ContractAddress,
        settlement_order_statement_program: ContractAddress,
        settlement_input_membership_statement_program: ContractAddress,
        settlement_output_recovery_statement_program: ContractAddress,
        liquidity_position_statement_program: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        settlement_note_fee_statement_program: ContractAddress,
        settlement_order_statement_program: ContractAddress,
        settlement_input_membership_statement_program: ContractAddress,
        settlement_output_recovery_statement_program: ContractAddress,
        liquidity_position_statement_program: ContractAddress,
    ) {
        assert(!settlement_note_fee_statement_program.is_zero(), 'BAD_NOTE_FEE');
        assert(!settlement_order_statement_program.is_zero(), 'BAD_ORDER');
        assert(!settlement_input_membership_statement_program.is_zero(), 'BAD_MEMBERSHIP');
        assert(!settlement_output_recovery_statement_program.is_zero(), 'BAD_RECOVERY');
        assert(!liquidity_position_statement_program.is_zero(), 'BAD_LP_PROGRAM');
        self.settlement_note_fee_statement_program.write(settlement_note_fee_statement_program);
        self.settlement_order_statement_program.write(settlement_order_statement_program);
        self
            .settlement_input_membership_statement_program
            .write(settlement_input_membership_statement_program);
        self
            .settlement_output_recovery_statement_program
            .write(settlement_output_recovery_statement_program);
        self.liquidity_position_statement_program.write(liquidity_position_statement_program);
    }

    #[abi(embed_v0)]
    impl SettlementStatementProgramImpl of super::ISettlementStatementProgram<ContractState> {
        fn verify_settlement_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            let settlement_note_fee_statement_program =
                ISettlementNoteFeeStatementProgramDispatcher {
                contract_address: self.settlement_note_fee_statement_program.read(),
            };
            let transcript_commitment = settlement_note_fee_statement_program
                .verify_settlement_note_fee_statement(serialized_settlement_witness);
            let settlement_order_statement_program = ISettlementOrderStatementProgramDispatcher {
                contract_address: self.settlement_order_statement_program.read(),
            };
            let order_transcript_commitment = settlement_order_statement_program
                .verify_settlement_order_statement(serialized_settlement_witness);
            assert(order_transcript_commitment == transcript_commitment, 'ORDER_BINDING');
            let settlement_input_membership_statement_program =
                ISettlementInputMembershipStatementProgramDispatcher {
                contract_address: self.settlement_input_membership_statement_program.read(),
            };
            let membership_transcript_commitment = settlement_input_membership_statement_program
                .verify_settlement_input_membership_statement(serialized_settlement_witness);
            assert(membership_transcript_commitment == transcript_commitment, 'MEM_BINDING');
            let settlement_output_recovery_statement_program =
                ISettlementOutputRecoveryStatementProgramDispatcher {
                contract_address: self.settlement_output_recovery_statement_program.read(),
            };
            let recovery_transcript_commitment = settlement_output_recovery_statement_program
                .verify_settlement_output_recovery_statement(serialized_settlement_witness);
            assert(recovery_transcript_commitment == transcript_commitment, 'REC_BINDING');
            let liquidity_position_statement_program =
                ILiquidityPositionStatementProgramDispatcher {
                contract_address: self.liquidity_position_statement_program.read(),
            };
            let (liquidity_transcript_commitment, _, _, _) = liquidity_position_statement_program
                .verify_liquidity_position_statement(serialized_settlement_witness);
            assert(liquidity_transcript_commitment == transcript_commitment, 'LP_BINDING');
            transcript_commitment
        }

        fn verify_settlement_note_fee_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            verify_settlement_note_fee_statement_impl(serialized_settlement_witness)
        }

        fn verify_settlement_order_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            verify_settlement_order_statement_impl(serialized_settlement_witness)
        }

        fn verify_settlement_output_recovery_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            verify_settlement_output_recovery_statement_impl(serialized_settlement_witness)
        }

        fn verify_settlement_input_membership_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            verify_settlement_input_membership_statement_impl(serialized_settlement_witness)
        }
    }
}

#[starknet::contract]
pub mod NullifierStatementProgram {
    use zylith_settlement_statement::verify_nullifier_statement as verify_nullifier_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl NullifierStatementProgramImpl of super::INullifierStatementProgram<ContractState> {
        fn verify_nullifier_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> (felt252, felt252, felt252, felt252) {
            verify_nullifier_statement_impl(serialized_settlement_witness)
        }
    }
}

#[starknet::contract]
pub mod RenewalStatementProgram {
    use zylith_settlement_statement::verify_renewal_statement as verify_renewal_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl RenewalStatementProgramImpl of super::IRenewalStatementProgram<ContractState> {
        fn verify_renewal_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> (felt252, felt252, felt252, felt252) {
            verify_renewal_statement_impl(serialized_settlement_witness)
        }
    }
}

#[starknet::contract]
pub mod LiquidityPositionStatementProgram {
    use zylith_settlement_statement::verify_liquidity_position_statement as verify_liquidity_position_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl LiquidityPositionStatementProgramImpl of super::ILiquidityPositionStatementProgram<
        ContractState,
    > {
        fn verify_liquidity_position_statement(
            ref self: ContractState, serialized_settlement_witness: Span<felt252>,
        ) -> (felt252, felt252, felt252, felt252) {
            verify_liquidity_position_statement_impl(serialized_settlement_witness)
        }
    }
}

#[starknet::contract]
pub mod MultiPairStatementProgram {
    use zylith_settlement_statement::verify_multi_pair_statement as verify_multi_pair_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl MultiPairStatementProgramImpl of super::IMultiPairStatementProgram<ContractState> {
        fn verify_multi_pair_statement(
            ref self: ContractState, serialized_multi_pair_witness: Span<felt252>,
        ) -> felt252 {
            verify_multi_pair_statement_impl(serialized_multi_pair_witness)
        }
    }
}

#[starknet::contract]
pub mod NoteConsolidationStatementProgram {
    use zylith_settlement_statement::verify_note_consolidation_statement as verify_note_consolidation_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl NoteConsolidationStatementProgramImpl of super::INoteConsolidationStatementProgram<
        ContractState,
    > {
        fn verify_note_consolidation_statement(
            ref self: ContractState, serialized_note_consolidation_witness: Span<felt252>,
        ) -> felt252 {
            verify_note_consolidation_statement_impl(serialized_note_consolidation_witness)
        }
    }
}

#[starknet::contract]
pub mod WithdrawalStatementProgram {
    use zylith_settlement_statement::verify_withdrawal_statement as verify_withdrawal_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl WithdrawalStatementProgramImpl of super::IWithdrawalStatementProgram<ContractState> {
        fn verify_withdrawal_statement(
            ref self: ContractState, serialized_withdrawal_witness: Span<felt252>,
        ) -> felt252 {
            verify_withdrawal_statement_impl(serialized_withdrawal_witness)
        }
    }
}

#[starknet::contract]
pub mod AdmissionStatementProgram {
    use zylith_settlement_statement::verify_admission_statement as verify_admission_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl AdmissionStatementProgramImpl of super::IAdmissionStatementProgram<ContractState> {
        fn verify_admission_statement(
            ref self: ContractState, serialized_admission_witness: Span<felt252>,
        ) -> (felt252, felt252, felt252) {
            verify_admission_statement_impl(serialized_admission_witness)
        }
    }
}

#[starknet::contract]
pub mod AuctionResultStatementProgram {
    use zylith_settlement_statement::verify_auction_result_statement as verify_auction_result_statement_impl;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl AuctionResultStatementProgramImpl of super::IAuctionResultStatementProgram<ContractState> {
        fn verify_auction_result_statement(
            ref self: ContractState, serialized_private_auction_witness: Span<felt252>,
        ) -> (felt252, felt252, felt252, felt252) {
            verify_auction_result_statement_impl(serialized_private_auction_witness)
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
    use super::{
        IAdmissionStatementProgramDispatcher, IAdmissionStatementProgramDispatcherTrait,
        IAuctionResultStatementProgramDispatcher, IAuctionResultStatementProgramDispatcherTrait,
        ILiquidityPositionStatementProgramDispatcher,
        ILiquidityPositionStatementProgramDispatcherTrait, IMultiPairStatementProgramDispatcher,
        IMultiPairStatementProgramDispatcherTrait, INoteConsolidationStatementProgramDispatcher,
        INoteConsolidationStatementProgramDispatcherTrait, INullifierStatementProgramDispatcher,
        INullifierStatementProgramDispatcherTrait, IRenewalStatementProgramDispatcher,
        IRenewalStatementProgramDispatcherTrait, ISettlementStatementProgramDispatcher,
        ISettlementStatementProgramDispatcherTrait, IWithdrawalStatementProgramDispatcher,
        IWithdrawalStatementProgramDispatcherTrait,
    };

    const SETTLEMENT_MESSAGE_DOMAIN: felt252 = 'zylith_settle_v1';
    const NULLIFIER_MESSAGE_DOMAIN: felt252 = 'zylith_null_v1';
    const RENEWAL_MESSAGE_DOMAIN: felt252 = 'zylith_renew_v1';
    const LIQUIDITY_POSITION_MESSAGE_DOMAIN: felt252 = 'zylith_lp_v1';
    const SETTLEMENT_ORDER_MESSAGE_DOMAIN: felt252 = 'zylith_ord_v1';
    const SETTLEMENT_INPUT_MEMBERSHIP_MESSAGE_DOMAIN: felt252 = 'zylith_inmem_v1';
    const SETTLEMENT_OUTPUT_RECOVERY_MESSAGE_DOMAIN: felt252 = 'zylith_outrec_v1';
    const NOTE_CONSOLIDATION_MESSAGE_DOMAIN: felt252 = 'zylith_consol_v1';
    const WITHDRAWAL_MESSAGE_DOMAIN: felt252 = 'zylith_withdraw_v1';
    const ADMISSION_MESSAGE_DOMAIN: felt252 = 'zylith_admit_v1';
    const AUCTION_RESULT_MESSAGE_DOMAIN: felt252 = 'zylith_aucres_v1';
    const MULTI_PAIR_MESSAGE_DOMAIN: felt252 = 'zylith_mpair_v1';
    const SETTLEMENT_PROOF_MESSAGE_TO: felt252 = 0;
    const AGGREGATE_RETURN_DOMAIN: felt252 = 'zylith_agg_v1';

    #[storage]
    struct Storage {
        settlement_statement_program: ContractAddress,
        nullifier_statement_program: ContractAddress,
        renewal_statement_program: ContractAddress,
        liquidity_position_statement_program: ContractAddress,
        note_consolidation_statement_program: ContractAddress,
        withdrawal_statement_program: ContractAddress,
        admission_statement_program: ContractAddress,
        auction_result_statement_program: ContractAddress,
        multi_pair_statement_program: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        settlement_statement_program: ContractAddress,
        nullifier_statement_program: ContractAddress,
        renewal_statement_program: ContractAddress,
        liquidity_position_statement_program: ContractAddress,
        note_consolidation_statement_program: ContractAddress,
        withdrawal_statement_program: ContractAddress,
        admission_statement_program: ContractAddress,
        auction_result_statement_program: ContractAddress,
        multi_pair_statement_program: ContractAddress,
    ) {
        assert(!settlement_statement_program.is_zero(), 'BAD_STMT_PROGRAM');
        assert(!nullifier_statement_program.is_zero(), 'BAD_NULL_PROGRAM');
        assert(!renewal_statement_program.is_zero(), 'BAD_RENEW_PROGRAM');
        assert(!liquidity_position_statement_program.is_zero(), 'BAD_LP_PROGRAM');
        assert(!note_consolidation_statement_program.is_zero(), 'BAD_CONSOL_PROGRAM');
        assert(!withdrawal_statement_program.is_zero(), 'BAD_WITHDRAW_PROGRAM');
        assert(!admission_statement_program.is_zero(), 'BAD_ADMIT_PROGRAM');
        assert(!auction_result_statement_program.is_zero(), 'BAD_RESULT_PROGRAM');
        assert(!multi_pair_statement_program.is_zero(), 'BAD_MULTIPAIR_PROGRAM');
        self.settlement_statement_program.write(settlement_statement_program);
        self.nullifier_statement_program.write(nullifier_statement_program);
        self.renewal_statement_program.write(renewal_statement_program);
        self.liquidity_position_statement_program.write(liquidity_position_statement_program);
        self.note_consolidation_statement_program.write(note_consolidation_statement_program);
        self.withdrawal_statement_program.write(withdrawal_statement_program);
        self.admission_statement_program.write(admission_statement_program);
        self.auction_result_statement_program.write(auction_result_statement_program);
        self.multi_pair_statement_program.write(multi_pair_statement_program);
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
                .verify_settlement_note_fee_statement(serialized_settlement_witness);
            emit_settlement_proof_message(auction_verifier, transcript_commitment)
        }

        fn compile_nullifier_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let nullifier_statement_program = INullifierStatementProgramDispatcher {
                contract_address: self.nullifier_statement_program.read(),
            };
            let (
                transcript_commitment,
                prior_nullifier_root,
                consumed_nullifier_root,
                new_nullifier_root,
            ) =
                nullifier_statement_program
                .verify_nullifier_statement(serialized_settlement_witness);
            emit_nullifier_proof_message(
                auction_verifier,
                transcript_commitment,
                prior_nullifier_root,
                consumed_nullifier_root,
                new_nullifier_root,
            )
        }

        fn compile_renewal_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let renewal_statement_program = IRenewalStatementProgramDispatcher {
                contract_address: self.renewal_statement_program.read(),
            };
            let (transcript_commitment, prior_renewal_root, renewal_child_root, new_renewal_root) =
                renewal_statement_program
                .verify_renewal_statement(serialized_settlement_witness);
            emit_renewal_proof_message(
                auction_verifier,
                transcript_commitment,
                prior_renewal_root,
                renewal_child_root,
                new_renewal_root,
            )
        }

        fn compile_liquidity_position_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let (
                transcript_commitment,
                prior_liquidity_position_root,
                liquidity_position_transition_root,
                new_liquidity_position_root,
            ) =
                ILiquidityPositionStatementProgramDispatcher {
                contract_address: self.liquidity_position_statement_program.read(),
            }
                .verify_liquidity_position_statement(serialized_settlement_witness);
            emit_liquidity_position_proof_message(
                auction_verifier,
                transcript_commitment,
                prior_liquidity_position_root,
                liquidity_position_transition_root,
                new_liquidity_position_root,
            )
        }

        fn compile_settlement_order_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let settlement_statement_program = ISettlementStatementProgramDispatcher {
                contract_address: self.settlement_statement_program.read(),
            };
            let transcript_commitment = settlement_statement_program
                .verify_settlement_order_statement(serialized_settlement_witness);
            emit_settlement_order_proof_message(auction_verifier, transcript_commitment)
        }

        fn compile_settlement_input_membership_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let settlement_statement_program = ISettlementStatementProgramDispatcher {
                contract_address: self.settlement_statement_program.read(),
            };
            let transcript_commitment = settlement_statement_program
                .verify_settlement_input_membership_statement(serialized_settlement_witness);
            emit_settlement_input_membership_proof_message(auction_verifier, transcript_commitment)
        }

        fn compile_settlement_output_recovery_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_settlement_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let settlement_statement_program = ISettlementStatementProgramDispatcher {
                contract_address: self.settlement_statement_program.read(),
            };
            let transcript_commitment = settlement_statement_program
                .verify_settlement_output_recovery_statement(serialized_settlement_witness);
            emit_settlement_output_recovery_proof_message(auction_verifier, transcript_commitment)
        }

        fn compile_note_consolidation_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_note_consolidation_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let note_consolidation_statement_program =
                INoteConsolidationStatementProgramDispatcher {
                contract_address: self.note_consolidation_statement_program.read(),
            };
            let consolidation_commitment = note_consolidation_statement_program
                .verify_note_consolidation_statement(serialized_note_consolidation_witness);
            emit_note_consolidation_proof_message(auction_verifier, consolidation_commitment)
        }

        fn compile_withdrawal_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_withdrawal_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let withdrawal_statement_program = IWithdrawalStatementProgramDispatcher {
                contract_address: self.withdrawal_statement_program.read(),
            };
            let withdrawal_commitment = withdrawal_statement_program
                .verify_withdrawal_statement(serialized_withdrawal_witness);
            emit_withdrawal_proof_message(auction_verifier, withdrawal_commitment)
        }

        fn compile_admission_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_admission_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let (batch_id, order_commitment_root, admission_root) =
                IAdmissionStatementProgramDispatcher {
                contract_address: self.admission_statement_program.read(),
            }
                .verify_admission_statement(serialized_admission_witness);
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
                IAuctionResultStatementProgramDispatcher {
                contract_address: self.auction_result_statement_program.read(),
            }
                .verify_auction_result_statement(serialized_private_auction_witness);
            emit_auction_result_proof_message(
                auction_verifier,
                batch_id,
                order_commitment_root,
                admission_root,
                transcript_commitment,
            )
        }

        fn compile_multi_pair_proof(
            ref self: ContractState,
            auction_verifier: ContractAddress,
            serialized_multi_pair_witness: Span<felt252>,
        ) -> felt252 {
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let multi_pair_statement_program = IMultiPairStatementProgramDispatcher {
                contract_address: self.multi_pair_statement_program.read(),
            };
            let multi_pair_commitment = multi_pair_statement_program
                .verify_multi_pair_statement(serialized_multi_pair_witness);
            emit_multi_pair_proof_message(auction_verifier, multi_pair_commitment)
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
            let nullifier_statement_program = INullifierStatementProgramDispatcher {
                contract_address: self.nullifier_statement_program.read(),
            };
            let renewal_statement_program = IRenewalStatementProgramDispatcher {
                contract_address: self.renewal_statement_program.read(),
            };
            let liquidity_position_statement_program =
                ILiquidityPositionStatementProgramDispatcher {
                contract_address: self.liquidity_position_statement_program.read(),
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
                let (
                    nullifier_transcript_commitment,
                    prior_nullifier_root,
                    consumed_nullifier_root,
                    new_nullifier_root,
                ) =
                    nullifier_statement_program
                    .verify_nullifier_statement(witness.span());
                assert(
                    nullifier_transcript_commitment == transcript_commitment, 'NULLIFIER_BINDING',
                );
                let (
                    renewal_transcript_commitment,
                    prior_renewal_root,
                    renewal_child_root,
                    new_renewal_root,
                ) =
                    renewal_statement_program
                    .verify_renewal_statement(witness.span());
                assert(renewal_transcript_commitment == transcript_commitment, 'RENEWAL_BINDING');
                let (
                    liquidity_transcript_commitment,
                    prior_liquidity_position_root,
                    liquidity_position_transition_root,
                    new_liquidity_position_root,
                ) =
                    liquidity_position_statement_program
                    .verify_liquidity_position_statement(witness.span());
                assert(
                    liquidity_transcript_commitment == transcript_commitment, 'LIQUIDITY_BINDING',
                );
                let settlement_message = emit_settlement_proof_message(
                    auction_verifier, transcript_commitment,
                );
                let nullifier_message = emit_nullifier_proof_message(
                    auction_verifier,
                    transcript_commitment,
                    prior_nullifier_root,
                    consumed_nullifier_root,
                    new_nullifier_root,
                );
                let renewal_message = emit_renewal_proof_message(
                    auction_verifier,
                    transcript_commitment,
                    prior_renewal_root,
                    renewal_child_root,
                    new_renewal_root,
                );
                let liquidity_message = emit_liquidity_position_proof_message(
                    auction_verifier,
                    transcript_commitment,
                    prior_liquidity_position_root,
                    liquidity_position_transition_root,
                    new_liquidity_position_root,
                );
                aggregate = poseidon_hash2(aggregate, settlement_message);
                aggregate = poseidon_hash2(aggregate, nullifier_message);
                aggregate = poseidon_hash2(aggregate, renewal_message);
                aggregate = poseidon_hash2(aggregate, liquidity_message);
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

        fn withdrawal_proof_message_hash(
            self: @ContractState, auction_verifier: ContractAddress, withdrawal_commitment: felt252,
        ) -> felt252 {
            let _ = self;
            assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
            let statement_message_hash = native_withdrawal_message_hash(
                auction_verifier, withdrawal_commitment,
            );
            withdrawal_proof_message_hash_from_statement(
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

    fn emit_nullifier_proof_message(
        auction_verifier: ContractAddress,
        transcript_commitment: felt252,
        prior_nullifier_root: felt252,
        consumed_nullifier_root: felt252,
        new_nullifier_root: felt252,
    ) -> felt252 {
        let statement_message_hash = native_nullifier_message_hash(
            auction_verifier,
            transcript_commitment,
            prior_nullifier_root,
            consumed_nullifier_root,
            new_nullifier_root,
        );
        let payload = nullifier_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        nullifier_proof_message_hash_from_statement(get_contract_address(), statement_message_hash)
    }

    fn emit_renewal_proof_message(
        auction_verifier: ContractAddress,
        transcript_commitment: felt252,
        prior_renewal_root: felt252,
        renewal_child_root: felt252,
        new_renewal_root: felt252,
    ) -> felt252 {
        let statement_message_hash = native_renewal_message_hash(
            auction_verifier,
            transcript_commitment,
            prior_renewal_root,
            renewal_child_root,
            new_renewal_root,
        );
        let payload = renewal_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        renewal_proof_message_hash_from_statement(get_contract_address(), statement_message_hash)
    }

    fn emit_liquidity_position_proof_message(
        auction_verifier: ContractAddress,
        transcript_commitment: felt252,
        prior_liquidity_position_root: felt252,
        liquidity_position_transition_root: felt252,
        new_liquidity_position_root: felt252,
    ) -> felt252 {
        let statement_message_hash = native_liquidity_position_message_hash(
            auction_verifier,
            transcript_commitment,
            prior_liquidity_position_root,
            liquidity_position_transition_root,
            new_liquidity_position_root,
        );
        let payload = liquidity_position_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        liquidity_position_proof_message_hash_from_statement(
            get_contract_address(), statement_message_hash,
        )
    }

    fn emit_settlement_order_proof_message(
        auction_verifier: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let statement_message_hash = native_settlement_order_message_hash(
            auction_verifier, transcript_commitment,
        );
        let payload = settlement_order_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        settlement_order_proof_message_hash_from_statement(
            get_contract_address(), statement_message_hash,
        )
    }

    fn emit_settlement_input_membership_proof_message(
        auction_verifier: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let statement_message_hash = native_settlement_input_membership_message_hash(
            auction_verifier, transcript_commitment,
        );
        let payload = settlement_input_membership_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        settlement_input_membership_proof_message_hash_from_statement(
            get_contract_address(), statement_message_hash,
        )
    }

    fn emit_settlement_output_recovery_proof_message(
        auction_verifier: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let statement_message_hash = native_settlement_output_recovery_message_hash(
            auction_verifier, transcript_commitment,
        );
        let payload = settlement_output_recovery_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        settlement_output_recovery_proof_message_hash_from_statement(
            get_contract_address(), statement_message_hash,
        )
    }

    fn emit_note_consolidation_proof_message(
        auction_verifier: ContractAddress, consolidation_commitment: felt252,
    ) -> felt252 {
        let statement_message_hash = native_note_consolidation_message_hash(
            auction_verifier, consolidation_commitment,
        );
        let payload = note_consolidation_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        note_consolidation_proof_message_hash_from_statement(
            get_contract_address(), statement_message_hash,
        )
    }

    fn emit_withdrawal_proof_message(
        auction_verifier: ContractAddress, withdrawal_commitment: felt252,
    ) -> felt252 {
        let statement_message_hash = native_withdrawal_message_hash(
            auction_verifier, withdrawal_commitment,
        );
        let payload = withdrawal_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        withdrawal_proof_message_hash_from_statement(get_contract_address(), statement_message_hash)
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

    fn emit_multi_pair_proof_message(
        auction_verifier: ContractAddress, multi_pair_commitment: felt252,
    ) -> felt252 {
        let statement_message_hash = native_multi_pair_message_hash(
            auction_verifier, multi_pair_commitment,
        );
        let payload = multi_pair_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        multi_pair_proof_message_hash_from_statement(get_contract_address(), statement_message_hash)
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

    fn nullifier_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![NULLIFIER_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn renewal_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![RENEWAL_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn liquidity_position_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![LIQUIDITY_POSITION_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn settlement_order_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![SETTLEMENT_ORDER_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn settlement_input_membership_proof_payload(
        statement_message_hash: felt252,
    ) -> Array<felt252> {
        array![SETTLEMENT_INPUT_MEMBERSHIP_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn settlement_output_recovery_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![SETTLEMENT_OUTPUT_RECOVERY_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn note_consolidation_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![NOTE_CONSOLIDATION_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn withdrawal_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![WITHDRAWAL_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn admission_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![ADMISSION_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn auction_result_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![AUCTION_RESULT_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn multi_pair_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![MULTI_PAIR_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn settlement_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = settlement_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn nullifier_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = nullifier_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn renewal_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = renewal_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn liquidity_position_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = liquidity_position_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn settlement_order_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = settlement_order_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn settlement_input_membership_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = settlement_input_membership_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn settlement_output_recovery_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = settlement_output_recovery_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn note_consolidation_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = note_consolidation_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn withdrawal_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = withdrawal_proof_payload(statement_message_hash);
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

    fn multi_pair_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = multi_pair_proof_payload(statement_message_hash);
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

    fn native_nullifier_message_hash(
        auction_verifier_address: ContractAddress,
        transcript_commitment: felt252,
        prior_nullifier_root: felt252,
        consumed_nullifier_root: felt252,
        new_nullifier_root: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(NULLIFIER_MESSAGE_DOMAIN, auction_verifier_address.into());
        state = poseidon_hash2(state, transcript_commitment);
        state = poseidon_hash2(state, prior_nullifier_root);
        state = poseidon_hash2(state, consumed_nullifier_root);
        state = poseidon_hash2(state, new_nullifier_root);
        state
    }

    fn native_renewal_message_hash(
        auction_verifier_address: ContractAddress,
        transcript_commitment: felt252,
        prior_renewal_root: felt252,
        renewal_child_root: felt252,
        new_renewal_root: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(RENEWAL_MESSAGE_DOMAIN, auction_verifier_address.into());
        state = poseidon_hash2(state, transcript_commitment);
        state = poseidon_hash2(state, prior_renewal_root);
        state = poseidon_hash2(state, renewal_child_root);
        state = poseidon_hash2(state, new_renewal_root);
        state
    }

    fn native_liquidity_position_message_hash(
        auction_verifier_address: ContractAddress,
        transcript_commitment: felt252,
        prior_liquidity_position_root: felt252,
        liquidity_position_transition_root: felt252,
        new_liquidity_position_root: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            LIQUIDITY_POSITION_MESSAGE_DOMAIN, auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, transcript_commitment);
        state = poseidon_hash2(state, prior_liquidity_position_root);
        state = poseidon_hash2(state, liquidity_position_transition_root);
        state = poseidon_hash2(state, new_liquidity_position_root);
        state
    }

    fn native_settlement_order_message_hash(
        auction_verifier_address: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            SETTLEMENT_ORDER_MESSAGE_DOMAIN, auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, transcript_commitment);
        state
    }

    fn native_settlement_input_membership_message_hash(
        auction_verifier_address: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            SETTLEMENT_INPUT_MEMBERSHIP_MESSAGE_DOMAIN, auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, transcript_commitment);
        state
    }

    fn native_settlement_output_recovery_message_hash(
        auction_verifier_address: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            SETTLEMENT_OUTPUT_RECOVERY_MESSAGE_DOMAIN, auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, transcript_commitment);
        state
    }

    fn native_note_consolidation_message_hash(
        auction_verifier_address: ContractAddress, consolidation_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            NOTE_CONSOLIDATION_MESSAGE_DOMAIN, auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, consolidation_commitment);
        state
    }

    fn native_withdrawal_message_hash(
        auction_verifier_address: ContractAddress, withdrawal_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(WITHDRAWAL_MESSAGE_DOMAIN, auction_verifier_address.into());
        state = poseidon_hash2(state, withdrawal_commitment);
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

    fn native_multi_pair_message_hash(
        auction_verifier_address: ContractAddress, multi_pair_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(MULTI_PAIR_MESSAGE_DOMAIN, auction_verifier_address.into());
        state = poseidon_hash2(state, multi_pair_commitment);
        state
    }
}
