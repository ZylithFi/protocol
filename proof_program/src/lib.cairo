use core::poseidon::{hades_permutation, poseidon_hash_span};
use starknet::syscalls::send_message_to_l1_syscall;
use starknet::{ContractAddress, SyscallResultTrait, get_contract_address};

#[starknet::interface]
pub trait ITransitionProofProgram<TContractState> {
    fn compile_transition_proof(
        ref self: TContractState, exchange: ContractAddress, witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait IWithdrawalProofProgram<TContractState> {
    fn compile_withdrawal_proof(
        ref self: TContractState, exchange: ContractAddress, witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait IResidualRecoveryProofProgram<TContractState> {
    fn compile_residual_recovery_proof(
        ref self: TContractState, exchange: ContractAddress, witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait IProofAccount<TContractState> {
    fn public_key(self: @TContractState) -> felt252;
    fn transition_program(self: @TContractState) -> ContractAddress;
    fn withdrawal_program(self: @TContractState) -> ContractAddress;
    fn residual_recovery_program(self: @TContractState) -> ContractAddress;
}

#[starknet::contract(account)]
pub mod ProofAccount {
    use core::array::{Array, ArrayTrait};
    use core::ecdsa::check_ecdsa_signature;
    use core::num::traits::Zero;
    use starknet::account::{AccountContract, Call};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::syscalls::call_contract_syscall;
    use starknet::{ContractAddress, SyscallResultTrait, VALIDATED, get_caller_address, get_tx_info};

    #[storage]
    struct Storage {
        public_key: felt252,
        transition_program: ContractAddress,
        withdrawal_program: ContractAddress,
        residual_recovery_program: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        public_key: felt252,
        transition_program: ContractAddress,
        withdrawal_program: ContractAddress,
        residual_recovery_program: ContractAddress,
    ) {
        assert(public_key != 0, 'BAD_KEY');
        assert(!transition_program.is_zero(), 'BAD_PROGRAM');
        assert(!withdrawal_program.is_zero(), 'BAD_PROGRAM');
        assert(!residual_recovery_program.is_zero(), 'BAD_PROGRAM');
        self.public_key.write(public_key);
        self.transition_program.write(transition_program);
        self.withdrawal_program.write(withdrawal_program);
        self.residual_recovery_program.write(residual_recovery_program);
    }

    #[abi(embed_v0)]
    impl ProofAccountImpl of AccountContract<ContractState> {
        fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
            assert_allowed_call(@self, @calls);
            let tx_info = get_tx_info().unbox();
            let signature = tx_info.signature;
            assert(signature.len() == 2, 'BAD_SIGNATURE');
            assert(
                check_ecdsa_signature(
                    tx_info.transaction_hash,
                    self.public_key.read(),
                    *signature.at(0),
                    *signature.at(1),
                ),
                'BAD_SIGNATURE',
            );
            VALIDATED
        }

        fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
            assert(get_caller_address().is_zero(), 'BAD_CALLER');
            assert_allowed_call(@self, @calls);
            let call = calls.at(0);
            let mut results = ArrayTrait::new();
            results
                .append(
                    call_contract_syscall(
                        address: *call.to,
                        entry_point_selector: *call.selector,
                        calldata: *call.calldata,
                    )
                        .unwrap_syscall(),
                );
            results
        }

        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            assert(false, 'DECLARE_DISABLED');
            VALIDATED
        }
    }

    #[abi(embed_v0)]
    impl ProofAccountViews of super::IProofAccount<ContractState> {
        fn public_key(self: @ContractState) -> felt252 {
            self.public_key.read()
        }

        fn transition_program(self: @ContractState) -> ContractAddress {
            self.transition_program.read()
        }

        fn withdrawal_program(self: @ContractState) -> ContractAddress {
            self.withdrawal_program.read()
        }

        fn residual_recovery_program(self: @ContractState) -> ContractAddress {
            self.residual_recovery_program.read()
        }
    }

    fn assert_allowed_call(self: @ContractState, calls: @Array<Call>) {
        assert(calls.len() == 1, 'ONE_CALL_ONLY');
        let call = calls.at(0);
        let target = *call.to;
        let selector = *call.selector;
        assert(
            (target == self.transition_program.read()
                && selector == selector!("compile_transition_proof"))
                || (target == self.withdrawal_program.read()
                    && selector == selector!("compile_withdrawal_proof"))
                || (target == self.residual_recovery_program.read()
                    && selector == selector!("compile_residual_recovery_proof")),
            'PROOF_CALL_ONLY',
        );
    }
}

#[starknet::contract]
pub mod TransitionProofProgram {
    use core::num::traits::Zero;
    use starknet::ContractAddress;
    use zylith_exchange_statement::exchange::transition::verify_transition_statement;

    const TRANSITION_MESSAGE_DOMAIN: felt252 = 'zylith_transition_msg_v1';

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl TransitionProofProgramImpl of super::ITransitionProofProgram<ContractState> {
        fn compile_transition_proof(
            ref self: ContractState, exchange: ContractAddress, witness: Span<felt252>,
        ) -> felt252 {
            assert(!exchange.is_zero(), 'BAD_EXCHANGE');
            let commitment = verify_transition_statement(witness);
            super::emit_bound_message(TRANSITION_MESSAGE_DOMAIN, exchange, commitment)
        }
    }
}

#[starknet::contract]
pub mod WithdrawalProofProgram {
    use core::num::traits::Zero;
    use starknet::ContractAddress;
    use zylith_exchange_statement::exchange::withdrawal::verify_exchange_withdrawal_statement;

    const WITHDRAWAL_MESSAGE_DOMAIN: felt252 = 'zylith_withdraw_msg_v1';

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl WithdrawalProofProgramImpl of super::IWithdrawalProofProgram<ContractState> {
        fn compile_withdrawal_proof(
            ref self: ContractState, exchange: ContractAddress, witness: Span<felt252>,
        ) -> felt252 {
            assert(!exchange.is_zero(), 'BAD_EXCHANGE');
            let commitment = verify_exchange_withdrawal_statement(witness);
            super::emit_bound_message(WITHDRAWAL_MESSAGE_DOMAIN, exchange, commitment)
        }
    }
}

#[starknet::contract]
pub mod ResidualRecoveryProofProgram {
    use core::num::traits::Zero;
    use starknet::ContractAddress;
    use zylith_exchange_statement::exchange::residual_recovery::verify_residual_recovery_statement;

    const RESIDUAL_RECOVERY_MESSAGE_DOMAIN: felt252 = 'zylith_res_recover_msg_v1';

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl ResidualRecoveryProofProgramImpl of super::IResidualRecoveryProofProgram<ContractState> {
        fn compile_residual_recovery_proof(
            ref self: ContractState, exchange: ContractAddress, witness: Span<felt252>,
        ) -> felt252 {
            assert(!exchange.is_zero(), 'BAD_EXCHANGE');
            let commitment = verify_residual_recovery_statement(witness);
            super::emit_bound_message(RESIDUAL_RECOVERY_MESSAGE_DOMAIN, exchange, commitment)
        }
    }
}

fn poseidon2(x: felt252, y: felt252) -> felt252 {
    let (result, _, _) = hades_permutation(x, y, 2);
    result
}

// each single-purpose program emits the same domain-bound l1 message shape.
fn emit_bound_message(domain: felt252, exchange: ContractAddress, commitment: felt252) -> felt252 {
    const PROOF_MESSAGE_TO: felt252 = 0;
    let statement_message = poseidon2(poseidon2(domain, exchange.into()), commitment);
    let payload = array![domain, statement_message];
    send_message_to_l1_syscall(to_address: PROOF_MESSAGE_TO, payload: payload.span())
        .unwrap_syscall();
    let mut l1_message_data = array![get_contract_address().into(), PROOF_MESSAGE_TO];
    payload.serialize(ref l1_message_data);
    poseidon_hash_span(l1_message_data.span())
}
