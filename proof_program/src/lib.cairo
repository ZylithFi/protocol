use starknet::ContractAddress;

/// the one program the network proves. each entrypoint runs its statement inside this class (no
/// cross-contract call, so the witness is never re-serialized) and emits the message the
/// exchange contract finds in the transaction's proof facts: `[domain, h(h(domain, exchange),
/// commitment)]`.
#[starknet::interface]
pub trait IExchangeProofProgram<TContractState> {
    fn compile_transition_proof(
        ref self: TContractState, exchange: ContractAddress, witness: Span<felt252>,
    ) -> felt252;
    fn compile_withdrawal_proof(
        ref self: TContractState, exchange: ContractAddress, witness: Span<felt252>,
    ) -> felt252;
    fn compile_residual_recovery_proof(
        ref self: TContractState, exchange: ContractAddress, witness: Span<felt252>,
    ) -> felt252;
}

#[starknet::contract]
pub mod ExchangeProofProgram {
    use core::num::traits::Zero;
    use core::poseidon::{hades_permutation, poseidon_hash_span};
    use starknet::syscalls::send_message_to_l1_syscall;
    use starknet::{ContractAddress, SyscallResultTrait, get_contract_address};
    use zylith_exchange_statement::exchange::residual_recovery::verify_residual_recovery_statement;
    use zylith_exchange_statement::exchange::transition::verify_transition_statement;
    use zylith_exchange_statement::exchange::withdrawal::verify_exchange_withdrawal_statement;

    pub const TRANSITION_MESSAGE_DOMAIN: felt252 = 'zylith_transition_msg_v1';
    pub const WITHDRAWAL_MESSAGE_DOMAIN: felt252 = 'zylith_withdraw_msg_v1';
    pub const RESIDUAL_RECOVERY_MESSAGE_DOMAIN: felt252 = 'zylith_res_recover_msg_v1';
    const PROOF_MESSAGE_TO: felt252 = 0;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl ExchangeProofProgramImpl of super::IExchangeProofProgram<ContractState> {
        fn compile_transition_proof(
            ref self: ContractState, exchange: ContractAddress, witness: Span<felt252>,
        ) -> felt252 {
            assert(!exchange.is_zero(), 'BAD_EXCHANGE');
            let commitment = verify_transition_statement(witness);
            emit_bound_message(TRANSITION_MESSAGE_DOMAIN, exchange, commitment)
        }

        fn compile_withdrawal_proof(
            ref self: ContractState, exchange: ContractAddress, witness: Span<felt252>,
        ) -> felt252 {
            assert(!exchange.is_zero(), 'BAD_EXCHANGE');
            let commitment = verify_exchange_withdrawal_statement(witness);
            emit_bound_message(WITHDRAWAL_MESSAGE_DOMAIN, exchange, commitment)
        }

        fn compile_residual_recovery_proof(
            ref self: ContractState, exchange: ContractAddress, witness: Span<felt252>,
        ) -> felt252 {
            assert(!exchange.is_zero(), 'BAD_EXCHANGE');
            let commitment = verify_residual_recovery_statement(witness);
            emit_bound_message(RESIDUAL_RECOVERY_MESSAGE_DOMAIN, exchange, commitment)
        }
    }

    fn poseidon2(x: felt252, y: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(x, y, 2);
        result
    }

    /// sends `[domain, h(h(domain, exchange), commitment)]` to l1 and returns the hash the proof
    /// facts carry for it.
    fn emit_bound_message(
        domain: felt252, exchange: ContractAddress, commitment: felt252,
    ) -> felt252 {
        let statement_message = poseidon2(poseidon2(domain, exchange.into()), commitment);
        let payload = array![domain, statement_message];
        send_message_to_l1_syscall(to_address: PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        let mut l1_message_data = array![get_contract_address().into(), PROOF_MESSAGE_TO];
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }
}
