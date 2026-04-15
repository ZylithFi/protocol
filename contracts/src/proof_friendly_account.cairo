#[starknet::contract(account)]
pub mod ProofFriendlyAccount {
    use core::array::{ArrayTrait, SpanTrait};
    use core::ecdsa::check_ecdsa_signature;
    use core::num::traits::Zero;
    use core::poseidon::hades_permutation;
    use starknet::account::Call;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, SyscallResultTrait};

    const ACCOUNT_DOMAIN: felt252 = 'zyl_pfa_v1';
    const CALL_DOMAIN: felt252 = 'zyl_pfa_call';
    const CALLDATA_DOMAIN: felt252 = 'zyl_pfa_data';
    const RESOURCE_BOUNDS_DOMAIN: felt252 = 'zyl_pfa_res';
    const DECLARE_DOMAIN: felt252 = 'zyl_pfa_decl';
    const DEPLOY_DOMAIN: felt252 = 'zyl_pfa_deploy';
    const EXECUTION_VERSION: felt252 = 3;
    const RESOURCE_L1_GAS: felt252 = 'L1_GAS';
    const RESOURCE_L2_GAS: felt252 = 'L2_GAS';
    const RESOURCE_L1_DATA: felt252 = 'L1_DATA';

    #[storage]
    struct Storage {
        public_key: felt252,
        allowed_target: ContractAddress,
        allowed_selector: felt252,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        public_key: felt252,
        allowed_target: ContractAddress,
        allowed_selector: felt252,
    ) {
        self.public_key.write(public_key);
        self.allowed_target.write(allowed_target);
        self.allowed_selector.write(allowed_selector);
    }

    #[external(v0)]
    fn __validate_deploy__(
        self: @ContractState,
        class_hash: felt252,
        contract_address_salt: felt252,
        public_key: felt252,
        allowed_target: ContractAddress,
        allowed_selector: felt252,
    ) -> felt252 {
        let tx_info = starknet::get_tx_info().unbox();
        validate_static_context(
            tx_info.version,
            tx_info.max_fee,
            tx_info.tip,
            tx_info.paymaster_data,
            tx_info.account_deployment_data,
            tx_info.nonce_data_availability_mode,
            tx_info.fee_data_availability_mode,
            tx_info.resource_bounds,
        );
        let message_hash = deploy_message_hash(
            tx_info.account_contract_address,
            tx_info.chain_id,
            tx_info.nonce,
            class_hash,
            contract_address_salt,
            public_key,
            allowed_target,
            allowed_selector,
        );
        assert_signature(message_hash, public_key, tx_info.signature);
        starknet::VALIDATED
    }

    #[external(v0)]
    fn get_public_key(self: @ContractState) -> felt252 {
        self.public_key.read()
    }

    #[external(v0)]
    fn get_allowed_target(self: @ContractState) -> ContractAddress {
        self.allowed_target.read()
    }

    #[external(v0)]
    fn get_allowed_selector(self: @ContractState) -> felt252 {
        self.allowed_selector.read()
    }

    #[external(v0)]
    fn is_valid_signature(
        self: @ContractState, hash: felt252, signature: Array<felt252>,
    ) -> felt252 {
        assert_signature(hash, self.public_key.read(), signature.span());
        starknet::VALIDATED
    }

    #[abi(embed_v0)]
    impl ProofFriendlyAccountImpl of starknet::account::AccountContract<ContractState> {
        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            validate_static_context(
                tx_info.version,
                tx_info.max_fee,
                tx_info.tip,
                tx_info.paymaster_data,
                tx_info.account_deployment_data,
                tx_info.nonce_data_availability_mode,
                tx_info.fee_data_availability_mode,
                tx_info.resource_bounds,
            );
            let message_hash = declare_message_hash(
                starknet::get_contract_address(),
                tx_info.chain_id,
                tx_info.nonce,
                class_hash,
            );
            assert_signature(message_hash, self.public_key.read(), tx_info.signature);
            starknet::VALIDATED
        }

        fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            validate_static_context(
                tx_info.version,
                tx_info.max_fee,
                tx_info.tip,
                tx_info.paymaster_data,
                tx_info.account_deployment_data,
                tx_info.nonce_data_availability_mode,
                tx_info.fee_data_availability_mode,
                tx_info.resource_bounds,
            );
            let call_hash = validate_single_allowed_call(@self, calls.span());
            let message_hash = invoke_message_hash(
                tx_info.account_contract_address,
                tx_info.chain_id,
                tx_info.nonce,
                call_hash,
            );
            assert_signature(message_hash, self.public_key.read(), tx_info.signature);
            starknet::VALIDATED
        }

        fn __execute__(ref self: ContractState, mut calls: Array<Call>) -> Array<Span<felt252>> {
            assert(starknet::get_caller_address().is_zero(), 'INVALID_CALLER');

            let tx_info = starknet::get_tx_info().unbox();
            assert(tx_info.version == EXECUTION_VERSION, 'INVALID_TX_VERSION');
            assert(calls.len() == 1, 'MULTI_CALL_NOT_SUPPORTED');

            let mut results = array![];
            loop {
                match calls.pop_front() {
                    Option::Some(call) => {
                        let return_data = starknet::syscalls::call_contract_syscall(
                            call.to,
                            call.selector,
                            call.calldata,
                        )
                            .unwrap_syscall();
                        results.append(return_data);
                    },
                    Option::None => {
                        break;
                    },
                }
            };
            results
        }
    }

    fn validate_single_allowed_call(
        self: @ContractState, calls: Span<Call>,
    ) -> felt252 {
        assert(calls.len() == 1, 'MULTI_CALL_NOT_SUPPORTED');
        let call = *calls.at(0);
        assert(call.to == self.allowed_target.read(), 'INVALID_TARGET');
        assert(call.selector == self.allowed_selector.read(), 'INVALID_SELECTOR');
        call_message_hash(call)
    }

    fn validate_static_context(
        version: felt252,
        max_fee: u128,
        tip: u128,
        paymaster_data: Span<felt252>,
        account_deployment_data: Span<felt252>,
        nonce_data_availability_mode: u32,
        fee_data_availability_mode: u32,
        resource_bounds: Span<starknet::ResourcesBounds>,
    ) {
        assert(version == EXECUTION_VERSION, 'INVALID_TX_VERSION');
        assert(max_fee == 0, 'INVALID_MAX_FEE');
        assert(tip == 0, 'INVALID_TIP');
        assert(paymaster_data.len() == 0, 'PAYMASTER_UNSUPPORTED');
        assert(account_deployment_data.len() == 0, 'ACCOUNT_DEPLOY_UNSUPPORTED');
        assert(nonce_data_availability_mode == 0_u32, 'INVALID_NONCE_DA');
        assert(fee_data_availability_mode == 0_u32, 'INVALID_FEE_DA');
        assert(resource_bounds.len() == 3, 'INVALID_RESOURCE_BOUNDS');
    }

    fn assert_signature(message_hash: felt252, public_key: felt252, signature: Span<felt252>) {
        assert(signature.len() == 2, 'INVALID_SIGNATURE_LENGTH');
        assert(
            check_ecdsa_signature(
                message_hash, public_key, *signature.at(0), *signature.at(1),
            ),
            'INVALID_SIGNATURE',
        );
    }

    fn invoke_message_hash(
        account_contract_address: ContractAddress,
        chain_id: felt252,
        nonce: felt252,
        call_hash: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(ACCOUNT_DOMAIN, EXECUTION_VERSION);
        state = poseidon_hash2(state, account_contract_address.into());
        state = poseidon_hash2(state, chain_id);
        state = poseidon_hash2(state, nonce);
        state = poseidon_hash2(state, call_hash);
        state
    }

    fn resource_bounds_hash(resource_bounds: Span<starknet::ResourcesBounds>) -> felt252 {
        assert(resource_bounds.len() == 3, 'INVALID_RESOURCE_BOUNDS');

        let mut seen_l1 = false;
        let mut seen_l2 = false;
        let mut seen_l1_data = false;
        let mut l1_hash = 0;
        let mut l2_hash = 0;
        let mut l1_data_hash = 0;

        let mut index = 0;
        while index < resource_bounds.len() {
            let bound = *resource_bounds.at(index);
            let bound_hash = resource_bound_hash(bound.resource, bound.max_amount, bound.max_price_per_unit);
            if bound.resource == RESOURCE_L1_GAS {
                assert(!seen_l1, 'DUP_RESOURCE_BOUND');
                seen_l1 = true;
                l1_hash = bound_hash;
            } else if bound.resource == RESOURCE_L2_GAS {
                assert(!seen_l2, 'DUP_RESOURCE_BOUND');
                seen_l2 = true;
                l2_hash = bound_hash;
            } else if bound.resource == RESOURCE_L1_DATA {
                assert(!seen_l1_data, 'DUP_RESOURCE_BOUND');
                seen_l1_data = true;
                l1_data_hash = bound_hash;
            } else {
                assert(1 == 0, 'INVALID_RESOURCE_BOUND');
            };
            index += 1;
        };

        assert(seen_l1, 'MISSING_L1_GAS_BOUND');
        assert(seen_l2, 'MISSING_L2_GAS_BOUND');
        assert(seen_l1_data, 'MISSING_L1_DATA_BOUND');

        let mut state = poseidon_hash2(RESOURCE_BOUNDS_DOMAIN, l1_hash);
        state = poseidon_hash2(state, l2_hash);
        state = poseidon_hash2(state, l1_data_hash);
        state
    }

    fn resource_bound_hash(resource: felt252, max_amount: u64, max_price_per_unit: u128) -> felt252 {
        let mut state = poseidon_hash2(resource, max_amount.into());
        state = poseidon_hash2(state, max_price_per_unit.into());
        state
    }

    fn declare_message_hash(
        account_contract_address: ContractAddress,
        chain_id: felt252,
        nonce: felt252,
        class_hash: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(DECLARE_DOMAIN, EXECUTION_VERSION);
        state = poseidon_hash2(state, account_contract_address.into());
        state = poseidon_hash2(state, chain_id);
        state = poseidon_hash2(state, nonce);
        state = poseidon_hash2(state, class_hash);
        state
    }

    fn deploy_message_hash(
        account_contract_address: ContractAddress,
        chain_id: felt252,
        nonce: felt252,
        class_hash: felt252,
        contract_address_salt: felt252,
        public_key: felt252,
        allowed_target: ContractAddress,
        allowed_selector: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(DEPLOY_DOMAIN, EXECUTION_VERSION);
        state = poseidon_hash2(state, account_contract_address.into());
        state = poseidon_hash2(state, chain_id);
        state = poseidon_hash2(state, nonce);
        state = poseidon_hash2(state, class_hash);
        state = poseidon_hash2(state, contract_address_salt);
        state = poseidon_hash2(state, public_key);
        state = poseidon_hash2(state, allowed_target.into());
        state = poseidon_hash2(state, allowed_selector);
        state
    }

    fn call_message_hash(call: Call) -> felt252 {
        let mut state = poseidon_hash2(CALL_DOMAIN, call.to.into());
        state = poseidon_hash2(state, call.selector);
        state = poseidon_hash2(state, calldata_message_hash(call.calldata));
        state
    }

    fn calldata_message_hash(calldata: Span<felt252>) -> felt252 {
        let mut state = poseidon_hash2(CALLDATA_DOMAIN, calldata.len().into());
        let mut index = 0;
        while index < calldata.len() {
            state = poseidon_hash2(state, *calldata.at(index));
            index += 1;
        };
        state
    }

    fn poseidon_hash2(x: felt252, y: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(x, y, 2);
        result
    }
}
