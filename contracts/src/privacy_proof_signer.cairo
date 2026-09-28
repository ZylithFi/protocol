#[starknet::interface]
pub trait IPrivacyProofSigner<TContractState> {
    fn signer_public_key(self: @TContractState) -> felt252;
    fn relay_message_hash(
        self: @TContractState, calls: Span<starknet::account::Call>, nonce: felt252,
    ) -> felt252;
    fn relay_nonce_used(self: @TContractState, nonce: felt252) -> bool;
    fn execute_from_relayer(
        ref self: TContractState,
        calls: Span<starknet::account::Call>,
        nonce: felt252,
        signature_r: felt252,
        signature_s: felt252,
    );
    fn is_valid_signature(
        self: @TContractState, hash: felt252, signature: Array<felt252>,
    ) -> felt252;
}

#[starknet::contract]
pub mod PrivacyProofSigner {
    use core::array::{Array, SpanTrait};
    use core::ecdsa::check_ecdsa_signature;
    use core::poseidon::hades_permutation;
    use starknet::account::Call;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::syscalls::call_contract_syscall;
    use starknet::{SyscallResultTrait, VALIDATED, get_contract_address, get_tx_info};

    const RELAY_MESSAGE_DOMAIN: felt252 = 'zylith_privacy_relay_v1';

    #[storage]
    struct Storage {
        signer_public_key: felt252,
        relay_nonce_used: Map<felt252, bool>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, signer_public_key: felt252) {
        assert(signer_public_key != 0, 'BAD_SIGNER');
        self.signer_public_key.write(signer_public_key);
    }

    #[abi(embed_v0)]
    impl PrivacyProofSignerImpl of super::IPrivacyProofSigner<ContractState> {
        fn signer_public_key(self: @ContractState) -> felt252 {
            self.signer_public_key.read()
        }

        fn relay_message_hash(self: @ContractState, calls: Span<Call>, nonce: felt252) -> felt252 {
            relay_message_hash(calls, nonce)
        }

        fn relay_nonce_used(self: @ContractState, nonce: felt252) -> bool {
            self.relay_nonce_used.read(nonce)
        }

        fn execute_from_relayer(
            ref self: ContractState,
            calls: Span<Call>,
            nonce: felt252,
            signature_r: felt252,
            signature_s: felt252,
        ) {
            assert(calls.len() > 0, 'EMPTY_RELAY_CALLS');
            assert(!self.relay_nonce_used.read(nonce), 'RELAY_NONCE_USED');
            assert(signature_r != 0, 'BAD_RELAY_SIG');
            assert(signature_s != 0, 'BAD_RELAY_SIG');
            let public_key = self.signer_public_key.read();
            assert(
                check_ecdsa_signature(
                    relay_message_hash(calls, nonce), public_key, signature_r, signature_s,
                ),
                'BAD_RELAY_SIG',
            );
            self.relay_nonce_used.write(nonce, true);
            for call in calls {
                let calldata = *call.calldata;
                call_contract_syscall(
                    address: *call.to, entry_point_selector: *call.selector, calldata: calldata,
                )
                    .unwrap_syscall();
            }
        }

        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            let signature_span = signature.span();
            if signature_span.len() != 2 {
                return 0;
            }
            let signature_r = *signature_span.at(0);
            let signature_s = *signature_span.at(1);
            if signature_r == 0 || signature_s == 0 {
                return 0;
            }
            let public_key = self.signer_public_key.read();
            if check_ecdsa_signature(hash, public_key, signature_r, signature_s) {
                VALIDATED
            } else {
                0
            }
        }
    }

    fn relay_message_hash(calls: Span<Call>, nonce: felt252) -> felt252 {
        let tx_info = get_tx_info().unbox();
        let mut state = poseidon_hash2(RELAY_MESSAGE_DOMAIN, tx_info.chain_id);
        state = poseidon_hash2(state, get_contract_address().into());
        state = poseidon_hash2(state, nonce);
        state = poseidon_hash2(state, calls.len().into());
        for call in calls {
            state = poseidon_hash2(state, (*call.to).into());
            state = poseidon_hash2(state, *call.selector);
            let calldata = *call.calldata;
            state = poseidon_hash2(state, calldata.len().into());
            let mut index = 0;
            loop {
                if index == calldata.len() {
                    break;
                }
                state = poseidon_hash2(state, *calldata.at(index));
                index += 1;
            }
        }
        state
    }

    fn poseidon_hash2(x: felt252, y: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(x, y, 2);
        result
    }
}
