#[starknet::interface]
pub trait IPrivacyProofSigner<TContractState> {
    fn signer_public_key(self: @TContractState) -> felt252;
    fn is_valid_signature(
        self: @TContractState, hash: felt252, signature: Array<felt252>,
    ) -> felt252;
}

#[starknet::contract]
pub mod PrivacyProofSigner {
    use core::array::{Array, SpanTrait};
    use core::ecdsa::check_ecdsa_signature;
    use starknet::VALIDATED;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        signer_public_key: felt252,
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
}
