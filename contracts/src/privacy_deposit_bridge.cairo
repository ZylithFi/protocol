use starknet::ContractAddress;

#[derive(Copy, Drop, Serde)]
pub struct OpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

#[starknet::interface]
pub trait IPrivacyDepositBridge<TContractState> {
    fn privacy_invoke(
        ref self: TContractState,
        funding_commitments: Span<felt252>,
        deposit_roots: Span<felt252>,
        encrypted_note_activations: Span<felt252>,
    ) -> Span<OpenNoteDeposit>;
    fn register_funding_activation(
        ref self: TContractState,
        funding_commitments: Span<felt252>,
        deposit_roots: Span<felt252>,
        encrypted_note_activations: Span<felt252>,
    );
    fn commitment_registry_address(self: @TContractState) -> ContractAddress;
    fn privacy_pool_address(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PrivacyDepositBridge {
    use core::num::traits::Zero;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_caller_address};
    use zylith_protocol::commitment_registry::{
        ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
    };

    #[storage]
    struct Storage {
        commitment_registry: ContractAddress,
        privacy_pool: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        commitment_registry: ContractAddress,
        privacy_pool: ContractAddress,
    ) {
        assert(!commitment_registry.is_zero(), 'BAD_REGISTRY');
        assert(!privacy_pool.is_zero(), 'BAD_PRIVACY_POOL');
        self.commitment_registry.write(commitment_registry);
        self.privacy_pool.write(privacy_pool);
    }

    #[abi(embed_v0)]
    impl PrivacyDepositBridgeImpl of super::IPrivacyDepositBridge<ContractState> {
        fn privacy_invoke(
            ref self: ContractState,
            funding_commitments: Span<felt252>,
            deposit_roots: Span<felt252>,
            encrypted_note_activations: Span<felt252>,
        ) -> Span<super::OpenNoteDeposit> {
            register_funding_activation_internal(
                ref self, funding_commitments, deposit_roots, encrypted_note_activations,
            );
            [].span()
        }

        fn register_funding_activation(
            ref self: ContractState,
            funding_commitments: Span<felt252>,
            deposit_roots: Span<felt252>,
            encrypted_note_activations: Span<felt252>,
        ) {
            register_funding_activation_internal(
                ref self, funding_commitments, deposit_roots, encrypted_note_activations,
            );
        }

        fn commitment_registry_address(self: @ContractState) -> ContractAddress {
            self.commitment_registry.read()
        }

        fn privacy_pool_address(self: @ContractState) -> ContractAddress {
            self.privacy_pool.read()
        }
    }

    fn register_funding_activation_internal(
        ref self: ContractState,
        funding_commitments: Span<felt252>,
        deposit_roots: Span<felt252>,
        encrypted_note_activations: Span<felt252>,
    ) {
        assert(get_caller_address() == self.privacy_pool.read(), 'BAD_PRIVACY_CALLER');
        let len = funding_commitments.len();
        assert(len > 0, 'EMPTY_ACTIVATION');
        assert(len <= 16, 'TOO_MANY_ACTIVATIONS');
        assert(deposit_roots.len() == len, 'BAD_ACTIVATION_LEN');
        assert(encrypted_note_activations.len() == len, 'BAD_ACTIVATION_LEN');
        let commitment_registry = ICommitmentRegistryDispatcher {
            contract_address: self.commitment_registry.read(),
        };
        let mut index = 0;
        loop {
            if index == len {
                break;
            }
            let funding_commitment = *funding_commitments.at(index);
            let deposit_root = *deposit_roots.at(index);
            let encrypted_note_activation = *encrypted_note_activations.at(index);
            assert(funding_commitment != 0, 'BAD_FUNDING');
            assert(deposit_root != 0, 'BAD_DEPOSIT_ROOT');
            assert(encrypted_note_activation != 0, 'BAD_ACTIVATION');
            let mut duplicate_index = index + 1;
            loop {
                if duplicate_index == len {
                    break;
                }
                assert(
                    funding_commitment != *funding_commitments.at(duplicate_index),
                    'DUPLICATE_FUNDING',
                );
                assert(deposit_root != *deposit_roots.at(duplicate_index), 'DUPLICATE_ROOT');
                duplicate_index += 1;
            }
            commitment_registry
                .register_funding_activation(
                    funding_commitment, deposit_root, encrypted_note_activation,
                );
            index += 1;
        };
    }
}
