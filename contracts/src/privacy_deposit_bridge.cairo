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
        asset_id: felt252,
        total_amount: u128,
        amounts: Span<u128>,
        deposit_nonces: Span<u64>,
        note_commitments: Span<felt252>,
        withdraw_authorities: Span<felt252>,
    ) -> Span<OpenNoteDeposit>;
    fn register_privacy_deposit(
        ref self: TContractState,
        asset_id: felt252,
        amount: u128,
        deposit_nonce: u64,
        note_commitment: felt252,
        withdraw_authority: felt252,
    );
    fn register_privacy_deposit_batch(
        ref self: TContractState,
        asset_id: felt252,
        total_amount: u128,
        amounts: Span<u128>,
        deposit_nonces: Span<u64>,
        note_commitments: Span<felt252>,
        withdraw_authorities: Span<felt252>,
    );
    fn commitment_registry_address(self: @TContractState) -> ContractAddress;
    fn shielded_asset_adapter_address(self: @TContractState) -> ContractAddress;
    fn privacy_pool_address(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PrivacyDepositBridge {
    use core::integer::u256;
    use core::num::traits::Zero;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use zylith_protocol::commitment_registry::{
        ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
    };
    use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
    use zylith_protocol::shielded_asset_adapter::{
        IShieldedAssetAdapterDispatcher, IShieldedAssetAdapterDispatcherTrait,
    };

    #[storage]
    struct Storage {
        commitment_registry: ContractAddress,
        shielded_asset_adapter: ContractAddress,
        privacy_pool: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        commitment_registry: ContractAddress,
        shielded_asset_adapter: ContractAddress,
        privacy_pool: ContractAddress,
    ) {
        assert(!commitment_registry.is_zero(), 'BAD_REGISTRY');
        assert(!shielded_asset_adapter.is_zero(), 'BAD_ADAPTER');
        assert(!privacy_pool.is_zero(), 'BAD_PRIVACY_POOL');
        self.commitment_registry.write(commitment_registry);
        self.shielded_asset_adapter.write(shielded_asset_adapter);
        self.privacy_pool.write(privacy_pool);
    }

    #[abi(embed_v0)]
    impl PrivacyDepositBridgeImpl of super::IPrivacyDepositBridge<ContractState> {
        fn privacy_invoke(
            ref self: ContractState,
            asset_id: felt252,
            total_amount: u128,
            amounts: Span<u128>,
            deposit_nonces: Span<u64>,
            note_commitments: Span<felt252>,
            withdraw_authorities: Span<felt252>,
        ) -> Span<super::OpenNoteDeposit> {
            register_privacy_deposit_batch_internal(
                ref self,
                asset_id,
                total_amount,
                amounts,
                deposit_nonces,
                note_commitments,
                withdraw_authorities,
            );
            [].span()
        }

        fn register_privacy_deposit(
            ref self: ContractState,
            asset_id: felt252,
            amount: u128,
            deposit_nonce: u64,
            note_commitment: felt252,
            withdraw_authority: felt252,
        ) {
            register_privacy_deposit_internal(
                ref self, asset_id, amount, deposit_nonce, note_commitment, withdraw_authority,
            );
        }

        fn register_privacy_deposit_batch(
            ref self: ContractState,
            asset_id: felt252,
            total_amount: u128,
            amounts: Span<u128>,
            deposit_nonces: Span<u64>,
            note_commitments: Span<felt252>,
            withdraw_authorities: Span<felt252>,
        ) {
            register_privacy_deposit_batch_internal(
                ref self,
                asset_id,
                total_amount,
                amounts,
                deposit_nonces,
                note_commitments,
                withdraw_authorities,
            );
        }

        fn commitment_registry_address(self: @ContractState) -> ContractAddress {
            self.commitment_registry.read()
        }

        fn shielded_asset_adapter_address(self: @ContractState) -> ContractAddress {
            self.shielded_asset_adapter.read()
        }

        fn privacy_pool_address(self: @ContractState) -> ContractAddress {
            self.privacy_pool.read()
        }
    }

    fn as_u256(amount: u128) -> u256 {
        u256 { low: amount, high: 0 }
    }

    fn register_privacy_deposit_internal(
        ref self: ContractState,
        asset_id: felt252,
        amount: u128,
        deposit_nonce: u64,
        note_commitment: felt252,
        withdraw_authority: felt252,
    ) {
        assert(amount > 0, 'BAD_AMOUNT');
        assert(note_commitment != 0, 'BAD_COMMITMENT');
        assert(withdraw_authority != 0, 'BAD_AUTHORITY');
        assert(get_caller_address() == self.privacy_pool.read(), 'BAD_PRIVACY_CALLER');

        let bridge = get_contract_address();
        let commitment_registry = ICommitmentRegistryDispatcher {
            contract_address: self.commitment_registry.read(),
        };
        let shielded_asset_adapter = IShieldedAssetAdapterDispatcher {
            contract_address: self.shielded_asset_adapter.read(),
        };
        let token_address = shielded_asset_adapter.asset_token(asset_id);
        assert(!token_address.is_zero(), 'UNSUPPORTED_ASSET');

        let token = IERC20Dispatcher { contract_address: token_address };
        token.approve(self.shielded_asset_adapter.read(), as_u256(amount));
        shielded_asset_adapter
            .register_erc20_deposit(
                bridge, asset_id, amount, deposit_nonce, note_commitment, withdraw_authority,
            );
        commitment_registry.register_deposit_note_commitment(note_commitment);
    }

    fn register_privacy_deposit_batch_internal(
        ref self: ContractState,
        asset_id: felt252,
        total_amount: u128,
        amounts: Span<u128>,
        deposit_nonces: Span<u64>,
        note_commitments: Span<felt252>,
        withdraw_authorities: Span<felt252>,
    ) {
        assert(total_amount > 0, 'BAD_AMOUNT');
        assert(get_caller_address() == self.privacy_pool.read(), 'BAD_PRIVACY_CALLER');
        let len = amounts.len();
        assert(len > 0, 'EMPTY_BATCH');
        assert(len <= 16, 'TOO_MANY_NOTES');
        assert(deposit_nonces.len() == len, 'BAD_BATCH_LENGTH');
        assert(note_commitments.len() == len, 'BAD_BATCH_LENGTH');
        assert(withdraw_authorities.len() == len, 'BAD_BATCH_LENGTH');

        let mut computed_total: u128 = 0;
        let mut index = 0;
        loop {
            if index == len {
                break;
            }
            let amount = *amounts.at(index);
            let note_commitment = *note_commitments.at(index);
            let withdraw_authority = *withdraw_authorities.at(index);
            assert(amount > 0, 'BAD_AMOUNT');
            assert(note_commitment != 0, 'BAD_COMMITMENT');
            assert(withdraw_authority != 0, 'BAD_AUTHORITY');
            computed_total = computed_total + amount;
            index += 1;
        }
        assert(computed_total == total_amount, 'BAD_TOTAL_AMOUNT');

        let bridge = get_contract_address();
        let commitment_registry = ICommitmentRegistryDispatcher {
            contract_address: self.commitment_registry.read(),
        };
        let shielded_asset_adapter = IShieldedAssetAdapterDispatcher {
            contract_address: self.shielded_asset_adapter.read(),
        };
        let token_address = shielded_asset_adapter.asset_token(asset_id);
        assert(!token_address.is_zero(), 'UNSUPPORTED_ASSET');

        let token = IERC20Dispatcher { contract_address: token_address };
        token.approve(self.shielded_asset_adapter.read(), as_u256(total_amount));
        shielded_asset_adapter
            .register_erc20_deposit_batch(
                bridge,
                asset_id,
                total_amount,
                amounts,
                deposit_nonces,
                note_commitments,
                withdraw_authorities,
            );

        let mut commitment_index = 0;
        loop {
            if commitment_index == len {
                break;
            }
            commitment_registry
                .register_deposit_note_commitment(*note_commitments.at(commitment_index));
            commitment_index += 1;
        };
    }
}
