use starknet::ContractAddress;

#[starknet::interface]
pub trait IDepositRouter<TContractState> {
    fn register_shielded_deposit(
        ref self: TContractState,
        asset_id: felt252,
        amount: u128,
        deposit_nonce: u64,
        note_commitment: felt252,
        withdraw_authority: ContractAddress,
    );
    fn commitment_registry_address(self: @TContractState) -> ContractAddress;
    fn shielded_asset_adapter_address(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod DepositRouter {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use zylith_protocol::commitment_registry::{
        ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
    };
    use zylith_protocol::shielded_asset_adapter::{
        IShieldedAssetAdapterDispatcher, IShieldedAssetAdapterDispatcherTrait,
    };

    #[storage]
    struct Storage {
        commitment_registry: ContractAddress,
        shielded_asset_adapter: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        commitment_registry: ContractAddress,
        shielded_asset_adapter: ContractAddress,
    ) {
        self.commitment_registry.write(commitment_registry);
        self.shielded_asset_adapter.write(shielded_asset_adapter);
    }

    #[abi(embed_v0)]
    impl DepositRouterImpl of super::IDepositRouter<ContractState> {
        fn register_shielded_deposit(
            ref self: ContractState,
            asset_id: felt252,
            amount: u128,
            deposit_nonce: u64,
            note_commitment: felt252,
            withdraw_authority: ContractAddress,
        ) {
            let owner = get_caller_address();
            assert(owner == withdraw_authority, 'WITHDRAW_AUTH_MISMATCH');
            let commitment_registry = ICommitmentRegistryDispatcher {
                contract_address: self.commitment_registry.read(),
            };
            let shielded_asset_adapter = IShieldedAssetAdapterDispatcher {
                contract_address: self.shielded_asset_adapter.read(),
            };
            shielded_asset_adapter.register_erc20_deposit(
                owner, asset_id, amount, deposit_nonce, note_commitment, withdraw_authority,
            );
            commitment_registry.register_deposit_note_commitment(note_commitment);
        }

        fn commitment_registry_address(self: @ContractState) -> ContractAddress {
            self.commitment_registry.read()
        }

        fn shielded_asset_adapter_address(self: @ContractState) -> ContractAddress {
            self.shielded_asset_adapter.read()
        }
    }
}
