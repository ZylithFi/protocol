use starknet::ContractAddress;

#[starknet::interface]
pub trait IFeeLedger<TContractState> {
    fn set_auction_verifier(ref self: TContractState, verifier: ContractAddress);
    fn set_shielded_asset_adapter(ref self: TContractState, adapter: ContractAddress);
    fn accrue_fees(
        ref self: TContractState,
        asset_ids: Span<felt252>,
        recipients: Span<felt252>,
        amounts: Span<u128>,
    );
    fn claim_fees(
        ref self: TContractState,
        asset_id: felt252,
        fee_recipient: felt252,
        amount: u128,
        token_recipient: ContractAddress,
    );
    fn accrued_fee(self: @TContractState, asset_id: felt252, recipient: felt252) -> u128;
    fn auction_verifier_address(self: @TContractState) -> ContractAddress;
    fn shielded_asset_adapter_address(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod FeeLedger {
    use core::num::traits::Zero;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};
    use zylith_protocol::shielded_asset_adapter::{
        IShieldedAssetAdapterDispatcher, IShieldedAssetAdapterDispatcherTrait,
    };

    #[storage]
    struct Storage {
        admin: ContractAddress,
        auction_verifier: ContractAddress,
        shielded_asset_adapter: ContractAddress,
        accrued_fees: Map<(felt252, felt252), u128>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        assert(!admin.is_zero(), 'BAD_ADMIN');
        self.admin.write(admin);
    }

    #[abi(embed_v0)]
    impl FeeLedgerImpl of super::IFeeLedger<ContractState> {
        fn set_auction_verifier(ref self: ContractState, verifier: ContractAddress) {
            assert_admin(@self);
            assert(!verifier.is_zero(), 'BAD_AUCTION_VERIFIER');
            self.auction_verifier.write(verifier);
        }

        fn set_shielded_asset_adapter(ref self: ContractState, adapter: ContractAddress) {
            assert_admin(@self);
            assert(!adapter.is_zero(), 'BAD_ADAPTER');
            self.shielded_asset_adapter.write(adapter);
        }

        fn accrue_fees(
            ref self: ContractState,
            asset_ids: Span<felt252>,
            recipients: Span<felt252>,
            amounts: Span<u128>,
        ) {
            assert_auction_verifier(@self);
            let len = asset_ids.len();
            assert(recipients.len() == len, 'BAD_FEE_LENGTH');
            assert(amounts.len() == len, 'BAD_FEE_LENGTH');

            let mut index = 0;
            loop {
                if index == len {
                    break;
                }

                let asset_id = *asset_ids.at(index);
                let recipient = *recipients.at(index);
                let amount = *amounts.at(index);
                assert(asset_id != 0, 'BAD_FEE_ASSET');
                assert(recipient != 0, 'BAD_FEE_RECIPIENT');
                assert(amount > 0, 'BAD_FEE_AMOUNT');
                let current = self.accrued_fees.read((asset_id, recipient));
                self.accrued_fees.write((asset_id, recipient), current + amount);
                index += 1;
            };
        }

        fn claim_fees(
            ref self: ContractState,
            asset_id: felt252,
            fee_recipient: felt252,
            amount: u128,
            token_recipient: ContractAddress,
        ) {
            assert_admin(@self);
            assert(asset_id != 0, 'BAD_FEE_ASSET');
            assert(fee_recipient != 0, 'BAD_FEE_RECIPIENT');
            assert(amount > 0, 'BAD_FEE_AMOUNT');
            assert(!token_recipient.is_zero(), 'BAD_TOKEN_RECIPIENT');
            let current = self.accrued_fees.read((asset_id, fee_recipient));
            assert(current >= amount, 'INSUFFICIENT_FEES');
            self.accrued_fees.write((asset_id, fee_recipient), current - amount);

            let adapter_address = self.shielded_asset_adapter.read();
            assert(!adapter_address.is_zero(), 'ADAPTER_UNSET');
            let adapter = IShieldedAssetAdapterDispatcher { contract_address: adapter_address };
            adapter.withdraw_fee(asset_id, amount, token_recipient);
        }

        fn accrued_fee(self: @ContractState, asset_id: felt252, recipient: felt252) -> u128 {
            self.accrued_fees.read((asset_id, recipient))
        }

        fn auction_verifier_address(self: @ContractState) -> ContractAddress {
            self.auction_verifier.read()
        }

        fn shielded_asset_adapter_address(self: @ContractState) -> ContractAddress {
            self.shielded_asset_adapter.read()
        }
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'UNAUTHORIZED');
    }

    fn assert_auction_verifier(self: @ContractState) {
        assert(get_caller_address() == self.auction_verifier.read(), 'UNAUTHORIZED');
    }
}
