use starknet::ContractAddress;

#[starknet::interface]
pub trait IFeeLedger<TContractState> {
    fn propose_admin(ref self: TContractState, new_admin: ContractAddress);
    fn accept_admin(ref self: TContractState);
    fn set_auction_verifier(ref self: TContractState, verifier: ContractAddress);
    fn set_shielded_asset_adapter(ref self: TContractState, adapter: ContractAddress);
    fn set_fee_claim_authority(ref self: TContractState, authority: ContractAddress);
    fn propose_fee_claim_authority(ref self: TContractState, authority: ContractAddress);
    fn execute_fee_claim_authority(ref self: TContractState);
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
    fn admin_address(self: @TContractState) -> ContractAddress;
    fn pending_admin_address(self: @TContractState) -> ContractAddress;
    fn admin_transfer_pending(self: @TContractState) -> bool;
    fn auction_verifier_address(self: @TContractState) -> ContractAddress;
    fn shielded_asset_adapter_address(self: @TContractState) -> ContractAddress;
    fn fee_claim_authority_address(self: @TContractState) -> ContractAddress;
    fn pending_fee_claim_authority(self: @TContractState) -> (ContractAddress, u64, bool);
}

#[starknet::contract]
pub mod FeeLedger {
    use core::num::traits::Zero;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
    use zylith_protocol::shielded_asset_adapter::{
        IShieldedAssetAdapterDispatcher, IShieldedAssetAdapterDispatcherTrait,
    };

    const FEE_CLAIM_AUTHORITY_TIMELOCK_SECONDS: u64 = 604800;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        pending_admin: ContractAddress,
        admin_transfer_pending: bool,
        auction_verifier: ContractAddress,
        shielded_asset_adapter: ContractAddress,
        fee_claim_authority: ContractAddress,
        pending_fee_claim_authority: ContractAddress,
        pending_fee_claim_authority_eta: u64,
        pending_fee_claim_authority_active: bool,
        accrued_fees: Map<(felt252, felt252), u128>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        assert(!admin.is_zero(), 'BAD_ADMIN');
        self.admin.write(admin);
    }

    #[abi(embed_v0)]
    impl FeeLedgerImpl of super::IFeeLedger<ContractState> {
        fn propose_admin(ref self: ContractState, new_admin: ContractAddress) {
            assert_admin(@self);
            assert(!new_admin.is_zero(), 'BAD_ADMIN');
            assert(new_admin != self.admin.read(), 'BAD_ADMIN');
            self.pending_admin.write(new_admin);
            self.admin_transfer_pending.write(true);
        }

        fn accept_admin(ref self: ContractState) {
            let caller = get_caller_address();
            assert(self.admin_transfer_pending.read(), 'NO_ADMIN_TRANSFER');
            assert(caller == self.pending_admin.read(), 'UNAUTHORIZED');
            self.admin.write(caller);
            self.admin_transfer_pending.write(false);
        }

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

        fn set_fee_claim_authority(ref self: ContractState, authority: ContractAddress) {
            assert_admin(@self);
            assert(!authority.is_zero(), 'BAD_FEE_CLAIM_AUTH');
            assert(self.fee_claim_authority.read().is_zero(), 'FEE_AUTH_TIMELOCK');
            self.fee_claim_authority.write(authority);
        }

        fn propose_fee_claim_authority(ref self: ContractState, authority: ContractAddress) {
            assert_admin(@self);
            assert(!authority.is_zero(), 'BAD_FEE_CLAIM_AUTH');
            assert(!self.fee_claim_authority.read().is_zero(), 'FEE_AUTH_UNSET');
            self.pending_fee_claim_authority.write(authority);
            self
                .pending_fee_claim_authority_eta
                .write(get_block_timestamp() + FEE_CLAIM_AUTHORITY_TIMELOCK_SECONDS);
            self.pending_fee_claim_authority_active.write(true);
        }

        fn execute_fee_claim_authority(ref self: ContractState) {
            assert_admin(@self);
            assert(self.pending_fee_claim_authority_active.read(), 'NO_FEE_AUTH_PENDING');
            let eta = self.pending_fee_claim_authority_eta.read();
            assert(get_block_timestamp() >= eta, 'FEE_AUTH_TIMELOCK');
            let authority = self.pending_fee_claim_authority.read();
            assert(!authority.is_zero(), 'BAD_FEE_CLAIM_AUTH');
            self.fee_claim_authority.write(authority);
            self.pending_fee_claim_authority_active.write(false);
            self.pending_fee_claim_authority_eta.write(0);
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
            assert_fee_claim_authority(@self);
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

        fn admin_address(self: @ContractState) -> ContractAddress {
            self.admin.read()
        }

        fn pending_admin_address(self: @ContractState) -> ContractAddress {
            self.pending_admin.read()
        }

        fn admin_transfer_pending(self: @ContractState) -> bool {
            self.admin_transfer_pending.read()
        }

        fn auction_verifier_address(self: @ContractState) -> ContractAddress {
            self.auction_verifier.read()
        }

        fn shielded_asset_adapter_address(self: @ContractState) -> ContractAddress {
            self.shielded_asset_adapter.read()
        }

        fn fee_claim_authority_address(self: @ContractState) -> ContractAddress {
            self.fee_claim_authority.read()
        }

        fn pending_fee_claim_authority(self: @ContractState) -> (ContractAddress, u64, bool) {
            (
                self.pending_fee_claim_authority.read(),
                self.pending_fee_claim_authority_eta.read(),
                self.pending_fee_claim_authority_active.read(),
            )
        }
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'UNAUTHORIZED');
    }

    fn assert_auction_verifier(self: @ContractState) {
        assert(get_caller_address() == self.auction_verifier.read(), 'UNAUTHORIZED');
    }

    fn assert_fee_claim_authority(self: @ContractState) {
        assert(get_caller_address() == self.fee_claim_authority.read(), 'UNAUTHORIZED');
    }
}
