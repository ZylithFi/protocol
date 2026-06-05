use zylith_protocol::types::WithdrawalRecord;

#[starknet::interface]
pub trait IShieldedAssetAdapter<TContractState> {
    fn propose_admin(ref self: TContractState, new_admin: starknet::ContractAddress);
    fn accept_admin(ref self: TContractState);
    fn set_auction_verifier(ref self: TContractState, verifier: starknet::ContractAddress);
    fn register_supported_asset(
        ref self: TContractState, asset_id: felt252, token_address: starknet::ContractAddress,
    );
    fn withdraw_verified_note(
        ref self: TContractState,
        asset_id: felt252,
        amount: u128,
        note_commitment: felt252,
        recipient: starknet::ContractAddress,
    );
    fn stage_verified_note_strk20_exit(
        ref self: TContractState,
        asset_id: felt252,
        amount: u128,
        note_commitment: felt252,
        withdraw_authority: felt252,
        exit_commitment: felt252,
    );
    fn asset_token(self: @TContractState, asset_id: felt252) -> starknet::ContractAddress;
    fn is_asset_supported(self: @TContractState, asset_id: felt252) -> bool;
    fn withdrawal_recipient(
        self: @TContractState, note_commitment: felt252,
    ) -> starknet::ContractAddress;
    fn withdrawal_count(self: @TContractState) -> u64;
    fn withdrawal_record(self: @TContractState, withdrawal_id: u64) -> WithdrawalRecord;
    fn admin_address(self: @TContractState) -> starknet::ContractAddress;
    fn pending_admin_address(self: @TContractState) -> starknet::ContractAddress;
    fn admin_transfer_pending(self: @TContractState) -> bool;
    fn auction_verifier_address(self: @TContractState) -> starknet::ContractAddress;
}

#[starknet::contract]
pub mod ShieldedAssetAdapter {
    use core::integer::u256;
    use core::num::traits::Zero;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
    use zylith_protocol::types::WithdrawalRecord;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        pending_admin: ContractAddress,
        admin_transfer_pending: bool,
        auction_verifier: ContractAddress,
        asset_tokens: Map<felt252, ContractAddress>,
        withdrawal_recipients: Map<felt252, ContractAddress>,
        withdrawal_count: u64,
        withdrawal_note_commitments: Map<u64, felt252>,
        withdrawal_asset_ids: Map<u64, felt252>,
        withdrawal_amounts: Map<u64, u128>,
        withdrawal_recipients_by_id: Map<u64, ContractAddress>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        assert(!admin.is_zero(), 'BAD_ADMIN');
        self.admin.write(admin);
    }

    #[abi(embed_v0)]
    impl ShieldedAssetAdapterImpl of super::IShieldedAssetAdapter<ContractState> {
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

        fn register_supported_asset(
            ref self: ContractState, asset_id: felt252, token_address: ContractAddress,
        ) {
            assert_admin(@self);
            assert(asset_id != 0, 'BAD_ASSET');
            assert(!token_address.is_zero(), 'BAD_TOKEN');

            let existing = self.asset_tokens.read(asset_id);
            if existing.is_zero() {
                self.asset_tokens.write(asset_id, token_address);
            } else {
                assert(existing == token_address, 'ASSET_IMMUTABLE');
            }
        }

        fn withdraw_verified_note(
            ref self: ContractState,
            asset_id: felt252,
            amount: u128,
            note_commitment: felt252,
            recipient: ContractAddress,
        ) {
            assert_auction_verifier(@self);
            assert(asset_id != 0, 'BAD_ASSET');
            assert(amount > 0, 'BAD_AMOUNT');
            assert(note_commitment != 0, 'BAD_COMMITMENT');
            assert(!recipient.is_zero(), 'BAD_RECIPIENT');
            assert(self.withdrawal_recipients.read(note_commitment).is_zero(), 'NOTE_WITHDRAWN');
            let token_address = self.asset_tokens.read(asset_id);
            assert(!token_address.is_zero(), 'UNSUPPORTED_ASSET');

            self.withdrawal_recipients.write(note_commitment, recipient);

            let withdrawal_id = self.withdrawal_count.read();
            self.withdrawal_note_commitments.write(withdrawal_id, note_commitment);
            self.withdrawal_asset_ids.write(withdrawal_id, asset_id);
            self.withdrawal_amounts.write(withdrawal_id, amount);
            self.withdrawal_recipients_by_id.write(withdrawal_id, recipient);
            self.withdrawal_count.write(withdrawal_id + 1);

            let token = IERC20Dispatcher { contract_address: token_address };
            let adapter_balance_before = checked_token_balance(token, get_contract_address());
            let recipient_balance_before = checked_token_balance(token, recipient);
            token.transfer(recipient, as_u256(amount));
            let adapter_balance_after = checked_token_balance(token, get_contract_address());
            let recipient_balance_after = checked_token_balance(token, recipient);
            assert(
                adapter_balance_before == adapter_balance_after + amount, 'TOKEN_TRANSFER_DELTA',
            );
            assert(
                recipient_balance_after == recipient_balance_before + amount,
                'TOKEN_TRANSFER_DELTA',
            );
        }

        fn stage_verified_note_strk20_exit(
            ref self: ContractState,
            asset_id: felt252,
            amount: u128,
            note_commitment: felt252,
            withdraw_authority: felt252,
            exit_commitment: felt252,
        ) {
            let _ = (asset_id, amount, note_commitment, withdraw_authority, exit_commitment);
            assert_auction_verifier(@self);
            assert(false, 'STRK20_EXIT_UNSUPPORTED');
        }

        fn asset_token(self: @ContractState, asset_id: felt252) -> ContractAddress {
            self.asset_tokens.read(asset_id)
        }

        fn is_asset_supported(self: @ContractState, asset_id: felt252) -> bool {
            !self.asset_tokens.read(asset_id).is_zero()
        }

        fn withdrawal_recipient(self: @ContractState, note_commitment: felt252) -> ContractAddress {
            self.withdrawal_recipients.read(note_commitment)
        }

        fn withdrawal_count(self: @ContractState) -> u64 {
            self.withdrawal_count.read()
        }

        fn withdrawal_record(self: @ContractState, withdrawal_id: u64) -> WithdrawalRecord {
            let count = self.withdrawal_count.read();
            assert(withdrawal_id < count, 'UNKNOWN_WITHDRAWAL');

            WithdrawalRecord {
                withdrawal_id,
                asset_id: self.withdrawal_asset_ids.read(withdrawal_id),
                amount: self.withdrawal_amounts.read(withdrawal_id),
                recipient: self.withdrawal_recipients_by_id.read(withdrawal_id),
                note_commitment: self.withdrawal_note_commitments.read(withdrawal_id),
            }
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
    }

    fn as_u256(amount: u128) -> u256 {
        u256 { low: amount, high: 0 }
    }

    fn checked_token_balance(token: IERC20Dispatcher, owner: ContractAddress) -> u128 {
        let balance = token.balance_of(owner);
        assert(balance.high == 0, 'TOKEN_BALANCE_HIGH');
        balance.low
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'UNAUTHORIZED');
    }

    fn assert_auction_verifier(self: @ContractState) {
        assert(get_caller_address() == self.auction_verifier.read(), 'UNAUTHORIZED');
    }
}
