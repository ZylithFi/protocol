use zylith_protocol::types::{DepositRecord, WithdrawalRecord};

#[starknet::interface]
pub trait IShieldedAssetAdapter<TContractState> {
    fn register_supported_asset(
        ref self: TContractState, asset_id: felt252, token_address: starknet::ContractAddress,
    );
    fn register_erc20_deposit(
        ref self: TContractState,
        owner: starknet::ContractAddress,
        asset_id: felt252,
        amount: u128,
        deposit_nonce: u64,
        note_commitment: felt252,
        withdraw_authority: starknet::ContractAddress,
    );
    fn settle_notes(
        ref self: TContractState,
        consumed_note_commitments: Span<felt252>,
        output_note_commitments: Span<felt252>,
        output_note_asset_ids: Span<felt252>,
        output_note_amounts: Span<u128>,
        output_note_withdraw_authorities: Span<starknet::ContractAddress>,
    );
    fn withdraw_to_l2(
        ref self: TContractState,
        note_commitment: felt252,
        recipient: starknet::ContractAddress,
    ) -> (felt252, u128);
    fn note_is_live(self: @TContractState, note_commitment: felt252) -> bool;
    fn note_asset(self: @TContractState, note_commitment: felt252) -> felt252;
    fn note_amount(self: @TContractState, note_commitment: felt252) -> u128;
    fn note_withdraw_authority(
        self: @TContractState, note_commitment: felt252,
    ) -> starknet::ContractAddress;
    fn escrowed_balance(self: @TContractState, asset_id: felt252) -> u128;
    fn asset_token(
        self: @TContractState, asset_id: felt252,
    ) -> starknet::ContractAddress;
    fn is_asset_supported(self: @TContractState, asset_id: felt252) -> bool;
    fn withdrawal_recipient(
        self: @TContractState, note_commitment: felt252,
    ) -> starknet::ContractAddress;
    fn deposit_count(self: @TContractState) -> u64;
    fn deposit_record(self: @TContractState, deposit_id: u64) -> DepositRecord;
    fn withdrawal_count(self: @TContractState) -> u64;
    fn withdrawal_record(self: @TContractState, withdrawal_id: u64) -> WithdrawalRecord;
}

#[starknet::contract]
pub mod ShieldedAssetAdapter {
    use core::integer::u256;
    use core::num::traits::Zero;
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
    use zylith_protocol::types::{DepositRecord, WithdrawalRecord};

    #[storage]
    struct Storage {
        admin: ContractAddress,
        asset_tokens: Map<felt252, ContractAddress>,
        note_live: Map<felt252, bool>,
        note_spent: Map<felt252, bool>,
        note_asset_ids: Map<felt252, felt252>,
        note_amounts: Map<felt252, u128>,
        note_withdraw_authorities: Map<felt252, ContractAddress>,
        escrowed_balances: Map<felt252, u128>,
        withdrawal_recipients: Map<felt252, ContractAddress>,
        deposit_count: u64,
        deposit_note_commitments: Map<u64, felt252>,
        deposit_asset_ids: Map<u64, felt252>,
        deposit_amounts: Map<u64, u128>,
        deposit_nonces: Map<u64, u64>,
        withdrawal_count: u64,
        withdrawal_note_commitments: Map<u64, felt252>,
        withdrawal_asset_ids: Map<u64, felt252>,
        withdrawal_amounts: Map<u64, u128>,
        withdrawal_recipients_by_id: Map<u64, ContractAddress>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        self.admin.write(admin);
    }

    #[abi(embed_v0)]
    impl ShieldedAssetAdapterImpl of super::IShieldedAssetAdapter<ContractState> {
        fn register_supported_asset(
            ref self: ContractState, asset_id: felt252, token_address: ContractAddress,
        ) {
            let caller = get_caller_address();
            assert(caller == self.admin.read(), 'UNAUTHORIZED');
            assert(!token_address.is_zero(), 'BAD_TOKEN');

            self.asset_tokens.write(asset_id, token_address);
        }

        fn register_erc20_deposit(
            ref self: ContractState,
            owner: ContractAddress,
            asset_id: felt252,
            amount: u128,
            deposit_nonce: u64,
            note_commitment: felt252,
            withdraw_authority: ContractAddress,
        ) {
            let token_address = self.asset_tokens.read(asset_id);
            assert(!token_address.is_zero(), 'UNSUPPORTED_ASSET');
            assert(!withdraw_authority.is_zero(), 'BAD_AUTHORITY');

            let exists = self.note_live.read(note_commitment);
            assert(exists == false, 'NOTE_EXISTS');

            let token = IERC20Dispatcher { contract_address: token_address };
            token.transfer_from(owner, get_contract_address(), as_u256(amount));

            self.note_live.write(note_commitment, true);
            self.note_asset_ids.write(note_commitment, asset_id);
            self.note_amounts.write(note_commitment, amount);
            self.note_withdraw_authorities.write(note_commitment, withdraw_authority);
            let current_balance = self.escrowed_balances.read(asset_id);
            self.escrowed_balances.write(asset_id, current_balance + amount);

            let deposit_id = self.deposit_count.read();
            self.deposit_note_commitments.write(deposit_id, note_commitment);
            self.deposit_asset_ids.write(deposit_id, asset_id);
            self.deposit_amounts.write(deposit_id, amount);
            self.deposit_nonces.write(deposit_id, deposit_nonce);
            self.deposit_count.write(deposit_id + 1);
        }

        fn settle_notes(
            ref self: ContractState,
            consumed_note_commitments: Span<felt252>,
            output_note_commitments: Span<felt252>,
            output_note_asset_ids: Span<felt252>,
            output_note_amounts: Span<u128>,
            output_note_withdraw_authorities: Span<ContractAddress>,
        ) {
            let output_len = output_note_commitments.len();
            assert(output_note_asset_ids.len() == output_len, 'BAD_OUTPUT_LENGTH');
            assert(output_note_amounts.len() == output_len, 'BAD_OUTPUT_LENGTH');
            assert(output_note_withdraw_authorities.len() == output_len, 'BAD_OUTPUT_LENGTH');

            let mut input_index = 0;
            let input_len = consumed_note_commitments.len();
            loop {
                if input_index == input_len {
                    break;
                }

                let note_commitment = *consumed_note_commitments.at(input_index);
                let registered = self.note_live.read(note_commitment);
                let spent = self.note_spent.read(note_commitment);
                assert(registered == true, 'UNKNOWN_INPUT_NOTE');
                assert(spent == false, 'UNKNOWN_INPUT_NOTE');
                self.note_spent.write(note_commitment, true);
                input_index += 1;
            };

            let mut output_index = 0;
            loop {
                if output_index == output_len {
                    break;
                }

                let output_note_commitment = *output_note_commitments.at(output_index);
                let exists = self.note_live.read(output_note_commitment);
                assert(exists == false, 'OUTPUT_NOTE_EXISTS');

                let asset_id = *output_note_asset_ids.at(output_index);
                let token_address = self.asset_tokens.read(asset_id);
                assert(!token_address.is_zero(), 'UNSUPPORTED_ASSET');

                let amount = *output_note_amounts.at(output_index);
                let withdraw_authority = *output_note_withdraw_authorities.at(output_index);
                assert(!withdraw_authority.is_zero(), 'BAD_AUTHORITY');
                self.note_live.write(output_note_commitment, true);
                self.note_asset_ids.write(output_note_commitment, asset_id);
                self.note_amounts.write(output_note_commitment, amount);
                self.note_withdraw_authorities.write(output_note_commitment, withdraw_authority);
                output_index += 1;
            };
        }

        fn withdraw_to_l2(
            ref self: ContractState, note_commitment: felt252, recipient: ContractAddress,
        ) -> (felt252, u128) {
            let caller = get_caller_address();
            let registered = self.note_live.read(note_commitment);
            let spent = self.note_spent.read(note_commitment);
            assert(registered == true, 'UNKNOWN_WITHDRAW_NOTE');
            assert(spent == false, 'UNKNOWN_WITHDRAW_NOTE');
            assert(!recipient.is_zero(), 'BAD_RECIPIENT');
            let withdraw_authority = self.note_withdraw_authorities.read(note_commitment);
            assert(!withdraw_authority.is_zero(), 'UNKNOWN_AUTHORITY');
            assert(caller == withdraw_authority, 'UNAUTHORIZED_WITHDRAW');

            let asset_id = self.note_asset_ids.read(note_commitment);
            let token_address = self.asset_tokens.read(asset_id);
            assert(!token_address.is_zero(), 'UNSUPPORTED_ASSET');

            let amount = self.note_amounts.read(note_commitment);
            let current_balance = self.escrowed_balances.read(asset_id);
            assert(current_balance >= amount, 'INSUFFICIENT_ESCROW');

            let token = IERC20Dispatcher { contract_address: token_address };
            token.transfer(recipient, as_u256(amount));

            self.note_spent.write(note_commitment, true);
            self.withdrawal_recipients.write(note_commitment, recipient);
            self.escrowed_balances.write(asset_id, current_balance - amount);

            let withdrawal_id = self.withdrawal_count.read();
            self.withdrawal_note_commitments.write(withdrawal_id, note_commitment);
            self.withdrawal_asset_ids.write(withdrawal_id, asset_id);
            self.withdrawal_amounts.write(withdrawal_id, amount);
            self.withdrawal_recipients_by_id.write(withdrawal_id, recipient);
            self.withdrawal_count.write(withdrawal_id + 1);

            (asset_id, amount)
        }

        fn note_is_live(self: @ContractState, note_commitment: felt252) -> bool {
            self.note_live.read(note_commitment) && !self.note_spent.read(note_commitment)
        }

        fn note_asset(self: @ContractState, note_commitment: felt252) -> felt252 {
            self.note_asset_ids.read(note_commitment)
        }

        fn note_amount(self: @ContractState, note_commitment: felt252) -> u128 {
            self.note_amounts.read(note_commitment)
        }

        fn note_withdraw_authority(
            self: @ContractState, note_commitment: felt252,
        ) -> ContractAddress {
            self.note_withdraw_authorities.read(note_commitment)
        }

        fn escrowed_balance(self: @ContractState, asset_id: felt252) -> u128 {
            self.escrowed_balances.read(asset_id)
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

        fn deposit_count(self: @ContractState) -> u64 {
            self.deposit_count.read()
        }

        fn deposit_record(self: @ContractState, deposit_id: u64) -> DepositRecord {
            let count = self.deposit_count.read();
            assert(deposit_id < count, 'UNKNOWN_DEPOSIT');

            DepositRecord {
                deposit_id,
                asset_id: self.deposit_asset_ids.read(deposit_id),
                amount: self.deposit_amounts.read(deposit_id),
                deposit_nonce: self.deposit_nonces.read(deposit_id),
                note_commitment: self.deposit_note_commitments.read(deposit_id),
            }
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
    }

    fn as_u256(amount: u128) -> u256 {
        u256 { low: amount, high: 0 }
    }
}
