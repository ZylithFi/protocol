use zylith_protocol::types::{DepositRecord, WithdrawalRecord};

#[starknet::interface]
pub trait IShieldedAssetAdapter<TContractState> {
    fn propose_admin(ref self: TContractState, new_admin: starknet::ContractAddress);
    fn accept_admin(ref self: TContractState);
    fn set_privacy_deposit_bridge(ref self: TContractState, bridge: starknet::ContractAddress);
    fn set_fee_ledger(ref self: TContractState, fee_ledger: starknet::ContractAddress);
    fn set_auction_verifier(ref self: TContractState, verifier: starknet::ContractAddress);
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
        withdraw_authority: felt252,
    );
    fn withdraw_to_l2(
        ref self: TContractState,
        note_commitment: felt252,
        withdraw_authorization_r: felt252,
        withdraw_authorization_s: felt252,
        recipient: starknet::ContractAddress,
    ) -> (felt252, u128);
    fn withdraw_fee(
        ref self: TContractState,
        asset_id: felt252,
        amount: u128,
        recipient: starknet::ContractAddress,
    );
    fn withdraw_verified_note(
        ref self: TContractState,
        asset_id: felt252,
        amount: u128,
        note_commitment: felt252,
        recipient: starknet::ContractAddress,
    );
    fn note_is_live(self: @TContractState, note_commitment: felt252) -> bool;
    fn note_asset(self: @TContractState, note_commitment: felt252) -> felt252;
    fn note_amount(self: @TContractState, note_commitment: felt252) -> u128;
    fn note_withdraw_authority(self: @TContractState, note_commitment: felt252) -> felt252;
    fn escrowed_balance(self: @TContractState, asset_id: felt252) -> u128;
    fn asset_token(self: @TContractState, asset_id: felt252) -> starknet::ContractAddress;
    fn is_asset_supported(self: @TContractState, asset_id: felt252) -> bool;
    fn withdrawal_recipient(
        self: @TContractState, note_commitment: felt252,
    ) -> starknet::ContractAddress;
    fn deposit_count(self: @TContractState) -> u64;
    fn deposit_record(self: @TContractState, deposit_id: u64) -> DepositRecord;
    fn withdrawal_count(self: @TContractState) -> u64;
    fn withdrawal_record(self: @TContractState, withdrawal_id: u64) -> WithdrawalRecord;
    fn admin_address(self: @TContractState) -> starknet::ContractAddress;
    fn pending_admin_address(self: @TContractState) -> starknet::ContractAddress;
    fn admin_transfer_pending(self: @TContractState) -> bool;
    fn privacy_deposit_bridge_address(self: @TContractState) -> starknet::ContractAddress;
    fn fee_ledger_address(self: @TContractState) -> starknet::ContractAddress;
    fn auction_verifier_address(self: @TContractState) -> starknet::ContractAddress;
}

#[starknet::contract]
pub mod ShieldedAssetAdapter {
    use core::ecdsa::check_ecdsa_signature;
    use core::integer::u256;
    use core::num::traits::Zero;
    use core::poseidon::hades_permutation;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
    use zylith_protocol::types::{DepositRecord, WithdrawalRecord};

    #[storage]
    struct Storage {
        admin: ContractAddress,
        pending_admin: ContractAddress,
        admin_transfer_pending: bool,
        privacy_deposit_bridge: ContractAddress,
        fee_ledger: ContractAddress,
        auction_verifier: ContractAddress,
        asset_tokens: Map<felt252, ContractAddress>,
        note_live: Map<felt252, bool>,
        note_spent: Map<felt252, bool>,
        note_asset_ids: Map<felt252, felt252>,
        note_amounts: Map<felt252, u128>,
        note_withdraw_authorities: Map<felt252, felt252>,
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

        fn set_privacy_deposit_bridge(ref self: ContractState, bridge: ContractAddress) {
            assert_admin(@self);
            assert(!bridge.is_zero(), 'BAD_PRIVACY_BRIDGE');
            self.privacy_deposit_bridge.write(bridge);
        }

        fn set_fee_ledger(ref self: ContractState, fee_ledger: ContractAddress) {
            assert_admin(@self);
            assert(!fee_ledger.is_zero(), 'BAD_FEE_LEDGER');
            self.fee_ledger.write(fee_ledger);
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

        fn register_erc20_deposit(
            ref self: ContractState,
            owner: ContractAddress,
            asset_id: felt252,
            amount: u128,
            deposit_nonce: u64,
            note_commitment: felt252,
            withdraw_authority: felt252,
        ) {
            assert_deposit_registrar(@self);
            assert(amount > 0, 'BAD_AMOUNT');
            assert(note_commitment != 0, 'BAD_COMMITMENT');
            let token_address = self.asset_tokens.read(asset_id);
            assert(!token_address.is_zero(), 'UNSUPPORTED_ASSET');
            assert(withdraw_authority != 0, 'BAD_AUTHORITY');

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

        fn withdraw_to_l2(
            ref self: ContractState,
            note_commitment: felt252,
            withdraw_authorization_r: felt252,
            withdraw_authorization_s: felt252,
            recipient: ContractAddress,
        ) -> (felt252, u128) {
            let registered = self.note_live.read(note_commitment);
            let spent = self.note_spent.read(note_commitment);
            assert(registered == true, 'UNKNOWN_WITHDRAW_NOTE');
            assert(spent == false, 'UNKNOWN_WITHDRAW_NOTE');
            assert(!recipient.is_zero(), 'BAD_RECIPIENT');
            let withdraw_authority = self.note_withdraw_authorities.read(note_commitment);
            assert(withdraw_authority != 0, 'UNKNOWN_AUTHORITY');
            assert(withdraw_authorization_r != 0, 'BAD_WITHDRAW_SIG');
            assert(withdraw_authorization_s != 0, 'BAD_WITHDRAW_SIG');
            assert(
                check_ecdsa_signature(
                    withdrawal_message_hash(note_commitment, recipient),
                    withdraw_authority,
                    withdraw_authorization_r,
                    withdraw_authorization_s,
                ),
                'UNAUTHORIZED_WITHDRAW',
            );

            let asset_id = self.note_asset_ids.read(note_commitment);
            let token_address = self.asset_tokens.read(asset_id);
            assert(!token_address.is_zero(), 'UNSUPPORTED_ASSET');

            let amount = self.note_amounts.read(note_commitment);
            let current_balance = self.escrowed_balances.read(asset_id);
            assert(current_balance >= amount, 'INSUFFICIENT_ESCROW');

            self.note_spent.write(note_commitment, true);
            self.withdrawal_recipients.write(note_commitment, recipient);
            self.escrowed_balances.write(asset_id, current_balance - amount);

            let withdrawal_id = self.withdrawal_count.read();
            self.withdrawal_note_commitments.write(withdrawal_id, note_commitment);
            self.withdrawal_asset_ids.write(withdrawal_id, asset_id);
            self.withdrawal_amounts.write(withdrawal_id, amount);
            self.withdrawal_recipients_by_id.write(withdrawal_id, recipient);
            self.withdrawal_count.write(withdrawal_id + 1);

            let token = IERC20Dispatcher { contract_address: token_address };
            token.transfer(recipient, as_u256(amount));

            (asset_id, amount)
        }

        fn withdraw_fee(
            ref self: ContractState, asset_id: felt252, amount: u128, recipient: ContractAddress,
        ) {
            assert_fee_ledger(@self);
            assert(asset_id != 0, 'BAD_ASSET');
            assert(amount > 0, 'BAD_AMOUNT');
            assert(!recipient.is_zero(), 'BAD_RECIPIENT');
            let token_address = self.asset_tokens.read(asset_id);
            assert(!token_address.is_zero(), 'UNSUPPORTED_ASSET');
            let current_balance = self.escrowed_balances.read(asset_id);
            assert(current_balance >= amount, 'INSUFFICIENT_ESCROW');
            self.escrowed_balances.write(asset_id, current_balance - amount);

            let token = IERC20Dispatcher { contract_address: token_address };
            token.transfer(recipient, as_u256(amount));
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
            let token_address = self.asset_tokens.read(asset_id);
            assert(!token_address.is_zero(), 'UNSUPPORTED_ASSET');
            let current_balance = self.escrowed_balances.read(asset_id);
            assert(current_balance >= amount, 'INSUFFICIENT_ESCROW');

            self.withdrawal_recipients.write(note_commitment, recipient);
            self.escrowed_balances.write(asset_id, current_balance - amount);

            let withdrawal_id = self.withdrawal_count.read();
            self.withdrawal_note_commitments.write(withdrawal_id, note_commitment);
            self.withdrawal_asset_ids.write(withdrawal_id, asset_id);
            self.withdrawal_amounts.write(withdrawal_id, amount);
            self.withdrawal_recipients_by_id.write(withdrawal_id, recipient);
            self.withdrawal_count.write(withdrawal_id + 1);

            let token = IERC20Dispatcher { contract_address: token_address };
            token.transfer(recipient, as_u256(amount));
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

        fn note_withdraw_authority(self: @ContractState, note_commitment: felt252) -> felt252 {
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

        fn admin_address(self: @ContractState) -> ContractAddress {
            self.admin.read()
        }

        fn pending_admin_address(self: @ContractState) -> ContractAddress {
            self.pending_admin.read()
        }

        fn admin_transfer_pending(self: @ContractState) -> bool {
            self.admin_transfer_pending.read()
        }

        fn privacy_deposit_bridge_address(self: @ContractState) -> ContractAddress {
            self.privacy_deposit_bridge.read()
        }

        fn fee_ledger_address(self: @ContractState) -> ContractAddress {
            self.fee_ledger.read()
        }

        fn auction_verifier_address(self: @ContractState) -> ContractAddress {
            self.auction_verifier.read()
        }
    }

    fn as_u256(amount: u128) -> u256 {
        u256 { low: amount, high: 0 }
    }

    fn poseidon_hash2(x: felt252, y: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(x, y, 2);
        result
    }

    fn withdrawal_message_hash(note_commitment: felt252, recipient: ContractAddress) -> felt252 {
        let tx_info = starknet::get_tx_info().unbox();
        poseidon_hash2(
            poseidon_hash2(
                poseidon_hash2(
                    poseidon_hash2(
                        0x008c9bee4df79ca43188c02c21699eee1b86520e8bbe0291c437af32d37ff0e4,
                        tx_info.chain_id,
                    ),
                    get_contract_address().into(),
                ),
                note_commitment,
            ),
            recipient.into(),
        )
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'UNAUTHORIZED');
    }

    fn assert_deposit_registrar(self: @ContractState) {
        assert(get_caller_address() == self.privacy_deposit_bridge.read(), 'UNAUTHORIZED');
    }

    fn assert_fee_ledger(self: @ContractState) {
        assert(get_caller_address() == self.fee_ledger.read(), 'UNAUTHORIZED');
    }

    fn assert_auction_verifier(self: @ContractState) {
        assert(get_caller_address() == self.auction_verifier.read(), 'UNAUTHORIZED');
    }
}
