use starknet::ContractAddress;
use zylith_protocol::types::WithdrawalRecord;

#[derive(Copy, Drop, Serde)]
pub struct OpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u128,
}

#[starknet::interface]
pub trait IPrivacyDepositBridge<TContractState> {
    fn propose_admin(ref self: TContractState, new_admin: ContractAddress);
    fn accept_admin(ref self: TContractState);
    fn set_auction_verifier(ref self: TContractState, verifier: ContractAddress);
    fn register_supported_asset(
        ref self: TContractState, asset_id: felt252, token_address: ContractAddress,
    );
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
    fn withdraw_verified_note(
        ref self: TContractState,
        asset_id: felt252,
        amount: u128,
        note_commitment: felt252,
        recipient: ContractAddress,
    );
    fn stage_verified_note_strk20_exit(
        ref self: TContractState,
        asset_id: felt252,
        amount: u128,
        note_commitment: felt252,
        withdraw_authority: felt252,
        exit_commitment: felt252,
    );
    fn strk20_exit_claimed_open_note_id(self: @TContractState, exit_commitment: felt252) -> felt252;
    fn asset_token(self: @TContractState, asset_id: felt252) -> ContractAddress;
    fn is_asset_supported(self: @TContractState, asset_id: felt252) -> bool;
    fn withdrawal_recipient(self: @TContractState, note_commitment: felt252) -> ContractAddress;
    fn withdrawal_count(self: @TContractState) -> u64;
    fn withdrawal_record(self: @TContractState, withdrawal_id: u64) -> WithdrawalRecord;
    fn admin_address(self: @TContractState) -> ContractAddress;
    fn pending_admin_address(self: @TContractState) -> ContractAddress;
    fn admin_transfer_pending(self: @TContractState) -> bool;
    fn auction_verifier_address(self: @TContractState) -> ContractAddress;
    fn commitment_registry_address(self: @TContractState) -> ContractAddress;
    fn privacy_pool_address(self: @TContractState) -> ContractAddress;
}

#[starknet::interface]
pub trait IStarknetPrivacyPool<TContractState> {
    fn deposit_to_open_note(
        ref self: TContractState, note_id: felt252, token: ContractAddress, amount: u128,
    );
}

#[starknet::contract]
pub mod PrivacyDepositBridge {
    use core::ecdsa::check_ecdsa_signature;
    use core::integer::u256;
    use core::num::traits::Zero;
    use core::poseidon::hades_permutation;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address, get_contract_address, get_tx_info};
    use zylith_protocol::commitment_registry::{
        ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
    };
    use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
    use zylith_protocol::privacy_deposit_bridge::{
        IStarknetPrivacyPoolDispatcher, IStarknetPrivacyPoolDispatcherTrait,
    };
    use zylith_protocol::types::WithdrawalRecord;

    const STRK20_EXIT_CLAIM_DOMAIN: felt252 = 0x7a796c6974685f7374726b32305f636c61696d5f7631;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        pending_admin: ContractAddress,
        admin_transfer_pending: bool,
        auction_verifier: ContractAddress,
        commitment_registry: ContractAddress,
        privacy_pool: ContractAddress,
        asset_tokens: Map<felt252, ContractAddress>,
        withdrawal_recipients: Map<felt252, ContractAddress>,
        withdrawal_count: u64,
        withdrawal_note_commitments: Map<u64, felt252>,
        withdrawal_asset_ids: Map<u64, felt252>,
        withdrawal_amounts: Map<u64, u128>,
        withdrawal_recipients_by_id: Map<u64, ContractAddress>,
        strk20_exit_asset_ids: Map<felt252, felt252>,
        strk20_exit_amounts: Map<felt252, u128>,
        strk20_exit_note_commitments: Map<felt252, felt252>,
        strk20_exit_withdraw_authorities: Map<felt252, felt252>,
        strk20_exit_claimed_open_note_ids: Map<felt252, felt252>,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        admin: ContractAddress,
        commitment_registry: ContractAddress,
        privacy_pool: ContractAddress,
    ) {
        assert(!admin.is_zero(), 'BAD_ADMIN');
        assert(!commitment_registry.is_zero(), 'BAD_REGISTRY');
        assert(!privacy_pool.is_zero(), 'BAD_PRIVACY_POOL');
        self.admin.write(admin);
        self.commitment_registry.write(commitment_registry);
        self.privacy_pool.write(privacy_pool);
    }

    #[abi(embed_v0)]
    impl PrivacyDepositBridgeImpl of super::IPrivacyDepositBridge<ContractState> {
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

        fn privacy_invoke(
            ref self: ContractState,
            funding_commitments: Span<felt252>,
            deposit_roots: Span<felt252>,
            encrypted_note_activations: Span<felt252>,
        ) -> Span<super::OpenNoteDeposit> {
            if funding_commitments.len() == 0 {
                claim_strk20_exit_internal(ref self, deposit_roots, encrypted_note_activations);
            } else {
                register_funding_activation_internal(
                    ref self, funding_commitments, deposit_roots, encrypted_note_activations,
                );
            }
            let empty: Array<super::OpenNoteDeposit> = array![];
            empty.span()
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
            let vault_balance_before = checked_token_balance(token, get_contract_address());
            let recipient_balance_before = checked_token_balance(token, recipient);
            token.transfer(recipient, as_u256(amount));
            let vault_balance_after = checked_token_balance(token, get_contract_address());
            let recipient_balance_after = checked_token_balance(token, recipient);
            assert(vault_balance_before == vault_balance_after + amount, 'TOKEN_TRANSFER_DELTA');
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
            assert_auction_verifier(@self);
            assert(asset_id != 0, 'BAD_ASSET');
            assert(amount > 0, 'BAD_AMOUNT');
            assert(note_commitment != 0, 'BAD_COMMITMENT');
            assert(withdraw_authority != 0, 'BAD_AUTHORITY');
            assert(exit_commitment != 0, 'BAD_EXIT');
            assert(self.strk20_exit_amounts.read(exit_commitment) == 0, 'EXIT_EXISTS');
            assert(self.strk20_exit_note_commitments.read(exit_commitment) == 0, 'EXIT_EXISTS');
            assert(self.withdrawal_recipients.read(note_commitment).is_zero(), 'NOTE_WITHDRAWN');
            let token_address = self.asset_tokens.read(asset_id);
            assert(!token_address.is_zero(), 'UNSUPPORTED_ASSET');

            self.strk20_exit_asset_ids.write(exit_commitment, asset_id);
            self.strk20_exit_amounts.write(exit_commitment, amount);
            self.strk20_exit_note_commitments.write(exit_commitment, note_commitment);
            self.strk20_exit_withdraw_authorities.write(exit_commitment, withdraw_authority);
        }

        fn strk20_exit_claimed_open_note_id(
            self: @ContractState, exit_commitment: felt252,
        ) -> felt252 {
            self.strk20_exit_claimed_open_note_ids.read(exit_commitment)
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

    fn claim_strk20_exit_internal(
        ref self: ContractState,
        claim_fields: Span<felt252>,
        encrypted_note_activations: Span<felt252>,
    ) {
        assert(get_caller_address() == self.privacy_pool.read(), 'BAD_PRIVACY_CALLER');
        assert(encrypted_note_activations.len() == 0, 'BAD_EXIT_CLAIM');
        assert(claim_fields.len() == 4, 'BAD_EXIT_CLAIM');
        let exit_commitment = *claim_fields.at(0);
        let open_note_id = *claim_fields.at(1);
        let signature_r = *claim_fields.at(2);
        let signature_s = *claim_fields.at(3);
        assert(exit_commitment != 0, 'BAD_EXIT');
        assert(open_note_id != 0, 'BAD_OPEN_NOTE');
        assert(signature_r != 0, 'BAD_EXIT_SIG');
        assert(signature_s != 0, 'BAD_EXIT_SIG');
        assert(self.strk20_exit_claimed_open_note_ids.read(exit_commitment) == 0, 'EXIT_CLAIMED');

        let amount = self.strk20_exit_amounts.read(exit_commitment);
        assert(amount > 0, 'UNKNOWN_EXIT');
        let asset_id = self.strk20_exit_asset_ids.read(exit_commitment);
        let withdraw_authority = self.strk20_exit_withdraw_authorities.read(exit_commitment);
        let token_address = self.asset_tokens.read(asset_id);
        assert(!token_address.is_zero(), 'UNSUPPORTED_ASSET');
        let privacy_pool = self.privacy_pool.read();
        assert(!privacy_pool.is_zero(), 'BAD_PRIVACY_POOL');
        let auction_verifier = self.auction_verifier.read();
        assert(!auction_verifier.is_zero(), 'BAD_VERIFIER');
        assert(
            check_ecdsa_signature(
                strk20_exit_claim_message_hash(
                    privacy_pool,
                    auction_verifier,
                    asset_id,
                    token_address,
                    amount,
                    exit_commitment,
                    open_note_id,
                ),
                withdraw_authority,
                signature_r,
                signature_s,
            ),
            'BAD_EXIT_SIG',
        );

        self.strk20_exit_amounts.write(exit_commitment, 0);
        self.strk20_exit_claimed_open_note_ids.write(exit_commitment, open_note_id);

        let token = IERC20Dispatcher { contract_address: token_address };
        let pool = IStarknetPrivacyPoolDispatcher { contract_address: privacy_pool };
        let bridge_balance_before = checked_token_balance(token, get_contract_address());
        let pool_balance_before = checked_token_balance(token, privacy_pool);
        token.approve(privacy_pool, as_u256(amount));
        pool.deposit_to_open_note(open_note_id, token_address, amount);
        let bridge_balance_after = checked_token_balance(token, get_contract_address());
        let pool_balance_after = checked_token_balance(token, privacy_pool);
        assert(bridge_balance_before == bridge_balance_after + amount, 'TOKEN_TRANSFER_DELTA');
        assert(pool_balance_after == pool_balance_before + amount, 'TOKEN_TRANSFER_DELTA');
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

    fn strk20_exit_claim_message_hash(
        privacy_pool: ContractAddress,
        auction_verifier: ContractAddress,
        asset_id: felt252,
        token_address: ContractAddress,
        amount: u128,
        exit_commitment: felt252,
        open_note_id: felt252,
    ) -> felt252 {
        let tx_info = get_tx_info().unbox();
        let mut state = poseidon_hash2(STRK20_EXIT_CLAIM_DOMAIN, tx_info.chain_id);
        state = poseidon_hash2(state, get_contract_address().into());
        state = poseidon_hash2(state, privacy_pool.into());
        state = poseidon_hash2(state, auction_verifier.into());
        state = poseidon_hash2(state, asset_id);
        state = poseidon_hash2(state, token_address.into());
        state = poseidon_hash2(state, amount.into());
        state = poseidon_hash2(state, exit_commitment);
        poseidon_hash2(state, open_note_id)
    }

    fn poseidon_hash2(x: felt252, y: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(x, y, 2);
        result
    }
}
