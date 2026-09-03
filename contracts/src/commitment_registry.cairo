use starknet::ContractAddress;
use zylith_protocol::types::DepositActivationRecord;

#[starknet::interface]
pub trait ICommitmentRegistry<TContractState> {
    fn propose_admin(ref self: TContractState, new_admin: ContractAddress);
    fn accept_admin(ref self: TContractState);
    fn lock_config(ref self: TContractState);
    fn set_batch_registrar(ref self: TContractState, registrar: ContractAddress);
    fn set_privacy_deposit_bridge(ref self: TContractState, bridge: ContractAddress);
    fn set_auction_verifier(ref self: TContractState, verifier: ContractAddress);
    fn register_order_commitments(
        ref self: TContractState, batch_id: felt252, commitments: Span<felt252>,
    );
    fn register_funding_activation(
        ref self: TContractState,
        funding_commitment: felt252,
        deposit_root: felt252,
        encrypted_note_activation: felt252,
    );
    fn is_order_commitment_registered(self: @TContractState, commitment: felt252) -> bool;
    fn is_funding_commitment_registered(self: @TContractState, funding_commitment: felt252) -> bool;
    fn order_commitment_batch(self: @TContractState, commitment: felt252) -> felt252;
    fn funding_activation_root(self: @TContractState, funding_commitment: felt252) -> felt252;
    fn funding_activation_ciphertext(self: @TContractState, funding_commitment: felt252) -> felt252;
    fn funding_activation_count(self: @TContractState) -> u64;
    fn funding_activation_record(
        self: @TContractState, activation_id: u64,
    ) -> DepositActivationRecord;
    fn admin_address(self: @TContractState) -> ContractAddress;
    fn pending_admin_address(self: @TContractState) -> ContractAddress;
    fn admin_transfer_pending(self: @TContractState) -> bool;
    fn config_is_locked(self: @TContractState) -> bool;
    fn batch_registrar_address(self: @TContractState) -> ContractAddress;
    fn privacy_deposit_bridge_address(self: @TContractState) -> ContractAddress;
    fn auction_verifier_address(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod CommitmentRegistry {
    use core::num::traits::Zero;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};
    use zylith_protocol::auction_verifier::{
        IAuctionVerifierDispatcher, IAuctionVerifierDispatcherTrait,
    };
    use zylith_protocol::types::DepositActivationRecord;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        pending_admin: ContractAddress,
        admin_transfer_pending: bool,
        config_locked: bool,
        batch_registrar: ContractAddress,
        privacy_deposit_bridge: ContractAddress,
        auction_verifier: ContractAddress,
        order_commitments: Map<felt252, bool>,
        order_commitment_batch_ids: Map<felt252, felt252>,
        funding_commitments: Map<felt252, bool>,
        funding_activation_roots: Map<felt252, felt252>,
        funding_activation_ciphertexts: Map<felt252, felt252>,
        funding_activation_count: u64,
        funding_activation_commitments_by_id: Map<u64, felt252>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        assert(!admin.is_zero(), 'BAD_ADMIN');
        self.admin.write(admin);
    }

    #[abi(embed_v0)]
    impl CommitmentRegistryImpl of super::ICommitmentRegistry<ContractState> {
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

        fn lock_config(ref self: ContractState) {
            assert_admin(@self);
            assert(!self.config_locked.read(), 'CONFIG_LOCKED');
            assert(!self.batch_registrar.read().is_zero(), 'REGISTRAR_UNSET');
            assert(!self.privacy_deposit_bridge.read().is_zero(), 'BRIDGE_UNSET');
            assert(!self.auction_verifier.read().is_zero(), 'VERIFIER_UNSET');
            self.config_locked.write(true);
        }

        fn set_batch_registrar(ref self: ContractState, registrar: ContractAddress) {
            assert_admin(@self);
            assert(!self.config_locked.read(), 'CONFIG_LOCKED');
            assert(!registrar.is_zero(), 'BAD_REGISTRAR');
            self.batch_registrar.write(registrar);
        }

        fn set_privacy_deposit_bridge(ref self: ContractState, bridge: ContractAddress) {
            assert_admin(@self);
            assert(!self.config_locked.read(), 'CONFIG_LOCKED');
            assert(!bridge.is_zero(), 'BAD_PRIVACY_BRIDGE');
            self.privacy_deposit_bridge.write(bridge);
        }

        fn set_auction_verifier(ref self: ContractState, verifier: ContractAddress) {
            assert_admin(@self);
            assert(!self.config_locked.read(), 'CONFIG_LOCKED');
            assert(!verifier.is_zero(), 'BAD_AUCTION_VERIFIER');
            self.auction_verifier.write(verifier);
        }

        fn register_order_commitments(
            ref self: ContractState, batch_id: felt252, commitments: Span<felt252>,
        ) {
            assert_batch_registrar(@self);
            assert(batch_id != 0, 'BAD_BATCH_ID');
            let mut index = 0;
            let len = commitments.len();
            loop {
                if index == len {
                    break;
                }

                let commitment = *commitments.at(index);
                assert(commitment != 0, 'BAD_COMMITMENT');
                let exists = self.order_commitments.read(commitment);
                assert(exists == false, 'ORDER_EXISTS');
                self.order_commitments.write(commitment, true);
                self.order_commitment_batch_ids.write(commitment, batch_id);
                index += 1;
            };
        }

        fn register_funding_activation(
            ref self: ContractState,
            funding_commitment: felt252,
            deposit_root: felt252,
            encrypted_note_activation: felt252,
        ) {
            assert_deposit_registrar(@self);
            assert(funding_commitment != 0, 'BAD_FUNDING');
            assert(deposit_root != 0, 'BAD_DEPOSIT_ROOT');
            assert(encrypted_note_activation != 0, 'BAD_ACTIVATION');
            let auction_verifier = self.auction_verifier.read();
            assert(!auction_verifier.is_zero(), 'AUCTION_VERIFIER_UNSET');
            let exists = self.funding_commitments.read(funding_commitment);
            assert(exists == false, 'FUNDING_EXISTS');
            self.funding_commitments.write(funding_commitment, true);
            self.funding_activation_roots.write(funding_commitment, deposit_root);
            self
                .funding_activation_ciphertexts
                .write(funding_commitment, encrypted_note_activation);
            let activation_id = self.funding_activation_count.read();
            self.funding_activation_commitments_by_id.write(activation_id, funding_commitment);
            self.funding_activation_count.write(activation_id + 1);
            let verifier = IAuctionVerifierDispatcher { contract_address: auction_verifier };
            verifier.activate_deposit_root(funding_commitment, deposit_root);
        }

        fn is_order_commitment_registered(self: @ContractState, commitment: felt252) -> bool {
            self.order_commitments.read(commitment)
        }

        fn is_funding_commitment_registered(
            self: @ContractState, funding_commitment: felt252,
        ) -> bool {
            self.funding_commitments.read(funding_commitment)
        }

        fn order_commitment_batch(self: @ContractState, commitment: felt252) -> felt252 {
            self.order_commitment_batch_ids.read(commitment)
        }

        fn funding_activation_root(self: @ContractState, funding_commitment: felt252) -> felt252 {
            self.funding_activation_roots.read(funding_commitment)
        }

        fn funding_activation_ciphertext(
            self: @ContractState, funding_commitment: felt252,
        ) -> felt252 {
            self.funding_activation_ciphertexts.read(funding_commitment)
        }

        fn funding_activation_count(self: @ContractState) -> u64 {
            self.funding_activation_count.read()
        }

        fn funding_activation_record(
            self: @ContractState, activation_id: u64,
        ) -> DepositActivationRecord {
            let count = self.funding_activation_count.read();
            assert(activation_id < count, 'UNKNOWN_ACTIVATION');
            let funding_commitment = self.funding_activation_commitments_by_id.read(activation_id);
            DepositActivationRecord {
                activation_id,
                funding_commitment,
                deposit_root: self.funding_activation_roots.read(funding_commitment),
                encrypted_note_activation: self
                    .funding_activation_ciphertexts
                    .read(funding_commitment),
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

        fn config_is_locked(self: @ContractState) -> bool {
            self.config_locked.read()
        }

        fn batch_registrar_address(self: @ContractState) -> ContractAddress {
            self.batch_registrar.read()
        }

        fn privacy_deposit_bridge_address(self: @ContractState) -> ContractAddress {
            self.privacy_deposit_bridge.read()
        }

        fn auction_verifier_address(self: @ContractState) -> ContractAddress {
            self.auction_verifier.read()
        }
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'UNAUTHORIZED');
    }

    fn assert_batch_registrar(self: @ContractState) {
        assert(get_caller_address() == self.batch_registrar.read(), 'UNAUTHORIZED');
    }

    fn assert_deposit_registrar(self: @ContractState) {
        assert(get_caller_address() == self.privacy_deposit_bridge.read(), 'UNAUTHORIZED');
    }
}
