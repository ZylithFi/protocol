use starknet::ContractAddress;

#[derive(Drop, Serde)]
pub struct DepositActivationRecord {
    pub activation_id: u64,
    pub funding_commitment: felt252,
    pub deposit_root: felt252,
    pub encrypted_note_activation: felt252,
}

/// records each deposit's activation (for wallet recovery) and appends its root to the
/// exchange's note accumulator.
#[starknet::interface]
pub trait ICommitmentRegistry<TContractState> {
    fn propose_admin(ref self: TContractState, new_admin: ContractAddress);
    fn accept_admin(ref self: TContractState);
    fn lock_config(ref self: TContractState);
    fn set_privacy_deposit_bridge(ref self: TContractState, bridge: ContractAddress);
    fn set_exchange(ref self: TContractState, exchange: ContractAddress);
    fn register_funding_activation(
        ref self: TContractState,
        funding_commitment: felt252,
        deposit_root: felt252,
        encrypted_note_activation: felt252,
    );
    fn is_funding_commitment_registered(self: @TContractState, funding_commitment: felt252) -> bool;
    fn funding_activation_root(self: @TContractState, funding_commitment: felt252) -> felt252;
    fn funding_activation_ciphertext(self: @TContractState, funding_commitment: felt252) -> felt252;
    fn funding_activation_count(self: @TContractState) -> u64;
    fn funding_activation_record(
        self: @TContractState, activation_id: u64,
    ) -> DepositActivationRecord;
    fn admin_address(self: @TContractState) -> ContractAddress;
    fn config_is_locked(self: @TContractState) -> bool;
    fn privacy_deposit_bridge_address(self: @TContractState) -> ContractAddress;
    fn exchange_address(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod CommitmentRegistry {
    use core::num::traits::Zero;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};
    use zylith_protocol::exchange::{IExchangeDispatcher, IExchangeDispatcherTrait};
    use super::DepositActivationRecord;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        pending_admin: ContractAddress,
        config_locked: bool,
        privacy_deposit_bridge: ContractAddress,
        exchange: ContractAddress,
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
            assert(!new_admin.is_zero() && new_admin != self.admin.read(), 'BAD_ADMIN');
            self.pending_admin.write(new_admin);
        }

        fn accept_admin(ref self: ContractState) {
            let pending = self.pending_admin.read();
            assert(!pending.is_zero() && get_caller_address() == pending, 'UNAUTHORIZED');
            self.admin.write(pending);
            self.pending_admin.write(Zero::zero());
        }

        fn lock_config(ref self: ContractState) {
            assert_admin(@self);
            assert(!self.config_locked.read(), 'CONFIG_LOCKED');
            assert(!self.privacy_deposit_bridge.read().is_zero(), 'BRIDGE_UNSET');
            assert(!self.exchange.read().is_zero(), 'EXCHANGE_UNSET');
            self.config_locked.write(true);
        }

        fn set_privacy_deposit_bridge(ref self: ContractState, bridge: ContractAddress) {
            assert_admin(@self);
            assert(!self.config_locked.read(), 'CONFIG_LOCKED');
            assert(!bridge.is_zero(), 'BAD_PRIVACY_BRIDGE');
            self.privacy_deposit_bridge.write(bridge);
        }

        fn set_exchange(ref self: ContractState, exchange: ContractAddress) {
            assert_admin(@self);
            assert(!self.config_locked.read(), 'CONFIG_LOCKED');
            assert(!exchange.is_zero(), 'BAD_EXCHANGE');
            self.exchange.write(exchange);
        }

        fn register_funding_activation(
            ref self: ContractState,
            funding_commitment: felt252,
            deposit_root: felt252,
            encrypted_note_activation: felt252,
        ) {
            assert(get_caller_address() == self.privacy_deposit_bridge.read(), 'UNAUTHORIZED');
            assert(funding_commitment != 0, 'BAD_FUNDING');
            assert(deposit_root != 0, 'BAD_DEPOSIT_ROOT');
            assert(encrypted_note_activation != 0, 'BAD_ACTIVATION');
            let exchange = self.exchange.read();
            assert(!exchange.is_zero(), 'EXCHANGE_UNSET');
            assert(!self.funding_commitments.read(funding_commitment), 'FUNDING_EXISTS');
            self.funding_commitments.write(funding_commitment, true);
            self.funding_activation_roots.write(funding_commitment, deposit_root);
            self
                .funding_activation_ciphertexts
                .write(funding_commitment, encrypted_note_activation);
            let activation_id = self.funding_activation_count.read();
            self.funding_activation_commitments_by_id.write(activation_id, funding_commitment);
            self.funding_activation_count.write(activation_id + 1);
            IExchangeDispatcher { contract_address: exchange }
                .activate_deposit_root(funding_commitment, deposit_root);
        }

        fn is_funding_commitment_registered(
            self: @ContractState, funding_commitment: felt252,
        ) -> bool {
            self.funding_commitments.read(funding_commitment)
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
            assert(activation_id < self.funding_activation_count.read(), 'UNKNOWN_ACTIVATION');
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

        fn config_is_locked(self: @ContractState) -> bool {
            self.config_locked.read()
        }

        fn privacy_deposit_bridge_address(self: @ContractState) -> ContractAddress {
            self.privacy_deposit_bridge.read()
        }

        fn exchange_address(self: @ContractState) -> ContractAddress {
            self.exchange.read()
        }
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'UNAUTHORIZED');
    }
}
