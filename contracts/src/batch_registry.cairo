use starknet::ContractAddress;
use zylith_protocol::types::{BatchStatus, BatchView};

#[starknet::interface]
pub trait IBatchRegistry<TContractState> {
    fn propose_admin(ref self: TContractState, new_admin: ContractAddress);
    fn accept_admin(ref self: TContractState);
    fn set_batch_registrar(ref self: TContractState, registrar: ContractAddress);
    fn set_auction_verifier(ref self: TContractState, verifier: ContractAddress);
    fn register_batch(
        ref self: TContractState,
        batch_id: felt252,
        pair_id: felt252,
        epoch_id: u64,
        close_time_unix_ms: u64,
        order_count: u64,
        order_commitment_root: felt252,
        encrypted_order_set_commitment: felt252,
    );
    fn record_order_set_commitments(
        ref self: TContractState,
        batch_id: felt252,
        order_count: u64,
        order_commitment_root: felt252,
        encrypted_order_set_commitment: felt252,
    );
    fn increment_order_count(ref self: TContractState, batch_id: felt252, delta: u64);
    fn transition_status(
        ref self: TContractState,
        batch_id: felt252,
        expected_status: BatchStatus,
        next_status: BatchStatus,
    );
    fn record_settlement_metadata(
        ref self: TContractState,
        batch_id: felt252,
        transcript_commitment: felt252,
        clearing_price: u128,
        output_bundle_ref: felt252,
    );
    fn batch_exists(self: @TContractState, batch_id: felt252) -> bool;
    fn get_batch(self: @TContractState, batch_id: felt252) -> BatchView;
    fn admin_address(self: @TContractState) -> ContractAddress;
    fn pending_admin_address(self: @TContractState) -> ContractAddress;
    fn admin_transfer_pending(self: @TContractState) -> bool;
    fn batch_registrar_address(self: @TContractState) -> ContractAddress;
    fn auction_verifier_address(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod BatchRegistry {
    use core::num::traits::Zero;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};
    use zylith_protocol::types::{BatchStatus, BatchView};

    #[storage]
    struct Storage {
        admin: ContractAddress,
        pending_admin: ContractAddress,
        admin_transfer_pending: bool,
        batch_registrar: ContractAddress,
        auction_verifier: ContractAddress,
        batch_exists: Map<felt252, bool>,
        pair_ids: Map<felt252, felt252>,
        epoch_ids: Map<felt252, u64>,
        close_times: Map<felt252, u64>,
        statuses: Map<felt252, BatchStatus>,
        order_counts: Map<felt252, u64>,
        order_commitment_roots: Map<felt252, felt252>,
        encrypted_order_set_commitments: Map<felt252, felt252>,
        output_bundle_refs: Map<felt252, felt252>,
        transcript_commitments: Map<felt252, felt252>,
        clearing_prices: Map<felt252, u128>,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, admin: ContractAddress, batch_registrar: ContractAddress,
    ) {
        assert(!admin.is_zero(), 'BAD_ADMIN');
        assert(!batch_registrar.is_zero(), 'BAD_REGISTRAR');
        self.admin.write(admin);
        self.batch_registrar.write(batch_registrar);
    }

    #[abi(embed_v0)]
    impl BatchRegistryImpl of super::IBatchRegistry<ContractState> {
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

        fn set_batch_registrar(ref self: ContractState, registrar: ContractAddress) {
            assert_admin(@self);
            assert(!registrar.is_zero(), 'BAD_REGISTRAR');
            self.batch_registrar.write(registrar);
        }

        fn set_auction_verifier(ref self: ContractState, verifier: ContractAddress) {
            assert_admin(@self);
            assert(!verifier.is_zero(), 'BAD_AUCTION_VERIFIER');
            self.auction_verifier.write(verifier);
        }

        fn register_batch(
            ref self: ContractState,
            batch_id: felt252,
            pair_id: felt252,
            epoch_id: u64,
            close_time_unix_ms: u64,
            order_count: u64,
            order_commitment_root: felt252,
            encrypted_order_set_commitment: felt252,
        ) {
            assert_batch_registrar(@self);
            assert(batch_id != 0, 'BAD_BATCH_ID');
            assert(pair_id != 0, 'BAD_PAIR_ID');
            assert(epoch_id != 0, 'BAD_EPOCH');
            assert(order_commitment_root != 0, 'BAD_ORDER_ROOT');
            assert(encrypted_order_set_commitment != 0, 'BAD_ENC_SET');
            let exists = self.batch_exists.read(batch_id);
            assert(exists == false, 'BATCH_EXISTS');

            self.batch_exists.write(batch_id, true);
            self.pair_ids.write(batch_id, pair_id);
            self.epoch_ids.write(batch_id, epoch_id);
            self.close_times.write(batch_id, close_time_unix_ms);
            self.statuses.write(batch_id, BatchStatus::Prepared);
            self.order_counts.write(batch_id, order_count);
            self.order_commitment_roots.write(batch_id, order_commitment_root);
            self.encrypted_order_set_commitments.write(batch_id, encrypted_order_set_commitment);
            self.output_bundle_refs.write(batch_id, 0);
            self.transcript_commitments.write(batch_id, 0);
            self.clearing_prices.write(batch_id, 0);
        }

        fn record_order_set_commitments(
            ref self: ContractState,
            batch_id: felt252,
            order_count: u64,
            order_commitment_root: felt252,
            encrypted_order_set_commitment: felt252,
        ) {
            assert_batch_registrar(@self);
            assert(false, 'FINAL_BATCH_ONLY');
            assert_batch_exists(@self, batch_id);
            assert(order_commitment_root != 0, 'BAD_ORDER_ROOT');
            assert(encrypted_order_set_commitment != 0, 'BAD_ENC_SET');
            let status = self.statuses.read(batch_id);
            assert(status == BatchStatus::Prepared, 'BATCH_NOT_PREPARED');
            assert(self.order_counts.read(batch_id) == order_count, 'ORDER_COUNT_MISMATCH');
            assert(
                self.order_commitment_roots.read(batch_id) == order_commitment_root,
                'ORDER_ROOT_MISMATCH',
            );
            assert(
                self
                    .encrypted_order_set_commitments
                    .read(batch_id) == encrypted_order_set_commitment,
                'ENC_SET_MISMATCH',
            );
        }

        fn increment_order_count(ref self: ContractState, batch_id: felt252, delta: u64) {
            assert_batch_registrar(@self);
            assert(false, 'FINAL_BATCH_ONLY');
            assert_batch_exists(@self, batch_id);
            let status = self.statuses.read(batch_id);
            assert(status == BatchStatus::Open, 'BATCH_NOT_OPEN');
            let current = self.order_counts.read(batch_id);
            self.order_counts.write(batch_id, current + delta);
        }

        fn transition_status(
            ref self: ContractState,
            batch_id: felt252,
            expected_status: BatchStatus,
            next_status: BatchStatus,
        ) {
            assert_batch_registrar(@self);
            assert_batch_exists(@self, batch_id);
            let current = self.statuses.read(batch_id);
            assert(current == expected_status, 'BAD_BATCH_STATUS');
            let valid_transition = if current == BatchStatus::Open {
                next_status == BatchStatus::Prepared || next_status == BatchStatus::Cancelled
            } else if current == BatchStatus::Prepared {
                next_status == BatchStatus::Cancelled
            } else {
                false
            };
            assert(valid_transition, 'BAD_STATUS_TRANSITION');
            self.statuses.write(batch_id, next_status);
        }

        fn record_settlement_metadata(
            ref self: ContractState,
            batch_id: felt252,
            transcript_commitment: felt252,
            clearing_price: u128,
            output_bundle_ref: felt252,
        ) {
            assert_auction_verifier(@self);
            assert_batch_exists(@self, batch_id);
            let status = self.statuses.read(batch_id);
            assert(status == BatchStatus::Prepared, 'BATCH_NOT_PREPARED');
            self.transcript_commitments.write(batch_id, transcript_commitment);
            self.clearing_prices.write(batch_id, clearing_price);
            self.output_bundle_refs.write(batch_id, output_bundle_ref);
            self.statuses.write(batch_id, BatchStatus::Settled);
        }

        fn batch_exists(self: @ContractState, batch_id: felt252) -> bool {
            self.batch_exists.read(batch_id)
        }

        fn get_batch(self: @ContractState, batch_id: felt252) -> BatchView {
            assert_batch_exists(self, batch_id);
            BatchView {
                batch_id,
                pair_id: self.pair_ids.read(batch_id),
                epoch_id: self.epoch_ids.read(batch_id),
                close_time_unix_ms: self.close_times.read(batch_id),
                status: self.statuses.read(batch_id),
                order_count: self.order_counts.read(batch_id),
                order_commitment_root: self.order_commitment_roots.read(batch_id),
                encrypted_order_set_commitment: self.encrypted_order_set_commitments.read(batch_id),
                output_bundle_ref: self.output_bundle_refs.read(batch_id),
                transcript_commitment: self.transcript_commitments.read(batch_id),
                clearing_price: self.clearing_prices.read(batch_id),
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

        fn batch_registrar_address(self: @ContractState) -> ContractAddress {
            self.batch_registrar.read()
        }

        fn auction_verifier_address(self: @ContractState) -> ContractAddress {
            self.auction_verifier.read()
        }
    }

    fn assert_batch_exists(self: @ContractState, batch_id: felt252) {
        let exists = self.batch_exists.read(batch_id);
        assert(exists == true, 'UNKNOWN_BATCH');
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'UNAUTHORIZED');
    }

    fn assert_batch_registrar(self: @ContractState) {
        assert(get_caller_address() == self.batch_registrar.read(), 'UNAUTHORIZED');
    }

    fn assert_auction_verifier(self: @ContractState) {
        assert(get_caller_address() == self.auction_verifier.read(), 'UNAUTHORIZED');
    }
}
