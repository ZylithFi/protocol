use zylith_protocol::types::{BatchStatus, BatchView};

#[starknet::interface]
pub trait IBatchRegistry<TContractState> {
    fn register_batch(
        ref self: TContractState,
        batch_id: felt252,
        pair_id: felt252,
        epoch_id: u64,
        close_time_unix_ms: u64,
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
}

#[starknet::contract]
pub mod BatchRegistry {
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use zylith_protocol::types::{BatchStatus, BatchView};

    #[storage]
    struct Storage {
        batch_exists: Map<felt252, bool>,
        pair_ids: Map<felt252, felt252>,
        epoch_ids: Map<felt252, u64>,
        close_times: Map<felt252, u64>,
        statuses: Map<felt252, BatchStatus>,
        order_counts: Map<felt252, u64>,
        output_bundle_refs: Map<felt252, felt252>,
        transcript_commitments: Map<felt252, felt252>,
        clearing_prices: Map<felt252, u128>,
    }

    #[abi(embed_v0)]
    impl BatchRegistryImpl of super::IBatchRegistry<ContractState> {
        fn register_batch(
            ref self: ContractState,
            batch_id: felt252,
            pair_id: felt252,
            epoch_id: u64,
            close_time_unix_ms: u64,
        ) {
            let exists = self.batch_exists.read(batch_id);
            assert(exists == false, 'BATCH_EXISTS');

            self.batch_exists.write(batch_id, true);
            self.pair_ids.write(batch_id, pair_id);
            self.epoch_ids.write(batch_id, epoch_id);
            self.close_times.write(batch_id, close_time_unix_ms);
            self.statuses.write(batch_id, BatchStatus::Open);
            self.order_counts.write(batch_id, 0);
            self.output_bundle_refs.write(batch_id, 0);
            self.transcript_commitments.write(batch_id, 0);
            self.clearing_prices.write(batch_id, 0);
        }

        fn increment_order_count(ref self: ContractState, batch_id: felt252, delta: u64) {
            assert_batch_exists(@self, batch_id);
            let current = self.order_counts.read(batch_id);
            self.order_counts.write(batch_id, current + delta);
        }

        fn transition_status(
            ref self: ContractState,
            batch_id: felt252,
            expected_status: BatchStatus,
            next_status: BatchStatus,
        ) {
            assert_batch_exists(@self, batch_id);
            let current = self.statuses.read(batch_id);
            assert(current == expected_status, 'BAD_BATCH_STATUS');
            self.statuses.write(batch_id, next_status);
        }

        fn record_settlement_metadata(
            ref self: ContractState,
            batch_id: felt252,
            transcript_commitment: felt252,
            clearing_price: u128,
            output_bundle_ref: felt252,
        ) {
            assert_batch_exists(@self, batch_id);
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
                output_bundle_ref: self.output_bundle_refs.read(batch_id),
                transcript_commitment: self.transcript_commitments.read(batch_id),
                clearing_price: self.clearing_prices.read(batch_id),
            }
        }
    }

    fn assert_batch_exists(self: @ContractState, batch_id: felt252) {
        let exists = self.batch_exists.read(batch_id);
        assert(exists == true, 'UNKNOWN_BATCH');
    }
}
