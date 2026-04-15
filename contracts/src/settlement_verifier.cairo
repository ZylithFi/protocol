use starknet::ContractAddress;
use zylith_protocol::types::SettlementRecord;

#[starknet::interface]
pub trait ISettlementVerifier<TContractState> {
    fn submit_settlement_native(
        ref self: TContractState,
        batch_id: felt252,
        transcript_commitment: felt252,
        proof_artifact_commitment: felt252,
        clearing_price: u128,
        matched_order_count: u64,
        output_bundle_ref: felt252,
        consumed_note_commitments: Span<felt252>,
        consumed_nullifiers: Span<felt252>,
        output_note_commitments: Span<felt252>,
        output_note_asset_ids: Span<felt252>,
        output_note_amounts: Span<u128>,
        output_note_withdraw_authorities: Span<ContractAddress>,
        fee_asset_ids: Span<felt252>,
        fee_recipients: Span<felt252>,
        fee_amounts: Span<u128>,
    );
    fn is_batch_settled(self: @TContractState, batch_id: felt252) -> bool;
    fn settlement_record(self: @TContractState, batch_id: felt252) -> SettlementRecord;
    fn commitment_registry_address(self: @TContractState) -> ContractAddress;
    fn batch_registry_address(self: @TContractState) -> ContractAddress;
    fn fee_ledger_address(self: @TContractState) -> ContractAddress;
    fn shielded_asset_adapter_address(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod SettlementVerifier {
    use core::array::{Array, ArrayTrait};
    use core::poseidon::hades_permutation;
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use zylith_protocol::batch_registry::{IBatchRegistryDispatcher, IBatchRegistryDispatcherTrait};
    use zylith_protocol::commitment_registry::{
        ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
    };
    use zylith_protocol::fee_ledger::{IFeeLedgerDispatcher, IFeeLedgerDispatcherTrait};
    use zylith_protocol::shielded_asset_adapter::{
        IShieldedAssetAdapterDispatcher, IShieldedAssetAdapterDispatcherTrait,
    };
    use zylith_protocol::types::SettlementRecord;

    #[storage]
    struct Storage {
        commitment_registry: ContractAddress,
        batch_registry: ContractAddress,
        fee_ledger: ContractAddress,
        shielded_asset_adapter: ContractAddress,
        settled_batches: Map<felt252, bool>,
        transcript_commitments: Map<felt252, felt252>,
        proof_artifact_commitments: Map<felt252, felt252>,
        clearing_prices: Map<felt252, u128>,
        matched_order_counts: Map<felt252, u64>,
        output_bundle_refs: Map<felt252, felt252>,
        consumed_note_counts: Map<felt252, u64>,
        consumed_nullifier_counts: Map<felt252, u64>,
        created_output_counts: Map<felt252, u64>,
        fee_entry_counts: Map<felt252, u64>,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        commitment_registry: ContractAddress,
        batch_registry: ContractAddress,
        fee_ledger: ContractAddress,
        shielded_asset_adapter: ContractAddress,
    ) {
        self.commitment_registry.write(commitment_registry);
        self.batch_registry.write(batch_registry);
        self.fee_ledger.write(fee_ledger);
        self.shielded_asset_adapter.write(shielded_asset_adapter);
    }

    #[abi(embed_v0)]
    impl SettlementVerifierImpl of super::ISettlementVerifier<ContractState> {
        fn submit_settlement_native(
            ref self: ContractState,
            batch_id: felt252,
            transcript_commitment: felt252,
            proof_artifact_commitment: felt252,
            clearing_price: u128,
            matched_order_count: u64,
            output_bundle_ref: felt252,
            consumed_note_commitments: Span<felt252>,
            consumed_nullifiers: Span<felt252>,
            output_note_commitments: Span<felt252>,
            output_note_asset_ids: Span<felt252>,
            output_note_amounts: Span<u128>,
            output_note_withdraw_authorities: Span<ContractAddress>,
            fee_asset_ids: Span<felt252>,
            fee_recipients: Span<felt252>,
            fee_amounts: Span<u128>,
        ) {
            let expected_message_hash = native_settlement_message_hash(
                starknet::get_contract_address(), transcript_commitment,
            );
            assert(proof_artifact_commitment == expected_message_hash, 'PROOF_COMMITMENT');

            settle_verified_batch(
                ref self,
                batch_id,
                transcript_commitment,
                proof_artifact_commitment,
                clearing_price,
                matched_order_count,
                output_bundle_ref,
                consumed_note_commitments,
                consumed_nullifiers,
                output_note_commitments,
                output_note_asset_ids,
                output_note_amounts,
                output_note_withdraw_authorities,
                fee_asset_ids,
                fee_recipients,
                fee_amounts,
            );
        }

        fn is_batch_settled(self: @ContractState, batch_id: felt252) -> bool {
            self.settled_batches.read(batch_id)
        }

        fn settlement_record(self: @ContractState, batch_id: felt252) -> SettlementRecord {
            let settled = self.settled_batches.read(batch_id);
            assert(settled == true, 'UNKNOWN_SETTLEMENT');

            SettlementRecord {
                batch_id,
                transcript_commitment: self.transcript_commitments.read(batch_id),
                proof_artifact_commitment: self.proof_artifact_commitments.read(batch_id),
                clearing_price: self.clearing_prices.read(batch_id),
                matched_order_count: self.matched_order_counts.read(batch_id),
                output_bundle_ref: self.output_bundle_refs.read(batch_id),
                consumed_note_count: self.consumed_note_counts.read(batch_id),
                consumed_nullifier_count: self.consumed_nullifier_counts.read(batch_id),
                created_output_count: self.created_output_counts.read(batch_id),
                fee_entry_count: self.fee_entry_counts.read(batch_id),
            }
        }

        fn commitment_registry_address(self: @ContractState) -> ContractAddress {
            self.commitment_registry.read()
        }

        fn batch_registry_address(self: @ContractState) -> ContractAddress {
            self.batch_registry.read()
        }

        fn fee_ledger_address(self: @ContractState) -> ContractAddress {
            self.fee_ledger.read()
        }

        fn shielded_asset_adapter_address(self: @ContractState) -> ContractAddress {
            self.shielded_asset_adapter.read()
        }
    }

    fn poseidon_hash2(x: felt252, y: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(x, y, 2);
        result
    }

    fn native_settlement_message_hash(
        settlement_verifier_address: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            0x326c16c927e3e9e1e2cb23ce296a3e7f3d21e798e34d6cac00f9b1241fdfc3a,
            settlement_verifier_address.into(),
        );
        state = poseidon_hash2(state, transcript_commitment);
        state
    }

    fn settle_verified_batch(
        ref self: ContractState,
        batch_id: felt252,
        transcript_commitment: felt252,
        proof_artifact_commitment: felt252,
        clearing_price: u128,
        matched_order_count: u64,
        output_bundle_ref: felt252,
        consumed_note_commitments: Span<felt252>,
        consumed_nullifiers: Span<felt252>,
        output_note_commitments: Span<felt252>,
        output_note_asset_ids: Span<felt252>,
        output_note_amounts: Span<u128>,
        output_note_withdraw_authorities: Span<ContractAddress>,
        fee_asset_ids: Span<felt252>,
        fee_recipients: Span<felt252>,
        fee_amounts: Span<u128>,
    ) {
        let already_settled = self.settled_batches.read(batch_id);
        assert(already_settled == false, 'BATCH_SETTLED');
        let output_count = output_note_commitments.len();
        assert(output_note_asset_ids.len() == output_count, 'BAD_OUTPUT_LENGTH');
        assert(output_note_amounts.len() == output_count, 'BAD_OUTPUT_LENGTH');
        assert(output_note_withdraw_authorities.len() == output_count, 'BAD_OUTPUT_LENGTH');
        let fee_count = fee_asset_ids.len();
        assert(fee_recipients.len() == fee_count, 'BAD_FEE_LENGTH');
        assert(fee_amounts.len() == fee_count, 'BAD_FEE_LENGTH');

        let recomputed_commitment = public_settlement_commitment(
            batch_id,
            clearing_price,
            output_bundle_ref,
            consumed_note_commitments,
            consumed_nullifiers,
            output_note_commitments,
            output_note_asset_ids,
            output_note_amounts,
            output_note_withdraw_authorities,
            fee_asset_ids,
            fee_recipients,
            fee_amounts,
        );
        assert(recomputed_commitment == transcript_commitment, 'SETTLEMENT_BINDING');

        let commitment_registry = ICommitmentRegistryDispatcher {
            contract_address: self.commitment_registry.read(),
        };
        commitment_registry.consume_nullifiers(consumed_nullifiers);
        commitment_registry.register_note_commitments(batch_id, output_note_commitments);

        let batch_registry = IBatchRegistryDispatcher {
            contract_address: self.batch_registry.read(),
        };
        batch_registry.record_settlement_metadata(
            batch_id, transcript_commitment, clearing_price, output_bundle_ref,
        );

        let fee_ledger = IFeeLedgerDispatcher {
            contract_address: self.fee_ledger.read(),
        };
        fee_ledger.accrue_fees(fee_asset_ids, fee_recipients, fee_amounts);

        let shielded_asset_adapter = IShieldedAssetAdapterDispatcher {
            contract_address: self.shielded_asset_adapter.read(),
        };
        shielded_asset_adapter.settle_notes(
            consumed_note_commitments,
            output_note_commitments,
            output_note_asset_ids,
            output_note_amounts,
            output_note_withdraw_authorities,
        );

        self.settled_batches.write(batch_id, true);
        self.transcript_commitments.write(batch_id, transcript_commitment);
        self.proof_artifact_commitments.write(batch_id, proof_artifact_commitment);
        self.clearing_prices.write(batch_id, clearing_price);
        self.matched_order_counts.write(batch_id, matched_order_count);
        self.output_bundle_refs.write(batch_id, output_bundle_ref);
        self.consumed_note_counts.write(batch_id, consumed_note_commitments.len().into());
        self.consumed_nullifier_counts.write(batch_id, consumed_nullifiers.len().into());
        self.created_output_counts.write(batch_id, output_count.into());
        self.fee_entry_counts.write(batch_id, fee_count.into());
    }

    fn public_settlement_commitment(
        batch_id: felt252,
        clearing_price: u128,
        output_bundle_ref: felt252,
        consumed_note_commitments: Span<felt252>,
        consumed_nullifiers: Span<felt252>,
        output_note_commitments: Span<felt252>,
        output_note_asset_ids: Span<felt252>,
        output_note_amounts: Span<u128>,
        output_note_withdraw_authorities: Span<ContractAddress>,
        fee_asset_ids: Span<felt252>,
        fee_recipients: Span<felt252>,
        fee_amounts: Span<u128>,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            0x283f626418aa97a073f64500f7e35dd8bf7c01ff8611917c3c38e5be92eb205,
            batch_id,
        );
        state = poseidon_hash2(state, clearing_price.into());
        state = poseidon_hash2(state, output_bundle_ref);

        let mut index = 0;
        while index < consumed_note_commitments.len() {
            state = poseidon_hash2(state, *consumed_note_commitments.at(index));
            state = poseidon_hash2(state, *consumed_nullifiers.at(index));
            index += 1;
        };

        index = 0;
        while index < output_note_commitments.len() {
            state = poseidon_hash2(state, *output_note_commitments.at(index));
            state = poseidon_hash2(state, *output_note_asset_ids.at(index));
            state = poseidon_hash2(state, (*output_note_amounts.at(index)).into());
            state = poseidon_hash2(
                state, (*output_note_withdraw_authorities.at(index)).into(),
            );
            index += 1;
        };

        index = 0;
        while index < fee_asset_ids.len() {
            state = poseidon_hash2(state, *fee_asset_ids.at(index));
            state = poseidon_hash2(state, *fee_recipients.at(index));
            state = poseidon_hash2(state, (*fee_amounts.at(index)).into());
            index += 1;
        };

        state
    }
}
