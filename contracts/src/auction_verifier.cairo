use starknet::ContractAddress;
use zylith_protocol::types::SettlementRecord;

#[derive(Drop, Serde, Debug, Copy)]
pub struct ProofFacts {
    pub proof_version: felt252,
    pub program_variant: felt252,
    pub virtual_program_hash: felt252,
    pub starknet_os_output_version: felt252,
    pub base_block_number: u64,
    pub base_block_hash: felt252,
    pub starknet_os_config_hash: felt252,
    pub message_to_l1_hashes: Span<felt252>,
}

#[starknet::interface]
pub trait IAuctionVerifier<TContractState> {
    fn set_authorized_settlement_account(ref self: TContractState, account: ContractAddress);
    fn set_proof_validity_blocks(ref self: TContractState, proof_validity_blocks: u64);
    fn compile_auction_proof(
        ref self: TContractState, serialized_private_auction_witness: Span<felt252>,
    ) -> felt252;
    fn submit_settlement_with_proof_facts(
        ref self: TContractState,
        batch_id: felt252,
        order_commitment_root: felt252,
        encrypted_order_set_commitment: felt252,
        transcript_commitment: felt252,
        proof_artifact_commitment: felt252,
        clearing_price: u128,
        matched_order_count: u64,
        output_bundle_ref: felt252,
        consumed_note_commitments: Span<felt252>,
        consumed_nullifiers: Span<felt252>,
        renewal_parent_order_commitments: Span<felt252>,
        renewal_child_nullifiers: Span<felt252>,
        output_note_commitments: Span<felt252>,
        output_note_asset_ids: Span<felt252>,
        output_note_amounts: Span<u128>,
        output_note_withdraw_authorities: Span<felt252>,
        fee_asset_ids: Span<felt252>,
        fee_recipients: Span<felt252>,
        fee_amounts: Span<u128>,
    );
    fn is_batch_settled(self: @TContractState, batch_id: felt252) -> bool;
    fn settlement_record(self: @TContractState, batch_id: felt252) -> SettlementRecord;
    fn settlement_proof_message_hash(
        self: @TContractState, transcript_commitment: felt252,
    ) -> felt252;
    fn commitment_registry_address(self: @TContractState) -> ContractAddress;
    fn batch_registry_address(self: @TContractState) -> ContractAddress;
    fn fee_ledger_address(self: @TContractState) -> ContractAddress;
    fn shielded_asset_adapter_address(self: @TContractState) -> ContractAddress;
    fn authorized_settlement_account_address(self: @TContractState) -> ContractAddress;
    fn proof_validity_blocks(self: @TContractState) -> u64;
}

#[starknet::contract(account)]
pub mod AuctionVerifier {
    use core::array::{Array, ArrayTrait, SpanTrait};
    use core::num::traits::Zero;
    use core::poseidon::{hades_permutation, poseidon_hash_span};
    use starknet::account::Call;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::syscalls::{
        call_contract_syscall, get_execution_info_v3_syscall, send_message_to_l1_syscall,
    };
    use starknet::{
        ContractAddress, SyscallResultTrait, VALIDATED, get_caller_address, get_contract_address,
    };
    use zylith_protocol::batch_registry::{IBatchRegistryDispatcher, IBatchRegistryDispatcherTrait};
    use zylith_protocol::commitment_registry::{
        ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
    };
    use zylith_protocol::fee_ledger::{IFeeLedgerDispatcher, IFeeLedgerDispatcherTrait};
    use zylith_protocol::shielded_asset_adapter::{
        IShieldedAssetAdapterDispatcher, IShieldedAssetAdapterDispatcherTrait,
    };
    use zylith_protocol::types::{BatchStatus, SettlementRecord};
    use zylith_settlement_statement::verify_auction_statement;

    const DEFAULT_PROOF_VALIDITY_BLOCKS: u64 = 450;
    const VIRTUAL_SNOS: felt252 = 'VIRTUAL_SNOS';
    const VIRTUAL_SNOS0: felt252 = 'VIRTUAL_SNOS0';
    const SETTLEMENT_MESSAGE_DOMAIN: felt252 = 'zylith_settle_v1';
    const SETTLEMENT_PROOF_MESSAGE_TO: felt252 = 0;
    const ACCOUNT_EXECUTION_VERSION: felt252 = 3;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        authorized_settlement_account: ContractAddress,
        proof_validity_blocks: u64,
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
        admin: ContractAddress,
        commitment_registry: ContractAddress,
        batch_registry: ContractAddress,
        fee_ledger: ContractAddress,
        shielded_asset_adapter: ContractAddress,
    ) {
        assert(!admin.is_zero(), 'BAD_ADMIN');
        assert(!commitment_registry.is_zero(), 'BAD_REGISTRY');
        assert(!batch_registry.is_zero(), 'BAD_BATCH_REGISTRY');
        assert(!fee_ledger.is_zero(), 'BAD_FEE_LEDGER');
        assert(!shielded_asset_adapter.is_zero(), 'BAD_ADAPTER');
        self.admin.write(admin);
        self.commitment_registry.write(commitment_registry);
        self.batch_registry.write(batch_registry);
        self.fee_ledger.write(fee_ledger);
        self.shielded_asset_adapter.write(shielded_asset_adapter);
        self.proof_validity_blocks.write(DEFAULT_PROOF_VALIDITY_BLOCKS);
    }

    #[abi(embed_v0)]
    impl AuctionVerifierImpl of super::IAuctionVerifier<ContractState> {
        fn set_authorized_settlement_account(ref self: ContractState, account: ContractAddress) {
            assert_admin(@self);
            assert(!account.is_zero(), 'BAD_SETTLEMENT_ACCOUNT');
            self.authorized_settlement_account.write(account);
        }

        fn set_proof_validity_blocks(ref self: ContractState, proof_validity_blocks: u64) {
            assert_admin(@self);
            assert(proof_validity_blocks > 0, 'BAD_PROOF_TTL');
            self.proof_validity_blocks.write(proof_validity_blocks);
        }

        fn compile_auction_proof(
            ref self: ContractState, serialized_private_auction_witness: Span<felt252>,
        ) -> felt252 {
            let transcript_commitment = verify_auction_statement(
                serialized_private_auction_witness,
            );
            emit_settlement_proof_message(transcript_commitment)
        }

        fn submit_settlement_with_proof_facts(
            ref self: ContractState,
            batch_id: felt252,
            order_commitment_root: felt252,
            encrypted_order_set_commitment: felt252,
            transcript_commitment: felt252,
            proof_artifact_commitment: felt252,
            clearing_price: u128,
            matched_order_count: u64,
            output_bundle_ref: felt252,
            consumed_note_commitments: Span<felt252>,
            consumed_nullifiers: Span<felt252>,
            renewal_parent_order_commitments: Span<felt252>,
            renewal_child_nullifiers: Span<felt252>,
            output_note_commitments: Span<felt252>,
            output_note_asset_ids: Span<felt252>,
            output_note_amounts: Span<u128>,
            output_note_withdraw_authorities: Span<felt252>,
            fee_asset_ids: Span<felt252>,
            fee_recipients: Span<felt252>,
            fee_amounts: Span<u128>,
        ) {
            assert_authorized_settlement_account(@self);
            let expected_statement_message = native_settlement_message_hash(
                get_contract_address(), transcript_commitment,
            );
            assert(proof_artifact_commitment == expected_statement_message, 'PROOF_COMMITMENT');
            assert_valid_proof_facts(@self, expected_statement_message);

            settle_verified_batch(
                ref self,
                batch_id,
                order_commitment_root,
                encrypted_order_set_commitment,
                transcript_commitment,
                proof_artifact_commitment,
                clearing_price,
                matched_order_count,
                output_bundle_ref,
                consumed_note_commitments,
                consumed_nullifiers,
                renewal_parent_order_commitments,
                renewal_child_nullifiers,
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

        fn settlement_proof_message_hash(
            self: @ContractState, transcript_commitment: felt252,
        ) -> felt252 {
            let statement_message_hash = native_settlement_message_hash(
                get_contract_address(), transcript_commitment,
            );
            settlement_proof_message_hash_from_statement(
                get_contract_address(), statement_message_hash,
            )
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

        fn authorized_settlement_account_address(self: @ContractState) -> ContractAddress {
            self.authorized_settlement_account.read()
        }

        fn proof_validity_blocks(self: @ContractState) -> u64 {
            self.proof_validity_blocks.read()
        }
    }

    fn emit_settlement_proof_message(transcript_commitment: felt252) -> felt252 {
        let statement_message_hash = native_settlement_message_hash(
            get_contract_address(), transcript_commitment,
        );
        let payload = settlement_proof_payload(statement_message_hash);
        send_message_to_l1_syscall(to_address: SETTLEMENT_PROOF_MESSAGE_TO, payload: payload.span())
            .unwrap_syscall();
        settlement_proof_message_hash_from_statement(get_contract_address(), statement_message_hash)
    }

    #[abi(embed_v0)]
    impl SettlementProofAccountImpl of starknet::account::AccountContract<ContractState> {
        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            let _ = class_hash;
            let tx_info = starknet::get_tx_info().unbox();
            validate_virtual_proof_account_context(
                tx_info.version,
                tx_info.max_fee,
                tx_info.tip,
                tx_info.paymaster_data,
                tx_info.account_deployment_data,
                tx_info.nonce_data_availability_mode,
                tx_info.fee_data_availability_mode,
                tx_info.resource_bounds,
            );
            assert(false, 'DECLARE_UNSUPPORTED');
            VALIDATED
        }

        fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            validate_virtual_proof_account_context(
                tx_info.version,
                tx_info.max_fee,
                tx_info.tip,
                tx_info.paymaster_data,
                tx_info.account_deployment_data,
                tx_info.nonce_data_availability_mode,
                tx_info.fee_data_availability_mode,
                tx_info.resource_bounds,
            );
            validate_single_self_proof_call(calls.span());
            VALIDATED
        }

        fn __execute__(ref self: ContractState, mut calls: Array<Call>) -> Array<Span<felt252>> {
            assert(get_caller_address().is_zero(), 'INVALID_CALLER');
            let tx_info = starknet::get_tx_info().unbox();
            validate_virtual_proof_account_context(
                tx_info.version,
                tx_info.max_fee,
                tx_info.tip,
                tx_info.paymaster_data,
                tx_info.account_deployment_data,
                tx_info.nonce_data_availability_mode,
                tx_info.fee_data_availability_mode,
                tx_info.resource_bounds,
            );
            validate_single_self_proof_call(calls.span());

            let mut results = array![];
            loop {
                match calls.pop_front() {
                    Option::Some(call) => {
                        let return_data = call_contract_syscall(
                            call.to, call.selector, call.calldata,
                        )
                            .unwrap_syscall();
                        results.append(return_data);
                    },
                    Option::None => { break; },
                }
            }
            results
        }
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'UNAUTHORIZED');
    }

    fn assert_authorized_settlement_account(self: @ContractState) {
        assert(get_caller_address() == self.authorized_settlement_account.read(), 'UNAUTHORIZED');
    }

    fn validate_virtual_proof_account_context(
        version: felt252,
        max_fee: u128,
        tip: u128,
        paymaster_data: Span<felt252>,
        account_deployment_data: Span<felt252>,
        nonce_data_availability_mode: u32,
        fee_data_availability_mode: u32,
        resource_bounds: Span<starknet::ResourcesBounds>,
    ) {
        assert(version == ACCOUNT_EXECUTION_VERSION, 'INVALID_TX_VERSION');
        assert(max_fee == 0, 'INVALID_MAX_FEE');
        assert(tip == 0, 'INVALID_TIP');
        assert(paymaster_data.len() == 0, 'PAYMASTER_UNSUPPORTED');
        assert(account_deployment_data.len() == 0, 'ACCOUNT_DEPLOY_UNSUPPORTED');
        assert(nonce_data_availability_mode == 0_u32, 'INVALID_NONCE_DA');
        assert(fee_data_availability_mode == 0_u32, 'INVALID_FEE_DA');
        assert(resource_bounds.len() == 3, 'INVALID_RESOURCE_BOUNDS');
        for resource_bound in resource_bounds {
            assert(resource_bound.max_price_per_unit.is_zero(), 'NON_ZERO_RESOURCE_PRICE');
        };
    }

    fn validate_single_self_proof_call(calls: Span<Call>) {
        assert(calls.len() == 1, 'MULTI_CALL_NOT_SUPPORTED');
        let call = *calls.at(0);
        assert(call.to == get_contract_address(), 'INVALID_PROOF_TARGET');
        assert(call.selector == selector!("compile_auction_proof"), 'INVALID_PROOF_SELECTOR');
    }

    fn assert_valid_proof_facts(self: @ContractState, statement_message_hash: felt252) {
        let execution_info = get_execution_info_v3_syscall().unwrap_syscall();
        let current_block_number = execution_info.block_info.block_number;
        let mut proof_facts_serialized = execution_info.tx_info.proof_facts;
        assert(!proof_facts_serialized.is_empty(), 'EMPTY_PROOF_FACTS');
        let proof_facts: super::ProofFacts = Serde::deserialize(ref proof_facts_serialized)
            .expect('BAD_PROOF_FACTS');
        assert(proof_facts_serialized.is_empty(), 'BAD_PROOF_FACTS_LEN');
        assert(proof_facts.program_variant == VIRTUAL_SNOS, 'BAD_PROOF_PROGRAM');
        assert(proof_facts.starknet_os_output_version == VIRTUAL_SNOS0, 'BAD_PROOF_OUTPUT');
        assert(proof_facts.base_block_number < current_block_number, 'STALE_PROOF_BASE');
        assert(
            current_block_number <= proof_facts.base_block_number
                + self.proof_validity_blocks.read(),
            'EXPIRED_PROOF',
        );

        let expected_message_hash = settlement_proof_message_hash_from_statement(
            get_contract_address(), statement_message_hash,
        );
        let expected_messages = array![expected_message_hash];
        assert(proof_facts.message_to_l1_hashes == expected_messages.span(), 'BAD_PROOF_MSG');
    }

    fn settlement_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![SETTLEMENT_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn settlement_proof_message_hash_from_statement(
        auction_verifier_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![
            auction_verifier_address.into(), SETTLEMENT_PROOF_MESSAGE_TO,
        ];
        let payload = settlement_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn poseidon_hash2(x: felt252, y: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(x, y, 2);
        result
    }

    fn native_settlement_message_hash(
        auction_verifier_address: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            0x326c16c927e3e9e1e2cb23ce296a3e7f3d21e798e34d6cac00f9b1241fdfc3a,
            auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, transcript_commitment);
        state
    }

    fn settle_verified_batch(
        ref self: ContractState,
        batch_id: felt252,
        order_commitment_root: felt252,
        encrypted_order_set_commitment: felt252,
        transcript_commitment: felt252,
        proof_artifact_commitment: felt252,
        clearing_price: u128,
        matched_order_count: u64,
        output_bundle_ref: felt252,
        consumed_note_commitments: Span<felt252>,
        consumed_nullifiers: Span<felt252>,
        renewal_parent_order_commitments: Span<felt252>,
        renewal_child_nullifiers: Span<felt252>,
        output_note_commitments: Span<felt252>,
        output_note_asset_ids: Span<felt252>,
        output_note_amounts: Span<u128>,
        output_note_withdraw_authorities: Span<felt252>,
        fee_asset_ids: Span<felt252>,
        fee_recipients: Span<felt252>,
        fee_amounts: Span<u128>,
    ) {
        let already_settled = self.settled_batches.read(batch_id);
        assert(already_settled == false, 'BATCH_SETTLED');
        assert(consumed_nullifiers.len() == consumed_note_commitments.len(), 'BAD_INPUT_LENGTH');
        assert(
            renewal_parent_order_commitments.len() == renewal_child_nullifiers.len(),
            'BAD_RENEWAL_LENGTH',
        );
        let output_count = output_note_commitments.len();
        assert(output_note_asset_ids.len() == output_count, 'BAD_OUTPUT_LENGTH');
        assert(output_note_amounts.len() == output_count, 'BAD_OUTPUT_LENGTH');
        assert(output_note_withdraw_authorities.len() == output_count, 'BAD_OUTPUT_LENGTH');
        let fee_count = fee_asset_ids.len();
        assert(fee_recipients.len() == fee_count, 'BAD_FEE_LENGTH');
        assert(fee_amounts.len() == fee_count, 'BAD_FEE_LENGTH');

        let batch_registry = IBatchRegistryDispatcher {
            contract_address: self.batch_registry.read(),
        };
        let batch = batch_registry.get_batch(batch_id);
        assert(batch.status == BatchStatus::Prepared, 'BATCH_NOT_PREPARED');
        assert(batch.order_commitment_root == order_commitment_root, 'ORDER_ROOT_BINDING');
        assert(
            batch.encrypted_order_set_commitment == encrypted_order_set_commitment,
            'ENC_SET_BINDING',
        );
        assert(matched_order_count <= batch.order_count, 'MATCH_GT_BATCH');

        let recomputed_commitment = public_settlement_commitment(
            batch_id,
            batch.pair_id,
            batch.epoch_id,
            order_commitment_root,
            encrypted_order_set_commitment,
            clearing_price,
            output_bundle_ref,
            consumed_note_commitments,
            consumed_nullifiers,
            renewal_parent_order_commitments,
            renewal_child_nullifiers,
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
        commitment_registry
            .consume_renewal_children(renewal_parent_order_commitments, renewal_child_nullifiers);
        commitment_registry.register_note_commitments(batch_id, output_note_commitments);

        batch_registry
            .record_settlement_metadata(
                batch_id, transcript_commitment, clearing_price, output_bundle_ref,
            );

        let fee_ledger = IFeeLedgerDispatcher { contract_address: self.fee_ledger.read() };
        fee_ledger.accrue_fees(fee_asset_ids, fee_recipients, fee_amounts);

        let shielded_asset_adapter = IShieldedAssetAdapterDispatcher {
            contract_address: self.shielded_asset_adapter.read(),
        };
        shielded_asset_adapter
            .settle_notes(
                consumed_note_commitments,
                output_note_commitments,
                output_note_asset_ids,
                output_note_amounts,
                output_note_withdraw_authorities,
                fee_asset_ids,
                fee_amounts,
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
        pair_id: felt252,
        batch_epoch: u64,
        order_commitment_root: felt252,
        encrypted_order_set_commitment: felt252,
        clearing_price: u128,
        output_bundle_ref: felt252,
        consumed_note_commitments: Span<felt252>,
        consumed_nullifiers: Span<felt252>,
        renewal_parent_order_commitments: Span<felt252>,
        renewal_child_nullifiers: Span<felt252>,
        output_note_commitments: Span<felt252>,
        output_note_asset_ids: Span<felt252>,
        output_note_amounts: Span<u128>,
        output_note_withdraw_authorities: Span<felt252>,
        fee_asset_ids: Span<felt252>,
        fee_recipients: Span<felt252>,
        fee_amounts: Span<u128>,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            0x283f626418aa97a073f64500f7e35dd8bf7c01ff8611917c3c38e5be92eb205, batch_id,
        );
        state = poseidon_hash2(state, pair_id);
        state = poseidon_hash2(state, batch_epoch.into());
        state = poseidon_hash2(state, order_commitment_root);
        state = poseidon_hash2(state, encrypted_order_set_commitment);
        state = poseidon_hash2(state, clearing_price.into());
        state = poseidon_hash2(state, output_bundle_ref);

        state = poseidon_hash2(state, consumed_note_commitments.len().into());
        let mut index = 0;
        while index < consumed_note_commitments.len() {
            state = poseidon_hash2(state, *consumed_note_commitments.at(index));
            state = poseidon_hash2(state, *consumed_nullifiers.at(index));
            index += 1;
        }

        state = poseidon_hash2(state, renewal_child_nullifiers.len().into());
        index = 0;
        while index < renewal_child_nullifiers.len() {
            state = poseidon_hash2(state, *renewal_parent_order_commitments.at(index));
            state = poseidon_hash2(state, *renewal_child_nullifiers.at(index));
            index += 1;
        }

        state = poseidon_hash2(state, output_note_commitments.len().into());
        index = 0;
        while index < output_note_commitments.len() {
            state = poseidon_hash2(state, *output_note_commitments.at(index));
            state = poseidon_hash2(state, *output_note_asset_ids.at(index));
            state = poseidon_hash2(state, (*output_note_amounts.at(index)).into());
            state = poseidon_hash2(state, *output_note_withdraw_authorities.at(index));
            index += 1;
        }

        state = poseidon_hash2(state, fee_asset_ids.len().into());
        index = 0;
        while index < fee_asset_ids.len() {
            state = poseidon_hash2(state, *fee_asset_ids.at(index));
            state = poseidon_hash2(state, *fee_recipients.at(index));
            state = poseidon_hash2(state, (*fee_amounts.at(index)).into());
            index += 1;
        }

        state
    }
}
