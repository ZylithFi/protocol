use starknet::ContractAddress;

#[derive(Drop, Serde, Debug, Copy)]
pub struct ProofFacts {
    pub proof_version: felt252,
    pub program_variant: felt252,
    pub starknet_os_config_hash: felt252,
    pub starknet_os_output_version: felt252,
    pub base_block_number: u64,
    pub base_block_hash: felt252,
    pub virtual_program_hash: felt252,
    pub message_to_l1_hashes: Span<felt252>,
}

#[starknet::interface]
pub trait IAuctionVerifier<TContractState> {
    fn propose_admin(ref self: TContractState, new_admin: ContractAddress);
    fn accept_admin(ref self: TContractState);
    fn set_pause_guardian(ref self: TContractState, guardian: ContractAddress);
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);
    fn lock_operational_config(ref self: TContractState);
    fn set_authorized_settlement_account(ref self: TContractState, account: ContractAddress);
    fn set_proof_program(
        ref self: TContractState, proof_program: ContractAddress, virtual_program_hash: felt252,
    );
    fn set_statement_proof_program_hash(
        ref self: TContractState, statement_kind: felt252, virtual_program_hash: felt252,
    );
    fn statement_proof_program_hash(self: @TContractState, statement_kind: felt252) -> felt252;
    fn lock_proof_program(ref self: TContractState);
    fn set_proof_validity_blocks(ref self: TContractState, proof_validity_blocks: u64);
    fn set_expected_starknet_os_config_hash(ref self: TContractState, config_hash: felt252);
    fn set_shielded_asset_adapter(ref self: TContractState, adapter: ContractAddress);
    fn set_deposit_root_registrar(ref self: TContractState, registrar: ContractAddress);
    fn set_output_claim_delay_seconds(ref self: TContractState, delay_seconds: u64);
    fn set_protocol_fee_recipient(ref self: TContractState, recipient: felt252);
    fn propose_protocol_fee_recipient(ref self: TContractState, recipient: felt252);
    fn execute_protocol_fee_recipient(ref self: TContractState);
    fn set_relay_fee_recipient(ref self: TContractState, recipient: felt252);
    fn propose_relay_fee_recipient(ref self: TContractState, recipient: felt252);
    fn execute_relay_fee_recipient(ref self: TContractState);
    fn set_pair_fee_config(
        ref self: TContractState, pair_id: felt252, taker_fee_bps: u128, relay_fee_bps: u128,
    );
    fn propose_pair_fee_config(
        ref self: TContractState, pair_id: felt252, taker_fee_bps: u128, relay_fee_bps: u128,
    );
    fn execute_pair_fee_config(ref self: TContractState, pair_id: felt252);
    fn cancel_renewal_parent_marker(
        ref self: TContractState,
        cancel_marker: felt252,
        cancel_authority: felt252,
        sparse_key_low: u128,
        sparse_key_high: u128,
        merkle_path: Span<felt252>,
        merkle_directions: Span<felt252>,
        signature_r: felt252,
        signature_s: felt252,
    );
    fn activate_deposit_root(
        ref self: TContractState, funding_commitment: felt252, deposit_root: felt252,
    );
    fn record_admission_root_with_proof_facts(
        ref self: TContractState,
        batch_id: felt252,
        order_commitment_root: felt252,
        admission_root: felt252,
    );
    fn record_auction_result_with_proof_facts(
        ref self: TContractState,
        batch_id: felt252,
        order_commitment_root: felt252,
        admission_root: felt252,
        transcript_commitment: felt252,
    );
    fn record_multi_pair_solution_with_proof_facts(
        ref self: TContractState, batch_id: felt252, multi_pair_commitment: felt252,
    );
    fn record_nullifier_roots_with_proof_facts(
        ref self: TContractState,
        batch_id: felt252,
        transcript_commitment: felt252,
        prior_nullifier_root: felt252,
        consumed_nullifier_root: felt252,
        new_nullifier_root: felt252,
    );
    fn record_renewal_roots_with_proof_facts(
        ref self: TContractState,
        batch_id: felt252,
        transcript_commitment: felt252,
        prior_renewal_root: felt252,
        renewal_child_root: felt252,
        new_renewal_root: felt252,
    );
    fn record_liquidity_position_roots_with_proof_facts(
        ref self: TContractState,
        batch_id: felt252,
        transcript_commitment: felt252,
        prior_liquidity_position_root: felt252,
        liquidity_position_transition_root: felt252,
        new_liquidity_position_root: felt252,
    );
    fn record_settlement_order_with_proof_facts(
        ref self: TContractState, batch_id: felt252, transcript_commitment: felt252,
    );
    fn record_settlement_input_membership_with_proof_facts(
        ref self: TContractState, batch_id: felt252, transcript_commitment: felt252,
    );
    fn record_settlement_output_recovery_with_proof_facts(
        ref self: TContractState, batch_id: felt252, transcript_commitment: felt252,
    );
    fn clear_unsettled_root_transition(ref self: TContractState, batch_id: felt252);
    fn submit_note_consolidation_with_proof_facts(
        ref self: TContractState,
        consolidation_id: felt252,
        proof_artifact_commitment: felt252,
        output_bundle_ref: felt252,
        prior_note_root: felt252,
        prior_nullifier_root: felt252,
        consumed_note_root: felt252,
        consumed_nullifier_root: felt252,
        output_note_root: felt252,
        new_note_root: felt252,
        new_nullifier_root: felt252,
    );
    fn submit_settlement_with_proof_facts(
        ref self: TContractState,
        batch_id: felt252,
        order_commitment_root: felt252,
        encrypted_order_set_commitment: felt252,
        transcript_commitment: felt252,
        proof_artifact_commitment: felt252,
        clearing_price: u128,
        price_base_scale: u128,
        taker_fee_bps: u128,
        relay_fee_bps: u128,
        protocol_fee_recipient: felt252,
        relay_fee_recipient: felt252,
        output_bundle_ref: felt252,
        prior_note_root: felt252,
        prior_nullifier_root: felt252,
        prior_renewal_root: felt252,
        prior_fee_root: felt252,
        prior_liquidity_position_root: felt252,
        consumed_note_root: felt252,
        consumed_nullifier_root: felt252,
        renewal_child_root: felt252,
        liquidity_position_transition_root: felt252,
        output_note_root: felt252,
        fee_root: felt252,
        new_note_root: felt252,
        new_nullifier_root: felt252,
        new_renewal_root: felt252,
        new_fee_root: felt252,
        new_liquidity_position_root: felt252,
    );
    fn submit_aggregate_settlements_with_proof_facts(
        ref self: TContractState, settlement_inputs: Span<felt252>,
    );
    fn withdraw_settlement_output_to_strk20_with_proof_facts(
        ref self: TContractState,
        batch_id: felt252,
        proof_artifact_commitment: felt252,
        prior_nullifier_root: felt252,
        consumed_nullifier_root: felt252,
        new_nullifier_root: felt252,
        note_commitment: felt252,
        asset_id: felt252,
        amount: u128,
        withdraw_authority: felt252,
        merkle_path: Span<felt252>,
        merkle_directions: Span<felt252>,
        withdraw_authorization_r: felt252,
        withdraw_authorization_s: felt252,
        exit_commitment: felt252,
    ) -> (felt252, u128, felt252);
    fn is_batch_settled(self: @TContractState, batch_id: felt252) -> bool;
    fn is_consolidation_settled(self: @TContractState, consolidation_id: felt252) -> bool;
    fn verified_admission_root(self: @TContractState, batch_id: felt252) -> felt252;
    fn verified_auction_transcript(self: @TContractState, batch_id: felt252) -> felt252;
    fn verified_multi_pair_solution(self: @TContractState, batch_id: felt252) -> (felt252, bool);
    fn output_note_root(self: @TContractState, batch_id: felt252) -> felt252;
    fn current_settlement_roots(self: @TContractState) -> (felt252, felt252, felt252, felt252);
    fn current_liquidity_position_root(self: @TContractState) -> felt252;
    fn renewal_cancel_marker_recorded(self: @TContractState, cancel_marker: felt252) -> bool;
    fn pair_fee_config(self: @TContractState, pair_id: felt252) -> (u128, u128, bool);
    fn pending_pair_fee_config(self: @TContractState, pair_id: felt252) -> (u128, u128, u64, bool);
    fn admin_address(self: @TContractState) -> ContractAddress;
    fn pending_admin_address(self: @TContractState) -> ContractAddress;
    fn admin_transfer_pending(self: @TContractState) -> bool;
    fn pause_guardian_address(self: @TContractState) -> ContractAddress;
    fn is_paused(self: @TContractState) -> bool;
    fn proof_program_is_locked(self: @TContractState) -> bool;
    fn protocol_fee_recipient(self: @TContractState) -> felt252;
    fn pending_protocol_fee_recipient(self: @TContractState) -> (felt252, u64, bool);
    fn relay_fee_recipient(self: @TContractState) -> felt252;
    fn pending_relay_fee_recipient(self: @TContractState) -> (felt252, u64, bool);
    fn note_root_transition_count(self: @TContractState) -> u64;
    fn note_root_transition(
        self: @TContractState, transition_id: u64,
    ) -> (felt252, felt252, felt252, felt252);
    fn settlement_proof_message_hash(
        self: @TContractState, transcript_commitment: felt252,
    ) -> felt252;
    fn note_consolidation_proof_message_hash(
        self: @TContractState, consolidation_commitment: felt252,
    ) -> felt252;
    fn withdrawal_proof_message_hash(
        self: @TContractState, withdrawal_commitment: felt252,
    ) -> felt252;
    fn multi_pair_proof_message_hash(
        self: @TContractState, multi_pair_commitment: felt252,
    ) -> felt252;
}

#[starknet::contract]
pub mod AuctionVerifier {
    use core::array::{Array, ArrayTrait, SpanTrait};
    use core::ecdsa::check_ecdsa_signature;
    use core::num::traits::Zero;
    use core::poseidon::{hades_permutation, poseidon_hash_span};
    use core::traits::TryInto;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::syscalls::get_execution_info_v3_syscall;
    use starknet::{
        ContractAddress, SyscallResultTrait, get_caller_address, get_contract_address, get_tx_info,
    };
    use zylith_protocol::batch_registry::{IBatchRegistryDispatcher, IBatchRegistryDispatcherTrait};
    use zylith_protocol::shielded_asset_adapter::{
        IShieldedAssetAdapterDispatcher, IShieldedAssetAdapterDispatcherTrait,
    };
    use zylith_protocol::types::BatchStatus;

    const DEFAULT_PROOF_VALIDITY_BLOCKS: u64 = 450;
    const VIRTUAL_SNOS: felt252 = 'VIRTUAL_SNOS';
    const VIRTUAL_SNOS0: felt252 = 'VIRTUAL_SNOS0';
    const EXPECTED_PROOF_VERSION: felt252 = 'PROOF1';
    const SETTLEMENT_MESSAGE_DOMAIN: felt252 = 'zylith_settle_v1';
    const NULLIFIER_MESSAGE_DOMAIN: felt252 = 'zylith_null_v1';
    const RENEWAL_MESSAGE_DOMAIN: felt252 = 'zylith_renew_v1';
    const LIQUIDITY_POSITION_MESSAGE_DOMAIN: felt252 = 'zylith_lp_v1';
    const SETTLEMENT_ORDER_MESSAGE_DOMAIN: felt252 = 'zylith_ord_v1';
    const SETTLEMENT_INPUT_MEMBERSHIP_MESSAGE_DOMAIN: felt252 = 'zylith_inmem_v1';
    const SETTLEMENT_OUTPUT_RECOVERY_MESSAGE_DOMAIN: felt252 = 'zylith_outrec_v1';
    const NOTE_CONSOLIDATION_MESSAGE_DOMAIN: felt252 = 'zylith_consol_v1';
    const WITHDRAWAL_MESSAGE_DOMAIN: felt252 = 'zylith_withdraw_v1';
    const ADMISSION_MESSAGE_DOMAIN: felt252 = 'zylith_admit_v1';
    const AUCTION_RESULT_MESSAGE_DOMAIN: felt252 = 'zylith_aucres_v1';
    const MULTI_PAIR_MESSAGE_DOMAIN: felt252 = 'zylith_mpair_v1';
    const SETTLEMENT_PROOF_MESSAGE_TO: felt252 = 0;
    const PUBLIC_NOTE_WITHDRAWAL_DOMAIN: felt252 = 0x7a796c6974685f6e6f74655f77697468647261775f7631;
    const ROOT_ONLY_STATE_TRANSITION_DOMAIN: felt252 =
        0x01f14f0555b0b80fd6af9553623a021c472d8c930dfcb5b204b35b26f0d2b1b2;
    const LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN: felt252 =
        0x0301dfad9cc240f421fd32f6b74d72002abc7f4056b885950bc5bc779213e5f7;
    const FEE_BPS_DENOMINATOR: u128 = 10000;
    const MAX_PAIR_FEE_BPS: u128 = 100;
    const PAIR_FEE_TIMELOCK_SECONDS: u64 = 86400;
    const FEE_RECIPIENT_TIMELOCK_SECONDS: u64 = 604800;
    const MAX_OUTPUT_CLAIM_DELAY_SECONDS: u64 = 604800;
    const MAX_AGGREGATE_SETTLEMENTS: usize = 16;
    const RENEWAL_PARENT_CANCEL_DOMAIN: felt252 =
        0x26f84b60309c08d4030876815edb467f89f78e5a5f62823af4521f1be502ca3;
    const RENEWAL_SPARSE_LEAF_DOMAIN: felt252 =
        0x03fd7c748b95292c230aa528dc391912cd4557ad3e157e94ab06b22af433f967;
    const RENEWAL_SPARSE_NODE_DOMAIN: felt252 =
        0x02de7e98b8f1ba580329d7cfcf51a36f6eb4f8611cae6f82b34e116bb9c2588c;
    const RENEWAL_SPARSE_TREE_DEPTH: usize = 128;
    const SPARSE_KEY_HIGH_MAX: u128 = 0x8000000000000110000000000000000;
    const TWO_POW_128: felt252 = 0x100000000000000000000000000000000;
    const OUTPUT_NOTE_LEAF_DOMAIN: felt252 =
        0x0f0c89949c6cba4ac7f170f7f00809b458b997f2e394481c7ab58cc68aa49b3;
    const OUTPUT_NOTE_NODE_DOMAIN: felt252 =
        0x03c6998f476a618431be1c1764a6724f13c0739be395bab4c1217bc0a65b2ee7;
    const OUTPUT_WITHDRAWAL_STRK20_EXIT_DOMAIN: felt252 =
        0x7a796c6974685f7374726b32305f657869745f7631;
    const NOTE_ROOT_TRANSITION_DEPOSIT: felt252 = 0;
    const NOTE_ROOT_TRANSITION_SETTLEMENT: felt252 = 1;
    const NOTE_ROOT_TRANSITION_CONSOLIDATION: felt252 = 2;
    const STATEMENT_ADMISSION: felt252 = 'ADMISSION';
    const STATEMENT_AUCTION_RESULT: felt252 = 'AUCTION_RESULT';
    const STATEMENT_NULLIFIER: felt252 = 'NULLIFIER';
    const STATEMENT_RENEWAL: felt252 = 'RENEWAL';
    const STATEMENT_LIQUIDITY_POSITION: felt252 = 'LIQUIDITY_POSITION';
    const STATEMENT_SETTLEMENT: felt252 = 'SETTLEMENT';
    const STATEMENT_SETTLEMENT_ORDER: felt252 = 'SETTLEMENT_ORDER';
    const STATEMENT_SETTLEMENT_INPUT_MEMBERSHIP: felt252 = 'SETTLEMENT_INPUT_MEMBERSHIP';
    const STATEMENT_SETTLEMENT_OUTPUT_RECOVERY: felt252 = 'SETTLEMENT_OUTPUT_RECOVERY';
    const STATEMENT_NOTE_CONSOLIDATION: felt252 = 'NOTE_CONSOLIDATION';
    const STATEMENT_AGGREGATE_SETTLEMENT: felt252 = 'AGGREGATE_SETTLEMENT';
    const STATEMENT_WITHDRAWAL: felt252 = 'WITHDRAWAL';
    const STATEMENT_MULTI_PAIR: felt252 = 'MULTI_PAIR';
    #[storage]
    struct Storage {
        admin: ContractAddress,
        pending_admin: ContractAddress,
        admin_transfer_pending: bool,
        pause_guardian: ContractAddress,
        paused: bool,
        operational_config_locked: bool,
        authorized_settlement_account: ContractAddress,
        proof_program: ContractAddress,
        proof_program_hash: felt252,
        statement_proof_program_hashes: Map<felt252, felt252>,
        proof_program_locked: bool,
        proof_validity_blocks: u64,
        expected_starknet_os_config_hash: felt252,
        output_claim_delay_seconds: u64,
        batch_registry: ContractAddress,
        shielded_asset_adapter: ContractAddress,
        protocol_fee_recipient: felt252,
        pending_protocol_fee_recipient: felt252,
        pending_protocol_fee_recipient_eta: u64,
        pending_protocol_fee_recipient_active: bool,
        relay_fee_recipient: felt252,
        pending_relay_fee_recipient: felt252,
        pending_relay_fee_recipient_eta: u64,
        pending_relay_fee_recipient_active: bool,
        pair_taker_fee_bps: Map<felt252, u128>,
        pair_relay_fee_bps: Map<felt252, u128>,
        pair_fee_configured: Map<felt252, bool>,
        pending_pair_taker_fee_bps: Map<felt252, u128>,
        pending_pair_relay_fee_bps: Map<felt252, u128>,
        pending_pair_fee_config_eta: Map<felt252, u64>,
        pending_pair_fee_config_active: Map<felt252, bool>,
        deposit_root_registrar: ContractAddress,
        settled_batches: Map<felt252, bool>,
        settled_consolidations: Map<felt252, bool>,
        settled_at_unix_seconds: Map<felt252, u64>,
        withdrawn_output_notes: Map<felt252, bool>,
        activated_funding_commitments: Map<felt252, bool>,
        current_note_root: felt252,
        current_nullifier_root: felt252,
        current_renewal_root: felt252,
        current_fee_root: felt252,
        current_liquidity_position_root: felt252,
        pending_root_transition_batch: felt252,
        renewal_cancel_markers: Map<felt252, bool>,
        note_root_transition_count: u64,
        note_root_transition_kinds: Map<u64, felt252>,
        note_root_transition_keys: Map<u64, felt252>,
        note_root_transition_batch_roots: Map<u64, felt252>,
        note_root_transition_new_roots: Map<u64, felt252>,
        output_note_roots: Map<felt252, felt252>,
        verified_admission_roots: Map<felt252, felt252>,
        verified_auction_transcripts: Map<felt252, felt252>,
        verified_multi_pair_solution_commitments: Map<felt252, felt252>,
        verified_multi_pair_solution_active: Map<felt252, bool>,
        verified_nullifier_roots_active: Map<felt252, bool>,
        verified_nullifier_transcripts: Map<felt252, felt252>,
        verified_prior_nullifier_roots: Map<felt252, felt252>,
        verified_consumed_nullifier_roots: Map<felt252, felt252>,
        verified_new_nullifier_roots: Map<felt252, felt252>,
        verified_renewal_roots_active: Map<felt252, bool>,
        verified_renewal_transcripts: Map<felt252, felt252>,
        verified_prior_renewal_roots: Map<felt252, felt252>,
        verified_renewal_child_roots: Map<felt252, felt252>,
        verified_new_renewal_roots: Map<felt252, felt252>,
        verified_liquidity_position_roots_active: Map<felt252, bool>,
        verified_liquidity_position_transcripts: Map<felt252, felt252>,
        verified_prior_liquidity_position_roots: Map<felt252, felt252>,
        verified_liquidity_position_transition_roots: Map<felt252, felt252>,
        verified_new_liquidity_position_roots: Map<felt252, felt252>,
        verified_settlement_order_active: Map<felt252, bool>,
        verified_settlement_order_transcripts: Map<felt252, felt252>,
        verified_settlement_input_membership_active: Map<felt252, bool>,
        verified_settlement_input_membership_transcripts: Map<felt252, felt252>,
        verified_settlement_output_recovery_active: Map<felt252, bool>,
        verified_settlement_output_recovery_transcripts: Map<felt252, felt252>,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        admin: ContractAddress,
        batch_registry: ContractAddress,
        initial_note_root: felt252,
        initial_nullifier_root: felt252,
        initial_renewal_root: felt252,
        initial_fee_root: felt252,
    ) {
        assert(!admin.is_zero(), 'BAD_ADMIN');
        assert(!batch_registry.is_zero(), 'BAD_BATCH_REGISTRY');
        self.admin.write(admin);
        self.batch_registry.write(batch_registry);
        self.current_note_root.write(initial_note_root);
        self.current_nullifier_root.write(initial_nullifier_root);
        self.current_renewal_root.write(initial_renewal_root);
        self.current_fee_root.write(initial_fee_root);
        self.proof_validity_blocks.write(DEFAULT_PROOF_VALIDITY_BLOCKS);
    }

    #[abi(embed_v0)]
    impl AuctionVerifierImpl of super::IAuctionVerifier<ContractState> {
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

        fn set_pause_guardian(ref self: ContractState, guardian: ContractAddress) {
            assert_admin(@self);
            assert(!guardian.is_zero(), 'BAD_GUARDIAN');
            self.pause_guardian.write(guardian);
        }

        fn pause(ref self: ContractState) {
            assert_pause_authority(@self);
            self.paused.write(true);
        }

        fn unpause(ref self: ContractState) {
            assert_admin(@self);
            self.paused.write(false);
        }

        fn lock_operational_config(ref self: ContractState) {
            assert_admin(@self);
            assert(self.expected_starknet_os_config_hash.read() != 0, 'OS_CONFIG_UNSET');
            assert(!self.authorized_settlement_account.read().is_zero(), 'SETTLEMENT_ACCT_UNSET');
            assert(!self.proof_program.read().is_zero(), 'PROOF_PROGRAM_UNSET');
            assert(self.proof_program_hash.read() != 0, 'PROOF_HASH_UNSET');
            assert_required_statement_proof_hashes(@self);
            assert(self.proof_program_locked.read(), 'PROOF_PROGRAM_UNLOCKED');
            assert(!self.shielded_asset_adapter.read().is_zero(), 'ADAPTER_UNSET');
            assert(!self.deposit_root_registrar.read().is_zero(), 'DEPOSIT_REG_UNSET');
            assert(self.protocol_fee_recipient.read() != 0, 'FEE_RECIPIENT_UNSET');
            assert(self.relay_fee_recipient.read() != 0, 'RELAY_RECIPIENT_UNSET');
            self.operational_config_locked.write(true);
        }

        fn set_authorized_settlement_account(ref self: ContractState, account: ContractAddress) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(!account.is_zero(), 'BAD_SETTLEMENT_ACCOUNT');
            self.authorized_settlement_account.write(account);
        }

        fn set_proof_program(
            ref self: ContractState, proof_program: ContractAddress, virtual_program_hash: felt252,
        ) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(!self.proof_program_locked.read(), 'PROOF_PROGRAM_LOCKED');
            assert(!proof_program.is_zero(), 'BAD_PROOF_PROGRAM');
            assert(virtual_program_hash != 0, 'BAD_PROOF_HASH');
            self.proof_program.write(proof_program);
            self.proof_program_hash.write(virtual_program_hash);
        }

        fn set_statement_proof_program_hash(
            ref self: ContractState, statement_kind: felt252, virtual_program_hash: felt252,
        ) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(!self.proof_program_locked.read(), 'PROOF_PROGRAM_LOCKED');
            assert(statement_kind != 0, 'BAD_STATEMENT_KIND');
            assert(virtual_program_hash != 0, 'BAD_PROOF_HASH');
            self.statement_proof_program_hashes.write(statement_kind, virtual_program_hash);
        }

        fn statement_proof_program_hash(self: @ContractState, statement_kind: felt252) -> felt252 {
            statement_proof_hash_or_default(self, statement_kind)
        }

        fn lock_proof_program(ref self: ContractState) {
            assert_admin(@self);
            assert(!self.proof_program.read().is_zero(), 'PROOF_PROGRAM_UNSET');
            assert(self.proof_program_hash.read() != 0, 'PROOF_HASH_UNSET');
            assert_required_statement_proof_hashes(@self);
            self.proof_program_locked.write(true);
        }

        fn set_proof_validity_blocks(ref self: ContractState, proof_validity_blocks: u64) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(proof_validity_blocks > 0, 'BAD_PROOF_TTL');
            self.proof_validity_blocks.write(proof_validity_blocks);
        }

        fn set_expected_starknet_os_config_hash(ref self: ContractState, config_hash: felt252) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(config_hash != 0, 'BAD_OS_CONFIG');
            self.expected_starknet_os_config_hash.write(config_hash);
        }

        fn set_shielded_asset_adapter(ref self: ContractState, adapter: ContractAddress) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(!adapter.is_zero(), 'BAD_ADAPTER');
            self.shielded_asset_adapter.write(adapter);
        }

        fn set_deposit_root_registrar(ref self: ContractState, registrar: ContractAddress) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(!registrar.is_zero(), 'BAD_DEPOSIT_REGISTRAR');
            self.deposit_root_registrar.write(registrar);
        }

        fn set_output_claim_delay_seconds(ref self: ContractState, delay_seconds: u64) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(delay_seconds <= MAX_OUTPUT_CLAIM_DELAY_SECONDS, 'BAD_CLAIM_DELAY');
            self.output_claim_delay_seconds.write(delay_seconds);
        }

        fn set_protocol_fee_recipient(ref self: ContractState, recipient: felt252) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(recipient != 0, 'BAD_FEE_RECIPIENT');
            assert(self.protocol_fee_recipient.read() == 0, 'FEE_RECIP_TIMELOCK');
            self.protocol_fee_recipient.write(recipient);
        }

        fn propose_protocol_fee_recipient(ref self: ContractState, recipient: felt252) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(recipient != 0, 'BAD_FEE_RECIPIENT');
            assert(self.protocol_fee_recipient.read() != 0, 'FEE_RECIP_UNSET');
            self.pending_protocol_fee_recipient.write(recipient);
            self
                .pending_protocol_fee_recipient_eta
                .write(current_block_timestamp() + FEE_RECIPIENT_TIMELOCK_SECONDS);
            self.pending_protocol_fee_recipient_active.write(true);
        }

        fn execute_protocol_fee_recipient(ref self: ContractState) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(self.pending_protocol_fee_recipient_active.read(), 'NO_FEE_RECIP_PENDING');
            let eta = self.pending_protocol_fee_recipient_eta.read();
            assert(current_block_timestamp() >= eta, 'FEE_RECIP_TIMELOCK');
            let recipient = self.pending_protocol_fee_recipient.read();
            assert(recipient != 0, 'BAD_FEE_RECIPIENT');
            self.protocol_fee_recipient.write(recipient);
            self.pending_protocol_fee_recipient_active.write(false);
            self.pending_protocol_fee_recipient_eta.write(0);
            self.pending_protocol_fee_recipient.write(0);
        }

        fn set_relay_fee_recipient(ref self: ContractState, recipient: felt252) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(recipient != 0, 'BAD_RELAY_RECIPIENT');
            assert(self.relay_fee_recipient.read() == 0, 'RELAY_RECIP_TIMELOCK');
            self.relay_fee_recipient.write(recipient);
        }

        fn propose_relay_fee_recipient(ref self: ContractState, recipient: felt252) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(recipient != 0, 'BAD_RELAY_RECIPIENT');
            assert(self.relay_fee_recipient.read() != 0, 'RELAY_RECIP_UNSET');
            self.pending_relay_fee_recipient.write(recipient);
            self
                .pending_relay_fee_recipient_eta
                .write(current_block_timestamp() + FEE_RECIPIENT_TIMELOCK_SECONDS);
            self.pending_relay_fee_recipient_active.write(true);
        }

        fn execute_relay_fee_recipient(ref self: ContractState) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(self.pending_relay_fee_recipient_active.read(), 'NO_RELAY_RECIP_PENDING');
            let eta = self.pending_relay_fee_recipient_eta.read();
            assert(current_block_timestamp() >= eta, 'RELAY_RECIP_TIMELOCK');
            let recipient = self.pending_relay_fee_recipient.read();
            assert(recipient != 0, 'BAD_RELAY_RECIPIENT');
            self.relay_fee_recipient.write(recipient);
            self.pending_relay_fee_recipient_active.write(false);
            self.pending_relay_fee_recipient_eta.write(0);
            self.pending_relay_fee_recipient.write(0);
        }

        fn set_pair_fee_config(
            ref self: ContractState, pair_id: felt252, taker_fee_bps: u128, relay_fee_bps: u128,
        ) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(pair_id != 0, 'BAD_PAIR');
            assert(taker_fee_bps <= MAX_PAIR_FEE_BPS, 'BAD_TAKER_FEE');
            assert(relay_fee_bps <= MAX_PAIR_FEE_BPS, 'BAD_RELAY_FEE');
            assert(!self.pair_fee_configured.read(pair_id), 'PAIR_FEE_TIMELOCK');
            self.pair_taker_fee_bps.write(pair_id, taker_fee_bps);
            self.pair_relay_fee_bps.write(pair_id, relay_fee_bps);
            self.pair_fee_configured.write(pair_id, true);
        }

        fn propose_pair_fee_config(
            ref self: ContractState, pair_id: felt252, taker_fee_bps: u128, relay_fee_bps: u128,
        ) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(pair_id != 0, 'BAD_PAIR');
            assert(self.pair_fee_configured.read(pair_id), 'PAIR_FEE_UNSET');
            assert(taker_fee_bps <= MAX_PAIR_FEE_BPS, 'BAD_TAKER_FEE');
            assert(relay_fee_bps <= MAX_PAIR_FEE_BPS, 'BAD_RELAY_FEE');
            self.pending_pair_taker_fee_bps.write(pair_id, taker_fee_bps);
            self.pending_pair_relay_fee_bps.write(pair_id, relay_fee_bps);
            self
                .pending_pair_fee_config_eta
                .write(pair_id, current_block_timestamp() + PAIR_FEE_TIMELOCK_SECONDS);
            self.pending_pair_fee_config_active.write(pair_id, true);
        }

        fn execute_pair_fee_config(ref self: ContractState, pair_id: felt252) {
            assert_admin(@self);
            assert(!self.operational_config_locked.read(), 'CONFIG_LOCKED');
            assert(pair_id != 0, 'BAD_PAIR');
            assert(self.pending_pair_fee_config_active.read(pair_id), 'NO_PAIR_FEE_PENDING');
            let eta = self.pending_pair_fee_config_eta.read(pair_id);
            assert(current_block_timestamp() >= eta, 'PAIR_FEE_TIMELOCK');
            self.pair_taker_fee_bps.write(pair_id, self.pending_pair_taker_fee_bps.read(pair_id));
            self.pair_relay_fee_bps.write(pair_id, self.pending_pair_relay_fee_bps.read(pair_id));
            self.pair_fee_configured.write(pair_id, true);
            self.pending_pair_fee_config_active.write(pair_id, false);
            self.pending_pair_fee_config_eta.write(pair_id, 0);
            self.pending_pair_taker_fee_bps.write(pair_id, 0);
            self.pending_pair_relay_fee_bps.write(pair_id, 0);
        }

        fn cancel_renewal_parent_marker(
            ref self: ContractState,
            cancel_marker: felt252,
            cancel_authority: felt252,
            sparse_key_low: u128,
            sparse_key_high: u128,
            merkle_path: Span<felt252>,
            merkle_directions: Span<felt252>,
            signature_r: felt252,
            signature_s: felt252,
        ) {
            assert_not_paused(@self);
            assert_no_pending_root_transition(@self);
            assert(cancel_marker != 0, 'BAD_CANCEL_MARKER');
            assert(cancel_authority != 0, 'BAD_CANCEL_AUTHORITY');
            assert(signature_r != 0, 'BAD_CANCEL_SIG');
            assert(signature_s != 0, 'BAD_CANCEL_SIG');
            assert(!self.renewal_cancel_markers.read(cancel_marker), 'RENEWAL_CANCEL_EXISTS');
            assert(
                cancel_marker == sparse_key_low.into() + sparse_key_high.into() * TWO_POW_128,
                'RENEWAL_KEY_BIND',
            );
            assert_renewal_sparse_key_in_field(sparse_key_low, sparse_key_high);
            assert(
                check_ecdsa_signature(
                    renewal_parent_cancel_marker_message_hash(cancel_marker),
                    cancel_authority,
                    signature_r,
                    signature_s,
                ),
                'BAD_CANCEL_SIG',
            );
            let prior_root = self.current_renewal_root.read();
            let new_root = sparse_insert_renewal_entry(
                prior_root,
                cancel_marker,
                sparse_key_low,
                sparse_key_high,
                merkle_path,
                merkle_directions,
            );
            self.current_renewal_root.write(new_root);
            self.renewal_cancel_markers.write(cancel_marker, true);
        }

        fn activate_deposit_root(
            ref self: ContractState, funding_commitment: felt252, deposit_root: felt252,
        ) {
            assert_deposit_root_registrar(@self);
            assert_not_paused(@self);
            assert_no_pending_root_transition(@self);
            assert(funding_commitment != 0, 'BAD_FUNDING');
            assert(deposit_root != 0, 'BAD_DEPOSIT_ROOT');
            let already_activated = self.activated_funding_commitments.read(funding_commitment);
            assert(already_activated == false, 'FUNDING_ACTIVE');
            let prior_note_root = self.current_note_root.read();
            let new_note_root = state_transition_root(prior_note_root, deposit_root);
            self.activated_funding_commitments.write(funding_commitment, true);
            self.current_note_root.write(new_note_root);
            record_note_root_transition(
                ref self,
                NOTE_ROOT_TRANSITION_DEPOSIT,
                funding_commitment,
                deposit_root,
                new_note_root,
            );
        }

        fn record_admission_root_with_proof_facts(
            ref self: ContractState,
            batch_id: felt252,
            order_commitment_root: felt252,
            admission_root: felt252,
        ) {
            assert_authorized_settlement_account(@self);
            assert_not_paused(@self);
            assert(batch_id != 0, 'BAD_BATCH');
            assert(self.settled_batches.read(batch_id) == false, 'BATCH_SETTLED');
            assert(self.verified_admission_roots.read(batch_id) == 0, 'ADMISSION_EXISTS');
            assert(order_commitment_root != 0, 'BAD_ORDER_ROOT');
            assert(admission_root != 0, 'BAD_ADMISSION_ROOT');
            let batch_registry = IBatchRegistryDispatcher {
                contract_address: self.batch_registry.read(),
            };
            let batch = batch_registry.get_batch(batch_id);
            assert(batch.order_commitment_root == order_commitment_root, 'ORDER_ROOT_BINDING');
            let expected_statement_message = native_admission_message_hash(
                get_contract_address(), batch_id, order_commitment_root, admission_root,
            );
            let expected_messages = array![
                admission_proof_message_hash_from_statement(
                    self.proof_program.read(), expected_statement_message,
                ),
            ];
            assert_valid_proof_facts_messages(@self, expected_messages.span(), STATEMENT_ADMISSION);
            self.verified_admission_roots.write(batch_id, admission_root);
        }

        fn record_auction_result_with_proof_facts(
            ref self: ContractState,
            batch_id: felt252,
            order_commitment_root: felt252,
            admission_root: felt252,
            transcript_commitment: felt252,
        ) {
            assert_authorized_settlement_account(@self);
            assert_not_paused(@self);
            assert(batch_id != 0, 'BAD_BATCH');
            assert(self.settled_batches.read(batch_id) == false, 'BATCH_SETTLED');
            assert(order_commitment_root != 0, 'BAD_ORDER_ROOT');
            assert(admission_root != 0, 'BAD_ADMISSION_ROOT');
            assert(transcript_commitment != 0, 'BAD_TRANSCRIPT');
            let existing_transcript = self.verified_auction_transcripts.read(batch_id);
            if existing_transcript != 0 {
                if existing_transcript == transcript_commitment {
                    return;
                }
                assert(false, 'AUCTION_RESULT_EXISTS');
            }
            let batch_registry = IBatchRegistryDispatcher {
                contract_address: self.batch_registry.read(),
            };
            let batch = batch_registry.get_batch(batch_id);
            assert(batch.order_commitment_root == order_commitment_root, 'ORDER_ROOT_BINDING');
            let verified_admission = self.verified_admission_roots.read(batch_id);
            assert(verified_admission != 0, 'ADMISSION_REQUIRED');
            assert(verified_admission == admission_root, 'ADMISSION_REQUIRED');
            let expected_statement_message = native_auction_result_message_hash(
                get_contract_address(),
                batch_id,
                order_commitment_root,
                admission_root,
                transcript_commitment,
            );
            let expected_messages = array![
                auction_result_proof_message_hash_from_statement(
                    self.proof_program.read(), expected_statement_message,
                ),
            ];
            assert_valid_proof_facts_messages(
                @self, expected_messages.span(), STATEMENT_AUCTION_RESULT,
            );
            self.verified_auction_transcripts.write(batch_id, transcript_commitment);
        }

        fn record_multi_pair_solution_with_proof_facts(
            ref self: ContractState, batch_id: felt252, multi_pair_commitment: felt252,
        ) {
            assert_authorized_settlement_account(@self);
            assert_not_paused(@self);
            assert(batch_id != 0, 'BAD_BATCH');
            assert(multi_pair_commitment != 0, 'BAD_MULTI_PAIR');
            assert(self.settled_batches.read(batch_id) == false, 'BATCH_SETTLED');
            if self.verified_multi_pair_solution_active.read(batch_id) {
                assert(
                    self
                        .verified_multi_pair_solution_commitments
                        .read(batch_id) == multi_pair_commitment,
                    'MULTI_PAIR_EXISTS',
                );
            } else {
                let expected_statement_message = native_multi_pair_message_hash(
                    get_contract_address(), multi_pair_commitment,
                );
                let expected_messages = array![
                    multi_pair_proof_message_hash_from_statement(
                        self.proof_program.read(), expected_statement_message,
                    ),
                ];
                assert_valid_proof_facts_messages(
                    @self, expected_messages.span(), STATEMENT_MULTI_PAIR,
                );
                self
                    .verified_multi_pair_solution_commitments
                    .write(batch_id, multi_pair_commitment);
                self.verified_multi_pair_solution_active.write(batch_id, true);
            }
        }

        fn record_nullifier_roots_with_proof_facts(
            ref self: ContractState,
            batch_id: felt252,
            transcript_commitment: felt252,
            prior_nullifier_root: felt252,
            consumed_nullifier_root: felt252,
            new_nullifier_root: felt252,
        ) {
            assert_authorized_settlement_account(@self);
            assert_not_paused(@self);
            assert(batch_id != 0, 'BAD_BATCH');
            assert(self.settled_batches.read(batch_id) == false, 'BATCH_SETTLED');
            assert(transcript_commitment != 0, 'BAD_TRANSCRIPT');
            assert(
                self.verified_auction_transcripts.read(batch_id) == transcript_commitment,
                'AUCTION_RESULT_REQUIRED',
            );
            if self.verified_nullifier_roots_active.read(batch_id) {
                assert(
                    self.verified_nullifier_transcripts.read(batch_id) == transcript_commitment,
                    'NULLIFIER_EXISTS',
                );
                assert(
                    self.verified_prior_nullifier_roots.read(batch_id) == prior_nullifier_root,
                    'NULLIFIER_EXISTS',
                );
                assert(
                    self
                        .verified_consumed_nullifier_roots
                        .read(batch_id) == consumed_nullifier_root,
                    'NULLIFIER_EXISTS',
                );
                assert(
                    self.verified_new_nullifier_roots.read(batch_id) == new_nullifier_root,
                    'NULLIFIER_EXISTS',
                );
            } else {
                claim_root_transition(ref self, batch_id);
                assert(
                    prior_nullifier_root == self.current_nullifier_root.read(),
                    'NULLIFIER_ROOT_STALE',
                );
                let expected_statement_message = native_nullifier_message_hash(
                    get_contract_address(),
                    transcript_commitment,
                    prior_nullifier_root,
                    consumed_nullifier_root,
                    new_nullifier_root,
                );
                let expected_messages = array![
                    nullifier_proof_message_hash_from_statement(
                        self.proof_program.read(), expected_statement_message,
                    ),
                ];
                assert_valid_proof_facts_messages(
                    @self, expected_messages.span(), STATEMENT_NULLIFIER,
                );
                self.verified_nullifier_roots_active.write(batch_id, true);
                self.verified_nullifier_transcripts.write(batch_id, transcript_commitment);
                self.verified_prior_nullifier_roots.write(batch_id, prior_nullifier_root);
                self.verified_consumed_nullifier_roots.write(batch_id, consumed_nullifier_root);
                self.verified_new_nullifier_roots.write(batch_id, new_nullifier_root);
            }
        }

        fn record_renewal_roots_with_proof_facts(
            ref self: ContractState,
            batch_id: felt252,
            transcript_commitment: felt252,
            prior_renewal_root: felt252,
            renewal_child_root: felt252,
            new_renewal_root: felt252,
        ) {
            assert_authorized_settlement_account(@self);
            assert_not_paused(@self);
            assert(batch_id != 0, 'BAD_BATCH');
            assert(self.settled_batches.read(batch_id) == false, 'BATCH_SETTLED');
            assert(transcript_commitment != 0, 'BAD_TRANSCRIPT');
            assert(
                self.verified_auction_transcripts.read(batch_id) == transcript_commitment,
                'AUCTION_RESULT_REQUIRED',
            );
            if self.verified_renewal_roots_active.read(batch_id) {
                assert(
                    self.verified_renewal_transcripts.read(batch_id) == transcript_commitment,
                    'RENEWAL_EXISTS',
                );
                assert(
                    self.verified_prior_renewal_roots.read(batch_id) == prior_renewal_root,
                    'RENEWAL_EXISTS',
                );
                assert(
                    self.verified_renewal_child_roots.read(batch_id) == renewal_child_root,
                    'RENEWAL_EXISTS',
                );
                assert(
                    self.verified_new_renewal_roots.read(batch_id) == new_renewal_root,
                    'RENEWAL_EXISTS',
                );
            } else {
                claim_root_transition(ref self, batch_id);
                assert(
                    prior_renewal_root == self.current_renewal_root.read(), 'RENEWAL_ROOT_STALE',
                );
                let expected_statement_message = native_renewal_message_hash(
                    get_contract_address(),
                    transcript_commitment,
                    prior_renewal_root,
                    renewal_child_root,
                    new_renewal_root,
                );
                let expected_messages = array![
                    renewal_proof_message_hash_from_statement(
                        self.proof_program.read(), expected_statement_message,
                    ),
                ];
                assert_valid_proof_facts_messages(
                    @self, expected_messages.span(), STATEMENT_RENEWAL,
                );
                self.verified_renewal_roots_active.write(batch_id, true);
                self.verified_renewal_transcripts.write(batch_id, transcript_commitment);
                self.verified_prior_renewal_roots.write(batch_id, prior_renewal_root);
                self.verified_renewal_child_roots.write(batch_id, renewal_child_root);
                self.verified_new_renewal_roots.write(batch_id, new_renewal_root);
            }
        }

        fn record_liquidity_position_roots_with_proof_facts(
            ref self: ContractState,
            batch_id: felt252,
            transcript_commitment: felt252,
            prior_liquidity_position_root: felt252,
            liquidity_position_transition_root: felt252,
            new_liquidity_position_root: felt252,
        ) {
            assert_authorized_settlement_account(@self);
            assert_not_paused(@self);
            assert(batch_id != 0, 'BAD_BATCH');
            assert(self.settled_batches.read(batch_id) == false, 'BATCH_SETTLED');
            assert(transcript_commitment != 0, 'BAD_TRANSCRIPT');
            assert(
                self.verified_auction_transcripts.read(batch_id) == transcript_commitment,
                'AUCTION_RESULT_REQUIRED',
            );
            assert_liquidity_position_root_transition(
                prior_liquidity_position_root,
                liquidity_position_transition_root,
                new_liquidity_position_root,
            );
            if self.verified_liquidity_position_roots_active.read(batch_id) {
                assert(
                    self
                        .verified_liquidity_position_transcripts
                        .read(batch_id) == transcript_commitment,
                    'LP_EXISTS',
                );
                assert(
                    self
                        .verified_prior_liquidity_position_roots
                        .read(batch_id) == prior_liquidity_position_root,
                    'LP_EXISTS',
                );
                assert(
                    self
                        .verified_liquidity_position_transition_roots
                        .read(batch_id) == liquidity_position_transition_root,
                    'LP_EXISTS',
                );
                assert(
                    self
                        .verified_new_liquidity_position_roots
                        .read(batch_id) == new_liquidity_position_root,
                    'LP_EXISTS',
                );
            } else {
                claim_root_transition(ref self, batch_id);
                assert(
                    prior_liquidity_position_root == self.current_liquidity_position_root.read(),
                    'LP_ROOT_STALE',
                );
                let expected_statement_message = native_liquidity_position_message_hash(
                    get_contract_address(),
                    transcript_commitment,
                    prior_liquidity_position_root,
                    liquidity_position_transition_root,
                    new_liquidity_position_root,
                );
                let expected_messages = array![
                    liquidity_position_proof_message_hash_from_statement(
                        self.proof_program.read(), expected_statement_message,
                    ),
                ];
                assert_valid_proof_facts_messages(
                    @self, expected_messages.span(), STATEMENT_LIQUIDITY_POSITION,
                );
                self.verified_liquidity_position_roots_active.write(batch_id, true);
                self.verified_liquidity_position_transcripts.write(batch_id, transcript_commitment);
                self
                    .verified_prior_liquidity_position_roots
                    .write(batch_id, prior_liquidity_position_root);
                self
                    .verified_liquidity_position_transition_roots
                    .write(batch_id, liquidity_position_transition_root);
                self
                    .verified_new_liquidity_position_roots
                    .write(batch_id, new_liquidity_position_root);
            }
        }

        fn record_settlement_order_with_proof_facts(
            ref self: ContractState, batch_id: felt252, transcript_commitment: felt252,
        ) {
            assert_authorized_settlement_account(@self);
            assert_not_paused(@self);
            assert(batch_id != 0, 'BAD_BATCH');
            assert(self.settled_batches.read(batch_id) == false, 'BATCH_SETTLED');
            assert(transcript_commitment != 0, 'BAD_TRANSCRIPT');
            assert(
                self.verified_auction_transcripts.read(batch_id) == transcript_commitment,
                'AUCTION_RESULT_REQUIRED',
            );
            if self.verified_settlement_order_active.read(batch_id) {
                assert(
                    self
                        .verified_settlement_order_transcripts
                        .read(batch_id) == transcript_commitment,
                    'ORDER_EXISTS',
                );
            } else {
                let expected_statement_message = native_settlement_order_message_hash(
                    get_contract_address(), transcript_commitment,
                );
                let expected_messages = array![
                    settlement_order_proof_message_hash_from_statement(
                        self.proof_program.read(), expected_statement_message,
                    ),
                ];
                assert_valid_proof_facts_messages(
                    @self, expected_messages.span(), STATEMENT_SETTLEMENT_ORDER,
                );
                self.verified_settlement_order_active.write(batch_id, true);
                self.verified_settlement_order_transcripts.write(batch_id, transcript_commitment);
            }
        }

        fn record_settlement_input_membership_with_proof_facts(
            ref self: ContractState, batch_id: felt252, transcript_commitment: felt252,
        ) {
            assert_authorized_settlement_account(@self);
            assert_not_paused(@self);
            assert(batch_id != 0, 'BAD_BATCH');
            assert(self.settled_batches.read(batch_id) == false, 'BATCH_SETTLED');
            assert(transcript_commitment != 0, 'BAD_TRANSCRIPT');
            assert(
                self.verified_auction_transcripts.read(batch_id) == transcript_commitment,
                'AUCTION_RESULT_REQUIRED',
            );
            if self.verified_settlement_input_membership_active.read(batch_id) {
                assert(
                    self
                        .verified_settlement_input_membership_transcripts
                        .read(batch_id) == transcript_commitment,
                    'MEMBERSHIP_EXISTS',
                );
            } else {
                let expected_statement_message = native_settlement_input_membership_message_hash(
                    get_contract_address(), transcript_commitment,
                );
                let expected_messages = array![
                    settlement_input_membership_proof_message_hash_from_statement(
                        self.proof_program.read(), expected_statement_message,
                    ),
                ];
                assert_valid_proof_facts_messages(
                    @self, expected_messages.span(), STATEMENT_SETTLEMENT_INPUT_MEMBERSHIP,
                );
                self.verified_settlement_input_membership_active.write(batch_id, true);
                self
                    .verified_settlement_input_membership_transcripts
                    .write(batch_id, transcript_commitment);
            }
        }

        fn record_settlement_output_recovery_with_proof_facts(
            ref self: ContractState, batch_id: felt252, transcript_commitment: felt252,
        ) {
            assert_authorized_settlement_account(@self);
            assert_not_paused(@self);
            assert(batch_id != 0, 'BAD_BATCH');
            assert(self.settled_batches.read(batch_id) == false, 'BATCH_SETTLED');
            assert(transcript_commitment != 0, 'BAD_TRANSCRIPT');
            assert(
                self.verified_auction_transcripts.read(batch_id) == transcript_commitment,
                'AUCTION_RESULT_REQUIRED',
            );
            if self.verified_settlement_output_recovery_active.read(batch_id) {
                assert(
                    self
                        .verified_settlement_output_recovery_transcripts
                        .read(batch_id) == transcript_commitment,
                    'RECOVERY_EXISTS',
                );
            } else {
                let expected_statement_message = native_settlement_output_recovery_message_hash(
                    get_contract_address(), transcript_commitment,
                );
                let expected_messages = array![
                    settlement_output_recovery_proof_message_hash_from_statement(
                        self.proof_program.read(), expected_statement_message,
                    ),
                ];
                assert_valid_proof_facts_messages(
                    @self, expected_messages.span(), STATEMENT_SETTLEMENT_OUTPUT_RECOVERY,
                );
                self.verified_settlement_output_recovery_active.write(batch_id, true);
                self
                    .verified_settlement_output_recovery_transcripts
                    .write(batch_id, transcript_commitment);
            }
        }

        fn clear_unsettled_root_transition(ref self: ContractState, batch_id: felt252) {
            assert_authorized_settlement_account(@self);
            assert_not_paused(@self);
            assert(batch_id != 0, 'BAD_BATCH');
            assert(self.settled_batches.read(batch_id) == false, 'BATCH_SETTLED');
            assert(self.pending_root_transition_batch.read() == batch_id, 'ROOT_TRANSITION_BATCH');
            self.verified_nullifier_roots_active.write(batch_id, false);
            self.verified_renewal_roots_active.write(batch_id, false);
            self.verified_liquidity_position_roots_active.write(batch_id, false);
            self.verified_settlement_order_active.write(batch_id, false);
            self.verified_settlement_input_membership_active.write(batch_id, false);
            self.verified_settlement_output_recovery_active.write(batch_id, false);
            self.verified_multi_pair_solution_active.write(batch_id, false);
            clear_root_transition(ref self, batch_id);
        }

        fn submit_settlement_with_proof_facts(
            ref self: ContractState,
            batch_id: felt252,
            order_commitment_root: felt252,
            encrypted_order_set_commitment: felt252,
            transcript_commitment: felt252,
            proof_artifact_commitment: felt252,
            clearing_price: u128,
            price_base_scale: u128,
            taker_fee_bps: u128,
            relay_fee_bps: u128,
            protocol_fee_recipient: felt252,
            relay_fee_recipient: felt252,
            output_bundle_ref: felt252,
            prior_note_root: felt252,
            prior_nullifier_root: felt252,
            prior_renewal_root: felt252,
            prior_fee_root: felt252,
            prior_liquidity_position_root: felt252,
            consumed_note_root: felt252,
            consumed_nullifier_root: felt252,
            renewal_child_root: felt252,
            liquidity_position_transition_root: felt252,
            output_note_root: felt252,
            fee_root: felt252,
            new_note_root: felt252,
            new_nullifier_root: felt252,
            new_renewal_root: felt252,
            new_fee_root: felt252,
            new_liquidity_position_root: felt252,
        ) {
            assert_authorized_settlement_account(@self);
            assert_not_paused(@self);
            claim_root_transition(ref self, batch_id);
            let expected_statement_message = native_settlement_message_hash(
                get_contract_address(), transcript_commitment,
            );
            assert(proof_artifact_commitment == expected_statement_message, 'PROOF_COMMITMENT');
            assert(self.verified_nullifier_roots_active.read(batch_id), 'NULLIFIER_PROOF_REQUIRED');
            assert(
                self.verified_nullifier_transcripts.read(batch_id) == transcript_commitment,
                'NULLIFIER_TRANSCRIPT',
            );
            assert(
                self.verified_prior_nullifier_roots.read(batch_id) == prior_nullifier_root,
                'PRIOR_NULLIFIER_ROOT',
            );
            assert(
                self.verified_consumed_nullifier_roots.read(batch_id) == consumed_nullifier_root,
                'CONSUMED_NULLIFIER_ROOT',
            );
            assert(
                self.verified_new_nullifier_roots.read(batch_id) == new_nullifier_root,
                'NEW_NULLIFIER_ROOT',
            );
            assert(self.verified_renewal_roots_active.read(batch_id), 'RENEWAL_PROOF_REQUIRED');
            assert(
                self.verified_renewal_transcripts.read(batch_id) == transcript_commitment,
                'RENEWAL_TRANSCRIPT',
            );
            assert(
                self.verified_prior_renewal_roots.read(batch_id) == prior_renewal_root,
                'PRIOR_RENEWAL_ROOT',
            );
            assert(
                self.verified_renewal_child_roots.read(batch_id) == renewal_child_root,
                'RENEWAL_CHILD_ROOT',
            );
            assert(
                self.verified_new_renewal_roots.read(batch_id) == new_renewal_root,
                'NEW_RENEWAL_ROOT',
            );
            assert(
                self.verified_liquidity_position_roots_active.read(batch_id), 'LP_PROOF_REQUIRED',
            );
            assert(
                self
                    .verified_liquidity_position_transcripts
                    .read(batch_id) == transcript_commitment,
                'LP_TRANSCRIPT',
            );
            assert(
                self
                    .verified_prior_liquidity_position_roots
                    .read(batch_id) == prior_liquidity_position_root,
                'LP_PRIOR_ROOT',
            );
            assert(
                self
                    .verified_liquidity_position_transition_roots
                    .read(batch_id) == liquidity_position_transition_root,
                'LP_TRANSITION_ROOT',
            );
            assert(
                self
                    .verified_new_liquidity_position_roots
                    .read(batch_id) == new_liquidity_position_root,
                'LP_NEW_ROOT',
            );
            assert(self.verified_settlement_order_active.read(batch_id), 'ORDER_PROOF_REQUIRED');
            assert(
                self.verified_settlement_order_transcripts.read(batch_id) == transcript_commitment,
                'ORDER_TRANSCRIPT',
            );
            assert(
                self.verified_settlement_input_membership_active.read(batch_id),
                'MEMBER_PROOF_REQUIRED',
            );
            assert(
                self
                    .verified_settlement_input_membership_transcripts
                    .read(batch_id) == transcript_commitment,
                'MEMBER_TRANSCRIPT',
            );
            assert(
                self.verified_settlement_output_recovery_active.read(batch_id),
                'RECOVERY_PROOF_REQUIRED',
            );
            assert(
                self
                    .verified_settlement_output_recovery_transcripts
                    .read(batch_id) == transcript_commitment,
                'RECOVERY_TRANSCRIPT',
            );
            let expected_messages = array![
                settlement_proof_message_hash_from_statement(
                    self.proof_program.read(), expected_statement_message,
                ),
            ];
            assert_valid_proof_facts_messages(
                @self, expected_messages.span(), STATEMENT_SETTLEMENT,
            );

            settle_verified_batch(
                ref self,
                batch_id,
                order_commitment_root,
                encrypted_order_set_commitment,
                transcript_commitment,
                clearing_price,
                price_base_scale,
                taker_fee_bps,
                relay_fee_bps,
                protocol_fee_recipient,
                relay_fee_recipient,
                output_bundle_ref,
                prior_note_root,
                prior_nullifier_root,
                prior_renewal_root,
                prior_fee_root,
                prior_liquidity_position_root,
                consumed_note_root,
                consumed_nullifier_root,
                renewal_child_root,
                liquidity_position_transition_root,
                output_note_root,
                fee_root,
                new_note_root,
                new_nullifier_root,
                new_renewal_root,
                new_fee_root,
                new_liquidity_position_root,
            );
            clear_root_transition(ref self, batch_id);
        }

        fn submit_note_consolidation_with_proof_facts(
            ref self: ContractState,
            consolidation_id: felt252,
            proof_artifact_commitment: felt252,
            output_bundle_ref: felt252,
            prior_note_root: felt252,
            prior_nullifier_root: felt252,
            consumed_note_root: felt252,
            consumed_nullifier_root: felt252,
            output_note_root: felt252,
            new_note_root: felt252,
            new_nullifier_root: felt252,
        ) {
            assert_not_paused(@self);
            assert_no_pending_root_transition(@self);
            assert(consolidation_id != 0, 'BAD_CONSOLIDATION');
            assert(output_bundle_ref != 0, 'BAD_OUTPUT_BUNDLE');
            assert(consumed_note_root != 0, 'BAD_CONSUMED_NOTES');
            assert(consumed_nullifier_root != 0, 'BAD_CONSUMED_NULLS');
            assert(output_note_root != 0, 'BAD_OUTPUT_ROOT');
            assert(prior_note_root == self.current_note_root.read(), 'NOTE_ROOT_STALE');
            assert(
                prior_nullifier_root == self.current_nullifier_root.read(), 'NULLIFIER_ROOT_STALE',
            );
            assert(
                new_note_root == state_transition_root(prior_note_root, output_note_root),
                'NEW_NOTE_ROOT',
            );
            assert(new_nullifier_root != 0, 'NEW_NULLIFIER_ROOT');
            let already_consolidated = self.settled_consolidations.read(consolidation_id);
            assert(already_consolidated == false, 'CONSOLIDATION_SETTLED');
            assert(self.settled_batches.read(consolidation_id) == false, 'CONSOLIDATION_ID_USED');
            assert(self.output_note_roots.read(consolidation_id) == 0, 'OUTPUT_ROOT_ID_USED');
            let batch_registry = IBatchRegistryDispatcher {
                contract_address: self.batch_registry.read(),
            };
            assert(
                batch_registry.batch_exists(consolidation_id) == false, 'CONSOLIDATION_ID_BATCH',
            );

            let consolidation_commitment = public_note_consolidation_commitment(
                consolidation_id,
                output_bundle_ref,
                prior_note_root,
                prior_nullifier_root,
                consumed_note_root,
                consumed_nullifier_root,
                output_note_root,
                new_note_root,
                new_nullifier_root,
            );
            let expected_statement_message = native_note_consolidation_message_hash(
                get_contract_address(), consolidation_commitment,
            );
            assert(proof_artifact_commitment == expected_statement_message, 'PROOF_COMMITMENT');
            let expected_messages = array![
                note_consolidation_proof_message_hash_from_statement(
                    self.proof_program.read(), expected_statement_message,
                ),
            ];
            assert_valid_proof_facts_messages(
                @self, expected_messages.span(), STATEMENT_NOTE_CONSOLIDATION,
            );

            self.settled_consolidations.write(consolidation_id, true);
            self.settled_at_unix_seconds.write(consolidation_id, current_block_timestamp());
            self.output_note_roots.write(consolidation_id, output_note_root);
            self.current_note_root.write(new_note_root);
            self.current_nullifier_root.write(new_nullifier_root);
            record_note_root_transition(
                ref self,
                NOTE_ROOT_TRANSITION_CONSOLIDATION,
                consolidation_id,
                output_note_root,
                new_note_root,
            );
        }

        fn submit_aggregate_settlements_with_proof_facts(
            ref self: ContractState, settlement_inputs: Span<felt252>,
        ) {
            assert_authorized_settlement_account(@self);
            assert_not_paused(@self);
            assert_no_pending_root_transition(@self);
            let settlement_count = aggregate_settlement_count(settlement_inputs);
            assert(settlement_count != 0, 'EMPTY_AGGREGATE');
            assert(settlement_count <= MAX_AGGREGATE_SETTLEMENTS, 'TOO_MANY_AGG');
            let expected_messages = aggregate_expected_messages(
                @self, settlement_inputs, settlement_count,
            );
            assert_valid_proof_facts_messages(
                @self, expected_messages.span(), STATEMENT_AGGREGATE_SETTLEMENT,
            );
            settle_aggregate_verified_batches(ref self, settlement_inputs, settlement_count);
        }

        fn withdraw_settlement_output_to_strk20_with_proof_facts(
            ref self: ContractState,
            batch_id: felt252,
            proof_artifact_commitment: felt252,
            prior_nullifier_root: felt252,
            consumed_nullifier_root: felt252,
            new_nullifier_root: felt252,
            note_commitment: felt252,
            asset_id: felt252,
            amount: u128,
            withdraw_authority: felt252,
            merkle_path: Span<felt252>,
            merkle_directions: Span<felt252>,
            withdraw_authorization_r: felt252,
            withdraw_authorization_s: felt252,
            exit_commitment: felt252,
        ) -> (felt252, u128, felt252) {
            assert_not_paused(@self);
            assert_no_pending_root_transition(@self);
            assert(batch_id != 0, 'BAD_BATCH');
            assert(proof_artifact_commitment != 0, 'BAD_PROOF');
            assert(consumed_nullifier_root != 0, 'BAD_CONSUMED_NULLS');
            assert(new_nullifier_root != 0, 'NEW_NULLIFIER_ROOT');
            assert(note_commitment != 0, 'BAD_COMMITMENT');
            assert(asset_id != 0, 'BAD_ASSET');
            assert(amount > 0, 'BAD_AMOUNT');
            assert(withdraw_authority != 0, 'BAD_AUTHORITY');
            assert(withdraw_authorization_r != 0, 'BAD_WITHDRAW_SIG');
            assert(withdraw_authorization_s != 0, 'BAD_WITHDRAW_SIG');
            assert(exit_commitment != 0, 'BAD_EXIT');
            assert(
                prior_nullifier_root == self.current_nullifier_root.read(), 'NULLIFIER_ROOT_STALE',
            );
            let settled = self.settled_batches.read(batch_id);
            let consolidated = self.settled_consolidations.read(batch_id);
            assert(settled == true || consolidated == true, 'UNKNOWN_SETTLEMENT');
            assert_output_claim_window_open(@self, batch_id);
            let already_withdrawn = self.withdrawn_output_notes.read(note_commitment);
            assert(already_withdrawn == false, 'OUTPUT_WITHDRAWN');
            let output_note_root = self.output_note_roots.read(batch_id);
            let recomputed_root = verify_output_note_path(
                note_commitment,
                asset_id,
                amount,
                withdraw_authority,
                merkle_path,
                merkle_directions,
            );
            assert(recomputed_root == output_note_root, 'OUTPUT_NOTE_PROOF');

            let withdrawal_commitment = public_note_withdrawal_commitment(
                batch_id,
                note_commitment,
                asset_id,
                amount,
                withdraw_authority,
                prior_nullifier_root,
                consumed_nullifier_root,
                new_nullifier_root,
            );
            let expected_statement_message = native_withdrawal_message_hash(
                get_contract_address(), withdrawal_commitment,
            );
            assert(proof_artifact_commitment == expected_statement_message, 'PROOF_COMMITMENT');
            let expected_messages = array![
                withdrawal_proof_message_hash_from_statement(
                    self.proof_program.read(), expected_statement_message,
                ),
            ];
            assert_valid_proof_facts_messages(
                @self, expected_messages.span(), STATEMENT_WITHDRAWAL,
            );

            let adapter_address = self.shielded_asset_adapter.read();
            assert(!adapter_address.is_zero(), 'BAD_ADAPTER');
            assert(
                check_ecdsa_signature(
                    output_strk20_exit_message_hash(
                        adapter_address,
                        batch_id,
                        note_commitment,
                        asset_id,
                        amount,
                        exit_commitment,
                    ),
                    withdraw_authority,
                    withdraw_authorization_r,
                    withdraw_authorization_s,
                ),
                'BAD_WITHDRAW_SIG',
            );

            self.current_nullifier_root.write(new_nullifier_root);
            self.withdrawn_output_notes.write(note_commitment, true);
            let adapter = IShieldedAssetAdapterDispatcher { contract_address: adapter_address };
            adapter
                .stage_verified_note_strk20_exit(
                    asset_id, amount, note_commitment, withdraw_authority, exit_commitment,
                );
            (asset_id, amount, exit_commitment)
        }

        fn is_batch_settled(self: @ContractState, batch_id: felt252) -> bool {
            self.settled_batches.read(batch_id)
        }

        fn is_consolidation_settled(self: @ContractState, consolidation_id: felt252) -> bool {
            self.settled_consolidations.read(consolidation_id)
        }

        fn verified_admission_root(self: @ContractState, batch_id: felt252) -> felt252 {
            self.verified_admission_roots.read(batch_id)
        }

        fn verified_auction_transcript(self: @ContractState, batch_id: felt252) -> felt252 {
            self.verified_auction_transcripts.read(batch_id)
        }

        fn output_note_root(self: @ContractState, batch_id: felt252) -> felt252 {
            self.output_note_roots.read(batch_id)
        }

        fn current_settlement_roots(self: @ContractState) -> (felt252, felt252, felt252, felt252) {
            (
                self.current_note_root.read(),
                self.current_nullifier_root.read(),
                self.current_renewal_root.read(),
                self.current_fee_root.read(),
            )
        }

        fn current_liquidity_position_root(self: @ContractState) -> felt252 {
            self.current_liquidity_position_root.read()
        }

        fn verified_multi_pair_solution(
            self: @ContractState, batch_id: felt252,
        ) -> (felt252, bool) {
            (
                self.verified_multi_pair_solution_commitments.read(batch_id),
                self.verified_multi_pair_solution_active.read(batch_id),
            )
        }

        fn renewal_cancel_marker_recorded(self: @ContractState, cancel_marker: felt252) -> bool {
            self.renewal_cancel_markers.read(cancel_marker)
        }

        fn pair_fee_config(self: @ContractState, pair_id: felt252) -> (u128, u128, bool) {
            (
                self.pair_taker_fee_bps.read(pair_id),
                self.pair_relay_fee_bps.read(pair_id),
                self.pair_fee_configured.read(pair_id),
            )
        }

        fn pending_pair_fee_config(
            self: @ContractState, pair_id: felt252,
        ) -> (u128, u128, u64, bool) {
            (
                self.pending_pair_taker_fee_bps.read(pair_id),
                self.pending_pair_relay_fee_bps.read(pair_id),
                self.pending_pair_fee_config_eta.read(pair_id),
                self.pending_pair_fee_config_active.read(pair_id),
            )
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

        fn pause_guardian_address(self: @ContractState) -> ContractAddress {
            self.pause_guardian.read()
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }

        fn proof_program_is_locked(self: @ContractState) -> bool {
            self.proof_program_locked.read()
        }

        fn protocol_fee_recipient(self: @ContractState) -> felt252 {
            self.protocol_fee_recipient.read()
        }

        fn pending_protocol_fee_recipient(self: @ContractState) -> (felt252, u64, bool) {
            (
                self.pending_protocol_fee_recipient.read(),
                self.pending_protocol_fee_recipient_eta.read(),
                self.pending_protocol_fee_recipient_active.read(),
            )
        }

        fn relay_fee_recipient(self: @ContractState) -> felt252 {
            self.relay_fee_recipient.read()
        }

        fn pending_relay_fee_recipient(self: @ContractState) -> (felt252, u64, bool) {
            (
                self.pending_relay_fee_recipient.read(),
                self.pending_relay_fee_recipient_eta.read(),
                self.pending_relay_fee_recipient_active.read(),
            )
        }

        fn note_root_transition_count(self: @ContractState) -> u64 {
            self.note_root_transition_count.read()
        }

        fn note_root_transition(
            self: @ContractState, transition_id: u64,
        ) -> (felt252, felt252, felt252, felt252) {
            assert(
                transition_id < self.note_root_transition_count.read(), 'UNKNOWN_ROOT_TRANSITION',
            );
            (
                self.note_root_transition_kinds.read(transition_id),
                self.note_root_transition_keys.read(transition_id),
                self.note_root_transition_batch_roots.read(transition_id),
                self.note_root_transition_new_roots.read(transition_id),
            )
        }

        fn settlement_proof_message_hash(
            self: @ContractState, transcript_commitment: felt252,
        ) -> felt252 {
            let proof_program = self.proof_program.read();
            assert(!proof_program.is_zero(), 'PROOF_PROGRAM_UNSET');
            let statement_message_hash = native_settlement_message_hash(
                get_contract_address(), transcript_commitment,
            );
            settlement_proof_message_hash_from_statement(proof_program, statement_message_hash)
        }

        fn note_consolidation_proof_message_hash(
            self: @ContractState, consolidation_commitment: felt252,
        ) -> felt252 {
            let proof_program = self.proof_program.read();
            assert(!proof_program.is_zero(), 'PROOF_PROGRAM_UNSET');
            let statement_message_hash = native_note_consolidation_message_hash(
                get_contract_address(), consolidation_commitment,
            );
            note_consolidation_proof_message_hash_from_statement(
                proof_program, statement_message_hash,
            )
        }

        fn withdrawal_proof_message_hash(
            self: @ContractState, withdrawal_commitment: felt252,
        ) -> felt252 {
            let proof_program = self.proof_program.read();
            assert(!proof_program.is_zero(), 'PROOF_PROGRAM_UNSET');
            let statement_message_hash = native_withdrawal_message_hash(
                get_contract_address(), withdrawal_commitment,
            );
            withdrawal_proof_message_hash_from_statement(proof_program, statement_message_hash)
        }

        fn multi_pair_proof_message_hash(
            self: @ContractState, multi_pair_commitment: felt252,
        ) -> felt252 {
            let proof_program = self.proof_program.read();
            assert(!proof_program.is_zero(), 'PROOF_PROGRAM_UNSET');
            let statement_message_hash = native_multi_pair_message_hash(
                get_contract_address(), multi_pair_commitment,
            );
            multi_pair_proof_message_hash_from_statement(proof_program, statement_message_hash)
        }
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'UNAUTHORIZED');
    }

    fn assert_pause_authority(self: @ContractState) {
        let caller = get_caller_address();
        let guardian = self.pause_guardian.read();
        assert(
            caller == self.admin.read() || (!guardian.is_zero() && caller == guardian),
            'UNAUTHORIZED',
        );
    }

    fn assert_not_paused(self: @ContractState) {
        assert(!self.paused.read(), 'PAUSED');
    }

    fn assert_authorized_settlement_account(self: @ContractState) {
        assert(get_caller_address() == self.authorized_settlement_account.read(), 'UNAUTHORIZED');
    }

    fn assert_no_pending_root_transition(self: @ContractState) {
        assert(self.pending_root_transition_batch.read() == 0, 'ROOT_TRANSITION_PENDING');
    }

    fn claim_root_transition(ref self: ContractState, batch_id: felt252) {
        assert(batch_id != 0, 'BAD_BATCH');
        let pending_batch = self.pending_root_transition_batch.read();
        if pending_batch == 0 {
            self.pending_root_transition_batch.write(batch_id);
        } else {
            assert(pending_batch == batch_id, 'ROOT_TRANSITION_PENDING');
        }
    }

    fn clear_root_transition(ref self: ContractState, batch_id: felt252) {
        if self.pending_root_transition_batch.read() == batch_id {
            self.pending_root_transition_batch.write(0);
        }
    }

    fn assert_deposit_root_registrar(self: @ContractState) {
        assert(get_caller_address() == self.deposit_root_registrar.read(), 'UNAUTHORIZED');
    }

    fn statement_proof_hash_or_default(self: @ContractState, statement_kind: felt252) -> felt252 {
        let statement_hash = self.statement_proof_program_hashes.read(statement_kind);
        if statement_hash == 0 {
            self.proof_program_hash.read()
        } else {
            statement_hash
        }
    }

    fn assert_statement_proof_hash_configured(self: @ContractState, statement_kind: felt252) {
        assert(self.statement_proof_program_hashes.read(statement_kind) != 0, 'PROOF_HASH_UNSET');
    }

    fn assert_required_statement_proof_hashes(self: @ContractState) {
        assert_statement_proof_hash_configured(self, STATEMENT_ADMISSION);
        assert_statement_proof_hash_configured(self, STATEMENT_AUCTION_RESULT);
        assert_statement_proof_hash_configured(self, STATEMENT_NULLIFIER);
        assert_statement_proof_hash_configured(self, STATEMENT_RENEWAL);
        assert_statement_proof_hash_configured(self, STATEMENT_LIQUIDITY_POSITION);
        assert_statement_proof_hash_configured(self, STATEMENT_SETTLEMENT);
        assert_statement_proof_hash_configured(self, STATEMENT_SETTLEMENT_ORDER);
        assert_statement_proof_hash_configured(self, STATEMENT_SETTLEMENT_INPUT_MEMBERSHIP);
        assert_statement_proof_hash_configured(self, STATEMENT_SETTLEMENT_OUTPUT_RECOVERY);
        assert_statement_proof_hash_configured(self, STATEMENT_NOTE_CONSOLIDATION);
        assert_statement_proof_hash_configured(self, STATEMENT_AGGREGATE_SETTLEMENT);
        assert_statement_proof_hash_configured(self, STATEMENT_WITHDRAWAL);
        assert_statement_proof_hash_configured(self, STATEMENT_MULTI_PAIR);
    }

    fn assert_valid_proof_facts_messages(
        self: @ContractState, expected_messages: Span<felt252>, statement_kind: felt252,
    ) {
        let execution_info = get_execution_info_v3_syscall().unwrap_syscall();
        let current_block_number = execution_info.block_info.block_number;
        let mut proof_facts_serialized = execution_info.tx_info.proof_facts;
        assert(!proof_facts_serialized.is_empty(), 'EMPTY_PROOF_FACTS');
        let proof_facts: super::ProofFacts = Serde::deserialize(ref proof_facts_serialized)
            .expect('BAD_PROOF_FACTS');
        assert(proof_facts_serialized.is_empty(), 'BAD_PROOF_FACTS_LEN');
        assert(proof_facts.proof_version == EXPECTED_PROOF_VERSION, 'BAD_PROOF_VERSION');
        assert(proof_facts.program_variant == VIRTUAL_SNOS, 'BAD_PROOF_PROGRAM');
        assert(proof_facts.starknet_os_output_version == VIRTUAL_SNOS0, 'BAD_PROOF_OUTPUT');
        assert(proof_facts.base_block_hash != 0, 'BAD_BASE_BLOCK_HASH');
        let expected_os_config_hash = self.expected_starknet_os_config_hash.read();
        assert(expected_os_config_hash != 0, 'OS_CONFIG_UNSET');
        assert(proof_facts.starknet_os_config_hash == expected_os_config_hash, 'BAD_OS_CONFIG');
        let proof_program = self.proof_program.read();
        let proof_program_hash = statement_proof_hash_or_default(self, statement_kind);
        assert(!proof_program.is_zero(), 'PROOF_PROGRAM_UNSET');
        assert(proof_program_hash != 0, 'PROOF_HASH_UNSET');
        assert(proof_facts.virtual_program_hash == proof_program_hash, 'BAD_PROOF_HASH');
        assert(proof_facts.base_block_number < current_block_number, 'STALE_PROOF_BASE');
        assert(
            current_block_number <= proof_facts.base_block_number
                + self.proof_validity_blocks.read(),
            'EXPIRED_PROOF',
        );

        assert(proof_facts.message_to_l1_hashes == expected_messages, 'BAD_PROOF_MSG');
    }

    fn assert_output_claim_window_open(self: @ContractState, batch_id: felt252) {
        let delay_seconds = self.output_claim_delay_seconds.read();
        if delay_seconds == 0 {
            return;
        }
        let settled_at = self.settled_at_unix_seconds.read(batch_id);
        assert(settled_at != 0, 'UNKNOWN_SETTLE_TIME');
        let now = current_block_timestamp();
        assert(now >= settled_at + delay_seconds, 'CLAIM_WINDOW_CLOSED');
    }

    fn current_block_timestamp() -> u64 {
        starknet::get_block_timestamp()
    }

    fn read_next(data: Span<felt252>, ref index: usize) -> felt252 {
        assert(index < data.len(), 'INPUT_TOO_SHORT');
        let value = *data.at(index);
        index += 1;
        value
    }

    fn read_next_u128(data: Span<felt252>, ref index: usize) -> u128 {
        read_next(data, ref index).try_into().expect('BAD_U128')
    }

    fn aggregate_settlement_count(data: Span<felt252>) -> usize {
        let mut index: usize = 0;
        let count_felt = read_next(data, ref index);
        count_felt.try_into().expect('BAD_AGG_COUNT')
    }

    fn aggregate_expected_messages(
        self: @ContractState, data: Span<felt252>, settlement_count: usize,
    ) -> Array<felt252> {
        let mut index: usize = 0;
        let parsed_count: usize = read_next(data, ref index).try_into().expect('BAD_AGG_COUNT');
        assert(parsed_count == settlement_count, 'BAD_AGG_COUNT');
        let mut expected_messages = array![];
        let mut cursor: usize = 0;
        loop {
            if cursor == settlement_count {
                break;
            }
            read_next(data, ref index);
            read_next(data, ref index);
            read_next(data, ref index);
            let transcript_commitment = read_next(data, ref index);
            let proof_artifact_commitment = read_next(data, ref index);
            read_next_u128(data, ref index);
            read_next_u128(data, ref index);
            read_next_u128(data, ref index);
            read_next_u128(data, ref index);
            read_next(data, ref index);
            read_next(data, ref index);
            read_next(data, ref index);
            read_next(data, ref index);
            let prior_nullifier_root = read_next(data, ref index);
            let prior_renewal_root = read_next(data, ref index);
            read_next(data, ref index);
            let prior_liquidity_position_root = read_next(data, ref index);
            read_next(data, ref index);
            let consumed_nullifier_root = read_next(data, ref index);
            let renewal_child_root = read_next(data, ref index);
            let liquidity_position_transition_root = read_next(data, ref index);
            read_next(data, ref index);
            read_next(data, ref index);
            read_next(data, ref index);
            let new_nullifier_root = read_next(data, ref index);
            let new_renewal_root = read_next(data, ref index);
            read_next(data, ref index);
            let new_liquidity_position_root = read_next(data, ref index);
            let statement_message = native_settlement_message_hash(
                get_contract_address(), transcript_commitment,
            );
            assert(proof_artifact_commitment == statement_message, 'PROOF_COMMITMENT');
            expected_messages
                .append(
                    settlement_proof_message_hash_from_statement(
                        self.proof_program.read(), statement_message,
                    ),
                );
            expected_messages
                .append(
                    nullifier_proof_message_hash_from_statement(
                        self.proof_program.read(),
                        native_nullifier_message_hash(
                            get_contract_address(),
                            transcript_commitment,
                            prior_nullifier_root,
                            consumed_nullifier_root,
                            new_nullifier_root,
                        ),
                    ),
                );
            expected_messages
                .append(
                    renewal_proof_message_hash_from_statement(
                        self.proof_program.read(),
                        native_renewal_message_hash(
                            get_contract_address(),
                            transcript_commitment,
                            prior_renewal_root,
                            renewal_child_root,
                            new_renewal_root,
                        ),
                    ),
                );
            expected_messages
                .append(
                    liquidity_position_proof_message_hash_from_statement(
                        self.proof_program.read(),
                        native_liquidity_position_message_hash(
                            get_contract_address(),
                            transcript_commitment,
                            prior_liquidity_position_root,
                            liquidity_position_transition_root,
                            new_liquidity_position_root,
                        ),
                    ),
                );
            cursor += 1;
        }
        assert(index == data.len(), 'TRAILING_AGG_INPUT');
        expected_messages
    }

    fn settle_aggregate_verified_batches(
        ref self: ContractState, data: Span<felt252>, settlement_count: usize,
    ) {
        let mut index: usize = 0;
        let parsed_count: usize = read_next(data, ref index).try_into().expect('BAD_AGG_COUNT');
        assert(parsed_count == settlement_count, 'BAD_AGG_COUNT');
        let mut cursor: usize = 0;
        loop {
            if cursor == settlement_count {
                break;
            }
            let batch_id = read_next(data, ref index);
            let order_commitment_root = read_next(data, ref index);
            let encrypted_order_set_commitment = read_next(data, ref index);
            let transcript_commitment = read_next(data, ref index);
            let proof_artifact_commitment = read_next(data, ref index);
            let clearing_price = read_next_u128(data, ref index);
            let price_base_scale = read_next_u128(data, ref index);
            let taker_fee_bps = read_next_u128(data, ref index);
            let relay_fee_bps = read_next_u128(data, ref index);
            let protocol_fee_recipient = read_next(data, ref index);
            let relay_fee_recipient = read_next(data, ref index);
            let output_bundle_ref = read_next(data, ref index);
            let prior_note_root = read_next(data, ref index);
            let prior_nullifier_root = read_next(data, ref index);
            let prior_renewal_root = read_next(data, ref index);
            let prior_fee_root = read_next(data, ref index);
            let prior_liquidity_position_root = read_next(data, ref index);
            let consumed_note_root = read_next(data, ref index);
            let consumed_nullifier_root = read_next(data, ref index);
            let renewal_child_root = read_next(data, ref index);
            let liquidity_position_transition_root = read_next(data, ref index);
            let output_note_root = read_next(data, ref index);
            let fee_root = read_next(data, ref index);
            let new_note_root = read_next(data, ref index);
            let new_nullifier_root = read_next(data, ref index);
            let new_renewal_root = read_next(data, ref index);
            let new_fee_root = read_next(data, ref index);
            let new_liquidity_position_root = read_next(data, ref index);

            let statement_message = native_settlement_message_hash(
                get_contract_address(), transcript_commitment,
            );
            assert(proof_artifact_commitment == statement_message, 'PROOF_COMMITMENT');
            settle_verified_batch(
                ref self,
                batch_id,
                order_commitment_root,
                encrypted_order_set_commitment,
                transcript_commitment,
                clearing_price,
                price_base_scale,
                taker_fee_bps,
                relay_fee_bps,
                protocol_fee_recipient,
                relay_fee_recipient,
                output_bundle_ref,
                prior_note_root,
                prior_nullifier_root,
                prior_renewal_root,
                prior_fee_root,
                prior_liquidity_position_root,
                consumed_note_root,
                consumed_nullifier_root,
                renewal_child_root,
                liquidity_position_transition_root,
                output_note_root,
                fee_root,
                new_note_root,
                new_nullifier_root,
                new_renewal_root,
                new_fee_root,
                new_liquidity_position_root,
            );
            cursor += 1;
        }
        assert(index == data.len(), 'TRAILING_AGG_INPUT');
    }

    fn record_note_root_transition(
        ref self: ContractState,
        kind: felt252,
        key: felt252,
        batch_root: felt252,
        new_root: felt252,
    ) {
        let transition_id = self.note_root_transition_count.read();
        self.note_root_transition_kinds.write(transition_id, kind);
        self.note_root_transition_keys.write(transition_id, key);
        self.note_root_transition_batch_roots.write(transition_id, batch_root);
        self.note_root_transition_new_roots.write(transition_id, new_root);
        self.note_root_transition_count.write(transition_id + 1);
    }

    fn settlement_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![SETTLEMENT_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn nullifier_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![NULLIFIER_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn renewal_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![RENEWAL_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn liquidity_position_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![LIQUIDITY_POSITION_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn settlement_order_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![SETTLEMENT_ORDER_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn settlement_input_membership_proof_payload(
        statement_message_hash: felt252,
    ) -> Array<felt252> {
        array![SETTLEMENT_INPUT_MEMBERSHIP_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn settlement_output_recovery_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![SETTLEMENT_OUTPUT_RECOVERY_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn note_consolidation_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![NOTE_CONSOLIDATION_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn withdrawal_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![WITHDRAWAL_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn admission_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![ADMISSION_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn auction_result_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![AUCTION_RESULT_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn multi_pair_proof_payload(statement_message_hash: felt252) -> Array<felt252> {
        array![MULTI_PAIR_MESSAGE_DOMAIN, statement_message_hash]
    }

    fn settlement_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = settlement_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn nullifier_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = nullifier_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn renewal_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = renewal_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn liquidity_position_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = liquidity_position_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn settlement_order_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = settlement_order_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn settlement_input_membership_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = settlement_input_membership_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn settlement_output_recovery_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = settlement_output_recovery_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn note_consolidation_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = note_consolidation_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn withdrawal_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = withdrawal_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn admission_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = admission_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn auction_result_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = auction_result_proof_payload(statement_message_hash);
        payload.serialize(ref l1_message_data);
        poseidon_hash_span(l1_message_data.span())
    }

    fn multi_pair_proof_message_hash_from_statement(
        proof_program_address: ContractAddress, statement_message_hash: felt252,
    ) -> felt252 {
        let mut l1_message_data = array![proof_program_address.into(), SETTLEMENT_PROOF_MESSAGE_TO];
        let payload = multi_pair_proof_payload(statement_message_hash);
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

    fn native_nullifier_message_hash(
        auction_verifier_address: ContractAddress,
        transcript_commitment: felt252,
        prior_nullifier_root: felt252,
        consumed_nullifier_root: felt252,
        new_nullifier_root: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(NULLIFIER_MESSAGE_DOMAIN, auction_verifier_address.into());
        state = poseidon_hash2(state, transcript_commitment);
        state = poseidon_hash2(state, prior_nullifier_root);
        state = poseidon_hash2(state, consumed_nullifier_root);
        state = poseidon_hash2(state, new_nullifier_root);
        state
    }

    fn native_renewal_message_hash(
        auction_verifier_address: ContractAddress,
        transcript_commitment: felt252,
        prior_renewal_root: felt252,
        renewal_child_root: felt252,
        new_renewal_root: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(RENEWAL_MESSAGE_DOMAIN, auction_verifier_address.into());
        state = poseidon_hash2(state, transcript_commitment);
        state = poseidon_hash2(state, prior_renewal_root);
        state = poseidon_hash2(state, renewal_child_root);
        state = poseidon_hash2(state, new_renewal_root);
        state
    }

    fn native_liquidity_position_message_hash(
        auction_verifier_address: ContractAddress,
        transcript_commitment: felt252,
        prior_liquidity_position_root: felt252,
        liquidity_position_transition_root: felt252,
        new_liquidity_position_root: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            LIQUIDITY_POSITION_MESSAGE_DOMAIN, auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, transcript_commitment);
        state = poseidon_hash2(state, prior_liquidity_position_root);
        state = poseidon_hash2(state, liquidity_position_transition_root);
        state = poseidon_hash2(state, new_liquidity_position_root);
        state
    }

    fn native_multi_pair_message_hash(
        auction_verifier_address: ContractAddress, multi_pair_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(MULTI_PAIR_MESSAGE_DOMAIN, auction_verifier_address.into());
        state = poseidon_hash2(state, multi_pair_commitment);
        state
    }

    fn native_settlement_order_message_hash(
        auction_verifier_address: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            SETTLEMENT_ORDER_MESSAGE_DOMAIN, auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, transcript_commitment);
        state
    }

    fn native_settlement_input_membership_message_hash(
        auction_verifier_address: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            SETTLEMENT_INPUT_MEMBERSHIP_MESSAGE_DOMAIN, auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, transcript_commitment);
        state
    }

    fn native_settlement_output_recovery_message_hash(
        auction_verifier_address: ContractAddress, transcript_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            SETTLEMENT_OUTPUT_RECOVERY_MESSAGE_DOMAIN, auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, transcript_commitment);
        state
    }

    fn native_note_consolidation_message_hash(
        auction_verifier_address: ContractAddress, consolidation_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            NOTE_CONSOLIDATION_MESSAGE_DOMAIN, auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, consolidation_commitment);
        state
    }

    fn native_withdrawal_message_hash(
        auction_verifier_address: ContractAddress, withdrawal_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(WITHDRAWAL_MESSAGE_DOMAIN, auction_verifier_address.into());
        state = poseidon_hash2(state, withdrawal_commitment);
        state
    }

    fn native_admission_message_hash(
        auction_verifier_address: ContractAddress,
        batch_id: felt252,
        order_commitment_root: felt252,
        admission_root: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(ADMISSION_MESSAGE_DOMAIN, auction_verifier_address.into());
        state = poseidon_hash2(state, batch_id);
        state = poseidon_hash2(state, order_commitment_root);
        state = poseidon_hash2(state, admission_root);
        state
    }

    fn native_auction_result_message_hash(
        auction_verifier_address: ContractAddress,
        batch_id: felt252,
        order_commitment_root: felt252,
        admission_root: felt252,
        transcript_commitment: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            AUCTION_RESULT_MESSAGE_DOMAIN, auction_verifier_address.into(),
        );
        state = poseidon_hash2(state, batch_id);
        state = poseidon_hash2(state, order_commitment_root);
        state = poseidon_hash2(state, admission_root);
        state = poseidon_hash2(state, transcript_commitment);
        state
    }

    fn settle_verified_batch(
        ref self: ContractState,
        batch_id: felt252,
        order_commitment_root: felt252,
        encrypted_order_set_commitment: felt252,
        transcript_commitment: felt252,
        clearing_price: u128,
        price_base_scale: u128,
        taker_fee_bps: u128,
        relay_fee_bps: u128,
        protocol_fee_recipient: felt252,
        relay_fee_recipient: felt252,
        output_bundle_ref: felt252,
        prior_note_root: felt252,
        prior_nullifier_root: felt252,
        prior_renewal_root: felt252,
        prior_fee_root: felt252,
        prior_liquidity_position_root: felt252,
        consumed_note_root: felt252,
        consumed_nullifier_root: felt252,
        renewal_child_root: felt252,
        liquidity_position_transition_root: felt252,
        output_note_root: felt252,
        fee_root: felt252,
        new_note_root: felt252,
        new_nullifier_root: felt252,
        new_renewal_root: felt252,
        new_fee_root: felt252,
        new_liquidity_position_root: felt252,
    ) {
        let already_settled = self.settled_batches.read(batch_id);
        assert(already_settled == false, 'BATCH_SETTLED');
        assert(prior_note_root == self.current_note_root.read(), 'NOTE_ROOT_STALE');
        assert(prior_nullifier_root == self.current_nullifier_root.read(), 'NULLIFIER_ROOT_STALE');
        assert(prior_renewal_root == self.current_renewal_root.read(), 'RENEWAL_ROOT_STALE');
        assert(prior_fee_root == self.current_fee_root.read(), 'FEE_ROOT_STALE');
        assert(
            prior_liquidity_position_root == self.current_liquidity_position_root.read(),
            'LP_ROOT_STALE',
        );
        assert(price_base_scale != 0, 'BAD_PRICE_SCALE');
        assert(taker_fee_bps <= MAX_PAIR_FEE_BPS, 'BAD_TAKER_FEE');
        assert(relay_fee_bps <= MAX_PAIR_FEE_BPS, 'BAD_RELAY_FEE');
        assert(protocol_fee_recipient != 0, 'BAD_FEE_RECIPIENT');
        assert(relay_fee_recipient != 0, 'BAD_RELAY_RECIPIENT');
        assert(
            new_note_root == state_transition_root(prior_note_root, output_note_root),
            'NEW_NOTE_ROOT',
        );
        assert(new_nullifier_root != 0 || prior_nullifier_root == 0, 'NEW_NULLIFIER_ROOT');
        assert(new_renewal_root != 0 || prior_renewal_root == 0, 'NEW_RENEWAL_ROOT');
        assert(new_fee_root == state_transition_root(prior_fee_root, fee_root), 'NEW_FEE_ROOT');
        assert_liquidity_position_root_transition(
            prior_liquidity_position_root,
            liquidity_position_transition_root,
            new_liquidity_position_root,
        );

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
        assert_pair_fee_config(
            @self,
            batch.pair_id,
            taker_fee_bps,
            relay_fee_bps,
            protocol_fee_recipient,
            relay_fee_recipient,
        );

        let recomputed_commitment = public_settlement_commitment(
            batch_id,
            batch.pair_id,
            batch.epoch_id,
            order_commitment_root,
            encrypted_order_set_commitment,
            clearing_price,
            price_base_scale,
            taker_fee_bps,
            relay_fee_bps,
            protocol_fee_recipient,
            relay_fee_recipient,
            output_bundle_ref,
            prior_note_root,
            prior_nullifier_root,
            prior_renewal_root,
            prior_fee_root,
            prior_liquidity_position_root,
            consumed_note_root,
            consumed_nullifier_root,
            renewal_child_root,
            output_note_root,
            fee_root,
            new_note_root,
            new_nullifier_root,
            new_renewal_root,
            new_fee_root,
            new_liquidity_position_root,
        );
        assert(recomputed_commitment == transcript_commitment, 'SETTLEMENT_BINDING');
        assert(
            self.verified_auction_transcripts.read(batch_id) == transcript_commitment,
            'AUCTION_PROOF_REQUIRED',
        );
        assert(self.settled_consolidations.read(batch_id) == false, 'BATCH_ID_CONSOLIDATION');

        batch_registry
            .record_settlement_metadata(
                batch_id, transcript_commitment, clearing_price, output_bundle_ref,
            );

        self.settled_batches.write(batch_id, true);
        self.settled_at_unix_seconds.write(batch_id, current_block_timestamp());
        self.output_note_roots.write(batch_id, output_note_root);
        self.current_note_root.write(new_note_root);
        self.current_nullifier_root.write(new_nullifier_root);
        self.current_renewal_root.write(new_renewal_root);
        self.current_fee_root.write(new_fee_root);
        self.current_liquidity_position_root.write(new_liquidity_position_root);
        self.verified_multi_pair_solution_active.write(batch_id, false);
        record_note_root_transition(
            ref self, NOTE_ROOT_TRANSITION_SETTLEMENT, batch_id, output_note_root, new_note_root,
        );
    }

    fn public_settlement_commitment(
        batch_id: felt252,
        pair_id: felt252,
        batch_epoch: u64,
        order_commitment_root: felt252,
        encrypted_order_set_commitment: felt252,
        clearing_price: u128,
        price_base_scale: u128,
        taker_fee_bps: u128,
        relay_fee_bps: u128,
        protocol_fee_recipient: felt252,
        relay_fee_recipient: felt252,
        output_bundle_ref: felt252,
        prior_note_root: felt252,
        prior_nullifier_root: felt252,
        prior_renewal_root: felt252,
        prior_fee_root: felt252,
        prior_liquidity_position_root: felt252,
        consumed_note_root: felt252,
        consumed_nullifier_root: felt252,
        renewal_child_root: felt252,
        output_note_root: felt252,
        fee_root: felt252,
        new_note_root: felt252,
        new_nullifier_root: felt252,
        new_renewal_root: felt252,
        new_fee_root: felt252,
        new_liquidity_position_root: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            0x283f626418aa97a073f64500f7e35dd8bf7c01ff8611917c3c38e5be92eb205, batch_id,
        );
        state = poseidon_hash2(state, pair_id);
        state = poseidon_hash2(state, batch_epoch.into());
        state = poseidon_hash2(state, order_commitment_root);
        state = poseidon_hash2(state, encrypted_order_set_commitment);
        state = poseidon_hash2(state, clearing_price.into());
        state = poseidon_hash2(state, price_base_scale.into());
        state = poseidon_hash2(state, taker_fee_bps.into());
        state = poseidon_hash2(state, relay_fee_bps.into());
        state = poseidon_hash2(state, protocol_fee_recipient);
        state = poseidon_hash2(state, relay_fee_recipient);
        state = poseidon_hash2(state, output_bundle_ref);
        state = poseidon_hash2(state, prior_note_root);
        state = poseidon_hash2(state, prior_nullifier_root);
        state = poseidon_hash2(state, prior_renewal_root);
        state = poseidon_hash2(state, prior_fee_root);
        state = poseidon_hash2(state, prior_liquidity_position_root);
        state = poseidon_hash2(state, consumed_note_root);
        state = poseidon_hash2(state, consumed_nullifier_root);
        state = poseidon_hash2(state, renewal_child_root);
        state = poseidon_hash2(state, output_note_root);
        state = poseidon_hash2(state, fee_root);
        state = poseidon_hash2(state, new_note_root);
        state = poseidon_hash2(state, new_nullifier_root);
        state = poseidon_hash2(state, new_renewal_root);
        state = poseidon_hash2(state, new_fee_root);
        state = poseidon_hash2(state, new_liquidity_position_root);

        state
    }

    fn public_note_consolidation_commitment(
        consolidation_id: felt252,
        output_bundle_ref: felt252,
        prior_note_root: felt252,
        prior_nullifier_root: felt252,
        consumed_note_root: felt252,
        consumed_nullifier_root: felt252,
        output_note_root: felt252,
        new_note_root: felt252,
        new_nullifier_root: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(
            0x7a796c6974685f6e6f74655f636f6e736f6c5f7631, consolidation_id,
        );
        state = poseidon_hash2(state, output_bundle_ref);
        state = poseidon_hash2(state, prior_note_root);
        state = poseidon_hash2(state, prior_nullifier_root);
        state = poseidon_hash2(state, consumed_note_root);
        state = poseidon_hash2(state, consumed_nullifier_root);
        state = poseidon_hash2(state, output_note_root);
        state = poseidon_hash2(state, new_note_root);
        state = poseidon_hash2(state, new_nullifier_root);
        state
    }

    fn public_note_withdrawal_commitment(
        batch_id: felt252,
        note_commitment: felt252,
        asset_id: felt252,
        amount: u128,
        withdraw_authority: felt252,
        prior_nullifier_root: felt252,
        consumed_nullifier_root: felt252,
        new_nullifier_root: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(PUBLIC_NOTE_WITHDRAWAL_DOMAIN, batch_id);
        state = poseidon_hash2(state, note_commitment);
        state = poseidon_hash2(state, asset_id);
        state = poseidon_hash2(state, amount.into());
        state = poseidon_hash2(state, withdraw_authority);
        state = poseidon_hash2(state, prior_nullifier_root);
        state = poseidon_hash2(state, consumed_nullifier_root);
        state = poseidon_hash2(state, new_nullifier_root);
        state
    }

    fn state_transition_root(prior_root: felt252, batch_root: felt252) -> felt252 {
        poseidon_hash2(poseidon_hash2(ROOT_ONLY_STATE_TRANSITION_DOMAIN, prior_root), batch_root)
    }

    fn assert_liquidity_position_root_transition(
        prior_root: felt252, transition_root: felt252, new_root: felt252,
    ) {
        assert(transition_root != 0, 'BAD_LP_TRANSITION');
        if transition_root == empty_liquidity_position_transition_root() {
            assert(new_root == prior_root, 'NEW_LP_ROOT');
        } else {
            assert(new_root != 0, 'NEW_LP_ROOT');
        }
    }

    fn empty_liquidity_position_transition_root() -> felt252 {
        poseidon_hash2(LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN, 0)
    }

    fn assert_pair_fee_config(
        self: @ContractState,
        pair_id: felt252,
        taker_fee_bps: u128,
        relay_fee_bps: u128,
        protocol_fee_recipient: felt252,
        relay_fee_recipient: felt252,
    ) {
        assert(self.pair_fee_configured.read(pair_id), 'PAIR_FEE_UNSET');
        assert(self.pair_taker_fee_bps.read(pair_id) == taker_fee_bps, 'TAKER_FEE_BINDING');
        assert(self.pair_relay_fee_bps.read(pair_id) == relay_fee_bps, 'RELAY_FEE_BINDING');
        assert(
            self.protocol_fee_recipient.read() == protocol_fee_recipient, 'FEE_RECIPIENT_BINDING',
        );
        assert(self.relay_fee_recipient.read() == relay_fee_recipient, 'RELAY_RECIP_BINDING');
    }

    fn single_field_root(domain: felt252, values: Span<felt252>) -> felt252 {
        let mut state = domain;
        let mut index = 0;
        loop {
            if index == values.len() {
                break;
            }
            state = poseidon_hash2(state, *values.at(index));
            index += 1;
        }
        poseidon_hash2(state, values.len().into())
    }

    fn renewal_parent_cancel_marker_message_hash(cancel_marker: felt252) -> felt252 {
        let tx_info = get_tx_info().unbox();
        let mut state = poseidon_hash2(RENEWAL_PARENT_CANCEL_DOMAIN, tx_info.chain_id);
        state = poseidon_hash2(state, get_contract_address().into());
        poseidon_hash2(state, cancel_marker)
    }

    fn sparse_insert_renewal_entry(
        prior_root: felt252,
        entry: felt252,
        key_low: u128,
        key_high: u128,
        merkle_path: Span<felt252>,
        merkle_directions: Span<felt252>,
    ) -> felt252 {
        assert(entry != 0, 'BAD_RENEWAL_ENTRY');
        assert(entry == key_low.into() + key_high.into() * TWO_POW_128, 'RENEWAL_KEY_BIND');
        assert_renewal_sparse_key_in_field(key_low, key_high);
        assert(merkle_path.len() == merkle_directions.len(), 'RENEWAL_PATH_LEN');
        if prior_root == 0 {
            assert(merkle_path.len() == 0, 'RENEWAL_EMPTY_PATH');
            return sparse_insert_renewal_entry_from_empty(entry, key_low);
        }
        assert(merkle_path.len() == RENEWAL_SPARSE_TREE_DEPTH, 'RENEWAL_PATH_COUNT');
        let mut reconstructed_low: felt252 = 0;
        let mut bit_weight: felt252 = 1;
        let mut empty_root = 0;
        let mut inserted_root = poseidon_hash2(RENEWAL_SPARSE_LEAF_DOMAIN, entry);
        let mut level = 0;
        loop {
            if level == RENEWAL_SPARSE_TREE_DEPTH {
                break;
            }
            let sibling = *merkle_path.at(level);
            let bit = *merkle_directions.at(level);
            assert(bit == 0 || bit == 1, 'RENEWAL_PATH_BIT');
            reconstructed_low = reconstructed_low + bit * bit_weight;
            bit_weight = bit_weight * 2;
            if bit == 0 {
                empty_root = renewal_sparse_node(empty_root, sibling, level);
                inserted_root = renewal_sparse_node(inserted_root, sibling, level);
            } else {
                empty_root = renewal_sparse_node(sibling, empty_root, level);
                inserted_root = renewal_sparse_node(sibling, inserted_root, level);
            }
            level += 1;
        }
        assert(reconstructed_low == key_low.into(), 'RENEWAL_KEY_LOW_BITS');
        assert(empty_root == prior_root, 'RENEWAL_SPARSE_PRIOR');
        inserted_root
    }

    fn sparse_insert_renewal_entry_from_empty(entry: felt252, key_low: u128) -> felt252 {
        let mut inserted_root = poseidon_hash2(RENEWAL_SPARSE_LEAF_DOMAIN, entry);
        let mut empty_sibling = 0;
        let mut remaining_key = key_low;
        let mut level = 0;
        loop {
            if level == RENEWAL_SPARSE_TREE_DEPTH {
                break;
            }
            let bit = remaining_key % 2;
            remaining_key = remaining_key / 2;
            if bit == 0 {
                inserted_root = renewal_sparse_node(inserted_root, empty_sibling, level);
            } else {
                inserted_root = renewal_sparse_node(empty_sibling, inserted_root, level);
            }
            empty_sibling = renewal_sparse_node(empty_sibling, empty_sibling, level);
            level += 1;
        }
        inserted_root
    }

    fn renewal_sparse_node(left: felt252, right: felt252, level: usize) -> felt252 {
        let state = poseidon_hash2(RENEWAL_SPARSE_NODE_DOMAIN, level.into());
        let state = poseidon_hash2(state, left);
        poseidon_hash2(state, right)
    }

    fn assert_renewal_sparse_key_in_field(key_low: u128, key_high: u128) {
        assert(
            key_high < SPARSE_KEY_HIGH_MAX || (key_high == SPARSE_KEY_HIGH_MAX && key_low == 0),
            'RENEWAL_KEY_FIELD',
        );
    }

    fn output_note_leaf(
        note_commitment: felt252, asset_id: felt252, amount: u128, withdraw_authority: felt252,
    ) -> felt252 {
        let mut state = poseidon_hash2(OUTPUT_NOTE_LEAF_DOMAIN, note_commitment);
        state = poseidon_hash2(state, asset_id);
        state = poseidon_hash2(state, amount.into());
        poseidon_hash2(state, withdraw_authority)
    }

    fn output_note_node(left: felt252, right: felt252) -> felt252 {
        poseidon_hash2(poseidon_hash2(OUTPUT_NOTE_NODE_DOMAIN, left), right)
    }

    fn verify_output_note_path(
        note_commitment: felt252,
        asset_id: felt252,
        amount: u128,
        withdraw_authority: felt252,
        merkle_path: Span<felt252>,
        merkle_directions: Span<felt252>,
    ) -> felt252 {
        assert(merkle_path.len() == merkle_directions.len(), 'BAD_OUTPUT_PATH_LEN');
        let mut root = output_note_leaf(note_commitment, asset_id, amount, withdraw_authority);
        let mut index = 0;
        loop {
            if index == merkle_path.len() {
                break;
            }
            let sibling = *merkle_path.at(index);
            let direction = *merkle_directions.at(index);
            if direction == 0 {
                root = output_note_node(root, sibling);
            } else {
                assert(direction == 1, 'BAD_OUTPUT_PATH_DIR');
                root = output_note_node(sibling, root);
            }
            index += 1;
        }
        root
    }

    fn output_strk20_exit_message_hash(
        adapter_address: ContractAddress,
        batch_id: felt252,
        note_commitment: felt252,
        asset_id: felt252,
        amount: u128,
        exit_commitment: felt252,
    ) -> felt252 {
        let tx_info = starknet::get_tx_info().unbox();
        let mut state = poseidon_hash2(OUTPUT_WITHDRAWAL_STRK20_EXIT_DOMAIN, tx_info.chain_id);
        state = poseidon_hash2(state, get_contract_address().into());
        state = poseidon_hash2(state, adapter_address.into());
        state = poseidon_hash2(state, batch_id);
        state = poseidon_hash2(state, note_commitment);
        state = poseidon_hash2(state, asset_id);
        state = poseidon_hash2(state, amount.into());
        poseidon_hash2(state, exit_commitment)
    }
}
