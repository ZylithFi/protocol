//! the zylith exchange: one proof-bearing transition per active epoch settles the private book,
//! and users withdraw their notes with their own proofs.
//!
//! the transition statement (`stwo_statement/src/exchange/transition.cairo`) proves everything
//! about the private book. this contract checks, once and cheaply, what the statement relies on
//! and cannot see: the chain position (seq, prior book root, close time), the attested midpoints
//! and their freshness, the pair fees, the nullifier set, the earlier external outcomes and the
//! fee recipient. it then commits the new book root, appends the transition's outputs to the note
//! accumulator and opens its external capacities.
//!
//! nullifiers live in a map, not a root, so user withdrawals never race a transition: a
//! withdrawal is requested (the nullifier becomes exit-pending) and finalized after a delay, and
//! a transition that consumes the same note first wins and voids the exit.

use starknet::ContractAddress;

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

/// the transition's public header: the values the statement commits besides the lists.
#[derive(Drop, Serde, Copy)]
pub struct TransitionHeader {
    pub seq: u32,
    pub close_time_ms: u64,
    pub prior_book_root: felt252,
    pub new_book_root: felt252,
    pub note_root: felt252,
    pub output_root: felt252,
}

/// one market's m0: the attested reference price of the pair at the close.
#[derive(Drop, Serde, Copy)]
pub struct MarketAttestation {
    pub pair_id: felt252,
    pub midpoint: u128,
    pub lower_price: u128,
    pub upper_price: u128,
    pub scale: u128,
    pub source_count: u64,
    pub observed_at_ms: u64,
    pub valid_until_ms: u64,
    pub source_set_commitment: felt252,
    pub nonce: u64,
    pub price_batch_commitment: felt252,
    pub signature_r: felt252,
    pub signature_s: felt252,
}

#[derive(Drop, Serde, Copy)]
pub struct OutcomeRecord {
    pub seq: u32,
    pub pair_id: felt252,
    pub sell: bool,
    pub consumed_base: u128,
    pub pool_quote: u128,
    pub m1: u128,
    pub m1_scale: u128,
}

#[derive(Drop, Serde, Copy)]
pub struct CapacityEntry {
    pub pair_id: felt252,
    pub sell: bool,
    pub bound: u128,
    pub total: u128,
}

#[derive(Drop, Serde, Copy)]
pub struct OutputRecord {
    pub leaf: felt252,
    pub enc: felt252,
}

#[derive(Drop, Serde, Copy, PartialEq, Debug)]
pub struct PairConfig {
    pub base_asset_id: felt252,
    pub quote_asset_id: felt252,
    pub fee_bps: u128,
}

#[derive(Drop, Serde, Copy, PartialEq, Debug, starknet::Store)]
pub struct Capacity {
    pub bound: u128,
    pub total: u128,
    pub scale: u128,
    pub opened_at: u64,
    /// the base filled so far, over every fill.
    pub consumed_base: u128,
    /// the quote the pool traded for it so far.
    pub pool_quote: u128,
    /// the latest fill's m1, the bound until the first fill.
    pub m1: u128,
    /// 0 unknown, 1 open, 2 filled (used up), 3 applied, 4 frozen at its cutoff.
    pub status: u8,
    /// cas version: every accepted fill and freeze increments it.
    pub generation: u64,
}

#[derive(Drop, Serde, Copy, PartialEq, Debug, starknet::Store)]
pub struct PendingExit {
    pub asset_id: felt252,
    pub amount: u128,
    pub exit_commitment: felt252,
    pub exit_authority: felt252,
    pub matures_at: u64,
}

#[starknet::interface]
pub trait IExchange<TContractState> {
    fn propose_admin(ref self: TContractState, new_admin: ContractAddress);
    fn accept_admin(ref self: TContractState);
    fn set_pause_guardian(ref self: TContractState, guardian: ContractAddress);
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);
    fn set_settlement_account(ref self: TContractState, account: ContractAddress);
    fn set_proof_program(
        ref self: TContractState, proof_program: ContractAddress, virtual_program_hash: felt252,
    );
    fn set_proof_validation(
        ref self: TContractState,
        proof_version: felt252,
        starknet_os_config_hash: felt252,
        proof_validity_blocks: u64,
    );
    fn set_custody(
        ref self: TContractState,
        bridge: ContractAddress,
        deposit_root_registrar: ContractAddress,
        external_router: ContractAddress,
    );
    fn set_reference_signer(ref self: TContractState, signer: felt252);
    fn propose_reference_signer(ref self: TContractState, signer: felt252);
    fn execute_reference_signer(ref self: TContractState);
    fn set_objective_numeraire(ref self: TContractState, asset_id: felt252);
    fn set_timing(
        ref self: TContractState,
        max_close_delay_ms: u64,
        withdrawal_delay_seconds: u64,
        external_window_seconds: u64,
    );
    fn register_pair(
        ref self: TContractState,
        pair_id: felt252,
        base_asset_id: felt252,
        quote_asset_id: felt252,
        fee_bps: u128,
    );
    fn propose_pair_fee(ref self: TContractState, pair_id: felt252, fee_bps: u128);
    fn execute_pair_fee(ref self: TContractState, pair_id: felt252);
    fn set_protocol_fee_recipient(ref self: TContractState, recipient: felt252);
    fn propose_protocol_fee_recipient(ref self: TContractState, recipient: felt252);
    fn execute_protocol_fee_recipient(ref self: TContractState);
    fn lock_config(ref self: TContractState);
    fn activate_deposit_root(
        ref self: TContractState, funding_commitment: felt252, deposit_root: felt252,
    );
    fn submit_transition(
        ref self: TContractState,
        header: TransitionHeader,
        markets: Span<MarketAttestation>,
        outcomes: Span<OutcomeRecord>,
        capacities: Span<CapacityEntry>,
        nullifiers: Span<felt252>,
        outputs: Span<OutputRecord>,
    );
    fn settle_external_fill(
        ref self: TContractState,
        seq: u32,
        pair_id: felt252,
        sell: bool,
        fill_base: u128,
        m1: MarketAttestation,
    ) -> (felt252, felt252, u128, u128);
    fn freeze_capacity(
        ref self: TContractState, seq: u32, pair_id: felt252, sell: bool, expected_generation: u64,
    );
    fn request_withdrawal(
        ref self: TContractState,
        note_root: felt252,
        nullifier: felt252,
        asset_id: felt252,
        amount: u128,
        exit_commitment: felt252,
        exit_authority: felt252,
    );
    fn finalize_withdrawal(ref self: TContractState, nullifier: felt252);
    fn transition_seq(self: @TContractState) -> u32;
    fn book_root(self: @TContractState) -> felt252;
    fn last_close_time_ms(self: @TContractState) -> u64;
    fn note_root(self: @TContractState) -> felt252;
    fn note_batch_count(self: @TContractState) -> u64;
    fn is_known_note_root(self: @TContractState, root: felt252) -> bool;
    fn nullifier_state(self: @TContractState, nullifier: felt252) -> u8;
    fn pending_exit(self: @TContractState, nullifier: felt252) -> PendingExit;
    fn capacity(self: @TContractState, seq: u32, pair_id: felt252, sell: bool) -> Capacity;
    fn pair_config(self: @TContractState, pair_id: felt252) -> PairConfig;
    fn protocol_fee_recipient(self: @TContractState) -> felt252;
    fn reference_signer(self: @TContractState) -> felt252;
    fn transition_message_hash(self: @TContractState, transition_commitment: felt252) -> felt252;
    fn withdrawal_message_hash(self: @TContractState, withdrawal_commitment: felt252) -> felt252;
    fn admin_address(self: @TContractState) -> ContractAddress;
    fn is_paused(self: @TContractState) -> bool;
    fn config_is_locked(self: @TContractState) -> bool;
}

#[starknet::interface]
pub trait IExitStaging<TContractState> {
    fn stage_verified_note_strk20_exit(
        ref self: TContractState,
        asset_id: felt252,
        amount: u128,
        note_commitment: felt252,
        withdraw_authority: felt252,
        exit_commitment: felt252,
    );
    fn settle_external_match_asset_swap(
        ref self: TContractState,
        matcher: ContractAddress,
        input_asset_id: felt252,
        output_asset_id: felt252,
        input_amount: u128,
        output_amount: u128,
    );
}

#[starknet::contract]
pub mod Exchange {
    use core::ecdsa::check_ecdsa_signature;
    use core::num::traits::Zero;
    use core::poseidon::{hades_permutation, poseidon_hash_span};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::syscalls::get_execution_info_v3_syscall;
    use starknet::{
        ContractAddress, SyscallResultTrait, get_block_timestamp, get_caller_address,
        get_contract_address,
    };
    use super::{
        Capacity, CapacityEntry, IExitStagingDispatcher, IExitStagingDispatcherTrait,
        MarketAttestation, OutcomeRecord, OutputRecord, PairConfig, PendingExit, ProofFacts,
        TransitionHeader,
    };

    const VIRTUAL_SNOS: felt252 = 'VIRTUAL_SNOS';
    const VIRTUAL_SNOS0: felt252 = 'VIRTUAL_SNOS0';
    const PROOF_MESSAGE_TO: felt252 = 0;
    const TRANSITION_MESSAGE_DOMAIN: felt252 = 'zylith_transition_msg_v1';
    const WITHDRAWAL_MESSAGE_DOMAIN: felt252 = 'zylith_withdraw_msg_v1';
    const TRANSITION_DOMAIN: felt252 = 'zylith_transition_v1';
    const WITHDRAWAL_DOMAIN: felt252 = 'zylith_withdrawal_v2';
    const M0_DOMAIN: felt252 = 'zylith_m0_v1';
    const OUTCOMES_DOMAIN: felt252 = 'zylith_outcomes_v1';
    const CAPACITY_DOMAIN: felt252 = 'zylith_capacity_v1';
    const NULLIFIERS_DOMAIN: felt252 = 'zylith_nullifiers_v1';
    const OUTPUTS_DOMAIN: felt252 = 'zylith_outputs_v1';
    const REFERENCE_PRICE_ATTESTATION_DOMAIN: felt252 =
        0x79508ce25b318644e4a7aea66c1edc2342856b522eb62152b5c118fc1ef3e67;
    const REFERENCE_PRICE_BATCH_DOMAIN: felt252 = 'zylith_price_batch_v1';
    const NOTE_ACCUMULATOR_LEAF_DOMAIN: felt252 = 0x7a796c6974685f6e6f74655f6163635f6c6561665f7631;
    const NOTE_ACCUMULATOR_NODE_DOMAIN: felt252 = 0x7a796c6974685f6e6f74655f6163635f6e6f64655f7631;
    const NOTE_ACCUMULATOR_DEPTH: u64 = 32;
    const NOTE_ACCUMULATOR_CAPACITY: u64 = 0x100000000;
    const DEFAULT_PROOF_VALIDITY_BLOCKS: u64 = 450;
    const MAX_FEE_BPS: u128 = 100;
    const FEE_TIMELOCK_SECONDS: u64 = 86400;
    const RECIPIENT_TIMELOCK_SECONDS: u64 = 604800;
    const REFERENCE_SIGNER_TIMELOCK_SECONDS: u64 = 86400;
    const MAX_REFERENCE_WINDOW_MS: u64 = 15000;
    const MAX_REFERENCE_FUTURE_SKEW_MS: u64 = 5000;
    const MIN_REFERENCE_SOURCES: u64 = 3;
    const NULLIFIER_UNUSED: u8 = 0;
    const NULLIFIER_SPENT: u8 = 1;
    const NULLIFIER_EXIT_PENDING: u8 = 2;
    const NULLIFIER_EXITED: u8 = 3;
    const CAPACITY_OPEN: u8 = 1;
    const CAPACITY_FILLED: u8 = 2;
    const CAPACITY_APPLIED: u8 = 3;
    const CAPACITY_FROZEN: u8 = 4;
    /// the statement's bound on an outcome's amounts, which an average price is made of.
    const OUTCOME_AMOUNT_BOUND: u128 = 0x1000000000000000000000000000000;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        pending_admin: ContractAddress,
        pause_guardian: ContractAddress,
        paused: bool,
        config_locked: bool,
        settlement_account: ContractAddress,
        proof_program: ContractAddress,
        virtual_program_hash: felt252,
        expected_proof_version: felt252,
        expected_os_config_hash: felt252,
        proof_validity_blocks: u64,
        bridge: ContractAddress,
        deposit_root_registrar: ContractAddress,
        external_router: ContractAddress,
        reference_signer: felt252,
        pending_reference_signer: felt252,
        pending_reference_signer_eta: u64,
        objective_numeraire: felt252,
        max_close_delay_ms: u64,
        withdrawal_delay_seconds: u64,
        external_window_seconds: u64,
        pair_base: Map<felt252, felt252>,
        pair_quote: Map<felt252, felt252>,
        pair_fee_bps: Map<felt252, u128>,
        pending_pair_fee_bps: Map<felt252, u128>,
        pending_pair_fee_eta: Map<felt252, u64>,
        protocol_fee_recipient: felt252,
        pending_fee_recipient: felt252,
        pending_fee_recipient_eta: u64,
        seq: u32,
        book_root: felt252,
        last_close_time_ms: u64,
        note_batch_count: u64,
        note_frontier: Map<u64, felt252>,
        current_note_root: felt252,
        known_note_roots: Map<felt252, bool>,
        activated_funding: Map<felt252, bool>,
        nullifier_states: Map<felt252, u8>,
        pending_exits: Map<felt252, PendingExit>,
        capacities: Map<(u32, felt252, bool), Capacity>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        DepositActivated: DepositActivated,
        TransitionSettled: TransitionSettled,
        ExternalFilled: ExternalFilled,
        WithdrawalRequested: WithdrawalRequested,
        WithdrawalFinalized: WithdrawalFinalized,
    }

    #[derive(Drop, starknet::Event)]
    pub struct DepositActivated {
        pub funding_commitment: felt252,
        pub deposit_root: felt252,
        pub note_root: felt252,
    }

    /// the output records are the transaction's calldata; recovering a note needs only this
    /// event's seq and that calldata.
    #[derive(Drop, starknet::Event)]
    pub struct TransitionSettled {
        #[key]
        pub seq: u32,
        pub new_book_root: felt252,
        pub output_root: felt252,
        pub note_root: felt252,
        pub output_count: u32,
    }

    #[derive(Drop, starknet::Event)]
    /// one fill of a capacity: its own base, quote and m1, and the capacity's totals after it.
    pub struct ExternalFilled {
        #[key]
        pub seq: u32,
        pub pair_id: felt252,
        pub sell: bool,
        pub fill_base: u128,
        pub fill_quote: u128,
        pub m1: u128,
        pub consumed_base: u128,
        pub pool_quote: u128,
    }

    #[derive(Drop, starknet::Event)]
    pub struct WithdrawalRequested {
        #[key]
        pub nullifier: felt252,
        pub matures_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct WithdrawalFinalized {
        #[key]
        pub nullifier: felt252,
        pub exit_commitment: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        assert(!admin.is_zero(), 'BAD_ADMIN');
        self.admin.write(admin);
        self.proof_validity_blocks.write(DEFAULT_PROOF_VALIDITY_BLOCKS);
        self.max_close_delay_ms.write(60000);
        self.withdrawal_delay_seconds.write(120);
        self.book_root.write(empty_book_root(get_contract_address().into()));
    }

    #[abi(embed_v0)]
    impl ExchangeImpl of super::IExchange<ContractState> {
        fn propose_admin(ref self: ContractState, new_admin: ContractAddress) {
            assert_admin(@self);
            assert(!new_admin.is_zero(), 'BAD_ADMIN');
            self.pending_admin.write(new_admin);
        }

        fn accept_admin(ref self: ContractState) {
            let pending = self.pending_admin.read();
            assert(!pending.is_zero() && get_caller_address() == pending, 'UNAUTHORIZED');
            self.admin.write(pending);
            self.pending_admin.write(Zero::zero());
        }

        fn set_pause_guardian(ref self: ContractState, guardian: ContractAddress) {
            assert_admin(@self);
            self.pause_guardian.write(guardian);
        }

        fn pause(ref self: ContractState) {
            let caller = get_caller_address();
            let guardian = self.pause_guardian.read();
            assert(
                caller == self.admin.read() || (!guardian.is_zero() && caller == guardian),
                'UNAUTHORIZED',
            );
            self.paused.write(true);
        }

        fn unpause(ref self: ContractState) {
            assert_admin(@self);
            self.paused.write(false);
        }

        fn set_settlement_account(ref self: ContractState, account: ContractAddress) {
            assert_admin(@self);
            assert(!account.is_zero(), 'BAD_ACCOUNT');
            self.settlement_account.write(account);
        }

        fn set_proof_program(
            ref self: ContractState, proof_program: ContractAddress, virtual_program_hash: felt252,
        ) {
            assert_unlocked_admin(@self);
            assert(!proof_program.is_zero() && virtual_program_hash != 0, 'BAD_PROOF_PROGRAM');
            self.proof_program.write(proof_program);
            self.virtual_program_hash.write(virtual_program_hash);
        }

        fn set_proof_validation(
            ref self: ContractState,
            proof_version: felt252,
            starknet_os_config_hash: felt252,
            proof_validity_blocks: u64,
        ) {
            assert_unlocked_admin(@self);
            assert(proof_version != 0 && starknet_os_config_hash != 0, 'BAD_PROOF_CONFIG');
            assert(proof_validity_blocks != 0, 'BAD_PROOF_CONFIG');
            self.expected_proof_version.write(proof_version);
            self.expected_os_config_hash.write(starknet_os_config_hash);
            self.proof_validity_blocks.write(proof_validity_blocks);
        }

        fn set_custody(
            ref self: ContractState,
            bridge: ContractAddress,
            deposit_root_registrar: ContractAddress,
            external_router: ContractAddress,
        ) {
            assert_unlocked_admin(@self);
            assert(!bridge.is_zero() && !deposit_root_registrar.is_zero(), 'BAD_CUSTODY');
            self.bridge.write(bridge);
            self.deposit_root_registrar.write(deposit_root_registrar);
            self.external_router.write(external_router);
        }

        fn set_reference_signer(ref self: ContractState, signer: felt252) {
            assert_unlocked_admin(@self);
            assert(signer != 0, 'BAD_SIGNER');
            self.reference_signer.write(signer);
        }

        fn propose_reference_signer(ref self: ContractState, signer: felt252) {
            assert_admin(@self);
            assert(signer != 0 && signer != self.reference_signer.read(), 'BAD_SIGNER');
            self.pending_reference_signer.write(signer);
            self
                .pending_reference_signer_eta
                .write(get_block_timestamp() + REFERENCE_SIGNER_TIMELOCK_SECONDS);
        }

        fn execute_reference_signer(ref self: ContractState) {
            assert_admin(@self);
            assert(self.paused.read(), 'NOT_PAUSED');
            let eta = self.pending_reference_signer_eta.read();
            assert(eta != 0 && get_block_timestamp() >= eta, 'SIGNER_TIMELOCK');
            self.reference_signer.write(self.pending_reference_signer.read());
            self.pending_reference_signer.write(0);
            self.pending_reference_signer_eta.write(0);
        }

        fn set_objective_numeraire(ref self: ContractState, asset_id: felt252) {
            assert_unlocked_admin(@self);
            assert(asset_id != 0, 'BAD_NUMERAIRE');
            self.objective_numeraire.write(asset_id);
        }

        fn set_timing(
            ref self: ContractState,
            max_close_delay_ms: u64,
            withdrawal_delay_seconds: u64,
            external_window_seconds: u64,
        ) {
            assert_unlocked_admin(@self);
            assert(max_close_delay_ms != 0 && withdrawal_delay_seconds != 0, 'BAD_TIMING');
            self.max_close_delay_ms.write(max_close_delay_ms);
            self.withdrawal_delay_seconds.write(withdrawal_delay_seconds);
            self.external_window_seconds.write(external_window_seconds);
        }

        fn register_pair(
            ref self: ContractState,
            pair_id: felt252,
            base_asset_id: felt252,
            quote_asset_id: felt252,
            fee_bps: u128,
        ) {
            assert_unlocked_admin(@self);
            assert(pair_id != 0 && base_asset_id != 0 && quote_asset_id != 0, 'BAD_PAIR');
            assert(base_asset_id != quote_asset_id, 'BAD_PAIR');
            assert(fee_bps <= MAX_FEE_BPS, 'BAD_FEE');
            assert(self.pair_base.read(pair_id) == 0, 'PAIR_EXISTS');
            self.pair_base.write(pair_id, base_asset_id);
            self.pair_quote.write(pair_id, quote_asset_id);
            self.pair_fee_bps.write(pair_id, fee_bps);
        }

        fn propose_pair_fee(ref self: ContractState, pair_id: felt252, fee_bps: u128) {
            assert_admin(@self);
            assert(self.pair_base.read(pair_id) != 0, 'UNKNOWN_PAIR');
            assert(fee_bps <= MAX_FEE_BPS, 'BAD_FEE');
            self.pending_pair_fee_bps.write(pair_id, fee_bps);
            self.pending_pair_fee_eta.write(pair_id, get_block_timestamp() + FEE_TIMELOCK_SECONDS);
        }

        fn execute_pair_fee(ref self: ContractState, pair_id: felt252) {
            assert_admin(@self);
            let eta = self.pending_pair_fee_eta.read(pair_id);
            assert(eta != 0 && get_block_timestamp() >= eta, 'FEE_TIMELOCK');
            self.pair_fee_bps.write(pair_id, self.pending_pair_fee_bps.read(pair_id));
            self.pending_pair_fee_eta.write(pair_id, 0);
        }

        fn set_protocol_fee_recipient(ref self: ContractState, recipient: felt252) {
            assert_unlocked_admin(@self);
            assert(recipient != 0, 'BAD_RECIPIENT');
            self.protocol_fee_recipient.write(recipient);
        }

        fn propose_protocol_fee_recipient(ref self: ContractState, recipient: felt252) {
            assert_admin(@self);
            assert(recipient != 0, 'BAD_RECIPIENT');
            self.pending_fee_recipient.write(recipient);
            self
                .pending_fee_recipient_eta
                .write(get_block_timestamp() + RECIPIENT_TIMELOCK_SECONDS);
        }

        fn execute_protocol_fee_recipient(ref self: ContractState) {
            assert_admin(@self);
            let eta = self.pending_fee_recipient_eta.read();
            assert(eta != 0 && get_block_timestamp() >= eta, 'RECIPIENT_TIMELOCK');
            self.protocol_fee_recipient.write(self.pending_fee_recipient.read());
            self.pending_fee_recipient_eta.write(0);
        }

        fn lock_config(ref self: ContractState) {
            assert_admin(@self);
            assert(!self.settlement_account.read().is_zero(), 'SETTLEMENT_UNSET');
            assert(!self.proof_program.read().is_zero(), 'PROOF_PROGRAM_UNSET');
            assert(self.expected_proof_version.read() != 0, 'PROOF_CONFIG_UNSET');
            assert(!self.bridge.read().is_zero(), 'CUSTODY_UNSET');
            assert(self.reference_signer.read() != 0, 'SIGNER_UNSET');
            assert(self.objective_numeraire.read() != 0, 'NUMERAIRE_UNSET');
            assert(self.protocol_fee_recipient.read() != 0, 'RECIPIENT_UNSET');
            self.config_locked.write(true);
        }

        fn activate_deposit_root(
            ref self: ContractState, funding_commitment: felt252, deposit_root: felt252,
        ) {
            assert(get_caller_address() == self.deposit_root_registrar.read(), 'UNAUTHORIZED');
            assert_not_paused(@self);
            assert(funding_commitment != 0 && deposit_root != 0, 'BAD_DEPOSIT');
            assert(!self.activated_funding.read(funding_commitment), 'FUNDING_ACTIVE');
            self.activated_funding.write(funding_commitment, true);
            let note_root = append_note_batch(ref self, deposit_root);
            self.emit(DepositActivated { funding_commitment, deposit_root, note_root });
        }

        fn submit_transition(
            ref self: ContractState,
            header: TransitionHeader,
            markets: Span<MarketAttestation>,
            outcomes: Span<OutcomeRecord>,
            capacities: Span<CapacityEntry>,
            nullifiers: Span<felt252>,
            outputs: Span<OutputRecord>,
        ) {
            assert(get_caller_address() == self.settlement_account.read(), 'UNAUTHORIZED');
            assert_not_paused(@self);
            let chain_context: felt252 = get_contract_address().into();

            // the chain position: strictly the next transition, on the current book.
            assert(header.seq == self.seq.read() + 1, 'BAD_SEQ');
            assert(header.prior_book_root == self.book_root.read(), 'STALE_BOOK');
            assert(header.close_time_ms > self.last_close_time_ms.read(), 'STALE_CLOSE');
            let now_ms = get_block_timestamp() * 1000;
            assert(header.close_time_ms <= now_ms + MAX_REFERENCE_FUTURE_SKEW_MS, 'FUTURE_CLOSE');
            assert(now_ms <= header.close_time_ms + self.max_close_delay_ms.read(), 'LATE_CLOSE');
            if nullifiers_admit_orders(header.note_root) {
                assert(self.known_note_roots.read(header.note_root), 'UNKNOWN_NOTE_ROOT');
            }

            let markets_commitment = verify_markets(
                @self, chain_context, header.seq, header.close_time_ms, markets,
            );
            let outcomes_commitment = apply_outcomes(ref self, outcomes);
            let capacity_commitment = open_capacities(
                ref self, chain_context, header.seq, markets, capacities,
            );
            let nullifiers_commitment = spend_nullifiers(ref self, chain_context, nullifiers);
            let outputs_commitment = outputs_commitment(chain_context, outputs);
            let fee_recipient = self.protocol_fee_recipient.read();
            assert(fee_recipient != 0, 'RECIPIENT_UNSET');

            let mut commitment = array![
                TRANSITION_DOMAIN, chain_context, header.seq.into(), header.close_time_ms.into(),
                header.prior_book_root, header.new_book_root, header.note_root, markets_commitment,
                outcomes_commitment, capacity_commitment, nullifiers_commitment, outputs_commitment,
                header.output_root, fee_recipient,
            ];
            let transition_commitment = poseidon_hash_span(commitment.span());
            assert_proof_facts_message(
                @self,
                bound_message(TRANSITION_MESSAGE_DOMAIN, chain_context, transition_commitment),
                TRANSITION_MESSAGE_DOMAIN,
            );

            self.seq.write(header.seq);
            self.book_root.write(header.new_book_root);
            self.last_close_time_ms.write(header.close_time_ms);
            let note_root = append_note_batch(ref self, header.output_root);
            self
                .emit(
                    TransitionSettled {
                        seq: header.seq,
                        new_book_root: header.new_book_root,
                        output_root: header.output_root,
                        note_root,
                        output_count: outputs.len(),
                    },
                );
            commitment = array![];
            let _ = commitment;
        }

        fn settle_external_fill(
            ref self: ContractState,
            seq: u32,
            pair_id: felt252,
            sell: bool,
            fill_base: u128,
            m1: MarketAttestation,
        ) -> (felt252, felt252, u128, u128) {
            let router = self.external_router.read();
            assert(!router.is_zero() && get_caller_address() == router, 'UNAUTHORIZED');
            assert_not_paused(@self);
            let key = (seq, pair_id, sell);
            let mut capacity = self.capacities.read(key);
            assert(capacity.status == CAPACITY_OPEN, 'CAPACITY_CLOSED');
            assert(
                get_block_timestamp() <= capacity.opened_at + self.external_window_seconds.read(),
                'CAPACITY_EXPIRED',
            );
            // a capacity fills in parts, by anyone, until it is used up or its window closes.
            assert(
                fill_base != 0 && fill_base <= capacity.total - capacity.consumed_base, 'BAD_FILL',
            );
            assert(m1.pair_id == pair_id && m1.scale == capacity.scale, 'BAD_M1_MARKET');
            let now_ms = get_block_timestamp() * 1000;
            assert(m1.observed_at_ms <= now_ms + MAX_REFERENCE_FUTURE_SKEW_MS, 'FUTURE_M1');
            assert(m1.valid_until_ms >= now_ms, 'STALE_M1');
            let singleton = array![m1];
            let batch_commitment = price_batch_commitment(
                @self, get_contract_address().into(), singleton.span(),
            );
            verify_attestation(@self, get_contract_address().into(), m1, batch_commitment);
            // the pool trades at m1, which respects every reserved order's limit.
            if sell {
                assert(m1.midpoint >= capacity.bound, 'M1_BELOW_BOUND');
            } else {
                assert(m1.midpoint <= capacity.bound, 'M1_ABOVE_BOUND');
            }
            let product: u256 = fill_base.into() * m1.midpoint.into();
            let (floor, remainder) = DivRem::div_rem(
                product, Into::<u128, u256>::into(m1.scale).try_into().unwrap(),
            );
            let floor: u128 = floor.try_into().expect('QUOTE_OVERFLOW');
            let pair = pair_config_of(@self, pair_id);
            // every fill is at least as good as the bound after rounding, not only its m1, so
            // the capacity's average price, at which its orders share the fills, respects every
            // reserved order's limit exactly.
            let at_bound: u256 = fill_base.into() * capacity.bound.into();
            let scale_u256: u256 = capacity.scale.into();
            // sells: the pool gives base and receives the floor of the quote; buys: the pool
            // gives the ceiling of the quote and receives base.
            let (input_asset, output_asset, input_amount, output_amount, fill_quote) = if sell {
                assert(floor != 0, 'BAD_FILL_QUOTE');
                let floor_u256: u256 = floor.into();
                assert(floor_u256 * scale_u256 >= at_bound, 'FILL_BELOW_BOUND');
                (pair.base_asset_id, pair.quote_asset_id, fill_base, floor, floor)
            } else {
                let ceil = if remainder == 0 {
                    floor
                } else {
                    floor + 1
                };
                let ceil_u256: u256 = ceil.into();
                assert(ceil_u256 * scale_u256 <= at_bound, 'FILL_ABOVE_BOUND');
                (pair.quote_asset_id, pair.base_asset_id, ceil, fill_base, ceil)
            };
            let consumed_base = capacity.consumed_base + fill_base;
            let pool_quote = capacity.pool_quote + fill_quote;
            assert(pool_quote < OUTCOME_AMOUNT_BOUND, 'QUOTE_OVERFLOW');
            IExitStagingDispatcher { contract_address: self.bridge.read() }
                .settle_external_match_asset_swap(
                    router, input_asset, output_asset, input_amount, output_amount,
                );
            capacity.consumed_base = consumed_base;
            capacity.pool_quote = pool_quote;
            capacity.m1 = m1.midpoint;
            capacity.generation += 1;
            if consumed_base == capacity.total {
                capacity.status = CAPACITY_FILLED;
            }
            self.capacities.write(key, capacity);
            self
                .emit(
                    ExternalFilled {
                        seq,
                        pair_id,
                        sell,
                        fill_base,
                        fill_quote,
                        m1: m1.midpoint,
                        consumed_base,
                        pool_quote,
                    },
                );
            (input_asset, output_asset, input_amount, output_amount)
        }

        /// establishes an on-chain cutoff for a capacity. fills ordered before this call remain
        /// firm; after it lands, the immutable unconsumed remainder may rejoin internal clearing.
        fn freeze_capacity(
            ref self: ContractState,
            seq: u32,
            pair_id: felt252,
            sell: bool,
            expected_generation: u64,
        ) {
            assert_settlement(@self);
            assert_not_paused(@self);
            let key = (seq, pair_id, sell);
            let mut capacity = self.capacities.read(key);
            assert(capacity.status == CAPACITY_OPEN, 'CAPACITY_CLOSED');
            assert(capacity.generation == expected_generation, 'STALE_CAPACITY');
            capacity.status = CAPACITY_FROZEN;
            capacity.generation += 1;
            self.capacities.write(key, capacity);
        }

        fn request_withdrawal(
            ref self: ContractState,
            note_root: felt252,
            nullifier: felt252,
            asset_id: felt252,
            amount: u128,
            exit_commitment: felt252,
            exit_authority: felt252,
        ) {
            assert_not_paused(@self);
            assert(nullifier != 0 && asset_id != 0 && amount != 0, 'BAD_WITHDRAWAL');
            assert(exit_commitment != 0 && exit_authority != 0, 'BAD_EXIT');
            assert(self.known_note_roots.read(note_root), 'UNKNOWN_NOTE_ROOT');
            assert(self.nullifier_states.read(nullifier) == NULLIFIER_UNUSED, 'NULLIFIER_USED');
            let chain_context: felt252 = get_contract_address().into();
            let commitment = poseidon_hash_span(
                array![
                    WITHDRAWAL_DOMAIN, chain_context, note_root, nullifier, asset_id, amount.into(),
                    exit_commitment, exit_authority,
                ]
                    .span(),
            );
            assert_proof_facts_message(
                @self,
                bound_message(WITHDRAWAL_MESSAGE_DOMAIN, chain_context, commitment),
                WITHDRAWAL_MESSAGE_DOMAIN,
            );
            let matures_at = get_block_timestamp() + self.withdrawal_delay_seconds.read();
            self.nullifier_states.write(nullifier, NULLIFIER_EXIT_PENDING);
            self
                .pending_exits
                .write(
                    nullifier,
                    PendingExit { asset_id, amount, exit_commitment, exit_authority, matures_at },
                );
            self.emit(WithdrawalRequested { nullifier, matures_at });
        }

        fn finalize_withdrawal(ref self: ContractState, nullifier: felt252) {
            assert_not_paused(@self);
            assert(
                self.nullifier_states.read(nullifier) == NULLIFIER_EXIT_PENDING, 'NO_PENDING_EXIT',
            );
            let exit = self.pending_exits.read(nullifier);
            assert(get_block_timestamp() >= exit.matures_at, 'EXIT_NOT_MATURE');
            self.nullifier_states.write(nullifier, NULLIFIER_EXITED);
            IExitStagingDispatcher { contract_address: self.bridge.read() }
                .stage_verified_note_strk20_exit(
                    exit.asset_id,
                    exit.amount,
                    nullifier,
                    exit.exit_authority,
                    exit.exit_commitment,
                );
            self.emit(WithdrawalFinalized { nullifier, exit_commitment: exit.exit_commitment });
        }

        fn transition_seq(self: @ContractState) -> u32 {
            self.seq.read()
        }

        fn book_root(self: @ContractState) -> felt252 {
            self.book_root.read()
        }

        fn last_close_time_ms(self: @ContractState) -> u64 {
            self.last_close_time_ms.read()
        }

        fn note_root(self: @ContractState) -> felt252 {
            self.current_note_root.read()
        }

        fn note_batch_count(self: @ContractState) -> u64 {
            self.note_batch_count.read()
        }

        fn is_known_note_root(self: @ContractState, root: felt252) -> bool {
            self.known_note_roots.read(root)
        }

        fn nullifier_state(self: @ContractState, nullifier: felt252) -> u8 {
            self.nullifier_states.read(nullifier)
        }

        fn pending_exit(self: @ContractState, nullifier: felt252) -> PendingExit {
            self.pending_exits.read(nullifier)
        }

        fn capacity(self: @ContractState, seq: u32, pair_id: felt252, sell: bool) -> Capacity {
            self.capacities.read((seq, pair_id, sell))
        }

        fn pair_config(self: @ContractState, pair_id: felt252) -> PairConfig {
            PairConfig {
                base_asset_id: self.pair_base.read(pair_id),
                quote_asset_id: self.pair_quote.read(pair_id),
                fee_bps: self.pair_fee_bps.read(pair_id),
            }
        }

        fn protocol_fee_recipient(self: @ContractState) -> felt252 {
            self.protocol_fee_recipient.read()
        }

        fn reference_signer(self: @ContractState) -> felt252 {
            self.reference_signer.read()
        }

        fn transition_message_hash(
            self: @ContractState, transition_commitment: felt252,
        ) -> felt252 {
            proof_message_hash(
                self.proof_program.read(),
                TRANSITION_MESSAGE_DOMAIN,
                bound_message(
                    TRANSITION_MESSAGE_DOMAIN, get_contract_address().into(), transition_commitment,
                ),
            )
        }

        fn withdrawal_message_hash(
            self: @ContractState, withdrawal_commitment: felt252,
        ) -> felt252 {
            proof_message_hash(
                self.proof_program.read(),
                WITHDRAWAL_MESSAGE_DOMAIN,
                bound_message(
                    WITHDRAWAL_MESSAGE_DOMAIN, get_contract_address().into(), withdrawal_commitment,
                ),
            )
        }

        fn admin_address(self: @ContractState) -> ContractAddress {
            self.admin.read()
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }

        fn config_is_locked(self: @ContractState) -> bool {
            self.config_locked.read()
        }
    }

    fn assert_admin(self: @ContractState) {
        assert(get_caller_address() == self.admin.read(), 'UNAUTHORIZED');
    }

    fn assert_settlement(self: @ContractState) {
        let settlement = self.settlement_account.read();
        assert(!settlement.is_zero() && get_caller_address() == settlement, 'UNAUTHORIZED');
    }

    fn assert_unlocked_admin(self: @ContractState) {
        assert_admin(self);
        assert(!self.config_locked.read(), 'CONFIG_LOCKED');
    }

    fn assert_not_paused(self: @ContractState) {
        assert(!self.paused.read(), 'PAUSED');
    }

    fn nullifiers_admit_orders(note_root: felt252) -> bool {
        note_root != 0
    }

    fn pair_config_of(self: @ContractState, pair_id: felt252) -> PairConfig {
        let base_asset_id = self.pair_base.read(pair_id);
        assert(base_asset_id != 0, 'UNKNOWN_PAIR');
        PairConfig {
            base_asset_id,
            quote_asset_id: self.pair_quote.read(pair_id),
            fee_bps: self.pair_fee_bps.read(pair_id),
        }
    }

    fn poseidon2(x: felt252, y: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(x, y, 2);
        result
    }

    /// the statement message the proof program emits: bound to this contract.
    fn bound_message(domain: felt252, chain_context: felt252, commitment: felt252) -> felt252 {
        poseidon2(poseidon2(domain, chain_context), commitment)
    }

    /// the l1 message hash the proof facts carry for a statement message.
    fn proof_message_hash(
        proof_program: ContractAddress, domain: felt252, statement_message: felt252,
    ) -> felt252 {
        poseidon_hash_span(
            array![proof_program.into(), PROOF_MESSAGE_TO, 2, domain, statement_message].span(),
        )
    }

    fn assert_proof_facts_message(
        self: @ContractState, statement_message: felt252, domain: felt252,
    ) {
        let execution_info = get_execution_info_v3_syscall().unwrap_syscall();
        let current_block_number = execution_info.block_info.block_number;
        let mut serialized = execution_info.tx_info.proof_facts;
        assert(!serialized.is_empty(), 'EMPTY_PROOF_FACTS');
        let facts: ProofFacts = Serde::deserialize(ref serialized).expect('BAD_PROOF_FACTS');
        assert(serialized.is_empty(), 'BAD_PROOF_FACTS_LEN');
        let proof_version = self.expected_proof_version.read();
        assert(proof_version != 0, 'PROOF_VERSION_UNSET');
        assert(facts.proof_version == proof_version, 'BAD_PROOF_VERSION');
        assert(facts.program_variant == VIRTUAL_SNOS, 'BAD_PROOF_PROGRAM');
        assert(facts.starknet_os_output_version == VIRTUAL_SNOS0, 'BAD_PROOF_OUTPUT');
        assert(facts.base_block_hash != 0, 'BAD_BASE_BLOCK_HASH');
        let os_config_hash = self.expected_os_config_hash.read();
        assert(os_config_hash != 0, 'OS_CONFIG_UNSET');
        assert(facts.starknet_os_config_hash == os_config_hash, 'BAD_OS_CONFIG');
        let proof_program = self.proof_program.read();
        assert(!proof_program.is_zero(), 'PROOF_PROGRAM_UNSET');
        assert(facts.virtual_program_hash == self.virtual_program_hash.read(), 'BAD_PROOF_HASH');
        assert(facts.base_block_number < current_block_number, 'STALE_PROOF_BASE');
        assert(
            current_block_number <= facts.base_block_number + self.proof_validity_blocks.read(),
            'EXPIRED_PROOF',
        );
        assert(
            facts
                .message_to_l1_hashes == array![
                    proof_message_hash(proof_program, domain, statement_message),
                ]
                .span(),
            'BAD_PROOF_MSG',
        );
    }

    /// verifies each market's m0 attestation and fee, and returns the statement's markets
    /// commitment.
    fn verify_markets(
        self: @ContractState,
        chain_context: felt252,
        seq: u32,
        close_time_ms: u64,
        markets: Span<MarketAttestation>,
    ) -> felt252 {
        assert(!markets.is_empty(), 'NO_MARKETS');
        let batch_commitment = price_batch_commitment(self, chain_context, markets);
        let mut values = array![
            M0_DOMAIN, chain_context, seq.into(), close_time_ms.into(),
            self.objective_numeraire.read(), markets.len().into(),
        ];
        for market in markets {
            let market = *market;
            verify_attestation(self, chain_context, market, batch_commitment);
            // the statement checks observed_at <= close_time <= valid_until.
            let pair = pair_config_of(self, market.pair_id);
            values.append(market.pair_id);
            values.append(pair.base_asset_id);
            values.append(pair.quote_asset_id);
            values.append(market.midpoint.into());
            values.append(market.scale.into());
            values.append(market.observed_at_ms.into());
            values.append(market.valid_until_ms.into());
            values.append(pair.fee_bps.into());
        }
        poseidon_hash_span(values.span())
    }

    fn price_batch_commitment(
        self: @ContractState, verifier: felt252, markets: Span<MarketAttestation>,
    ) -> felt252 {
        let mut state = poseidon2(REFERENCE_PRICE_BATCH_DOMAIN, verifier);
        state = poseidon2(state, markets.len().into());
        for market in markets {
            let market = *market;
            let pair = pair_config_of(self, market.pair_id);
            for value in array![
                market.pair_id, pair.base_asset_id, pair.quote_asset_id, market.midpoint.into(),
                market.lower_price.into(), market.upper_price.into(), market.scale.into(),
                market.source_count.into(), market.observed_at_ms.into(),
                market.valid_until_ms.into(), market.source_set_commitment, market.nonce.into(),
            ] {
                state = poseidon2(state, value);
            }
        }
        state
    }

    fn verify_attestation(
        self: @ContractState,
        verifier: felt252,
        market: MarketAttestation,
        expected_batch_commitment: felt252,
    ) {
        assert(market.midpoint != 0 && market.lower_price <= market.midpoint, 'BAD_REF_PRICE');
        assert(market.midpoint <= market.upper_price && market.scale != 0, 'BAD_REF_PRICE');
        assert(
            market.source_count >= MIN_REFERENCE_SOURCES && market.source_set_commitment != 0,
            'BAD_REF_SOURCES',
        );
        assert(market.valid_until_ms > market.observed_at_ms, 'BAD_REF_WINDOW');
        assert(
            market.valid_until_ms - market.observed_at_ms <= MAX_REFERENCE_WINDOW_MS,
            'BAD_REF_WINDOW',
        );
        let pair = pair_config_of(self, market.pair_id);
        assert(market.price_batch_commitment == expected_batch_commitment, 'BAD_PRICE_BATCH');
        let signer = self.reference_signer.read();
        assert(signer != 0, 'SIGNER_UNSET');
        let mut state = poseidon2(REFERENCE_PRICE_ATTESTATION_DOMAIN, verifier);
        for value in array![
            market.pair_id, pair.base_asset_id, pair.quote_asset_id, market.midpoint.into(),
            market.lower_price.into(), market.upper_price.into(), market.scale.into(),
            market.source_count.into(), market.observed_at_ms.into(), market.valid_until_ms.into(),
            market.source_set_commitment, market.nonce.into(), market.price_batch_commitment,
            signer,
        ] {
            state = poseidon2(state, value);
        }
        assert(
            check_ecdsa_signature(state, signer, market.signature_r, market.signature_s),
            'BAD_REF_SIGNATURE',
        );
    }

    /// consumes each earlier outcome exactly once, once its capacity is used up or its external
    /// window closed, and returns the statement's outcomes commitment.
    fn apply_outcomes(ref self: ContractState, outcomes: Span<OutcomeRecord>) -> felt252 {
        let mut values = array![OUTCOMES_DOMAIN];
        let window = self.external_window_seconds.read();
        let now = get_block_timestamp();
        for outcome in outcomes {
            let outcome = *outcome;
            let key = (outcome.seq, outcome.pair_id, outcome.sell);
            let mut capacity = self.capacities.read(key);
            assert(
                capacity.status == CAPACITY_OPEN
                    || capacity.status == CAPACITY_FILLED
                    || capacity.status == CAPACITY_FROZEN,
                'OUTCOME_UNAVAILABLE',
            );
            // a used-up capacity can take no more fills, so its totals are final at once and
            // its orders settle at the next transition; a capacity with base left settles once
            // its window closes.
            assert(
                capacity.status == CAPACITY_FILLED
                    || capacity.status == CAPACITY_FROZEN
                    || now > capacity.opened_at
                    + window,
                'OUTCOME_WINDOW_OPEN',
            );
            assert(outcome.consumed_base == capacity.consumed_base, 'OUTCOME_MISMATCH');
            assert(outcome.pool_quote == capacity.pool_quote, 'OUTCOME_MISMATCH');
            // the orders share every fill at the average price; an unfilled capacity keeps its
            // bound, which prices nothing.
            let (price, price_scale) = if capacity.consumed_base == 0 {
                (capacity.m1, capacity.scale)
            } else {
                (capacity.pool_quote, capacity.consumed_base)
            };
            assert(outcome.m1 == price && outcome.m1_scale == price_scale, 'OUTCOME_MISMATCH');
            capacity.status = CAPACITY_APPLIED;
            self.capacities.write(key, capacity);
            values.append(outcome.seq.into());
            values.append(outcome.pair_id);
            values.append(if outcome.sell {
                1
            } else {
                0
            });
            values.append(outcome.consumed_base.into());
            values.append(outcome.pool_quote.into());
            values.append(outcome.m1.into());
            values.append(outcome.m1_scale.into());
        }
        values.append(outcomes.len().into());
        poseidon_hash_span(values.span())
    }

    /// records this transition's external capacities, each with a zero outcome until a fill,
    /// and returns the statement's capacity commitment.
    fn open_capacities(
        ref self: ContractState,
        chain_context: felt252,
        seq: u32,
        markets: Span<MarketAttestation>,
        capacities: Span<CapacityEntry>,
    ) -> felt252 {
        let mut values = array![CAPACITY_DOMAIN, chain_context];
        let now = get_block_timestamp();
        for entry in capacities {
            let entry = *entry;
            assert(entry.bound != 0 && entry.total != 0, 'BAD_CAPACITY');
            let mut scale: u128 = 0;
            for market in markets {
                if (*market).pair_id == entry.pair_id {
                    scale = (*market).scale;
                }
            }
            assert(scale != 0, 'CAPACITY_MARKET');
            self
                .capacities
                .write(
                    (seq, entry.pair_id, entry.sell),
                    Capacity {
                        bound: entry.bound,
                        total: entry.total,
                        scale,
                        opened_at: now,
                        consumed_base: 0,
                        pool_quote: 0,
                        m1: entry.bound,
                        status: CAPACITY_OPEN,
                        generation: 0,
                    },
                );
            values.append(entry.pair_id);
            values.append(if entry.sell {
                1
            } else {
                0
            });
            values.append(entry.bound.into());
            values.append(entry.total.into());
        }
        values.append(capacities.len().into());
        poseidon_hash_span(values.span())
    }

    /// spends every admitted note's nullifier; a pending exit on the same note is voided.
    fn spend_nullifiers(
        ref self: ContractState, chain_context: felt252, nullifiers: Span<felt252>,
    ) -> felt252 {
        let mut state = poseidon2(NULLIFIERS_DOMAIN, chain_context);
        for nullifier in nullifiers {
            let nullifier = *nullifier;
            let current = self.nullifier_states.read(nullifier);
            assert(
                current == NULLIFIER_UNUSED || current == NULLIFIER_EXIT_PENDING, 'NULLIFIER_SPENT',
            );
            self.nullifier_states.write(nullifier, NULLIFIER_SPENT);
            state = poseidon2(state, nullifier);
        }
        poseidon2(state, nullifiers.len().into())
    }

    fn outputs_commitment(chain_context: felt252, outputs: Span<OutputRecord>) -> felt252 {
        let mut values = array![OUTPUTS_DOMAIN, chain_context];
        for output in outputs {
            values.append((*output).leaf);
            values.append((*output).enc);
        }
        values.append(outputs.len().into());
        poseidon_hash_span(values.span())
    }

    fn empty_book_root(chain_context: felt252) -> felt252 {
        poseidon_hash_span(array!['zylith_book_v1', chain_context, 0].span())
    }

    fn note_accumulator_node(left: felt252, right: felt252, level: u64) -> felt252 {
        if left == 0 && right == 0 {
            return 0;
        }
        let (result, _, _) = hades_permutation(
            left, right, NOTE_ACCUMULATOR_NODE_DOMAIN + level.into(),
        );
        result
    }

    /// appends a batch root (a deposit leaf or a transition's output root) to the note
    /// accumulator and records the new root as known.
    fn append_note_batch(ref self: ContractState, batch_root: felt252) -> felt252 {
        assert(batch_root != 0, 'BAD_BATCH_ROOT');
        let leaf_count = self.note_batch_count.read();
        assert(leaf_count < NOTE_ACCUMULATOR_CAPACITY, 'NOTE_ACC_CAPACITY');
        let mut carry = poseidon2(NOTE_ACCUMULATOR_LEAF_DOMAIN, batch_root);
        let mut remaining = leaf_count;
        let mut level: u64 = 0;
        while remaining % 2 == 1 {
            let left = self.note_frontier.read(level);
            carry = note_accumulator_node(left, carry, level);
            remaining = remaining / 2;
            level += 1;
        }
        self.note_frontier.write(level, carry);
        let size = leaf_count + 1;
        self.note_batch_count.write(size);
        // fold the frontier into the root: a peak at every set bit of the size.
        let mut root: felt252 = 0;
        let mut size_bits = size;
        let mut level: u64 = 0;
        while level != NOTE_ACCUMULATOR_DEPTH {
            root =
                if size_bits % 2 == 1 {
                    note_accumulator_node(self.note_frontier.read(level), root, level)
                } else {
                    note_accumulator_node(root, 0, level)
                };
            size_bits = size_bits / 2;
            level += 1;
        }
        self.current_note_root.write(root);
        self.known_note_roots.write(root, true);
        root
    }
}
