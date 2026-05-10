use core::array::{Array, ArrayTrait};
use core::ecdsa::check_ecdsa_signature;
use core::poseidon::hades_permutation;
use core::traits::{Into, TryInto};

const ORDER_SIDE_BUY: felt252 = 0;
const ORDER_SIDE_SELL: felt252 = 1;
const ORDER_TYPE_LIMIT_BATCH: felt252 = 0;
const ORDER_TYPE_MAKER_CURVE: felt252 = 1;
const ORDER_TYPE_HEARTBEAT_COVER: felt252 = 2;
const TIF_CURRENT_BATCH_ONLY: felt252 = 0;
const TIF_FILL_OR_KILL: felt252 = 1;
const PROTOCOL_FEE_BPS: u128 = 30;
const FEE_BPS_DENOMINATOR: u128 = 10000;
const PROTOCOL_FEE_RECIPIENT: felt252 =
    0x17f17d05fe8e71146a7d5bb6f40f83ca10d838c8259a10e7ec3e799932fd476;
const RENEWAL_CHILD_NULLIFIER_DOMAIN: felt252 =
    0x362b534b676bb36e394d08e276c8e64e65e3733e5d517a7eb6f438eafe54b61;
const RENEWAL_PARENT_SECRET_DOMAIN: felt252 =
    0x7d7cdc3705c6b67855258ca803ee7b93dd4092346289da942f337b30d857667;
const RENEWAL_PARENT_DOMAIN: felt252 =
    0x3c16da1b34d6fcc6f6ea27674de3b6cead275b20c1dfafa4abb43515a8974b4;
const RENEWAL_PARENT_CANCEL_DOMAIN: felt252 =
    0x26f84b60309c08d4030876815edb467f89f78e5a5f62823af4521f1be502ca3;
const OUTPUT_NOTE_LEAF_DOMAIN: felt252 =
    0x0f0c89949c6cba4ac7f170f7f00809b458b997f2e394481c7ab58cc68aa49b3;
const OUTPUT_NOTE_NODE_DOMAIN: felt252 =
    0x03c6998f476a618431be1c1764a6724f13c0739be395bab4c1217bc0a65b2ee7;
const EMPTY_OUTPUT_NOTE_ROOT_DOMAIN: felt252 =
    0x0279c22958925b34e81138c0d651a82cdbfd3287fa3de370e021a7201b4ce30b;
const OUTPUT_RECOVERY_FIELD_COUNT: usize = 21;
const OUTPUT_RECOVERY_PROOF_SLOTS: usize = 4;
const OUTPUT_RECOVERY_BUNDLE_DOMAIN: felt252 = 0x7a796c6974685f6f75745f62756e646c655f7631;
const OUTPUT_RECOVERY_RECORD_DOMAIN: felt252 = 0x7a796c6974685f6f75745f7265635f7631;
const OUTPUT_RECOVERY_STREAM_DOMAIN: felt252 = 0x7a796c6974685f6f75745f73747265616d5f7631;
const OUTPUT_RECOVERY_AUTH_DOMAIN: felt252 = 0x7a796c6974685f6f75745f617574685f7631;
const OUTPUT_RECOVERY_TAG_DOMAIN: felt252 = 0x7a796c6974685f6f75745f7461675f7631;
const DEPOSIT_NOTE_ROOT_DOMAIN: felt252 = 0x7a796c6974685f6465706f7369745f6e6f74655f726f6f745f7631;
const NULLIFIER_SPARSE_TREE_DEPTH: usize = 64;
const NULLIFIER_KEY_HIGH_BOUND: u128 = 0x10000000000000000000000000000000;
const NULLIFIER_KEY_LOW_MODULUS: u128 = 0x10000000000000000;
const TWO_POW_128: felt252 = 0x100000000000000000000000000000000;
const NOTE_MEMBERSHIP_KIND_DEPOSIT: felt252 = 0;
const NOTE_MEMBERSHIP_KIND_SETTLEMENT_OUTPUT: felt252 = 1;
const STATEMENT_TYPE_SETTLEMENT: felt252 = 1;
const STATEMENT_TYPE_ADMISSION: felt252 = 3;
const STATEMENT_TYPE_AUCTION_RESULT: felt252 = 4;
const ADMISSION_ROOT_DOMAIN: felt252 = 0x7a796c6974685f61646d69745f726f6f745f7631;
const ADMISSION_LEAF_DOMAIN: felt252 = 0x7a796c6974685f61646d69745f6c6561665f7631;

#[executable]
fn main(input: Array<felt252>) -> felt252 {
    let data = input.span();
    assert(data.len() != 0, 'EMPTY_INPUT');
    let statement_type = *data.at(0);
    if statement_type == STATEMENT_TYPE_ADMISSION {
        let (_batch_id, _order_commitment_root, admission_root) = verify_admission_statement(data);
        admission_root
    } else if statement_type == STATEMENT_TYPE_AUCTION_RESULT {
        let (_batch_id, _order_commitment_root, _admission_root, transcript_commitment) =
            verify_auction_result_statement(
            data,
        );
        transcript_commitment
    } else {
        verify_settlement_statement(data)
    }
}

pub fn verify_settlement_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');

    let note_commitment_domain = read_next(data, ref index);
    let spend_authority_domain = read_next(data, ref index);
    let nullifier_domain = read_next(data, ref index);
    let order_commitment_domain = read_next(data, ref index);
    let maker_curve_domain = read_next(data, ref index);
    let public_settlement_domain = read_next(data, ref index);
    let batch_id = read_next(data, ref index);
    let pair_id = read_next(data, ref index);
    let batch_epoch = read_next(data, ref index);
    let order_commitment_root = read_next(data, ref index);
    let encrypted_order_set_commitment = read_next(data, ref index);
    let transcript_commitment = read_next(data, ref index);
    let base_asset_id = read_next(data, ref index);
    let quote_asset_id = read_next(data, ref index);
    let clearing_price = read_next(data, ref index);
    let matched_order_count = read_next(data, ref index);
    let output_bundle_ref = read_next(data, ref index);
    let prior_note_root = read_next(data, ref index);
    let prior_nullifier_root = read_next(data, ref index);
    let prior_renewal_root = read_next(data, ref index);
    let prior_fee_root = read_next(data, ref index);
    let consumed_note_root_domain = read_next(data, ref index);
    let consumed_nullifier_root_domain = read_next(data, ref index);
    let renewal_child_root_domain = read_next(data, ref index);
    let output_note_root_domain = read_next(data, ref index);
    let fee_root_domain = read_next(data, ref index);
    let state_transition_root_domain = read_next(data, ref index);
    let nullifier_sparse_leaf_domain = read_next(data, ref index);
    let nullifier_sparse_node_domain = read_next(data, ref index);
    assert(note_commitment_domain != 0, 'BAD_NOTE_DOMAIN');
    assert(spend_authority_domain != 0, 'BAD_SPEND_DOMAIN');
    assert(nullifier_domain != 0, 'BAD_NULLIFIER_DOMAIN');
    assert(order_commitment_domain != 0, 'BAD_ORDER_DOMAIN');
    assert(maker_curve_domain != 0, 'BAD_CURVE_DOMAIN');
    assert(public_settlement_domain != 0, 'BAD_SETTLEMENT_DOMAIN');
    assert(batch_id != 0, 'BAD_BATCH');
    assert(batch_epoch != 0, 'BAD_BATCH_EPOCH');
    assert(order_commitment_root != 0, 'BAD_ORDER_ROOT');
    assert(encrypted_order_set_commitment != 0, 'BAD_ENC_SET');
    assert(transcript_commitment != 0, 'BAD_TRANSCRIPT');
    assert(pair_id != 0, 'BAD_PAIR');
    assert(base_asset_id != 0, 'BAD_BASE');
    assert(quote_asset_id != 0, 'BAD_QUOTE');
    if matched_order_count != 0 {
        assert(clearing_price != 0, 'BAD_PRICE');
    }
    assert(output_bundle_ref != 0, 'BAD_OUTPUT_REF');
    assert(consumed_note_root_domain != 0, 'BAD_INPUT_ROOT_DOMAIN');
    assert(consumed_nullifier_root_domain != 0, 'BAD_NULL_ROOT_DOMAIN');
    assert(renewal_child_root_domain != 0, 'BAD_RENEWAL_ROOT_DOMAIN');
    assert(output_note_root_domain != 0, 'BAD_OUTPUT_ROOT_DOMAIN');
    assert(fee_root_domain != 0, 'BAD_FEE_ROOT_DOMAIN');
    assert(state_transition_root_domain != 0, 'BAD_STATE_ROOT_DOMAIN');
    assert(nullifier_sparse_leaf_domain != 0, 'BAD_NULL_LEAF_DOMAIN');
    assert(nullifier_sparse_node_domain != 0, 'BAD_NULL_NODE_DOMAIN');
    assert(base_asset_id != quote_asset_id, 'PAIR_COLLISION');

    let matched_order_commitments = read_vector(data, ref index);
    let matched_fill_amounts = read_vector(data, ref index);
    let matched_sides = read_vector(data, ref index);
    let matched_order_types = read_vector(data, ref index);
    let matched_maker_curve_commitments = read_vector(data, ref index);
    let matched_maker_curve_point_counts = read_vector(data, ref index);
    let matched_maker_curve_prices = read_vector(data, ref index);
    let matched_maker_curve_base_amounts = read_vector(data, ref index);
    let matched_limit_prices = read_vector(data, ref index);
    let matched_order_amounts = read_vector(data, ref index);
    let matched_min_fills = read_vector(data, ref index);
    let matched_time_in_force = read_vector(data, ref index);
    let matched_expiry_epochs = read_vector(data, ref index);
    let matched_order_nonces = read_vector(data, ref index);
    let matched_parent_order_commitments = read_vector(data, ref index);
    let matched_parent_child_indexes = read_vector(data, ref index);
    let matched_parent_secret_commitments = read_vector(data, ref index);
    let matched_parent_cancel_authorities = read_vector(data, ref index);
    let matched_parent_authorization_secrets = read_vector(data, ref index);
    let matched_auditor_flags = read_vector(data, ref index);
    let matched_funding_note_refs = read_vector(data, ref index);
    let matched_funding_note_commitments = read_vector(data, ref index);
    let matched_funding_note_asset_ids = read_vector(data, ref index);
    let matched_funding_note_amounts = read_vector(data, ref index);
    let matched_funding_note_owner_keys = read_vector(data, ref index);
    let matched_funding_note_spend_authorities = read_vector(data, ref index);
    let matched_funding_note_withdraw_authorities = read_vector(data, ref index);
    let matched_funding_note_blindings = read_vector(data, ref index);
    let matched_funding_note_nonces = read_vector(data, ref index);
    let matched_funding_note_metadata_commitments = read_vector(data, ref index);
    let matched_funding_authorization_rs = read_vector(data, ref index);
    let matched_funding_authorization_ss = read_vector(data, ref index);
    let matched_funding_nullifiers = read_vector(data, ref index);
    let matched_recipient_owner_keys = read_vector(data, ref index);
    let matched_recipient_spend_authorities = read_vector(data, ref index);
    let matched_recipient_withdraw_authorities = read_vector(data, ref index);
    let matched_res_withdraw_auths = read_vector(data, ref index);
    let matched_output_note_commitments = read_vector(data, ref index);
    let matched_output_note_asset_ids = read_vector(data, ref index);
    let matched_output_note_amounts = read_vector(data, ref index);
    let matched_output_note_owner_keys = read_vector(data, ref index);
    let matched_output_note_spend_authorities = read_vector(data, ref index);
    let matched_output_note_withdraw_authorities = read_vector(data, ref index);
    let matched_output_note_blindings = read_vector(data, ref index);
    let matched_output_note_nonces = read_vector(data, ref index);
    let matched_output_note_metadata_commitments = read_vector(data, ref index);
    let matched_residual_note_flags = read_vector(data, ref index);
    let matched_residual_note_commitments = read_vector(data, ref index);
    let matched_residual_note_asset_ids = read_vector(data, ref index);
    let matched_residual_note_amounts = read_vector(data, ref index);
    let matched_residual_note_owner_keys = read_vector(data, ref index);
    let matched_residual_note_spend_authorities = read_vector(data, ref index);
    let matched_residual_note_withdraw_authorities = read_vector(data, ref index);
    let matched_residual_note_blindings = read_vector(data, ref index);
    let matched_residual_note_nonces = read_vector(data, ref index);
    let matched_residual_note_metadata_commitments = read_vector(data, ref index);

    let consumed_note_commitments = read_vector(data, ref index);
    let consumed_nullifiers = read_vector(data, ref index);
    let nullifier_sparse_key_lows = read_vector(data, ref index);
    let nullifier_sparse_key_highs = read_vector(data, ref index);
    let nullifier_sparse_path_counts = read_vector(data, ref index);
    let nullifier_sparse_path_values = read_vector(data, ref index);
    let nullifier_sparse_path_directions = read_vector(data, ref index);
    let note_membership_kinds = read_vector(data, ref index);
    let note_membership_prefix_roots = read_vector(data, ref index);
    let note_membership_batch_roots = read_vector(data, ref index);
    let note_membership_path_counts = read_vector(data, ref index);
    let note_membership_path_values = read_vector(data, ref index);
    let note_membership_path_directions = read_vector(data, ref index);
    let note_membership_suffix_counts = read_vector(data, ref index);
    let note_membership_suffix_roots = read_vector(data, ref index);
    let renewal_parent_order_commitments = read_vector(data, ref index);
    let renewal_child_nullifiers = read_vector(data, ref index);
    let renewal_child_sparse_key_lows = read_vector(data, ref index);
    let renewal_child_sparse_key_highs = read_vector(data, ref index);
    let renewal_child_sparse_path_counts = read_vector(data, ref index);
    let renewal_child_sparse_path_values = read_vector(data, ref index);
    let renewal_child_sparse_path_directions = read_vector(data, ref index);
    let renewal_cancel_sparse_key_lows = read_vector(data, ref index);
    let renewal_cancel_sparse_key_highs = read_vector(data, ref index);
    let renewal_cancel_sparse_path_counts = read_vector(data, ref index);
    let renewal_cancel_sparse_path_values = read_vector(data, ref index);
    let renewal_cancel_sparse_path_directions = read_vector(data, ref index);
    let output_note_commitments = read_vector(data, ref index);
    let output_note_asset_ids = read_vector(data, ref index);
    let output_note_amounts = read_vector(data, ref index);
    let output_note_withdraw_authorities = read_vector(data, ref index);
    let output_note_owner_keys = read_vector(data, ref index);
    let output_note_spend_authorities = read_vector(data, ref index);
    let output_note_blindings = read_vector(data, ref index);
    let output_note_nonces = read_vector(data, ref index);
    let output_note_metadata_commitments = read_vector(data, ref index);
    let output_recovery_key_tags = read_vector(data, ref index);
    let output_recovery_auth_tags = read_vector(data, ref index);
    let output_recovery_ciphertext_fields = read_vector(data, ref index);
    let output_recovery_dummy_commitments = read_vector(data, ref index);

    let matched_len: felt252 = matched_order_commitments.len().into();
    assert(matched_len == matched_order_count, 'BAD_MATCH_COUNT');
    assert_all_lengths_match(
        matched_order_commitments.len(),
        array![
            matched_fill_amounts.len().into(), matched_sides.len().into(),
            matched_order_types.len().into(), matched_limit_prices.len().into(),
            matched_order_amounts.len().into(), matched_min_fills.len().into(),
            matched_maker_curve_commitments.len().into(),
            matched_maker_curve_point_counts.len().into(), matched_time_in_force.len().into(),
            matched_expiry_epochs.len().into(), matched_order_nonces.len().into(),
            matched_parent_order_commitments.len().into(),
            matched_parent_child_indexes.len().into(),
            matched_parent_secret_commitments.len().into(),
            matched_parent_cancel_authorities.len().into(),
            matched_parent_authorization_secrets.len().into(), matched_auditor_flags.len().into(),
            matched_funding_note_refs.len().into(), matched_funding_note_commitments.len().into(),
            matched_funding_note_asset_ids.len().into(), matched_funding_note_amounts.len().into(),
            matched_funding_note_owner_keys.len().into(),
            matched_funding_note_spend_authorities.len().into(),
            matched_funding_note_withdraw_authorities.len().into(),
            matched_funding_note_blindings.len().into(), matched_funding_note_nonces.len().into(),
            matched_funding_note_metadata_commitments.len().into(),
            matched_funding_authorization_rs.len().into(),
            matched_funding_authorization_ss.len().into(), matched_funding_nullifiers.len().into(),
            matched_recipient_owner_keys.len().into(),
            matched_recipient_spend_authorities.len().into(),
            matched_recipient_withdraw_authorities.len().into(),
            matched_res_withdraw_auths.len().into(), matched_output_note_commitments.len().into(),
            matched_output_note_asset_ids.len().into(), matched_output_note_amounts.len().into(),
            matched_output_note_owner_keys.len().into(),
            matched_output_note_spend_authorities.len().into(),
            matched_output_note_withdraw_authorities.len().into(),
            matched_output_note_blindings.len().into(), matched_output_note_nonces.len().into(),
            matched_output_note_metadata_commitments.len().into(),
            matched_residual_note_flags.len().into(),
            matched_residual_note_commitments.len().into(),
            matched_residual_note_asset_ids.len().into(),
            matched_residual_note_amounts.len().into(),
            matched_residual_note_owner_keys.len().into(),
            matched_residual_note_spend_authorities.len().into(),
            matched_residual_note_withdraw_authorities.len().into(),
            matched_residual_note_blindings.len().into(), matched_residual_note_nonces.len().into(),
            matched_residual_note_metadata_commitments.len().into(),
            consumed_note_commitments.len().into(), consumed_nullifiers.len().into(),
            note_membership_kinds.len().into(), note_membership_prefix_roots.len().into(),
            note_membership_batch_roots.len().into(), note_membership_path_counts.len().into(),
            note_membership_suffix_counts.len().into(),
        ]
            .span(),
        'BAD_WITNESS_LEN',
    );
    assert(
        note_membership_path_values.len() == note_membership_path_directions.len(),
        'BAD_INPUT_PATH_LEN',
    );
    assert(output_note_commitments.len() == output_note_asset_ids.len(), 'BAD_OUTPUT_LEN');
    assert(output_note_commitments.len() == output_note_amounts.len(), 'BAD_OUTPUT_LEN');
    assert(
        output_note_commitments.len() == output_note_withdraw_authorities.len(), 'BAD_OUTPUT_LEN',
    );
    assert(output_note_commitments.len() == output_note_owner_keys.len(), 'BAD_OUTPUT_PREIMAGE');
    assert(
        output_note_commitments.len() == output_note_spend_authorities.len(), 'BAD_OUTPUT_PREIMAGE',
    );
    assert(output_note_commitments.len() == output_note_blindings.len(), 'BAD_OUTPUT_PREIMAGE');
    assert(output_note_commitments.len() == output_note_nonces.len(), 'BAD_OUTPUT_PREIMAGE');
    assert(
        output_note_commitments.len() == output_note_metadata_commitments.len(),
        'BAD_OUTPUT_PREIMAGE',
    );
    assert(output_note_commitments.len() == output_recovery_key_tags.len(), 'BAD_RECOVERY_LEN');
    assert(output_note_commitments.len() == output_recovery_auth_tags.len(), 'BAD_RECOVERY_LEN');
    assert(
        output_recovery_ciphertext_fields.len() == output_note_commitments.len()
            * OUTPUT_RECOVERY_FIELD_COUNT,
        'BAD_RECOVERY_FIELDS',
    );
    if matched_order_commitments.len() == 0 {
        assert(consumed_note_commitments.len() == 0, 'NOOP_INPUTS');
        assert(consumed_nullifiers.len() == 0, 'NOOP_NULLIFIERS');
        assert(nullifier_sparse_key_lows.len() == 0, 'NOOP_NULLIFIER_PATH');
        assert(nullifier_sparse_key_highs.len() == 0, 'NOOP_NULLIFIER_PATH');
        assert(nullifier_sparse_path_counts.len() == 0, 'NOOP_NULLIFIER_PATH');
        assert(nullifier_sparse_path_values.len() == 0, 'NOOP_NULLIFIER_PATH');
        assert(nullifier_sparse_path_directions.len() == 0, 'NOOP_NULLIFIER_PATH');
        assert(note_membership_kinds.len() == 0, 'NOOP_INPUT_PROOFS');
        assert(renewal_parent_order_commitments.len() == 0, 'NOOP_RENEWALS');
        assert(renewal_child_nullifiers.len() == 0, 'NOOP_RENEWALS');
        assert(renewal_child_sparse_key_lows.len() == 0, 'NOOP_RENEWAL_PATH');
        assert(renewal_child_sparse_key_highs.len() == 0, 'NOOP_RENEWAL_PATH');
        assert(renewal_child_sparse_path_counts.len() == 0, 'NOOP_RENEWAL_PATH');
        assert(renewal_child_sparse_path_values.len() == 0, 'NOOP_RENEWAL_PATH');
        assert(renewal_child_sparse_path_directions.len() == 0, 'NOOP_RENEWAL_PATH');
        assert(renewal_cancel_sparse_key_lows.len() == 0, 'NOOP_RENEWAL_PATH');
        assert(renewal_cancel_sparse_key_highs.len() == 0, 'NOOP_RENEWAL_PATH');
        assert(renewal_cancel_sparse_path_counts.len() == 0, 'NOOP_RENEWAL_PATH');
        assert(renewal_cancel_sparse_path_values.len() == 0, 'NOOP_RENEWAL_PATH');
        assert(renewal_cancel_sparse_path_directions.len() == 0, 'NOOP_RENEWAL_PATH');
        assert(output_note_commitments.len() == 0, 'NOOP_OUTPUTS');
        assert(output_note_owner_keys.len() == 0, 'NOOP_OUTPUTS');
        assert(output_recovery_key_tags.len() == 0, 'NOOP_RECOVERY');
        assert(output_recovery_auth_tags.len() == 0, 'NOOP_RECOVERY');
        assert(output_recovery_ciphertext_fields.len() == 0, 'NOOP_RECOVERY');
    }
    let total_curve_points = sum_curve_point_counts(matched_maker_curve_point_counts.span());
    assert(matched_maker_curve_prices.len() == total_curve_points, 'BAD_CURVE_LEN');
    assert(matched_maker_curve_base_amounts.len() == total_curve_points, 'BAD_CURVE_LEN');

    assert_unique(matched_order_commitments.span(), 'DUP_ORDER');
    assert_unique(consumed_note_commitments.span(), 'DUP_INPUT_NOTE');
    assert_unique(consumed_nullifiers.span(), 'DUP_NULLIFIER');
    assert(nullifier_sparse_key_lows.len() == consumed_nullifiers.len(), 'SPARSE_NULLIFIER_LEN');
    assert(nullifier_sparse_key_highs.len() == consumed_nullifiers.len(), 'SPARSE_NULLIFIER_LEN');
    assert(nullifier_sparse_path_counts.len() == consumed_nullifiers.len(), 'SPARSE_NULLIFIER_LEN');
    assert(
        renewal_parent_order_commitments.len() == renewal_child_nullifiers.len(), 'BAD_RENEWAL_LEN',
    );
    assert(
        renewal_child_sparse_key_lows.len() == renewal_child_nullifiers.len(),
        'RENEWAL_KEY_LOW_LEN',
    );
    assert(
        renewal_child_sparse_key_highs.len() == renewal_child_nullifiers.len(),
        'RENEWAL_KEY_HIGH_LEN',
    );
    assert(
        renewal_child_sparse_path_counts.len() == renewal_child_nullifiers.len(),
        'RENEWAL_PATH_COUNT_LEN',
    );
    assert(
        renewal_cancel_sparse_key_lows.len() == renewal_child_nullifiers.len(),
        'RENEWAL_CANCEL_LOW_LEN',
    );
    assert(
        renewal_cancel_sparse_key_highs.len() == renewal_child_nullifiers.len(),
        'RENEWAL_CANCEL_HIGH_LEN',
    );
    assert(
        renewal_cancel_sparse_path_counts.len() == renewal_child_nullifiers.len(),
        'RENEWAL_CANCEL_COUNT_LEN',
    );
    assert_unique(renewal_child_nullifiers.span(), 'DUP_RENEWAL_CHILD');
    assert_unique(output_note_commitments.span(), 'DUP_OUTPUT');

    let clearing_price_u128 = felt_to_u128(clearing_price);
    let mut index_order = 0;
    let mut total_buy_base: u128 = 0;
    let mut total_sell_base: u128 = 0;
    let mut expected_base_fee: u128 = 0;
    let mut expected_quote_fee: u128 = 0;
    let mut curve_cursor = 0;
    let mut renewal_cursor = 0;
    let mut renewal_child_path_cursor = 0;
    let mut renewal_cancel_path_cursor = 0;
    let mut running_renewal_root = prior_renewal_root;
    let mut note_membership_path_cursor = 0;
    let mut note_membership_suffix_cursor = 0;

    while index_order < matched_order_commitments.len() {
        let order_commitment = *matched_order_commitments.at(index_order);
        let filled_amount_felt = *matched_fill_amounts.at(index_order);
        let side = *matched_sides.at(index_order);
        let order_type = *matched_order_types.at(index_order);
        let maker_curve_commitment = *matched_maker_curve_commitments.at(index_order);
        let maker_curve_point_count_felt = *matched_maker_curve_point_counts.at(index_order);
        let limit_price_felt = *matched_limit_prices.at(index_order);
        let order_amount_felt = *matched_order_amounts.at(index_order);
        let min_fill_felt = *matched_min_fills.at(index_order);
        let time_in_force = *matched_time_in_force.at(index_order);
        let expiry_epoch_felt = *matched_expiry_epochs.at(index_order);
        let order_nonce_felt = *matched_order_nonces.at(index_order);
        let parent_order_commitment = *matched_parent_order_commitments.at(index_order);
        let parent_child_index = *matched_parent_child_indexes.at(index_order);
        let parent_secret_commitment = *matched_parent_secret_commitments.at(index_order);
        let parent_cancel_authority = *matched_parent_cancel_authorities.at(index_order);
        let parent_authorization_secret = *matched_parent_authorization_secrets.at(index_order);
        let auditor_view_allowed = *matched_auditor_flags.at(index_order);
        let funding_note_ref = *matched_funding_note_refs.at(index_order);
        let funding_note_commitment = *matched_funding_note_commitments.at(index_order);
        let funding_note_asset_id = *matched_funding_note_asset_ids.at(index_order);
        let funding_note_amount_felt = *matched_funding_note_amounts.at(index_order);
        let funding_note_owner_key = *matched_funding_note_owner_keys.at(index_order);
        let funding_note_spend_authority = *matched_funding_note_spend_authorities.at(index_order);
        let funding_note_withdraw_authority = *matched_funding_note_withdraw_authorities
            .at(index_order);
        let funding_note_blinding = *matched_funding_note_blindings.at(index_order);
        let funding_note_nonce_felt = *matched_funding_note_nonces.at(index_order);
        let funding_note_metadata_commitment = *matched_funding_note_metadata_commitments
            .at(index_order);
        let funding_authorization_r = *matched_funding_authorization_rs.at(index_order);
        let funding_authorization_s = *matched_funding_authorization_ss.at(index_order);
        let funding_nullifier = *matched_funding_nullifiers.at(index_order);
        let recipient_owner_key = *matched_recipient_owner_keys.at(index_order);
        let recipient_spend_authority = *matched_recipient_spend_authorities.at(index_order);
        let recipient_withdraw_authority = *matched_recipient_withdraw_authorities.at(index_order);
        let recipient_residual_withdraw_authority = *matched_res_withdraw_auths.at(index_order);
        let output_note_commitment = *matched_output_note_commitments.at(index_order);
        let output_note_asset_id = *matched_output_note_asset_ids.at(index_order);
        let output_note_amount_felt = *matched_output_note_amounts.at(index_order);
        let output_note_owner_key = *matched_output_note_owner_keys.at(index_order);
        let output_note_spend_authority = *matched_output_note_spend_authorities.at(index_order);
        let output_note_withdraw_authority = *matched_output_note_withdraw_authorities
            .at(index_order);
        let output_note_blinding = *matched_output_note_blindings.at(index_order);
        let output_note_nonce_felt = *matched_output_note_nonces.at(index_order);
        let output_note_metadata_commitment = *matched_output_note_metadata_commitments
            .at(index_order);
        let residual_note_flag = *matched_residual_note_flags.at(index_order);
        let residual_note_commitment = *matched_residual_note_commitments.at(index_order);
        let residual_note_asset_id = *matched_residual_note_asset_ids.at(index_order);
        let residual_note_amount_felt = *matched_residual_note_amounts.at(index_order);
        let residual_note_owner_key = *matched_residual_note_owner_keys.at(index_order);
        let residual_note_spend_authority = *matched_residual_note_spend_authorities
            .at(index_order);
        let residual_note_withdraw_authority = *matched_residual_note_withdraw_authorities
            .at(index_order);
        let residual_note_blinding = *matched_residual_note_blindings.at(index_order);
        let residual_note_nonce_felt = *matched_residual_note_nonces.at(index_order);
        let residual_note_metadata_commitment = *matched_residual_note_metadata_commitments
            .at(index_order);

        let filled_amount = felt_to_u128(filled_amount_felt);
        let limit_price = felt_to_u128(limit_price_felt);
        let order_amount = felt_to_u128(order_amount_felt);
        let min_fill = felt_to_u128(min_fill_felt);
        let funding_note_amount = felt_to_u128(funding_note_amount_felt);
        let output_note_amount = felt_to_u128(output_note_amount_felt);
        let maker_curve_point_count: usize = maker_curve_point_count_felt
            .try_into()
            .expect('CURVE_COUNT');

        assert(order_commitment != 0, 'BAD_ORDER');
        assert(filled_amount_felt != 0, 'ZERO_FILL');
        assert(order_amount_felt != 0, 'ZERO_ORDER');
        assert(min_fill_felt != 0, 'ZERO_MIN_FILL');
        assert(funding_note_commitment != 0, 'BAD_INPUT_NOTE');
        assert(output_note_commitment != 0, 'BAD_OUTPUT_NOTE');
        assert(funding_note_owner_key != 0, 'BAD_INPUT_OWNER');
        assert(funding_note_spend_authority != 0, 'BAD_INPUT_SPEND');
        assert(funding_note_withdraw_authority != 0, 'BAD_INPUT_AUTH');
        assert(funding_authorization_r != 0, 'BAD_AUTH_R');
        assert(funding_authorization_s != 0, 'BAD_AUTH_S');
        assert(recipient_owner_key != 0, 'BAD_RECIPIENT');
        assert(recipient_spend_authority != 0, 'BAD_RECIPIENT_SPEND');
        assert(recipient_withdraw_authority != 0, 'BAD_WITHDRAW_AUTH');
        assert(recipient_residual_withdraw_authority != 0, 'BAD_RES_AUTH');
        assert(output_note_owner_key != 0, 'BAD_OUTPUT_OWNER');
        assert(output_note_spend_authority != 0, 'BAD_OUTPUT_SPEND');
        assert(output_note_withdraw_authority != 0, 'BAD_OUTPUT_AUTH');
        assert(funding_note_blinding != 0, 'BAD_INPUT_BLIND');
        assert(output_note_blinding != 0, 'BAD_OUTPUT_BLIND');
        assert(funding_note_metadata_commitment != 0, 'BAD_INPUT_META');
        assert(output_note_metadata_commitment != 0, 'BAD_OUTPUT_META');
        assert(funding_nullifier != 0, 'BAD_NULLIFIER');
        assert(output_note_amount_felt != 0, 'ZERO_OUTPUT');
        assert(expiry_epoch_felt != 0, 'ZERO_EXPIRY');
        assert(expiry_epoch_felt == batch_epoch, 'EXPIRY_DOMAIN');
        assert(order_nonce_felt != 0, 'ZERO_NONCE');
        assert_parent_link(
            parent_order_commitment,
            parent_child_index,
            parent_secret_commitment,
            parent_cancel_authority,
            parent_authorization_secret,
        );
        if parent_order_commitment != 0 {
            assert(renewal_cursor < renewal_child_nullifiers.len(), 'MISSING_RENEWAL_CHILD');
            assert(
                *renewal_parent_order_commitments.at(renewal_cursor) == parent_order_commitment,
                'RENEWAL_PARENT_BIND',
            );
            assert(
                *renewal_child_nullifiers
                    .at(
                        renewal_cursor,
                    ) == renewal_child_nullifier(
                        parent_order_commitment, parent_child_index, parent_authorization_secret,
                    ),
                'RENEWAL_CHILD_BIND',
            );
            let renewal_cancel_marker = renewal_parent_cancel_marker(
                parent_secret_commitment, parent_cancel_authority,
            );
            running_renewal_root =
                assert_sparse_entry_absent(
                    running_renewal_root,
                    renewal_cancel_marker,
                    *renewal_cancel_sparse_key_lows.at(renewal_cursor),
                    *renewal_cancel_sparse_key_highs.at(renewal_cursor),
                    *renewal_cancel_sparse_path_counts.at(renewal_cursor),
                    ref renewal_cancel_path_cursor,
                    renewal_cancel_sparse_path_values.span(),
                    renewal_cancel_sparse_path_directions.span(),
                    nullifier_sparse_node_domain,
                );
            running_renewal_root =
                assert_sparse_entry_insert(
                    running_renewal_root,
                    *renewal_child_nullifiers.at(renewal_cursor),
                    *renewal_child_sparse_key_lows.at(renewal_cursor),
                    *renewal_child_sparse_key_highs.at(renewal_cursor),
                    *renewal_child_sparse_path_counts.at(renewal_cursor),
                    ref renewal_child_path_cursor,
                    renewal_child_sparse_path_values.span(),
                    renewal_child_sparse_path_directions.span(),
                    nullifier_sparse_leaf_domain,
                    nullifier_sparse_node_domain,
                );
            renewal_cursor += 1;
        }
        assert(
            order_type == ORDER_TYPE_LIMIT_BATCH || order_type == ORDER_TYPE_MAKER_CURVE,
            'BAD_ORDER_TYPE',
        );
        let (curve_total_amount, curve_capacity_at_price, curve_quote_funding_required) =
            assert_maker_curve(
            order_type,
            side,
            maker_curve_domain,
            maker_curve_commitment,
            maker_curve_point_count,
            curve_cursor,
            clearing_price_u128,
            matched_maker_curve_prices.span(),
            matched_maker_curve_base_amounts.span(),
        );
        curve_cursor += maker_curve_point_count;
        if order_type == ORDER_TYPE_MAKER_CURVE {
            assert(order_amount == curve_total_amount, 'CURVE_AMOUNT');
            assert(filled_amount <= curve_capacity_at_price, 'CURVE_OVERFILL');
            if side == ORDER_SIDE_BUY {
                assert(funding_note_amount >= curve_quote_funding_required, 'CURVE_BUY_FUNDS');
            } else {
                assert(funding_note_amount >= curve_total_amount, 'CURVE_SELL_FUNDS');
            }
        }
        assert(
            time_in_force == TIF_CURRENT_BATCH_ONLY || time_in_force == TIF_FILL_OR_KILL, 'BAD_TIF',
        );
        assert(auditor_view_allowed == 0 || auditor_view_allowed == 1, 'BAD_AUDITOR');
        assert(residual_note_flag == 0 || residual_note_flag == 1, 'BAD_RES_FLAG');
        assert(filled_amount <= order_amount, 'FILL_GT_ORDER');
        assert(filled_amount >= min_fill, 'FILL_LT_MIN');
        if time_in_force == TIF_FILL_OR_KILL {
            assert(filled_amount == order_amount, 'FOK_FILL');
        }

        let recomputed_order_commitment = order_intent_commitment(
            order_commitment_domain,
            pair_id,
            batch_id,
            side,
            order_type,
            maker_curve_commitment,
            limit_price_felt,
            order_amount_felt,
            min_fill_felt,
            time_in_force,
            expiry_epoch_felt,
            order_nonce_felt,
            parent_order_commitment,
            parent_child_index,
            parent_secret_commitment,
            parent_cancel_authority,
            parent_authorization_secret,
            funding_note_ref,
            funding_nullifier,
            recipient_owner_key,
            recipient_spend_authority,
            recipient_withdraw_authority,
            recipient_residual_withdraw_authority,
            auditor_view_allowed,
        );
        assert(order_commitment == recomputed_order_commitment, 'ORDER_BIND');

        let recomputed_funding_note_commitment = note_commitment(
            note_commitment_domain,
            funding_note_asset_id,
            funding_note_amount_felt,
            funding_note_owner_key,
            funding_note_spend_authority,
            funding_note_withdraw_authority,
            funding_note_blinding,
            funding_note_nonce_felt,
            funding_note_metadata_commitment,
        );
        assert(funding_note_commitment == recomputed_funding_note_commitment, 'INPUT_NOTE_BIND');
        assert(funding_note_ref == funding_note_commitment, 'INPUT_REF_MISMATCH');
        assert(
            funding_nullifier == note_nullifier(
                nullifier_domain, funding_note_commitment, funding_note_blinding,
            ),
            'NULLIFIER_BIND',
        );
        let recomputed_output_note_commitment = note_commitment(
            note_commitment_domain,
            output_note_asset_id,
            output_note_amount_felt,
            output_note_owner_key,
            output_note_spend_authority,
            output_note_withdraw_authority,
            output_note_blinding,
            output_note_nonce_felt,
            output_note_metadata_commitment,
        );
        assert(output_note_commitment == recomputed_output_note_commitment, 'OUTPUT_NOTE_BIND');

        assert(
            funding_note_commitment == *consumed_note_commitments.at(index_order), 'INPUT_MISMATCH',
        );
        assert(funding_nullifier == *consumed_nullifiers.at(index_order), 'NULLIFIER_MISMATCH');
        assert_note_membership(
            funding_note_commitment,
            funding_note_asset_id,
            funding_note_amount_felt,
            funding_note_withdraw_authority,
            prior_note_root,
            *note_membership_kinds.at(index_order),
            *note_membership_prefix_roots.at(index_order),
            *note_membership_batch_roots.at(index_order),
            *note_membership_path_counts.at(index_order),
            ref note_membership_path_cursor,
            note_membership_path_values.span(),
            note_membership_path_directions.span(),
            *note_membership_suffix_counts.at(index_order),
            ref note_membership_suffix_cursor,
            note_membership_suffix_roots.span(),
            state_transition_root_domain,
        );

        assert_public_output_present(
            output_note_commitment,
            output_note_asset_id,
            output_note_amount,
            output_note_withdraw_authority,
            output_note_commitments.span(),
            output_note_asset_ids.span(),
            output_note_amounts.span(),
            output_note_withdraw_authorities.span(),
        );
        assert(output_note_owner_key == recipient_owner_key, 'OUTPUT_RECIPIENT');
        assert(output_note_spend_authority == recipient_spend_authority, 'OUTPUT_SPEND_AUTH');
        assert(
            output_note_withdraw_authority == recipient_withdraw_authority, 'OUTPUT_WITHDRAW_AUTH',
        );

        let expected_residual_amount = if side == ORDER_SIDE_BUY {
            assert(limit_price >= clearing_price_u128, 'BUY_LIMIT');
            assert(funding_note_asset_id == quote_asset_id, 'BUY_INPUT_ASSET');
            assert(output_note_asset_id == base_asset_id, 'BUY_OUTPUT_ASSET');

            let spend_amount = filled_amount * clearing_price_u128;
            assert(funding_note_amount >= spend_amount, 'BUY_FUNDS');
            let fee_amount = filled_amount * PROTOCOL_FEE_BPS / FEE_BPS_DENOMINATOR;
            total_buy_base = total_buy_base + filled_amount;
            expected_base_fee = expected_base_fee + fee_amount;
            funding_note_amount - spend_amount
        } else {
            assert(side == ORDER_SIDE_SELL, 'BAD_SIDE');
            assert(limit_price <= clearing_price_u128, 'SELL_LIMIT');
            assert(funding_note_asset_id == base_asset_id, 'SELL_INPUT_ASSET');
            assert(output_note_asset_id == quote_asset_id, 'SELL_OUTPUT_ASSET');
            assert(funding_note_amount >= filled_amount, 'SELL_FUNDS');

            let gross_quote = filled_amount * clearing_price_u128;
            let fee_amount = gross_quote * PROTOCOL_FEE_BPS / FEE_BPS_DENOMINATOR;
            total_sell_base = total_sell_base + filled_amount;
            expected_quote_fee = expected_quote_fee + fee_amount;
            funding_note_amount - filled_amount
        };

        if expected_residual_amount == 0 {
            assert_absent_residual(
                residual_note_flag,
                residual_note_commitment,
                residual_note_asset_id,
                residual_note_amount_felt,
                residual_note_owner_key,
                residual_note_spend_authority,
                residual_note_withdraw_authority,
                residual_note_blinding,
                residual_note_nonce_felt,
                residual_note_metadata_commitment,
            );
        } else {
            assert(residual_note_flag == 1, 'RES_FLAG_MISSING');
            let expected_residual_asset_id = if side == ORDER_SIDE_BUY {
                quote_asset_id
            } else {
                base_asset_id
            };
            assert(residual_note_asset_id == expected_residual_asset_id, 'BAD_RES_ASSET');
            assert(residual_note_owner_key == recipient_owner_key, 'RES_OWNER');
            assert(residual_note_spend_authority == recipient_spend_authority, 'RES_SPEND_AUTH');
            assert(
                residual_note_withdraw_authority == recipient_residual_withdraw_authority,
                'RES_AUTH',
            );
            assert(residual_note_blinding != 0, 'BAD_RES_BLIND');
            assert(residual_note_nonce_felt != 0, 'BAD_RES_NONCE');
            assert(residual_note_metadata_commitment != 0, 'BAD_RES_META');

            let recomputed_residual_note_commitment = note_commitment(
                note_commitment_domain,
                residual_note_asset_id,
                residual_note_amount_felt,
                residual_note_owner_key,
                residual_note_spend_authority,
                residual_note_withdraw_authority,
                residual_note_blinding,
                residual_note_nonce_felt,
                residual_note_metadata_commitment,
            );
            assert(
                residual_note_commitment == recomputed_residual_note_commitment, 'RES_NOTE_BIND',
            );
            assert_public_output_present(
                residual_note_commitment,
                residual_note_asset_id,
                felt_to_u128(residual_note_amount_felt),
                residual_note_withdraw_authority,
                output_note_commitments.span(),
                output_note_asset_ids.span(),
                output_note_amounts.span(),
                output_note_withdraw_authorities.span(),
            );
        }

        index_order += 1;
    }
    assert(renewal_cursor == renewal_child_nullifiers.len(), 'RENEWAL_CURSOR');
    assert(
        renewal_child_path_cursor == renewal_child_sparse_path_values.len(), 'RENEWAL_PATH_CURSOR',
    );
    assert(
        renewal_child_path_cursor == renewal_child_sparse_path_directions.len(),
        'RENEWAL_DIR_CURSOR',
    );
    assert(
        renewal_cancel_path_cursor == renewal_cancel_sparse_path_values.len(),
        'RENEWAL_CANCEL_CURSOR',
    );
    assert(
        renewal_cancel_path_cursor == renewal_cancel_sparse_path_directions.len(),
        'RENEWAL_CANCEL_DIR',
    );
    assert(note_membership_path_cursor == note_membership_path_values.len(), 'INPUT_PATH_CURSOR');
    assert(
        note_membership_path_cursor == note_membership_path_directions.len(), 'INPUT_DIR_CURSOR',
    );
    assert(
        note_membership_suffix_cursor == note_membership_suffix_roots.len(), 'INPUT_SUFFIX_CURSOR',
    );

    assert(total_buy_base == total_sell_base, 'BASE_IMBALANCE');
    assert_netted_public_outputs(
        base_asset_id,
        quote_asset_id,
        clearing_price_u128,
        matched_fill_amounts.span(),
        matched_sides.span(),
        matched_funding_note_amounts.span(),
        matched_output_note_commitments.span(),
        matched_residual_note_flags.span(),
        matched_residual_note_commitments.span(),
        output_note_commitments.span(),
        output_note_amounts.span(),
    );

    let consumed_note_root = single_field_root(
        consumed_note_root_domain, consumed_note_commitments.span(),
    );
    let consumed_nullifier_root = single_field_root(
        consumed_nullifier_root_domain, consumed_nullifiers.span(),
    );
    let renewal_child_root = single_field_root(
        renewal_child_root_domain, renewal_child_nullifiers.span(),
    );
    let output_note_root = output_note_merkle_root(
        output_bundle_ref,
        output_note_commitments.span(),
        output_note_asset_ids.span(),
        output_note_amounts.span(),
        output_note_withdraw_authorities.span(),
    );
    assert_output_recovery_bundle(
        note_commitment_domain,
        output_bundle_ref,
        batch_id,
        output_note_root,
        output_note_commitments.span(),
        output_note_asset_ids.span(),
        output_note_amounts.span(),
        output_note_withdraw_authorities.span(),
        output_note_owner_keys.span(),
        output_note_spend_authorities.span(),
        output_note_blindings.span(),
        output_note_nonces.span(),
        output_note_metadata_commitments.span(),
        output_recovery_key_tags.span(),
        output_recovery_auth_tags.span(),
        output_recovery_ciphertext_fields.span(),
        output_recovery_dummy_commitments.span(),
    );
    let fee_root = protocol_fee_root(
        fee_root_domain, base_asset_id, quote_asset_id, expected_base_fee, expected_quote_fee,
    );
    let new_note_root = state_transition_root(
        state_transition_root_domain, prior_note_root, output_note_root,
    );
    let new_nullifier_root = assert_sparse_nullifier_updates(
        prior_nullifier_root,
        consumed_nullifiers.span(),
        nullifier_sparse_key_lows.span(),
        nullifier_sparse_key_highs.span(),
        nullifier_sparse_path_counts.span(),
        nullifier_sparse_path_values.span(),
        nullifier_sparse_path_directions.span(),
        nullifier_sparse_leaf_domain,
        nullifier_sparse_node_domain,
    );
    let new_renewal_root = running_renewal_root;
    let new_fee_root = state_transition_root(
        state_transition_root_domain, prior_fee_root, fee_root,
    );

    let recomputed_public_settlement = public_settlement_commitment(
        public_settlement_domain,
        batch_id,
        pair_id,
        batch_epoch,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        prior_note_root,
        prior_nullifier_root,
        prior_renewal_root,
        prior_fee_root,
        consumed_note_root,
        consumed_nullifier_root,
        renewal_child_root,
        output_note_root,
        fee_root,
        new_note_root,
        new_nullifier_root,
        new_renewal_root,
        new_fee_root,
    );
    assert(recomputed_public_settlement == transcript_commitment, 'PUBLIC_SETTLEMENT_BIND');

    assert(curve_cursor == total_curve_points, 'CURVE_CURSOR');
    assert(index == data.len(), 'TRAILING_INPUT');

    transcript_commitment
}

pub fn verify_admission_statement(data: Span<felt252>) -> (felt252, felt252, felt252) {
    let mut index: usize = 0;
    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_ADMISSION, 'BAD_ADMIT_TYPE');

    let settlement_payload = read_vector(data, ref index);
    let order_commitment_root = settlement_order_commitment_root(settlement_payload.span());
    let note_commitment_domain = settlement_note_commitment_domain(settlement_payload.span());
    let spend_authority_domain = settlement_spend_authority_domain(settlement_payload.span());
    let nullifier_domain = settlement_nullifier_domain(settlement_payload.span());
    let order_commitment_domain = settlement_order_commitment_domain(settlement_payload.span());
    let maker_curve_domain = settlement_maker_curve_domain(settlement_payload.span());
    let batch_id = settlement_batch_id(settlement_payload.span());
    let pair_id = settlement_pair_id(settlement_payload.span());
    let batch_epoch = settlement_batch_epoch(settlement_payload.span());
    let base_asset_id = settlement_base_asset_id(settlement_payload.span());
    let quote_asset_id = settlement_quote_asset_id(settlement_payload.span());

    let order_commitments = read_vector(data, ref index);
    let sides = read_vector(data, ref index);
    let order_types = read_vector(data, ref index);
    let maker_curve_commitments = read_vector(data, ref index);
    let maker_curve_point_counts = read_vector(data, ref index);
    let maker_curve_prices = read_vector(data, ref index);
    let maker_curve_base_amounts = read_vector(data, ref index);
    let limit_prices = read_vector(data, ref index);
    let order_amounts = read_vector(data, ref index);
    let min_fills = read_vector(data, ref index);
    let time_in_force = read_vector(data, ref index);
    let expiry_epochs = read_vector(data, ref index);
    let order_nonces = read_vector(data, ref index);
    let parent_order_commitments = read_vector(data, ref index);
    let parent_child_indexes = read_vector(data, ref index);
    let parent_secret_commitments = read_vector(data, ref index);
    let parent_cancel_authorities = read_vector(data, ref index);
    let parent_authorization_secrets = read_vector(data, ref index);
    let auditor_flags = read_vector(data, ref index);
    let funding_note_refs = read_vector(data, ref index);
    let funding_note_commitments = read_vector(data, ref index);
    let funding_note_asset_ids = read_vector(data, ref index);
    let funding_note_amounts = read_vector(data, ref index);
    let funding_note_owner_keys = read_vector(data, ref index);
    let funding_note_spend_authorities = read_vector(data, ref index);
    let funding_note_withdraw_authorities = read_vector(data, ref index);
    let funding_note_blindings = read_vector(data, ref index);
    let funding_note_nonces = read_vector(data, ref index);
    let funding_note_metadata_commitments = read_vector(data, ref index);
    let funding_authorization_rs = read_vector(data, ref index);
    let funding_authorization_ss = read_vector(data, ref index);
    let funding_nullifiers = read_vector(data, ref index);
    let recipient_owner_keys = read_vector(data, ref index);
    let recipient_spend_authorities = read_vector(data, ref index);
    let recipient_withdraw_authorities = read_vector(data, ref index);
    let res_auths = read_vector(data, ref index);
    let res_auths_span = res_auths.span();

    assert_all_lengths_match(
        order_commitments.len(),
        array![
            sides.len().into(), order_types.len().into(), maker_curve_commitments.len().into(),
            maker_curve_point_counts.len().into(), limit_prices.len().into(),
            order_amounts.len().into(), min_fills.len().into(), time_in_force.len().into(),
            expiry_epochs.len().into(), order_nonces.len().into(), auditor_flags.len().into(),
            parent_order_commitments.len().into(), parent_child_indexes.len().into(),
            parent_secret_commitments.len().into(), parent_cancel_authorities.len().into(),
            parent_authorization_secrets.len().into(), funding_note_refs.len().into(),
            funding_note_commitments.len().into(), funding_note_asset_ids.len().into(),
            funding_note_amounts.len().into(), funding_note_owner_keys.len().into(),
            funding_note_spend_authorities.len().into(),
            funding_note_withdraw_authorities.len().into(), funding_note_blindings.len().into(),
            funding_note_nonces.len().into(), funding_note_metadata_commitments.len().into(),
            funding_authorization_rs.len().into(), funding_authorization_ss.len().into(),
            funding_nullifiers.len().into(), recipient_owner_keys.len().into(),
            recipient_spend_authorities.len().into(), recipient_withdraw_authorities.len().into(),
            res_auths_span.len().into(),
        ]
            .span(),
        'BAD_ADMISSION_LEN',
    );
    let total_curve_points = sum_curve_point_counts(maker_curve_point_counts.span());
    assert(maker_curve_prices.len() == total_curve_points, 'BAD_ADMISSION_CURVES');
    assert(maker_curve_base_amounts.len() == total_curve_points, 'BAD_ADMISSION_CURVES');
    assert_unique(order_commitments.span(), 'DUP_ADMISSION_ORDER');
    assert(
        ordered_commitment_root(order_commitments.span()) == order_commitment_root,
        'ADMISSION_ROOT_BIND',
    );
    if order_commitments.len() != 0 {
        assert_auction_order_preimages(
            0,
            order_commitments.span(),
            sides.span(),
            order_types.span(),
            maker_curve_commitments.span(),
            maker_curve_point_counts.span(),
            maker_curve_prices.span(),
            maker_curve_base_amounts.span(),
            limit_prices.span(),
            order_amounts.span(),
            min_fills.span(),
            time_in_force.span(),
            expiry_epochs.span(),
            order_nonces.span(),
            parent_order_commitments.span(),
            parent_child_indexes.span(),
            parent_secret_commitments.span(),
            parent_cancel_authorities.span(),
            parent_authorization_secrets.span(),
            auditor_flags.span(),
            funding_note_refs.span(),
            funding_note_commitments.span(),
            funding_note_asset_ids.span(),
            funding_note_amounts.span(),
            funding_note_owner_keys.span(),
            funding_note_spend_authorities.span(),
            funding_note_withdraw_authorities.span(),
            funding_note_blindings.span(),
            funding_note_nonces.span(),
            funding_note_metadata_commitments.span(),
            funding_authorization_rs.span(),
            funding_authorization_ss.span(),
            funding_nullifiers.span(),
            recipient_owner_keys.span(),
            recipient_spend_authorities.span(),
            recipient_withdraw_authorities.span(),
            res_auths_span,
            note_commitment_domain,
            spend_authority_domain,
            nullifier_domain,
            order_commitment_domain,
            maker_curve_domain,
            batch_id,
            pair_id,
            batch_epoch,
            base_asset_id,
            quote_asset_id,
        );
    }
    assert(index == data.len(), 'TRAILING_ADMISSION_INPUT');
    let admission_root = admission_summary_root(
        order_commitments.span(),
        sides.span(),
        order_types.span(),
        maker_curve_commitments.span(),
        limit_prices.span(),
        order_amounts.span(),
        min_fills.span(),
        time_in_force.span(),
        funding_note_amounts.span(),
        funding_note_owner_keys.span(),
    );
    (batch_id, order_commitment_root, admission_root)
}

pub fn verify_auction_result_statement(
    data: Span<felt252>,
) -> (felt252, felt252, felt252, felt252) {
    let mut index: usize = 0;
    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_AUCTION_RESULT, 'BAD_AUCRES_TYPE');

    let settlement_payload = read_vector(data, ref index);
    let transcript_commitment = settlement_transcript_commitment(settlement_payload.span());
    let order_commitment_root = settlement_order_commitment_root(settlement_payload.span());
    let clearing_price = settlement_clearing_price(settlement_payload.span());
    let maker_curve_domain = settlement_maker_curve_domain(settlement_payload.span());
    let batch_id = settlement_batch_id(settlement_payload.span());
    let matched_order_commitments = settlement_matched_order_commitments(settlement_payload.span());
    let matched_fill_amounts = settlement_matched_fill_amounts(settlement_payload.span());
    let clearing_price_u128 = felt_to_u128(clearing_price);
    let admission_root = read_next(data, ref index);

    let order_commitments = read_vector(data, ref index);
    let sides = read_vector(data, ref index);
    let order_types = read_vector(data, ref index);
    let maker_curve_commitments = read_vector(data, ref index);
    let maker_curve_point_counts = read_vector(data, ref index);
    let maker_curve_prices = read_vector(data, ref index);
    let maker_curve_base_amounts = read_vector(data, ref index);
    let limit_prices = read_vector(data, ref index);
    let order_amounts = read_vector(data, ref index);
    let min_fills = read_vector(data, ref index);
    let time_in_force = read_vector(data, ref index);
    let funding_note_amounts = read_vector(data, ref index);
    let funding_note_owner_keys = read_vector(data, ref index);
    let allocation_fill_amounts = read_vector(data, ref index);
    let privacy_gate_enforced = read_next(data, ref index);
    let privacy_min_batch_base_liquidity = read_next(data, ref index);
    let privacy_min_batch_participants = read_next(data, ref index);
    let privacy_min_eligible_orders = read_next(data, ref index);
    let privacy_max_single_order_fill_bps = read_next(data, ref index);
    let privacy_max_single_owner_fill_bps = read_next(data, ref index);
    let privacy_min_maker_participants = read_next(data, ref index);
    let privacy_max_maker_fill_bps = read_next(data, ref index);

    assert_all_lengths_match(
        order_commitments.len(),
        array![
            sides.len().into(), order_types.len().into(), maker_curve_commitments.len().into(),
            maker_curve_point_counts.len().into(), limit_prices.len().into(),
            order_amounts.len().into(), min_fills.len().into(), time_in_force.len().into(),
            funding_note_amounts.len().into(), funding_note_owner_keys.len().into(),
            allocation_fill_amounts.len().into(),
        ]
            .span(),
        'BAD_AUCRES_LEN',
    );
    let total_curve_points = sum_curve_point_counts(maker_curve_point_counts.span());
    assert(maker_curve_prices.len() == total_curve_points, 'BAD_AUCRES_CURVES');
    assert(maker_curve_base_amounts.len() == total_curve_points, 'BAD_AUCRES_CURVES');
    assert_unique(order_commitments.span(), 'DUP_AUCRES_ORDER');
    assert(
        ordered_commitment_root(order_commitments.span()) == order_commitment_root,
        'AUCRES_ORDER_ROOT',
    );
    assert(
        admission_summary_root(
            order_commitments.span(),
            sides.span(),
            order_types.span(),
            maker_curve_commitments.span(),
            limit_prices.span(),
            order_amounts.span(),
            min_fills.span(),
            time_in_force.span(),
            funding_note_amounts.span(),
            funding_note_owner_keys.span(),
        ) == admission_root,
        'AUCRES_ADMISSION_ROOT',
    );
    assert_curve_commitments_for_summary(
        clearing_price_u128,
        sides.span(),
        order_types.span(),
        maker_curve_domain,
        maker_curve_commitments.span(),
        maker_curve_point_counts.span(),
        maker_curve_prices.span(),
        maker_curve_base_amounts.span(),
    );
    if matched_order_commitments.len() == 0 {
        assert_all_zero(allocation_fill_amounts.span(), 'NOOP_ALLOC');
        if privacy_gate_enforced == 1 {
            assert_privacy_gate_failure(
                clearing_price_u128,
                sides.span(),
                order_types.span(),
                maker_curve_point_counts.span(),
                maker_curve_prices.span(),
                maker_curve_base_amounts.span(),
                limit_prices.span(),
                order_amounts.span(),
                min_fills.span(),
                time_in_force.span(),
                funding_note_amounts.span(),
                funding_note_owner_keys.span(),
                privacy_min_batch_base_liquidity,
                privacy_min_batch_participants,
                privacy_min_eligible_orders,
                privacy_max_single_order_fill_bps,
                privacy_max_single_owner_fill_bps,
                privacy_min_maker_participants,
                privacy_max_maker_fill_bps,
            );
        } else {
            assert_no_executable_auction(
                sides.span(),
                order_types.span(),
                maker_curve_point_counts.span(),
                maker_curve_prices.span(),
                maker_curve_base_amounts.span(),
                limit_prices.span(),
                order_amounts.span(),
                min_fills.span(),
                time_in_force.span(),
                funding_note_amounts.span(),
            );
        }
    } else {
        assert(privacy_gate_enforced == 1, 'MATCH_PRIVACY_GATE');
        assert_auction_allocation(
            clearing_price_u128,
            order_commitments.span(),
            sides.span(),
            order_types.span(),
            maker_curve_point_counts.span(),
            maker_curve_prices.span(),
            maker_curve_base_amounts.span(),
            limit_prices.span(),
            order_amounts.span(),
            min_fills.span(),
            time_in_force.span(),
            funding_note_amounts.span(),
            allocation_fill_amounts.span(),
            matched_order_commitments.span(),
            matched_fill_amounts.span(),
        );
        assert_best_clearing_price(
            clearing_price_u128,
            sides.span(),
            order_types.span(),
            maker_curve_point_counts.span(),
            maker_curve_prices.span(),
            maker_curve_base_amounts.span(),
            limit_prices.span(),
            order_amounts.span(),
            min_fills.span(),
            time_in_force.span(),
            funding_note_amounts.span(),
        );
        assert_privacy_gate_success(
            clearing_price_u128,
            sides.span(),
            order_types.span(),
            maker_curve_point_counts.span(),
            maker_curve_prices.span(),
            maker_curve_base_amounts.span(),
            limit_prices.span(),
            order_amounts.span(),
            min_fills.span(),
            time_in_force.span(),
            funding_note_amounts.span(),
            funding_note_owner_keys.span(),
            privacy_min_batch_base_liquidity,
            privacy_min_batch_participants,
            privacy_min_eligible_orders,
            privacy_max_single_order_fill_bps,
            privacy_max_single_owner_fill_bps,
            privacy_min_maker_participants,
            privacy_max_maker_fill_bps,
        );
    }
    assert(index == data.len(), 'TRAILING_AUCRES_INPUT');
    (batch_id, order_commitment_root, admission_root, transcript_commitment)
}

fn settlement_clearing_price(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 15, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(15)
}

fn settlement_transcript_commitment(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 12, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(12)
}

fn settlement_order_commitment_root(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 10, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(10)
}

fn settlement_note_commitment_domain(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 1, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(1)
}

fn settlement_spend_authority_domain(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 2, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(2)
}

fn settlement_nullifier_domain(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 3, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(3)
}

fn settlement_order_commitment_domain(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 4, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(4)
}

fn settlement_maker_curve_domain(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 5, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(5)
}

fn settlement_batch_id(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 7, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(7)
}

fn settlement_pair_id(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 8, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(8)
}

fn settlement_batch_epoch(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 9, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(9)
}

fn settlement_base_asset_id(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 13, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(13)
}

fn settlement_quote_asset_id(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 14, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(14)
}

fn settlement_matched_order_commitments(settlement_payload: Span<felt252>) -> Array<felt252> {
    assert(settlement_payload.len() > 30, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    let mut index: usize = 30;
    read_vector(settlement_payload, ref index)
}

fn settlement_matched_fill_amounts(settlement_payload: Span<felt252>) -> Array<felt252> {
    assert(settlement_payload.len() > 30, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    let mut index: usize = 30;
    let _matched_order_commitments = read_vector(settlement_payload, ref index);
    read_vector(settlement_payload, ref index)
}

fn assert_auction_order_preimages(
    clearing_price: u128,
    order_commitments: Span<felt252>,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_commitments: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    expiry_epochs: Span<felt252>,
    order_nonces: Span<felt252>,
    parent_order_commitments: Span<felt252>,
    parent_child_indexes: Span<felt252>,
    parent_secret_commitments: Span<felt252>,
    parent_cancel_authorities: Span<felt252>,
    parent_authorization_secrets: Span<felt252>,
    auditor_flags: Span<felt252>,
    funding_note_refs: Span<felt252>,
    funding_note_commitments: Span<felt252>,
    funding_note_asset_ids: Span<felt252>,
    funding_note_amounts: Span<felt252>,
    funding_note_owner_keys: Span<felt252>,
    funding_note_spend_authorities: Span<felt252>,
    funding_note_withdraw_authorities: Span<felt252>,
    funding_note_blindings: Span<felt252>,
    funding_note_nonces: Span<felt252>,
    funding_note_metadata_commitments: Span<felt252>,
    funding_authorization_rs: Span<felt252>,
    funding_authorization_ss: Span<felt252>,
    funding_nullifiers: Span<felt252>,
    recipient_owner_keys: Span<felt252>,
    recipient_spend_authorities: Span<felt252>,
    recipient_withdraw_authorities: Span<felt252>,
    residual_withdraw_authorities: Span<felt252>,
    note_commitment_domain: felt252,
    spend_authority_domain: felt252,
    nullifier_domain: felt252,
    order_commitment_domain: felt252,
    maker_curve_domain: felt252,
    batch_id: felt252,
    pair_id: felt252,
    batch_epoch: felt252,
    base_asset_id: felt252,
    quote_asset_id: felt252,
) {
    let mut index = 0;
    let mut curve_cursor = 0;
    while index < order_commitments.len() {
        let order_commitment = *order_commitments.at(index);
        let side = *sides.at(index);
        let order_type = *order_types.at(index);
        let limit_price = *limit_prices.at(index);
        let order_amount = *order_amounts.at(index);
        let min_fill = *min_fills.at(index);
        let tif = *time_in_force.at(index);
        let expiry_epoch = *expiry_epochs.at(index);
        let order_nonce = *order_nonces.at(index);
        let parent_order_commitment = *parent_order_commitments.at(index);
        let parent_child_index = *parent_child_indexes.at(index);
        let parent_secret_commitment = *parent_secret_commitments.at(index);
        let parent_cancel_authority = *parent_cancel_authorities.at(index);
        let parent_authorization_secret = *parent_authorization_secrets.at(index);
        let auditor_view_allowed = *auditor_flags.at(index);
        let funding_note_ref = *funding_note_refs.at(index);
        let funding_note_commitment = *funding_note_commitments.at(index);
        let funding_note_asset_id = *funding_note_asset_ids.at(index);
        let funding_note_amount = *funding_note_amounts.at(index);
        let funding_note_owner_key = *funding_note_owner_keys.at(index);
        let funding_note_spend_authority = *funding_note_spend_authorities.at(index);
        let funding_note_withdraw_authority = *funding_note_withdraw_authorities.at(index);
        let funding_note_blinding = *funding_note_blindings.at(index);
        let funding_note_nonce = *funding_note_nonces.at(index);
        let funding_note_metadata_commitment = *funding_note_metadata_commitments.at(index);
        let funding_authorization_r = *funding_authorization_rs.at(index);
        let funding_authorization_s = *funding_authorization_ss.at(index);
        let funding_nullifier = *funding_nullifiers.at(index);
        let recipient_owner_key = *recipient_owner_keys.at(index);
        let recipient_spend_authority = *recipient_spend_authorities.at(index);
        let recipient_withdraw_authority = *recipient_withdraw_authorities.at(index);
        let recipient_residual_withdraw_authority = *residual_withdraw_authorities.at(index);
        let point_count: usize = (*maker_curve_point_counts.at(index))
            .try_into()
            .expect('CURVE_COUNT');

        assert(order_commitment != 0, 'BAD_AUCTION_ORDER');
        assert(side == ORDER_SIDE_BUY || side == ORDER_SIDE_SELL, 'BAD_SIDE');
        assert(
            order_type == ORDER_TYPE_LIMIT_BATCH
                || order_type == ORDER_TYPE_MAKER_CURVE
                || order_type == ORDER_TYPE_HEARTBEAT_COVER,
            'BAD_ORDER_TYPE',
        );
        assert(limit_price != 0, 'BAD_LIMIT');
        assert(order_amount != 0, 'BAD_AMOUNT');
        assert(min_fill != 0, 'BAD_MIN_FILL');
        assert(felt_to_u128(min_fill) <= felt_to_u128(order_amount), 'MIN_FILL_GT_AMOUNT');
        assert(tif == TIF_CURRENT_BATCH_ONLY || tif == TIF_FILL_OR_KILL, 'BAD_TIF');
        if tif == TIF_FILL_OR_KILL {
            assert(min_fill == order_amount, 'FOK_MIN_FILL');
        }
        assert(expiry_epoch != 0, 'BAD_EXPIRY');
        assert(expiry_epoch == batch_epoch, 'AUCTION_EXPIRY_DOMAIN');
        assert(order_nonce != 0, 'BAD_NONCE');
        assert_parent_link(
            parent_order_commitment,
            parent_child_index,
            parent_secret_commitment,
            parent_cancel_authority,
            parent_authorization_secret,
        );
        assert(auditor_view_allowed == 0 || auditor_view_allowed == 1, 'BAD_AUDITOR');
        assert(recipient_owner_key != 0, 'BAD_RECIPIENT');
        assert(recipient_spend_authority != 0, 'BAD_RECIPIENT_SPEND');
        assert(recipient_withdraw_authority != 0, 'BAD_RECIPIENT_AUTH');
        assert(recipient_residual_withdraw_authority != 0, 'BAD_RES_AUTH');
        let (curve_total_amount, _curve_capacity_at_price, curve_quote_funding_required) =
            assert_maker_curve(
            order_type,
            side,
            maker_curve_domain,
            *maker_curve_commitments.at(index),
            point_count,
            curve_cursor,
            clearing_price,
            maker_curve_prices,
            maker_curve_base_amounts,
        );
        if order_type == ORDER_TYPE_MAKER_CURVE {
            assert(order_amount == curve_total_amount.into(), 'CURVE_AMOUNT');
            if side == ORDER_SIDE_BUY {
                assert(
                    felt_to_u128(funding_note_amount) >= curve_quote_funding_required,
                    'CURVE_BUY_FUNDS',
                );
            } else {
                assert(felt_to_u128(funding_note_amount) >= curve_total_amount, 'CURVE_SELL_FUNDS');
            }
        }

        if order_type != ORDER_TYPE_HEARTBEAT_COVER {
            assert(funding_note_ref != 0, 'BAD_FUNDING_REF');
            assert(funding_note_commitment != 0, 'BAD_FUNDING_NOTE');
            assert(funding_note_owner_key != 0, 'BAD_FUNDING_OWNER');
            assert(funding_note_spend_authority != 0, 'BAD_FUNDING_SPEND');
            assert(funding_note_withdraw_authority != 0, 'BAD_FUNDING_AUTH');
            assert(funding_note_blinding != 0, 'BAD_FUNDING_BLIND');
            assert(funding_note_metadata_commitment != 0, 'BAD_FUNDING_META');
            assert(funding_authorization_r != 0, 'BAD_AUTH_R');
            assert(funding_authorization_s != 0, 'BAD_AUTH_S');
            assert(
                check_ecdsa_signature(
                    order_commitment,
                    funding_note_spend_authority,
                    funding_authorization_r,
                    funding_authorization_s,
                ),
                'BAD_AUTH_SIG',
            );
            assert(funding_nullifier != 0, 'BAD_NULLIFIER');
            assert(funding_note_amount != 0, 'BAD_FUNDS');
            if side == ORDER_SIDE_BUY {
                assert(funding_note_asset_id == quote_asset_id, 'BUY_INPUT_ASSET');
            } else {
                assert(funding_note_asset_id == base_asset_id, 'SELL_INPUT_ASSET');
            }
        }
        let recomputed_order_commitment = order_intent_commitment(
            order_commitment_domain,
            pair_id,
            batch_id,
            side,
            order_type,
            *maker_curve_commitments.at(index),
            limit_price,
            order_amount,
            min_fill,
            tif,
            expiry_epoch,
            order_nonce,
            parent_order_commitment,
            parent_child_index,
            parent_secret_commitment,
            parent_cancel_authority,
            parent_authorization_secret,
            funding_note_ref,
            funding_nullifier,
            recipient_owner_key,
            recipient_spend_authority,
            recipient_withdraw_authority,
            recipient_residual_withdraw_authority,
            auditor_view_allowed,
        );
        assert(order_commitment == recomputed_order_commitment, 'AUCTION_ORDER_BIND');

        if order_type != ORDER_TYPE_HEARTBEAT_COVER {
            let recomputed_funding_note_commitment = note_commitment(
                note_commitment_domain,
                funding_note_asset_id,
                funding_note_amount,
                funding_note_owner_key,
                funding_note_spend_authority,
                funding_note_withdraw_authority,
                funding_note_blinding,
                funding_note_nonce,
                funding_note_metadata_commitment,
            );
            assert(
                funding_note_commitment == recomputed_funding_note_commitment, 'AUCTION_NOTE_BIND',
            );
            assert(funding_note_ref == funding_note_commitment, 'AUCTION_REF_BIND');
            assert(
                funding_nullifier == note_nullifier(
                    nullifier_domain, funding_note_commitment, funding_note_blinding,
                ),
                'AUCTION_NULL_BIND',
            );
        }
        curve_cursor += point_count;
        index += 1;
    }
    assert(curve_cursor == maker_curve_prices.len(), 'AUCTION_CURVE_CURSOR');
}

fn assert_auction_allocation(
    clearing_price: u128,
    order_commitments: Span<felt252>,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
    allocation_fill_amounts: Span<felt252>,
    matched_order_commitments: Span<felt252>,
    matched_fill_amounts: Span<felt252>,
) {
    let active_flags = stable_active_flags(
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    let mut index = 0;
    let mut matched_index = 0;
    let mut total_buy_fill: u128 = 0;
    let mut total_sell_fill: u128 = 0;

    while index < order_commitments.len() {
        let fill = felt_to_u128(*allocation_fill_amounts.at(index));
        let expected_fill = expected_fill_with_active_flags(
            index,
            active_flags.span(),
            clearing_price,
            sides,
            order_types,
            maker_curve_point_counts,
            maker_curve_prices,
            maker_curve_base_amounts,
            limit_prices,
            order_amounts,
            min_fills,
            time_in_force,
            funding_note_amounts,
        );
        assert(fill == expected_fill, 'ALLOCATION_PRIORITY');
        if fill != 0 {
            assert(fill >= felt_to_u128(*min_fills.at(index)), 'ALLOCATION_MIN_FILL');
            if *time_in_force.at(index) == TIF_FILL_OR_KILL {
                assert(fill == felt_to_u128(*order_amounts.at(index)), 'ALLOCATION_FOK');
            }
            assert(matched_index < matched_order_commitments.len(), 'MATCHED_EOF');
            assert(
                *matched_order_commitments.at(matched_index) == *order_commitments.at(index),
                'MATCHED_ORDER_BIND',
            );
            assert(
                *matched_fill_amounts.at(matched_index) == *allocation_fill_amounts.at(index),
                'MATCHED_FILL_BIND',
            );
            matched_index += 1;
        }
        if *sides.at(index) == ORDER_SIDE_BUY {
            total_buy_fill = total_buy_fill + fill;
        } else {
            total_sell_fill = total_sell_fill + fill;
        }
        index += 1;
    }

    assert(matched_index == matched_order_commitments.len(), 'UNBOUND_MATCHED_ORDER');
    assert(total_buy_fill == total_sell_fill, 'ALLOCATION_IMBALANCE');
    let (max_matched, _imbalance) = auction_score_at_price(
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    assert(total_buy_fill == max_matched, 'UNDERFILLED_AUCTION');
}

fn stable_active_flags(
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> Array<felt252> {
    let mut active_flags = initial_active_flags(
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    let mut round = 0;
    loop {
        if round >= sides.len() {
            break;
        }
        let next_flags = next_active_flags(
            active_flags.span(),
            clearing_price,
            sides,
            order_types,
            maker_curve_point_counts,
            maker_curve_prices,
            maker_curve_base_amounts,
            limit_prices,
            order_amounts,
            min_fills,
            time_in_force,
            funding_note_amounts,
        );
        let changed = active_flags_changed(active_flags.span(), next_flags.span());
        active_flags = next_flags;
        if changed == 0 {
            break;
        }
        round += 1;
    }
    active_flags
}

fn initial_active_flags(
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> Array<felt252> {
    let mut flags = array![];
    let mut index = 0;
    while index < sides.len() {
        let max_fill = max_fill_at_candidate(
            index,
            clearing_price,
            *sides.at(index),
            *order_types.at(index),
            maker_curve_point_counts,
            maker_curve_prices,
            maker_curve_base_amounts,
            *limit_prices.at(index),
            *order_amounts.at(index),
            *min_fills.at(index),
            *time_in_force.at(index),
            *funding_note_amounts.at(index),
        );
        if max_fill == 0 {
            flags.append(0);
        } else {
            flags.append(1);
        }
        index += 1;
    }
    flags
}

fn next_active_flags(
    active_flags: Span<felt252>,
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> Array<felt252> {
    let mut next = array![];
    let mut index = 0;
    while index < active_flags.len() {
        if *active_flags.at(index) == 0 {
            next.append(0);
        } else {
            let fill = expected_fill_with_active_flags(
                index,
                active_flags,
                clearing_price,
                sides,
                order_types,
                maker_curve_point_counts,
                maker_curve_prices,
                maker_curve_base_amounts,
                limit_prices,
                order_amounts,
                min_fills,
                time_in_force,
                funding_note_amounts,
            );
            if fill == 0 {
                next.append(1);
            } else {
                let min_fill = felt_to_u128(*min_fills.at(index));
                let order_amount = felt_to_u128(*order_amounts.at(index));
                if fill < min_fill {
                    next.append(0);
                } else {
                    if *time_in_force.at(index) == TIF_FILL_OR_KILL && fill < order_amount {
                        next.append(0);
                    } else {
                        next.append(1);
                    }
                }
            }
        }
        index += 1;
    }
    next
}

fn active_flags_changed(left: Span<felt252>, right: Span<felt252>) -> felt252 {
    assert(left.len() == right.len(), 'BAD_ACTIVE_LEN');
    let mut index = 0;
    while index < left.len() {
        if *left.at(index) != *right.at(index) {
            return 1;
        }
        index += 1;
    }
    0
}

fn expected_fill_with_active_flags(
    target_index: usize,
    active_flags: Span<felt252>,
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> u128 {
    if *active_flags.at(target_index) == 0 {
        return 0;
    }
    let target_side = *sides.at(target_index);
    let max_fill = max_fill_at_candidate(
        target_index,
        clearing_price,
        target_side,
        *order_types.at(target_index),
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        *limit_prices.at(target_index),
        *order_amounts.at(target_index),
        *min_fills.at(target_index),
        *time_in_force.at(target_index),
        *funding_note_amounts.at(target_index),
    );
    let opposite_side = if target_side == ORDER_SIDE_BUY {
        ORDER_SIDE_SELL
    } else {
        ORDER_SIDE_BUY
    };
    let opposite_total = active_capacity_total(
        active_flags,
        opposite_side,
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    let priority_capacity = active_priority_capacity_before(
        target_index,
        active_flags,
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    greedy_priority_fill(max_fill, opposite_total, priority_capacity)
}

fn active_capacity_total(
    active_flags: Span<felt252>,
    side: felt252,
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> u128 {
    let mut index = 0;
    let mut capacity: u128 = 0;
    while index < sides.len() {
        if *active_flags.at(index) == 1 && *sides.at(index) == side {
            capacity +=
                max_fill_at_candidate(
                    index,
                    clearing_price,
                    *sides.at(index),
                    *order_types.at(index),
                    maker_curve_point_counts,
                    maker_curve_prices,
                    maker_curve_base_amounts,
                    *limit_prices.at(index),
                    *order_amounts.at(index),
                    *min_fills.at(index),
                    *time_in_force.at(index),
                    *funding_note_amounts.at(index),
                );
        }
        index += 1;
    }
    capacity
}

fn active_priority_capacity_before(
    target_index: usize,
    active_flags: Span<felt252>,
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> u128 {
    let target_side = *sides.at(target_index);
    let target_limit_price = felt_to_u128(*limit_prices.at(target_index));
    let mut index = 0;
    let mut capacity: u128 = 0;

    while index < sides.len() {
        if *active_flags.at(index) == 1 && *sides.at(index) == target_side {
            let limit_price = felt_to_u128(*limit_prices.at(index));
            let has_priority = if target_side == ORDER_SIDE_BUY {
                limit_price > target_limit_price
                    || (limit_price == target_limit_price && index < target_index)
            } else {
                limit_price < target_limit_price
                    || (limit_price == target_limit_price && index < target_index)
            };
            if has_priority {
                capacity +=
                    max_fill_at_candidate(
                        index,
                        clearing_price,
                        *sides.at(index),
                        *order_types.at(index),
                        maker_curve_point_counts,
                        maker_curve_prices,
                        maker_curve_base_amounts,
                        *limit_prices.at(index),
                        *order_amounts.at(index),
                        *min_fills.at(index),
                        *time_in_force.at(index),
                        *funding_note_amounts.at(index),
                    );
            }
        }
        index += 1;
    }

    capacity
}

fn greedy_priority_fill(
    own_capacity: u128, opposite_total_capacity: u128, same_side_priority_capacity: u128,
) -> u128 {
    if opposite_total_capacity <= same_side_priority_capacity {
        return 0;
    }
    u128_min(own_capacity, opposite_total_capacity - same_side_priority_capacity)
}

fn assert_best_clearing_price(
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) {
    let mut best_initialized = 0;
    let mut best_price: u128 = 0;
    let mut best_matched: u128 = 0;
    let mut best_imbalance: u128 = 0;
    let mut order_index = 0;

    while order_index < sides.len() {
        if *order_types
            .at(order_index) == ORDER_TYPE_HEARTBEAT_COVER {} else if *order_types
                .at(order_index) == ORDER_TYPE_MAKER_CURVE {
                let cursor = curve_cursor_for_order(maker_curve_point_counts, order_index);
                let point_count: usize = (*maker_curve_point_counts.at(order_index))
                    .try_into()
                    .expect('CURVE_COUNT');
                let mut point_index = 0;
                while point_index < point_count {
                    let candidate = felt_to_u128(*maker_curve_prices.at(cursor + point_index));
                    let (matched, imbalance) = auction_score_at_price(
                        candidate,
                        sides,
                        order_types,
                        maker_curve_point_counts,
                        maker_curve_prices,
                        maker_curve_base_amounts,
                        limit_prices,
                        order_amounts,
                        min_fills,
                        time_in_force,
                        funding_note_amounts,
                    );
                    let update = should_update_best(
                        best_initialized,
                        candidate,
                        matched,
                        imbalance,
                        best_price,
                        best_matched,
                        best_imbalance,
                    );
                    if update == 1 {
                        best_initialized = 1;
                        best_price = candidate;
                        best_matched = matched;
                        best_imbalance = imbalance;
                    }
                    point_index += 1;
                };
            } else {
                let candidate = felt_to_u128(*limit_prices.at(order_index));
                let (matched, imbalance) = auction_score_at_price(
                    candidate,
                    sides,
                    order_types,
                    maker_curve_point_counts,
                    maker_curve_prices,
                    maker_curve_base_amounts,
                    limit_prices,
                    order_amounts,
                    min_fills,
                    time_in_force,
                    funding_note_amounts,
                );
                let update = should_update_best(
                    best_initialized,
                    candidate,
                    matched,
                    imbalance,
                    best_price,
                    best_matched,
                    best_imbalance,
                );
                if update == 1 {
                    best_initialized = 1;
                    best_price = candidate;
                    best_matched = matched;
                    best_imbalance = imbalance;
                }
            }
        order_index += 1;
    }

    assert(best_initialized == 1, 'NO_AUCTION_PRICE');
    assert(clearing_price == best_price, 'BAD_CLEARING_PRICE');
}

fn assert_no_executable_auction(
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) {
    let mut order_index = 0;
    while order_index < sides.len() {
        if *order_types
            .at(order_index) == ORDER_TYPE_HEARTBEAT_COVER {} else if *order_types
                .at(order_index) == ORDER_TYPE_MAKER_CURVE {
                let cursor = curve_cursor_for_order(maker_curve_point_counts, order_index);
                let point_count: usize = (*maker_curve_point_counts.at(order_index))
                    .try_into()
                    .expect('CURVE_COUNT');
                let mut point_index = 0;
                while point_index < point_count {
                    let candidate = felt_to_u128(*maker_curve_prices.at(cursor + point_index));
                    let (matched, _imbalance) = auction_score_at_price(
                        candidate,
                        sides,
                        order_types,
                        maker_curve_point_counts,
                        maker_curve_prices,
                        maker_curve_base_amounts,
                        limit_prices,
                        order_amounts,
                        min_fills,
                        time_in_force,
                        funding_note_amounts,
                    );
                    assert(matched == 0, 'NOOP_HAS_CROSS');
                    point_index += 1;
                };
            } else {
                let candidate = felt_to_u128(*limit_prices.at(order_index));
                let (matched, _imbalance) = auction_score_at_price(
                    candidate,
                    sides,
                    order_types,
                    maker_curve_point_counts,
                    maker_curve_prices,
                    maker_curve_base_amounts,
                    limit_prices,
                    order_amounts,
                    min_fills,
                    time_in_force,
                    funding_note_amounts,
                );
                assert(matched == 0, 'NOOP_HAS_CROSS');
            }
        order_index += 1;
    }
}

fn has_non_cover_orders(order_types: Span<felt252>) -> felt252 {
    let mut index = 0;
    while index < order_types.len() {
        if *order_types.at(index) != ORDER_TYPE_HEARTBEAT_COVER {
            return 1;
        }
        index += 1;
    }
    0
}

fn admission_summary_leaf(
    order_commitment: felt252,
    side: felt252,
    order_type: felt252,
    maker_curve_commitment: felt252,
    limit_price: felt252,
    amount: felt252,
    min_fill: felt252,
    time_in_force: felt252,
    funding_note_amount: felt252,
    funding_note_owner_key: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(ADMISSION_LEAF_DOMAIN, order_commitment);
    state = poseidon_hash2(state, side);
    state = poseidon_hash2(state, order_type);
    state = poseidon_hash2(state, maker_curve_commitment);
    state = poseidon_hash2(state, limit_price);
    state = poseidon_hash2(state, amount);
    state = poseidon_hash2(state, min_fill);
    state = poseidon_hash2(state, time_in_force);
    state = poseidon_hash2(state, funding_note_amount);
    poseidon_hash2(state, funding_note_owner_key)
}

fn admission_summary_root(
    order_commitments: Span<felt252>,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_commitments: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
    funding_note_owner_keys: Span<felt252>,
) -> felt252 {
    let mut state = poseidon_hash2(ADMISSION_ROOT_DOMAIN, order_commitments.len().into());
    let mut index = 0;
    while index < order_commitments.len() {
        state =
            poseidon_hash2(
                state,
                admission_summary_leaf(
                    *order_commitments.at(index),
                    *sides.at(index),
                    *order_types.at(index),
                    *maker_curve_commitments.at(index),
                    *limit_prices.at(index),
                    *order_amounts.at(index),
                    *min_fills.at(index),
                    *time_in_force.at(index),
                    *funding_note_amounts.at(index),
                    *funding_note_owner_keys.at(index),
                ),
            );
        index += 1;
    }
    state
}

fn assert_curve_commitments_for_summary(
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_domain: felt252,
    maker_curve_commitments: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
) {
    let mut index = 0;
    let mut curve_cursor = 0;
    while index < maker_curve_commitments.len() {
        let point_count: usize = (*maker_curve_point_counts.at(index))
            .try_into()
            .expect('CURVE_COUNT');
        let (_total, _eligible, _quote_required) = assert_maker_curve(
            *order_types.at(index),
            *sides.at(index),
            maker_curve_domain,
            *maker_curve_commitments.at(index),
            point_count,
            curve_cursor,
            clearing_price,
            maker_curve_prices,
            maker_curve_base_amounts,
        );
        curve_cursor += point_count;
        index += 1;
    }
    assert(curve_cursor == maker_curve_prices.len(), 'AUCRES_CURVE_CURSOR');
}

fn assert_privacy_gate_failure(
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
    funding_note_owner_keys: Span<felt252>,
    min_batch_base_liquidity: felt252,
    min_batch_participants: felt252,
    min_eligible_orders: felt252,
    max_single_order_fill_bps: felt252,
    max_single_owner_fill_bps: felt252,
    min_maker_participants: felt252,
    max_maker_fill_bps: felt252,
) {
    let active_flags = stable_active_flags(
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    let (matched_volume, _imbalance) = auction_score_at_price(
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    let eligible_count = eligible_order_count_at_price(
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    let participant_count = distinct_filled_owner_count(
        active_flags.span(),
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
        funding_note_owner_keys,
        0,
    );
    let maker_participant_count = distinct_filled_owner_count(
        active_flags.span(),
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
        funding_note_owner_keys,
        1,
    );
    let max_order_fill = max_order_fill_at_price(
        active_flags.span(),
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
        0,
    );
    let max_maker_fill = max_order_fill_at_price(
        active_flags.span(),
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
        1,
    );
    let max_owner_fill = max_owner_fill_at_price(
        active_flags.span(),
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
        funding_note_owner_keys,
    );

    let mut failed = 0;
    if min_batch_base_liquidity != 0 {
        let threshold = felt_to_u128(min_batch_base_liquidity);
        if matched_volume > 0 {
            if matched_volume < threshold {
                failed = 1;
            }
        }
    }
    if min_batch_participants != 0 {
        if participant_count > 0 {
            if participant_count < felt_to_u128(min_batch_participants) {
                failed = 1;
            }
        }
    }
    if min_eligible_orders != 0 {
        if eligible_count > 0 {
            if eligible_count < felt_to_u128(min_eligible_orders) {
                failed = 1;
            }
        }
    }
    if matched_volume > 0 {
        if max_single_order_fill_bps != 0 {
            if max_order_fill * 10000 / matched_volume > felt_to_u128(max_single_order_fill_bps) {
                failed = 1;
            }
        }
        if max_single_owner_fill_bps != 0 {
            if max_owner_fill * 10000 / matched_volume > felt_to_u128(max_single_owner_fill_bps) {
                failed = 1;
            }
        }
        if max_maker_fill_bps != 0 {
            if max_maker_fill * 10000 / matched_volume > felt_to_u128(max_maker_fill_bps) {
                failed = 1;
            }
        }
    }
    if min_maker_participants != 0 {
        if maker_participant_count > 0 {
            if maker_participant_count < felt_to_u128(min_maker_participants) {
                failed = 1;
            }
        }
    }
    assert(failed == 1, 'PRIVACY_GATE_NOT_FAILED');
}

fn assert_privacy_gate_success(
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
    funding_note_owner_keys: Span<felt252>,
    min_batch_base_liquidity: felt252,
    min_batch_participants: felt252,
    min_eligible_orders: felt252,
    max_single_order_fill_bps: felt252,
    max_single_owner_fill_bps: felt252,
    min_maker_participants: felt252,
    max_maker_fill_bps: felt252,
) {
    let active_flags = stable_active_flags(
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    let (matched_volume, _imbalance) = auction_score_at_price(
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    let eligible_count = eligible_order_count_at_price(
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    let participant_count = distinct_filled_owner_count(
        active_flags.span(),
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
        funding_note_owner_keys,
        0,
    );
    let maker_participant_count = distinct_filled_owner_count(
        active_flags.span(),
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
        funding_note_owner_keys,
        1,
    );
    let max_order_fill = max_order_fill_at_price(
        active_flags.span(),
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
        0,
    );
    let max_maker_fill = max_order_fill_at_price(
        active_flags.span(),
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
        1,
    );
    let max_owner_fill = max_owner_fill_at_price(
        active_flags.span(),
        clearing_price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
        funding_note_owner_keys,
    );

    assert(matched_volume != 0, 'PRIVACY_GATE_EMPTY_MATCH');
    if min_batch_base_liquidity != 0 {
        assert(matched_volume >= felt_to_u128(min_batch_base_liquidity), 'PRIVACY_MIN_LIQUIDITY');
    }
    if min_batch_participants != 0 {
        assert(
            participant_count >= felt_to_u128(min_batch_participants), 'PRIVACY_MIN_PARTICIPANTS',
        );
    }
    if min_eligible_orders != 0 {
        assert(eligible_count >= felt_to_u128(min_eligible_orders), 'PRIVACY_MIN_ELIGIBLE');
    }
    if max_single_order_fill_bps != 0 {
        assert(
            max_order_fill * 10000 / matched_volume <= felt_to_u128(max_single_order_fill_bps),
            'PRIVACY_ORDER_DOMINANCE',
        );
    }
    if max_single_owner_fill_bps != 0 {
        assert(
            max_owner_fill * 10000 / matched_volume <= felt_to_u128(max_single_owner_fill_bps),
            'PRIVACY_OWNER_DOMINANCE',
        );
    }
    if max_maker_fill_bps != 0 {
        assert(
            max_maker_fill * 10000 / matched_volume <= felt_to_u128(max_maker_fill_bps),
            'PRIVACY_MAKER_DOMINANCE',
        );
    }
    if min_maker_participants != 0 {
        assert(
            maker_participant_count >= felt_to_u128(min_maker_participants), 'PRIVACY_MIN_MAKERS',
        );
    }
}

fn eligible_order_count_at_price(
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> u128 {
    let mut count: u128 = 0;
    let mut index = 0;
    while index < sides.len() {
        let fill = max_fill_at_candidate(
            index,
            clearing_price,
            *sides.at(index),
            *order_types.at(index),
            maker_curve_point_counts,
            maker_curve_prices,
            maker_curve_base_amounts,
            *limit_prices.at(index),
            *order_amounts.at(index),
            *min_fills.at(index),
            *time_in_force.at(index),
            *funding_note_amounts.at(index),
        );
        if fill > 0 {
            count += 1;
        }
        index += 1;
    }
    count
}

fn max_order_fill_at_price(
    active_flags: Span<felt252>,
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
    maker_only: felt252,
) -> u128 {
    let mut max_fill: u128 = 0;
    let mut index = 0;
    while index < active_flags.len() {
        if maker_only == 0 || *order_types.at(index) == ORDER_TYPE_MAKER_CURVE {
            let fill = expected_fill_with_active_flags(
                index,
                active_flags,
                clearing_price,
                sides,
                order_types,
                maker_curve_point_counts,
                maker_curve_prices,
                maker_curve_base_amounts,
                limit_prices,
                order_amounts,
                min_fills,
                time_in_force,
                funding_note_amounts,
            );
            if fill > max_fill {
                max_fill = fill;
            }
        }
        index += 1;
    }
    max_fill
}

fn max_owner_fill_at_price(
    active_flags: Span<felt252>,
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
    funding_note_owner_keys: Span<felt252>,
) -> u128 {
    let mut max_fill: u128 = 0;
    let mut index = 0;
    while index < active_flags.len() {
        let owner = *funding_note_owner_keys.at(index);
        let mut owner_fill: u128 = 0;
        let mut cursor = 0;
        while cursor < active_flags.len() {
            if *funding_note_owner_keys.at(cursor) == owner {
                owner_fill = owner_fill
                    + expected_fill_with_active_flags(
                        cursor,
                        active_flags,
                        clearing_price,
                        sides,
                        order_types,
                        maker_curve_point_counts,
                        maker_curve_prices,
                        maker_curve_base_amounts,
                        limit_prices,
                        order_amounts,
                        min_fills,
                        time_in_force,
                        funding_note_amounts,
                    );
            }
            cursor += 1;
        }
        if owner_fill > max_fill {
            max_fill = owner_fill;
        }
        index += 1;
    }
    max_fill
}

fn distinct_filled_owner_count(
    active_flags: Span<felt252>,
    clearing_price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
    funding_note_owner_keys: Span<felt252>,
    maker_only: felt252,
) -> u128 {
    let mut count: u128 = 0;
    let mut index = 0;
    while index < active_flags.len() {
        if maker_only == 0 || *order_types.at(index) == ORDER_TYPE_MAKER_CURVE {
            let fill = expected_fill_with_active_flags(
                index,
                active_flags,
                clearing_price,
                sides,
                order_types,
                maker_curve_point_counts,
                maker_curve_prices,
                maker_curve_base_amounts,
                limit_prices,
                order_amounts,
                min_fills,
                time_in_force,
                funding_note_amounts,
            );
            if fill > 0 {
                let owner = *funding_note_owner_keys.at(index);
                let mut seen = 0;
                let mut cursor = 0;
                while cursor < index {
                    if *funding_note_owner_keys.at(cursor) == owner {
                        if maker_only == 0 || *order_types.at(cursor) == ORDER_TYPE_MAKER_CURVE {
                            let prior_fill = expected_fill_with_active_flags(
                                cursor,
                                active_flags,
                                clearing_price,
                                sides,
                                order_types,
                                maker_curve_point_counts,
                                maker_curve_prices,
                                maker_curve_base_amounts,
                                limit_prices,
                                order_amounts,
                                min_fills,
                                time_in_force,
                                funding_note_amounts,
                            );
                            if prior_fill > 0 {
                                seen = 1;
                            }
                        }
                    }
                    cursor += 1;
                }
                if seen == 0 {
                    count += 1;
                }
            }
        }
        index += 1;
    }
    count
}

fn should_update_best(
    best_initialized: felt252,
    candidate: u128,
    matched: u128,
    imbalance: u128,
    best_price: u128,
    best_matched: u128,
    best_imbalance: u128,
) -> felt252 {
    if best_initialized == 0 {
        return 1;
    }
    if matched > best_matched {
        return 1;
    }
    if matched == best_matched {
        if imbalance < best_imbalance {
            return 1;
        }
        if imbalance == best_imbalance {
            if candidate < best_price {
                return 1;
            }
        }
    }
    0
}

fn assert_all_zero(values: Span<felt252>, message: felt252) {
    let mut index = 0;
    while index < values.len() {
        assert(*values.at(index) == 0, message);
        index += 1;
    }
}

fn auction_score_at_price(
    price: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> (u128, u128) {
    let active_flags = stable_active_flags(
        price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    let buy_demand = active_capacity_total(
        active_flags.span(),
        ORDER_SIDE_BUY,
        price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    let sell_supply = active_capacity_total(
        active_flags.span(),
        ORDER_SIDE_SELL,
        price,
        sides,
        order_types,
        maker_curve_point_counts,
        maker_curve_prices,
        maker_curve_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );

    let matched = u128_min(buy_demand, sell_supply);
    let imbalance = u128_abs_diff(buy_demand, sell_supply);
    (matched, imbalance)
}

fn max_fill_at_candidate(
    order_index: usize,
    price: u128,
    side: felt252,
    order_type: felt252,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
    limit_price_felt: felt252,
    order_amount_felt: felt252,
    min_fill_felt: felt252,
    time_in_force: felt252,
    funding_note_amount_felt: felt252,
) -> u128 {
    if order_type == ORDER_TYPE_HEARTBEAT_COVER {
        return 0;
    }
    let limit_price = felt_to_u128(limit_price_felt);
    let order_amount = felt_to_u128(order_amount_felt);
    let min_fill = felt_to_u128(min_fill_felt);
    let funding_note_amount = felt_to_u128(funding_note_amount_felt);
    let requested_amount = if order_type == ORDER_TYPE_MAKER_CURVE {
        maker_curve_capacity_at_candidate(
            order_index,
            price,
            side,
            maker_curve_point_counts,
            maker_curve_prices,
            maker_curve_base_amounts,
        )
    } else {
        if side == ORDER_SIDE_BUY {
            if limit_price >= price {
                order_amount
            } else {
                0
            }
        } else {
            if limit_price <= price {
                order_amount
            } else {
                0
            }
        }
    };

    if side == ORDER_SIDE_BUY {
        if price == 0 {
            return 0;
        }
        let available_amount = u128_min(requested_amount, funding_note_amount / price);
        if available_amount < min_fill {
            return 0;
        }
        if time_in_force == TIF_FILL_OR_KILL {
            if available_amount < order_amount {
                return 0;
            }
        }
        return available_amount;
    }
    let available_amount = u128_min(requested_amount, funding_note_amount);
    if available_amount < min_fill {
        return 0;
    }
    if time_in_force == TIF_FILL_OR_KILL {
        if available_amount < order_amount {
            return 0;
        }
    }
    available_amount
}

fn maker_curve_capacity_at_candidate(
    order_index: usize,
    price: u128,
    side: felt252,
    maker_curve_point_counts: Span<felt252>,
    maker_curve_prices: Span<felt252>,
    maker_curve_base_amounts: Span<felt252>,
) -> u128 {
    let cursor = curve_cursor_for_order(maker_curve_point_counts, order_index);
    let point_count: usize = (*maker_curve_point_counts.at(order_index))
        .try_into()
        .expect('CURVE_COUNT');
    let mut capacity: u128 = 0;
    let mut point_index = 0;
    while point_index < point_count {
        let point_price = felt_to_u128(*maker_curve_prices.at(cursor + point_index));
        let point_amount = felt_to_u128(*maker_curve_base_amounts.at(cursor + point_index));
        if side == ORDER_SIDE_BUY {
            if point_price >= price {
                capacity += point_amount;
            }
        } else {
            if point_price <= price {
                capacity += point_amount;
            }
        }
        point_index += 1;
    }
    capacity
}

fn curve_cursor_for_order(point_counts: Span<felt252>, order_index: usize) -> usize {
    let mut cursor = 0;
    let mut index = 0;
    while index < order_index {
        let count: usize = (*point_counts.at(index)).try_into().expect('CURVE_COUNT');
        cursor += count;
        index += 1;
    }
    cursor
}

fn u128_min(left: u128, right: u128) -> u128 {
    if left < right {
        return left;
    }
    right
}

fn u128_abs_diff(left: u128, right: u128) -> u128 {
    if left >= right {
        return left - right;
    }
    right - left
}

fn read_next(data: Span<felt252>, ref index: usize) -> felt252 {
    assert(index < data.len(), 'UNEXPECTED_EOF');
    let value = *data.at(index);
    index += 1;
    value
}

fn read_vector(data: Span<felt252>, ref index: usize) -> Array<felt252> {
    let len = read_next(data, ref index);
    let mut remaining = len;
    let mut values = array![];

    while remaining != 0 {
        values.append(read_next(data, ref index));
        remaining = remaining - 1;
    }

    values
}

fn assert_all_lengths_match(expected_len: usize, lengths: Span<felt252>, message: felt252) {
    let expected: felt252 = expected_len.into();
    let mut index = 0;
    while index < lengths.len() {
        assert(*lengths.at(index) == expected, message);
        index += 1;
    };
}

fn sum_curve_point_counts(counts: Span<felt252>) -> usize {
    let mut index = 0;
    let mut total = 0;
    while index < counts.len() {
        let count: usize = (*counts.at(index)).try_into().expect('CURVE_COUNT');
        total += count;
        index += 1;
    }
    total
}

fn assert_maker_curve(
    order_type: felt252,
    side: felt252,
    maker_curve_domain: felt252,
    expected_commitment: felt252,
    point_count: usize,
    cursor: usize,
    clearing_price: u128,
    prices: Span<felt252>,
    base_amounts: Span<felt252>,
) -> (u128, u128, u128) {
    if order_type != ORDER_TYPE_MAKER_CURVE {
        assert(expected_commitment == 0, 'UNEXPECTED_CURVE');
        assert(point_count == 0, 'UNEXPECTED_CURVE');
        return (0, 0, 0);
    }

    assert(expected_commitment != 0, 'BAD_CURVE');
    assert(point_count != 0, 'EMPTY_CURVE');
    assert(cursor + point_count <= prices.len(), 'CURVE_EOF');
    assert(cursor + point_count <= base_amounts.len(), 'CURVE_EOF');

    let point_count_felt: felt252 = point_count.into();
    let mut recomputed_commitment = poseidon_hash2(maker_curve_domain, point_count_felt);
    let mut index = 0;
    let mut previous_price: u128 = 0;
    let mut total_base_amount: u128 = 0;
    let mut eligible_base_amount: u128 = 0;
    let mut quote_funding_required: u128 = 0;

    while index < point_count {
        let price_felt = *prices.at(cursor + index);
        let base_amount_felt = *base_amounts.at(cursor + index);
        assert(price_felt != 0, 'BAD_CURVE_PRICE');
        assert(base_amount_felt != 0, 'BAD_CURVE_SIZE');

        let price = felt_to_u128(price_felt);
        let base_amount = felt_to_u128(base_amount_felt);
        if index != 0 {
            assert(price > previous_price, 'CURVE_ORDER');
        }
        previous_price = price;
        total_base_amount = total_base_amount + base_amount;
        quote_funding_required = quote_funding_required + price * base_amount;
        if side == ORDER_SIDE_BUY {
            if price >= clearing_price {
                eligible_base_amount = eligible_base_amount + base_amount;
            }
        } else {
            assert(side == ORDER_SIDE_SELL, 'BAD_SIDE');
            if price <= clearing_price {
                eligible_base_amount = eligible_base_amount + base_amount;
            }
        }

        recomputed_commitment = poseidon_hash2(recomputed_commitment, price_felt);
        recomputed_commitment = poseidon_hash2(recomputed_commitment, base_amount_felt);
        index += 1;
    }

    assert(recomputed_commitment == expected_commitment, 'CURVE_BIND');
    (total_base_amount, eligible_base_amount, quote_funding_required)
}

fn assert_public_output_present(
    expected_commitment: felt252,
    expected_asset_id: felt252,
    expected_amount: u128,
    expected_withdraw_authority: felt252,
    output_note_commitments: Span<felt252>,
    output_note_asset_ids: Span<felt252>,
    output_note_amounts: Span<felt252>,
    output_note_withdraw_authorities: Span<felt252>,
) {
    let mut index = 0;
    while index < output_note_commitments.len() {
        if expected_commitment == *output_note_commitments.at(index) {
            assert(expected_asset_id == *output_note_asset_ids.at(index), 'OUTPUT_ASSET_MISMATCH');
            assert(
                expected_amount == felt_to_u128(*output_note_amounts.at(index)),
                'OUTPUT_AMOUNT_MISMATCH',
            );
            assert(
                expected_withdraw_authority == *output_note_withdraw_authorities.at(index),
                'OUTPUT_AUTH_MISMATCH',
            );
            return;
        }
        index += 1;
    }
    assert(false, 'OUTPUT_MISSING');
}

fn assert_netted_public_outputs(
    base_asset_id: felt252,
    quote_asset_id: felt252,
    clearing_price: u128,
    matched_fill_amounts: Span<felt252>,
    matched_sides: Span<felt252>,
    matched_funding_note_amounts: Span<felt252>,
    matched_output_note_commitments: Span<felt252>,
    matched_residual_note_flags: Span<felt252>,
    matched_residual_note_commitments: Span<felt252>,
    output_note_commitments: Span<felt252>,
    output_note_amounts: Span<felt252>,
) {
    let _ = base_asset_id;
    let _ = quote_asset_id;
    let mut output_index = 0;
    while output_index < output_note_commitments.len() {
        let public_commitment = *output_note_commitments.at(output_index);
        let public_amount = felt_to_u128(*output_note_amounts.at(output_index));
        let mut expected_amount: u128 = 0;
        let mut order_index = 0;
        while order_index < matched_output_note_commitments.len() {
            let filled_amount = felt_to_u128(*matched_fill_amounts.at(order_index));
            let side = *matched_sides.at(order_index);
            let funding_note_amount = felt_to_u128(*matched_funding_note_amounts.at(order_index));
            let primary_amount = if side == ORDER_SIDE_BUY {
                let fee_amount = filled_amount * PROTOCOL_FEE_BPS / FEE_BPS_DENOMINATOR;
                filled_amount - fee_amount
            } else {
                assert(side == ORDER_SIDE_SELL, 'BAD_SIDE');
                let gross_quote = filled_amount * clearing_price;
                let fee_amount = gross_quote * PROTOCOL_FEE_BPS / FEE_BPS_DENOMINATOR;
                gross_quote - fee_amount
            };
            if *matched_output_note_commitments.at(order_index) == public_commitment {
                expected_amount = expected_amount + primary_amount;
            }

            let residual_amount = if side == ORDER_SIDE_BUY {
                funding_note_amount - filled_amount * clearing_price
            } else {
                funding_note_amount - filled_amount
            };
            if *matched_residual_note_flags.at(order_index) == 1 {
                if *matched_residual_note_commitments.at(order_index) == public_commitment {
                    expected_amount = expected_amount + residual_amount;
                }
            }
            order_index += 1;
        }
        assert(expected_amount != 0, 'UNBACKED_OUTPUT');
        assert(public_amount == expected_amount, 'NETTED_OUTPUT_AMOUNT');
        output_index += 1;
    }
}

fn assert_sparse_nullifier_updates(
    prior_nullifier_root: felt252,
    current_nullifiers: Span<felt252>,
    key_lows: Span<felt252>,
    key_highs: Span<felt252>,
    path_counts: Span<felt252>,
    path_values: Span<felt252>,
    path_directions: Span<felt252>,
    sparse_leaf_domain: felt252,
    sparse_node_domain: felt252,
) -> felt252 {
    assert(current_nullifiers.len() == key_lows.len(), 'NULL_KEY_LOW_LEN');
    assert(current_nullifiers.len() == key_highs.len(), 'NULL_KEY_HIGH_LEN');
    assert(current_nullifiers.len() == path_counts.len(), 'NULL_PATH_COUNT_LEN');
    let mut running_root = prior_nullifier_root;
    let mut path_cursor = 0;
    let mut index = 0;
    while index < current_nullifiers.len() {
        let nullifier = *current_nullifiers.at(index);
        assert(nullifier != 0, 'BAD_NULLIFIER');
        let key_low: u128 = (*key_lows.at(index)).try_into().expect('NULL_KEY_LOW');
        let key_high: u128 = (*key_highs.at(index)).try_into().expect('NULL_KEY_HIGH');
        assert(key_high < NULLIFIER_KEY_HIGH_BOUND, 'NULL_KEY_HIGH');
        assert(nullifier == key_low.into() + key_high.into() * TWO_POW_128, 'NULL_KEY_BIND');
        let path_count: usize = (*path_counts.at(index)).try_into().expect('NULL_PATH_COUNT');
        assert(path_cursor + path_count <= path_values.len(), 'NULL_PATH_EOF');
        assert(path_cursor + path_count <= path_directions.len(), 'NULL_DIR_EOF');
        if running_root == 0 {
            assert(path_count == 0, 'NULL_EMPTY_PATH');
            running_root = poseidon_hash2(sparse_leaf_domain, nullifier);
        } else {
            assert(path_count == NULLIFIER_SPARSE_TREE_DEPTH, 'NULL_PATH_COUNT');
            running_root =
                sparse_insert_nullifier(
                    running_root,
                    nullifier,
                    key_low,
                    key_high,
                    path_cursor,
                    path_values,
                    path_directions,
                    sparse_leaf_domain,
                    sparse_node_domain,
                );
        }
        path_cursor += path_count;
        index += 1;
    }
    assert(path_cursor == path_values.len(), 'NULL_PATH_CURSOR');
    assert(path_cursor == path_directions.len(), 'NULL_DIR_CURSOR');
    running_root
}

fn assert_sparse_entry_insert(
    prior_root: felt252,
    entry: felt252,
    key_low_felt: felt252,
    key_high_felt: felt252,
    path_count_felt: felt252,
    ref path_cursor: usize,
    path_values: Span<felt252>,
    path_directions: Span<felt252>,
    sparse_leaf_domain: felt252,
    sparse_node_domain: felt252,
) -> felt252 {
    assert(entry != 0, 'BAD_SPARSE_ENTRY');
    let key_low: u128 = key_low_felt.try_into().expect('SPARSE_KEY_LOW');
    let key_high: u128 = key_high_felt.try_into().expect('SPARSE_KEY_HIGH');
    assert(key_high < NULLIFIER_KEY_HIGH_BOUND, 'SPARSE_KEY_HIGH');
    assert(entry == key_low.into() + key_high.into() * TWO_POW_128, 'SPARSE_KEY_BIND');
    let path_count: usize = path_count_felt.try_into().expect('SPARSE_PATH_COUNT');
    assert(path_cursor + path_count <= path_values.len(), 'SPARSE_PATH_EOF');
    assert(path_cursor + path_count <= path_directions.len(), 'SPARSE_DIR_EOF');
    let new_root = if prior_root == 0 {
        assert(path_count == 0, 'SPARSE_EMPTY_PATH');
        poseidon_hash2(sparse_leaf_domain, entry)
    } else {
        assert(path_count == NULLIFIER_SPARSE_TREE_DEPTH, 'SPARSE_PATH_COUNT');
        sparse_insert_nullifier(
            prior_root,
            entry,
            key_low,
            key_high,
            path_cursor,
            path_values,
            path_directions,
            sparse_leaf_domain,
            sparse_node_domain,
        )
    };
    path_cursor += path_count;
    new_root
}

fn assert_sparse_entry_absent(
    prior_root: felt252,
    entry: felt252,
    key_low_felt: felt252,
    key_high_felt: felt252,
    path_count_felt: felt252,
    ref path_cursor: usize,
    path_values: Span<felt252>,
    path_directions: Span<felt252>,
    sparse_node_domain: felt252,
) -> felt252 {
    assert(entry != 0, 'BAD_SPARSE_ENTRY');
    let key_low: u128 = key_low_felt.try_into().expect('SPARSE_KEY_LOW');
    let key_high: u128 = key_high_felt.try_into().expect('SPARSE_KEY_HIGH');
    assert(key_high < NULLIFIER_KEY_HIGH_BOUND, 'SPARSE_KEY_HIGH');
    assert(entry == key_low.into() + key_high.into() * TWO_POW_128, 'SPARSE_KEY_BIND');
    let path_count: usize = path_count_felt.try_into().expect('SPARSE_PATH_COUNT');
    assert(path_cursor + path_count <= path_values.len(), 'SPARSE_PATH_EOF');
    assert(path_cursor + path_count <= path_directions.len(), 'SPARSE_DIR_EOF');
    if prior_root == 0 {
        assert(path_count == 0, 'SPARSE_EMPTY_PATH');
        return prior_root;
    }
    assert(path_count == NULLIFIER_SPARSE_TREE_DEPTH, 'SPARSE_PATH_COUNT');
    let mut reconstructed_low: felt252 = 0;
    let mut bit_weight: felt252 = 1;
    let mut empty_root = 0;
    let mut level = 0;
    while level < NULLIFIER_SPARSE_TREE_DEPTH {
        let sibling = *path_values.at(path_cursor + level);
        let bit = *path_directions.at(path_cursor + level);
        assert(bit == 0 || bit == 1, 'SPARSE_PATH_BIT');
        reconstructed_low = reconstructed_low + bit * bit_weight;
        bit_weight = bit_weight * 2;
        if bit == 0 {
            empty_root = sparse_nullifier_node(sparse_node_domain, empty_root, sibling);
        } else {
            empty_root = sparse_nullifier_node(sparse_node_domain, sibling, empty_root);
        }
        level += 1;
    }
    assert(
        reconstructed_low == (key_low % NULLIFIER_KEY_LOW_MODULUS).into(), 'SPARSE_KEY_LOW_BITS',
    );
    assert(empty_root == prior_root, 'SPARSE_ABSENT_PRIOR');
    path_cursor += path_count;
    prior_root
}

fn sparse_insert_nullifier(
    prior_root: felt252,
    nullifier: felt252,
    key_low: u128,
    key_high: u128,
    path_cursor: usize,
    path_values: Span<felt252>,
    path_directions: Span<felt252>,
    sparse_leaf_domain: felt252,
    sparse_node_domain: felt252,
) -> felt252 {
    let mut reconstructed_low: felt252 = 0;
    let mut bit_weight: felt252 = 1;
    let mut empty_root = 0;
    let mut inserted_root = poseidon_hash2(sparse_leaf_domain, nullifier);
    let mut level = 0;
    while level < NULLIFIER_SPARSE_TREE_DEPTH {
        let sibling = *path_values.at(path_cursor + level);
        let bit = *path_directions.at(path_cursor + level);
        assert(bit == 0 || bit == 1, 'NULL_PATH_BIT');
        reconstructed_low = reconstructed_low + bit * bit_weight;
        bit_weight = bit_weight * 2;
        if bit == 0 {
            empty_root = sparse_nullifier_node(sparse_node_domain, empty_root, sibling);
            inserted_root = sparse_nullifier_node(sparse_node_domain, inserted_root, sibling);
        } else {
            empty_root = sparse_nullifier_node(sparse_node_domain, sibling, empty_root);
            inserted_root = sparse_nullifier_node(sparse_node_domain, sibling, inserted_root);
        }
        level += 1;
    }
    assert(reconstructed_low == (key_low % NULLIFIER_KEY_LOW_MODULUS).into(), 'NULL_KEY_LOW_BITS');
    assert(empty_root == prior_root, 'NULL_SPARSE_PRIOR');
    assert(nullifier == key_low.into() + key_high.into() * TWO_POW_128, 'NULL_KEY_BIND');
    inserted_root
}

fn sparse_nullifier_node(domain: felt252, left: felt252, right: felt252) -> felt252 {
    if left == 0 {
        return right;
    }
    if right == 0 {
        return left;
    }
    let (result, _, _) = hades_permutation(domain, left, right);
    result
}

fn assert_note_membership(
    note_commitment_value: felt252,
    asset_id: felt252,
    amount: felt252,
    withdraw_authority: felt252,
    prior_note_root: felt252,
    kind: felt252,
    prefix_root: felt252,
    batch_root: felt252,
    path_count_felt: felt252,
    ref path_cursor: usize,
    path_values: Span<felt252>,
    path_directions: Span<felt252>,
    suffix_count_felt: felt252,
    ref suffix_cursor: usize,
    suffix_roots: Span<felt252>,
    state_transition_root_domain: felt252,
) {
    let path_count: usize = path_count_felt.try_into().expect('INPUT_PATH_COUNT');
    let suffix_count: usize = suffix_count_felt.try_into().expect('INPUT_SUFFIX_COUNT');
    assert(path_cursor + path_count <= path_values.len(), 'INPUT_PATH_EOF');
    assert(path_cursor + path_count <= path_directions.len(), 'INPUT_DIR_EOF');
    assert(suffix_cursor + suffix_count <= suffix_roots.len(), 'INPUT_SUFFIX_EOF');

    let recomputed_batch_root = if kind == NOTE_MEMBERSHIP_KIND_DEPOSIT {
        assert(path_count == 0, 'DEPOSIT_PATH');
        deposit_note_root(note_commitment_value)
    } else {
        assert(kind == NOTE_MEMBERSHIP_KIND_SETTLEMENT_OUTPUT, 'BAD_INPUT_KIND');
        let mut root = output_note_leaf(
            note_commitment_value, asset_id, amount, withdraw_authority,
        );
        let end = path_cursor + path_count;
        while path_cursor < end {
            let sibling = *path_values.at(path_cursor);
            let direction = *path_directions.at(path_cursor);
            if direction == 0 {
                root = output_note_node(root, sibling);
            } else {
                assert(direction == 1, 'BAD_INPUT_PATH_DIR');
                root = output_note_node(sibling, root);
            }
            path_cursor += 1;
        }
        root
    };
    assert(recomputed_batch_root == batch_root, 'INPUT_BATCH_ROOT');

    let mut root = state_transition_root(state_transition_root_domain, prefix_root, batch_root);
    let suffix_end = suffix_cursor + suffix_count;
    while suffix_cursor < suffix_end {
        root =
            state_transition_root(
                state_transition_root_domain, root, *suffix_roots.at(suffix_cursor),
            );
        suffix_cursor += 1;
    }
    assert(root == prior_note_root, 'INPUT_ROOT_MEMBERSHIP');
}

fn assert_absent_residual(
    residual_note_flag: felt252,
    residual_note_commitment: felt252,
    residual_note_asset_id: felt252,
    residual_note_amount: felt252,
    residual_note_owner_key: felt252,
    residual_note_spend_authority: felt252,
    residual_note_withdraw_authority: felt252,
    residual_note_blinding: felt252,
    residual_note_nonce: felt252,
    residual_note_metadata_commitment: felt252,
) {
    assert(residual_note_flag == 0, 'UNEXPECTED_RES');
    assert(residual_note_commitment == 0, 'UNEXPECTED_RES');
    assert(residual_note_asset_id == 0, 'UNEXPECTED_RES');
    assert(residual_note_amount == 0, 'UNEXPECTED_RES');
    assert(residual_note_owner_key == 0, 'UNEXPECTED_RES');
    assert(residual_note_spend_authority == 0, 'UNEXPECTED_RES');
    assert(residual_note_withdraw_authority == 0, 'UNEXPECTED_RES');
    assert(residual_note_blinding == 0, 'UNEXPECTED_RES');
    assert(residual_note_nonce == 0, 'UNEXPECTED_RES');
    assert(residual_note_metadata_commitment == 0, 'UNEXPECTED_RES');
}

fn assert_unique(values: Span<felt252>, message: felt252) {
    let mut left = 0;
    while left < values.len() {
        let current = *values.at(left);
        let mut right = left + 1;
        while right < values.len() {
            let other = *values.at(right);
            assert(current != other, message);
            right += 1;
        }
        left += 1;
    };
}

fn felt_to_u128(value: felt252) -> u128 {
    value.try_into().expect('U128_RANGE')
}

fn protocol_fee_root(
    domain: felt252,
    base_asset_id: felt252,
    quote_asset_id: felt252,
    base_fee_amount: u128,
    quote_fee_amount: u128,
) -> felt252 {
    let mut state = domain;
    let mut fee_count: felt252 = 0;
    if base_fee_amount != 0 {
        state = poseidon_hash2(state, base_asset_id);
        state = poseidon_hash2(state, PROTOCOL_FEE_RECIPIENT);
        state = poseidon_hash2(state, base_fee_amount.into());
        fee_count += 1;
    }
    if quote_fee_amount != 0 {
        state = poseidon_hash2(state, quote_asset_id);
        state = poseidon_hash2(state, PROTOCOL_FEE_RECIPIENT);
        state = poseidon_hash2(state, quote_fee_amount.into());
        fee_count += 1;
    }
    poseidon_hash2(state, fee_count)
}

fn poseidon_hash2(x: felt252, y: felt252) -> felt252 {
    let (result, _, _) = hades_permutation(x, y, 2);
    result
}

fn note_commitment(
    seed: felt252,
    asset_id: felt252,
    amount: felt252,
    owner_public_key: felt252,
    spend_authority: felt252,
    withdraw_authority: felt252,
    blinding: felt252,
    nonce: felt252,
    metadata_commitment: felt252,
) -> felt252 {
    let with_asset = poseidon_hash2(seed, asset_id);
    let with_amount = poseidon_hash2(with_asset, amount);
    let with_owner = poseidon_hash2(with_amount, owner_public_key);
    let with_spend_authority = poseidon_hash2(with_owner, spend_authority);
    let with_authority = poseidon_hash2(with_spend_authority, withdraw_authority);
    let with_blinding = poseidon_hash2(with_authority, blinding);
    let with_nonce = poseidon_hash2(with_blinding, nonce);
    poseidon_hash2(with_nonce, metadata_commitment)
}

fn note_nullifier(seed: felt252, note_commitment: felt252, note_secret: felt252) -> felt252 {
    poseidon_hash2(poseidon_hash2(seed, note_commitment), note_secret)
}

fn order_intent_commitment(
    seed: felt252,
    pair_id: felt252,
    batch_id: felt252,
    side: felt252,
    order_type: felt252,
    maker_curve_commitment: felt252,
    limit_price: felt252,
    amount: felt252,
    min_fill: felt252,
    time_in_force: felt252,
    expiry_epoch: felt252,
    order_nonce: felt252,
    parent_order_commitment: felt252,
    parent_child_index: felt252,
    parent_secret_commitment: felt252,
    parent_cancel_authority: felt252,
    parent_authorization_secret: felt252,
    funding_note_ref: felt252,
    funding_nullifier: felt252,
    recipient_owner_key: felt252,
    recipient_spend_authority: felt252,
    recipient_withdraw_authority: felt252,
    recipient_residual_withdraw_authority: felt252,
    auditor_view_allowed: felt252,
) -> felt252 {
    let with_pair = poseidon_hash2(seed, pair_id);
    let with_batch = poseidon_hash2(with_pair, batch_id);
    let with_side = poseidon_hash2(with_batch, side);
    let with_order_type = poseidon_hash2(with_side, order_type);
    let with_curve = poseidon_hash2(with_order_type, maker_curve_commitment);
    let with_limit = poseidon_hash2(with_curve, limit_price);
    let with_amount = poseidon_hash2(with_limit, amount);
    let with_min_fill = poseidon_hash2(with_amount, min_fill);
    let with_time_in_force = poseidon_hash2(with_min_fill, time_in_force);
    let with_expiry = poseidon_hash2(with_time_in_force, expiry_epoch);
    let with_nonce = poseidon_hash2(with_expiry, order_nonce);
    let with_parent = poseidon_hash2(with_nonce, parent_order_commitment);
    let with_parent_child = poseidon_hash2(with_parent, parent_child_index);
    let with_parent_secret = poseidon_hash2(with_parent_child, parent_secret_commitment);
    let with_parent_cancel = poseidon_hash2(with_parent_secret, parent_cancel_authority);
    let with_parent_auth = poseidon_hash2(with_parent_cancel, parent_authorization_secret);
    let with_funding_ref = poseidon_hash2(with_parent_auth, funding_note_ref);
    let with_nullifier = poseidon_hash2(with_funding_ref, funding_nullifier);
    let with_recipient = poseidon_hash2(with_nullifier, recipient_owner_key);
    let with_recipient_spend = poseidon_hash2(with_recipient, recipient_spend_authority);
    let with_withdraw_authority = poseidon_hash2(
        with_recipient_spend, recipient_withdraw_authority,
    );
    let with_residual_withdraw_authority = poseidon_hash2(
        with_withdraw_authority, recipient_residual_withdraw_authority,
    );
    poseidon_hash2(with_residual_withdraw_authority, auditor_view_allowed)
}

fn assert_parent_link(
    parent_order_commitment: felt252,
    parent_child_index: felt252,
    parent_secret_commitment: felt252,
    parent_cancel_authority: felt252,
    parent_authorization_secret: felt252,
) {
    if parent_order_commitment == 0 {
        assert(parent_child_index == 0, 'PARENT_INDEX_WITHOUT_PARENT');
        assert(parent_secret_commitment == 0, 'PARENT_SECRET_WITHOUT_PARENT');
        assert(parent_cancel_authority == 0, 'PARENT_CANCEL_WITHOUT_PARENT');
        assert(parent_authorization_secret == 0, 'PARENT_AUTH_WITHOUT_PARENT');
    } else {
        assert(parent_child_index != 0, 'PARENT_WITHOUT_INDEX');
        assert(parent_secret_commitment != 0, 'PARENT_WITHOUT_SECRET');
        assert(parent_cancel_authority != 0, 'PARENT_WITHOUT_CANCEL');
        assert(parent_authorization_secret != 0, 'PARENT_WITHOUT_AUTH');
        assert(
            renewal_parent_secret_commitment(
                parent_authorization_secret,
            ) == parent_secret_commitment,
            'PARENT_SECRET_BIND',
        );
        assert(
            renewal_parent_commitment(
                parent_secret_commitment, parent_cancel_authority,
            ) == parent_order_commitment,
            'PARENT_AUTH_BIND',
        );
    }
}

fn renewal_parent_secret_commitment(parent_authorization_secret: felt252) -> felt252 {
    poseidon_hash2(RENEWAL_PARENT_SECRET_DOMAIN, parent_authorization_secret)
}

fn renewal_parent_commitment(
    parent_secret_commitment: felt252, parent_cancel_authority: felt252,
) -> felt252 {
    let with_secret = poseidon_hash2(RENEWAL_PARENT_DOMAIN, parent_secret_commitment);
    poseidon_hash2(with_secret, parent_cancel_authority)
}

fn renewal_parent_cancel_marker(
    parent_secret_commitment: felt252, parent_cancel_authority: felt252,
) -> felt252 {
    let with_secret = poseidon_hash2(RENEWAL_PARENT_CANCEL_DOMAIN, parent_secret_commitment);
    poseidon_hash2(with_secret, parent_cancel_authority)
}

fn renewal_child_nullifier(
    parent_order_commitment: felt252,
    parent_child_index: felt252,
    parent_authorization_secret: felt252,
) -> felt252 {
    let with_parent = poseidon_hash2(RENEWAL_CHILD_NULLIFIER_DOMAIN, parent_order_commitment);
    let with_index = poseidon_hash2(with_parent, parent_child_index);
    poseidon_hash2(with_index, parent_authorization_secret)
}

fn public_settlement_commitment(
    seed: felt252,
    batch_id: felt252,
    pair_id: felt252,
    batch_epoch: felt252,
    order_commitment_root: felt252,
    encrypted_order_set_commitment: felt252,
    clearing_price: felt252,
    output_bundle_ref: felt252,
    prior_note_root: felt252,
    prior_nullifier_root: felt252,
    prior_renewal_root: felt252,
    prior_fee_root: felt252,
    consumed_note_root: felt252,
    consumed_nullifier_root: felt252,
    renewal_child_root: felt252,
    output_note_root: felt252,
    fee_root: felt252,
    new_note_root: felt252,
    new_nullifier_root: felt252,
    new_renewal_root: felt252,
    new_fee_root: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(seed, batch_id);
    state = poseidon_hash2(state, pair_id);
    state = poseidon_hash2(state, batch_epoch);
    state = poseidon_hash2(state, order_commitment_root);
    state = poseidon_hash2(state, encrypted_order_set_commitment);
    state = poseidon_hash2(state, clearing_price);
    state = poseidon_hash2(state, output_bundle_ref);
    state = poseidon_hash2(state, prior_note_root);
    state = poseidon_hash2(state, prior_nullifier_root);
    state = poseidon_hash2(state, prior_renewal_root);
    state = poseidon_hash2(state, prior_fee_root);
    state = poseidon_hash2(state, consumed_note_root);
    state = poseidon_hash2(state, consumed_nullifier_root);
    state = poseidon_hash2(state, renewal_child_root);
    state = poseidon_hash2(state, output_note_root);
    state = poseidon_hash2(state, fee_root);
    state = poseidon_hash2(state, new_note_root);
    state = poseidon_hash2(state, new_nullifier_root);
    state = poseidon_hash2(state, new_renewal_root);
    state = poseidon_hash2(state, new_fee_root);

    state
}

fn single_field_root(domain: felt252, values: Span<felt252>) -> felt252 {
    let mut state = domain;
    let mut index = 0;
    while index < values.len() {
        state = poseidon_hash2(state, *values.at(index));
        index += 1;
    }
    poseidon_hash2(state, values.len().into())
}

fn pair_field_root(domain: felt252, left: Span<felt252>, right: Span<felt252>) -> felt252 {
    assert(left.len() == right.len(), 'BAD_PAIR_ROOT_LEN');
    let mut state = domain;
    let mut index = 0;
    while index < left.len() {
        state = poseidon_hash2(state, *left.at(index));
        state = poseidon_hash2(state, *right.at(index));
        index += 1;
    }
    poseidon_hash2(state, left.len().into())
}

fn three_field_root(
    domain: felt252, first: Span<felt252>, second: Span<felt252>, third: Span<felt252>,
) -> felt252 {
    assert(first.len() == second.len(), 'BAD_THREE_ROOT_LEN');
    assert(first.len() == third.len(), 'BAD_THREE_ROOT_LEN');
    let mut state = domain;
    let mut index = 0;
    while index < first.len() {
        state = poseidon_hash2(state, *first.at(index));
        state = poseidon_hash2(state, *second.at(index));
        state = poseidon_hash2(state, *third.at(index));
        index += 1;
    }
    poseidon_hash2(state, first.len().into())
}

fn four_field_root(
    domain: felt252,
    first: Span<felt252>,
    second: Span<felt252>,
    third: Span<felt252>,
    fourth: Span<felt252>,
) -> felt252 {
    assert(first.len() == second.len(), 'BAD_FOUR_ROOT_LEN');
    assert(first.len() == third.len(), 'BAD_FOUR_ROOT_LEN');
    assert(first.len() == fourth.len(), 'BAD_FOUR_ROOT_LEN');
    let mut state = domain;
    let mut index = 0;
    while index < first.len() {
        state = poseidon_hash2(state, *first.at(index));
        state = poseidon_hash2(state, *second.at(index));
        state = poseidon_hash2(state, *third.at(index));
        state = poseidon_hash2(state, *fourth.at(index));
        index += 1;
    }
    poseidon_hash2(state, first.len().into())
}

fn output_note_merkle_root(
    output_bundle_ref: felt252,
    note_commitments: Span<felt252>,
    asset_ids: Span<felt252>,
    amounts: Span<felt252>,
    withdraw_authorities: Span<felt252>,
) -> felt252 {
    assert(note_commitments.len() == asset_ids.len(), 'BAD_OUTPUT_ROOT_LEN');
    assert(note_commitments.len() == amounts.len(), 'BAD_OUTPUT_ROOT_LEN');
    assert(note_commitments.len() == withdraw_authorities.len(), 'BAD_OUTPUT_ROOT_LEN');
    if note_commitments.len() == 0 {
        return poseidon_hash2(EMPTY_OUTPUT_NOTE_ROOT_DOMAIN, output_bundle_ref);
    }

    let mut level = array![];
    let mut index = 0;
    while index < note_commitments.len() {
        level
            .append(
                output_note_leaf(
                    *note_commitments.at(index),
                    *asset_ids.at(index),
                    *amounts.at(index),
                    *withdraw_authorities.at(index),
                ),
            );
        index += 1;
    }

    merkle_root_from_leaves(level)
}

fn assert_output_recovery_bundle(
    note_commitment_domain: felt252,
    output_bundle_ref: felt252,
    batch_id: felt252,
    output_note_root: felt252,
    note_commitments: Span<felt252>,
    asset_ids: Span<felt252>,
    amounts: Span<felt252>,
    withdraw_authorities: Span<felt252>,
    owner_keys: Span<felt252>,
    spend_authorities: Span<felt252>,
    blindings: Span<felt252>,
    nonces: Span<felt252>,
    metadata_commitments: Span<felt252>,
    recovery_key_tags: Span<felt252>,
    recovery_auth_tags: Span<felt252>,
    recovery_ciphertext_fields: Span<felt252>,
    recovery_dummy_commitments: Span<felt252>,
) {
    let mut bundle_state = OUTPUT_RECOVERY_BUNDLE_DOMAIN;
    let mut output_index: usize = 0;
    while output_index < note_commitments.len() {
        let record_commitment = assert_output_recovery_record(
            note_commitment_domain,
            batch_id,
            output_index,
            output_note_root,
            *note_commitments.at(output_index),
            *asset_ids.at(output_index),
            *amounts.at(output_index),
            *withdraw_authorities.at(output_index),
            *owner_keys.at(output_index),
            *spend_authorities.at(output_index),
            *blindings.at(output_index),
            *nonces.at(output_index),
            *metadata_commitments.at(output_index),
            *recovery_key_tags.at(output_index),
            *recovery_auth_tags.at(output_index),
            recovery_ciphertext_fields,
        );
        bundle_state = poseidon_hash2(bundle_state, record_commitment);
        output_index += 1;
    }

    let mut dummy_index: usize = 0;
    while dummy_index < recovery_dummy_commitments.len() {
        let commitment = *recovery_dummy_commitments.at(dummy_index);
        assert(commitment != 0, 'BAD_DUMMY_RECOVERY');
        bundle_state = poseidon_hash2(bundle_state, commitment);
        dummy_index += 1;
    }
    let total_count: felt252 = (note_commitments.len() + recovery_dummy_commitments.len()).into();
    assert(poseidon_hash2(bundle_state, total_count) == output_bundle_ref, 'OUTPUT_BUNDLE_BIND');
}

fn assert_output_recovery_record(
    note_commitment_domain: felt252,
    batch_id: felt252,
    output_index: usize,
    output_note_root: felt252,
    note_commitment_value: felt252,
    asset_id: felt252,
    amount: felt252,
    withdraw_authority: felt252,
    owner_key: felt252,
    spend_authority: felt252,
    blinding: felt252,
    nonce: felt252,
    metadata_commitment: felt252,
    key_tag: felt252,
    auth_tag: felt252,
    recovery_ciphertext_fields: Span<felt252>,
) -> felt252 {
    let output_index_felt: felt252 = output_index.into();
    assert(
        note_commitment_value == note_commitment(
            note_commitment_domain,
            asset_id,
            amount,
            owner_key,
            spend_authority,
            withdraw_authority,
            blinding,
            nonce,
            metadata_commitment,
        ),
        'OUTPUT_NOTE_PREIMAGE',
    );
    assert(
        key_tag == output_recovery_key_tag(spend_authority, batch_id, output_index_felt),
        'OUTPUT_RECOVERY_TAG',
    );

    let field_cursor = output_index * OUTPUT_RECOVERY_FIELD_COUNT;
    let mut field_index: usize = 0;
    let mut auth_state = poseidon_hash2(OUTPUT_RECOVERY_AUTH_DOMAIN, spend_authority);
    let mut record_state = poseidon_hash2(OUTPUT_RECOVERY_RECORD_DOMAIN, key_tag);
    let mut stream_state = output_recovery_stream_seed(
        spend_authority, batch_id, output_index_felt,
    );
    let mut plaintext_fields = array![];
    record_state = poseidon_hash2(record_state, auth_tag);
    while field_index < OUTPUT_RECOVERY_FIELD_COUNT {
        let ciphertext = *recovery_ciphertext_fields.at(field_cursor + field_index);
        stream_state = poseidon_hash2(stream_state, field_index.into());
        let plaintext = ciphertext - stream_state;
        assert_expected_output_recovery_field(
            field_index,
            plaintext,
            batch_id,
            output_index_felt,
            note_commitment_value,
            asset_id,
            amount,
            owner_key,
            spend_authority,
            withdraw_authority,
            blinding,
            nonce,
            metadata_commitment,
        );
        auth_state = poseidon_hash2(auth_state, plaintext);
        record_state = poseidon_hash2(record_state, ciphertext);
        plaintext_fields.append(plaintext);
        field_index += 1;
    }
    assert(auth_state == auth_tag, 'OUTPUT_RECOVERY_AUTH');

    assert_output_recovery_merkle_path(
        note_commitment_value,
        asset_id,
        amount,
        withdraw_authority,
        output_note_root,
        plaintext_fields.span(),
    );

    record_state
}

fn assert_expected_output_recovery_field(
    field_index: usize,
    plaintext: felt252,
    batch_id: felt252,
    output_index: felt252,
    note_commitment: felt252,
    asset_id: felt252,
    amount: felt252,
    owner_key: felt252,
    spend_authority: felt252,
    withdraw_authority: felt252,
    blinding: felt252,
    nonce: felt252,
    metadata_commitment: felt252,
) {
    if field_index == 0 {
        assert(plaintext == 1, 'RECOVERY_VERSION');
    } else if field_index == 1 {
        assert(plaintext == batch_id, 'RECOVERY_BATCH');
    } else if field_index == 2 {
        assert(plaintext == output_index, 'RECOVERY_INDEX');
    } else if field_index == 3 {
        assert(plaintext == note_commitment, 'RECOVERY_NOTE');
    } else if field_index == 4 {
        assert(plaintext == asset_id, 'RECOVERY_ASSET');
    } else if field_index == 5 {
        assert(plaintext == amount, 'RECOVERY_AMOUNT');
    } else if field_index == 6 {
        assert(plaintext == owner_key, 'RECOVERY_OWNER');
    } else if field_index == 7 {
        assert(plaintext == spend_authority, 'RECOVERY_SPEND');
    } else if field_index == 8 {
        assert(plaintext == withdraw_authority, 'RECOVERY_WITHDRAW');
    } else if field_index == 9 {
        assert(plaintext == blinding, 'RECOVERY_BLINDING');
    } else if field_index == 10 {
        assert(plaintext == nonce, 'RECOVERY_NONCE');
    } else if field_index == 11 {
        assert(plaintext == metadata_commitment, 'RECOVERY_META');
    }
}

fn assert_output_recovery_merkle_path(
    note_commitment: felt252,
    asset_id: felt252,
    amount: felt252,
    withdraw_authority: felt252,
    output_note_root: felt252,
    plaintext_fields: Span<felt252>,
) {
    let proof_len_felt = *plaintext_fields.at(12);
    let proof_len: usize = proof_len_felt.try_into().expect('RECOVERY_PROOF_LEN');
    assert(proof_len <= OUTPUT_RECOVERY_PROOF_SLOTS, 'RECOVERY_PROOF_SLOTS');
    let mut root = output_note_leaf(note_commitment, asset_id, amount, withdraw_authority);
    let mut slot: usize = 0;
    while slot < OUTPUT_RECOVERY_PROOF_SLOTS {
        let sibling_field_index = 13 + slot;
        let direction_field_index = 13 + OUTPUT_RECOVERY_PROOF_SLOTS + slot;
        let sibling = *plaintext_fields.at(sibling_field_index);
        let direction = *plaintext_fields.at(direction_field_index);
        if slot < proof_len {
            if direction == 0 {
                root = output_note_node(root, sibling);
            } else {
                assert(direction == 1, 'RECOVERY_PATH_DIR');
                root = output_note_node(sibling, root);
            }
        } else {
            assert(sibling == 0, 'RECOVERY_PATH_PAD');
            assert(direction == 0, 'RECOVERY_DIR_PAD');
        }
        slot += 1;
    }
    assert(root == output_note_root, 'RECOVERY_OUTPUT_ROOT');
}

fn output_recovery_stream_seed(
    spend_authority: felt252, batch_id: felt252, output_index: felt252,
) -> felt252 {
    let with_key = poseidon_hash2(OUTPUT_RECOVERY_STREAM_DOMAIN, spend_authority);
    let with_batch = poseidon_hash2(with_key, batch_id);
    poseidon_hash2(with_batch, output_index)
}

fn output_recovery_key_tag(
    spend_authority: felt252, batch_id: felt252, output_index: felt252,
) -> felt252 {
    let with_key = poseidon_hash2(OUTPUT_RECOVERY_TAG_DOMAIN, spend_authority);
    let with_batch = poseidon_hash2(with_key, batch_id);
    poseidon_hash2(with_batch, output_index)
}

fn output_note_leaf(
    note_commitment: felt252, asset_id: felt252, amount: felt252, withdraw_authority: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(OUTPUT_NOTE_LEAF_DOMAIN, note_commitment);
    state = poseidon_hash2(state, asset_id);
    state = poseidon_hash2(state, amount);
    poseidon_hash2(state, withdraw_authority)
}

fn output_note_node(left: felt252, right: felt252) -> felt252 {
    poseidon_hash2(poseidon_hash2(OUTPUT_NOTE_NODE_DOMAIN, left), right)
}

fn deposit_note_root(note_commitment: felt252) -> felt252 {
    poseidon_hash2(poseidon_hash2(DEPOSIT_NOTE_ROOT_DOMAIN, note_commitment), 1)
}

fn merkle_root_from_leaves(mut level: Array<felt252>) -> felt252 {
    loop {
        if level.len() == 1 {
            break;
        }

        let mut next = array![];
        let mut index = 0;
        loop {
            if index >= level.len() {
                break;
            }
            let left = *level.at(index);
            let right = if index + 1 < level.len() {
                *level.at(index + 1)
            } else {
                0
            };
            next.append(output_note_node(left, right));
            index += 2;
        }
        level = next;
    };
    *level.at(0)
}

fn state_transition_root(domain: felt252, prior_root: felt252, batch_root: felt252) -> felt252 {
    poseidon_hash2(poseidon_hash2(domain, prior_root), batch_root)
}

fn ordered_commitment_root(order_commitments: Span<felt252>) -> felt252 {
    let mut state = poseidon_hash2(
        0x40c317b270c4b0a209944388e3403aade81c19ab712f370986c555da92c6cdc,
        order_commitments.len().into(),
    );
    let mut index = 0;
    while index < order_commitments.len() {
        state = poseidon_hash2(state, *order_commitments.at(index));
        index += 1;
    }
    state
}

#[cfg(test)]
mod tests {
    use core::array::{Array, ArrayTrait};
    use super::{
        EMPTY_OUTPUT_NOTE_ROOT_DOMAIN, OUTPUT_RECOVERY_BUNDLE_DOMAIN, STATEMENT_TYPE_SETTLEMENT,
        poseidon_hash2, protocol_fee_root, public_settlement_commitment, single_field_root,
        state_transition_root, verify_settlement_statement,
    };

    #[test]
    fn settlement_statement_accepts_root_only_noop_payload() {
        let output_bundle_ref = poseidon_hash2(OUTPUT_RECOVERY_BUNDLE_DOMAIN, 0);
        let output_note_root = poseidon_hash2(EMPTY_OUTPUT_NOTE_ROOT_DOMAIN, output_bundle_ref);
        let consumed_note_root = single_field_root(0x3001, array![].span());
        let consumed_nullifier_root = single_field_root(0x3002, array![].span());
        let renewal_child_root = single_field_root(0x3003, array![].span());
        let fee_root = protocol_fee_root(0x3005, 0x2006, 0x2007, 0, 0);
        let new_note_root = state_transition_root(0x3006, 0, output_note_root);
        let new_fee_root = state_transition_root(0x3006, 0, fee_root);
        let transcript_commitment = public_settlement_commitment(
            0x1006,
            0x2001,
            0x2002,
            0x2003,
            0x2004,
            0x2005,
            0,
            output_bundle_ref,
            0,
            0,
            0,
            0,
            consumed_note_root,
            consumed_nullifier_root,
            renewal_child_root,
            output_note_root,
            fee_root,
            new_note_root,
            0,
            0,
            new_fee_root,
        );
        let payload = empty_settlement_test_payload(transcript_commitment);
        assert(
            verify_settlement_statement(payload.span()) == transcript_commitment, 'BAD_TRANSCRIPT',
        );
    }

    #[test]
    #[should_panic]
    fn settlement_statement_rejects_public_transcript_mismatch() {
        let payload = empty_settlement_test_payload(0xdead);
        verify_settlement_statement(payload.span());
    }

    fn empty_settlement_test_payload(transcript_commitment: felt252) -> Array<felt252> {
        let mut payload = array![
            STATEMENT_TYPE_SETTLEMENT, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x2001,
            0x2002, 0x2003, 0x2004, 0x2005, transcript_commitment, 0x2006, 0x2007, 0, 0,
            poseidon_hash2(OUTPUT_RECOVERY_BUNDLE_DOMAIN, 0), 0, 0, 0, 0, 0x3001, 0x3002, 0x3003,
            0x3004, 0x3005, 0x3006, 0x3007, 0x3008,
        ];
        append_empty_test_vectors(ref payload, 96);
        payload
    }

    fn append_empty_test_vectors(ref payload: Array<felt252>, count: usize) {
        let mut index = 0;
        loop {
            if index == count {
                break;
            }
            payload.append(0);
            index += 1;
        };
    }
}
