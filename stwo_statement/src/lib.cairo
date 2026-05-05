use core::array::{Array, ArrayTrait};
use core::ecdsa::check_ecdsa_signature;
use core::poseidon::hades_permutation;
use core::traits::{Into, TryInto};

const ORDER_SIDE_BUY: felt252 = 0;
const ORDER_SIDE_SELL: felt252 = 1;
const ORDER_TYPE_LIMIT_BATCH: felt252 = 0;
const ORDER_TYPE_MAKER_CURVE: felt252 = 1;
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
const STATEMENT_TYPE_SETTLEMENT: felt252 = 1;
const STATEMENT_TYPE_AUCTION: felt252 = 2;

#[executable]
fn main(input: Array<felt252>) -> felt252 {
    let data = input.span();
    assert(data.len() != 0, 'EMPTY_INPUT');
    let statement_type = *data.at(0);
    if statement_type == STATEMENT_TYPE_AUCTION {
        verify_auction_statement(data)
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
    assert(clearing_price != 0, 'BAD_PRICE');
    assert(output_bundle_ref != 0, 'BAD_OUTPUT_REF');
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
    let renewal_parent_order_commitments = read_vector(data, ref index);
    let renewal_child_nullifiers = read_vector(data, ref index);
    let output_note_commitments = read_vector(data, ref index);
    let output_note_asset_ids = read_vector(data, ref index);
    let output_note_amounts = read_vector(data, ref index);
    let output_note_withdraw_authorities = read_vector(data, ref index);
    let fee_asset_ids = read_vector(data, ref index);
    let fee_recipients = read_vector(data, ref index);
    let fee_amounts = read_vector(data, ref index);

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
            matched_parent_order_commitments.len().into(), matched_parent_child_indexes.len().into(),
            matched_parent_secret_commitments.len().into(),
            matched_parent_cancel_authorities.len().into(),
            matched_parent_authorization_secrets.len().into(),
            matched_auditor_flags.len().into(), matched_funding_note_refs.len().into(),
            matched_funding_note_commitments.len().into(),
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
        ]
            .span(),
        'BAD_WITNESS_LEN',
    );
    assert(output_note_commitments.len() == output_note_asset_ids.len(), 'BAD_OUTPUT_LEN');
    assert(output_note_commitments.len() == output_note_amounts.len(), 'BAD_OUTPUT_LEN');
    assert(
        output_note_commitments.len() == output_note_withdraw_authorities.len(), 'BAD_OUTPUT_LEN',
    );
    assert(fee_asset_ids.len() == fee_recipients.len(), 'BAD_FEE_LEN');
    assert(fee_asset_ids.len() == fee_amounts.len(), 'BAD_FEE_LEN');
    let total_curve_points = sum_curve_point_counts(matched_maker_curve_point_counts.span());
    assert(matched_maker_curve_prices.len() == total_curve_points, 'BAD_CURVE_LEN');
    assert(matched_maker_curve_base_amounts.len() == total_curve_points, 'BAD_CURVE_LEN');

    assert_unique(matched_order_commitments.span(), 'DUP_ORDER');
    assert_unique(consumed_note_commitments.span(), 'DUP_INPUT_NOTE');
    assert_unique(consumed_nullifiers.span(), 'DUP_NULLIFIER');
    assert(renewal_parent_order_commitments.len() == renewal_child_nullifiers.len(), 'BAD_RENEWAL_LEN');
    assert_unique(renewal_child_nullifiers.span(), 'DUP_RENEWAL_CHILD');
    assert_unique(output_note_commitments.span(), 'DUP_OUTPUT');

    let clearing_price_u128 = felt_to_u128(clearing_price);
    let mut index_order = 0;
    let mut public_output_index = 0;
    let mut total_buy_base: u128 = 0;
    let mut total_sell_base: u128 = 0;
    let mut expected_base_fee: u128 = 0;
    let mut expected_quote_fee: u128 = 0;
    let mut curve_cursor = 0;
    let mut renewal_cursor = 0;

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
                *renewal_child_nullifiers.at(renewal_cursor) == renewal_child_nullifier(
                    parent_order_commitment, parent_child_index, parent_authorization_secret,
                ),
                'RENEWAL_CHILD_BIND',
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
            check_ecdsa_signature(
                order_commitment,
                funding_note_spend_authority,
                funding_authorization_r,
                funding_authorization_s,
            ),
            'ORDER_AUTH_SIG',
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

        assert_public_output(
            public_output_index,
            output_note_commitment,
            output_note_asset_id,
            output_note_amount,
            output_note_withdraw_authority,
            output_note_commitments.span(),
            output_note_asset_ids.span(),
            output_note_amounts.span(),
            output_note_withdraw_authorities.span(),
        );
        public_output_index += 1;
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
            assert(output_note_amount == filled_amount - fee_amount, 'BUY_FEE_POLICY');

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
            assert(output_note_amount == gross_quote - fee_amount, 'SELL_FEE_POLICY');

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
            assert(residual_note_amount_felt == expected_residual_amount.into(), 'BAD_RES_AMOUNT');
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
            assert_public_output(
                public_output_index,
                residual_note_commitment,
                residual_note_asset_id,
                expected_residual_amount,
                residual_note_withdraw_authority,
                output_note_commitments.span(),
                output_note_asset_ids.span(),
                output_note_amounts.span(),
                output_note_withdraw_authorities.span(),
            );
            public_output_index += 1;
        }

        index_order += 1;
    }
    assert(renewal_cursor == renewal_child_nullifiers.len(), 'RENEWAL_CURSOR');

    assert(public_output_index == output_note_commitments.len(), 'OUTPUT_CURSOR');
    assert(total_buy_base == total_sell_base, 'BASE_IMBALANCE');

    let (actual_base_fee, actual_quote_fee) = aggregate_fees(
        base_asset_id,
        quote_asset_id,
        PROTOCOL_FEE_RECIPIENT,
        fee_asset_ids.span(),
        fee_recipients.span(),
        fee_amounts.span(),
    );
    assert(actual_base_fee == expected_base_fee, 'BASE_FEE');
    assert(actual_quote_fee == expected_quote_fee, 'QUOTE_FEE');

    let recomputed_public_settlement = public_settlement_commitment(
        public_settlement_domain,
        batch_id,
        pair_id,
        batch_epoch,
        order_commitment_root,
        encrypted_order_set_commitment,
        clearing_price,
        output_bundle_ref,
        consumed_note_commitments.span(),
        consumed_nullifiers.span(),
        renewal_parent_order_commitments.span(),
        renewal_child_nullifiers.span(),
        output_note_commitments.span(),
        output_note_asset_ids.span(),
        output_note_amounts.span(),
        output_note_withdraw_authorities.span(),
        fee_asset_ids.span(),
        fee_recipients.span(),
        fee_amounts.span(),
    );
    assert(recomputed_public_settlement == transcript_commitment, 'PUBLIC_SETTLEMENT_BIND');

    assert(curve_cursor == total_curve_points, 'CURVE_CURSOR');
    assert(index == data.len(), 'TRAILING_INPUT');

    transcript_commitment
}

pub fn verify_auction_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_AUCTION, 'BAD_AUCTION_TYPE');

    let settlement_payload = read_vector(data, ref index);
    let transcript_commitment = verify_settlement_statement(settlement_payload.span());
    let order_commitment_root = settlement_order_commitment_root(settlement_payload.span());
    let clearing_price = settlement_clearing_price(settlement_payload.span());
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
    let matched_order_commitments = settlement_matched_order_commitments(settlement_payload.span());
    let matched_fill_amounts = settlement_matched_fill_amounts(settlement_payload.span());
    let clearing_price_u128 = felt_to_u128(clearing_price);

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
    let allocation_fill_amounts = read_vector(data, ref index);

    assert(order_commitments.len() != 0, 'EMPTY_AUCTION');
    assert_all_lengths_match(
        order_commitments.len(),
        array![
            sides.len().into(), order_types.len().into(), maker_curve_commitments.len().into(),
            maker_curve_point_counts.len().into(), limit_prices.len().into(),
            order_amounts.len().into(), min_fills.len().into(), time_in_force.len().into(),
            expiry_epochs.len().into(), order_nonces.len().into(), auditor_flags.len().into(),
            parent_order_commitments.len().into(), parent_child_indexes.len().into(),
            parent_secret_commitments.len().into(), parent_cancel_authorities.len().into(),
            parent_authorization_secrets.len().into(),
            funding_note_refs.len().into(), funding_note_commitments.len().into(),
            funding_note_asset_ids.len().into(), funding_note_amounts.len().into(),
            funding_note_owner_keys.len().into(), funding_note_spend_authorities.len().into(),
            funding_note_withdraw_authorities.len().into(), funding_note_blindings.len().into(),
            funding_note_nonces.len().into(), funding_note_metadata_commitments.len().into(),
            funding_authorization_rs.len().into(), funding_authorization_ss.len().into(),
            funding_nullifiers.len().into(), recipient_owner_keys.len().into(),
            recipient_spend_authorities.len().into(), recipient_withdraw_authorities.len().into(),
            res_auths_span.len().into(), allocation_fill_amounts.len().into(),
        ]
            .span(),
        'BAD_AUCTION_LEN',
    );
    let total_curve_points = sum_curve_point_counts(maker_curve_point_counts.span());
    assert(maker_curve_prices.len() == total_curve_points, 'BAD_AUCTION_CURVES');
    assert(maker_curve_base_amounts.len() == total_curve_points, 'BAD_AUCTION_CURVES');
    assert_unique(order_commitments.span(), 'DUP_AUCTION_ORDER');
    assert(
        ordered_commitment_root(order_commitments.span()) == order_commitment_root,
        'AUCTION_ROOT_BIND',
    );

    assert_auction_order_preimages(
        clearing_price_u128,
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

    assert(index == data.len(), 'TRAILING_AUCTION_INPUT');
    transcript_commitment
}

fn settlement_clearing_price(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 15, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    *settlement_payload.at(15)
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
    assert(settlement_payload.len() > 18, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    let mut index: usize = 18;
    read_vector(settlement_payload, ref index)
}

fn settlement_matched_fill_amounts(settlement_payload: Span<felt252>) -> Array<felt252> {
    assert(settlement_payload.len() > 18, 'BAD_SETTLEMENT_HEADER');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'BAD_STMT_TYPE');
    let mut index: usize = 18;
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
            order_type == ORDER_TYPE_LIMIT_BATCH || order_type == ORDER_TYPE_MAKER_CURVE,
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
        assert(funding_note_ref != 0, 'BAD_FUNDING_REF');
        assert(funding_note_commitment != 0, 'BAD_FUNDING_NOTE');
        assert(funding_note_owner_key != 0, 'BAD_FUNDING_OWNER');
        assert(funding_note_spend_authority != 0, 'BAD_FUNDING_SPEND');
        assert(funding_note_withdraw_authority != 0, 'BAD_FUNDING_AUTH');
        assert(funding_note_blinding != 0, 'BAD_FUNDING_BLIND');
        assert(funding_note_metadata_commitment != 0, 'BAD_FUNDING_META');
        assert(funding_authorization_r != 0, 'BAD_AUTH_R');
        assert(funding_authorization_s != 0, 'BAD_AUTH_S');
        assert(funding_nullifier != 0, 'BAD_NULLIFIER');
        assert(recipient_owner_key != 0, 'BAD_RECIPIENT');
        assert(recipient_spend_authority != 0, 'BAD_RECIPIENT_SPEND');
        assert(recipient_withdraw_authority != 0, 'BAD_RECIPIENT_AUTH');
        assert(recipient_residual_withdraw_authority != 0, 'BAD_RES_AUTH');
        assert(funding_note_amount != 0, 'BAD_FUNDS');
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
        if side == ORDER_SIDE_BUY {
            assert(funding_note_asset_id == quote_asset_id, 'BUY_INPUT_ASSET');
        } else {
            assert(funding_note_asset_id == base_asset_id, 'SELL_INPUT_ASSET');
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
        assert(funding_note_commitment == recomputed_funding_note_commitment, 'AUCTION_NOTE_BIND');
        assert(funding_note_ref == funding_note_commitment, 'AUCTION_REF_BIND');
        assert(
            check_ecdsa_signature(
                order_commitment,
                funding_note_spend_authority,
                funding_authorization_r,
                funding_authorization_s,
            ),
            'AUCTION_AUTH_SIG',
        );
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
        if *order_types.at(order_index) == ORDER_TYPE_MAKER_CURVE {
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

fn assert_public_output(
    output_index: usize,
    expected_commitment: felt252,
    expected_asset_id: felt252,
    expected_amount: u128,
    expected_withdraw_authority: felt252,
    output_note_commitments: Span<felt252>,
    output_note_asset_ids: Span<felt252>,
    output_note_amounts: Span<felt252>,
    output_note_withdraw_authorities: Span<felt252>,
) {
    assert(output_index < output_note_commitments.len(), 'OUTPUT_EOF');
    assert(expected_commitment == *output_note_commitments.at(output_index), 'OUTPUT_MISMATCH');
    assert(expected_asset_id == *output_note_asset_ids.at(output_index), 'OUTPUT_ASSET_MISMATCH');
    assert(
        expected_amount == felt_to_u128(*output_note_amounts.at(output_index)),
        'OUTPUT_AMOUNT_MISMATCH',
    );
    assert(
        expected_withdraw_authority == *output_note_withdraw_authorities.at(output_index),
        'OUTPUT_AUTH_MISMATCH',
    );
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

fn aggregate_fees(
    base_asset_id: felt252,
    quote_asset_id: felt252,
    expected_recipient: felt252,
    fee_asset_ids: Span<felt252>,
    fee_recipients: Span<felt252>,
    fee_amounts: Span<felt252>,
) -> (u128, u128) {
    let mut base_fee_total: u128 = 0;
    let mut quote_fee_total: u128 = 0;
    let mut index = 0;

    while index < fee_asset_ids.len() {
        let asset_id = *fee_asset_ids.at(index);
        let recipient = *fee_recipients.at(index);
        let amount = felt_to_u128(*fee_amounts.at(index));

        assert(recipient == expected_recipient, 'BAD_FEE_RECIPIENT');
        if asset_id == base_asset_id {
            base_fee_total = base_fee_total + amount;
        } else {
            assert(asset_id == quote_asset_id, 'BAD_FEE_ASSET');
            quote_fee_total = quote_fee_total + amount;
        }

        index += 1;
    }

    (base_fee_total, quote_fee_total)
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
            renewal_parent_secret_commitment(parent_authorization_secret) == parent_secret_commitment,
            'PARENT_SECRET_BIND',
        );
        assert(
            renewal_parent_commitment(parent_secret_commitment, parent_cancel_authority)
                == parent_order_commitment,
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
    consumed_note_commitments: Span<felt252>,
    consumed_nullifiers: Span<felt252>,
    renewal_parent_order_commitments: Span<felt252>,
    renewal_child_nullifiers: Span<felt252>,
    output_note_commitments: Span<felt252>,
    output_note_asset_ids: Span<felt252>,
    output_note_amounts: Span<felt252>,
    output_note_withdraw_authorities: Span<felt252>,
    fee_asset_ids: Span<felt252>,
    fee_recipients: Span<felt252>,
    fee_amounts: Span<felt252>,
) -> felt252 {
    let mut state = poseidon_hash2(seed, batch_id);
    state = poseidon_hash2(state, pair_id);
    state = poseidon_hash2(state, batch_epoch);
    state = poseidon_hash2(state, order_commitment_root);
    state = poseidon_hash2(state, encrypted_order_set_commitment);
    state = poseidon_hash2(state, clearing_price);
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
        state = poseidon_hash2(state, *output_note_amounts.at(index));
        state = poseidon_hash2(state, *output_note_withdraw_authorities.at(index));
        index += 1;
    }

    state = poseidon_hash2(state, fee_asset_ids.len().into());
    index = 0;
    while index < fee_asset_ids.len() {
        state = poseidon_hash2(state, *fee_asset_ids.at(index));
        state = poseidon_hash2(state, *fee_recipients.at(index));
        state = poseidon_hash2(state, *fee_amounts.at(index));
        index += 1;
    }

    state
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
