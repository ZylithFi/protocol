use core::array::{Array, ArrayTrait};
use core::poseidon::hades_permutation;
use core::traits::{Into, TryInto};

const ORDER_SIDE_BUY: felt252 = 0;
const ORDER_SIDE_SELL: felt252 = 1;

#[executable]
fn main(input: Array<felt252>) -> felt252 {
    let data = input.span();
    let mut index: usize = 0;

    let schema_version = read_next(data, ref index);
    assert(schema_version == 5, 'BAD_VERSION');

    let note_commitment_domain = read_next(data, ref index);
    let order_commitment_domain = read_next(data, ref index);
    let public_settlement_domain = read_next(data, ref index);
    let batch_id = read_next(data, ref index);
    let transcript_commitment = read_next(data, ref index);
    let pair_id = read_next(data, ref index);
    let base_asset_id = read_next(data, ref index);
    let quote_asset_id = read_next(data, ref index);
    let clearing_price = read_next(data, ref index);
    let matched_order_count = read_next(data, ref index);
    let output_bundle_ref = read_next(data, ref index);

    assert(note_commitment_domain != 0, 'BAD_NOTE_DOMAIN');
    assert(order_commitment_domain != 0, 'BAD_ORDER_DOMAIN');
    assert(public_settlement_domain != 0, 'BAD_SETTLEMENT_DOMAIN');
    assert(batch_id != 0, 'BAD_BATCH');
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
    let matched_limit_prices = read_vector(data, ref index);
    let matched_order_amounts = read_vector(data, ref index);
    let matched_min_fills = read_vector(data, ref index);
    let matched_expiry_epochs = read_vector(data, ref index);
    let matched_order_nonces = read_vector(data, ref index);
    let matched_auditor_flags = read_vector(data, ref index);
    let matched_funding_note_refs = read_vector(data, ref index);
    let matched_funding_note_commitments = read_vector(data, ref index);
    let matched_funding_note_asset_ids = read_vector(data, ref index);
    let matched_funding_note_amounts = read_vector(data, ref index);
    let matched_funding_note_owner_keys = read_vector(data, ref index);
    let matched_funding_note_withdraw_authorities = read_vector(data, ref index);
    let matched_funding_note_blindings = read_vector(data, ref index);
    let matched_funding_note_nonces = read_vector(data, ref index);
    let matched_funding_note_metadata_commitments = read_vector(data, ref index);
    let matched_funding_nullifiers = read_vector(data, ref index);
    let matched_recipient_owner_keys = read_vector(data, ref index);
    let matched_recipient_withdraw_authorities = read_vector(data, ref index);
    let matched_output_note_commitments = read_vector(data, ref index);
    let matched_output_note_asset_ids = read_vector(data, ref index);
    let matched_output_note_amounts = read_vector(data, ref index);
    let matched_output_note_owner_keys = read_vector(data, ref index);
    let matched_output_note_withdraw_authorities = read_vector(data, ref index);
    let matched_output_note_blindings = read_vector(data, ref index);
    let matched_output_note_nonces = read_vector(data, ref index);
    let matched_output_note_metadata_commitments = read_vector(data, ref index);

    let consumed_note_commitments = read_vector(data, ref index);
    let consumed_nullifiers = read_vector(data, ref index);
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
            matched_fill_amounts.len().into(),
            matched_sides.len().into(),
            matched_limit_prices.len().into(),
            matched_order_amounts.len().into(),
            matched_min_fills.len().into(),
            matched_expiry_epochs.len().into(),
            matched_order_nonces.len().into(),
            matched_auditor_flags.len().into(),
            matched_funding_note_refs.len().into(),
            matched_funding_note_commitments.len().into(),
            matched_funding_note_asset_ids.len().into(),
            matched_funding_note_amounts.len().into(),
            matched_funding_note_owner_keys.len().into(),
            matched_funding_note_withdraw_authorities.len().into(),
            matched_funding_note_blindings.len().into(),
            matched_funding_note_nonces.len().into(),
            matched_funding_note_metadata_commitments.len().into(),
            matched_funding_nullifiers.len().into(),
            matched_recipient_owner_keys.len().into(),
            matched_recipient_withdraw_authorities.len().into(),
            matched_output_note_commitments.len().into(),
            matched_output_note_asset_ids.len().into(),
            matched_output_note_amounts.len().into(),
            matched_output_note_owner_keys.len().into(),
            matched_output_note_withdraw_authorities.len().into(),
            matched_output_note_blindings.len().into(),
            matched_output_note_nonces.len().into(),
            matched_output_note_metadata_commitments.len().into(),
            consumed_note_commitments.len().into(),
            consumed_nullifiers.len().into(),
            output_note_commitments.len().into(),
            output_note_asset_ids.len().into(),
            output_note_amounts.len().into(),
            output_note_withdraw_authorities.len().into(),
        ]
            .span(),
        'BAD_WITNESS_LEN',
    );
    assert(fee_asset_ids.len() == fee_recipients.len(), 'BAD_FEE_LEN');
    assert(fee_asset_ids.len() == fee_amounts.len(), 'BAD_FEE_LEN');

    assert_unique(matched_order_commitments.span(), 'DUP_ORDER');
    assert_unique(consumed_nullifiers.span(), 'DUP_NULLIFIER');
    assert_unique(output_note_commitments.span(), 'DUP_OUTPUT');

    let clearing_price_u128 = felt_to_u128(clearing_price);
    let mut index_order = 0;
    let mut total_buy_base: u128 = 0;
    let mut total_sell_base: u128 = 0;
    let mut expected_base_fee: u128 = 0;
    let mut expected_quote_fee: u128 = 0;

    while index_order < matched_order_commitments.len() {
        let order_commitment = *matched_order_commitments.at(index_order);
        let filled_amount_felt = *matched_fill_amounts.at(index_order);
        let side = *matched_sides.at(index_order);
        let limit_price_felt = *matched_limit_prices.at(index_order);
        let order_amount_felt = *matched_order_amounts.at(index_order);
        let min_fill_felt = *matched_min_fills.at(index_order);
        let expiry_epoch_felt = *matched_expiry_epochs.at(index_order);
        let order_nonce_felt = *matched_order_nonces.at(index_order);
        let auditor_view_allowed = *matched_auditor_flags.at(index_order);
        let funding_note_ref = *matched_funding_note_refs.at(index_order);
        let funding_note_commitment = *matched_funding_note_commitments.at(index_order);
        let funding_note_asset_id = *matched_funding_note_asset_ids.at(index_order);
        let funding_note_amount_felt = *matched_funding_note_amounts.at(index_order);
        let funding_note_owner_key = *matched_funding_note_owner_keys.at(index_order);
        let funding_note_withdraw_authority =
            *matched_funding_note_withdraw_authorities.at(index_order);
        let funding_note_blinding = *matched_funding_note_blindings.at(index_order);
        let funding_note_nonce_felt = *matched_funding_note_nonces.at(index_order);
        let funding_note_metadata_commitment =
            *matched_funding_note_metadata_commitments.at(index_order);
        let funding_nullifier = *matched_funding_nullifiers.at(index_order);
        let recipient_owner_key = *matched_recipient_owner_keys.at(index_order);
        let recipient_withdraw_authority =
            *matched_recipient_withdraw_authorities.at(index_order);
        let output_note_commitment = *matched_output_note_commitments.at(index_order);
        let output_note_asset_id = *matched_output_note_asset_ids.at(index_order);
        let output_note_amount_felt = *matched_output_note_amounts.at(index_order);
        let output_note_owner_key = *matched_output_note_owner_keys.at(index_order);
        let output_note_withdraw_authority =
            *matched_output_note_withdraw_authorities.at(index_order);
        let output_note_blinding = *matched_output_note_blindings.at(index_order);
        let output_note_nonce_felt = *matched_output_note_nonces.at(index_order);
        let output_note_metadata_commitment =
            *matched_output_note_metadata_commitments.at(index_order);

        let filled_amount = felt_to_u128(filled_amount_felt);
        let limit_price = felt_to_u128(limit_price_felt);
        let order_amount = felt_to_u128(order_amount_felt);
        let min_fill = felt_to_u128(min_fill_felt);
        let funding_note_amount = felt_to_u128(funding_note_amount_felt);
        let output_note_amount = felt_to_u128(output_note_amount_felt);

        assert(order_commitment != 0, 'BAD_ORDER');
        assert(filled_amount_felt != 0, 'ZERO_FILL');
        assert(order_amount_felt != 0, 'ZERO_ORDER');
        assert(min_fill_felt != 0, 'ZERO_MIN_FILL');
        assert(funding_note_commitment != 0, 'BAD_INPUT_NOTE');
        assert(output_note_commitment != 0, 'BAD_OUTPUT_NOTE');
        assert(funding_note_owner_key != 0, 'BAD_INPUT_OWNER');
        assert(funding_note_withdraw_authority != 0, 'BAD_INPUT_AUTH');
        assert(recipient_owner_key != 0, 'BAD_RECIPIENT');
        assert(recipient_withdraw_authority != 0, 'BAD_WITHDRAW_AUTH');
        assert(output_note_owner_key != 0, 'BAD_OUTPUT_OWNER');
        assert(output_note_withdraw_authority != 0, 'BAD_OUTPUT_AUTH');
        assert(funding_note_blinding != 0, 'BAD_INPUT_BLIND');
        assert(output_note_blinding != 0, 'BAD_OUTPUT_BLIND');
        assert(funding_note_metadata_commitment != 0, 'BAD_INPUT_META');
        assert(output_note_metadata_commitment != 0, 'BAD_OUTPUT_META');
        assert(funding_nullifier != 0, 'BAD_NULLIFIER');
        assert(output_note_amount_felt != 0, 'ZERO_OUTPUT');
        assert(expiry_epoch_felt != 0, 'ZERO_EXPIRY');
        assert(order_nonce_felt != 0, 'ZERO_NONCE');
        assert(auditor_view_allowed == 0 || auditor_view_allowed == 1, 'BAD_AUDITOR');
        assert(filled_amount <= order_amount, 'FILL_GT_ORDER');
        assert(filled_amount >= min_fill, 'FILL_LT_MIN');

        let recomputed_order_commitment = order_intent_commitment(
            order_commitment_domain,
            pair_id,
            side,
            limit_price_felt,
            order_amount_felt,
            min_fill_felt,
            expiry_epoch_felt,
            order_nonce_felt,
            funding_note_ref,
            funding_nullifier,
            recipient_owner_key,
            recipient_withdraw_authority,
            auditor_view_allowed,
        );
        assert(order_commitment == recomputed_order_commitment, 'ORDER_BIND');

        let recomputed_funding_note_commitment = note_commitment(
            note_commitment_domain,
            funding_note_asset_id,
            funding_note_amount_felt,
            funding_note_owner_key,
            funding_note_withdraw_authority,
            funding_note_blinding,
            funding_note_nonce_felt,
            funding_note_metadata_commitment,
        );
        assert(funding_note_commitment == recomputed_funding_note_commitment, 'INPUT_NOTE_BIND');
        assert(funding_note_ref == funding_note_commitment, 'INPUT_REF_MISMATCH');

        let recomputed_output_note_commitment = note_commitment(
            note_commitment_domain,
            output_note_asset_id,
            output_note_amount_felt,
            output_note_owner_key,
            output_note_withdraw_authority,
            output_note_blinding,
            output_note_nonce_felt,
            output_note_metadata_commitment,
        );
        assert(output_note_commitment == recomputed_output_note_commitment, 'OUTPUT_NOTE_BIND');

        assert(funding_note_commitment == *consumed_note_commitments.at(index_order), 'INPUT_MISMATCH');
        assert(funding_nullifier == *consumed_nullifiers.at(index_order), 'NULLIFIER_MISMATCH');

        assert(output_note_commitment == *output_note_commitments.at(index_order), 'OUTPUT_MISMATCH');
        assert(output_note_asset_id == *output_note_asset_ids.at(index_order), 'OUTPUT_ASSET_MISMATCH');
        assert(output_note_amount == felt_to_u128(*output_note_amounts.at(index_order)), 'OUTPUT_AMOUNT_MISMATCH');
        assert(output_note_withdraw_authority == *output_note_withdraw_authorities.at(index_order), 'OUTPUT_AUTH_MISMATCH');
        assert(output_note_owner_key == recipient_owner_key, 'OUTPUT_RECIPIENT');
        assert(output_note_withdraw_authority == recipient_withdraw_authority, 'OUTPUT_WITHDRAW_AUTH');

        if side == ORDER_SIDE_BUY {
            assert(limit_price >= clearing_price_u128, 'BUY_LIMIT');
            assert(funding_note_asset_id == quote_asset_id, 'BUY_INPUT_ASSET');
            assert(output_note_asset_id == base_asset_id, 'BUY_OUTPUT_ASSET');

            let spend_amount = filled_amount * clearing_price_u128;
            assert(funding_note_amount >= spend_amount, 'BUY_FUNDS');
            assert(output_note_amount <= filled_amount, 'BUY_OUTPUT_GT_FILL');

            total_buy_base = total_buy_base + filled_amount;
            expected_base_fee = expected_base_fee + (filled_amount - output_note_amount);
        } else {
            assert(side == ORDER_SIDE_SELL, 'BAD_SIDE');
            assert(limit_price <= clearing_price_u128, 'SELL_LIMIT');
            assert(funding_note_asset_id == base_asset_id, 'SELL_INPUT_ASSET');
            assert(output_note_asset_id == quote_asset_id, 'SELL_OUTPUT_ASSET');
            assert(funding_note_amount >= filled_amount, 'SELL_FUNDS');

            let gross_quote = filled_amount * clearing_price_u128;
            assert(output_note_amount <= gross_quote, 'SELL_OUTPUT_GT_GROSS');

            total_sell_base = total_sell_base + filled_amount;
            expected_quote_fee = expected_quote_fee + (gross_quote - output_note_amount);
        };

        index_order += 1;
    };

    assert(total_buy_base == total_sell_base, 'BASE_IMBALANCE');

    let (actual_base_fee, actual_quote_fee) = aggregate_fees(
        base_asset_id,
        quote_asset_id,
        fee_asset_ids.span(),
        fee_recipients.span(),
        fee_amounts.span(),
    );
    assert(actual_base_fee == expected_base_fee, 'BASE_FEE');
    assert(actual_quote_fee == expected_quote_fee, 'QUOTE_FEE');

    let recomputed_public_settlement = public_settlement_commitment(
        public_settlement_domain,
        batch_id,
        clearing_price,
        output_bundle_ref,
        consumed_note_commitments.span(),
        consumed_nullifiers.span(),
        output_note_commitments.span(),
        output_note_asset_ids.span(),
        output_note_amounts.span(),
        output_note_withdraw_authorities.span(),
        fee_asset_ids.span(),
        fee_recipients.span(),
        fee_amounts.span(),
    );
    assert(recomputed_public_settlement == transcript_commitment, 'PUBLIC_SETTLEMENT_BIND');

    assert(index == data.len(), 'TRAILING_INPUT');

    matched_order_count
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
    };

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

fn assert_unique(values: Span<felt252>, message: felt252) {
    let mut left = 0;
    while left < values.len() {
        let current = *values.at(left);
        let mut right = left + 1;
        while right < values.len() {
            let other = *values.at(right);
            assert(current != other, message);
            right += 1;
        };
        left += 1;
    };
}

fn felt_to_u128(value: felt252) -> u128 {
    value.try_into().expect('U128_RANGE')
}

fn aggregate_fees(
    base_asset_id: felt252,
    quote_asset_id: felt252,
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

        assert(recipient != 0, 'BAD_RECIPIENT');
        if asset_id == base_asset_id {
            base_fee_total = base_fee_total + amount;
        } else {
            assert(asset_id == quote_asset_id, 'BAD_FEE_ASSET');
            quote_fee_total = quote_fee_total + amount;
        };

        index += 1;
    };

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
    withdraw_authority: felt252,
    blinding: felt252,
    nonce: felt252,
    metadata_commitment: felt252,
) -> felt252 {
    let with_asset = poseidon_hash2(seed, asset_id);
    let with_amount = poseidon_hash2(with_asset, amount);
    let with_owner = poseidon_hash2(with_amount, owner_public_key);
    let with_authority = poseidon_hash2(with_owner, withdraw_authority);
    let with_blinding = poseidon_hash2(with_authority, blinding);
    let with_nonce = poseidon_hash2(with_blinding, nonce);
    poseidon_hash2(with_nonce, metadata_commitment)
}

fn order_intent_commitment(
    seed: felt252,
    pair_id: felt252,
    side: felt252,
    limit_price: felt252,
    amount: felt252,
    min_fill: felt252,
    expiry_epoch: felt252,
    order_nonce: felt252,
    funding_note_ref: felt252,
    funding_nullifier: felt252,
    recipient_owner_key: felt252,
    recipient_withdraw_authority: felt252,
    auditor_view_allowed: felt252,
) -> felt252 {
    let with_pair = poseidon_hash2(seed, pair_id);
    let with_side = poseidon_hash2(with_pair, side);
    let with_limit = poseidon_hash2(with_side, limit_price);
    let with_amount = poseidon_hash2(with_limit, amount);
    let with_min_fill = poseidon_hash2(with_amount, min_fill);
    let with_expiry = poseidon_hash2(with_min_fill, expiry_epoch);
    let with_nonce = poseidon_hash2(with_expiry, order_nonce);
    let with_funding_ref = poseidon_hash2(with_nonce, funding_note_ref);
    let with_nullifier = poseidon_hash2(with_funding_ref, funding_nullifier);
    let with_recipient = poseidon_hash2(with_nullifier, recipient_owner_key);
    let with_withdraw_authority = poseidon_hash2(with_recipient, recipient_withdraw_authority);
    poseidon_hash2(with_withdraw_authority, auditor_view_allowed)
}

fn public_settlement_commitment(
    seed: felt252,
    batch_id: felt252,
    clearing_price: felt252,
    output_bundle_ref: felt252,
    consumed_note_commitments: Span<felt252>,
    consumed_nullifiers: Span<felt252>,
    output_note_commitments: Span<felt252>,
    output_note_asset_ids: Span<felt252>,
    output_note_amounts: Span<felt252>,
    output_note_withdraw_authorities: Span<felt252>,
    fee_asset_ids: Span<felt252>,
    fee_recipients: Span<felt252>,
    fee_amounts: Span<felt252>,
) -> felt252 {
    let mut state = poseidon_hash2(seed, batch_id);
    state = poseidon_hash2(state, clearing_price);
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
        state = poseidon_hash2(state, *output_note_amounts.at(index));
        state = poseidon_hash2(state, *output_note_withdraw_authorities.at(index));
        index += 1;
    };

    index = 0;
    while index < fee_asset_ids.len() {
        state = poseidon_hash2(state, *fee_asset_ids.at(index));
        state = poseidon_hash2(state, *fee_recipients.at(index));
        state = poseidon_hash2(state, *fee_amounts.at(index));
        index += 1;
    };

    state
}
