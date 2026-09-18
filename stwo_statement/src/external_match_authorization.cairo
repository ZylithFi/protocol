use core::array::{Array, ArrayTrait};
use core::ecdsa::check_ecdsa_signature;
use core::integer::u256;
use core::traits::{Into, TryInto};
use super::{
    EXECUTION_PRIVATE_THEN_EXTERNAL, FEE_BPS_DENOMINATOR, ORDER_SIDE_BUY, ORDER_SIDE_SELL,
    REFERENCE_PRICE_ATTESTATION_DOMAIN, assert_pair_config, felt_to_u128, length_prefixed_payload,
    multi_pair_payload_chosen_fill_vectors, multi_pair_payload_eligible_order_commitments,
    poseidon_hash2, reference_price_attestation_commitment, verify_multi_pair_statement,
};

const STATEMENT_TYPE_EXTERNAL_MATCH_AUTHORIZATION: felt252 = 10;
const EXTERNAL_MATCH_REQUEST_DOMAIN: felt252 =
    0x5a142e8c2ea142e1782d243178a45254a2bcdb574541586ce831596e11fb84b;
const EXTERNAL_MATCH_ORDER_LEAF_DOMAIN: felt252 =
    0x172f93ebaa2a166d465999477e5bb4f0f1b127de1a310e710c9310a840a5c2e;
const EXTERNAL_MATCH_AUTHORIZATION_DOMAIN: felt252 =
    0x4944e3edf8c94cdca9ba99f3c9c626587e0f5108b1d4428ff2c8f23ceb69ed7;
const EXTERNAL_MATCH_REQUEST_LEAF_DOMAIN: felt252 =
    0x20fb26bf6509d9087ab80295aca27ea56e22e440ffb6b50d276fc8d2fcf51d2;
const MAX_EXTERNAL_MATCH_ORDERS: usize = 64;
const MAX_EXTERNAL_MATCH_REQUESTS: usize = 16;

pub fn verify_external_match_authorization_statement(
    data: Span<felt252>,
) -> (felt252, felt252, felt252, felt252) {
    let mut index: usize = 0;
    assert(read_next(data, ref index) == STATEMENT_TYPE_EXTERNAL_MATCH_AUTHORIZATION, 'EMA_TYPE');
    let batch_id = read_next(data, ref index);
    let auction_verifier_address = read_next(data, ref index);
    let reference_price_signer = read_next(data, ref index);
    let claimed_multi_pair_commitment = read_next(data, ref index);
    let claimed_request_root = read_next(data, ref index);
    assert(batch_id != 0, 'EMA_BATCH');
    assert(auction_verifier_address != 0, 'EMA_VERIFIER');
    assert(reference_price_signer != 0, 'EMA_SIGNER');

    let nested_serialized = read_vector(data, ref index);
    let order_commitments = read_vector(data, ref index);
    let order_pair_ids = read_vector(data, ref index);
    let order_base_asset_ids = read_vector(data, ref index);
    let order_quote_asset_ids = read_vector(data, ref index);
    let order_sides = read_vector(data, ref index);
    let order_submitted_base_amounts = read_vector(data, ref index);
    let order_min_fill_base_amounts = read_vector(data, ref index);
    let order_limit_prices = read_vector(data, ref index);
    let order_price_base_scales = read_vector(data, ref index);
    let order_available_input_amounts = read_vector(data, ref index);
    let order_taker_fee_bps = read_vector(data, ref index);
    let order_execution_preferences = read_vector(data, ref index);

    let attestation_pair_ids = read_vector(data, ref index);
    let attestation_base_asset_ids = read_vector(data, ref index);
    let attestation_quote_asset_ids = read_vector(data, ref index);
    let attestation_midpoints = read_vector(data, ref index);
    let attestation_lowers = read_vector(data, ref index);
    let attestation_uppers = read_vector(data, ref index);
    let attestation_price_base_scales = read_vector(data, ref index);
    let attestation_source_counts = read_vector(data, ref index);
    let attestation_observed_at_values = read_vector(data, ref index);
    let attestation_source_set_commitments = read_vector(data, ref index);
    let attestation_valid_until_values = read_vector(data, ref index);
    let attestation_nonces = read_vector(data, ref index);
    let attestation_signers = read_vector(data, ref index);
    let attestation_signature_rs = read_vector(data, ref index);
    let attestation_signature_ss = read_vector(data, ref index);

    let request_ids = read_vector(data, ref index);
    let request_pair_ids = read_vector(data, ref index);
    let request_base_asset_ids = read_vector(data, ref index);
    let request_quote_asset_ids = read_vector(data, ref index);
    let request_sides = read_vector(data, ref index);
    let request_max_base_amounts = read_vector(data, ref index);
    let request_midpoints = read_vector(data, ref index);
    let request_price_base_scales = read_vector(data, ref index);
    let request_valid_until_values = read_vector(data, ref index);
    assert(index == data.len(), 'EMA_LEN');

    assert_same_length_12(
        order_commitments.span(),
        order_pair_ids.span(),
        order_base_asset_ids.span(),
        order_quote_asset_ids.span(),
        order_sides.span(),
        order_submitted_base_amounts.span(),
        order_min_fill_base_amounts.span(),
        order_limit_prices.span(),
        order_price_base_scales.span(),
        order_available_input_amounts.span(),
        order_taker_fee_bps.span(),
        order_execution_preferences.span(),
    );
    assert(order_commitments.len() != 0, 'EMA_ORDERS');
    assert(order_commitments.len() <= MAX_EXTERNAL_MATCH_ORDERS, 'EMA_ORDERS');
    assert_same_length_15(
        attestation_pair_ids.span(),
        attestation_base_asset_ids.span(),
        attestation_quote_asset_ids.span(),
        attestation_midpoints.span(),
        attestation_lowers.span(),
        attestation_uppers.span(),
        attestation_price_base_scales.span(),
        attestation_source_counts.span(),
        attestation_observed_at_values.span(),
        attestation_source_set_commitments.span(),
        attestation_valid_until_values.span(),
        attestation_nonces.span(),
        attestation_signers.span(),
        attestation_signature_rs.span(),
        attestation_signature_ss.span(),
    );
    assert_same_length_9(
        request_ids.span(),
        request_pair_ids.span(),
        request_base_asset_ids.span(),
        request_quote_asset_ids.span(),
        request_sides.span(),
        request_max_base_amounts.span(),
        request_midpoints.span(),
        request_price_base_scales.span(),
        request_valid_until_values.span(),
    );
    assert(request_ids.len() != 0, 'EMA_REQUESTS');
    assert(request_ids.len() <= MAX_EXTERNAL_MATCH_REQUESTS, 'EMA_REQUESTS');
    assert_unique(order_commitments.span(), 'EMA_ORDER_DUP');
    assert_unique(attestation_pair_ids.span(), 'EMA_ATTEST_DUP');
    assert_unique(request_ids.span(), 'EMA_REQUEST_DUP');

    let mut nested_payload = array![];
    let mut private_fill_order_commitments = array![];
    let mut private_fill_base_amounts = array![];
    let mut private_fill_quote_amounts = array![];
    if nested_serialized.len() == 0 {
        assert(claimed_multi_pair_commitment == 0, 'EMA_MP_COMMITMENT');
    } else {
        nested_payload = length_prefixed_payload(nested_serialized.span(), 'EMA_MP');
        assert(*nested_payload.at(1) == batch_id, 'EMA_MP_BATCH');
        assert(
            verify_multi_pair_statement(nested_payload.span()) == claimed_multi_pair_commitment,
            'EMA_MP_COMMITMENT',
        );
        let eligible = multi_pair_payload_eligible_order_commitments(nested_payload.span());
        assert_same_set(order_commitments.span(), eligible.span(), 'EMA_MP_ORDERS');
        let (
            chosen_order_commitments,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            chosen_fill_amounts,
            chosen_quote_amounts,
            _,
            _,
        ) =
            multi_pair_payload_chosen_fill_vectors(
            nested_payload.span(),
        );
        private_fill_order_commitments = chosen_order_commitments;
        private_fill_base_amounts = chosen_fill_amounts;
        private_fill_quote_amounts = chosen_quote_amounts;
    }

    assert_orders(
        order_commitments.span(),
        order_pair_ids.span(),
        order_base_asset_ids.span(),
        order_quote_asset_ids.span(),
        order_sides.span(),
        order_submitted_base_amounts.span(),
        order_min_fill_base_amounts.span(),
        order_limit_prices.span(),
        order_price_base_scales.span(),
        order_available_input_amounts.span(),
        order_taker_fee_bps.span(),
        order_execution_preferences.span(),
    );
    assert_attestations(
        auction_verifier_address,
        reference_price_signer,
        attestation_pair_ids.span(),
        attestation_base_asset_ids.span(),
        attestation_quote_asset_ids.span(),
        attestation_midpoints.span(),
        attestation_lowers.span(),
        attestation_uppers.span(),
        attestation_price_base_scales.span(),
        attestation_source_counts.span(),
        attestation_observed_at_values.span(),
        attestation_source_set_commitments.span(),
        attestation_valid_until_values.span(),
        attestation_nonces.span(),
        attestation_signers.span(),
        attestation_signature_rs.span(),
        attestation_signature_ss.span(),
    );

    let mut request_index: usize = 0;
    let mut request_accumulator: felt252 = 0;
    while request_index < request_ids.len() {
        let pair_id = *request_pair_ids.at(request_index);
        let base_asset_id = *request_base_asset_ids.at(request_index);
        let quote_asset_id = *request_quote_asset_ids.at(request_index);
        let side = *request_sides.at(request_index);
        let midpoint = felt_to_u128(*request_midpoints.at(request_index));
        let price_base_scale = felt_to_u128(*request_price_base_scales.at(request_index));
        let valid_until = *request_valid_until_values.at(request_index);
        assert(side == ORDER_SIDE_BUY || side == ORDER_SIDE_SELL, 'EMA_SIDE');
        assert_pair_config(pair_id, base_asset_id, quote_asset_id, price_base_scale.into());
        let attestation_index = find_attestation(
            pair_id,
            base_asset_id,
            quote_asset_id,
            price_base_scale.into(),
            attestation_pair_ids.span(),
            attestation_base_asset_ids.span(),
            attestation_quote_asset_ids.span(),
            attestation_price_base_scales.span(),
        );
        assert(midpoint == felt_to_u128(*attestation_midpoints.at(attestation_index)), 'EMA_MID');
        assert(valid_until == *attestation_valid_until_values.at(attestation_index), 'EMA_EXPIRY');

        let (derived_max_base, order_count, order_accumulator) = derive_request_amount(
            pair_id,
            base_asset_id,
            quote_asset_id,
            side,
            midpoint,
            price_base_scale,
            order_commitments.span(),
            order_pair_ids.span(),
            order_base_asset_ids.span(),
            order_quote_asset_ids.span(),
            order_sides.span(),
            order_submitted_base_amounts.span(),
            order_limit_prices.span(),
            order_price_base_scales.span(),
            order_available_input_amounts.span(),
            order_execution_preferences.span(),
            private_fill_order_commitments.span(),
            private_fill_base_amounts.span(),
            private_fill_quote_amounts.span(),
        );
        assert(order_count != 0, 'EMA_EMPTY_REQUEST');
        assert(
            derived_max_base == felt_to_u128(*request_max_base_amounts.at(request_index)),
            'EMA_MAX',
        );
        assert(quote_amount(derived_max_base, midpoint, price_base_scale) != 0, 'EMA_QUOTE');
        let expected_request_id = request_id(
            batch_id,
            pair_id,
            base_asset_id,
            quote_asset_id,
            side,
            derived_max_base,
            midpoint,
            price_base_scale,
            valid_until,
            order_count,
            order_accumulator,
        );
        assert(expected_request_id == *request_ids.at(request_index), 'EMA_REQUEST_ID');

        let mut leaf = poseidon_hash2(EXTERNAL_MATCH_REQUEST_LEAF_DOMAIN, expected_request_id);
        leaf = poseidon_hash2(leaf, batch_id);
        leaf = poseidon_hash2(leaf, pair_id);
        leaf = poseidon_hash2(leaf, base_asset_id);
        leaf = poseidon_hash2(leaf, quote_asset_id);
        leaf = poseidon_hash2(leaf, side);
        leaf = poseidon_hash2(leaf, derived_max_base.into());
        leaf = poseidon_hash2(leaf, midpoint.into());
        leaf = poseidon_hash2(leaf, price_base_scale.into());
        leaf = poseidon_hash2(leaf, valid_until);
        request_accumulator += leaf;
        request_index += 1;
    }

    assert_every_external_order_has_request(
        order_commitments.span(),
        order_pair_ids.span(),
        order_base_asset_ids.span(),
        order_quote_asset_ids.span(),
        order_sides.span(),
        order_submitted_base_amounts.span(),
        order_limit_prices.span(),
        order_price_base_scales.span(),
        order_available_input_amounts.span(),
        order_execution_preferences.span(),
        private_fill_order_commitments.span(),
        private_fill_base_amounts.span(),
        private_fill_quote_amounts.span(),
        request_pair_ids.span(),
        request_base_asset_ids.span(),
        request_quote_asset_ids.span(),
        request_sides.span(),
        request_midpoints.span(),
        request_price_base_scales.span(),
        attestation_pair_ids.span(),
        attestation_base_asset_ids.span(),
        attestation_quote_asset_ids.span(),
        attestation_midpoints.span(),
        attestation_price_base_scales.span(),
    );
    let root_seed = poseidon_hash2(EXTERNAL_MATCH_AUTHORIZATION_DOMAIN, request_ids.len().into());
    let request_root = poseidon_hash2(root_seed, request_accumulator);
    assert(request_root == claimed_request_root, 'EMA_ROOT');
    (batch_id, claimed_multi_pair_commitment, request_root, reference_price_signer)
}

fn derive_request_amount(
    pair_id: felt252,
    base_asset_id: felt252,
    quote_asset_id: felt252,
    side: felt252,
    midpoint: u128,
    price_base_scale: u128,
    order_commitments: Span<felt252>,
    order_pair_ids: Span<felt252>,
    order_base_asset_ids: Span<felt252>,
    order_quote_asset_ids: Span<felt252>,
    order_sides: Span<felt252>,
    submitted: Span<felt252>,
    limits: Span<felt252>,
    scales: Span<felt252>,
    available_inputs: Span<felt252>,
    preferences: Span<felt252>,
    private_commitments: Span<felt252>,
    private_bases: Span<felt252>,
    private_quotes: Span<felt252>,
) -> (u128, usize, felt252) {
    let mut total: u128 = 0;
    let mut count: usize = 0;
    let mut accumulator: felt252 = 0;
    let mut index: usize = 0;
    while index < order_commitments.len() {
        if *preferences.at(index) == EXECUTION_PRIVATE_THEN_EXTERNAL
            && *order_pair_ids.at(index) == pair_id
            && *order_base_asset_ids.at(index) == base_asset_id
            && *order_quote_asset_ids.at(index) == quote_asset_id
            && *order_sides.at(index) == side
            && felt_to_u128(*scales.at(index)) == price_base_scale {
            let (private_base, private_quote) = private_fill_for(
                *order_commitments.at(index), private_commitments, private_bases, private_quotes,
            );
            let submitted_base = felt_to_u128(*submitted.at(index));
            let available_input = felt_to_u128(*available_inputs.at(index));
            assert(private_base <= submitted_base, 'EMA_PRIVATE_BASE');
            let consumed_input = if side == ORDER_SIDE_BUY {
                private_quote
            } else {
                private_base
            };
            assert(consumed_input <= available_input, 'EMA_PRIVATE_INPUT');
            let remaining_base = submitted_base - private_base;
            let remaining_input = available_input - consumed_input;
            let limit = felt_to_u128(*limits.at(index));
            let eligible = if side == ORDER_SIDE_BUY {
                midpoint <= limit
            } else {
                midpoint >= limit
            };
            if eligible && remaining_base != 0 && remaining_input != 0 {
                let capacity = if side == ORDER_SIDE_BUY {
                    min_u128(
                        remaining_base,
                        affordable_base(remaining_input, midpoint, price_base_scale),
                    )
                } else {
                    min_u128(remaining_base, remaining_input)
                };
                if capacity != 0 {
                    total += capacity;
                    count += 1;
                    accumulator +=
                        poseidon_hash2(
                            EXTERNAL_MATCH_ORDER_LEAF_DOMAIN, *order_commitments.at(index),
                        );
                }
            }
        }
        index += 1;
    }
    (total, count, accumulator)
}

fn every_order_request_match_count(
    pair_id: felt252,
    base_asset_id: felt252,
    quote_asset_id: felt252,
    side: felt252,
    scale: felt252,
    request_pair_ids: Span<felt252>,
    request_base_asset_ids: Span<felt252>,
    request_quote_asset_ids: Span<felt252>,
    request_sides: Span<felt252>,
    request_price_base_scales: Span<felt252>,
) -> usize {
    let mut count = 0;
    let mut index = 0;
    while index < request_pair_ids.len() {
        if *request_pair_ids.at(index) == pair_id
            && *request_base_asset_ids.at(index) == base_asset_id
            && *request_quote_asset_ids.at(index) == quote_asset_id
            && *request_sides.at(index) == side
            && *request_price_base_scales.at(index) == scale {
            count += 1;
        }
        index += 1;
    }
    count
}

fn assert_every_external_order_has_request(
    commitments: Span<felt252>,
    pair_ids: Span<felt252>,
    base_ids: Span<felt252>,
    quote_ids: Span<felt252>,
    sides: Span<felt252>,
    submitted: Span<felt252>,
    limits: Span<felt252>,
    scales: Span<felt252>,
    available_inputs: Span<felt252>,
    preferences: Span<felt252>,
    private_commitments: Span<felt252>,
    private_bases: Span<felt252>,
    private_quotes: Span<felt252>,
    request_pair_ids: Span<felt252>,
    request_base_ids: Span<felt252>,
    request_quote_ids: Span<felt252>,
    request_sides: Span<felt252>,
    request_midpoints: Span<felt252>,
    request_scales: Span<felt252>,
    attestation_pair_ids: Span<felt252>,
    attestation_base_ids: Span<felt252>,
    attestation_quote_ids: Span<felt252>,
    attestation_midpoints: Span<felt252>,
    attestation_scales: Span<felt252>,
) {
    let mut index = 0;
    while index < pair_ids.len() {
        if *preferences.at(index) == EXECUTION_PRIVATE_THEN_EXTERNAL {
            let side = *sides.at(index);
            let (private_base, private_quote) = private_fill_for(
                *commitments.at(index), private_commitments, private_bases, private_quotes,
            );
            let submitted_base = felt_to_u128(*submitted.at(index));
            let available_input = felt_to_u128(*available_inputs.at(index));
            assert(private_base <= submitted_base, 'EMA_PRIVATE_BASE');
            let consumed_input = if side == ORDER_SIDE_BUY {
                private_quote
            } else {
                private_base
            };
            assert(consumed_input <= available_input, 'EMA_PRIVATE_INPUT');
            let remaining_base = submitted_base - private_base;
            let remaining_input = available_input - consumed_input;
            let request_count = every_order_request_match_count(
                *pair_ids.at(index),
                *base_ids.at(index),
                *quote_ids.at(index),
                *sides.at(index),
                *scales.at(index),
                request_pair_ids,
                request_base_ids,
                request_quote_ids,
                request_sides,
                request_scales,
            );
            if remaining_base != 0 && remaining_input != 0 {
                let attestation_index = find_attestation(
                    *pair_ids.at(index),
                    *base_ids.at(index),
                    *quote_ids.at(index),
                    *scales.at(index),
                    attestation_pair_ids,
                    attestation_base_ids,
                    attestation_quote_ids,
                    attestation_scales,
                );
                let midpoint = felt_to_u128(*attestation_midpoints.at(attestation_index));
                let eligible = if side == ORDER_SIDE_BUY {
                    midpoint <= felt_to_u128(*limits.at(index))
                } else {
                    midpoint >= felt_to_u128(*limits.at(index))
                };
                let capacity = if !eligible {
                    0
                } else if side == ORDER_SIDE_BUY {
                    min_u128(
                        remaining_base,
                        affordable_base(remaining_input, midpoint, felt_to_u128(*scales.at(index))),
                    )
                } else {
                    min_u128(remaining_base, remaining_input)
                };
                if capacity != 0 {
                    assert(request_count == 1, 'EMA_ORDER_REQUEST');
                    let request_index = find_request(
                        *pair_ids.at(index),
                        *base_ids.at(index),
                        *quote_ids.at(index),
                        *sides.at(index),
                        *scales.at(index),
                        request_pair_ids,
                        request_base_ids,
                        request_quote_ids,
                        request_sides,
                        request_scales,
                    );
                    assert(
                        felt_to_u128(*request_midpoints.at(request_index)) == midpoint,
                        'EMA_ORDER_MID',
                    );
                }
            } else {
                assert(request_count == 0, 'EMA_ORDER_REQUEST');
            }
        }
        index += 1;
    }
}

fn assert_orders(
    commitments: Span<felt252>,
    pair_ids: Span<felt252>,
    base_ids: Span<felt252>,
    quote_ids: Span<felt252>,
    sides: Span<felt252>,
    submitted: Span<felt252>,
    min_fills: Span<felt252>,
    limits: Span<felt252>,
    scales: Span<felt252>,
    available_inputs: Span<felt252>,
    fee_bps: Span<felt252>,
    preferences: Span<felt252>,
) {
    let mut index = 0;
    while index < commitments.len() {
        let submitted_base = felt_to_u128(*submitted.at(index));
        let min_fill = felt_to_u128(*min_fills.at(index));
        let scale = felt_to_u128(*scales.at(index));
        assert(*commitments.at(index) != 0, 'EMA_ORDER');
        assert(
            *sides.at(index) == ORDER_SIDE_BUY || *sides.at(index) == ORDER_SIDE_SELL, 'EMA_SIDE',
        );
        assert(submitted_base != 0 && min_fill != 0 && min_fill <= submitted_base, 'EMA_AMOUNT');
        assert(felt_to_u128(*limits.at(index)) != 0 && scale != 0, 'EMA_PRICE');
        assert(felt_to_u128(*available_inputs.at(index)) != 0, 'EMA_INPUT');
        assert(felt_to_u128(*fee_bps.at(index)) <= FEE_BPS_DENOMINATOR, 'EMA_FEE');
        assert(
            *preferences.at(index) == 0
                || *preferences.at(index) == EXECUTION_PRIVATE_THEN_EXTERNAL,
            'EMA_PREF',
        );
        assert_pair_config(
            *pair_ids.at(index), *base_ids.at(index), *quote_ids.at(index), *scales.at(index),
        );
        index += 1;
    }
}

fn assert_attestations(
    verifier: felt252,
    expected_signer: felt252,
    pair_ids: Span<felt252>,
    base_ids: Span<felt252>,
    quote_ids: Span<felt252>,
    midpoints: Span<felt252>,
    lowers: Span<felt252>,
    uppers: Span<felt252>,
    scales: Span<felt252>,
    source_counts: Span<felt252>,
    observed: Span<felt252>,
    source_sets: Span<felt252>,
    valid_until: Span<felt252>,
    nonces: Span<felt252>,
    signers: Span<felt252>,
    signature_rs: Span<felt252>,
    signature_ss: Span<felt252>,
) {
    let mut index = 0;
    while index < pair_ids.len() {
        let midpoint = felt_to_u128(*midpoints.at(index));
        let lower = felt_to_u128(*lowers.at(index));
        let upper = felt_to_u128(*uppers.at(index));
        assert(
            midpoint != 0 && lower != 0 && lower <= midpoint && midpoint <= upper,
            'EMA_ATTEST_PRICE',
        );
        assert(felt_to_u128(*source_counts.at(index)) >= 3, 'EMA_ATTEST_SOURCES');
        assert(
            felt_to_u128(*observed.at(index)) < felt_to_u128(*valid_until.at(index)),
            'EMA_ATTEST_EXPIRY',
        );
        assert(*source_sets.at(index) != 0, 'EMA_ATTEST_SOURCES');
        assert(*signers.at(index) == expected_signer, 'EMA_ATTEST_SIGNER');
        assert_pair_config(
            *pair_ids.at(index), *base_ids.at(index), *quote_ids.at(index), *scales.at(index),
        );
        let commitment = reference_price_attestation_commitment(
            REFERENCE_PRICE_ATTESTATION_DOMAIN,
            verifier,
            *pair_ids.at(index),
            *base_ids.at(index),
            *quote_ids.at(index),
            *midpoints.at(index),
            *lowers.at(index),
            *uppers.at(index),
            *scales.at(index),
            *source_counts.at(index),
            *observed.at(index),
            *valid_until.at(index),
            *source_sets.at(index),
            *nonces.at(index),
            *signers.at(index),
        );
        assert(
            check_ecdsa_signature(
                commitment, *signers.at(index), *signature_rs.at(index), *signature_ss.at(index),
            ),
            'EMA_ATTEST_SIG',
        );
        index += 1;
    }
}

fn request_id(
    batch_id: felt252,
    pair_id: felt252,
    base_id: felt252,
    quote_id: felt252,
    side: felt252,
    max_base: u128,
    midpoint: u128,
    scale: u128,
    valid_until: felt252,
    order_count: usize,
    order_accumulator: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(EXTERNAL_MATCH_REQUEST_DOMAIN, batch_id);
    state = poseidon_hash2(state, pair_id);
    state = poseidon_hash2(state, base_id);
    state = poseidon_hash2(state, quote_id);
    state = poseidon_hash2(state, side);
    state = poseidon_hash2(state, max_base.into());
    state = poseidon_hash2(state, midpoint.into());
    state = poseidon_hash2(state, scale.into());
    state = poseidon_hash2(state, valid_until);
    state = poseidon_hash2(state, order_count.into());
    poseidon_hash2(state, order_accumulator)
}

fn private_fill_for(
    commitment: felt252, commitments: Span<felt252>, bases: Span<felt252>, quotes: Span<felt252>,
) -> (u128, u128) {
    let mut total_base: u128 = 0;
    let mut total_quote: u128 = 0;
    let mut index = 0;
    while index < commitments.len() {
        if *commitments.at(index) == commitment {
            total_base += felt_to_u128(*bases.at(index));
            total_quote += felt_to_u128(*quotes.at(index));
        }
        index += 1;
    }
    (total_base, total_quote)
}

fn affordable_base(quote: u128, price: u128, scale: u128) -> u128 {
    assert(price != 0 && scale != 0, 'EMA_PRICE');
    let mut value: u256 = quote.into();
    value *= scale.into();
    value /= price.into();
    value.try_into().expect('EMA_OVERFLOW')
}

fn quote_amount(base: u128, price: u128, scale: u128) -> u128 {
    assert(scale != 0, 'EMA_PRICE');
    let mut value: u256 = base.into();
    value *= price.into();
    value /= scale.into();
    value.try_into().expect('EMA_OVERFLOW')
}

fn min_u128(left: u128, right: u128) -> u128 {
    if left < right {
        left
    } else {
        right
    }
}

fn find_attestation(
    pair_id: felt252,
    base_id: felt252,
    quote_id: felt252,
    scale: felt252,
    pair_ids: Span<felt252>,
    base_ids: Span<felt252>,
    quote_ids: Span<felt252>,
    scales: Span<felt252>,
) -> usize {
    let mut found = pair_ids.len();
    let mut index = 0;
    while index < pair_ids.len() {
        if *pair_ids.at(index) == pair_id
            && *base_ids.at(index) == base_id
            && *quote_ids.at(index) == quote_id
            && *scales.at(index) == scale {
            assert(found == pair_ids.len(), 'EMA_ATTEST_DUP');
            found = index;
        }
        index += 1;
    }
    assert(found != pair_ids.len(), 'EMA_ATTEST_MISSING');
    found
}

fn find_request(
    pair_id: felt252,
    base_id: felt252,
    quote_id: felt252,
    side: felt252,
    scale: felt252,
    pair_ids: Span<felt252>,
    base_ids: Span<felt252>,
    quote_ids: Span<felt252>,
    sides: Span<felt252>,
    scales: Span<felt252>,
) -> usize {
    let mut index = 0;
    while index < pair_ids.len() {
        if *pair_ids.at(index) == pair_id
            && *base_ids.at(index) == base_id
            && *quote_ids.at(index) == quote_id
            && *sides.at(index) == side
            && *scales.at(index) == scale {
            return index;
        }
        index += 1;
    }
    assert(false, 'EMA_REQUEST_MISSING');
    0
}

fn assert_unique(values: Span<felt252>, message: felt252) {
    let mut left = 0;
    while left < values.len() {
        let mut right = left + 1;
        while right < values.len() {
            assert(*values.at(left) != *values.at(right), message);
            right += 1;
        }
        left += 1;
    }
}

fn assert_same_set(left: Span<felt252>, right: Span<felt252>, message: felt252) {
    assert(left.len() == right.len(), message);
    let mut index = 0;
    while index < left.len() {
        let mut found = false;
        let mut cursor = 0;
        while cursor < right.len() {
            if *left.at(index) == *right.at(cursor) {
                found = true;
            }
            cursor += 1;
        }
        assert(found, message);
        index += 1;
    }
}

fn read_next(data: Span<felt252>, ref index: usize) -> felt252 {
    assert(index < data.len(), 'EMA_SHORT');
    let value = *data.at(index);
    index += 1;
    value
}

fn read_vector(data: Span<felt252>, ref index: usize) -> Array<felt252> {
    let length: usize = read_next(data, ref index).try_into().expect('EMA_VECTOR');
    let mut values = array![];
    let mut cursor = 0;
    while cursor < length {
        values.append(read_next(data, ref index));
        cursor += 1;
    }
    values
}

fn assert_same_length_9(
    a: Span<felt252>,
    b: Span<felt252>,
    c: Span<felt252>,
    d: Span<felt252>,
    e: Span<felt252>,
    f: Span<felt252>,
    g: Span<felt252>,
    h: Span<felt252>,
    i: Span<felt252>,
) {
    let n = a.len();
    assert(
        n == b.len()
            && n == c.len()
            && n == d.len()
            && n == e.len()
            && n == f.len()
            && n == g.len()
            && n == h.len()
            && n == i.len(),
        'EMA_VECTOR_LEN',
    );
}

fn assert_same_length_12(
    a: Span<felt252>,
    b: Span<felt252>,
    c: Span<felt252>,
    d: Span<felt252>,
    e: Span<felt252>,
    f: Span<felt252>,
    g: Span<felt252>,
    h: Span<felt252>,
    i: Span<felt252>,
    j: Span<felt252>,
    k: Span<felt252>,
    l: Span<felt252>,
) {
    let n = a.len();
    assert(
        n == b.len()
            && n == c.len()
            && n == d.len()
            && n == e.len()
            && n == f.len()
            && n == g.len()
            && n == h.len()
            && n == i.len()
            && n == j.len()
            && n == k.len()
            && n == l.len(),
        'EMA_VECTOR_LEN',
    );
}

fn assert_same_length_15(
    a: Span<felt252>,
    b: Span<felt252>,
    c: Span<felt252>,
    d: Span<felt252>,
    e: Span<felt252>,
    f: Span<felt252>,
    g: Span<felt252>,
    h: Span<felt252>,
    i: Span<felt252>,
    j: Span<felt252>,
    k: Span<felt252>,
    l: Span<felt252>,
    m: Span<felt252>,
    n: Span<felt252>,
    o: Span<felt252>,
) {
    let length = a.len();
    assert(
        length == b.len()
            && length == c.len()
            && length == d.len()
            && length == e.len()
            && length == f.len()
            && length == g.len()
            && length == h.len()
            && length == i.len()
            && length == j.len()
            && length == k.len()
            && length == l.len()
            && length == m.len()
            && length == n.len()
            && length == o.len(),
        'EMA_VECTOR_LEN',
    );
}
