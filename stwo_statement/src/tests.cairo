use super::{
    ASSET_ID_ETH, ASSET_ID_STRK, ASSET_ID_USDC, ASSET_SCALE_18, CONSUMED_NOTE_ROOT_DOMAIN,
    CONSUMED_NULLIFIER_ROOT_DOMAIN, FEE_ROOT_DOMAIN, FinalMultiPairFillInputs,
    NOTE_COMMITMENT_DOMAIN, NULLIFIER_DOMAIN, NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL,
    NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL, ORDER_COMMITMENT_DOMAIN, OUTPUT_NOTE_ROOT_DOMAIN,
    OUTPUT_RECOVERY_BUNDLE_DOMAIN, PAIR_ID_ETH_USDC, PAIR_ID_STRK_USDC, PUBLIC_SETTLEMENT_DOMAIN,
    REFERENCE_PRICE_ATTESTATION_DOMAIN, RENEWAL_CHILD_ROOT_DOMAIN, SPEND_AUTHORITY_DOMAIN,
    STATEMENT_TYPE_MULTI_PAIR, STATEMENT_TYPE_SETTLEMENT, STATE_TRANSITION_ROOT_DOMAIN,
    assert_final_multi_pair_fill_vectors, assert_optimal_clearing_score, poseidon_hash2,
    sparse_insert_nullifier_from_empty, verify_external_match_authorization_statement,
    verify_multi_pair_statement, verify_nullifier_statement, verify_renewal_statement,
};

#[test]
fn final_multi_pair_fills_merge_private_and_external_execution() {
    let binding_batch_ids = array![0x10];
    let binding_pair_ids = array![PAIR_ID_ETH_USDC];
    let binding_base_asset_ids = array![ASSET_ID_ETH];
    let binding_quote_asset_ids = array![ASSET_ID_USDC];
    let binding_scales = array![1];
    let binding_fees = array![4];
    let admission_batch_ids = array![0x10, 0x10];
    let admission_commitments = array![0x1, 0x2];
    let admission_sides = array![0, 0];
    let admission_types = array![0, 0];
    let admission_limits = array![4100, 4050];
    let admission_amounts = array![1000, 500];
    let admission_preferences = array![1, 1];
    let admission_funding = array![4000000, 2000000];
    let private_commitments = array![0x1];
    let private_base = array![400];
    let private_quote = array![1600000];
    let external_pair_ids = array![PAIR_ID_ETH_USDC];
    let external_base_assets = array![ASSET_ID_ETH];
    let external_quote_assets = array![ASSET_ID_USDC];
    let external_sides = array![0];
    let external_max = array![1100];
    let external_midpoints = array![4000];
    let external_scales = array![1];
    let external_consumed = array![550];
    let inputs = FinalMultiPairFillInputs {
        binding_batch_ids: binding_batch_ids.span(),
        binding_pair_ids: binding_pair_ids.span(),
        binding_base_asset_ids: binding_base_asset_ids.span(),
        binding_quote_asset_ids: binding_quote_asset_ids.span(),
        binding_price_base_scales: binding_scales.span(),
        binding_taker_fee_bps: binding_fees.span(),
        admission_batch_ids: admission_batch_ids.span(),
        admission_order_commitments: admission_commitments.span(),
        admission_sides: admission_sides.span(),
        admission_order_types: admission_types.span(),
        admission_limit_prices: admission_limits.span(),
        admission_order_amounts: admission_amounts.span(),
        admission_execution_preferences: admission_preferences.span(),
        admission_funding_amounts: admission_funding.span(),
        private_order_commitments: private_commitments.span(),
        private_filled_base_amounts: private_base.span(),
        private_quote_amounts: private_quote.span(),
        external_pair_ids: external_pair_ids.span(),
        external_base_asset_ids: external_base_assets.span(),
        external_quote_asset_ids: external_quote_assets.span(),
        external_sides: external_sides.span(),
        external_max_base_amounts: external_max.span(),
        external_midpoint_prices: external_midpoints.span(),
        external_price_base_scales: external_scales.span(),
        external_consumed_base_amounts: external_consumed.span(),
    };
    let matched_batches = array![0x10, 0x10];
    let matched_commitments = array![0x1, 0x2];
    let matched_fills = array![700, 250];
    let matched_sides = array![0, 0];
    let matched_amounts = array![1000, 500];
    let matched_limits = array![4100, 4050];
    let (_, _, _, _, _, quote_amounts, fee_amounts) = assert_final_multi_pair_fill_vectors(
        @inputs,
        matched_batches.span(),
        matched_commitments.span(),
        matched_fills.span(),
        matched_sides.span(),
        matched_amounts.span(),
        matched_limits.span(),
    );
    assert(*quote_amounts.at(0) == 2800000, 'FINAL_QUOTE_0');
    assert(*quote_amounts.at(1) == 1000000, 'FINAL_QUOTE_1');
    assert(*fee_amounts.at(0) == 1, 'FINAL_FEE_0');
    assert(*fee_amounts.at(1) == 1, 'FINAL_FEE_1');
}

#[test]
fn external_match_authorization_accepts_rust_one_sided_fixture() {
    let data = external_match_authorization_fixture(false);
    let (batch_id, multi_pair_commitment, request_root, signer) =
        verify_external_match_authorization_statement(
        data.span(),
    );
    assert(
        batch_id == 0x25dffbccee5972454ed36ad85a2990a6709d8304043e0f6cc94a80164bf4c92, 'EMA_BATCH',
    );
    assert(multi_pair_commitment == 0, 'EMA_MP');
    assert(
        signer == 0x765fddbeb208bd018551a75abe81818370f51425ddfae86dc53b13cc89d5c74, 'EMA_SIGNER',
    );
    assert(
        request_root == 0xe49400e89dac15c1cfc3ef426fa5753508fa8b90a7ba3ac99ff97547bfb8ec,
        'EMA_ROOT',
    );
}

#[test]
#[should_panic(expected: 'EMA_MAX')]
fn external_match_authorization_rejects_tampered_request_amount() {
    let data = external_match_authorization_fixture(true);
    verify_external_match_authorization_statement(data.span());
}

fn external_match_authorization_fixture(tamper_max_base: bool) -> Array<felt252> {
    array![
        0xa, 0x25dffbccee5972454ed36ad85a2990a6709d8304043e0f6cc94a80164bf4c92, 0x456,
        0x765fddbeb208bd018551a75abe81818370f51425ddfae86dc53b13cc89d5c74, 0x0,
        0xe49400e89dac15c1cfc3ef426fa5753508fa8b90a7ba3ac99ff97547bfb8ec, 0x0, 0x1, 0x1, 0x1,
        0x2cbcdace0891f8e930c42d95e41029a4b97dbefe3c7ab4fc1624e094b2c8b5, 0x1,
        0x83191fc191d03c3f6f70ea7a1420780d860230dda0edfc2ae9ab762c72b2fe, 0x1,
        0x1e565426a7cff134da7e67f4587da64258d8e50b249f60444b53d8aebb4987c, 0x1, 0x0, 0x1,
        0xde0b6b3a7640000, 0x1, 0x1, 0x1, 0xf4610900, 0x1, 0xde0b6b3a7640000, 0x1, 0xee6b2800, 0x1,
        0x4, 0x1, 0x1, 0x1, 0x2cbcdace0891f8e930c42d95e41029a4b97dbefe3c7ab4fc1624e094b2c8b5, 0x1,
        0x83191fc191d03c3f6f70ea7a1420780d860230dda0edfc2ae9ab762c72b2fe, 0x1,
        0x1e565426a7cff134da7e67f4587da64258d8e50b249f60444b53d8aebb4987c, 0x1, 0xee6b2800, 0x1,
        0xee0f9a80, 0x1, 0xeec6b580, 0x1, 0xde0b6b3a7640000, 0x1, 0x3, 0x1, 0x3e8, 0x1,
        0x2a982672cfa5321f3b54d66af5fdcbaef619dacb33411ea1e1bae15045f2003, 0x1, 0x1770, 0x1, 0x7,
        0x1, 0x765fddbeb208bd018551a75abe81818370f51425ddfae86dc53b13cc89d5c74, 0x1,
        0x682267153235f10f0ae41ac2652512fc2e690fd73b6f29a6ef2a83bfcc547c4, 0x1,
        0x6f544537ae2e05d7710a80e3fa7483f3e339b35582da853394e1cf267c402b8, 0x1,
        0x78c6d3745678b0a3a9b1d99856b3f4cef76313e8f72debf26afe846d0196618, 0x1,
        0x2cbcdace0891f8e930c42d95e41029a4b97dbefe3c7ab4fc1624e094b2c8b5, 0x1,
        0x83191fc191d03c3f6f70ea7a1420780d860230dda0edfc2ae9ab762c72b2fe, 0x1,
        0x1e565426a7cff134da7e67f4587da64258d8e50b249f60444b53d8aebb4987c, 0x1, 0x0, 0x1,
        if tamper_max_base {
            0xde0b6b3a7640001
        } else {
            0xde0b6b3a7640000
        }, 0x1, 0xee6b2800, 0x1,
        0xde0b6b3a7640000, 0x1, 0x1770,
    ]
}

#[test]
fn reference_price_inside_optimal_crossing_plateau_is_valid() {
    let sides = array![0, 1];
    let order_types = array![0, 0];
    let limit_prices = array![200, 100];
    let order_amounts = array![10, 10];
    let min_fills = array![1, 1];
    let time_in_force = array![0, 0];
    let funding_note_amounts = array![2000, 10];

    assert_optimal_clearing_score(
        150,
        1,
        sides.span(),
        order_types.span(),
        limit_prices.span(),
        order_amounts.span(),
        min_fills.span(),
        time_in_force.span(),
        funding_note_amounts.span(),
    );
}

#[test]
#[should_panic]
fn reference_price_with_lower_executable_volume_is_rejected() {
    let sides = array![0, 1];
    let order_types = array![0, 0];
    let limit_prices = array![200, 100];
    let order_amounts = array![10, 10];
    let min_fills = array![1, 1];
    let time_in_force = array![0, 0];
    let funding_note_amounts = array![2000, 10];

    assert_optimal_clearing_score(
        250,
        1,
        sides.span(),
        order_types.span(),
        limit_prices.span(),
        order_amounts.span(),
        min_fills.span(),
        time_in_force.span(),
        funding_note_amounts.span(),
    );
}

#[test]
#[should_panic]
fn multi_pair_statement_rejects_fill_away_from_reference_asset_values() {
    let mut data = array![STATEMENT_TYPE_MULTI_PAIR, 0x42];
    append_multi_pair_off_reference_fill_vectors(ref data);
    append_multi_pair_off_reference_delta_vectors(ref data);
    append_vector(ref data, array![0x1, 0x2].span());
    append_vector(ref data, array![ASSET_ID_ETH, ASSET_ID_USDC].span());
    append_vector(ref data, array![2500, 1].span());
    append_vector(ref data, array![1, 1].span());
    append_vector(ref data, array![0x99].span());
    append_vector(ref data, array![2].span());
    append_vector(ref data, array![4].span());
    append_multi_pair_off_reference_fill_vectors(ref data);
    append_multi_pair_off_reference_delta_vectors(ref data);

    verify_multi_pair_statement(data.span());
}

#[test]
#[should_panic]
fn multi_pair_statement_rejects_fee_that_does_not_match_fill_rate() {
    let mut data = array![STATEMENT_TYPE_MULTI_PAIR, 0x43];
    append_multi_pair_fee_mismatch_fill_vectors(ref data);
    append_multi_pair_fee_mismatch_delta_vectors(ref data);
    append_vector(ref data, array![0x1, 0x2].span());
    append_vector(ref data, array![ASSET_ID_ETH, ASSET_ID_USDC].span());
    append_vector(ref data, array![2500, 1].span());
    append_vector(ref data, array![1, 1].span());
    append_vector(ref data, array![0x99].span());
    append_vector(ref data, array![2].span());
    append_vector(ref data, array![5].span());
    append_multi_pair_fee_mismatch_fill_vectors(ref data);
    append_multi_pair_fee_mismatch_delta_vectors(ref data);

    verify_multi_pair_statement(data.span());
}

#[test]
fn multi_pair_statement_accepts_external_only_candidate() {
    let mut data = array![STATEMENT_TYPE_MULTI_PAIR, 0x44];
    append_empty_vectors(ref data, 13);
    append_empty_vectors(ref data, 5);
    append_vector(ref data, array![0x1].span());
    append_vector(ref data, array![ASSET_ID_USDC].span());
    append_vector(ref data, array![1].span());
    append_vector(ref data, array![1].span());
    append_vector(ref data, array![0x99].span());
    append_vector(ref data, array![0].span());
    append_vector(ref data, array![0].span());
    append_empty_vectors(ref data, 13);
    append_empty_vectors(ref data, 5);

    let commitment = verify_multi_pair_statement(data.span());
    assert(commitment != 0, 'MP_EMPTY_COMMITMENT');
}

#[test]
fn nullifier_parser_accepts_nonempty_canonical_vectors() {
    let nullifier: felt252 = 0x333;
    let nullifier_key_low: u128 = 0x333;
    let mut payload = settlement_header(0xabc);
    append_empty_vectors(ref payload, 57);
    append_vector(ref payload, array![0x111].span());
    append_vector(ref payload, array![nullifier].span());
    append_vector(ref payload, array![nullifier].span());
    append_vector(ref payload, array![0].span());
    append_vector(ref payload, array![0].span());
    append_vector(ref payload, array![].span());
    append_vector(ref payload, array![].span());
    append_empty_vectors(ref payload, 33);
    payload
        .append(
            sparse_insert_nullifier_from_empty(
                nullifier,
                nullifier_key_low,
                NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL,
                NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL,
            ),
        );
    payload.append(0);

    let (transcript, prior_root, consumed_root, new_root) = verify_nullifier_statement(
        payload.span(),
    );
    assert(transcript == 0xabc, 'NULLIFIER_TRANSCRIPT');
    assert(prior_root == 0, 'NULLIFIER_PRIOR');
    assert(consumed_root != 0, 'NULLIFIER_CONSUMED');
    assert(new_root != 0, 'NULLIFIER_NEW');
}

#[test]
fn renewal_parser_accepts_nonempty_order_vectors() {
    let mut payload = settlement_header(0xdef);
    append_vector(ref payload, array![0x999].span());
    append_empty_vectors(ref payload, 11);
    append_vector(ref payload, array![0].span());
    append_vector(ref payload, array![0].span());
    append_vector(ref payload, array![0].span());
    append_vector(ref payload, array![0].span());
    append_vector(ref payload, array![0].span());
    append_empty_vectors(ref payload, 55);
    append_empty_vectors(ref payload, 12);
    append_empty_vectors(ref payload, 13);
    payload.append(0);
    payload.append(0);

    let (transcript, prior_root, child_root, new_root) = verify_renewal_statement(payload.span());
    assert(transcript == 0xdef, 'RENEWAL_TRANSCRIPT');
    assert(prior_root == 0, 'RENEWAL_PRIOR');
    assert(child_root != 0, 'RENEWAL_CHILD');
    assert(new_root == 0, 'RENEWAL_NEW');
}

fn settlement_header(transcript: felt252) -> Array<felt252> {
    array![
        STATEMENT_TYPE_SETTLEMENT, NOTE_COMMITMENT_DOMAIN, SPEND_AUTHORITY_DOMAIN, NULLIFIER_DOMAIN,
        ORDER_COMMITMENT_DOMAIN, PUBLIC_SETTLEMENT_DOMAIN, 0x2001, PAIR_ID_STRK_USDC, 0x2003,
        0x2004, 0x2005, 0x2006, REFERENCE_PRICE_ATTESTATION_DOMAIN, 0x2007, 0x2008, 6000, 1, 1, 1,
        3, 1000, 0x2009, 1, transcript, ASSET_ID_STRK, ASSET_ID_USDC, 0, ASSET_SCALE_18, 4, 0x4010,
        0x4020, 0, poseidon_hash2(OUTPUT_RECOVERY_BUNDLE_DOMAIN, 0), 0, 0, 0, 0,
        CONSUMED_NOTE_ROOT_DOMAIN, CONSUMED_NULLIFIER_ROOT_DOMAIN, RENEWAL_CHILD_ROOT_DOMAIN,
        OUTPUT_NOTE_ROOT_DOMAIN, FEE_ROOT_DOMAIN, STATE_TRANSITION_ROOT_DOMAIN,
        NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL, NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL,
    ]
}

fn append_empty_vectors(ref payload: Array<felt252>, count: usize) {
    let mut index = 0;
    loop {
        if index == count {
            break;
        }
        append_vector(ref payload, array![].span());
        index += 1;
    };
}

fn append_vector(ref payload: Array<felt252>, values: Span<felt252>) {
    payload.append(values.len().into());
    let mut index = 0;
    loop {
        if index == values.len() {
            break;
        }
        payload.append(*values.at(index));
        index += 1;
    };
}

fn append_multi_pair_off_reference_fill_vectors(ref payload: Array<felt252>) {
    append_vector(ref payload, array![0x1, 0x2].span());
    append_vector(ref payload, array![PAIR_ID_ETH_USDC, PAIR_ID_ETH_USDC].span());
    append_vector(ref payload, array![ASSET_ID_ETH, ASSET_ID_ETH].span());
    append_vector(ref payload, array![ASSET_ID_USDC, ASSET_ID_USDC].span());
    append_vector(ref payload, array![0, 1].span());
    append_vector(ref payload, array![10, 10].span());
    append_vector(ref payload, array![1, 1].span());
    append_vector(ref payload, array![3000, 2000].span());
    append_vector(ref payload, array![1, 1].span());
    append_vector(ref payload, array![10, 10].span());
    append_vector(ref payload, array![24000, 24000].span());
    append_vector(ref payload, array![0, 0].span());
    append_vector(ref payload, array![0, 0].span());
}

fn append_multi_pair_off_reference_delta_vectors(ref payload: Array<felt252>) {
    append_vector(
        ref payload, array![ASSET_ID_USDC, ASSET_ID_ETH, ASSET_ID_ETH, ASSET_ID_USDC].span(),
    );
    append_vector(ref payload, array![24000, 10, 10, 24000].span());
    append_vector(ref payload, array![0, 1, 0, 1].span());
    append_vector(ref payload, array![0, 0, 0, 0].span());
    append_vector(ref payload, array![0x1, 0x1, 0x2, 0x2].span());
}

fn append_multi_pair_fee_mismatch_fill_vectors(ref payload: Array<felt252>) {
    append_vector(ref payload, array![0x1, 0x2].span());
    append_vector(ref payload, array![PAIR_ID_ETH_USDC, PAIR_ID_ETH_USDC].span());
    append_vector(ref payload, array![ASSET_ID_ETH, ASSET_ID_ETH].span());
    append_vector(ref payload, array![ASSET_ID_USDC, ASSET_ID_USDC].span());
    append_vector(ref payload, array![0, 1].span());
    append_vector(ref payload, array![10, 10].span());
    append_vector(ref payload, array![1, 1].span());
    append_vector(ref payload, array![3000, 2000].span());
    append_vector(ref payload, array![1, 1].span());
    append_vector(ref payload, array![10, 10].span());
    append_vector(ref payload, array![25000, 25000].span());
    append_vector(ref payload, array![0, 0].span());
    append_vector(ref payload, array![1, 0].span());
}

fn append_multi_pair_fee_mismatch_delta_vectors(ref payload: Array<felt252>) {
    append_vector(
        ref payload,
        array![ASSET_ID_USDC, ASSET_ID_ETH, ASSET_ID_ETH, ASSET_ID_ETH, ASSET_ID_USDC].span(),
    );
    append_vector(ref payload, array![25000, 9, 1, 10, 25000].span());
    append_vector(ref payload, array![0, 1, 1, 0, 1].span());
    append_vector(ref payload, array![0, 0, 1, 0, 0].span());
    append_vector(ref payload, array![0x1, 0x1, 0x1, 0x2, 0x2].span());
}
