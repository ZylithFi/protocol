use core::array::{Array, ArrayTrait};
use core::integer::u256;
use core::poseidon::hades_permutation;
use core::traits::{Into, TryInto};
mod admission_executable;
mod auction_result_executable;

mod executable;
mod multi_pair_executable;

const ORDER_SIDE_BUY: felt252 = 0;
const ORDER_SIDE_SELL: felt252 = 1;
const ORDER_TYPE_LIMIT_BATCH: felt252 = 0;
const ORDER_TYPE_HEARTBEAT_COVER: felt252 = 2;
const RELAY_MODE_SELF: felt252 = 0;
const RELAY_MODE_ZYLITH: felt252 = 1;
const TIF_CURRENT_BATCH_ONLY: felt252 = 0;
const TIF_FILL_OR_KILL: felt252 = 1;
const EXECUTION_PRIVATE_ONLY: felt252 = 0;
const EXECUTION_PRIVATE_THEN_EXTERNAL: felt252 = 1;
const FEE_BPS_DENOMINATOR: u128 = 10000;
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
const OUTPUT_RECOVERY_BUNDLE_DOMAIN: felt252 = 0x7a796c6974685f6f75745f62756e646c655f7631;
const OUTPUT_RECOVERY_RECORD_DOMAIN: felt252 = 0x7a796c6974685f6f75745f7265635f7631;
const NULLIFIER_SPARSE_TREE_DEPTH: usize = 128;
const RENEWAL_SPARSE_TREE_DEPTH: usize = 128;
const SPARSE_KEY_HIGH_MAX: u128 = 0x8000000000000110000000000000000;
const TWO_POW_128: felt252 = 0x100000000000000000000000000000000;
const NOTE_MEMBERSHIP_KIND_DEPOSIT: felt252 = 0;
const NOTE_MEMBERSHIP_KIND_SETTLEMENT_OUTPUT: felt252 = 1;
const STATEMENT_TYPE_SETTLEMENT: felt252 = 1;
const STATEMENT_TYPE_ADMISSION: felt252 = 3;
const STATEMENT_TYPE_AUCTION_RESULT: felt252 = 4;
const STATEMENT_TYPE_NOTE_CONSOLIDATION: felt252 = 5;
const STATEMENT_TYPE_WITHDRAWAL: felt252 = 6;
const STATEMENT_TYPE_MULTI_PAIR: felt252 = 8;
const STATEMENT_TYPE_MULTI_PAIR_SETTLEMENT: felt252 = 9;
const MULTI_PAIR_DELTA_DIRECTION_IN: felt252 = 0;
const MULTI_PAIR_DELTA_DIRECTION_OUT: felt252 = 1;
const MULTI_PAIR_DELTA_SOURCE_USER: felt252 = 0;
const MULTI_PAIR_DELTA_SOURCE_EXTERNAL_COMPLETION: felt252 = 1;
const MULTI_PAIR_DELTA_SOURCE_FEE: felt252 = 2;
const MULTI_PAIR_WITNESS_DIGEST_DOMAIN: felt252 = 'zylith_mpair_in_v1';
const ADMISSION_ROOT_DOMAIN: felt252 = 0x7a796c6974685f61646d69745f726f6f745f7631;
const ADMISSION_LEAF_DOMAIN: felt252 = 0x7a796c6974685f61646d69745f6c6561665f7631;
const MAX_ORDER_FUNDING_INPUTS: usize = 4;
const MAX_SETTLEMENT_ORDERS: usize = 64;
const MAX_MULTI_PAIR_FILLS: usize = 64;
const MAX_MULTI_PAIR_ASSETS: usize = 8;
const MAX_MULTI_PAIR_ASSET_DELTAS: usize = 256;
const MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS: usize = 64;
const MAX_SETTLEMENT_INPUT_NOTES: usize = MAX_SETTLEMENT_ORDERS * MAX_ORDER_FUNDING_INPUTS;
const MAX_SETTLEMENT_OUTPUT_NOTES: usize = MAX_SETTLEMENT_ORDERS * 2 + 4;
const SETTLEMENT_HEADER_FIELD_COUNT: usize = 33;
const MAX_NOTE_CONSOLIDATION_NOTES: usize = MAX_SETTLEMENT_INPUT_NOTES;
const PAIR_ID_STRK_USDC: felt252 =
    0x116ee836b759d809a28dfcf84de04ce4d7ba6aca96741019ffcbbbbcaa8b29e;
const PAIR_ID_ETH_USDC: felt252 = 0x2cbcdace0891f8e930c42d95e41029a4b97dbefe3c7ab4fc1624e094b2c8b5;
const PAIR_ID_STRKBTC_USDC: felt252 =
    0x3175bbc313ab68e1f07eba1058d265be29fbdf69c0ddb8caccbfd76d3e30879;
const PAIR_ID_STRK_ETH: felt252 = 0x14b1e84d7d6fae29b9439cef188f5442d46c99d19dff91661595863d506e556;
const PAIR_ID_STRK_STRKBTC: felt252 =
    0x65011444e534a7ca8b4ee58eff07819342a4f35d51495af313aaffa482051a;
const PAIR_ID_WBTC_STRKBTC: felt252 =
    0x252c28489d75ea03408323cb9e3a5612c379ef971ba447b7a49f431ec9d2866;
const PAIR_ID_USDC_USDT: felt252 =
    0x28f97fdad77fbff0fc4c369dc3df554e9a0f782131015058ff3b0a8a2b22c22;
const ASSET_ID_STRK: felt252 = 0x8926041840302bbb1edfd15c98ffaf0f2a9e8ba0ac43bfd446942d708b7b7c;
const ASSET_ID_ETH: felt252 = 0x83191fc191d03c3f6f70ea7a1420780d860230dda0edfc2ae9ab762c72b2fe;
const ASSET_ID_USDC: felt252 = 0x1e565426a7cff134da7e67f4587da64258d8e50b249f60444b53d8aebb4987c;
const ASSET_ID_STRKBTC: felt252 = 0x26dca572f753af8ffa55041c9c436bd9e535bd7477c064dddca379969d2ae6e;
const ASSET_ID_WBTC: felt252 = 0x3b3e000e53e244119faa38c55046e99c91a379094cba1004bb729234aa64b6e;
const ASSET_ID_USDT: felt252 = 0x3b32cc2e88e8af80d7bd707fdcbf5ff2a2fb42b5fdf80b3289e5baf36c9f200;
const ASSET_SCALE_6: felt252 = 1000000;
const ASSET_SCALE_8: felt252 = 100000000;
const ASSET_SCALE_18: felt252 = 1000000000000000000;
const FUNDING_INPUT_SET_DOMAIN: felt252 = 0x7a796c6974685f66756e64696e675f7365745f7631;
const FUNDING_NULLIFIER_SET_DOMAIN: felt252 = 0x7a796c6974685f66756e64696e675f6e756c6c5f7631;
const NOTE_COMMITMENT_DOMAIN: felt252 =
    0x43aeae569e031a74671a28c60a017d2a53bbb5ffa6f6a7711c076348fb186c;
const SPEND_AUTHORITY_DOMAIN: felt252 =
    0x21b92fb580b0e2cb7898509d56df3d7b51d6f68f17b50aa02e93e0227b15f3b;
const SPEND_AUTHORIZATION_TAG_DOMAIN: felt252 =
    0x025a229e7207657107d37566206d51ed8d588a4c5406063f47350cb7ddc938f4;
const NULLIFIER_DOMAIN: felt252 = 0x6cd79aee4dd094aadf944f50e83fad66ce717a58d59d73a92df351aac6d14e3;
const ORDER_COMMITMENT_DOMAIN: felt252 =
    0x7cd5dda33869da7da5ccb3afbc70fc766fb0cbe3d560c2bfb3bdbab8a4b844d;
const PUBLIC_SETTLEMENT_DOMAIN: felt252 =
    0x0283f626418aa97a073f64500f7e35dd8bf7c01ff8611917c3c38e5be92eb205;
const PUBLIC_MULTI_PAIR_SETTLEMENT_DOMAIN: felt252 = 0x7a796c6974685f6d756c74695f736574746c655f7631;
const PUBLIC_NOTE_CONSOLIDATION_DOMAIN: felt252 = 0x7a796c6974685f6e6f74655f636f6e736f6c5f7631;
const PUBLIC_NOTE_WITHDRAWAL_DOMAIN: felt252 = 0x7a796c6974685f6e6f74655f77697468647261775f7631;
const CONSUMED_NOTE_ROOT_DOMAIN: felt252 =
    0x5ca3bbd6a01ed8e6017182aa4b43ec8d9e4055d9d4133b008c3ea9916b347dd;
const CONSUMED_NULLIFIER_ROOT_DOMAIN: felt252 =
    0x52259833b97a525483b8fff0635ce1f9fdfd08b5a8db2486d4a05378989b0f0;
const RENEWAL_CHILD_ROOT_DOMAIN: felt252 =
    0x7fa9bd33f1b9cd81a22d77d4dc7ea4d33abd249f7585d0e451b0fafa39dfc3d;
const OUTPUT_NOTE_ROOT_DOMAIN: felt252 =
    0x322d8a4d6fe2953496989824ec66bcb9d011aa052bb4be4593670c1ea7908dc;
const FEE_ROOT_DOMAIN: felt252 = 0x79a9e0b9d4a6b4cac728c0e5f6298e37533fa1348f020f3575a78c5adf7d44b;
const STATE_TRANSITION_ROOT_DOMAIN: felt252 =
    0x01f14f0555b0b80fd6af9553623a021c472d8c930dfcb5b204b35b26f0d2b1b2;
const NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL: felt252 =
    0x03fd7c748b95292c230aa528dc391912cd4557ad3e157e94ab06b22af433f967;
const NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL: felt252 =
    0x02de7e98b8f1ba580329d7cfcf51a36f6eb4f8611cae6f82b34e116bb9c2588c;

#[derive(Copy, Drop)]
struct MultiPairSettlementHeader {
    note_commitment_domain: felt252,
    spend_authority_domain: felt252,
    nullifier_domain: felt252,
    order_commitment_domain: felt252,
    public_multi_pair_settlement_domain: felt252,
    group_id: felt252,
    batch_epoch: felt252,
    transcript_commitment: felt252,
    protocol_fee_recipient: felt252,
    matched_order_count: felt252,
    output_bundle_ref: felt252,
    multi_pair_commitment: felt252,
    batch_binding_root: felt252,
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
}
const MULTI_PAIR_BATCH_ROOT_DOMAIN: felt252 =
    0x039f98f789ba5c8e01cb79a02c22b9d9e3d71e692cc6c17cb60f2ab76a4e9090;

fn assert_stwo_spend_authorization(
    message_hash: felt252,
    spend_authority: felt252,
    authorization_secret: felt252,
    authorization_tag: felt252,
    error_message: felt252,
) {
    assert(spend_authority != 0, error_message);
    assert(authorization_secret != 0, error_message);
    assert(authorization_tag != 0, error_message);
    assert(
        poseidon_hash2(SPEND_AUTHORITY_DOMAIN, authorization_secret) == spend_authority,
        error_message,
    );
    assert(
        poseidon_hash2(
            poseidon_hash2(SPEND_AUTHORIZATION_TAG_DOMAIN, message_hash), authorization_secret,
        ) == authorization_tag,
        error_message,
    );
}

pub fn verify_settlement_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_SETTLEMENT, 'E');

    let note_commitment_domain = read_next(data, ref index);
    let spend_authority_domain = read_next(data, ref index);
    let nullifier_domain = read_next(data, ref index);
    let order_commitment_domain = read_next(data, ref index);
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
    let price_base_scale = read_next(data, ref index);
    let taker_fee_bps = read_next(data, ref index);
    let protocol_fee_recipient = read_next(data, ref index);
    let matched_order_count = read_next(data, ref index);
    let output_bundle_ref = read_next(data, ref index);
    let multi_pair_commitment = read_next(data, ref index);
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

    assert(note_commitment_domain == NOTE_COMMITMENT_DOMAIN, 'E');
    assert(spend_authority_domain == SPEND_AUTHORITY_DOMAIN, 'E');
    assert(nullifier_domain == NULLIFIER_DOMAIN, 'E');
    assert(order_commitment_domain == ORDER_COMMITMENT_DOMAIN, 'E');
    assert(public_settlement_domain == PUBLIC_SETTLEMENT_DOMAIN, 'E');
    assert(batch_id != 0, 'E');
    assert(batch_epoch != 0, 'E');
    assert(order_commitment_root != 0, 'E');
    assert(encrypted_order_set_commitment != 0, 'E');
    assert(transcript_commitment != 0, 'E');
    assert(pair_id != 0, 'E');
    assert(base_asset_id != 0, 'E');
    assert(quote_asset_id != 0, 'E');
    if matched_order_count != 0 {
        assert(clearing_price != 0, 'E');
    }
    assert(price_base_scale != 0, 'E');
    assert(output_bundle_ref != 0, 'E');
    assert(consumed_note_root_domain == CONSUMED_NOTE_ROOT_DOMAIN, 'E');
    assert(consumed_nullifier_root_domain == CONSUMED_NULLIFIER_ROOT_DOMAIN, 'E');
    assert(renewal_child_root_domain == RENEWAL_CHILD_ROOT_DOMAIN, 'E');
    assert(output_note_root_domain == OUTPUT_NOTE_ROOT_DOMAIN, 'E');
    assert(fee_root_domain == FEE_ROOT_DOMAIN, 'E');
    assert(state_transition_root_domain == STATE_TRANSITION_ROOT_DOMAIN, 'E');
    assert(nullifier_sparse_leaf_domain == NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL, 'E');
    assert(nullifier_sparse_node_domain == NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL, 'E');
    assert(base_asset_id != quote_asset_id, 'E');
    assert_pair_config(pair_id, base_asset_id, quote_asset_id, price_base_scale);

    let matched_order_commitments = read_vector(data, ref index);
    let matched_fill_amounts = read_vector(data, ref index);
    let matched_sides = read_vector(data, ref index);
    let matched_order_types = read_vector(data, ref index);
    let matched_relay_modes = read_vector(data, ref index);
    let matched_limit_prices = read_vector(data, ref index);
    let matched_order_amounts = read_vector(data, ref index);
    let matched_min_fills = read_vector(data, ref index);
    let matched_time_in_force = read_vector(data, ref index);
    let matched_execution_preferences = read_vector(data, ref index);
    let matched_expiry_epochs = read_vector(data, ref index);
    let matched_order_nonces = read_vector(data, ref index);
    let matched_parent_order_commitments = read_vector(data, ref index);
    let matched_parent_child_indexes = read_vector(data, ref index);
    let matched_parent_secret_commitments = read_vector(data, ref index);
    let matched_parent_cancel_authorities = read_vector(data, ref index);
    let matched_parent_authorization_secrets = read_vector(data, ref index);
    let matched_auditor_flags = read_vector(data, ref index);
    let matched_funding_note_refs = read_vector(data, ref index);
    let matched_funding_input_counts = read_vector(data, ref index);
    let matched_funding_note_commitments = read_vector(data, ref index);
    let matched_funding_note_asset_ids = read_vector(data, ref index);
    let matched_funding_input_amounts = read_vector(data, ref index);
    let matched_funding_input_owner_keys = read_vector(data, ref index);
    let matched_funding_note_spend_authorities = read_vector(data, ref index);
    let matched_funding_note_withdraw_authorities = read_vector(data, ref index);
    let matched_funding_note_blindings = read_vector(data, ref index);
    let matched_funding_note_nonces = read_vector(data, ref index);
    let matched_funding_note_metadata_commitments = read_vector(data, ref index);
    let matched_funding_note_amounts = read_vector(data, ref index);
    let matched_funding_note_owner_keys = read_vector(data, ref index);
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
    assert(matched_len == matched_order_count, 'E');
    let funding_input_count = sum_funding_input_counts(matched_funding_input_counts.span());
    assert_settlement_bounds(
        matched_order_commitments.len(), funding_input_count, output_note_commitments.len(),
    );
    assert_all_lengths_match(
        matched_order_commitments.len(),
        array![
            matched_fill_amounts.len().into(), matched_sides.len().into(),
            matched_order_types.len().into(), matched_relay_modes.len().into(),
            matched_limit_prices.len().into(), matched_order_amounts.len().into(),
            matched_min_fills.len().into(), matched_time_in_force.len().into(),
            matched_execution_preferences.len().into(), matched_expiry_epochs.len().into(),
            matched_order_nonces.len().into(), matched_parent_order_commitments.len().into(),
            matched_parent_child_indexes.len().into(),
            matched_parent_secret_commitments.len().into(),
            matched_parent_cancel_authorities.len().into(),
            matched_parent_authorization_secrets.len().into(), matched_auditor_flags.len().into(),
            matched_funding_note_refs.len().into(), matched_funding_input_counts.len().into(),
            matched_funding_note_amounts.len().into(), matched_funding_note_owner_keys.len().into(),
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
        ]
            .span(),
        'E',
    );
    assert_all_lengths_match(
        funding_input_count,
        array![
            matched_funding_note_commitments.len().into(),
            matched_funding_note_asset_ids.len().into(), matched_funding_input_amounts.len().into(),
            matched_funding_input_owner_keys.len().into(),
            matched_funding_note_spend_authorities.len().into(),
            matched_funding_note_withdraw_authorities.len().into(),
            matched_funding_note_blindings.len().into(), matched_funding_note_nonces.len().into(),
            matched_funding_note_metadata_commitments.len().into(),
        ]
            .span(),
        'E',
    );
    assert_all_lengths_match(
        funding_input_count,
        array![
            consumed_note_commitments.len().into(), consumed_nullifiers.len().into(),
            note_membership_kinds.len().into(), note_membership_prefix_roots.len().into(),
            note_membership_batch_roots.len().into(), note_membership_path_counts.len().into(),
            note_membership_suffix_counts.len().into(),
        ]
            .span(),
        'E',
    );
    assert(note_membership_path_values.len() == note_membership_path_directions.len(), 'E');
    assert(output_note_commitments.len() == output_note_asset_ids.len(), 'E');
    assert(output_note_commitments.len() == output_note_amounts.len(), 'E');
    assert(output_note_commitments.len() == output_note_withdraw_authorities.len(), 'E');
    assert(output_note_commitments.len() == output_note_owner_keys.len(), 'E');
    assert(output_note_commitments.len() == output_note_spend_authorities.len(), 'E');
    assert(output_note_commitments.len() == output_note_blindings.len(), 'E');
    assert(output_note_commitments.len() == output_note_nonces.len(), 'E');
    assert(output_note_commitments.len() == output_note_metadata_commitments.len(), 'E');
    if matched_order_commitments.len() == 0 {
        assert(consumed_note_commitments.len() == 0, 'E');
        assert(consumed_nullifiers.len() == 0, 'E');
        assert(nullifier_sparse_key_lows.len() == 0, 'E');
        assert(nullifier_sparse_key_highs.len() == 0, 'E');
        assert(nullifier_sparse_path_counts.len() == 0, 'E');
        assert(nullifier_sparse_path_values.len() == 0, 'E');
        assert(nullifier_sparse_path_directions.len() == 0, 'E');
        assert(note_membership_kinds.len() == 0, 'E');
        assert(renewal_parent_order_commitments.len() == 0, 'E');
        assert(renewal_child_nullifiers.len() == 0, 'E');
        assert(renewal_child_sparse_key_lows.len() == 0, 'E');
        assert(renewal_child_sparse_key_highs.len() == 0, 'E');
        assert(renewal_child_sparse_path_counts.len() == 0, 'E');
        assert(renewal_child_sparse_path_values.len() == 0, 'E');
        assert(renewal_child_sparse_path_directions.len() == 0, 'E');
        assert(renewal_cancel_sparse_key_lows.len() == 0, 'E');
        assert(renewal_cancel_sparse_key_highs.len() == 0, 'E');
        assert(renewal_cancel_sparse_path_counts.len() == 0, 'E');
        assert(renewal_cancel_sparse_path_values.len() == 0, 'E');
        assert(renewal_cancel_sparse_path_directions.len() == 0, 'E');
        assert(output_note_commitments.len() == 0, 'E');
        assert(output_note_owner_keys.len() == 0, 'E');
    }

    assert_unique(matched_order_commitments.span(), 'E');
    assert_unique(consumed_note_commitments.span(), 'E');
    assert_unique(consumed_nullifiers.span(), 'E');
    assert(nullifier_sparse_key_lows.len() == consumed_nullifiers.len(), 'E');
    assert(nullifier_sparse_key_highs.len() == consumed_nullifiers.len(), 'E');
    assert(nullifier_sparse_path_counts.len() == consumed_nullifiers.len(), 'E');
    assert(nullifier_sparse_path_values.len() == nullifier_sparse_path_directions.len(), 'E');
    assert(renewal_parent_order_commitments.len() == renewal_child_nullifiers.len(), 'E');
    assert(renewal_child_sparse_key_lows.len() == renewal_child_nullifiers.len(), 'E');
    assert(renewal_child_sparse_key_highs.len() == renewal_child_nullifiers.len(), 'E');
    assert(renewal_child_sparse_path_counts.len() == renewal_child_nullifiers.len(), 'E');
    assert(renewal_cancel_sparse_key_lows.len() == renewal_child_nullifiers.len(), 'E');
    assert(renewal_cancel_sparse_key_highs.len() == renewal_child_nullifiers.len(), 'E');
    assert(renewal_cancel_sparse_path_counts.len() == renewal_child_nullifiers.len(), 'E');
    assert_unique(renewal_child_nullifiers.span(), 'E');
    assert_unique(output_note_commitments.span(), 'E');

    let clearing_price_u128 = felt_to_u128(clearing_price);
    let price_base_scale_u128 = felt_to_u128(price_base_scale);
    let taker_fee_bps_u128 = felt_to_u128(taker_fee_bps);
    assert(taker_fee_bps_u128 <= FEE_BPS_DENOMINATOR, 'E');
    assert(protocol_fee_recipient != 0, 'E');
    let mut index_order = 0;
    let mut total_buy_base: u128 = 0;
    let mut total_sell_base: u128 = 0;
    let mut expected_base_fee: u128 = 0;
    let mut expected_quote_fee: u128 = 0;
    let mut renewal_cursor = 0;
    let mut note_membership_path_cursor = 0;
    let mut note_membership_suffix_cursor = 0;
    let mut funding_input_cursor = 0;
    let mut public_output_cursor = 0;

    while index_order < matched_order_commitments.len() {
        let order_commitment = *matched_order_commitments.at(index_order);
        let filled_amount_felt = *matched_fill_amounts.at(index_order);
        let side = *matched_sides.at(index_order);
        let order_type = *matched_order_types.at(index_order);
        let relay_mode = *matched_relay_modes.at(index_order);
        let limit_price_felt = *matched_limit_prices.at(index_order);
        let order_amount_felt = *matched_order_amounts.at(index_order);
        let min_fill_felt = *matched_min_fills.at(index_order);
        let time_in_force = *matched_time_in_force.at(index_order);
        let execution_preference = *matched_execution_preferences.at(index_order);
        let expiry_epoch_felt = *matched_expiry_epochs.at(index_order);
        let order_nonce_felt = *matched_order_nonces.at(index_order);
        let parent_order_commitment = *matched_parent_order_commitments.at(index_order);
        let parent_child_index = *matched_parent_child_indexes.at(index_order);
        let parent_secret_commitment = *matched_parent_secret_commitments.at(index_order);
        let parent_cancel_authority = *matched_parent_cancel_authorities.at(index_order);
        let parent_authorization_secret = *matched_parent_authorization_secrets.at(index_order);
        let auditor_view_allowed = *matched_auditor_flags.at(index_order);
        let funding_note_ref = *matched_funding_note_refs.at(index_order);
        let funding_input_count_felt = *matched_funding_input_counts.at(index_order);
        let funding_note_amount_felt = *matched_funding_note_amounts.at(index_order);
        let funding_note_owner_key = *matched_funding_note_owner_keys.at(index_order);
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

        assert(order_commitment != 0, 'E');
        assert(filled_amount_felt != 0, 'E');
        assert(order_amount_felt != 0, 'E');
        assert(min_fill_felt != 0, 'E');
        assert(funding_note_ref != 0, 'E');
        assert(output_note_commitment != 0, 'E');
        assert(funding_note_owner_key != 0, 'E');
        assert(funding_note_amount_felt != 0, 'E');
        assert(funding_authorization_r != 0, 'E');
        assert(funding_authorization_s != 0, 'E');
        assert(recipient_owner_key != 0, 'E');
        assert(recipient_spend_authority != 0, 'E');
        assert(recipient_withdraw_authority != 0, 'E');
        assert(recipient_residual_withdraw_authority != 0, 'E');
        assert(output_note_owner_key != 0, 'E');
        assert(output_note_spend_authority != 0, 'E');
        assert(output_note_withdraw_authority != 0, 'E');
        assert(output_note_blinding != 0, 'E');
        assert(output_note_metadata_commitment != 0, 'E');
        assert(funding_nullifier != 0, 'E');
        assert(output_note_amount_felt != 0, 'E');
        assert(expiry_epoch_felt != 0, 'E');
        assert(expiry_epoch_felt == batch_epoch, 'E');
        assert(order_nonce_felt != 0, 'E');
        assert_parent_link(
            parent_order_commitment,
            parent_child_index,
            parent_secret_commitment,
            parent_cancel_authority,
            parent_authorization_secret,
        );
        assert_relay_mode(relay_mode, order_type, parent_order_commitment);
        if parent_order_commitment != 0 {
            assert(renewal_cursor < renewal_child_nullifiers.len(), 'E');
            assert(
                *renewal_parent_order_commitments.at(renewal_cursor) == parent_order_commitment,
                'E',
            );
            assert(
                *renewal_child_nullifiers
                    .at(
                        renewal_cursor,
                    ) == renewal_child_nullifier(
                        parent_order_commitment, parent_child_index, parent_authorization_secret,
                    ),
                'E',
            );
            renewal_cursor += 1;
        }
        assert(order_type == ORDER_TYPE_LIMIT_BATCH, 'E');
        assert(time_in_force == TIF_CURRENT_BATCH_ONLY || time_in_force == TIF_FILL_OR_KILL, 'E');
        assert(
            execution_preference == EXECUTION_PRIVATE_ONLY
                || execution_preference == EXECUTION_PRIVATE_THEN_EXTERNAL,
            'E',
        );
        assert(auditor_view_allowed == 0 || auditor_view_allowed == 1, 'E');
        assert(residual_note_flag == 0 || residual_note_flag == 1, 'E');
        assert(filled_amount <= order_amount, 'E');
        assert(filled_amount >= min_fill, 'E');
        if time_in_force == TIF_FILL_OR_KILL {
            assert(filled_amount == order_amount, 'E');
        }

        let recomputed_order_commitment = order_intent_commitment(
            order_commitment_domain,
            pair_id,
            batch_id,
            side,
            order_type,
            relay_mode,
            limit_price_felt,
            order_amount_felt,
            min_fill_felt,
            time_in_force,
            execution_preference,
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
        assert(order_commitment == recomputed_order_commitment, 'E');

        let funding_input_count: usize = funding_input_count_felt.try_into().expect('E');
        assert(funding_input_count != 0, 'E');
        assert(funding_input_count <= MAX_ORDER_FUNDING_INPUTS, 'E');
        assert(funding_input_cursor + funding_input_count <= consumed_note_commitments.len(), 'E');
        let first_input_commitment = *matched_funding_note_commitments.at(funding_input_cursor);
        let first_input_nullifier = note_nullifier(
            nullifier_domain,
            first_input_commitment,
            *matched_funding_note_blindings.at(funding_input_cursor),
        );
        let first_spend_authority = *matched_funding_note_spend_authorities
            .at(funding_input_cursor);
        assert(first_spend_authority != 0, 'E');
        assert_stwo_spend_authorization(
            order_commitment,
            first_spend_authority,
            funding_authorization_r,
            funding_authorization_s,
            'E',
        );
        let mut input_set_state = FUNDING_INPUT_SET_DOMAIN;
        let mut nullifier_set_state = FUNDING_NULLIFIER_SET_DOMAIN;
        let mut funding_input_index = 0;
        let mut recomputed_funding_amount: u128 = 0;
        while funding_input_index < funding_input_count {
            let flat_index = funding_input_cursor + funding_input_index;
            let funding_note_commitment = *matched_funding_note_commitments.at(flat_index);
            let funding_note_asset_id = *matched_funding_note_asset_ids.at(flat_index);
            let funding_input_amount_felt = *matched_funding_input_amounts.at(flat_index);
            let funding_input_owner_key = *matched_funding_input_owner_keys.at(flat_index);
            let funding_note_spend_authority = *matched_funding_note_spend_authorities
                .at(flat_index);
            let funding_note_withdraw_authority = *matched_funding_note_withdraw_authorities
                .at(flat_index);
            let funding_note_blinding = *matched_funding_note_blindings.at(flat_index);
            let funding_note_nonce_felt = *matched_funding_note_nonces.at(flat_index);
            let funding_note_metadata_commitment = *matched_funding_note_metadata_commitments
                .at(flat_index);

            assert(funding_note_commitment != 0, 'E');
            assert(funding_input_amount_felt != 0, 'E');
            assert(funding_input_owner_key == funding_note_owner_key, 'E');
            assert(funding_note_spend_authority == first_spend_authority, 'E');
            assert(funding_note_withdraw_authority != 0, 'E');
            assert(funding_note_blinding != 0, 'E');
            assert(funding_note_metadata_commitment != 0, 'E');
            if side == ORDER_SIDE_BUY {
                assert(funding_note_asset_id == quote_asset_id, 'E');
            } else {
                assert(side == ORDER_SIDE_SELL, 'E');
                assert(funding_note_asset_id == base_asset_id, 'E');
            }

            let recomputed_funding_note_commitment = note_commitment(
                note_commitment_domain,
                funding_note_asset_id,
                funding_input_amount_felt,
                funding_input_owner_key,
                funding_note_spend_authority,
                funding_note_withdraw_authority,
                funding_note_blinding,
                funding_note_nonce_felt,
                funding_note_metadata_commitment,
            );
            assert(funding_note_commitment == recomputed_funding_note_commitment, 'E');
            let input_nullifier = note_nullifier(
                nullifier_domain, funding_note_commitment, funding_note_blinding,
            );
            assert(funding_note_commitment == *consumed_note_commitments.at(flat_index), 'E');
            assert(input_nullifier == *consumed_nullifiers.at(flat_index), 'E');
            assert_note_membership(
                funding_note_commitment,
                funding_note_asset_id,
                funding_input_amount_felt,
                funding_note_withdraw_authority,
                prior_note_root,
                *note_membership_kinds.at(flat_index),
                *note_membership_prefix_roots.at(flat_index),
                *note_membership_batch_roots.at(flat_index),
                *note_membership_path_counts.at(flat_index),
                ref note_membership_path_cursor,
                note_membership_path_values.span(),
                note_membership_path_directions.span(),
                *note_membership_suffix_counts.at(flat_index),
                ref note_membership_suffix_cursor,
                note_membership_suffix_roots.span(),
                state_transition_root_domain,
            );
            input_set_state = poseidon_hash2(input_set_state, funding_note_commitment);
            nullifier_set_state = poseidon_hash2(nullifier_set_state, input_nullifier);
            recomputed_funding_amount = recomputed_funding_amount
                + felt_to_u128(funding_input_amount_felt);
            funding_input_index += 1;
        }
        let recomputed_funding_note_ref = if funding_input_count == 1 {
            first_input_commitment
        } else {
            poseidon_hash2(input_set_state, funding_input_count.into())
        };
        let recomputed_funding_nullifier = if funding_input_count == 1 {
            first_input_nullifier
        } else {
            poseidon_hash2(nullifier_set_state, funding_input_count.into())
        };
        assert(funding_note_ref == recomputed_funding_note_ref, 'E');
        assert(funding_nullifier == recomputed_funding_nullifier, 'E');
        assert(recomputed_funding_amount == funding_note_amount, 'E');
        funding_input_cursor += funding_input_count;

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
        assert(output_note_commitment == recomputed_output_note_commitment, 'E');
        assert(output_note_owner_key == recipient_owner_key, 'E');
        assert(output_note_spend_authority == recipient_spend_authority, 'E');
        assert(output_note_withdraw_authority == recipient_withdraw_authority, 'E');

        let order_fee_bps = fee_bps_for_order_type(
            order_type, parent_order_commitment, taker_fee_bps_u128,
        );
        let (expected_primary_amount, expected_residual_amount) = if side == ORDER_SIDE_BUY {
            assert(limit_price >= clearing_price_u128, 'E');
            assert(output_note_asset_id == base_asset_id, 'E');
            let spend_amount = quote_amount_for_base_amount(
                filled_amount, clearing_price_u128, price_base_scale_u128,
            );
            assert(funding_note_amount >= spend_amount, 'E');
            let fee_amount = ceil_fee_amount(filled_amount, order_fee_bps);
            assert(fee_amount <= filled_amount, 'E');
            total_buy_base = total_buy_base + filled_amount;
            expected_base_fee = expected_base_fee + fee_amount;
            (filled_amount - fee_amount, funding_note_amount - spend_amount)
        } else {
            assert(side == ORDER_SIDE_SELL, 'E');
            assert(limit_price <= clearing_price_u128, 'E');
            assert(output_note_asset_id == quote_asset_id, 'E');
            assert(funding_note_amount >= filled_amount, 'E');
            let gross_quote = quote_amount_for_base_amount(
                filled_amount, clearing_price_u128, price_base_scale_u128,
            );
            let fee_amount = ceil_fee_amount(gross_quote, order_fee_bps);
            assert(fee_amount <= gross_quote, 'E');
            total_sell_base = total_sell_base + filled_amount;
            expected_quote_fee = expected_quote_fee + fee_amount;
            (gross_quote - fee_amount, funding_note_amount - filled_amount)
        };
        assert(output_note_amount == expected_primary_amount, 'E');
        assert_canonical_public_output(
            ref public_output_cursor,
            output_note_commitment,
            output_note_asset_id,
            output_note_amount,
            output_note_withdraw_authority,
            output_note_commitments.span(),
            output_note_asset_ids.span(),
            output_note_amounts.span(),
            output_note_withdraw_authorities.span(),
        );

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
            assert(residual_note_flag == 1, 'E');
            let expected_residual_asset_id = if side == ORDER_SIDE_BUY {
                quote_asset_id
            } else {
                base_asset_id
            };
            assert(residual_note_asset_id == expected_residual_asset_id, 'E');
            assert(residual_note_owner_key == recipient_owner_key, 'E');
            assert(residual_note_spend_authority == recipient_spend_authority, 'E');
            assert(residual_note_withdraw_authority == recipient_residual_withdraw_authority, 'E');
            assert(residual_note_blinding != 0, 'E');
            assert(residual_note_nonce_felt != 0, 'E');
            assert(residual_note_metadata_commitment != 0, 'E');
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
            assert(residual_note_commitment == recomputed_residual_note_commitment, 'E');
            assert(felt_to_u128(residual_note_amount_felt) == expected_residual_amount, 'E');
            assert_canonical_public_output(
                ref public_output_cursor,
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
    assert(renewal_cursor == renewal_child_nullifiers.len(), 'E');
    assert(total_buy_base == total_sell_base, 'E');
    assert(funding_input_cursor == consumed_note_commitments.len(), 'E');
    assert(note_membership_path_cursor == note_membership_path_values.len(), 'E');
    assert(note_membership_path_cursor == note_membership_path_directions.len(), 'E');
    assert(note_membership_suffix_cursor == note_membership_suffix_roots.len(), 'E');

    assert_fee_output(
        ref public_output_cursor,
        note_commitment_domain,
        base_asset_id,
        expected_base_fee,
        protocol_fee_recipient,
        output_note_commitments.span(),
        output_note_asset_ids.span(),
        output_note_amounts.span(),
        output_note_withdraw_authorities.span(),
        output_note_owner_keys.span(),
        output_note_spend_authorities.span(),
        output_note_blindings.span(),
        output_note_nonces.span(),
        output_note_metadata_commitments.span(),
    );
    assert_fee_output(
        ref public_output_cursor,
        note_commitment_domain,
        quote_asset_id,
        expected_quote_fee,
        protocol_fee_recipient,
        output_note_commitments.span(),
        output_note_asset_ids.span(),
        output_note_amounts.span(),
        output_note_withdraw_authorities.span(),
        output_note_owner_keys.span(),
        output_note_spend_authorities.span(),
        output_note_blindings.span(),
        output_note_nonces.span(),
        output_note_metadata_commitments.span(),
    );
    assert(public_output_cursor == output_note_commitments.len(), 'E');

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
        fee_root_domain,
        base_asset_id,
        quote_asset_id,
        protocol_fee_recipient,
        expected_base_fee,
        expected_quote_fee,
    );
    let new_note_root = state_transition_root(
        state_transition_root_domain, prior_note_root, output_note_root,
    );
    let new_nullifier_root = read_next(data, ref index);
    if consumed_nullifiers.len() == 0 {
        assert(new_nullifier_root == prior_nullifier_root, 'E');
    }
    let new_renewal_root = read_next(data, ref index);
    if renewal_child_nullifiers.len() == 0 {
        assert(new_renewal_root == prior_renewal_root, 'E');
    }
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
        price_base_scale,
        taker_fee_bps,
        protocol_fee_recipient,
        output_bundle_ref,
        multi_pair_commitment,
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
    assert(recomputed_public_settlement == transcript_commitment, 'E');
    assert(index == data.len(), 'E');

    transcript_commitment
}

pub fn verify_settlement_note_fee_statement(data: Span<felt252>) -> felt252 {
    verify_settlement_statement(data)
}

pub fn verify_settlement_order_statement(data: Span<felt252>) -> felt252 {
    verify_settlement_statement(data)
}

pub fn verify_settlement_output_recovery_statement(data: Span<felt252>) -> felt252 {
    verify_settlement_statement(data)
}

pub fn verify_settlement_input_membership_statement(data: Span<felt252>) -> felt252 {
    verify_settlement_statement(data)
}

pub fn verify_nullifier_statement(data: Span<felt252>) -> (felt252, felt252, felt252, felt252) {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_SETTLEMENT, 'E');
    skip_fields(data, ref index, 10);
    let transcript_commitment = read_next(data, ref index);
    skip_fields(data, ref index, 10);
    let prior_nullifier_root = read_next(data, ref index);
    skip_fields(data, ref index, 3);
    let consumed_nullifier_root_domain = read_next(data, ref index);
    skip_fields(data, ref index, 4);
    let nullifier_sparse_leaf_domain = read_next(data, ref index);
    let nullifier_sparse_node_domain = read_next(data, ref index);

    assert(transcript_commitment != 0, 'E');
    assert(consumed_nullifier_root_domain == CONSUMED_NULLIFIER_ROOT_DOMAIN, 'E');
    assert(nullifier_sparse_leaf_domain == NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL, 'E');
    assert(nullifier_sparse_node_domain == NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL, 'E');

    skip_vectors(data, ref index, 56);
    let consumed_note_commitments = read_vector(data, ref index);
    let consumed_nullifiers = read_vector(data, ref index);
    let nullifier_sparse_key_lows = read_vector(data, ref index);
    let nullifier_sparse_key_highs = read_vector(data, ref index);
    let nullifier_sparse_path_counts = read_vector(data, ref index);
    let nullifier_sparse_path_values = read_vector(data, ref index);
    let nullifier_sparse_path_directions = read_vector(data, ref index);
    skip_vectors(data, ref index, 33);
    let claimed_new_nullifier_root = read_next(data, ref index);
    read_next(data, ref index);
    assert(index == data.len(), 'E');

    assert(consumed_note_commitments.len() == consumed_nullifiers.len(), 'E');
    assert(consumed_nullifiers.len() <= MAX_SETTLEMENT_INPUT_NOTES, 'E');
    assert(nullifier_sparse_key_lows.len() == consumed_nullifiers.len(), 'E');
    assert(nullifier_sparse_key_highs.len() == consumed_nullifiers.len(), 'E');
    assert(nullifier_sparse_path_counts.len() == consumed_nullifiers.len(), 'E');
    assert_unique(consumed_nullifiers.span(), 'E');

    let consumed_nullifier_root = single_field_root(
        consumed_nullifier_root_domain, consumed_nullifiers.span(),
    );
    let running_nullifier_root = assert_sparse_nullifier_updates(
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
    if consumed_nullifiers.len() == 0 {
        assert(claimed_new_nullifier_root == prior_nullifier_root, 'E');
    } else {
        assert(running_nullifier_root == claimed_new_nullifier_root, 'E');
    }
    (
        transcript_commitment,
        prior_nullifier_root,
        consumed_nullifier_root,
        claimed_new_nullifier_root,
    )
}

pub fn verify_renewal_statement(data: Span<felt252>) -> (felt252, felt252, felt252, felt252) {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_SETTLEMENT, 'E');
    skip_fields(data, ref index, 10);
    let transcript_commitment = read_next(data, ref index);
    skip_fields(data, ref index, 11);
    let prior_renewal_root = read_next(data, ref index);
    skip_fields(data, ref index, 3);
    let renewal_child_root_domain = read_next(data, ref index);
    skip_fields(data, ref index, 3);
    let nullifier_sparse_leaf_domain = read_next(data, ref index);
    let nullifier_sparse_node_domain = read_next(data, ref index);

    assert(transcript_commitment != 0, 'E');
    assert(renewal_child_root_domain == RENEWAL_CHILD_ROOT_DOMAIN, 'E');
    assert(nullifier_sparse_leaf_domain == NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL, 'E');
    assert(nullifier_sparse_node_domain == NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL, 'E');

    let matched_order_commitments = read_vector(data, ref index);
    skip_vectors(data, ref index, 10);
    let matched_parent_order_commitments = read_vector(data, ref index);
    let matched_parent_child_indexes = read_vector(data, ref index);
    let matched_parent_secret_commitments = read_vector(data, ref index);
    let matched_parent_cancel_authorities = read_vector(data, ref index);
    let matched_parent_authorization_secrets = read_vector(data, ref index);
    skip_vectors(data, ref index, 55);
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
    skip_vectors(data, ref index, 13);
    read_next(data, ref index);
    let claimed_new_renewal_root = read_next(data, ref index);
    assert(index == data.len(), 'E');

    assert_all_lengths_match(
        matched_order_commitments.len(),
        array![
            matched_parent_order_commitments.len().into(),
            matched_parent_child_indexes.len().into(),
            matched_parent_secret_commitments.len().into(),
            matched_parent_cancel_authorities.len().into(),
            matched_parent_authorization_secrets.len().into(),
        ]
            .span(),
        'E',
    );
    assert(matched_order_commitments.len() <= MAX_SETTLEMENT_ORDERS, 'E');
    assert(renewal_child_nullifiers.len() <= MAX_SETTLEMENT_ORDERS, 'E');
    assert(renewal_parent_order_commitments.len() == renewal_child_nullifiers.len(), 'E');
    assert(renewal_child_sparse_key_lows.len() == renewal_child_nullifiers.len(), 'E');
    assert(renewal_child_sparse_key_highs.len() == renewal_child_nullifiers.len(), 'E');
    assert(renewal_child_sparse_path_counts.len() == renewal_child_nullifiers.len(), 'E');
    assert(renewal_cancel_sparse_key_lows.len() == renewal_child_nullifiers.len(), 'E');
    assert(renewal_cancel_sparse_key_highs.len() == renewal_child_nullifiers.len(), 'E');
    assert(renewal_cancel_sparse_path_counts.len() == renewal_child_nullifiers.len(), 'E');
    assert_unique(renewal_child_nullifiers.span(), 'E');

    let mut renewal_cursor = 0;
    let mut renewal_child_path_cursor = 0;
    let mut renewal_cancel_path_cursor = 0;
    let mut running_renewal_root = prior_renewal_root;
    let mut order_index = 0;
    while order_index < matched_order_commitments.len() {
        let parent_order_commitment = *matched_parent_order_commitments.at(order_index);
        let parent_child_index = *matched_parent_child_indexes.at(order_index);
        let parent_secret_commitment = *matched_parent_secret_commitments.at(order_index);
        let parent_cancel_authority = *matched_parent_cancel_authorities.at(order_index);
        let parent_authorization_secret = *matched_parent_authorization_secrets.at(order_index);
        assert_parent_link(
            parent_order_commitment,
            parent_child_index,
            parent_secret_commitment,
            parent_cancel_authority,
            parent_authorization_secret,
        );
        if parent_order_commitment != 0 {
            assert(renewal_cursor < renewal_child_nullifiers.len(), 'E');
            assert(
                *renewal_parent_order_commitments.at(renewal_cursor) == parent_order_commitment,
                'E',
            );
            assert(
                *renewal_child_nullifiers
                    .at(
                        renewal_cursor,
                    ) == renewal_child_nullifier(
                        parent_order_commitment, parent_child_index, parent_authorization_secret,
                    ),
                'E',
            );
            let renewal_cancel_marker = renewal_parent_cancel_marker(
                parent_secret_commitment, parent_cancel_authority,
            );
            running_renewal_root =
                assert_renewal_entry_absent(
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
                assert_renewal_entry_insert(
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
        order_index += 1;
    }
    assert(renewal_cursor == renewal_child_nullifiers.len(), 'E');
    assert(renewal_child_path_cursor == renewal_child_sparse_path_values.len(), 'E');
    assert(renewal_child_path_cursor == renewal_child_sparse_path_directions.len(), 'E');
    assert(renewal_cancel_path_cursor == renewal_cancel_sparse_path_values.len(), 'E');
    assert(renewal_cancel_path_cursor == renewal_cancel_sparse_path_directions.len(), 'E');

    let renewal_child_root = single_field_root(
        renewal_child_root_domain, renewal_child_nullifiers.span(),
    );
    if renewal_child_nullifiers.len() == 0 {
        assert(claimed_new_renewal_root == prior_renewal_root, 'E');
    } else {
        assert(running_renewal_root == claimed_new_renewal_root, 'E');
    }
    (transcript_commitment, prior_renewal_root, renewal_child_root, claimed_new_renewal_root)
}

pub fn verify_multi_pair_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_MULTI_PAIR, 'MP_TYPE');
    let batch_id = read_next(data, ref index);
    assert(batch_id != 0, 'MP_BATCH');

    let order_commitments = read_vector(data, ref index);
    let pair_ids = read_vector(data, ref index);
    let base_asset_ids = read_vector(data, ref index);
    let quote_asset_ids = read_vector(data, ref index);
    let sides = read_vector(data, ref index);
    let submitted_base_amounts = read_vector(data, ref index);
    let min_fill_base_amounts = read_vector(data, ref index);
    let limit_prices = read_vector(data, ref index);
    let price_base_scales = read_vector(data, ref index);
    let filled_base_amounts = read_vector(data, ref index);
    let quote_amounts = read_vector(data, ref index);
    let fee_amounts = read_vector(data, ref index);

    let delta_asset_ids = read_vector(data, ref index);
    let delta_amounts = read_vector(data, ref index);
    let delta_directions = read_vector(data, ref index);
    let delta_sources = read_vector(data, ref index);
    let delta_source_commitments = read_vector(data, ref index);

    let eligible_order_commitments = read_vector(data, ref index);
    let objective_asset_ids = read_vector(data, ref index);
    let objective_numerators = read_vector(data, ref index);
    let objective_denominators = read_vector(data, ref index);

    let candidate_solution_ids = read_vector(data, ref index);
    let candidate_fill_counts = read_vector(data, ref index);
    let candidate_delta_counts = read_vector(data, ref index);

    let candidate_order_commitments = read_vector(data, ref index);
    let candidate_pair_ids = read_vector(data, ref index);
    let candidate_base_asset_ids = read_vector(data, ref index);
    let candidate_quote_asset_ids = read_vector(data, ref index);
    let candidate_sides = read_vector(data, ref index);
    let candidate_submitted_base_amounts = read_vector(data, ref index);
    let candidate_min_fill_base_amounts = read_vector(data, ref index);
    let candidate_limit_prices = read_vector(data, ref index);
    let candidate_price_base_scales = read_vector(data, ref index);
    let candidate_filled_base_amounts = read_vector(data, ref index);
    let candidate_quote_amounts = read_vector(data, ref index);
    let candidate_fee_amounts = read_vector(data, ref index);

    let candidate_delta_asset_ids = read_vector(data, ref index);
    let candidate_delta_amounts = read_vector(data, ref index);
    let candidate_delta_directions = read_vector(data, ref index);
    let candidate_delta_sources = read_vector(data, ref index);
    let candidate_delta_source_commitments = read_vector(data, ref index);

    assert(index == data.len(), 'MP_LEN');

    assert_multi_pair_fill_vectors(
        order_commitments.span(),
        pair_ids.span(),
        base_asset_ids.span(),
        quote_asset_ids.span(),
        sides.span(),
        submitted_base_amounts.span(),
        min_fill_base_amounts.span(),
        limit_prices.span(),
        price_base_scales.span(),
        filled_base_amounts.span(),
        quote_amounts.span(),
        fee_amounts.span(),
        0,
        order_commitments.len(),
    );
    assert_multi_pair_delta_vectors(
        delta_asset_ids.span(),
        delta_amounts.span(),
        delta_directions.span(),
        delta_sources.span(),
        delta_source_commitments.span(),
        0,
        delta_asset_ids.len(),
    );
    assert_multi_pair_eligible_orders(
        order_commitments.span(), 0, order_commitments.len(), eligible_order_commitments.span(),
    );
    assert_multi_pair_asset_conservation(
        delta_asset_ids.span(),
        delta_amounts.span(),
        delta_directions.span(),
        0,
        delta_asset_ids.len(),
    );
    assert_multi_pair_user_fee_delta_bindings(
        order_commitments.span(),
        base_asset_ids.span(),
        quote_asset_ids.span(),
        sides.span(),
        filled_base_amounts.span(),
        quote_amounts.span(),
        fee_amounts.span(),
        0,
        order_commitments.len(),
        delta_asset_ids.span(),
        delta_amounts.span(),
        delta_directions.span(),
        delta_sources.span(),
        delta_source_commitments.span(),
        0,
        delta_asset_ids.len(),
    );
    assert_multi_pair_objective_weights(
        objective_asset_ids.span(), objective_numerators.span(), objective_denominators.span(),
    );

    let chosen_objective = multi_pair_objective_score(
        base_asset_ids.span(),
        quote_asset_ids.span(),
        sides.span(),
        filled_base_amounts.span(),
        quote_amounts.span(),
        fee_amounts.span(),
        0,
        order_commitments.len(),
        objective_asset_ids.span(),
        objective_numerators.span(),
        objective_denominators.span(),
    );

    assert(candidate_solution_ids.len() != 0, 'MP_CAND');
    assert(candidate_solution_ids.len() <= MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS, 'MP_CAND');
    assert(candidate_solution_ids.len() == candidate_fill_counts.len(), 'MP_CAND');
    assert(candidate_solution_ids.len() == candidate_delta_counts.len(), 'MP_CAND');

    let mut candidate_index = 0;
    let mut fill_cursor: usize = 0;
    let mut delta_cursor: usize = 0;
    while candidate_index < candidate_solution_ids.len() {
        assert(*candidate_solution_ids.at(candidate_index) != 0, 'MP_CAND');
        let fill_count: usize = (*candidate_fill_counts.at(candidate_index))
            .try_into()
            .expect('MP_CAND');
        let delta_count: usize = (*candidate_delta_counts.at(candidate_index))
            .try_into()
            .expect('MP_CAND');
        assert(fill_count != 0, 'MP_CAND');
        assert(delta_count != 0, 'MP_CAND');

        assert_multi_pair_fill_vectors(
            candidate_order_commitments.span(),
            candidate_pair_ids.span(),
            candidate_base_asset_ids.span(),
            candidate_quote_asset_ids.span(),
            candidate_sides.span(),
            candidate_submitted_base_amounts.span(),
            candidate_min_fill_base_amounts.span(),
            candidate_limit_prices.span(),
            candidate_price_base_scales.span(),
            candidate_filled_base_amounts.span(),
            candidate_quote_amounts.span(),
            candidate_fee_amounts.span(),
            fill_cursor,
            fill_count,
        );
        assert_multi_pair_delta_vectors(
            candidate_delta_asset_ids.span(),
            candidate_delta_amounts.span(),
            candidate_delta_directions.span(),
            candidate_delta_sources.span(),
            candidate_delta_source_commitments.span(),
            delta_cursor,
            delta_count,
        );
        assert_multi_pair_eligible_orders(
            candidate_order_commitments.span(),
            fill_cursor,
            fill_count,
            eligible_order_commitments.span(),
        );
        assert_multi_pair_asset_conservation(
            candidate_delta_asset_ids.span(),
            candidate_delta_amounts.span(),
            candidate_delta_directions.span(),
            delta_cursor,
            delta_count,
        );
        assert_multi_pair_user_fee_delta_bindings(
            candidate_order_commitments.span(),
            candidate_base_asset_ids.span(),
            candidate_quote_asset_ids.span(),
            candidate_sides.span(),
            candidate_filled_base_amounts.span(),
            candidate_quote_amounts.span(),
            candidate_fee_amounts.span(),
            fill_cursor,
            fill_count,
            candidate_delta_asset_ids.span(),
            candidate_delta_amounts.span(),
            candidate_delta_directions.span(),
            candidate_delta_sources.span(),
            candidate_delta_source_commitments.span(),
            delta_cursor,
            delta_count,
        );
        let candidate_objective = multi_pair_objective_score(
            candidate_base_asset_ids.span(),
            candidate_quote_asset_ids.span(),
            candidate_sides.span(),
            candidate_filled_base_amounts.span(),
            candidate_quote_amounts.span(),
            candidate_fee_amounts.span(),
            fill_cursor,
            fill_count,
            objective_asset_ids.span(),
            objective_numerators.span(),
            objective_denominators.span(),
        );
        assert(chosen_objective >= candidate_objective, 'MP_BEST');

        fill_cursor += fill_count;
        delta_cursor += delta_count;
        candidate_index += 1;
    }

    assert(fill_cursor == candidate_order_commitments.len(), 'MP_CAND');
    assert(delta_cursor == candidate_delta_asset_ids.len(), 'MP_CAND');

    let witness_digest = multi_pair_witness_digest(data);
    multi_pair_statement_commitment(
        batch_id,
        chosen_objective.into(),
        order_commitments.len().into(),
        delta_asset_ids.len().into(),
        candidate_solution_ids.len().into(),
        witness_digest,
    )
}

fn read_multi_pair_settlement_header(
    data: Span<felt252>, ref index: usize,
) -> MultiPairSettlementHeader {
    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_MULTI_PAIR_SETTLEMENT, 'MPS_TYPE');
    let header = MultiPairSettlementHeader {
        note_commitment_domain: read_next(data, ref index),
        spend_authority_domain: read_next(data, ref index),
        nullifier_domain: read_next(data, ref index),
        order_commitment_domain: read_next(data, ref index),
        public_multi_pair_settlement_domain: read_next(data, ref index),
        group_id: read_next(data, ref index),
        batch_epoch: read_next(data, ref index),
        transcript_commitment: read_next(data, ref index),
        protocol_fee_recipient: read_next(data, ref index),
        matched_order_count: read_next(data, ref index),
        output_bundle_ref: read_next(data, ref index),
        multi_pair_commitment: read_next(data, ref index),
        batch_binding_root: read_next(data, ref index),
        prior_note_root: read_next(data, ref index),
        prior_nullifier_root: read_next(data, ref index),
        prior_renewal_root: read_next(data, ref index),
        prior_fee_root: read_next(data, ref index),
        consumed_note_root: read_next(data, ref index),
        consumed_nullifier_root: read_next(data, ref index),
        renewal_child_root: read_next(data, ref index),
        output_note_root: read_next(data, ref index),
        fee_root: read_next(data, ref index),
        new_note_root: read_next(data, ref index),
        new_nullifier_root: read_next(data, ref index),
        new_renewal_root: read_next(data, ref index),
        new_fee_root: read_next(data, ref index),
    };
    assert(header.note_commitment_domain == NOTE_COMMITMENT_DOMAIN, 'MPS_DOMAIN');
    assert(header.spend_authority_domain == SPEND_AUTHORITY_DOMAIN, 'MPS_DOMAIN');
    assert(header.nullifier_domain == NULLIFIER_DOMAIN, 'MPS_DOMAIN');
    assert(header.order_commitment_domain == ORDER_COMMITMENT_DOMAIN, 'MPS_DOMAIN');
    assert(
        header.public_multi_pair_settlement_domain == PUBLIC_MULTI_PAIR_SETTLEMENT_DOMAIN,
        'MPS_DOMAIN',
    );
    assert(header.group_id != 0, 'MPS_GROUP');
    assert(header.batch_epoch != 0, 'MPS_EPOCH');
    assert(header.transcript_commitment != 0, 'MPS_TRANSCRIPT');
    assert(header.protocol_fee_recipient != 0, 'MPS_FEE_RECIPIENT');
    assert(header.output_bundle_ref != 0, 'MPS_OUTPUT_BUNDLE');
    assert(header.multi_pair_commitment != 0, 'MPS_MULTI_PAIR');
    assert(header.batch_binding_root != 0, 'MPS_BINDING_ROOT');
    header
}

fn assert_multi_pair_settlement_public_commitment(header: MultiPairSettlementHeader) {
    let recomputed_commitment = public_multi_pair_settlement_commitment(
        header.group_id,
        header.batch_epoch,
        header.batch_binding_root,
        header.protocol_fee_recipient,
        header.output_bundle_ref,
        header.multi_pair_commitment,
        header.prior_note_root,
        header.prior_nullifier_root,
        header.prior_renewal_root,
        header.prior_fee_root,
        header.consumed_note_root,
        header.consumed_nullifier_root,
        header.renewal_child_root,
        header.output_note_root,
        header.fee_root,
        header.new_note_root,
        header.new_nullifier_root,
        header.new_renewal_root,
        header.new_fee_root,
    );
    assert(recomputed_commitment == header.transcript_commitment, 'MPS_TRANSCRIPT_BIND');
}

pub fn verify_multi_pair_settlement_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_MULTI_PAIR_SETTLEMENT, 'MPS_TYPE');
    let note_commitment_domain = read_next(data, ref index);
    let spend_authority_domain = read_next(data, ref index);
    let nullifier_domain = read_next(data, ref index);
    let order_commitment_domain = read_next(data, ref index);
    let public_multi_pair_settlement_domain = read_next(data, ref index);
    let group_id = read_next(data, ref index);
    let batch_epoch = read_next(data, ref index);
    let transcript_commitment = read_next(data, ref index);
    let protocol_fee_recipient = read_next(data, ref index);
    let matched_order_count = read_next(data, ref index);
    let output_bundle_ref = read_next(data, ref index);
    let multi_pair_commitment = read_next(data, ref index);
    let batch_binding_root = read_next(data, ref index);
    let prior_note_root = read_next(data, ref index);
    let prior_nullifier_root = read_next(data, ref index);
    let prior_renewal_root = read_next(data, ref index);
    let prior_fee_root = read_next(data, ref index);
    let consumed_note_root = read_next(data, ref index);
    let consumed_nullifier_root = read_next(data, ref index);
    let renewal_child_root = read_next(data, ref index);
    let output_note_root = read_next(data, ref index);
    let fee_root = read_next(data, ref index);
    let new_note_root = read_next(data, ref index);
    let new_nullifier_root = read_next(data, ref index);
    let new_renewal_root = read_next(data, ref index);
    let new_fee_root = read_next(data, ref index);

    assert(note_commitment_domain == NOTE_COMMITMENT_DOMAIN, 'MPS_DOMAIN');
    assert(spend_authority_domain == SPEND_AUTHORITY_DOMAIN, 'MPS_DOMAIN');
    assert(nullifier_domain == NULLIFIER_DOMAIN, 'MPS_DOMAIN');
    assert(order_commitment_domain == ORDER_COMMITMENT_DOMAIN, 'MPS_DOMAIN');
    assert(
        public_multi_pair_settlement_domain == PUBLIC_MULTI_PAIR_SETTLEMENT_DOMAIN, 'MPS_DOMAIN',
    );
    assert(group_id != 0, 'MPS_GROUP');
    assert(batch_epoch != 0, 'MPS_EPOCH');
    assert(transcript_commitment != 0, 'MPS_TRANSCRIPT');
    assert(protocol_fee_recipient != 0, 'MPS_FEE_RECIPIENT');
    assert(output_bundle_ref != 0, 'MPS_OUTPUT_BUNDLE');
    assert(multi_pair_commitment != 0, 'MPS_MULTI_PAIR');
    assert(batch_binding_root != 0, 'MPS_BINDING_ROOT');

    let batch_ids = read_vector(data, ref index);
    let pair_ids = read_vector(data, ref index);
    let order_commitment_roots = read_vector(data, ref index);
    let encrypted_order_set_commitments = read_vector(data, ref index);
    let base_asset_ids = read_vector(data, ref index);
    let quote_asset_ids = read_vector(data, ref index);
    let price_base_scales = read_vector(data, ref index);
    let taker_fee_bps_values = read_vector(data, ref index);
    let nested_multi_pair_serialized = read_vector(data, ref index);
    let nested_multi_pair = length_prefixed_payload(nested_multi_pair_serialized.span(), 'MPS_MP');

    let matched_order_batch_ids = read_vector(data, ref index);
    let matched_order_commitments = read_vector(data, ref index);
    let matched_fill_amounts = read_vector(data, ref index);
    let consumed_note_commitments = read_vector(data, ref index);
    let consumed_nullifiers = read_vector(data, ref index);
    let renewal_parent_order_commitments = read_vector(data, ref index);
    let renewal_child_nullifiers = read_vector(data, ref index);
    let output_note_commitments = read_vector(data, ref index);
    let output_note_asset_ids = read_vector(data, ref index);
    let output_note_amounts = read_vector(data, ref index);
    let output_note_withdraw_authorities = read_vector(data, ref index);
    let fee_asset_ids = read_vector(data, ref index);
    let fee_amounts = read_vector(data, ref index);
    let fee_recipients = read_vector(data, ref index);
    let matched_sides = read_vector(data, ref index);
    let matched_order_types = read_vector(data, ref index);
    let matched_relay_modes = read_vector(data, ref index);
    let matched_limit_prices = read_vector(data, ref index);
    let matched_order_amounts = read_vector(data, ref index);
    let matched_min_fills = read_vector(data, ref index);
    let matched_time_in_force = read_vector(data, ref index);
    let matched_execution_preferences = read_vector(data, ref index);
    let matched_expiry_epochs = read_vector(data, ref index);
    let matched_order_nonces = read_vector(data, ref index);
    let matched_parent_order_commitments = read_vector(data, ref index);
    let matched_parent_child_indexes = read_vector(data, ref index);
    let matched_parent_secret_commitments = read_vector(data, ref index);
    let matched_parent_cancel_authorities = read_vector(data, ref index);
    let matched_parent_authorization_secrets = read_vector(data, ref index);
    let matched_auditor_flags = read_vector(data, ref index);
    let matched_funding_note_refs = read_vector(data, ref index);
    let matched_funding_input_counts = read_vector(data, ref index);
    let matched_funding_note_commitments = read_vector(data, ref index);
    let matched_funding_note_asset_ids = read_vector(data, ref index);
    let matched_funding_input_amounts = read_vector(data, ref index);
    let matched_funding_input_owner_keys = read_vector(data, ref index);
    let matched_funding_note_spend_authorities = read_vector(data, ref index);
    let matched_funding_note_withdraw_authorities = read_vector(data, ref index);
    let matched_funding_note_blindings = read_vector(data, ref index);
    let matched_funding_note_nonces = read_vector(data, ref index);
    let matched_funding_note_metadata_commitments = read_vector(data, ref index);
    let matched_funding_note_amounts = read_vector(data, ref index);
    let matched_funding_note_owner_keys = read_vector(data, ref index);
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
    let output_note_owner_keys = read_vector(data, ref index);
    let output_note_spend_authorities = read_vector(data, ref index);
    let output_note_blindings = read_vector(data, ref index);
    let output_note_nonces = read_vector(data, ref index);
    let output_note_metadata_commitments = read_vector(data, ref index);
    let output_recovery_key_tags = read_vector(data, ref index);
    let output_recovery_auth_tags = read_vector(data, ref index);
    let output_recovery_ciphertext_fields = read_vector(data, ref index);
    let output_recovery_dummy_commitments = read_vector(data, ref index);
    assert(index == data.len(), 'MPS_LEN');

    assert_multi_pair_settlement_binding_vectors(
        batch_ids.span(),
        pair_ids.span(),
        order_commitment_roots.span(),
        encrypted_order_set_commitments.span(),
        base_asset_ids.span(),
        quote_asset_ids.span(),
        price_base_scales.span(),
        taker_fee_bps_values.span(),
    );
    assert_all_nonzero(batch_ids.span(), 'MPS_BATCH');
    assert_all_nonzero(pair_ids.span(), 'MPS_PAIR');
    assert_all_nonzero(order_commitment_roots.span(), 'MPS_ORDER_ROOT');
    assert_all_nonzero(encrypted_order_set_commitments.span(), 'MPS_ENC_ROOT');
    assert_all_nonzero(base_asset_ids.span(), 'MPS_BASE');
    assert_all_nonzero(quote_asset_ids.span(), 'MPS_QUOTE');
    assert_unique_nonzero(batch_ids.span(), 'MPS_BATCH_DUP');
    let mut binding_index = 0;
    while binding_index < batch_ids.len() {
        assert(*base_asset_ids.at(binding_index) != *quote_asset_ids.at(binding_index), 'MPS_PAIR');
        assert(felt_to_u128(*price_base_scales.at(binding_index)) != 0, 'MPS_PRICE_SCALE');
        assert(
            felt_to_u128(*taker_fee_bps_values.at(binding_index)) <= FEE_BPS_DENOMINATOR, 'MPS_FEE',
        );
        binding_index += 1;
    }
    assert(
        multi_pair_batch_binding_root(
            batch_ids.span(),
            pair_ids.span(),
            batch_epoch,
            order_commitment_roots.span(),
            encrypted_order_set_commitments.span(),
            base_asset_ids.span(),
            quote_asset_ids.span(),
            price_base_scales.span(),
            taker_fee_bps_values.span(),
        ) == batch_binding_root,
        'MPS_BINDING',
    );

    let nested_commitment = verify_multi_pair_statement(nested_multi_pair.span());
    assert(nested_commitment == multi_pair_commitment, 'MPS_MP_BIND');
    assert(multi_pair_payload_group_id(nested_multi_pair.span()) == group_id, 'MPS_MP_GROUP');
    let (
        nested_order_commitments,
        nested_pair_ids,
        nested_base_asset_ids,
        nested_quote_asset_ids,
        nested_sides,
        nested_submitted_base_amounts,
        nested_min_fill_base_amounts,
        nested_limit_prices,
        nested_price_base_scales,
        nested_filled_base_amounts,
        nested_quote_amounts,
        nested_fee_amounts,
    ) =
        multi_pair_payload_chosen_fill_vectors(
        nested_multi_pair.span(),
    );

    assert(matched_order_count == matched_order_commitments.len().into(), 'MPS_MATCHED');
    assert(matched_order_count == matched_order_batch_ids.len().into(), 'MPS_MATCHED');
    assert(matched_order_count == matched_fill_amounts.len().into(), 'MPS_MATCHED');
    assert(matched_order_count == nested_order_commitments.len().into(), 'MPS_MATCHED');
    assert_equal_vectors(
        matched_order_commitments.span(), nested_order_commitments.span(), 'MPS_MATCHED',
    );
    assert_equal_vectors(
        matched_fill_amounts.span(), nested_filled_base_amounts.span(), 'MPS_FILL',
    );
    assert_equal_vectors(matched_sides.span(), nested_sides.span(), 'MPS_SIDE');
    assert_equal_vectors(
        matched_order_amounts.span(), nested_submitted_base_amounts.span(), 'MPS_AMOUNT',
    );
    assert_equal_vectors(
        matched_min_fills.span(), nested_min_fill_base_amounts.span(), 'MPS_MIN_FILL',
    );
    assert_equal_vectors(matched_limit_prices.span(), nested_limit_prices.span(), 'MPS_LIMIT');
    assert_matched_fill_batch_bindings(
        matched_order_batch_ids.span(),
        nested_pair_ids.span(),
        nested_base_asset_ids.span(),
        nested_quote_asset_ids.span(),
        nested_price_base_scales.span(),
        batch_ids.span(),
        pair_ids.span(),
        base_asset_ids.span(),
        quote_asset_ids.span(),
        price_base_scales.span(),
    );

    let funding_input_count = sum_funding_input_counts(matched_funding_input_counts.span());
    assert_settlement_bounds(
        matched_order_commitments.len(), funding_input_count, output_note_commitments.len(),
    );
    assert_all_lengths_match(
        matched_order_commitments.len(),
        array![
            matched_sides.len().into(), matched_order_types.len().into(),
            matched_relay_modes.len().into(), matched_limit_prices.len().into(),
            matched_order_amounts.len().into(), matched_min_fills.len().into(),
            matched_time_in_force.len().into(), matched_execution_preferences.len().into(),
            matched_expiry_epochs.len().into(), matched_order_nonces.len().into(),
            matched_parent_order_commitments.len().into(),
            matched_parent_child_indexes.len().into(),
            matched_parent_secret_commitments.len().into(),
            matched_parent_cancel_authorities.len().into(),
            matched_parent_authorization_secrets.len().into(), matched_auditor_flags.len().into(),
            matched_funding_note_refs.len().into(), matched_funding_input_counts.len().into(),
            matched_funding_note_amounts.len().into(), matched_funding_note_owner_keys.len().into(),
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
        ]
            .span(),
        'MPS_ORDER_LEN',
    );
    assert_all_lengths_match(
        funding_input_count,
        array![
            matched_funding_note_commitments.len().into(),
            matched_funding_note_asset_ids.len().into(), matched_funding_input_amounts.len().into(),
            matched_funding_input_owner_keys.len().into(),
            matched_funding_note_spend_authorities.len().into(),
            matched_funding_note_withdraw_authorities.len().into(),
            matched_funding_note_blindings.len().into(), matched_funding_note_nonces.len().into(),
            matched_funding_note_metadata_commitments.len().into(),
            consumed_note_commitments.len().into(), consumed_nullifiers.len().into(),
            note_membership_kinds.len().into(), note_membership_prefix_roots.len().into(),
            note_membership_batch_roots.len().into(), note_membership_path_counts.len().into(),
            note_membership_suffix_counts.len().into(),
        ]
            .span(),
        'MPS_FUNDING_LEN',
    );
    assert(
        note_membership_path_values.len() == note_membership_path_directions.len(), 'MPS_NOTE_PATH',
    );
    assert(renewal_parent_order_commitments.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL');
    assert(renewal_child_sparse_key_lows.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL');
    assert(renewal_child_sparse_key_highs.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL');
    assert(renewal_child_sparse_path_counts.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL');
    assert(renewal_cancel_sparse_key_lows.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL');
    assert(renewal_cancel_sparse_key_highs.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL');
    assert(
        renewal_cancel_sparse_path_counts.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL',
    );
    assert(
        renewal_child_sparse_path_values.len() == renewal_child_sparse_path_directions.len(),
        'MPS_RENEWAL_PATH',
    );
    assert(
        renewal_cancel_sparse_path_values.len() == renewal_cancel_sparse_path_directions.len(),
        'MPS_RENEWAL_PATH',
    );
    assert(output_note_commitments.len() == output_note_asset_ids.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_amounts.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_withdraw_authorities.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_owner_keys.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_spend_authorities.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_blindings.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_nonces.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_metadata_commitments.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_recovery_key_tags.len(), 'MPS_RECOVERY');
    assert(output_note_commitments.len() == output_recovery_auth_tags.len(), 'MPS_RECOVERY');
    assert(
        output_recovery_ciphertext_fields.len() == output_note_commitments.len()
            * OUTPUT_RECOVERY_FIELD_COUNT,
        'MPS_RECOVERY',
    );
    assert(fee_asset_ids.len() == fee_amounts.len(), 'MPS_FEE');
    assert(fee_asset_ids.len() == fee_recipients.len(), 'MPS_FEE');
    assert_unique_nonzero(matched_order_commitments.span(), 'MPS_ORDER_DUP');
    assert_unique(consumed_note_commitments.span(), 'MPS_CONSUMED_DUP');
    assert_unique(consumed_nullifiers.span(), 'MPS_NULLIFIER_DUP');
    assert_unique(renewal_child_nullifiers.span(), 'MPS_RENEWAL_DUP');
    assert_unique_nonzero(fee_asset_ids.span(), 'MPS_FEE_DUP');
    assert(nullifier_sparse_key_lows.len() == consumed_nullifiers.len(), 'MPS_NULLIFIER');
    assert(nullifier_sparse_key_highs.len() == consumed_nullifiers.len(), 'MPS_NULLIFIER');
    assert(nullifier_sparse_path_counts.len() == consumed_nullifiers.len(), 'MPS_NULLIFIER');
    assert(
        nullifier_sparse_path_values.len() == nullifier_sparse_path_directions.len(),
        'MPS_NULLIFIER',
    );

    let mut order_index = 0;
    let mut funding_input_cursor = 0;
    let mut renewal_cursor = 0;
    let mut renewal_child_path_cursor = 0;
    let mut renewal_cancel_path_cursor = 0;
    let mut running_renewal_root = prior_renewal_root;
    let mut public_output_cursor = 0;
    let mut note_membership_path_cursor = 0;
    let mut note_membership_suffix_cursor = 0;
    while order_index < matched_order_commitments.len() {
        let order_commitment = *matched_order_commitments.at(order_index);
        let batch_id_for_order = *matched_order_batch_ids.at(order_index);
        let pair_id_for_order = *nested_pair_ids.at(order_index);
        let base_asset_id_for_order = *nested_base_asset_ids.at(order_index);
        let quote_asset_id_for_order = *nested_quote_asset_ids.at(order_index);
        let side = *matched_sides.at(order_index);
        let order_type = *matched_order_types.at(order_index);
        let relay_mode = *matched_relay_modes.at(order_index);
        let limit_price_felt = *matched_limit_prices.at(order_index);
        let order_amount_felt = *matched_order_amounts.at(order_index);
        let min_fill_felt = *matched_min_fills.at(order_index);
        let time_in_force = *matched_time_in_force.at(order_index);
        let execution_preference = *matched_execution_preferences.at(order_index);
        let expiry_epoch_felt = *matched_expiry_epochs.at(order_index);
        let order_nonce_felt = *matched_order_nonces.at(order_index);
        let parent_order_commitment = *matched_parent_order_commitments.at(order_index);
        let parent_child_index = *matched_parent_child_indexes.at(order_index);
        let parent_secret_commitment = *matched_parent_secret_commitments.at(order_index);
        let parent_cancel_authority = *matched_parent_cancel_authorities.at(order_index);
        let parent_authorization_secret = *matched_parent_authorization_secrets.at(order_index);
        let auditor_view_allowed = *matched_auditor_flags.at(order_index);
        let funding_note_ref = *matched_funding_note_refs.at(order_index);
        let funding_input_count_felt = *matched_funding_input_counts.at(order_index);
        let funding_note_amount_felt = *matched_funding_note_amounts.at(order_index);
        let funding_note_owner_key = *matched_funding_note_owner_keys.at(order_index);
        let funding_authorization_r = *matched_funding_authorization_rs.at(order_index);
        let funding_authorization_s = *matched_funding_authorization_ss.at(order_index);
        let funding_nullifier = *matched_funding_nullifiers.at(order_index);
        let recipient_owner_key = *matched_recipient_owner_keys.at(order_index);
        let recipient_spend_authority = *matched_recipient_spend_authorities.at(order_index);
        let recipient_withdraw_authority = *matched_recipient_withdraw_authorities.at(order_index);
        let recipient_residual_withdraw_authority = *matched_res_withdraw_auths.at(order_index);
        let output_note_commitment = *matched_output_note_commitments.at(order_index);
        let output_note_asset_id = *matched_output_note_asset_ids.at(order_index);
        let output_note_amount_felt = *matched_output_note_amounts.at(order_index);
        let output_note_owner_key = *matched_output_note_owner_keys.at(order_index);
        let output_note_spend_authority = *matched_output_note_spend_authorities.at(order_index);
        let output_note_withdraw_authority = *matched_output_note_withdraw_authorities
            .at(order_index);
        let output_note_blinding = *matched_output_note_blindings.at(order_index);
        let output_note_nonce_felt = *matched_output_note_nonces.at(order_index);
        let output_note_metadata_commitment = *matched_output_note_metadata_commitments
            .at(order_index);
        let residual_note_flag = *matched_residual_note_flags.at(order_index);
        let residual_note_commitment = *matched_residual_note_commitments.at(order_index);
        let residual_note_asset_id = *matched_residual_note_asset_ids.at(order_index);
        let residual_note_amount_felt = *matched_residual_note_amounts.at(order_index);
        let residual_note_owner_key = *matched_residual_note_owner_keys.at(order_index);
        let residual_note_spend_authority = *matched_residual_note_spend_authorities
            .at(order_index);
        let residual_note_withdraw_authority = *matched_residual_note_withdraw_authorities
            .at(order_index);
        let residual_note_blinding = *matched_residual_note_blindings.at(order_index);
        let residual_note_nonce_felt = *matched_residual_note_nonces.at(order_index);
        let residual_note_metadata_commitment = *matched_residual_note_metadata_commitments
            .at(order_index);

        let filled_base_amount = felt_to_u128(*nested_filled_base_amounts.at(order_index));
        let quote_amount = felt_to_u128(*nested_quote_amounts.at(order_index));
        let fee_amount = felt_to_u128(*nested_fee_amounts.at(order_index));
        let order_amount = felt_to_u128(order_amount_felt);
        let min_fill = felt_to_u128(min_fill_felt);
        let funding_note_amount = felt_to_u128(funding_note_amount_felt);
        let output_note_amount = felt_to_u128(output_note_amount_felt);

        assert(order_type == ORDER_TYPE_LIMIT_BATCH, 'MPS_ORDER_TYPE');
        assert(order_commitment != 0, 'MPS_ORDER');
        assert(filled_base_amount != 0, 'MPS_FILL');
        assert(filled_base_amount <= order_amount, 'MPS_FILL');
        assert(filled_base_amount >= min_fill, 'MPS_FILL');
        assert(
            time_in_force == TIF_CURRENT_BATCH_ONLY || time_in_force == TIF_FILL_OR_KILL, 'MPS_TIF',
        );
        assert(
            execution_preference == EXECUTION_PRIVATE_ONLY
                || execution_preference == EXECUTION_PRIVATE_THEN_EXTERNAL,
            'MPS_EXEC',
        );
        if time_in_force == TIF_FILL_OR_KILL {
            assert(filled_base_amount == order_amount, 'MPS_FOK');
        }
        assert(expiry_epoch_felt == batch_epoch, 'MPS_EPOCH');
        assert(order_nonce_felt != 0, 'MPS_NONCE');
        assert_parent_link(
            parent_order_commitment,
            parent_child_index,
            parent_secret_commitment,
            parent_cancel_authority,
            parent_authorization_secret,
        );
        assert_relay_mode(relay_mode, order_type, parent_order_commitment);
        if parent_order_commitment != 0 {
            assert(renewal_cursor < renewal_child_nullifiers.len(), 'MPS_RENEWAL');
            assert(
                *renewal_parent_order_commitments.at(renewal_cursor) == parent_order_commitment,
                'MPS_RENEWAL',
            );
            assert(
                *renewal_child_nullifiers
                    .at(
                        renewal_cursor,
                    ) == renewal_child_nullifier(
                        parent_order_commitment, parent_child_index, parent_authorization_secret,
                    ),
                'MPS_RENEWAL',
            );
            let renewal_cancel_marker = renewal_parent_cancel_marker(
                parent_secret_commitment, parent_cancel_authority,
            );
            running_renewal_root =
                assert_renewal_entry_absent(
                    running_renewal_root,
                    renewal_cancel_marker,
                    *renewal_cancel_sparse_key_lows.at(renewal_cursor),
                    *renewal_cancel_sparse_key_highs.at(renewal_cursor),
                    *renewal_cancel_sparse_path_counts.at(renewal_cursor),
                    ref renewal_cancel_path_cursor,
                    renewal_cancel_sparse_path_values.span(),
                    renewal_cancel_sparse_path_directions.span(),
                    NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL,
                );
            running_renewal_root =
                assert_renewal_entry_insert(
                    running_renewal_root,
                    *renewal_child_nullifiers.at(renewal_cursor),
                    *renewal_child_sparse_key_lows.at(renewal_cursor),
                    *renewal_child_sparse_key_highs.at(renewal_cursor),
                    *renewal_child_sparse_path_counts.at(renewal_cursor),
                    ref renewal_child_path_cursor,
                    renewal_child_sparse_path_values.span(),
                    renewal_child_sparse_path_directions.span(),
                    NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL,
                    NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL,
                );
            renewal_cursor += 1;
        }
        assert(auditor_view_allowed == 0 || auditor_view_allowed == 1, 'MPS_AUDITOR');
        let recomputed_order_commitment = order_intent_commitment(
            order_commitment_domain,
            pair_id_for_order,
            batch_id_for_order,
            side,
            order_type,
            relay_mode,
            limit_price_felt,
            order_amount_felt,
            min_fill_felt,
            time_in_force,
            execution_preference,
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
        assert(order_commitment == recomputed_order_commitment, 'MPS_ORDER_COMMIT');

        let funding_input_count_for_order: usize = funding_input_count_felt
            .try_into()
            .expect('MPS_FUNDING');
        assert(funding_input_count_for_order != 0, 'MPS_FUNDING');
        assert(funding_input_count_for_order <= MAX_ORDER_FUNDING_INPUTS, 'MPS_FUNDING');
        assert(
            funding_input_cursor + funding_input_count_for_order <= consumed_note_commitments.len(),
            'MPS_FUNDING',
        );
        let first_input_commitment = *matched_funding_note_commitments.at(funding_input_cursor);
        let first_input_nullifier = note_nullifier(
            nullifier_domain,
            first_input_commitment,
            *matched_funding_note_blindings.at(funding_input_cursor),
        );
        let first_spend_authority = *matched_funding_note_spend_authorities
            .at(funding_input_cursor);
        assert_stwo_spend_authorization(
            order_commitment,
            first_spend_authority,
            funding_authorization_r,
            funding_authorization_s,
            'MPS_AUTH',
        );
        let mut input_set_state = FUNDING_INPUT_SET_DOMAIN;
        let mut nullifier_set_state = FUNDING_NULLIFIER_SET_DOMAIN;
        let mut recomputed_funding_amount: u128 = 0;
        let mut funding_index = 0;
        while funding_index < funding_input_count_for_order {
            let flat_index = funding_input_cursor + funding_index;
            let funding_note_commitment = *matched_funding_note_commitments.at(flat_index);
            let funding_note_asset_id = *matched_funding_note_asset_ids.at(flat_index);
            let funding_input_amount_felt = *matched_funding_input_amounts.at(flat_index);
            let funding_input_owner_key = *matched_funding_input_owner_keys.at(flat_index);
            let funding_note_spend_authority = *matched_funding_note_spend_authorities
                .at(flat_index);
            let funding_note_withdraw_authority = *matched_funding_note_withdraw_authorities
                .at(flat_index);
            let funding_note_blinding = *matched_funding_note_blindings.at(flat_index);
            let funding_note_nonce_felt = *matched_funding_note_nonces.at(flat_index);
            let funding_note_metadata_commitment = *matched_funding_note_metadata_commitments
                .at(flat_index);
            assert(funding_note_commitment != 0, 'MPS_FUNDING');
            assert(funding_input_owner_key == funding_note_owner_key, 'MPS_FUNDING_OWNER');
            assert(funding_note_spend_authority == first_spend_authority, 'MPS_FUNDING_AUTH');
            if side == ORDER_SIDE_BUY {
                assert(funding_note_asset_id == quote_asset_id_for_order, 'MPS_FUNDING_ASSET');
            } else {
                assert(side == ORDER_SIDE_SELL, 'MPS_SIDE');
                assert(funding_note_asset_id == base_asset_id_for_order, 'MPS_FUNDING_ASSET');
            }
            assert(
                note_commitment(
                    note_commitment_domain,
                    funding_note_asset_id,
                    funding_input_amount_felt,
                    funding_input_owner_key,
                    funding_note_spend_authority,
                    funding_note_withdraw_authority,
                    funding_note_blinding,
                    funding_note_nonce_felt,
                    funding_note_metadata_commitment,
                ) == funding_note_commitment,
                'MPS_FUNDING_COMMIT',
            );
            let input_nullifier = note_nullifier(
                nullifier_domain, funding_note_commitment, funding_note_blinding,
            );
            assert(funding_note_commitment == *consumed_note_commitments.at(flat_index), 'MPS_IN');
            assert(input_nullifier == *consumed_nullifiers.at(flat_index), 'MPS_NULLIFIER');
            assert_note_membership(
                funding_note_commitment,
                funding_note_asset_id,
                funding_input_amount_felt,
                funding_note_withdraw_authority,
                prior_note_root,
                *note_membership_kinds.at(flat_index),
                *note_membership_prefix_roots.at(flat_index),
                *note_membership_batch_roots.at(flat_index),
                *note_membership_path_counts.at(flat_index),
                ref note_membership_path_cursor,
                note_membership_path_values.span(),
                note_membership_path_directions.span(),
                *note_membership_suffix_counts.at(flat_index),
                ref note_membership_suffix_cursor,
                note_membership_suffix_roots.span(),
                STATE_TRANSITION_ROOT_DOMAIN,
            );
            input_set_state = poseidon_hash2(input_set_state, funding_note_commitment);
            nullifier_set_state = poseidon_hash2(nullifier_set_state, input_nullifier);
            recomputed_funding_amount += felt_to_u128(funding_input_amount_felt);
            funding_index += 1;
        }
        let recomputed_funding_note_ref = if funding_input_count_for_order == 1 {
            first_input_commitment
        } else {
            poseidon_hash2(input_set_state, funding_input_count_for_order.into())
        };
        let recomputed_funding_nullifier = if funding_input_count_for_order == 1 {
            first_input_nullifier
        } else {
            poseidon_hash2(nullifier_set_state, funding_input_count_for_order.into())
        };
        assert(funding_note_ref == recomputed_funding_note_ref, 'MPS_FUNDING_REF');
        assert(funding_nullifier == recomputed_funding_nullifier, 'MPS_FUNDING_NULL');
        assert(recomputed_funding_amount == funding_note_amount, 'MPS_FUNDING_AMOUNT');
        funding_input_cursor += funding_input_count_for_order;

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
        assert(output_note_commitment == recomputed_output_note_commitment, 'MPS_OUT_COMMIT');
        assert(output_note_owner_key == recipient_owner_key, 'MPS_OUT_OWNER');
        assert(output_note_spend_authority == recipient_spend_authority, 'MPS_OUT_AUTH');
        assert(output_note_withdraw_authority == recipient_withdraw_authority, 'MPS_OUT_WITHDRAW');
        let input_amount = if side == ORDER_SIDE_BUY {
            quote_amount
        } else {
            filled_base_amount
        };
        let gross_output = if side == ORDER_SIDE_BUY {
            filled_base_amount
        } else {
            quote_amount
        };
        let expected_output_asset = if side == ORDER_SIDE_BUY {
            base_asset_id_for_order
        } else {
            quote_asset_id_for_order
        };
        assert(funding_note_amount >= input_amount, 'MPS_FUNDING_AMOUNT');
        assert(fee_amount < gross_output, 'MPS_FEE_AMOUNT');
        assert(output_note_asset_id == expected_output_asset, 'MPS_OUT_ASSET');
        assert(output_note_amount == gross_output - fee_amount, 'MPS_OUT_AMOUNT');
        assert_canonical_public_output(
            ref public_output_cursor,
            output_note_commitment,
            output_note_asset_id,
            output_note_amount,
            output_note_withdraw_authority,
            output_note_commitments.span(),
            output_note_asset_ids.span(),
            output_note_amounts.span(),
            output_note_withdraw_authorities.span(),
        );
        let expected_residual_amount = funding_note_amount - input_amount;
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
            assert(residual_note_flag == 1, 'MPS_RESIDUAL');
            let expected_residual_asset = if side == ORDER_SIDE_BUY {
                quote_asset_id_for_order
            } else {
                base_asset_id_for_order
            };
            assert(residual_note_asset_id == expected_residual_asset, 'MPS_RES_ASSET');
            assert(residual_note_owner_key == recipient_owner_key, 'MPS_RES_OWNER');
            assert(residual_note_spend_authority == recipient_spend_authority, 'MPS_RES_AUTH');
            assert(
                residual_note_withdraw_authority == recipient_residual_withdraw_authority,
                'MPS_RES_WITHDRAW',
            );
            assert(residual_note_blinding != 0, 'MPS_RES_BLINDING');
            assert(residual_note_nonce_felt != 0, 'MPS_RES_NONCE');
            assert(residual_note_metadata_commitment != 0, 'MPS_RES_META');
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
                residual_note_commitment == recomputed_residual_note_commitment, 'MPS_RES_COMMIT',
            );
            assert(
                felt_to_u128(residual_note_amount_felt) == expected_residual_amount,
                'MPS_RES_AMOUNT',
            );
            assert_canonical_public_output(
                ref public_output_cursor,
                residual_note_commitment,
                residual_note_asset_id,
                expected_residual_amount,
                residual_note_withdraw_authority,
                output_note_commitments.span(),
                output_note_asset_ids.span(),
                output_note_amounts.span(),
                output_note_withdraw_authorities.span(),
            );
        }
        order_index += 1;
    }
    assert(funding_input_cursor == consumed_note_commitments.len(), 'MPS_FUNDING_TRAIL');
    assert(renewal_cursor == renewal_child_nullifiers.len(), 'MPS_RENEWAL_TRAIL');
    assert(renewal_child_path_cursor == renewal_child_sparse_path_values.len(), 'MPS_RENEWAL_PATH');
    assert(
        renewal_child_path_cursor == renewal_child_sparse_path_directions.len(), 'MPS_RENEWAL_PATH',
    );
    assert(
        renewal_cancel_path_cursor == renewal_cancel_sparse_path_values.len(), 'MPS_RENEWAL_PATH',
    );
    assert(
        renewal_cancel_path_cursor == renewal_cancel_sparse_path_directions.len(),
        'MPS_RENEWAL_PATH',
    );
    assert(note_membership_path_cursor == note_membership_path_values.len(), 'MPS_NOTE_PATH');
    assert(note_membership_path_cursor == note_membership_path_directions.len(), 'MPS_NOTE_PATH');
    assert(note_membership_suffix_cursor == note_membership_suffix_roots.len(), 'MPS_NOTE_SUFFIX');

    assert(
        single_field_root(
            CONSUMED_NOTE_ROOT_DOMAIN, consumed_note_commitments.span(),
        ) == consumed_note_root,
        'MPS_CONSUMED_NOTES',
    );
    assert(
        single_field_root(
            CONSUMED_NULLIFIER_ROOT_DOMAIN, consumed_nullifiers.span(),
        ) == consumed_nullifier_root,
        'MPS_CONSUMED_NULLS',
    );
    assert(
        single_field_root(
            RENEWAL_CHILD_ROOT_DOMAIN, renewal_child_nullifiers.span(),
        ) == renewal_child_root,
        'MPS_RENEWAL_ROOT',
    );
    assert(
        output_note_merkle_root(
            output_bundle_ref,
            output_note_commitments.span(),
            output_note_asset_ids.span(),
            output_note_amounts.span(),
            output_note_withdraw_authorities.span(),
        ) == output_note_root,
        'MPS_OUTPUT_ROOT',
    );
    assert(
        multi_pair_fee_root(
            FEE_ROOT_DOMAIN, fee_asset_ids.span(), fee_amounts.span(), fee_recipients.span(),
        ) == fee_root,
        'MPS_FEE_ROOT',
    );
    assert(
        new_note_root == state_transition_root(
            STATE_TRANSITION_ROOT_DOMAIN, prior_note_root, output_note_root,
        ),
        'MPS_NOTE_ROOT',
    );
    let running_nullifier_root = assert_sparse_nullifier_updates(
        prior_nullifier_root,
        consumed_nullifiers.span(),
        nullifier_sparse_key_lows.span(),
        nullifier_sparse_key_highs.span(),
        nullifier_sparse_path_counts.span(),
        nullifier_sparse_path_values.span(),
        nullifier_sparse_path_directions.span(),
        NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL,
        NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL,
    );
    if consumed_nullifiers.len() == 0 {
        assert(new_nullifier_root == prior_nullifier_root, 'MPS_NULL_ROOT');
    } else {
        assert(new_nullifier_root == running_nullifier_root, 'MPS_NULL_ROOT');
    }
    if renewal_child_nullifiers.len() == 0 {
        assert(new_renewal_root == prior_renewal_root, 'MPS_RENEWAL_STATE');
    } else {
        assert(new_renewal_root == running_renewal_root, 'MPS_RENEWAL_STATE');
    }
    assert_multi_pair_all_positive_fees_have_entries(
        fee_asset_ids.span(),
        fee_amounts.span(),
        nested_base_asset_ids.span(),
        nested_quote_asset_ids.span(),
        nested_sides.span(),
        nested_fee_amounts.span(),
    );
    assert_multi_pair_fee_entries_are_exact(
        fee_asset_ids.span(),
        fee_amounts.span(),
        nested_base_asset_ids.span(),
        nested_quote_asset_ids.span(),
        nested_sides.span(),
        nested_fee_amounts.span(),
    );
    let mut fee_index = 0;
    while fee_index < fee_asset_ids.len() {
        assert(*fee_recipients.at(fee_index) == protocol_fee_recipient, 'MPS_FEE_RECIPIENT');
        assert_fee_output(
            ref public_output_cursor,
            note_commitment_domain,
            *fee_asset_ids.at(fee_index),
            felt_to_u128(*fee_amounts.at(fee_index)),
            protocol_fee_recipient,
            output_note_commitments.span(),
            output_note_asset_ids.span(),
            output_note_amounts.span(),
            output_note_withdraw_authorities.span(),
            output_note_owner_keys.span(),
            output_note_spend_authorities.span(),
            output_note_blindings.span(),
            output_note_nonces.span(),
            output_note_metadata_commitments.span(),
        );
        fee_index += 1;
    }
    assert(public_output_cursor == output_note_commitments.len(), 'MPS_OUTPUT_TRAIL');
    assert_output_recovery_bundle(
        note_commitment_domain,
        output_bundle_ref,
        group_id,
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
    assert(
        new_fee_root == state_transition_root(
            STATE_TRANSITION_ROOT_DOMAIN, prior_fee_root, fee_root,
        ),
        'MPS_FEE_STATE',
    );

    let recomputed_commitment = public_multi_pair_settlement_commitment(
        group_id,
        batch_epoch,
        batch_binding_root,
        protocol_fee_recipient,
        output_bundle_ref,
        multi_pair_commitment,
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
    assert(recomputed_commitment == transcript_commitment, 'MPS_TRANSCRIPT_BIND');
    transcript_commitment
}

pub fn verify_multi_pair_settlement_public_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;
    let header = read_multi_pair_settlement_header(data, ref index);

    let batch_ids = read_vector(data, ref index);
    let pair_ids = read_vector(data, ref index);
    let order_commitment_roots = read_vector(data, ref index);
    let encrypted_order_set_commitments = read_vector(data, ref index);
    let base_asset_ids = read_vector(data, ref index);
    let quote_asset_ids = read_vector(data, ref index);
    let price_base_scales = read_vector(data, ref index);
    let taker_fee_bps_values = read_vector(data, ref index);
    skip_vectors(data, ref index, 101);
    assert(index == data.len(), 'MPS_PUBLIC_LEN');

    assert_multi_pair_settlement_binding_vectors(
        batch_ids.span(),
        pair_ids.span(),
        order_commitment_roots.span(),
        encrypted_order_set_commitments.span(),
        base_asset_ids.span(),
        quote_asset_ids.span(),
        price_base_scales.span(),
        taker_fee_bps_values.span(),
    );
    assert_all_nonzero(batch_ids.span(), 'MPS_BATCH');
    assert_all_nonzero(pair_ids.span(), 'MPS_PAIR');
    assert_all_nonzero(order_commitment_roots.span(), 'MPS_ORDER_ROOT');
    assert_all_nonzero(encrypted_order_set_commitments.span(), 'MPS_ENC_ROOT');
    assert_all_nonzero(base_asset_ids.span(), 'MPS_BASE');
    assert_all_nonzero(quote_asset_ids.span(), 'MPS_QUOTE');
    assert_unique_nonzero(batch_ids.span(), 'MPS_BATCH_DUP');
    let mut binding_index = 0;
    while binding_index < batch_ids.len() {
        assert(*base_asset_ids.at(binding_index) != *quote_asset_ids.at(binding_index), 'MPS_PAIR');
        assert(felt_to_u128(*price_base_scales.at(binding_index)) != 0, 'MPS_PRICE_SCALE');
        assert(
            felt_to_u128(*taker_fee_bps_values.at(binding_index)) <= FEE_BPS_DENOMINATOR, 'MPS_FEE',
        );
        binding_index += 1;
    }
    assert(
        multi_pair_batch_binding_root(
            batch_ids.span(),
            pair_ids.span(),
            header.batch_epoch,
            order_commitment_roots.span(),
            encrypted_order_set_commitments.span(),
            base_asset_ids.span(),
            quote_asset_ids.span(),
            price_base_scales.span(),
            taker_fee_bps_values.span(),
        ) == header
            .batch_binding_root,
        'MPS_BINDING',
    );
    assert_multi_pair_settlement_public_commitment(header);
    header.transcript_commitment
}

pub fn verify_multi_pair_settlement_order_state_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;
    let header = read_multi_pair_settlement_header(data, ref index);
    skip_vectors(data, ref index, 8);
    let nested_multi_pair_serialized = read_vector(data, ref index);
    let nested_multi_pair = length_prefixed_payload(nested_multi_pair_serialized.span(), 'MPS_MP');
    assert(
        multi_pair_payload_group_id(nested_multi_pair.span()) == header.group_id, 'MPS_MP_GROUP',
    );
    let (
        nested_order_commitments,
        nested_pair_ids,
        nested_base_asset_ids,
        nested_quote_asset_ids,
        nested_sides,
        nested_submitted_base_amounts,
        nested_min_fill_base_amounts,
        nested_limit_prices,
        _nested_price_base_scales,
        nested_filled_base_amounts,
        nested_quote_amounts,
        nested_fee_amounts,
    ) =
        multi_pair_payload_chosen_fill_vectors(
        nested_multi_pair.span(),
    );

    let matched_order_batch_ids = read_vector(data, ref index);
    let matched_order_commitments = read_vector(data, ref index);
    let matched_fill_amounts = read_vector(data, ref index);
    let consumed_note_commitments = read_vector(data, ref index);
    let consumed_nullifiers = read_vector(data, ref index);
    let renewal_parent_order_commitments = read_vector(data, ref index);
    let renewal_child_nullifiers = read_vector(data, ref index);
    let output_note_commitments = read_vector(data, ref index);
    let output_note_asset_ids = read_vector(data, ref index);
    let output_note_amounts = read_vector(data, ref index);
    let output_note_withdraw_authorities = read_vector(data, ref index);
    skip_vectors(data, ref index, 3);
    let matched_sides = read_vector(data, ref index);
    let matched_order_types = read_vector(data, ref index);
    let matched_relay_modes = read_vector(data, ref index);
    let matched_limit_prices = read_vector(data, ref index);
    let matched_order_amounts = read_vector(data, ref index);
    let matched_min_fills = read_vector(data, ref index);
    let matched_time_in_force = read_vector(data, ref index);
    let matched_execution_preferences = read_vector(data, ref index);
    let matched_expiry_epochs = read_vector(data, ref index);
    let matched_order_nonces = read_vector(data, ref index);
    let matched_parent_order_commitments = read_vector(data, ref index);
    let matched_parent_child_indexes = read_vector(data, ref index);
    let matched_parent_secret_commitments = read_vector(data, ref index);
    let matched_parent_cancel_authorities = read_vector(data, ref index);
    let matched_parent_authorization_secrets = read_vector(data, ref index);
    let matched_auditor_flags = read_vector(data, ref index);
    let matched_funding_note_refs = read_vector(data, ref index);
    let matched_funding_input_counts = read_vector(data, ref index);
    let matched_funding_note_commitments = read_vector(data, ref index);
    let matched_funding_note_asset_ids = read_vector(data, ref index);
    let matched_funding_input_amounts = read_vector(data, ref index);
    let matched_funding_input_owner_keys = read_vector(data, ref index);
    let matched_funding_note_spend_authorities = read_vector(data, ref index);
    let matched_funding_note_withdraw_authorities = read_vector(data, ref index);
    let matched_funding_note_blindings = read_vector(data, ref index);
    let matched_funding_note_nonces = read_vector(data, ref index);
    let matched_funding_note_metadata_commitments = read_vector(data, ref index);
    let matched_funding_note_amounts = read_vector(data, ref index);
    let matched_funding_note_owner_keys = read_vector(data, ref index);
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
    skip_vectors(data, ref index, 5);
    skip_vectors(data, ref index, 4);
    assert(index == data.len(), 'MPS_ORDER_STATE_LEN');

    assert(header.matched_order_count == matched_order_commitments.len().into(), 'MPS_MATCHED');
    assert(header.matched_order_count == matched_order_batch_ids.len().into(), 'MPS_MATCHED');
    assert(header.matched_order_count == matched_fill_amounts.len().into(), 'MPS_MATCHED');
    assert(header.matched_order_count == nested_order_commitments.len().into(), 'MPS_MATCHED');
    assert_equal_vectors(
        matched_order_commitments.span(), nested_order_commitments.span(), 'MPS_MATCHED',
    );
    assert_equal_vectors(
        matched_fill_amounts.span(), nested_filled_base_amounts.span(), 'MPS_FILL',
    );
    assert_equal_vectors(matched_sides.span(), nested_sides.span(), 'MPS_SIDE');
    assert_equal_vectors(
        matched_order_amounts.span(), nested_submitted_base_amounts.span(), 'MPS_AMOUNT',
    );
    assert_equal_vectors(
        matched_min_fills.span(), nested_min_fill_base_amounts.span(), 'MPS_MIN_FILL',
    );
    assert_equal_vectors(matched_limit_prices.span(), nested_limit_prices.span(), 'MPS_LIMIT');

    let funding_input_count = sum_funding_input_counts(matched_funding_input_counts.span());
    assert_settlement_bounds(
        matched_order_commitments.len(), funding_input_count, output_note_commitments.len(),
    );
    assert_all_lengths_match(
        matched_order_commitments.len(),
        array![
            matched_sides.len().into(), matched_order_types.len().into(),
            matched_relay_modes.len().into(), matched_limit_prices.len().into(),
            matched_order_amounts.len().into(), matched_min_fills.len().into(),
            matched_time_in_force.len().into(), matched_execution_preferences.len().into(),
            matched_expiry_epochs.len().into(), matched_order_nonces.len().into(),
            matched_parent_order_commitments.len().into(),
            matched_parent_child_indexes.len().into(),
            matched_parent_secret_commitments.len().into(),
            matched_parent_cancel_authorities.len().into(),
            matched_parent_authorization_secrets.len().into(), matched_auditor_flags.len().into(),
            matched_funding_note_refs.len().into(), matched_funding_input_counts.len().into(),
            matched_funding_note_amounts.len().into(), matched_funding_note_owner_keys.len().into(),
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
        ]
            .span(),
        'MPS_ORDER_LEN',
    );
    assert_all_lengths_match(
        funding_input_count,
        array![
            matched_funding_note_commitments.len().into(),
            matched_funding_note_asset_ids.len().into(), matched_funding_input_amounts.len().into(),
            matched_funding_input_owner_keys.len().into(),
            matched_funding_note_spend_authorities.len().into(),
            matched_funding_note_withdraw_authorities.len().into(),
            matched_funding_note_blindings.len().into(), matched_funding_note_nonces.len().into(),
            matched_funding_note_metadata_commitments.len().into(),
            consumed_note_commitments.len().into(), consumed_nullifiers.len().into(),
            note_membership_kinds.len().into(), note_membership_prefix_roots.len().into(),
            note_membership_batch_roots.len().into(), note_membership_path_counts.len().into(),
            note_membership_suffix_counts.len().into(),
        ]
            .span(),
        'MPS_FUNDING_LEN',
    );
    assert(
        note_membership_path_values.len() == note_membership_path_directions.len(), 'MPS_NOTE_PATH',
    );
    assert(renewal_parent_order_commitments.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL');
    assert(renewal_child_sparse_key_lows.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL');
    assert(renewal_child_sparse_key_highs.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL');
    assert(renewal_child_sparse_path_counts.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL');
    assert(renewal_cancel_sparse_key_lows.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL');
    assert(renewal_cancel_sparse_key_highs.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL');
    assert(
        renewal_cancel_sparse_path_counts.len() == renewal_child_nullifiers.len(), 'MPS_RENEWAL',
    );
    assert(
        renewal_child_sparse_path_values.len() == renewal_child_sparse_path_directions.len(),
        'MPS_RENEWAL_PATH',
    );
    assert(
        renewal_cancel_sparse_path_values.len() == renewal_cancel_sparse_path_directions.len(),
        'MPS_RENEWAL_PATH',
    );
    assert_unique_nonzero(matched_order_commitments.span(), 'MPS_ORDER_DUP');
    assert_unique(consumed_note_commitments.span(), 'MPS_CONSUMED_DUP');
    assert_unique(consumed_nullifiers.span(), 'MPS_NULLIFIER_DUP');
    assert_unique(renewal_child_nullifiers.span(), 'MPS_RENEWAL_DUP');
    assert(nullifier_sparse_key_lows.len() == consumed_nullifiers.len(), 'MPS_NULLIFIER');
    assert(nullifier_sparse_key_highs.len() == consumed_nullifiers.len(), 'MPS_NULLIFIER');
    assert(nullifier_sparse_path_counts.len() == consumed_nullifiers.len(), 'MPS_NULLIFIER');
    assert(
        nullifier_sparse_path_values.len() == nullifier_sparse_path_directions.len(),
        'MPS_NULLIFIER',
    );

    let mut order_index = 0;
    let mut funding_input_cursor = 0;
    let mut renewal_cursor = 0;
    let mut renewal_child_path_cursor = 0;
    let mut renewal_cancel_path_cursor = 0;
    let mut running_renewal_root = header.prior_renewal_root;
    let mut public_output_cursor = 0;
    let mut note_membership_path_cursor = 0;
    let mut note_membership_suffix_cursor = 0;
    while order_index < matched_order_commitments.len() {
        let order_commitment = *matched_order_commitments.at(order_index);
        let batch_id_for_order = *matched_order_batch_ids.at(order_index);
        let pair_id_for_order = *nested_pair_ids.at(order_index);
        let base_asset_id_for_order = *nested_base_asset_ids.at(order_index);
        let quote_asset_id_for_order = *nested_quote_asset_ids.at(order_index);
        let side = *matched_sides.at(order_index);
        let order_type = *matched_order_types.at(order_index);
        let relay_mode = *matched_relay_modes.at(order_index);
        let limit_price_felt = *matched_limit_prices.at(order_index);
        let order_amount_felt = *matched_order_amounts.at(order_index);
        let min_fill_felt = *matched_min_fills.at(order_index);
        let time_in_force = *matched_time_in_force.at(order_index);
        let execution_preference = *matched_execution_preferences.at(order_index);
        let expiry_epoch_felt = *matched_expiry_epochs.at(order_index);
        let order_nonce_felt = *matched_order_nonces.at(order_index);
        let parent_order_commitment = *matched_parent_order_commitments.at(order_index);
        let parent_child_index = *matched_parent_child_indexes.at(order_index);
        let parent_secret_commitment = *matched_parent_secret_commitments.at(order_index);
        let parent_cancel_authority = *matched_parent_cancel_authorities.at(order_index);
        let parent_authorization_secret = *matched_parent_authorization_secrets.at(order_index);
        let auditor_view_allowed = *matched_auditor_flags.at(order_index);
        let funding_note_ref = *matched_funding_note_refs.at(order_index);
        let funding_input_count_felt = *matched_funding_input_counts.at(order_index);
        let funding_note_amount_felt = *matched_funding_note_amounts.at(order_index);
        let funding_note_owner_key = *matched_funding_note_owner_keys.at(order_index);
        let funding_authorization_r = *matched_funding_authorization_rs.at(order_index);
        let funding_authorization_s = *matched_funding_authorization_ss.at(order_index);
        let funding_nullifier = *matched_funding_nullifiers.at(order_index);
        let recipient_owner_key = *matched_recipient_owner_keys.at(order_index);
        let recipient_spend_authority = *matched_recipient_spend_authorities.at(order_index);
        let recipient_withdraw_authority = *matched_recipient_withdraw_authorities.at(order_index);
        let recipient_residual_withdraw_authority = *matched_res_withdraw_auths.at(order_index);
        let output_note_commitment = *matched_output_note_commitments.at(order_index);
        let output_note_asset_id = *matched_output_note_asset_ids.at(order_index);
        let output_note_amount_felt = *matched_output_note_amounts.at(order_index);
        let output_note_owner_key = *matched_output_note_owner_keys.at(order_index);
        let output_note_spend_authority = *matched_output_note_spend_authorities.at(order_index);
        let output_note_withdraw_authority = *matched_output_note_withdraw_authorities
            .at(order_index);
        let output_note_blinding = *matched_output_note_blindings.at(order_index);
        let output_note_nonce_felt = *matched_output_note_nonces.at(order_index);
        let output_note_metadata_commitment = *matched_output_note_metadata_commitments
            .at(order_index);
        let residual_note_flag = *matched_residual_note_flags.at(order_index);
        let residual_note_commitment = *matched_residual_note_commitments.at(order_index);
        let residual_note_asset_id = *matched_residual_note_asset_ids.at(order_index);
        let residual_note_amount_felt = *matched_residual_note_amounts.at(order_index);
        let residual_note_owner_key = *matched_residual_note_owner_keys.at(order_index);
        let residual_note_spend_authority = *matched_residual_note_spend_authorities
            .at(order_index);
        let residual_note_withdraw_authority = *matched_residual_note_withdraw_authorities
            .at(order_index);
        let residual_note_blinding = *matched_residual_note_blindings.at(order_index);
        let residual_note_nonce_felt = *matched_residual_note_nonces.at(order_index);
        let residual_note_metadata_commitment = *matched_residual_note_metadata_commitments
            .at(order_index);

        let filled_base_amount = felt_to_u128(*nested_filled_base_amounts.at(order_index));
        let quote_amount = felt_to_u128(*nested_quote_amounts.at(order_index));
        let fee_amount = felt_to_u128(*nested_fee_amounts.at(order_index));
        let order_amount = felt_to_u128(order_amount_felt);
        let min_fill = felt_to_u128(min_fill_felt);
        let funding_note_amount = felt_to_u128(funding_note_amount_felt);
        let output_note_amount = felt_to_u128(output_note_amount_felt);

        assert(order_type == ORDER_TYPE_LIMIT_BATCH, 'MPS_ORDER_TYPE');
        assert(order_commitment != 0, 'MPS_ORDER');
        assert(filled_base_amount != 0, 'MPS_FILL');
        assert(filled_base_amount <= order_amount, 'MPS_FILL');
        assert(filled_base_amount >= min_fill, 'MPS_FILL');
        assert(
            time_in_force == TIF_CURRENT_BATCH_ONLY || time_in_force == TIF_FILL_OR_KILL, 'MPS_TIF',
        );
        assert(
            execution_preference == EXECUTION_PRIVATE_ONLY
                || execution_preference == EXECUTION_PRIVATE_THEN_EXTERNAL,
            'MPS_EXEC',
        );
        if time_in_force == TIF_FILL_OR_KILL {
            assert(filled_base_amount == order_amount, 'MPS_FOK');
        }
        assert(expiry_epoch_felt == header.batch_epoch, 'MPS_EPOCH');
        assert(order_nonce_felt != 0, 'MPS_NONCE');
        assert_parent_link(
            parent_order_commitment,
            parent_child_index,
            parent_secret_commitment,
            parent_cancel_authority,
            parent_authorization_secret,
        );
        assert_relay_mode(relay_mode, order_type, parent_order_commitment);
        if parent_order_commitment != 0 {
            assert(renewal_cursor < renewal_child_nullifiers.len(), 'MPS_RENEWAL');
            assert(
                *renewal_parent_order_commitments.at(renewal_cursor) == parent_order_commitment,
                'MPS_RENEWAL',
            );
            assert(
                *renewal_child_nullifiers
                    .at(
                        renewal_cursor,
                    ) == renewal_child_nullifier(
                        parent_order_commitment, parent_child_index, parent_authorization_secret,
                    ),
                'MPS_RENEWAL',
            );
            let renewal_cancel_marker = renewal_parent_cancel_marker(
                parent_secret_commitment, parent_cancel_authority,
            );
            running_renewal_root =
                assert_renewal_entry_absent(
                    running_renewal_root,
                    renewal_cancel_marker,
                    *renewal_cancel_sparse_key_lows.at(renewal_cursor),
                    *renewal_cancel_sparse_key_highs.at(renewal_cursor),
                    *renewal_cancel_sparse_path_counts.at(renewal_cursor),
                    ref renewal_cancel_path_cursor,
                    renewal_cancel_sparse_path_values.span(),
                    renewal_cancel_sparse_path_directions.span(),
                    NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL,
                );
            running_renewal_root =
                assert_renewal_entry_insert(
                    running_renewal_root,
                    *renewal_child_nullifiers.at(renewal_cursor),
                    *renewal_child_sparse_key_lows.at(renewal_cursor),
                    *renewal_child_sparse_key_highs.at(renewal_cursor),
                    *renewal_child_sparse_path_counts.at(renewal_cursor),
                    ref renewal_child_path_cursor,
                    renewal_child_sparse_path_values.span(),
                    renewal_child_sparse_path_directions.span(),
                    NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL,
                    NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL,
                );
            renewal_cursor += 1;
        }
        assert(auditor_view_allowed == 0 || auditor_view_allowed == 1, 'MPS_AUDITOR');
        let recomputed_order_commitment = order_intent_commitment(
            header.order_commitment_domain,
            pair_id_for_order,
            batch_id_for_order,
            side,
            order_type,
            relay_mode,
            limit_price_felt,
            order_amount_felt,
            min_fill_felt,
            time_in_force,
            execution_preference,
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
        assert(order_commitment == recomputed_order_commitment, 'MPS_ORDER_COMMIT');

        let funding_input_count_for_order: usize = funding_input_count_felt
            .try_into()
            .expect('MPS_FUNDING');
        assert(funding_input_count_for_order != 0, 'MPS_FUNDING');
        assert(funding_input_count_for_order <= MAX_ORDER_FUNDING_INPUTS, 'MPS_FUNDING');
        assert(
            funding_input_cursor + funding_input_count_for_order <= consumed_note_commitments.len(),
            'MPS_FUNDING',
        );
        let first_input_commitment = *matched_funding_note_commitments.at(funding_input_cursor);
        let first_input_nullifier = note_nullifier(
            header.nullifier_domain,
            first_input_commitment,
            *matched_funding_note_blindings.at(funding_input_cursor),
        );
        let first_spend_authority = *matched_funding_note_spend_authorities
            .at(funding_input_cursor);
        assert_stwo_spend_authorization(
            order_commitment,
            first_spend_authority,
            funding_authorization_r,
            funding_authorization_s,
            'MPS_AUTH',
        );
        let mut input_set_state = FUNDING_INPUT_SET_DOMAIN;
        let mut nullifier_set_state = FUNDING_NULLIFIER_SET_DOMAIN;
        let mut recomputed_funding_amount: u128 = 0;
        let mut funding_index = 0;
        while funding_index < funding_input_count_for_order {
            let flat_index = funding_input_cursor + funding_index;
            let funding_note_commitment = *matched_funding_note_commitments.at(flat_index);
            let funding_note_asset_id = *matched_funding_note_asset_ids.at(flat_index);
            let funding_input_amount_felt = *matched_funding_input_amounts.at(flat_index);
            let funding_input_owner_key = *matched_funding_input_owner_keys.at(flat_index);
            let funding_note_spend_authority = *matched_funding_note_spend_authorities
                .at(flat_index);
            let funding_note_withdraw_authority = *matched_funding_note_withdraw_authorities
                .at(flat_index);
            let funding_note_blinding = *matched_funding_note_blindings.at(flat_index);
            let funding_note_nonce_felt = *matched_funding_note_nonces.at(flat_index);
            let funding_note_metadata_commitment = *matched_funding_note_metadata_commitments
                .at(flat_index);
            assert(funding_note_commitment != 0, 'MPS_FUNDING');
            assert(funding_input_owner_key == funding_note_owner_key, 'MPS_FUNDING_OWNER');
            assert(funding_note_spend_authority == first_spend_authority, 'MPS_FUNDING_AUTH');
            if side == ORDER_SIDE_BUY {
                assert(funding_note_asset_id == quote_asset_id_for_order, 'MPS_FUNDING_ASSET');
            } else {
                assert(side == ORDER_SIDE_SELL, 'MPS_SIDE');
                assert(funding_note_asset_id == base_asset_id_for_order, 'MPS_FUNDING_ASSET');
            }
            assert(
                note_commitment(
                    header.note_commitment_domain,
                    funding_note_asset_id,
                    funding_input_amount_felt,
                    funding_input_owner_key,
                    funding_note_spend_authority,
                    funding_note_withdraw_authority,
                    funding_note_blinding,
                    funding_note_nonce_felt,
                    funding_note_metadata_commitment,
                ) == funding_note_commitment,
                'MPS_FUNDING_COMMIT',
            );
            let input_nullifier = note_nullifier(
                header.nullifier_domain, funding_note_commitment, funding_note_blinding,
            );
            assert(funding_note_commitment == *consumed_note_commitments.at(flat_index), 'MPS_IN');
            assert(input_nullifier == *consumed_nullifiers.at(flat_index), 'MPS_NULLIFIER');
            assert_note_membership(
                funding_note_commitment,
                funding_note_asset_id,
                funding_input_amount_felt,
                funding_note_withdraw_authority,
                header.prior_note_root,
                *note_membership_kinds.at(flat_index),
                *note_membership_prefix_roots.at(flat_index),
                *note_membership_batch_roots.at(flat_index),
                *note_membership_path_counts.at(flat_index),
                ref note_membership_path_cursor,
                note_membership_path_values.span(),
                note_membership_path_directions.span(),
                *note_membership_suffix_counts.at(flat_index),
                ref note_membership_suffix_cursor,
                note_membership_suffix_roots.span(),
                STATE_TRANSITION_ROOT_DOMAIN,
            );
            input_set_state = poseidon_hash2(input_set_state, funding_note_commitment);
            nullifier_set_state = poseidon_hash2(nullifier_set_state, input_nullifier);
            recomputed_funding_amount += felt_to_u128(funding_input_amount_felt);
            funding_index += 1;
        }
        let recomputed_funding_note_ref = if funding_input_count_for_order == 1 {
            first_input_commitment
        } else {
            poseidon_hash2(input_set_state, funding_input_count_for_order.into())
        };
        let recomputed_funding_nullifier = if funding_input_count_for_order == 1 {
            first_input_nullifier
        } else {
            poseidon_hash2(nullifier_set_state, funding_input_count_for_order.into())
        };
        assert(funding_note_ref == recomputed_funding_note_ref, 'MPS_FUNDING_REF');
        assert(funding_nullifier == recomputed_funding_nullifier, 'MPS_FUNDING_NULL');
        assert(recomputed_funding_amount == funding_note_amount, 'MPS_FUNDING_AMOUNT');
        funding_input_cursor += funding_input_count_for_order;

        let recomputed_output_note_commitment = note_commitment(
            header.note_commitment_domain,
            output_note_asset_id,
            output_note_amount_felt,
            output_note_owner_key,
            output_note_spend_authority,
            output_note_withdraw_authority,
            output_note_blinding,
            output_note_nonce_felt,
            output_note_metadata_commitment,
        );
        assert(output_note_commitment == recomputed_output_note_commitment, 'MPS_OUT_COMMIT');
        assert(output_note_owner_key == recipient_owner_key, 'MPS_OUT_OWNER');
        assert(output_note_spend_authority == recipient_spend_authority, 'MPS_OUT_AUTH');
        assert(output_note_withdraw_authority == recipient_withdraw_authority, 'MPS_OUT_WITHDRAW');
        let input_amount = if side == ORDER_SIDE_BUY {
            quote_amount
        } else {
            filled_base_amount
        };
        let gross_output = if side == ORDER_SIDE_BUY {
            filled_base_amount
        } else {
            quote_amount
        };
        let expected_output_asset = if side == ORDER_SIDE_BUY {
            base_asset_id_for_order
        } else {
            quote_asset_id_for_order
        };
        assert(funding_note_amount >= input_amount, 'MPS_FUNDING_AMOUNT');
        assert(fee_amount < gross_output, 'MPS_FEE_AMOUNT');
        assert(output_note_asset_id == expected_output_asset, 'MPS_OUT_ASSET');
        assert(output_note_amount == gross_output - fee_amount, 'MPS_OUT_AMOUNT');
        assert_canonical_public_output(
            ref public_output_cursor,
            output_note_commitment,
            output_note_asset_id,
            output_note_amount,
            output_note_withdraw_authority,
            output_note_commitments.span(),
            output_note_asset_ids.span(),
            output_note_amounts.span(),
            output_note_withdraw_authorities.span(),
        );
        let expected_residual_amount = funding_note_amount - input_amount;
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
            assert(residual_note_flag == 1, 'MPS_RESIDUAL');
            let expected_residual_asset = if side == ORDER_SIDE_BUY {
                quote_asset_id_for_order
            } else {
                base_asset_id_for_order
            };
            assert(residual_note_asset_id == expected_residual_asset, 'MPS_RES_ASSET');
            assert(residual_note_owner_key == recipient_owner_key, 'MPS_RES_OWNER');
            assert(residual_note_spend_authority == recipient_spend_authority, 'MPS_RES_AUTH');
            assert(
                residual_note_withdraw_authority == recipient_residual_withdraw_authority,
                'MPS_RES_WITHDRAW',
            );
            assert(residual_note_blinding != 0, 'MPS_RES_BLINDING');
            assert(residual_note_nonce_felt != 0, 'MPS_RES_NONCE');
            assert(residual_note_metadata_commitment != 0, 'MPS_RES_META');
            let recomputed_residual_note_commitment = note_commitment(
                header.note_commitment_domain,
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
                residual_note_commitment == recomputed_residual_note_commitment, 'MPS_RES_COMMIT',
            );
            assert(
                felt_to_u128(residual_note_amount_felt) == expected_residual_amount,
                'MPS_RES_AMOUNT',
            );
            assert_canonical_public_output(
                ref public_output_cursor,
                residual_note_commitment,
                residual_note_asset_id,
                expected_residual_amount,
                residual_note_withdraw_authority,
                output_note_commitments.span(),
                output_note_asset_ids.span(),
                output_note_amounts.span(),
                output_note_withdraw_authorities.span(),
            );
        }
        order_index += 1;
    }
    assert(funding_input_cursor == consumed_note_commitments.len(), 'MPS_FUNDING_TRAIL');
    assert(renewal_cursor == renewal_child_nullifiers.len(), 'MPS_RENEWAL_TRAIL');
    assert(renewal_child_path_cursor == renewal_child_sparse_path_values.len(), 'MPS_RENEWAL_PATH');
    assert(
        renewal_child_path_cursor == renewal_child_sparse_path_directions.len(), 'MPS_RENEWAL_PATH',
    );
    assert(
        renewal_cancel_path_cursor == renewal_cancel_sparse_path_values.len(), 'MPS_RENEWAL_PATH',
    );
    assert(
        renewal_cancel_path_cursor == renewal_cancel_sparse_path_directions.len(),
        'MPS_RENEWAL_PATH',
    );
    assert(note_membership_path_cursor == note_membership_path_values.len(), 'MPS_NOTE_PATH');
    assert(note_membership_path_cursor == note_membership_path_directions.len(), 'MPS_NOTE_PATH');
    assert(note_membership_suffix_cursor == note_membership_suffix_roots.len(), 'MPS_NOTE_SUFFIX');

    assert(
        single_field_root(CONSUMED_NOTE_ROOT_DOMAIN, consumed_note_commitments.span()) == header
            .consumed_note_root,
        'MPS_CONSUMED_NOTES',
    );
    assert(
        single_field_root(CONSUMED_NULLIFIER_ROOT_DOMAIN, consumed_nullifiers.span()) == header
            .consumed_nullifier_root,
        'MPS_CONSUMED_NULLS',
    );
    assert(
        single_field_root(RENEWAL_CHILD_ROOT_DOMAIN, renewal_child_nullifiers.span()) == header
            .renewal_child_root,
        'MPS_RENEWAL_ROOT',
    );
    assert(
        output_note_merkle_root(
            header.output_bundle_ref,
            output_note_commitments.span(),
            output_note_asset_ids.span(),
            output_note_amounts.span(),
            output_note_withdraw_authorities.span(),
        ) == header
            .output_note_root,
        'MPS_OUTPUT_ROOT',
    );
    assert(
        header
            .new_note_root == state_transition_root(
                STATE_TRANSITION_ROOT_DOMAIN, header.prior_note_root, header.output_note_root,
            ),
        'MPS_NOTE_ROOT',
    );
    let running_nullifier_root = assert_sparse_nullifier_updates(
        header.prior_nullifier_root,
        consumed_nullifiers.span(),
        nullifier_sparse_key_lows.span(),
        nullifier_sparse_key_highs.span(),
        nullifier_sparse_path_counts.span(),
        nullifier_sparse_path_values.span(),
        nullifier_sparse_path_directions.span(),
        NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL,
        NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL,
    );
    if consumed_nullifiers.len() == 0 {
        assert(header.new_nullifier_root == header.prior_nullifier_root, 'MPS_NULL_ROOT');
    } else {
        assert(header.new_nullifier_root == running_nullifier_root, 'MPS_NULL_ROOT');
    }
    if renewal_child_nullifiers.len() == 0 {
        assert(header.new_renewal_root == header.prior_renewal_root, 'MPS_RENEWAL_STATE');
    } else {
        assert(header.new_renewal_root == running_renewal_root, 'MPS_RENEWAL_STATE');
    }
    assert(public_output_cursor <= output_note_commitments.len(), 'MPS_OUTPUT_TRAIL');
    header.transcript_commitment
}

pub fn verify_multi_pair_settlement_completion_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;
    let header = read_multi_pair_settlement_header(data, ref index);

    let batch_ids = read_vector(data, ref index);
    let pair_ids = read_vector(data, ref index);
    let _order_commitment_roots = read_vector(data, ref index);
    let _encrypted_order_set_commitments = read_vector(data, ref index);
    let base_asset_ids = read_vector(data, ref index);
    let quote_asset_ids = read_vector(data, ref index);
    let price_base_scales = read_vector(data, ref index);
    let _taker_fee_bps_values = read_vector(data, ref index);
    let nested_multi_pair_serialized = read_vector(data, ref index);
    let nested_multi_pair = length_prefixed_payload(nested_multi_pair_serialized.span(), 'MPS_MP');

    let matched_order_batch_ids = read_vector(data, ref index);
    let matched_order_commitments = read_vector(data, ref index);
    let matched_fill_amounts = read_vector(data, ref index);
    skip_vectors(data, ref index, 11);
    let matched_sides = read_vector(data, ref index);
    skip_vectors(data, ref index, 2);
    let matched_limit_prices = read_vector(data, ref index);
    let matched_order_amounts = read_vector(data, ref index);
    let matched_min_fills = read_vector(data, ref index);
    skip_vectors(data, ref index, 80);
    assert(index == data.len(), 'MPS_COMPLETE_LEN');

    let nested_commitment = verify_multi_pair_statement(nested_multi_pair.span());
    assert(nested_commitment == header.multi_pair_commitment, 'MPS_MP_BIND');
    assert(
        multi_pair_payload_group_id(nested_multi_pair.span()) == header.group_id, 'MPS_MP_GROUP',
    );
    let (
        nested_order_commitments,
        nested_pair_ids,
        nested_base_asset_ids,
        nested_quote_asset_ids,
        nested_sides,
        nested_submitted_base_amounts,
        nested_min_fill_base_amounts,
        nested_limit_prices,
        nested_price_base_scales,
        nested_filled_base_amounts,
        _nested_quote_amounts,
        _nested_fee_amounts,
    ) =
        multi_pair_payload_chosen_fill_vectors(
        nested_multi_pair.span(),
    );

    assert(header.matched_order_count == matched_order_commitments.len().into(), 'MPS_MATCHED');
    assert(header.matched_order_count == matched_order_batch_ids.len().into(), 'MPS_MATCHED');
    assert(header.matched_order_count == matched_fill_amounts.len().into(), 'MPS_MATCHED');
    assert(header.matched_order_count == nested_order_commitments.len().into(), 'MPS_MATCHED');
    assert_equal_vectors(
        matched_order_commitments.span(), nested_order_commitments.span(), 'MPS_MATCHED',
    );
    assert_equal_vectors(
        matched_fill_amounts.span(), nested_filled_base_amounts.span(), 'MPS_FILL',
    );
    assert_equal_vectors(matched_sides.span(), nested_sides.span(), 'MPS_SIDE');
    assert_equal_vectors(
        matched_order_amounts.span(), nested_submitted_base_amounts.span(), 'MPS_AMOUNT',
    );
    assert_equal_vectors(
        matched_min_fills.span(), nested_min_fill_base_amounts.span(), 'MPS_MIN_FILL',
    );
    assert_equal_vectors(matched_limit_prices.span(), nested_limit_prices.span(), 'MPS_LIMIT');
    assert_matched_fill_batch_bindings(
        matched_order_batch_ids.span(),
        nested_pair_ids.span(),
        nested_base_asset_ids.span(),
        nested_quote_asset_ids.span(),
        nested_price_base_scales.span(),
        batch_ids.span(),
        pair_ids.span(),
        base_asset_ids.span(),
        quote_asset_ids.span(),
        price_base_scales.span(),
    );
    header.transcript_commitment
}

pub fn verify_multi_pair_settlement_fee_recovery_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;
    let header = read_multi_pair_settlement_header(data, ref index);
    skip_vectors(data, ref index, 8);
    let nested_multi_pair_serialized = read_vector(data, ref index);
    let nested_multi_pair = length_prefixed_payload(nested_multi_pair_serialized.span(), 'MPS_MP');
    assert(
        multi_pair_payload_group_id(nested_multi_pair.span()) == header.group_id, 'MPS_MP_GROUP',
    );
    skip_vectors(data, ref index, 1);
    let matched_order_commitments = read_vector(data, ref index);
    skip_vectors(data, ref index, 5);
    let output_note_commitments = read_vector(data, ref index);
    let output_note_asset_ids = read_vector(data, ref index);
    let output_note_amounts = read_vector(data, ref index);
    let output_note_withdraw_authorities = read_vector(data, ref index);
    let fee_asset_ids = read_vector(data, ref index);
    let fee_amounts = read_vector(data, ref index);
    let fee_recipients = read_vector(data, ref index);
    let (
        _nested_order_commitments,
        _nested_pair_ids,
        nested_base_asset_ids,
        nested_quote_asset_ids,
        nested_sides,
        _nested_submitted_base_amounts,
        _nested_min_fill_base_amounts,
        _nested_limit_prices,
        _nested_price_base_scales,
        _nested_filled_base_amounts,
        _nested_quote_amounts,
        nested_fee_amounts,
    ) =
        multi_pair_payload_chosen_fill_vectors(
        nested_multi_pair.span(),
    );
    skip_vectors(data, ref index, 44);
    let matched_residual_note_flags = read_vector(data, ref index);
    skip_vectors(data, ref index, 32);
    let output_note_owner_keys = read_vector(data, ref index);
    let output_note_spend_authorities = read_vector(data, ref index);
    let output_note_blindings = read_vector(data, ref index);
    let output_note_nonces = read_vector(data, ref index);
    let output_note_metadata_commitments = read_vector(data, ref index);
    let output_recovery_key_tags = read_vector(data, ref index);
    let output_recovery_auth_tags = read_vector(data, ref index);
    let output_recovery_ciphertext_fields = read_vector(data, ref index);
    let output_recovery_dummy_commitments = read_vector(data, ref index);
    assert(index == data.len(), 'MPS_FEE_LEN');

    assert(output_note_commitments.len() == output_note_asset_ids.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_amounts.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_withdraw_authorities.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_owner_keys.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_spend_authorities.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_blindings.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_nonces.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_note_metadata_commitments.len(), 'MPS_OUTPUT');
    assert(output_note_commitments.len() == output_recovery_key_tags.len(), 'MPS_RECOVERY');
    assert(output_note_commitments.len() == output_recovery_auth_tags.len(), 'MPS_RECOVERY');
    assert(
        output_recovery_ciphertext_fields.len() == output_note_commitments.len()
            * OUTPUT_RECOVERY_FIELD_COUNT,
        'MPS_RECOVERY',
    );
    assert(fee_asset_ids.len() == fee_amounts.len(), 'MPS_FEE');
    assert(fee_asset_ids.len() == fee_recipients.len(), 'MPS_FEE');
    assert_unique_nonzero(fee_asset_ids.span(), 'MPS_FEE_DUP');
    assert(
        output_note_merkle_root(
            header.output_bundle_ref,
            output_note_commitments.span(),
            output_note_asset_ids.span(),
            output_note_amounts.span(),
            output_note_withdraw_authorities.span(),
        ) == header
            .output_note_root,
        'MPS_OUTPUT_ROOT',
    );
    assert(
        multi_pair_fee_root(
            FEE_ROOT_DOMAIN, fee_asset_ids.span(), fee_amounts.span(), fee_recipients.span(),
        ) == header
            .fee_root,
        'MPS_FEE_ROOT',
    );
    assert_multi_pair_all_positive_fees_have_entries(
        fee_asset_ids.span(),
        fee_amounts.span(),
        nested_base_asset_ids.span(),
        nested_quote_asset_ids.span(),
        nested_sides.span(),
        nested_fee_amounts.span(),
    );
    assert_multi_pair_fee_entries_are_exact(
        fee_asset_ids.span(),
        fee_amounts.span(),
        nested_base_asset_ids.span(),
        nested_quote_asset_ids.span(),
        nested_sides.span(),
        nested_fee_amounts.span(),
    );
    let mut fee_index = 0;
    let mut public_output_cursor = matched_public_output_count(
        matched_order_commitments.span(), matched_residual_note_flags.span(),
    );
    while fee_index < fee_asset_ids.len() {
        assert(*fee_recipients.at(fee_index) == header.protocol_fee_recipient, 'MPS_FEE_RECIPIENT');
        assert_fee_output(
            ref public_output_cursor,
            header.note_commitment_domain,
            *fee_asset_ids.at(fee_index),
            felt_to_u128(*fee_amounts.at(fee_index)),
            header.protocol_fee_recipient,
            output_note_commitments.span(),
            output_note_asset_ids.span(),
            output_note_amounts.span(),
            output_note_withdraw_authorities.span(),
            output_note_owner_keys.span(),
            output_note_spend_authorities.span(),
            output_note_blindings.span(),
            output_note_nonces.span(),
            output_note_metadata_commitments.span(),
        );
        fee_index += 1;
    }
    assert_output_recovery_bundle(
        header.note_commitment_domain,
        header.output_bundle_ref,
        header.group_id,
        header.output_note_root,
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
    assert(
        header
            .new_fee_root == state_transition_root(
                STATE_TRANSITION_ROOT_DOMAIN, header.prior_fee_root, header.fee_root,
            ),
        'MPS_FEE_STATE',
    );
    header.transcript_commitment
}

pub fn verify_note_consolidation_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_NOTE_CONSOLIDATION, 'E');
    let note_commitment_domain = read_next(data, ref index);
    let nullifier_domain = read_next(data, ref index);
    let public_consolidation_domain = read_next(data, ref index);
    let consolidation_id = read_next(data, ref index);
    let consolidation_commitment = read_next(data, ref index);
    let output_bundle_ref = read_next(data, ref index);
    let prior_note_root = read_next(data, ref index);
    let prior_nullifier_root = read_next(data, ref index);
    let consumed_note_root_domain = read_next(data, ref index);
    let consumed_nullifier_root_domain = read_next(data, ref index);
    let output_note_root_domain = read_next(data, ref index);
    let state_transition_root_domain = read_next(data, ref index);
    let nullifier_sparse_leaf_domain = read_next(data, ref index);
    let nullifier_sparse_node_domain = read_next(data, ref index);
    assert(note_commitment_domain == NOTE_COMMITMENT_DOMAIN, 'E');
    assert(nullifier_domain == NULLIFIER_DOMAIN, 'E');
    assert(public_consolidation_domain == PUBLIC_NOTE_CONSOLIDATION_DOMAIN, 'E');
    assert(consolidation_id != 0, 'E');
    assert(consolidation_commitment != 0, 'E');
    assert(output_bundle_ref != 0, 'E');
    assert(consumed_note_root_domain == CONSUMED_NOTE_ROOT_DOMAIN, 'E');
    assert(consumed_nullifier_root_domain == CONSUMED_NULLIFIER_ROOT_DOMAIN, 'E');
    assert(output_note_root_domain == OUTPUT_NOTE_ROOT_DOMAIN, 'E');
    assert(state_transition_root_domain == STATE_TRANSITION_ROOT_DOMAIN, 'E');
    assert(nullifier_sparse_leaf_domain == NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL, 'E');
    assert(nullifier_sparse_node_domain == NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL, 'E');

    let input_note_commitments = read_vector(data, ref index);
    let input_asset_ids = read_vector(data, ref index);
    let input_amounts = read_vector(data, ref index);
    let input_owner_keys = read_vector(data, ref index);
    let input_spend_authorities = read_vector(data, ref index);
    let input_withdraw_authorities = read_vector(data, ref index);
    let input_blindings = read_vector(data, ref index);
    let input_nonces = read_vector(data, ref index);
    let input_metadata_commitments = read_vector(data, ref index);
    let input_nullifiers = read_vector(data, ref index);
    let spend_authorization_r = read_next(data, ref index);
    let spend_authorization_s = read_next(data, ref index);

    let note_membership_kinds = read_vector(data, ref index);
    let note_membership_prefix_roots = read_vector(data, ref index);
    let note_membership_batch_roots = read_vector(data, ref index);
    let note_membership_path_counts = read_vector(data, ref index);
    let note_membership_path_values = read_vector(data, ref index);
    let note_membership_path_directions = read_vector(data, ref index);
    let note_membership_suffix_counts = read_vector(data, ref index);
    let note_membership_suffix_roots = read_vector(data, ref index);

    let nullifier_sparse_key_lows = read_vector(data, ref index);
    let nullifier_sparse_key_highs = read_vector(data, ref index);
    let nullifier_sparse_path_counts = read_vector(data, ref index);
    let nullifier_sparse_path_values = read_vector(data, ref index);
    let nullifier_sparse_path_directions = read_vector(data, ref index);

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
    let claimed_new_nullifier_root = read_next(data, ref index);
    assert(index == data.len(), 'E');

    assert(input_note_commitments.len() != 0, 'E');
    assert(output_note_commitments.len() != 0, 'E');
    assert(input_note_commitments.len() <= MAX_NOTE_CONSOLIDATION_NOTES, 'E');
    assert(output_note_commitments.len() <= MAX_NOTE_CONSOLIDATION_NOTES, 'E');
    assert_all_lengths_match(
        input_note_commitments.len(),
        array![
            input_asset_ids.len().into(), input_amounts.len().into(), input_owner_keys.len().into(),
            input_spend_authorities.len().into(), input_withdraw_authorities.len().into(),
            input_blindings.len().into(), input_nonces.len().into(),
            input_metadata_commitments.len().into(), input_nullifiers.len().into(),
            note_membership_kinds.len().into(), note_membership_prefix_roots.len().into(),
            note_membership_batch_roots.len().into(), note_membership_path_counts.len().into(),
            note_membership_suffix_counts.len().into(), nullifier_sparse_key_lows.len().into(),
            nullifier_sparse_key_highs.len().into(), nullifier_sparse_path_counts.len().into(),
        ]
            .span(),
        'E',
    );
    assert(output_note_commitments.len() == output_note_asset_ids.len(), 'E');
    assert(output_note_commitments.len() == output_note_amounts.len(), 'E');
    assert(output_note_commitments.len() == output_note_withdraw_authorities.len(), 'E');
    assert(output_note_commitments.len() == output_note_owner_keys.len(), 'E');
    assert(output_note_commitments.len() == output_note_spend_authorities.len(), 'E');
    assert(output_note_commitments.len() == output_note_blindings.len(), 'E');
    assert(output_note_commitments.len() == output_note_nonces.len(), 'E');
    assert(output_note_commitments.len() == output_note_metadata_commitments.len(), 'E');
    assert(output_note_commitments.len() == output_recovery_key_tags.len(), 'E');
    assert(output_note_commitments.len() == output_recovery_auth_tags.len(), 'E');
    assert(
        output_recovery_ciphertext_fields.len() == output_note_commitments.len()
            * OUTPUT_RECOVERY_FIELD_COUNT,
        'E',
    );
    assert(note_membership_path_values.len() == note_membership_path_directions.len(), 'E');
    assert(nullifier_sparse_path_values.len() == nullifier_sparse_path_directions.len(), 'E');
    assert(spend_authorization_r != 0, 'E');
    assert(spend_authorization_s != 0, 'E');
    assert_unique(input_note_commitments.span(), 'E');
    assert_unique(input_nullifiers.span(), 'E');
    assert_unique(output_note_commitments.span(), 'E');

    let asset_id = *input_asset_ids.at(0);
    let spend_authority = *input_spend_authorities.at(0);
    assert(asset_id != 0, 'E');
    assert(spend_authority != 0, 'E');
    assert_stwo_spend_authorization(
        consolidation_commitment,
        spend_authority,
        spend_authorization_r,
        spend_authorization_s,
        'E',
    );

    let mut input_total: u128 = 0;
    let mut membership_path_cursor = 0;
    let mut membership_suffix_cursor = 0;
    let mut input_index = 0;
    while input_index < input_note_commitments.len() {
        let input_commitment = *input_note_commitments.at(input_index);
        let input_asset = *input_asset_ids.at(input_index);
        let input_amount = *input_amounts.at(input_index);
        let input_owner = *input_owner_keys.at(input_index);
        let input_spend = *input_spend_authorities.at(input_index);
        let input_withdraw = *input_withdraw_authorities.at(input_index);
        let input_blinding = *input_blindings.at(input_index);
        let input_nonce = *input_nonces.at(input_index);
        let input_metadata = *input_metadata_commitments.at(input_index);
        assert(input_asset == asset_id, 'E');
        assert(input_spend == spend_authority, 'E');
        assert(input_amount != 0, 'E');
        assert(
            note_commitment(
                note_commitment_domain,
                input_asset,
                input_amount,
                input_owner,
                input_spend,
                input_withdraw,
                input_blinding,
                input_nonce,
                input_metadata,
            ) == input_commitment,
            'E',
        );
        assert(
            note_nullifier(nullifier_domain, input_commitment, input_blinding) == *input_nullifiers
                .at(input_index),
            'E',
        );
        assert_note_membership(
            input_commitment,
            input_asset,
            input_amount,
            input_withdraw,
            prior_note_root,
            *note_membership_kinds.at(input_index),
            *note_membership_prefix_roots.at(input_index),
            *note_membership_batch_roots.at(input_index),
            *note_membership_path_counts.at(input_index),
            ref membership_path_cursor,
            note_membership_path_values.span(),
            note_membership_path_directions.span(),
            *note_membership_suffix_counts.at(input_index),
            ref membership_suffix_cursor,
            note_membership_suffix_roots.span(),
            state_transition_root_domain,
        );
        input_total += input_amount.try_into().expect('E');
        input_index += 1;
    }
    assert(membership_path_cursor == note_membership_path_values.len(), 'E');
    assert(membership_path_cursor == note_membership_path_directions.len(), 'E');
    assert(membership_suffix_cursor == note_membership_suffix_roots.len(), 'E');

    let mut output_total: u128 = 0;
    let mut output_index = 0;
    while output_index < output_note_commitments.len() {
        let output_asset = *output_note_asset_ids.at(output_index);
        let output_amount = *output_note_amounts.at(output_index);
        let output_withdraw = *output_note_withdraw_authorities.at(output_index);
        let output_nonce = *output_note_nonces.at(output_index);
        assert(output_asset == asset_id, 'E');
        assert(output_amount != 0, 'E');
        assert(output_nonce != 0, 'E');
        assert(
            note_commitment(
                note_commitment_domain,
                output_asset,
                output_amount,
                *output_note_owner_keys.at(output_index),
                *output_note_spend_authorities.at(output_index),
                output_withdraw,
                *output_note_blindings.at(output_index),
                output_nonce,
                *output_note_metadata_commitments.at(output_index),
            ) == *output_note_commitments
                .at(output_index),
            'E',
        );
        output_total += output_amount.try_into().expect('E');
        output_index += 1;
    }
    assert(input_total == output_total, 'E');

    let consumed_note_root = single_field_root(
        consumed_note_root_domain, input_note_commitments.span(),
    );
    let consumed_nullifier_root = single_field_root(
        consumed_nullifier_root_domain, input_nullifiers.span(),
    );
    let running_nullifier_root = assert_sparse_nullifier_updates(
        prior_nullifier_root,
        input_nullifiers.span(),
        nullifier_sparse_key_lows.span(),
        nullifier_sparse_key_highs.span(),
        nullifier_sparse_path_counts.span(),
        nullifier_sparse_path_values.span(),
        nullifier_sparse_path_directions.span(),
        nullifier_sparse_leaf_domain,
        nullifier_sparse_node_domain,
    );
    assert(running_nullifier_root == claimed_new_nullifier_root, 'E');
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
        consolidation_id,
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
    let new_note_root = state_transition_root(
        state_transition_root_domain, prior_note_root, output_note_root,
    );
    let recomputed_commitment = public_note_consolidation_commitment(
        public_consolidation_domain,
        consolidation_id,
        output_bundle_ref,
        prior_note_root,
        prior_nullifier_root,
        consumed_note_root,
        consumed_nullifier_root,
        output_note_root,
        new_note_root,
        claimed_new_nullifier_root,
    );
    assert(recomputed_commitment == consolidation_commitment, 'E');
    consolidation_commitment
}

pub fn verify_withdrawal_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_WITHDRAWAL, 'E');
    let note_commitment_domain = read_next(data, ref index);
    let nullifier_domain = read_next(data, ref index);
    let public_withdrawal_domain = read_next(data, ref index);
    let batch_id = read_next(data, ref index);
    let withdrawal_commitment = read_next(data, ref index);
    let note_commitment_claim = read_next(data, ref index);
    let asset_id = read_next(data, ref index);
    let amount = read_next(data, ref index);
    let withdraw_authority = read_next(data, ref index);
    let prior_nullifier_root = read_next(data, ref index);
    let consumed_nullifier_root_domain = read_next(data, ref index);
    let nullifier_sparse_leaf_domain = read_next(data, ref index);
    let nullifier_sparse_node_domain = read_next(data, ref index);
    assert(note_commitment_domain == NOTE_COMMITMENT_DOMAIN, 'E');
    assert(nullifier_domain == NULLIFIER_DOMAIN, 'E');
    assert(public_withdrawal_domain == PUBLIC_NOTE_WITHDRAWAL_DOMAIN, 'E');
    assert(batch_id != 0, 'E');
    assert(withdrawal_commitment != 0, 'E');
    assert(note_commitment_claim != 0, 'E');
    assert(asset_id != 0, 'E');
    assert(amount != 0, 'E');
    assert(withdraw_authority != 0, 'E');
    assert(consumed_nullifier_root_domain == CONSUMED_NULLIFIER_ROOT_DOMAIN, 'E');
    assert(nullifier_sparse_leaf_domain == NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL, 'E');
    assert(nullifier_sparse_node_domain == NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL, 'E');

    let owner_public_key = read_next(data, ref index);
    let spend_authority = read_next(data, ref index);
    let blinding = read_next(data, ref index);
    let nonce = read_next(data, ref index);
    let metadata_commitment = read_next(data, ref index);
    let nullifier = read_next(data, ref index);
    let nullifier_sparse_key_low = read_next(data, ref index);
    let nullifier_sparse_key_high = read_next(data, ref index);
    let nullifier_sparse_path_count = read_next(data, ref index);
    let nullifier_sparse_path_values = read_vector(data, ref index);
    let nullifier_sparse_path_directions = read_vector(data, ref index);
    let claimed_new_nullifier_root = read_next(data, ref index);
    assert(index == data.len(), 'E');

    assert(owner_public_key != 0, 'E');
    assert(spend_authority != 0, 'E');
    assert(blinding != 0, 'E');
    assert(nonce != 0, 'E');
    assert(metadata_commitment != 0, 'E');
    assert(nullifier != 0, 'E');
    assert(claimed_new_nullifier_root != 0, 'E');
    assert(nullifier_sparse_path_values.len() == nullifier_sparse_path_directions.len(), 'E');

    let recomputed_note_commitment = note_commitment(
        note_commitment_domain,
        asset_id,
        amount,
        owner_public_key,
        spend_authority,
        withdraw_authority,
        blinding,
        nonce,
        metadata_commitment,
    );
    assert(recomputed_note_commitment == note_commitment_claim, 'E');
    assert(note_nullifier(nullifier_domain, note_commitment_claim, blinding) == nullifier, 'E');

    let nullifiers = array![nullifier];
    let sparse_key_lows = array![nullifier_sparse_key_low];
    let sparse_key_highs = array![nullifier_sparse_key_high];
    let sparse_path_counts = array![nullifier_sparse_path_count];
    let consumed_nullifier_root = single_field_root(
        consumed_nullifier_root_domain, nullifiers.span(),
    );
    let running_nullifier_root = assert_sparse_nullifier_updates(
        prior_nullifier_root,
        nullifiers.span(),
        sparse_key_lows.span(),
        sparse_key_highs.span(),
        sparse_path_counts.span(),
        nullifier_sparse_path_values.span(),
        nullifier_sparse_path_directions.span(),
        nullifier_sparse_leaf_domain,
        nullifier_sparse_node_domain,
    );
    assert(running_nullifier_root == claimed_new_nullifier_root, 'E');

    let recomputed_commitment = public_note_withdrawal_commitment(
        public_withdrawal_domain,
        batch_id,
        note_commitment_claim,
        asset_id,
        amount,
        withdraw_authority,
        prior_nullifier_root,
        consumed_nullifier_root,
        claimed_new_nullifier_root,
    );
    assert(recomputed_commitment == withdrawal_commitment, 'E');
    withdrawal_commitment
}

pub fn verify_admission_statement(data: Span<felt252>) -> (felt252, felt252, felt252) {
    let mut index: usize = 0;
    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_ADMISSION, 'ADM_TYPE');

    let settlement_payload = read_vector(data, ref index);
    let order_commitment_root = settlement_order_commitment_root(settlement_payload.span());
    let note_commitment_domain = settlement_note_commitment_domain(settlement_payload.span());
    let spend_authority_domain = settlement_spend_authority_domain(settlement_payload.span());
    let nullifier_domain = settlement_nullifier_domain(settlement_payload.span());
    let order_commitment_domain = settlement_order_commitment_domain(settlement_payload.span());
    let batch_id = settlement_batch_id(settlement_payload.span());
    let pair_id = settlement_pair_id(settlement_payload.span());
    let batch_epoch = settlement_batch_epoch(settlement_payload.span());
    let base_asset_id = settlement_base_asset_id(settlement_payload.span());
    let quote_asset_id = settlement_quote_asset_id(settlement_payload.span());
    let price_base_scale = felt_to_u128(settlement_price_base_scale(settlement_payload.span()));
    assert(price_base_scale != 0, 'ADM_SCALE');

    let order_commitments = read_vector(data, ref index);
    let sides = read_vector(data, ref index);
    let order_types = read_vector(data, ref index);
    let relay_modes = read_vector(data, ref index);
    let limit_prices = read_vector(data, ref index);
    let order_amounts = read_vector(data, ref index);
    let min_fills = read_vector(data, ref index);
    let time_in_force = read_vector(data, ref index);
    let execution_preferences = read_vector(data, ref index);
    let expiry_epochs = read_vector(data, ref index);
    let order_nonces = read_vector(data, ref index);
    let parent_order_commitments = read_vector(data, ref index);
    let parent_child_indexes = read_vector(data, ref index);
    let parent_secret_commitments = read_vector(data, ref index);
    let parent_cancel_authorities = read_vector(data, ref index);
    let parent_authorization_secrets = read_vector(data, ref index);
    let auditor_flags = read_vector(data, ref index);
    let funding_note_refs = read_vector(data, ref index);
    let funding_input_counts = read_vector(data, ref index);
    let funding_note_commitments = read_vector(data, ref index);
    let funding_note_asset_ids = read_vector(data, ref index);
    let funding_input_amounts = read_vector(data, ref index);
    let funding_input_owner_keys = read_vector(data, ref index);
    let funding_note_spend_authorities = read_vector(data, ref index);
    let funding_note_withdraw_authorities = read_vector(data, ref index);
    let funding_note_blindings = read_vector(data, ref index);
    let funding_note_nonces = read_vector(data, ref index);
    let funding_note_metadata_commitments = read_vector(data, ref index);
    let funding_note_amounts = read_vector(data, ref index);
    let funding_note_owner_keys = read_vector(data, ref index);
    let funding_authorization_rs = read_vector(data, ref index);
    let funding_authorization_ss = read_vector(data, ref index);
    let funding_nullifiers = read_vector(data, ref index);
    let recipient_owner_keys = read_vector(data, ref index);
    let recipient_spend_authorities = read_vector(data, ref index);
    let recipient_withdraw_authorities = read_vector(data, ref index);
    let res_auths = read_vector(data, ref index);
    let res_auths_span = res_auths.span();
    let funding_input_count = sum_funding_input_counts(funding_input_counts.span());

    assert_all_lengths_match(
        order_commitments.len(),
        array![
            sides.len().into(), order_types.len().into(), relay_modes.len().into(),
            limit_prices.len().into(), order_amounts.len().into(), min_fills.len().into(),
            time_in_force.len().into(), execution_preferences.len().into(),
            expiry_epochs.len().into(), order_nonces.len().into(), auditor_flags.len().into(),
            parent_order_commitments.len().into(), parent_child_indexes.len().into(),
            parent_secret_commitments.len().into(), parent_cancel_authorities.len().into(),
            parent_authorization_secrets.len().into(), funding_note_refs.len().into(),
            funding_input_counts.len().into(), funding_note_amounts.len().into(),
            funding_note_owner_keys.len().into(), funding_authorization_rs.len().into(),
            funding_authorization_ss.len().into(), funding_nullifiers.len().into(),
            recipient_owner_keys.len().into(), recipient_spend_authorities.len().into(),
            recipient_withdraw_authorities.len().into(), res_auths_span.len().into(),
        ]
            .span(),
        'ADM_LEN',
    );
    assert_all_lengths_match(
        funding_input_count,
        array![
            funding_note_commitments.len().into(), funding_note_asset_ids.len().into(),
            funding_input_amounts.len().into(), funding_input_owner_keys.len().into(),
            funding_note_spend_authorities.len().into(),
            funding_note_withdraw_authorities.len().into(), funding_note_blindings.len().into(),
            funding_note_nonces.len().into(), funding_note_metadata_commitments.len().into(),
        ]
            .span(),
        'ADM_FUNDING_LEN',
    );
    assert_admission_bounds(order_commitments.len(), funding_input_count);
    assert_unique(order_commitments.span(), 'ADM_UNIQUE');
    assert(ordered_commitment_root(order_commitments.span()) == order_commitment_root, 'ADM_ROOT');
    if order_commitments.len() != 0 {
        assert_auction_order_preimages(
            0,
            price_base_scale,
            order_commitments.span(),
            sides.span(),
            order_types.span(),
            relay_modes.span(),
            limit_prices.span(),
            order_amounts.span(),
            min_fills.span(),
            time_in_force.span(),
            execution_preferences.span(),
            expiry_epochs.span(),
            order_nonces.span(),
            parent_order_commitments.span(),
            parent_child_indexes.span(),
            parent_secret_commitments.span(),
            parent_cancel_authorities.span(),
            parent_authorization_secrets.span(),
            auditor_flags.span(),
            funding_note_refs.span(),
            funding_input_counts.span(),
            funding_note_commitments.span(),
            funding_note_asset_ids.span(),
            funding_input_amounts.span(),
            funding_input_owner_keys.span(),
            funding_note_spend_authorities.span(),
            funding_note_withdraw_authorities.span(),
            funding_note_blindings.span(),
            funding_note_nonces.span(),
            funding_note_metadata_commitments.span(),
            funding_note_amounts.span(),
            funding_note_owner_keys.span(),
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
            batch_id,
            pair_id,
            batch_epoch,
            base_asset_id,
            quote_asset_id,
        );
    }
    assert(index == data.len(), 'ADM_TRAIL');
    let admission_root = admission_summary_root(
        order_commitments.span(),
        sides.span(),
        order_types.span(),
        relay_modes.span(),
        limit_prices.span(),
        order_amounts.span(),
        min_fills.span(),
        time_in_force.span(),
        execution_preferences.span(),
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
    assert(statement_type == STATEMENT_TYPE_AUCTION_RESULT, 'AR_TYPE');

    let settlement_payload = read_vector(data, ref index);
    let transcript_commitment = settlement_transcript_commitment(settlement_payload.span());
    let order_commitment_root = settlement_order_commitment_root(settlement_payload.span());
    let clearing_price = settlement_clearing_price(settlement_payload.span());
    let price_base_scale = settlement_price_base_scale(settlement_payload.span());
    let batch_id = settlement_batch_id(settlement_payload.span());
    let _pair_id = settlement_pair_id(settlement_payload.span());
    let matched_order_commitments = settlement_matched_order_commitments(settlement_payload.span());
    let matched_fill_amounts = settlement_matched_fill_amounts(settlement_payload.span());
    let clearing_price_u128 = felt_to_u128(clearing_price);
    let price_base_scale_u128 = felt_to_u128(price_base_scale);
    assert(price_base_scale_u128 != 0, 'AR_SCALE');
    let admission_root = read_next(data, ref index);

    let order_commitments = read_vector(data, ref index);
    let sides = read_vector(data, ref index);
    let order_types = read_vector(data, ref index);
    let relay_modes = read_vector(data, ref index);
    let limit_prices = read_vector(data, ref index);
    let order_amounts = read_vector(data, ref index);
    let min_fills = read_vector(data, ref index);
    let time_in_force = read_vector(data, ref index);
    let execution_preferences = read_vector(data, ref index);
    let funding_note_amounts = read_vector(data, ref index);
    let funding_note_owner_keys = read_vector(data, ref index);
    let allocation_fill_amounts = read_vector(data, ref index);

    assert_all_lengths_match(
        order_commitments.len(),
        array![
            sides.len().into(), order_types.len().into(), relay_modes.len().into(),
            limit_prices.len().into(), order_amounts.len().into(), min_fills.len().into(),
            time_in_force.len().into(), execution_preferences.len().into(),
            funding_note_amounts.len().into(), funding_note_owner_keys.len().into(),
            allocation_fill_amounts.len().into(),
        ]
            .span(),
        'AR_LEN',
    );
    assert_admission_bounds(
        order_commitments.len(), order_commitments.len() * MAX_ORDER_FUNDING_INPUTS,
    );
    assert_unique(order_commitments.span(), 'AR_UNIQ');
    assert(
        ordered_commitment_root(order_commitments.span()) == order_commitment_root, 'AR_ORD_ROOT',
    );
    assert(
        admission_summary_root(
            order_commitments.span(),
            sides.span(),
            order_types.span(),
            relay_modes.span(),
            limit_prices.span(),
            order_amounts.span(),
            min_fills.span(),
            time_in_force.span(),
            execution_preferences.span(),
            funding_note_amounts.span(),
            funding_note_owner_keys.span(),
        ) == admission_root,
        'AR_ADMIT',
    );
    if matched_order_commitments.len() == 0 {
        assert_all_zero(allocation_fill_amounts.span(), 'AR_ZERO');
        assert_no_executable_auction(
            price_base_scale_u128,
            sides.span(),
            order_types.span(),
            limit_prices.span(),
            order_amounts.span(),
            min_fills.span(),
            time_in_force.span(),
            funding_note_amounts.span(),
        );
    } else {
        assert_auction_allocation(
            clearing_price_u128,
            price_base_scale_u128,
            order_commitments.span(),
            sides.span(),
            order_types.span(),
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
            price_base_scale_u128,
            sides.span(),
            order_types.span(),
            limit_prices.span(),
            order_amounts.span(),
            min_fills.span(),
            time_in_force.span(),
            funding_note_amounts.span(),
        );
    }
    assert(index == data.len(), 'AR_TRAIL');
    (batch_id, order_commitment_root, admission_root, transcript_commitment)
}

fn settlement_clearing_price(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 14, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(14)
}

fn settlement_price_base_scale(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 15, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(15)
}

fn settlement_transcript_commitment(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 11, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(11)
}

fn settlement_order_commitment_root(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 9, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(9)
}

fn settlement_note_commitment_domain(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 1, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(1)
}

fn settlement_spend_authority_domain(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 2, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(2)
}

fn settlement_nullifier_domain(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 3, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(3)
}

fn settlement_order_commitment_domain(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 4, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(4)
}

fn settlement_batch_id(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 6, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(6)
}

fn settlement_pair_id(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 7, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(7)
}

fn settlement_batch_epoch(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 8, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(8)
}

fn settlement_base_asset_id(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 12, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(12)
}

fn settlement_quote_asset_id(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 13, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(13)
}

fn settlement_matched_order_commitments(settlement_payload: Span<felt252>) -> Array<felt252> {
    assert(settlement_payload.len() > SETTLEMENT_HEADER_FIELD_COUNT, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    let mut index: usize = SETTLEMENT_HEADER_FIELD_COUNT;
    read_vector(settlement_payload, ref index)
}

fn settlement_matched_fill_amounts(settlement_payload: Span<felt252>) -> Array<felt252> {
    assert(settlement_payload.len() > SETTLEMENT_HEADER_FIELD_COUNT, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    let mut index: usize = SETTLEMENT_HEADER_FIELD_COUNT;
    let _matched_order_commitments = read_vector(settlement_payload, ref index);
    read_vector(settlement_payload, ref index)
}

fn assert_auction_order_preimages(
    clearing_price: u128,
    price_base_scale: u128,
    order_commitments: Span<felt252>,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    relay_modes: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    execution_preferences: Span<felt252>,
    expiry_epochs: Span<felt252>,
    order_nonces: Span<felt252>,
    parent_order_commitments: Span<felt252>,
    parent_child_indexes: Span<felt252>,
    parent_secret_commitments: Span<felt252>,
    parent_cancel_authorities: Span<felt252>,
    parent_authorization_secrets: Span<felt252>,
    auditor_flags: Span<felt252>,
    funding_note_refs: Span<felt252>,
    funding_input_counts: Span<felt252>,
    funding_note_commitments: Span<felt252>,
    funding_note_asset_ids: Span<felt252>,
    funding_input_amounts: Span<felt252>,
    funding_input_owner_keys: Span<felt252>,
    funding_note_spend_authorities: Span<felt252>,
    funding_note_withdraw_authorities: Span<felt252>,
    funding_note_blindings: Span<felt252>,
    funding_note_nonces: Span<felt252>,
    funding_note_metadata_commitments: Span<felt252>,
    funding_note_amounts: Span<felt252>,
    funding_note_owner_keys: Span<felt252>,
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
    batch_id: felt252,
    pair_id: felt252,
    batch_epoch: felt252,
    base_asset_id: felt252,
    quote_asset_id: felt252,
) {
    let mut index = 0;
    let mut funding_input_cursor = 0;
    while index < order_commitments.len() {
        let order_commitment = *order_commitments.at(index);
        let side = *sides.at(index);
        let order_type = *order_types.at(index);
        let relay_mode = *relay_modes.at(index);
        let limit_price = *limit_prices.at(index);
        let order_amount = *order_amounts.at(index);
        let min_fill = *min_fills.at(index);
        let tif = *time_in_force.at(index);
        let execution_preference = *execution_preferences.at(index);
        let expiry_epoch = *expiry_epochs.at(index);
        let order_nonce = *order_nonces.at(index);
        let parent_order_commitment = *parent_order_commitments.at(index);
        let parent_child_index = *parent_child_indexes.at(index);
        let parent_secret_commitment = *parent_secret_commitments.at(index);
        let parent_cancel_authority = *parent_cancel_authorities.at(index);
        let parent_authorization_secret = *parent_authorization_secrets.at(index);
        let auditor_view_allowed = *auditor_flags.at(index);
        let funding_note_ref = *funding_note_refs.at(index);
        let funding_input_count_felt = *funding_input_counts.at(index);
        let funding_note_amount = *funding_note_amounts.at(index);
        let funding_note_owner_key = *funding_note_owner_keys.at(index);
        let funding_authorization_r = *funding_authorization_rs.at(index);
        let funding_authorization_s = *funding_authorization_ss.at(index);
        let funding_nullifier = *funding_nullifiers.at(index);
        let recipient_owner_key = *recipient_owner_keys.at(index);
        let recipient_spend_authority = *recipient_spend_authorities.at(index);
        let recipient_withdraw_authority = *recipient_withdraw_authorities.at(index);
        let recipient_residual_withdraw_authority = *residual_withdraw_authorities.at(index);

        assert(order_commitment != 0, 'E');
        assert(side == ORDER_SIDE_BUY || side == ORDER_SIDE_SELL, 'E');
        assert(
            order_type == ORDER_TYPE_LIMIT_BATCH || order_type == ORDER_TYPE_HEARTBEAT_COVER, 'E',
        );
        assert(limit_price != 0, 'E');
        assert(order_amount != 0, 'E');
        assert(min_fill != 0, 'E');
        assert(felt_to_u128(min_fill) <= felt_to_u128(order_amount), 'E');
        assert(tif == TIF_CURRENT_BATCH_ONLY || tif == TIF_FILL_OR_KILL, 'E');
        assert(
            execution_preference == EXECUTION_PRIVATE_ONLY
                || execution_preference == EXECUTION_PRIVATE_THEN_EXTERNAL,
            'E',
        );
        if tif == TIF_FILL_OR_KILL {
            assert(min_fill == order_amount, 'E');
        }
        assert(expiry_epoch != 0, 'E');
        assert(expiry_epoch == batch_epoch, 'E');
        assert(order_nonce != 0, 'E');
        assert_parent_link(
            parent_order_commitment,
            parent_child_index,
            parent_secret_commitment,
            parent_cancel_authority,
            parent_authorization_secret,
        );
        assert_relay_mode(relay_mode, order_type, parent_order_commitment);
        assert(auditor_view_allowed == 0 || auditor_view_allowed == 1, 'E');
        assert(recipient_owner_key != 0, 'E');
        assert(recipient_spend_authority != 0, 'E');
        assert(recipient_withdraw_authority != 0, 'E');
        assert(recipient_residual_withdraw_authority != 0, 'E');

        let funding_input_count: usize = funding_input_count_felt.try_into().expect('E');
        assert(funding_input_count != 0, 'E');
        assert(funding_input_count <= MAX_ORDER_FUNDING_INPUTS, 'E');
        assert(funding_input_cursor + funding_input_count <= funding_note_commitments.len(), 'E');
        assert(funding_note_ref != 0, 'E');
        assert(funding_note_owner_key != 0, 'E');
        assert(funding_authorization_r != 0, 'E');
        assert(funding_authorization_s != 0, 'E');
        assert(funding_nullifier != 0, 'E');
        assert(funding_note_amount != 0, 'E');
        let first_input_commitment = *funding_note_commitments.at(funding_input_cursor);
        let first_input_nullifier = note_nullifier(
            nullifier_domain,
            first_input_commitment,
            *funding_note_blindings.at(funding_input_cursor),
        );
        let first_spend_authority = *funding_note_spend_authorities.at(funding_input_cursor);
        assert(first_spend_authority != 0, 'E');
        assert_stwo_spend_authorization(
            order_commitment,
            first_spend_authority,
            funding_authorization_r,
            funding_authorization_s,
            'E',
        );
        let recomputed_order_commitment = order_intent_commitment(
            order_commitment_domain,
            pair_id,
            batch_id,
            side,
            order_type,
            relay_mode,
            limit_price,
            order_amount,
            min_fill,
            tif,
            execution_preference,
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
        assert(order_commitment == recomputed_order_commitment, 'E');

        let mut input_set_state = FUNDING_INPUT_SET_DOMAIN;
        let mut nullifier_set_state = FUNDING_NULLIFIER_SET_DOMAIN;
        let mut funding_input_index = 0;
        let mut recomputed_funding_amount: u128 = 0;
        while funding_input_index < funding_input_count {
            let flat_index = funding_input_cursor + funding_input_index;
            let funding_note_commitment = *funding_note_commitments.at(flat_index);
            let funding_note_asset_id = *funding_note_asset_ids.at(flat_index);
            let funding_input_amount = *funding_input_amounts.at(flat_index);
            let funding_input_owner_key = *funding_input_owner_keys.at(flat_index);
            let funding_note_spend_authority = *funding_note_spend_authorities.at(flat_index);
            let funding_note_withdraw_authority = *funding_note_withdraw_authorities.at(flat_index);
            let funding_note_blinding = *funding_note_blindings.at(flat_index);
            let funding_note_nonce = *funding_note_nonces.at(flat_index);
            let funding_note_metadata_commitment = *funding_note_metadata_commitments
                .at(flat_index);
            assert(funding_note_commitment != 0, 'E');
            assert(funding_input_amount != 0, 'E');
            assert(funding_input_owner_key == funding_note_owner_key, 'E');
            assert(funding_note_spend_authority == first_spend_authority, 'E');
            assert(funding_note_withdraw_authority != 0, 'E');
            assert(funding_note_blinding != 0, 'E');
            assert(funding_note_metadata_commitment != 0, 'E');
            if side == ORDER_SIDE_BUY {
                assert(funding_note_asset_id == quote_asset_id, 'E');
            } else {
                assert(side == ORDER_SIDE_SELL, 'E');
                assert(funding_note_asset_id == base_asset_id, 'E');
            }
            let recomputed_funding_note_commitment = note_commitment(
                note_commitment_domain,
                funding_note_asset_id,
                funding_input_amount,
                funding_input_owner_key,
                funding_note_spend_authority,
                funding_note_withdraw_authority,
                funding_note_blinding,
                funding_note_nonce,
                funding_note_metadata_commitment,
            );
            assert(funding_note_commitment == recomputed_funding_note_commitment, 'E');
            let input_nullifier = note_nullifier(
                nullifier_domain, funding_note_commitment, funding_note_blinding,
            );
            input_set_state = poseidon_hash2(input_set_state, funding_note_commitment);
            nullifier_set_state = poseidon_hash2(nullifier_set_state, input_nullifier);
            recomputed_funding_amount = recomputed_funding_amount
                + felt_to_u128(funding_input_amount);
            funding_input_index += 1;
        }
        let recomputed_funding_note_ref = if funding_input_count == 1 {
            first_input_commitment
        } else {
            poseidon_hash2(input_set_state, funding_input_count.into())
        };
        let recomputed_funding_nullifier = if funding_input_count == 1 {
            first_input_nullifier
        } else {
            poseidon_hash2(nullifier_set_state, funding_input_count.into())
        };
        assert(funding_note_ref == recomputed_funding_note_ref, 'E');
        assert(funding_nullifier == recomputed_funding_nullifier, 'E');
        assert(recomputed_funding_amount == felt_to_u128(funding_note_amount), 'E');
        funding_input_cursor += funding_input_count;
        index += 1;
    }
    assert(funding_input_cursor == funding_note_commitments.len(), 'E');
}

fn assert_auction_allocation(
    clearing_price: u128,
    price_base_scale: u128,
    order_commitments: Span<felt252>,
    sides: Span<felt252>,
    order_types: Span<felt252>,
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
        price_base_scale,
        sides,
        order_types,
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
            price_base_scale,
            sides,
            order_types,
            limit_prices,
            order_amounts,
            min_fills,
            time_in_force,
            funding_note_amounts,
        );
        assert(fill == expected_fill, 'E');
        if fill != 0 {
            assert(fill >= felt_to_u128(*min_fills.at(index)), 'E');
            if *time_in_force.at(index) == TIF_FILL_OR_KILL {
                assert(fill == felt_to_u128(*order_amounts.at(index)), 'E');
            }
            assert(matched_index < matched_order_commitments.len(), 'E');
            assert(
                *matched_order_commitments.at(matched_index) == *order_commitments.at(index), 'E',
            );
            assert(
                *matched_fill_amounts.at(matched_index) == *allocation_fill_amounts.at(index), 'E',
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

    assert(matched_index == matched_order_commitments.len(), 'E');
    assert(total_buy_fill == total_sell_fill, 'E');
    let (max_matched, _imbalance) = auction_score_at_price(
        clearing_price,
        price_base_scale,
        sides,
        order_types,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    assert(total_buy_fill == max_matched, 'E');
}

fn stable_active_flags(
    clearing_price: u128,
    price_base_scale: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> Array<felt252> {
    let mut active_flags = initial_active_flags(
        clearing_price,
        price_base_scale,
        sides,
        order_types,
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
            price_base_scale,
            sides,
            order_types,
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
    price_base_scale: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
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
            clearing_price,
            price_base_scale,
            *sides.at(index),
            *order_types.at(index),
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
    price_base_scale: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
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
                price_base_scale,
                sides,
                order_types,
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
    assert(left.len() == right.len(), 'E');
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
    price_base_scale: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
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
        clearing_price,
        price_base_scale,
        target_side,
        *order_types.at(target_index),
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
        price_base_scale,
        sides,
        order_types,
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
        price_base_scale,
        sides,
        order_types,
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
    price_base_scale: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
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
                    clearing_price,
                    price_base_scale,
                    *sides.at(index),
                    *order_types.at(index),
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
    price_base_scale: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
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
                        clearing_price,
                        price_base_scale,
                        *sides.at(index),
                        *order_types.at(index),
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

fn admission_summary_leaf(
    order_commitment: felt252,
    side: felt252,
    order_type: felt252,
    relay_mode: felt252,
    limit_price: felt252,
    amount: felt252,
    min_fill: felt252,
    time_in_force: felt252,
    execution_preference: felt252,
    funding_note_amount: felt252,
    funding_note_owner_key: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(ADMISSION_LEAF_DOMAIN, order_commitment);
    state = poseidon_hash2(state, side);
    state = poseidon_hash2(state, order_type);
    state = poseidon_hash2(state, relay_mode);
    state = poseidon_hash2(state, limit_price);
    state = poseidon_hash2(state, amount);
    state = poseidon_hash2(state, min_fill);
    state = poseidon_hash2(state, time_in_force);
    state = poseidon_hash2(state, execution_preference);
    state = poseidon_hash2(state, funding_note_amount);
    poseidon_hash2(state, funding_note_owner_key)
}

fn admission_summary_root(
    order_commitments: Span<felt252>,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    relay_modes: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    execution_preferences: Span<felt252>,
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
                    *relay_modes.at(index),
                    *limit_prices.at(index),
                    *order_amounts.at(index),
                    *min_fills.at(index),
                    *time_in_force.at(index),
                    *execution_preferences.at(index),
                    *funding_note_amounts.at(index),
                    *funding_note_owner_keys.at(index),
                ),
            );
        index += 1;
    }
    state
}

fn should_update_best(
    best_initialized: felt252,
    matched: u128,
    imbalance: u128,
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
    }
    0
}

fn midpoint_u128(low: u128, high: u128) -> u128 {
    (low / 2) + (high / 2) + (((low % 2) + (high % 2)) / 2)
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
    price_base_scale: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> (u128, u128) {
    let active_flags = stable_active_flags(
        price,
        price_base_scale,
        sides,
        order_types,
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
        price_base_scale,
        sides,
        order_types,
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
        price_base_scale,
        sides,
        order_types,
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

fn assert_best_clearing_price(
    clearing_price: u128,
    price_base_scale: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) {
    let mut best_initialized = 0;
    let mut best_low_price: u128 = 0;
    let mut best_high_price: u128 = 0;
    let mut best_matched: u128 = 0;
    let mut best_imbalance: u128 = 0;
    let mut order_index = 0;

    while order_index < sides.len() {
        if *order_types.at(order_index) != ORDER_TYPE_HEARTBEAT_COVER {
            let candidate = felt_to_u128(*limit_prices.at(order_index));
            if candidate_seen_before(order_types, limit_prices, order_index, candidate) == 0 {
                let (matched, imbalance) = auction_score_at_price(
                    candidate,
                    price_base_scale,
                    sides,
                    order_types,
                    limit_prices,
                    order_amounts,
                    min_fills,
                    time_in_force,
                    funding_note_amounts,
                );
                let update = should_update_best(
                    best_initialized, matched, imbalance, best_matched, best_imbalance,
                );
                if update == 1 {
                    best_initialized = 1;
                    best_low_price = candidate;
                    best_high_price = candidate;
                    best_matched = matched;
                    best_imbalance = imbalance;
                } else if matched == best_matched && imbalance == best_imbalance {
                    if candidate < best_low_price {
                        best_low_price = candidate;
                    }
                    if candidate > best_high_price {
                        best_high_price = candidate;
                    }
                }
            }
        }
        order_index += 1;
    }

    assert(best_initialized == 1, 'E');
    if best_matched == 0 {
        assert(clearing_price == best_low_price, 'E');
    } else {
        assert(clearing_price == midpoint_u128(best_low_price, best_high_price), 'E');
    }
}

fn assert_no_executable_auction(
    price_base_scale: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) {
    let mut order_index = 0;
    while order_index < sides.len() {
        if *order_types.at(order_index) != ORDER_TYPE_HEARTBEAT_COVER {
            let candidate = felt_to_u128(*limit_prices.at(order_index));
            if candidate_seen_before(order_types, limit_prices, order_index, candidate) == 0 {
                let (matched, _imbalance) = auction_score_at_price(
                    candidate,
                    price_base_scale,
                    sides,
                    order_types,
                    limit_prices,
                    order_amounts,
                    min_fills,
                    time_in_force,
                    funding_note_amounts,
                );
                assert(matched == 0, 'E');
            }
        }
        order_index += 1;
    }
}

fn candidate_seen_before(
    order_types: Span<felt252>,
    limit_prices: Span<felt252>,
    candidate_order_index: usize,
    candidate: u128,
) -> felt252 {
    let mut order_index = 0;
    while order_index < candidate_order_index {
        if *order_types.at(order_index) != ORDER_TYPE_HEARTBEAT_COVER {
            if felt_to_u128(*limit_prices.at(order_index)) == candidate {
                return 1;
            }
        }
        order_index += 1;
    }
    0
}

fn max_fill_at_candidate(
    price: u128,
    price_base_scale: u128,
    side: felt252,
    order_type: felt252,
    limit_price_felt: felt252,
    order_amount_felt: felt252,
    min_fill_felt: felt252,
    time_in_force: felt252,
    funding_note_amount_felt: felt252,
) -> u128 {
    if order_type == ORDER_TYPE_HEARTBEAT_COVER {
        return 0;
    }
    assert(order_type == ORDER_TYPE_LIMIT_BATCH, 'E');
    let limit_price = felt_to_u128(limit_price_felt);
    let order_amount = felt_to_u128(order_amount_felt);
    let min_fill = felt_to_u128(min_fill_felt);
    let funding_note_amount = felt_to_u128(funding_note_amount_felt);
    let requested_amount = if side == ORDER_SIDE_BUY {
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
    };

    if side == ORDER_SIDE_BUY {
        if price == 0 {
            return 0;
        }
        let available_amount = u128_min(
            requested_amount,
            base_amount_affordable_for_quote(funding_note_amount, price, price_base_scale),
        );
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

fn u128_min(left: u128, right: u128) -> u128 {
    if left < right {
        return left;
    }
    right
}

fn u128_max(left: u128, right: u128) -> u128 {
    if left > right {
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

fn assert_multi_pair_fill_vectors(
    order_commitments: Span<felt252>,
    pair_ids: Span<felt252>,
    base_asset_ids: Span<felt252>,
    quote_asset_ids: Span<felt252>,
    sides: Span<felt252>,
    submitted_base_amounts: Span<felt252>,
    min_fill_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    price_base_scales: Span<felt252>,
    filled_base_amounts: Span<felt252>,
    quote_amounts: Span<felt252>,
    fee_amounts: Span<felt252>,
    start: usize,
    count: usize,
) {
    assert(count != 0, 'MP_FILL');
    assert(count <= MAX_MULTI_PAIR_FILLS, 'MP_FILL');
    assert(start + count <= order_commitments.len(), 'MP_FILL');
    assert_all_lengths_match(
        order_commitments.len(),
        array![
            pair_ids.len().into(), base_asset_ids.len().into(), quote_asset_ids.len().into(),
            sides.len().into(), submitted_base_amounts.len().into(),
            min_fill_base_amounts.len().into(), limit_prices.len().into(),
            price_base_scales.len().into(), filled_base_amounts.len().into(),
            quote_amounts.len().into(), fee_amounts.len().into(),
        ]
            .span(),
        'MP_FILL',
    );

    let mut index = 0;
    while index < count {
        let cursor = start + index;
        assert(*order_commitments.at(cursor) != 0, 'MP_FILL');
        assert(*pair_ids.at(cursor) != 0, 'MP_FILL');
        assert(*base_asset_ids.at(cursor) != 0, 'MP_FILL');
        assert(*quote_asset_ids.at(cursor) != 0, 'MP_FILL');
        assert(*base_asset_ids.at(cursor) != *quote_asset_ids.at(cursor), 'MP_FILL');
        let side = *sides.at(cursor);
        assert(side == ORDER_SIDE_BUY || side == ORDER_SIDE_SELL, 'MP_FILL');
        let submitted_base = felt_to_u128(*submitted_base_amounts.at(cursor));
        let min_fill = felt_to_u128(*min_fill_base_amounts.at(cursor));
        let filled_base = felt_to_u128(*filled_base_amounts.at(cursor));
        let quote_amount = felt_to_u128(*quote_amounts.at(cursor));
        let limit_price = felt_to_u128(*limit_prices.at(cursor));
        let price_base_scale = felt_to_u128(*price_base_scales.at(cursor));
        let fee_amount = felt_to_u128(*fee_amounts.at(cursor));
        assert(submitted_base != 0, 'MP_FILL');
        assert(filled_base != 0, 'MP_FILL');
        assert(quote_amount != 0, 'MP_FILL');
        assert(limit_price != 0, 'MP_FILL');
        assert(price_base_scale != 0, 'MP_FILL');
        assert(min_fill <= submitted_base, 'MP_FILL');
        assert(filled_base <= submitted_base, 'MP_FILL');
        assert(filled_base >= min_fill, 'MP_FILL');
        let gross_output = if side == ORDER_SIDE_BUY {
            filled_base
        } else {
            quote_amount
        };
        assert(fee_amount < gross_output, 'MP_FILL');

        let limit_quote_amount = quote_amount_for_base_amount(
            filled_base, limit_price, price_base_scale,
        );
        if side == ORDER_SIDE_BUY {
            assert(quote_amount <= limit_quote_amount, 'MP_PRICE');
        } else {
            assert(quote_amount >= limit_quote_amount, 'MP_PRICE');
        }

        let mut right = index + 1;
        while right < count {
            assert(*order_commitments.at(cursor) != *order_commitments.at(start + right), 'MP_DUP');
            right += 1;
        }
        index += 1;
    }
}

fn assert_multi_pair_delta_vectors(
    asset_ids: Span<felt252>,
    amounts: Span<felt252>,
    directions: Span<felt252>,
    sources: Span<felt252>,
    source_commitments: Span<felt252>,
    start: usize,
    count: usize,
) {
    assert(count != 0, 'MP_DELTA');
    assert(count <= MAX_MULTI_PAIR_ASSET_DELTAS, 'MP_DELTA');
    assert(start + count <= asset_ids.len(), 'MP_DELTA');
    assert_all_lengths_match(
        asset_ids.len(),
        array![
            amounts.len().into(), directions.len().into(), sources.len().into(),
            source_commitments.len().into(),
        ]
            .span(),
        'MP_DELTA',
    );
    let mut index = 0;
    while index < count {
        let cursor = start + index;
        assert(*asset_ids.at(cursor) != 0, 'MP_DELTA');
        assert(felt_to_u128(*amounts.at(cursor)) != 0, 'MP_DELTA');
        let direction = *directions.at(cursor);
        assert(
            direction == MULTI_PAIR_DELTA_DIRECTION_IN
                || direction == MULTI_PAIR_DELTA_DIRECTION_OUT,
            'MP_DELTA',
        );
        let source = *sources.at(cursor);
        assert(
            source == MULTI_PAIR_DELTA_SOURCE_USER
                || source == MULTI_PAIR_DELTA_SOURCE_EXTERNAL_COMPLETION
                || source == MULTI_PAIR_DELTA_SOURCE_FEE,
            'MP_DELTA',
        );
        assert(*source_commitments.at(cursor) != 0, 'MP_DELTA');
        index += 1;
    }
}

fn assert_multi_pair_eligible_orders(
    order_commitments: Span<felt252>,
    start: usize,
    count: usize,
    eligible_order_commitments: Span<felt252>,
) {
    assert(eligible_order_commitments.len() != 0, 'MP_ELIG');
    assert(eligible_order_commitments.len() <= MAX_MULTI_PAIR_FILLS, 'MP_ELIG');
    assert_unique_nonzero(eligible_order_commitments, 'MP_ELIG');
    let mut index = 0;
    while index < count {
        let commitment = *order_commitments.at(start + index);
        let mut found = false;
        let mut eligible_index = 0;
        while eligible_index < eligible_order_commitments.len() {
            if commitment == *eligible_order_commitments.at(eligible_index) {
                found = true;
            }
            eligible_index += 1;
        }
        assert(found, 'MP_ELIG');
        index += 1;
    }
}

fn assert_multi_pair_asset_conservation(
    asset_ids: Span<felt252>,
    amounts: Span<felt252>,
    directions: Span<felt252>,
    start: usize,
    count: usize,
) {
    let mut unique_assets = 0;
    let mut index = 0;
    while index < count {
        let cursor = start + index;
        let asset_id = *asset_ids.at(cursor);
        if multi_pair_first_asset_occurrence(asset_ids, start, cursor) {
            unique_assets += 1;
            let inputs = multi_pair_sum_asset_delta(
                asset_ids,
                amounts,
                directions,
                start,
                count,
                asset_id,
                MULTI_PAIR_DELTA_DIRECTION_IN,
            );
            let outputs = multi_pair_sum_asset_delta(
                asset_ids,
                amounts,
                directions,
                start,
                count,
                asset_id,
                MULTI_PAIR_DELTA_DIRECTION_OUT,
            );
            assert(inputs == outputs, 'MP_CONSERVE');
        }
        index += 1;
    }
    assert(unique_assets <= MAX_MULTI_PAIR_ASSETS, 'MP_ASSETS');
}

fn multi_pair_first_asset_occurrence(
    asset_ids: Span<felt252>, start: usize, cursor: usize,
) -> bool {
    let mut index = start;
    while index < cursor {
        if *asset_ids.at(index) == *asset_ids.at(cursor) {
            return false;
        }
        index += 1;
    }
    true
}

fn multi_pair_sum_asset_delta(
    asset_ids: Span<felt252>,
    amounts: Span<felt252>,
    directions: Span<felt252>,
    start: usize,
    count: usize,
    asset_id: felt252,
    direction: felt252,
) -> u128 {
    let mut total: u128 = 0;
    let mut index = 0;
    while index < count {
        let cursor = start + index;
        if *asset_ids.at(cursor) == asset_id && *directions.at(cursor) == direction {
            total = total + felt_to_u128(*amounts.at(cursor));
        }
        index += 1;
    }
    total
}

fn assert_multi_pair_user_fee_delta_bindings(
    order_commitments: Span<felt252>,
    base_asset_ids: Span<felt252>,
    quote_asset_ids: Span<felt252>,
    sides: Span<felt252>,
    filled_base_amounts: Span<felt252>,
    quote_amounts: Span<felt252>,
    fee_amounts: Span<felt252>,
    fill_start: usize,
    fill_count: usize,
    delta_asset_ids: Span<felt252>,
    delta_amounts: Span<felt252>,
    delta_directions: Span<felt252>,
    delta_sources: Span<felt252>,
    delta_source_commitments: Span<felt252>,
    delta_start: usize,
    delta_count: usize,
) {
    let mut fill_index = 0;
    while fill_index < fill_count {
        let cursor = fill_start + fill_index;
        let commitment = *order_commitments.at(cursor);
        let side = *sides.at(cursor);
        let filled_base = felt_to_u128(*filled_base_amounts.at(cursor));
        let quote_amount = felt_to_u128(*quote_amounts.at(cursor));
        let fee_amount = felt_to_u128(*fee_amounts.at(cursor));
        let input_asset = if side == ORDER_SIDE_BUY {
            *quote_asset_ids.at(cursor)
        } else {
            *base_asset_ids.at(cursor)
        };
        let input_amount = if side == ORDER_SIDE_BUY {
            quote_amount
        } else {
            filled_base
        };
        let output_asset = if side == ORDER_SIDE_BUY {
            *base_asset_ids.at(cursor)
        } else {
            *quote_asset_ids.at(cursor)
        };
        let gross_output = if side == ORDER_SIDE_BUY {
            filled_base
        } else {
            quote_amount
        };
        assert(
            multi_pair_sum_bound_delta(
                delta_asset_ids,
                delta_amounts,
                delta_directions,
                delta_sources,
                delta_source_commitments,
                delta_start,
                delta_count,
                commitment,
                input_asset,
                MULTI_PAIR_DELTA_DIRECTION_IN,
                MULTI_PAIR_DELTA_SOURCE_USER,
            ) == input_amount,
            'MP_BIND',
        );
        assert(
            multi_pair_sum_bound_delta(
                delta_asset_ids,
                delta_amounts,
                delta_directions,
                delta_sources,
                delta_source_commitments,
                delta_start,
                delta_count,
                commitment,
                output_asset,
                MULTI_PAIR_DELTA_DIRECTION_OUT,
                MULTI_PAIR_DELTA_SOURCE_USER,
            ) == gross_output
                - fee_amount,
            'MP_BIND',
        );
        assert(
            multi_pair_sum_bound_delta(
                delta_asset_ids,
                delta_amounts,
                delta_directions,
                delta_sources,
                delta_source_commitments,
                delta_start,
                delta_count,
                commitment,
                output_asset,
                MULTI_PAIR_DELTA_DIRECTION_OUT,
                MULTI_PAIR_DELTA_SOURCE_FEE,
            ) == fee_amount,
            'MP_BIND',
        );
        fill_index += 1;
    }

    let mut delta_index = 0;
    while delta_index < delta_count {
        let cursor = delta_start + delta_index;
        let source = *delta_sources.at(cursor);
        if source == MULTI_PAIR_DELTA_SOURCE_USER || source == MULTI_PAIR_DELTA_SOURCE_FEE {
            let commitment = *delta_source_commitments.at(cursor);
            let asset_id = *delta_asset_ids.at(cursor);
            let direction = *delta_directions.at(cursor);
            let actual = multi_pair_sum_bound_delta(
                delta_asset_ids,
                delta_amounts,
                delta_directions,
                delta_sources,
                delta_source_commitments,
                delta_start,
                delta_count,
                commitment,
                asset_id,
                direction,
                source,
            );
            let expected = multi_pair_expected_bound_delta(
                order_commitments,
                base_asset_ids,
                quote_asset_ids,
                sides,
                filled_base_amounts,
                quote_amounts,
                fee_amounts,
                fill_start,
                fill_count,
                commitment,
                asset_id,
                direction,
                source,
            );
            assert(actual == expected, 'MP_BIND');
        }
        delta_index += 1;
    }
}

fn multi_pair_sum_bound_delta(
    delta_asset_ids: Span<felt252>,
    delta_amounts: Span<felt252>,
    delta_directions: Span<felt252>,
    delta_sources: Span<felt252>,
    delta_source_commitments: Span<felt252>,
    delta_start: usize,
    delta_count: usize,
    commitment: felt252,
    asset_id: felt252,
    direction: felt252,
    source: felt252,
) -> u128 {
    let mut total: u128 = 0;
    let mut index = 0;
    while index < delta_count {
        let cursor = delta_start + index;
        if *delta_source_commitments.at(cursor) == commitment
            && *delta_asset_ids.at(cursor) == asset_id
            && *delta_directions.at(cursor) == direction
            && *delta_sources.at(cursor) == source {
            total = total + felt_to_u128(*delta_amounts.at(cursor));
        }
        index += 1;
    }
    total
}

fn multi_pair_expected_bound_delta(
    order_commitments: Span<felt252>,
    base_asset_ids: Span<felt252>,
    quote_asset_ids: Span<felt252>,
    sides: Span<felt252>,
    filled_base_amounts: Span<felt252>,
    quote_amounts: Span<felt252>,
    fee_amounts: Span<felt252>,
    fill_start: usize,
    fill_count: usize,
    commitment: felt252,
    asset_id: felt252,
    direction: felt252,
    source: felt252,
) -> u128 {
    let mut total: u128 = 0;
    let mut index = 0;
    while index < fill_count {
        let cursor = fill_start + index;
        if *order_commitments.at(cursor) == commitment {
            let side = *sides.at(cursor);
            let filled_base = felt_to_u128(*filled_base_amounts.at(cursor));
            let quote_amount = felt_to_u128(*quote_amounts.at(cursor));
            let fee_amount = felt_to_u128(*fee_amounts.at(cursor));
            let input_asset = if side == ORDER_SIDE_BUY {
                *quote_asset_ids.at(cursor)
            } else {
                *base_asset_ids.at(cursor)
            };
            let input_amount = if side == ORDER_SIDE_BUY {
                quote_amount
            } else {
                filled_base
            };
            let output_asset = if side == ORDER_SIDE_BUY {
                *base_asset_ids.at(cursor)
            } else {
                *quote_asset_ids.at(cursor)
            };
            let gross_output = if side == ORDER_SIDE_BUY {
                filled_base
            } else {
                quote_amount
            };
            if source == MULTI_PAIR_DELTA_SOURCE_USER
                && direction == MULTI_PAIR_DELTA_DIRECTION_IN
                && asset_id == input_asset {
                total = total + input_amount;
            }
            if source == MULTI_PAIR_DELTA_SOURCE_USER
                && direction == MULTI_PAIR_DELTA_DIRECTION_OUT
                && asset_id == output_asset {
                total = total + gross_output - fee_amount;
            }
            if source == MULTI_PAIR_DELTA_SOURCE_FEE
                && direction == MULTI_PAIR_DELTA_DIRECTION_OUT
                && asset_id == output_asset {
                total = total + fee_amount;
            }
        }
        index += 1;
    }
    total
}

fn assert_multi_pair_objective_weights(
    asset_ids: Span<felt252>, numerators: Span<felt252>, denominators: Span<felt252>,
) {
    assert(asset_ids.len() != 0, 'MP_WEIGHT');
    assert(asset_ids.len() <= MAX_MULTI_PAIR_ASSETS, 'MP_WEIGHT');
    assert(asset_ids.len() == numerators.len(), 'MP_WEIGHT');
    assert(asset_ids.len() == denominators.len(), 'MP_WEIGHT');
    assert_unique_nonzero(asset_ids, 'MP_WEIGHT');
    let mut index = 0;
    while index < asset_ids.len() {
        assert(felt_to_u128(*numerators.at(index)) != 0, 'MP_WEIGHT');
        assert(felt_to_u128(*denominators.at(index)) != 0, 'MP_WEIGHT');
        index += 1;
    }
}

fn multi_pair_objective_score(
    base_asset_ids: Span<felt252>,
    quote_asset_ids: Span<felt252>,
    sides: Span<felt252>,
    filled_base_amounts: Span<felt252>,
    quote_amounts: Span<felt252>,
    fee_amounts: Span<felt252>,
    start: usize,
    count: usize,
    objective_asset_ids: Span<felt252>,
    objective_numerators: Span<felt252>,
    objective_denominators: Span<felt252>,
) -> u128 {
    let mut score: u128 = 0;
    let mut index = 0;
    while index < count {
        let cursor = start + index;
        let side = *sides.at(cursor);
        let output_asset = if side == ORDER_SIDE_BUY {
            *base_asset_ids.at(cursor)
        } else {
            *quote_asset_ids.at(cursor)
        };
        let gross_output = if side == ORDER_SIDE_BUY {
            felt_to_u128(*filled_base_amounts.at(cursor))
        } else {
            felt_to_u128(*quote_amounts.at(cursor))
        };
        let fee_amount = felt_to_u128(*fee_amounts.at(cursor));
        let net_output = gross_output - fee_amount;
        let (numerator, denominator) = multi_pair_objective_weight_for_asset(
            output_asset, objective_asset_ids, objective_numerators, objective_denominators,
        );
        score = score + net_output * numerator / denominator;
        index += 1;
    }
    score
}

fn multi_pair_objective_weight_for_asset(
    asset_id: felt252,
    objective_asset_ids: Span<felt252>,
    objective_numerators: Span<felt252>,
    objective_denominators: Span<felt252>,
) -> (u128, u128) {
    let mut index = 0;
    while index < objective_asset_ids.len() {
        if *objective_asset_ids.at(index) == asset_id {
            return (
                felt_to_u128(*objective_numerators.at(index)),
                felt_to_u128(*objective_denominators.at(index)),
            );
        }
        index += 1;
    }
    assert(false, 'MP_WEIGHT');
    (0, 1)
}

fn multi_pair_statement_commitment(
    batch_id: felt252,
    chosen_objective: felt252,
    fill_count: felt252,
    delta_count: felt252,
    candidate_count: felt252,
    witness_digest: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(STATEMENT_TYPE_MULTI_PAIR, batch_id);
    state = poseidon_hash2(state, chosen_objective);
    state = poseidon_hash2(state, fill_count);
    state = poseidon_hash2(state, delta_count);
    state = poseidon_hash2(state, candidate_count);
    poseidon_hash2(state, witness_digest)
}

fn multi_pair_witness_digest(data: Span<felt252>) -> felt252 {
    let mut state = poseidon_hash2(MULTI_PAIR_WITNESS_DIGEST_DOMAIN, data.len().into());
    let mut index = 0;
    while index < data.len() {
        state = poseidon_hash2(state, *data.at(index));
        index += 1;
    }
    state
}

fn length_prefixed_payload(serialized: Span<felt252>, message: felt252) -> Array<felt252> {
    assert(serialized.len() != 0, message);
    let payload_len: usize = (*serialized.at(0)).try_into().expect('MPS_PAYLOAD');
    assert(payload_len + 1 == serialized.len(), message);
    let mut payload = array![];
    let mut index: usize = 1;
    while index < serialized.len() {
        payload.append(*serialized.at(index));
        index += 1;
    }
    payload
}

fn multi_pair_payload_group_id(payload: Span<felt252>) -> felt252 {
    assert(payload.len() >= 2, 'MPS_MP');
    assert(*payload.at(0) == STATEMENT_TYPE_MULTI_PAIR, 'MPS_MP');
    let group_id = *payload.at(1);
    assert(group_id != 0, 'MPS_MP');
    group_id
}

fn multi_pair_payload_chosen_fill_vectors(
    payload: Span<felt252>,
) -> (
    Array<felt252>,
    Array<felt252>,
    Array<felt252>,
    Array<felt252>,
    Array<felt252>,
    Array<felt252>,
    Array<felt252>,
    Array<felt252>,
    Array<felt252>,
    Array<felt252>,
    Array<felt252>,
    Array<felt252>,
) {
    let mut index: usize = 2;
    let order_commitments = read_vector(payload, ref index);
    let pair_ids = read_vector(payload, ref index);
    let base_asset_ids = read_vector(payload, ref index);
    let quote_asset_ids = read_vector(payload, ref index);
    let sides = read_vector(payload, ref index);
    let submitted_base_amounts = read_vector(payload, ref index);
    let min_fill_base_amounts = read_vector(payload, ref index);
    let limit_prices = read_vector(payload, ref index);
    let price_base_scales = read_vector(payload, ref index);
    let filled_base_amounts = read_vector(payload, ref index);
    let quote_amounts = read_vector(payload, ref index);
    let fee_amounts = read_vector(payload, ref index);
    (
        order_commitments,
        pair_ids,
        base_asset_ids,
        quote_asset_ids,
        sides,
        submitted_base_amounts,
        min_fill_base_amounts,
        limit_prices,
        price_base_scales,
        filled_base_amounts,
        quote_amounts,
        fee_amounts,
    )
}

fn multi_pair_payload_chosen_delta_vectors(
    payload: Span<felt252>,
) -> (Array<felt252>, Array<felt252>, Array<felt252>, Array<felt252>, Array<felt252>) {
    let mut index: usize = 2;
    skip_vectors(payload, ref index, 12);
    let delta_asset_ids = read_vector(payload, ref index);
    let delta_amounts = read_vector(payload, ref index);
    let delta_directions = read_vector(payload, ref index);
    let delta_sources = read_vector(payload, ref index);
    let delta_source_commitments = read_vector(payload, ref index);
    (delta_asset_ids, delta_amounts, delta_directions, delta_sources, delta_source_commitments)
}

fn assert_multi_pair_settlement_binding_vectors(
    batch_ids: Span<felt252>,
    pair_ids: Span<felt252>,
    order_commitment_roots: Span<felt252>,
    encrypted_order_set_commitments: Span<felt252>,
    base_asset_ids: Span<felt252>,
    quote_asset_ids: Span<felt252>,
    price_base_scales: Span<felt252>,
    taker_fee_bps_values: Span<felt252>,
) {
    assert(batch_ids.len() != 0, 'MPS_BATCH');
    assert(batch_ids.len() <= MAX_MULTI_PAIR_ASSETS, 'MPS_BATCH');
    assert(batch_ids.len() == pair_ids.len(), 'MPS_BIND_LEN');
    assert(batch_ids.len() == order_commitment_roots.len(), 'MPS_BIND_LEN');
    assert(batch_ids.len() == encrypted_order_set_commitments.len(), 'MPS_BIND_LEN');
    assert(batch_ids.len() == base_asset_ids.len(), 'MPS_BIND_LEN');
    assert(batch_ids.len() == quote_asset_ids.len(), 'MPS_BIND_LEN');
    assert(batch_ids.len() == price_base_scales.len(), 'MPS_BIND_LEN');
    assert(batch_ids.len() == taker_fee_bps_values.len(), 'MPS_BIND_LEN');
}

fn assert_all_nonzero(values: Span<felt252>, message: felt252) {
    let mut index = 0;
    while index < values.len() {
        assert(*values.at(index) != 0, message);
        index += 1;
    }
}

fn assert_equal_vectors(left: Span<felt252>, right: Span<felt252>, message: felt252) {
    assert(left.len() == right.len(), message);
    let mut index = 0;
    while index < left.len() {
        assert(*left.at(index) == *right.at(index), message);
        index += 1;
    }
}

fn assert_matched_fill_batch_bindings(
    matched_batch_ids: Span<felt252>,
    fill_pair_ids: Span<felt252>,
    fill_base_asset_ids: Span<felt252>,
    fill_quote_asset_ids: Span<felt252>,
    fill_price_base_scales: Span<felt252>,
    batch_ids: Span<felt252>,
    pair_ids: Span<felt252>,
    base_asset_ids: Span<felt252>,
    quote_asset_ids: Span<felt252>,
    price_base_scales: Span<felt252>,
) {
    assert(matched_batch_ids.len() == fill_pair_ids.len(), 'MPS_FILL_BIND');
    assert(matched_batch_ids.len() == fill_base_asset_ids.len(), 'MPS_FILL_BIND');
    assert(matched_batch_ids.len() == fill_quote_asset_ids.len(), 'MPS_FILL_BIND');
    assert(matched_batch_ids.len() == fill_price_base_scales.len(), 'MPS_FILL_BIND');
    let mut fill_index = 0;
    while fill_index < matched_batch_ids.len() {
        let mut found = false;
        let mut binding_index = 0;
        while binding_index < batch_ids.len() {
            if *matched_batch_ids.at(fill_index) == *batch_ids.at(binding_index)
                && *fill_pair_ids.at(fill_index) == *pair_ids.at(binding_index) {
                assert(
                    *fill_base_asset_ids.at(fill_index) == *base_asset_ids.at(binding_index),
                    'MPS_FILL_BIND',
                );
                assert(
                    *fill_quote_asset_ids.at(fill_index) == *quote_asset_ids.at(binding_index),
                    'MPS_FILL_BIND',
                );
                assert(
                    *fill_price_base_scales.at(fill_index) == *price_base_scales.at(binding_index),
                    'MPS_FILL_BIND',
                );
                found = true;
            }
            binding_index += 1;
        }
        assert(found, 'MPS_FILL_BIND');
        fill_index += 1;
    }
}

fn multi_pair_gross_fee_for_asset(
    asset_id: felt252,
    base_asset_ids: Span<felt252>,
    quote_asset_ids: Span<felt252>,
    sides: Span<felt252>,
    fee_amounts: Span<felt252>,
) -> u128 {
    let mut total: u128 = 0;
    let mut index = 0;
    while index < fee_amounts.len() {
        let output_asset = if *sides.at(index) == ORDER_SIDE_BUY {
            *base_asset_ids.at(index)
        } else {
            *quote_asset_ids.at(index)
        };
        if output_asset == asset_id {
            total += felt_to_u128(*fee_amounts.at(index));
        }
        index += 1;
    }
    total
}

fn multi_pair_fee_entry_amount(
    fee_asset_ids: Span<felt252>, fee_amounts: Span<felt252>, asset_id: felt252,
) -> u128 {
    let mut total: u128 = 0;
    let mut index = 0;
    while index < fee_asset_ids.len() {
        if *fee_asset_ids.at(index) == asset_id {
            total += felt_to_u128(*fee_amounts.at(index));
        }
        index += 1;
    }
    total
}

fn assert_multi_pair_fee_entries_are_exact(
    fee_asset_ids: Span<felt252>,
    fee_amounts: Span<felt252>,
    base_asset_ids: Span<felt252>,
    quote_asset_ids: Span<felt252>,
    sides: Span<felt252>,
    fill_fee_amounts: Span<felt252>,
) {
    let mut index = 0;
    while index < fee_asset_ids.len() {
        let asset_id = *fee_asset_ids.at(index);
        let expected_fee = multi_pair_gross_fee_for_asset(
            asset_id, base_asset_ids, quote_asset_ids, sides, fill_fee_amounts,
        );
        assert(expected_fee != 0, 'MPS_FEE_EXTRA');
        assert(felt_to_u128(*fee_amounts.at(index)) == expected_fee, 'MPS_FEE_AMOUNT');
        index += 1;
    }
}

fn assert_multi_pair_all_positive_fees_have_entries(
    fee_asset_ids: Span<felt252>,
    fee_amounts: Span<felt252>,
    base_asset_ids: Span<felt252>,
    quote_asset_ids: Span<felt252>,
    sides: Span<felt252>,
    fill_fee_amounts: Span<felt252>,
) {
    let mut index = 0;
    while index < fill_fee_amounts.len() {
        let asset_id = if *sides.at(index) == ORDER_SIDE_BUY {
            *base_asset_ids.at(index)
        } else {
            *quote_asset_ids.at(index)
        };
        let expected_fee = multi_pair_gross_fee_for_asset(
            asset_id, base_asset_ids, quote_asset_ids, sides, fill_fee_amounts,
        );
        if expected_fee != 0 {
            assert(
                multi_pair_fee_entry_amount(fee_asset_ids, fee_amounts, asset_id) == expected_fee,
                'MPS_FEE_MISSING',
            );
        }
        index += 1;
    }
}

fn multi_pair_batch_binding_root(
    batch_ids: Span<felt252>,
    pair_ids: Span<felt252>,
    batch_epoch: felt252,
    order_commitment_roots: Span<felt252>,
    encrypted_order_set_commitments: Span<felt252>,
    base_asset_ids: Span<felt252>,
    quote_asset_ids: Span<felt252>,
    price_base_scales: Span<felt252>,
    taker_fee_bps_values: Span<felt252>,
) -> felt252 {
    assert_multi_pair_settlement_binding_vectors(
        batch_ids,
        pair_ids,
        order_commitment_roots,
        encrypted_order_set_commitments,
        base_asset_ids,
        quote_asset_ids,
        price_base_scales,
        taker_fee_bps_values,
    );
    let mut state = MULTI_PAIR_BATCH_ROOT_DOMAIN;
    let mut index = 0;
    while index < batch_ids.len() {
        state = poseidon_hash2(state, *batch_ids.at(index));
        state = poseidon_hash2(state, *pair_ids.at(index));
        state = poseidon_hash2(state, batch_epoch);
        state = poseidon_hash2(state, *order_commitment_roots.at(index));
        state = poseidon_hash2(state, *encrypted_order_set_commitments.at(index));
        state = poseidon_hash2(state, *base_asset_ids.at(index));
        state = poseidon_hash2(state, *quote_asset_ids.at(index));
        state = poseidon_hash2(state, *price_base_scales.at(index));
        state = poseidon_hash2(state, *taker_fee_bps_values.at(index));
        index += 1;
    }
    poseidon_hash2(state, batch_ids.len().into())
}

fn multi_pair_fee_root(
    domain: felt252, asset_ids: Span<felt252>, amounts: Span<felt252>, recipients: Span<felt252>,
) -> felt252 {
    assert(asset_ids.len() == amounts.len(), 'MPS_FEE');
    assert(asset_ids.len() == recipients.len(), 'MPS_FEE');
    let mut state = domain;
    let mut index = 0;
    while index < asset_ids.len() {
        state = poseidon_hash2(state, *asset_ids.at(index));
        state = poseidon_hash2(state, *recipients.at(index));
        state = poseidon_hash2(state, *amounts.at(index));
        index += 1;
    }
    poseidon_hash2(state, asset_ids.len().into())
}

fn public_multi_pair_settlement_commitment(
    group_id: felt252,
    batch_epoch: felt252,
    batch_binding_root: felt252,
    protocol_fee_recipient: felt252,
    output_bundle_ref: felt252,
    multi_pair_commitment: felt252,
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
    let mut state = poseidon_hash2(PUBLIC_MULTI_PAIR_SETTLEMENT_DOMAIN, group_id);
    state = poseidon_hash2(state, batch_epoch);
    state = poseidon_hash2(state, batch_binding_root);
    state = poseidon_hash2(state, protocol_fee_recipient);
    state = poseidon_hash2(state, output_bundle_ref);
    state = poseidon_hash2(state, multi_pair_commitment);
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

fn quote_amount_for_base_amount(base_amount: u128, price: u128, price_base_scale: u128) -> u128 {
    assert(price_base_scale != 0, 'E');
    base_amount * price / price_base_scale
}

fn base_amount_affordable_for_quote(
    quote_amount: u128, price: u128, price_base_scale: u128,
) -> u128 {
    assert(price_base_scale != 0, 'E');
    if price == 0 {
        return 0;
    }
    quote_amount * price_base_scale / price
}

fn mul_div_floor_u128(left: u128, right: u128, denominator: u128) -> u128 {
    assert(denominator != 0, 'E');
    left * right / denominator
}

fn mul_div_ceil_u128(left: u128, right: u128, denominator: u128) -> u128 {
    assert(denominator != 0, 'E');
    if left == 0 || right == 0 {
        return 0;
    }
    let product = left * right;
    (product + denominator - 1) / denominator
}

fn u128_clamp(value: u128, lower: u128, upper: u128) -> u128 {
    if value < lower {
        return lower;
    }
    if value > upper {
        return upper;
    }
    value
}

fn usize_to_u128(value: usize) -> u128 {
    let value_felt: felt252 = value.into();
    felt_to_u128(value_felt)
}

fn pow2_u128(exp: usize) -> u128 {
    let mut value: u128 = 1;
    let mut index = 0;
    while index < exp {
        value *= 2;
        index += 1;
    }
    value
}

fn pow2_u256(exp: usize) -> u256 {
    let mut value: u256 = 1_u256;
    let mut index = 0;
    while index < exp {
        value *= 2_u256;
        index += 1;
    }
    value
}

fn u128_rotate_left(value: u128, shift: usize) -> u128 {
    let bounded_shift = shift % 128;
    if bounded_shift == 0 {
        return value;
    }
    let modulus = u256 { low: 0, high: 1 };
    let product: u256 = value.into() * pow2_u256(bounded_shift);
    let left: u128 = (product % modulus).try_into().expect('ROT_SEED');
    let right = value / pow2_u128(128 - bounded_shift);
    left + right
}

fn read_next(data: Span<felt252>, ref index: usize) -> felt252 {
    assert(index < data.len(), 'E');
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

fn skip_fields(data: Span<felt252>, ref index: usize, count: usize) {
    let mut cursor = 0;
    while cursor < count {
        read_next(data, ref index);
        cursor += 1;
    }
}

fn skip_vectors(data: Span<felt252>, ref index: usize, count: usize) {
    let mut cursor = 0;
    while cursor < count {
        read_vector(data, ref index);
        cursor += 1;
    }
}

fn assert_all_lengths_match(expected_len: usize, lengths: Span<felt252>, message: felt252) {
    let expected: felt252 = expected_len.into();
    let mut index = 0;
    while index < lengths.len() {
        assert(*lengths.at(index) == expected, message);
        index += 1;
    };
}

fn sum_funding_input_counts(counts: Span<felt252>) -> usize {
    assert(counts.len() <= MAX_SETTLEMENT_ORDERS, 'E');
    let mut index = 0;
    let mut total = 0;
    while index < counts.len() {
        let count: usize = (*counts.at(index)).try_into().expect('E');
        assert(count != 0, 'E');
        assert(count <= MAX_ORDER_FUNDING_INPUTS, 'E');
        total += count;
        index += 1;
    }
    total
}

fn assert_admission_bounds(order_count: usize, funding_input_count: usize) {
    assert(order_count <= MAX_SETTLEMENT_ORDERS, 'E');
    assert(funding_input_count <= MAX_SETTLEMENT_INPUT_NOTES, 'E');
}

fn assert_settlement_bounds(
    order_count: usize, funding_input_count: usize, output_note_count: usize,
) {
    assert_admission_bounds(order_count, funding_input_count);
    assert(output_note_count <= MAX_SETTLEMENT_OUTPUT_NOTES, 'E');
}

fn assert_canonical_public_output(
    ref output_cursor: usize,
    expected_commitment: felt252,
    expected_asset_id: felt252,
    expected_amount: u128,
    expected_withdraw_authority: felt252,
    output_note_commitments: Span<felt252>,
    output_note_asset_ids: Span<felt252>,
    output_note_amounts: Span<felt252>,
    output_note_withdraw_authorities: Span<felt252>,
) {
    assert(output_cursor < output_note_commitments.len(), 'OUT_CURSOR');
    assert(expected_commitment == *output_note_commitments.at(output_cursor), 'OUT_COMMIT');
    assert(expected_asset_id == *output_note_asset_ids.at(output_cursor), 'OUT_ASSET');
    assert(expected_amount == felt_to_u128(*output_note_amounts.at(output_cursor)), 'OUT_AMOUNT');
    assert(
        expected_withdraw_authority == *output_note_withdraw_authorities.at(output_cursor),
        'OUT_WITHDRAW',
    );
    output_cursor += 1;
}

fn assert_fee_output(
    ref output_cursor: usize,
    note_commitment_domain: felt252,
    expected_asset_id: felt252,
    expected_amount: u128,
    expected_withdraw_authority: felt252,
    output_note_commitments: Span<felt252>,
    output_note_asset_ids: Span<felt252>,
    output_note_amounts: Span<felt252>,
    output_note_withdraw_authorities: Span<felt252>,
    output_note_owner_keys: Span<felt252>,
    output_note_spend_authorities: Span<felt252>,
    output_note_blindings: Span<felt252>,
    output_note_nonces: Span<felt252>,
    output_note_metadata_commitments: Span<felt252>,
) {
    if expected_amount == 0 {
        return;
    }
    assert(output_cursor < output_note_commitments.len(), 'E');
    let output_note_owner_key = *output_note_owner_keys.at(output_cursor);
    let output_note_spend_authority = *output_note_spend_authorities.at(output_cursor);
    let output_note_blinding = *output_note_blindings.at(output_cursor);
    let output_note_nonce = *output_note_nonces.at(output_cursor);
    let output_note_metadata_commitment = *output_note_metadata_commitments.at(output_cursor);
    assert(output_note_owner_key != 0, 'E');
    assert(output_note_spend_authority != 0, 'E');
    assert(output_note_spend_authority == expected_withdraw_authority, 'E');
    assert(output_note_blinding != 0, 'E');
    assert(output_note_nonce != 0, 'E');
    assert(output_note_metadata_commitment != 0, 'E');
    let recomputed_commitment = note_commitment(
        note_commitment_domain,
        expected_asset_id,
        expected_amount.into(),
        output_note_owner_key,
        output_note_spend_authority,
        expected_withdraw_authority,
        output_note_blinding,
        output_note_nonce,
        output_note_metadata_commitment,
    );
    assert_canonical_public_output(
        ref output_cursor,
        recomputed_commitment,
        expected_asset_id,
        expected_amount,
        expected_withdraw_authority,
        output_note_commitments,
        output_note_asset_ids,
        output_note_amounts,
        output_note_withdraw_authorities,
    );
}

fn matched_public_output_count(
    matched_order_commitments: Span<felt252>, matched_residual_note_flags: Span<felt252>,
) -> usize {
    assert(matched_order_commitments.len() == matched_residual_note_flags.len(), 'E');
    let mut output_count = matched_order_commitments.len();
    let mut index = 0;
    while index < matched_residual_note_flags.len() {
        let residual_note_flag = *matched_residual_note_flags.at(index);
        assert(residual_note_flag == 0 || residual_note_flag == 1, 'E');
        if residual_note_flag == 1 {
            output_count += 1;
        }
        index += 1;
    }
    output_count
}

fn matched_consumed_input_count(
    matched_order_commitments: Span<felt252>, matched_funding_input_counts: Span<felt252>,
) -> usize {
    assert(matched_order_commitments.len() == matched_funding_input_counts.len(), 'E');
    let mut input_count = 0;
    let mut index = 0;
    while index < matched_funding_input_counts.len() {
        let funding_input_count: usize = (*matched_funding_input_counts.at(index))
            .try_into()
            .expect('E');
        assert(funding_input_count != 0, 'E');
        assert(funding_input_count <= MAX_ORDER_FUNDING_INPUTS, 'E');
        input_count += funding_input_count;
        index += 1;
    }
    input_count
}

fn prefix_count_sum(counts: Span<felt252>, prefix_len: usize, message: felt252) -> usize {
    assert(prefix_len <= counts.len(), message);
    let mut count_sum = 0;
    let mut index = 0;
    while index < prefix_len {
        let count: usize = (*counts.at(index)).try_into().expect(message);
        count_sum += count;
        index += 1;
    }
    count_sum
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
    assert(current_nullifiers.len() == key_lows.len(), 'E');
    assert(current_nullifiers.len() == key_highs.len(), 'E');
    assert(current_nullifiers.len() == path_counts.len(), 'E');
    let mut running_root = prior_nullifier_root;
    let mut path_cursor = 0;
    let mut index = 0;
    while index < current_nullifiers.len() {
        let nullifier = *current_nullifiers.at(index);
        assert(nullifier != 0, 'E');
        let key_low: u128 = (*key_lows.at(index)).try_into().expect('E');
        let key_high: u128 = (*key_highs.at(index)).try_into().expect('E');
        assert_sparse_key_in_field(key_low, key_high);
        assert(nullifier == key_low.into() + key_high.into() * TWO_POW_128, 'E');
        let path_count: usize = (*path_counts.at(index)).try_into().expect('E');
        assert(path_cursor + path_count <= path_values.len(), 'E');
        assert(path_cursor + path_count <= path_directions.len(), 'E');
        if running_root == 0 {
            assert(path_count == 0, 'E');
            running_root =
                sparse_insert_nullifier_from_empty(
                    nullifier, key_low, sparse_leaf_domain, sparse_node_domain,
                );
        } else {
            assert(path_count == NULLIFIER_SPARSE_TREE_DEPTH, 'E');
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
    assert(path_cursor == path_values.len(), 'E');
    assert(path_cursor == path_directions.len(), 'E');
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
    assert(entry != 0, 'E');
    let key_low: u128 = key_low_felt.try_into().expect('E');
    let key_high: u128 = key_high_felt.try_into().expect('E');
    assert_sparse_key_in_field(key_low, key_high);
    assert(entry == key_low.into() + key_high.into() * TWO_POW_128, 'E');
    let path_count: usize = path_count_felt.try_into().expect('E');
    assert(path_cursor + path_count <= path_values.len(), 'E');
    assert(path_cursor + path_count <= path_directions.len(), 'E');
    let new_root = if prior_root == 0 {
        assert(path_count == 0, 'E');
        sparse_insert_nullifier_from_empty(entry, key_low, sparse_leaf_domain, sparse_node_domain)
    } else {
        assert(path_count == NULLIFIER_SPARSE_TREE_DEPTH, 'E');
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

fn assert_sparse_key_in_field(key_low: u128, key_high: u128) {
    assert(
        key_high < SPARSE_KEY_HIGH_MAX || (key_high == SPARSE_KEY_HIGH_MAX && key_low == 0), 'E',
    );
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
    assert(entry != 0, 'E');
    let key_low: u128 = key_low_felt.try_into().expect('E');
    let key_high: u128 = key_high_felt.try_into().expect('E');
    assert_sparse_key_in_field(key_low, key_high);
    assert(entry == key_low.into() + key_high.into() * TWO_POW_128, 'E');
    let path_count: usize = path_count_felt.try_into().expect('E');
    assert(path_cursor + path_count <= path_values.len(), 'E');
    assert(path_cursor + path_count <= path_directions.len(), 'E');
    if prior_root == 0 {
        assert(path_count == 0, 'E');
        return prior_root;
    }
    assert(path_count == NULLIFIER_SPARSE_TREE_DEPTH, 'E');
    let mut reconstructed_low: felt252 = 0;
    let mut bit_weight: felt252 = 1;
    let mut empty_root = 0;
    let mut level = 0;
    while level < NULLIFIER_SPARSE_TREE_DEPTH {
        let sibling = *path_values.at(path_cursor + level);
        let bit = *path_directions.at(path_cursor + level);
        assert(bit == 0 || bit == 1, 'E');
        reconstructed_low = reconstructed_low + bit * bit_weight;
        bit_weight = bit_weight * 2;
        if bit == 0 {
            empty_root = sparse_nullifier_node(sparse_node_domain, empty_root, sibling, level);
        } else {
            empty_root = sparse_nullifier_node(sparse_node_domain, sibling, empty_root, level);
        }
        level += 1;
    }
    assert(reconstructed_low == key_low.into(), 'E');
    assert(empty_root == prior_root, 'E');
    path_cursor += path_count;
    prior_root
}

fn assert_renewal_entry_insert(
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
    assert(entry != 0, 'E');
    let key_low: u128 = key_low_felt.try_into().expect('E');
    let key_high: u128 = key_high_felt.try_into().expect('E');
    assert_sparse_key_in_field(key_low, key_high);
    assert(entry == key_low.into() + key_high.into() * TWO_POW_128, 'E');
    let path_count: usize = path_count_felt.try_into().expect('E');
    assert(path_cursor + path_count <= path_values.len(), 'E');
    assert(path_cursor + path_count <= path_directions.len(), 'E');
    let new_root = if prior_root == 0 {
        assert(path_count == 0, 'E');
        sparse_insert_renewal_from_empty(entry, key_low, sparse_leaf_domain, sparse_node_domain)
    } else {
        assert(path_count == RENEWAL_SPARSE_TREE_DEPTH, 'E');
        sparse_insert_renewal(
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

fn assert_renewal_entry_absent(
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
    assert(entry != 0, 'E');
    let key_low: u128 = key_low_felt.try_into().expect('E');
    let key_high: u128 = key_high_felt.try_into().expect('E');
    assert_sparse_key_in_field(key_low, key_high);
    assert(entry == key_low.into() + key_high.into() * TWO_POW_128, 'E');
    let path_count: usize = path_count_felt.try_into().expect('E');
    assert(path_cursor + path_count <= path_values.len(), 'E');
    assert(path_cursor + path_count <= path_directions.len(), 'E');
    if prior_root == 0 {
        assert(path_count == 0, 'E');
        return prior_root;
    }
    assert(path_count == RENEWAL_SPARSE_TREE_DEPTH, 'E');
    let mut reconstructed_low: felt252 = 0;
    let mut bit_weight: felt252 = 1;
    let mut empty_root = 0;
    let mut level = 0;
    while level < RENEWAL_SPARSE_TREE_DEPTH {
        let sibling = *path_values.at(path_cursor + level);
        let bit = *path_directions.at(path_cursor + level);
        assert(bit == 0 || bit == 1, 'E');
        reconstructed_low = reconstructed_low + bit * bit_weight;
        bit_weight = bit_weight * 2;
        if bit == 0 {
            empty_root = sparse_nullifier_node(sparse_node_domain, empty_root, sibling, level);
        } else {
            empty_root = sparse_nullifier_node(sparse_node_domain, sibling, empty_root, level);
        }
        level += 1;
    }
    assert(reconstructed_low == key_low.into(), 'E');
    assert(empty_root == prior_root, 'E');
    path_cursor += path_count;
    prior_root
}

fn sparse_insert_renewal(
    prior_root: felt252,
    entry: felt252,
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
    let mut inserted_root = poseidon_hash2(sparse_leaf_domain, entry);
    let mut level = 0;
    while level < RENEWAL_SPARSE_TREE_DEPTH {
        let sibling = *path_values.at(path_cursor + level);
        let bit = *path_directions.at(path_cursor + level);
        assert(bit == 0 || bit == 1, 'E');
        reconstructed_low = reconstructed_low + bit * bit_weight;
        bit_weight = bit_weight * 2;
        if bit == 0 {
            empty_root = sparse_nullifier_node(sparse_node_domain, empty_root, sibling, level);
            inserted_root =
                sparse_nullifier_node(sparse_node_domain, inserted_root, sibling, level);
        } else {
            empty_root = sparse_nullifier_node(sparse_node_domain, sibling, empty_root, level);
            inserted_root =
                sparse_nullifier_node(sparse_node_domain, sibling, inserted_root, level);
        }
        level += 1;
    }
    assert(reconstructed_low == key_low.into(), 'E');
    assert(empty_root == prior_root, 'E');
    assert(entry == key_low.into() + key_high.into() * TWO_POW_128, 'E');
    inserted_root
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
        assert(bit == 0 || bit == 1, 'E');
        reconstructed_low = reconstructed_low + bit * bit_weight;
        bit_weight = bit_weight * 2;
        if bit == 0 {
            empty_root = sparse_nullifier_node(sparse_node_domain, empty_root, sibling, level);
            inserted_root =
                sparse_nullifier_node(sparse_node_domain, inserted_root, sibling, level);
        } else {
            empty_root = sparse_nullifier_node(sparse_node_domain, sibling, empty_root, level);
            inserted_root =
                sparse_nullifier_node(sparse_node_domain, sibling, inserted_root, level);
        }
        level += 1;
    }
    assert(reconstructed_low == key_low.into(), 'E');
    assert(empty_root == prior_root, 'E');
    assert(nullifier == key_low.into() + key_high.into() * TWO_POW_128, 'E');
    inserted_root
}

fn sparse_insert_nullifier_from_empty(
    entry: felt252, key_low: u128, sparse_leaf_domain: felt252, sparse_node_domain: felt252,
) -> felt252 {
    let mut inserted_root = poseidon_hash2(sparse_leaf_domain, entry);
    let mut empty_sibling = 0;
    let mut remaining_key = key_low;
    let mut level = 0;
    while level < NULLIFIER_SPARSE_TREE_DEPTH {
        let bit = remaining_key % 2;
        remaining_key = remaining_key / 2;
        if bit == 0 {
            inserted_root =
                sparse_nullifier_node(sparse_node_domain, inserted_root, empty_sibling, level);
        } else {
            inserted_root =
                sparse_nullifier_node(sparse_node_domain, empty_sibling, inserted_root, level);
        }
        empty_sibling =
            sparse_nullifier_node(sparse_node_domain, empty_sibling, empty_sibling, level);
        level += 1;
    }
    inserted_root
}

fn sparse_insert_renewal_from_empty(
    entry: felt252, key_low: u128, sparse_leaf_domain: felt252, sparse_node_domain: felt252,
) -> felt252 {
    let mut inserted_root = poseidon_hash2(sparse_leaf_domain, entry);
    let mut empty_sibling = 0;
    let mut remaining_key = key_low;
    let mut level = 0;
    while level < RENEWAL_SPARSE_TREE_DEPTH {
        let bit = remaining_key % 2;
        remaining_key = remaining_key / 2;
        if bit == 0 {
            inserted_root =
                sparse_nullifier_node(sparse_node_domain, inserted_root, empty_sibling, level);
        } else {
            inserted_root =
                sparse_nullifier_node(sparse_node_domain, empty_sibling, inserted_root, level);
        }
        empty_sibling =
            sparse_nullifier_node(sparse_node_domain, empty_sibling, empty_sibling, level);
        level += 1;
    }
    inserted_root
}

fn sparse_nullifier_node(domain: felt252, left: felt252, right: felt252, level: usize) -> felt252 {
    let state = poseidon_hash2(domain, level.into());
    let state = poseidon_hash2(state, left);
    poseidon_hash2(state, right)
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
    let path_count: usize = path_count_felt.try_into().expect('NOTE_PATH');
    let suffix_count: usize = suffix_count_felt.try_into().expect('NOTE_SUFFIX');
    assert(path_cursor + path_count <= path_values.len(), 'NOTE_PATH');
    assert(path_cursor + path_count <= path_directions.len(), 'NOTE_PATH');
    assert(suffix_cursor + suffix_count <= suffix_roots.len(), 'NOTE_SUFFIX');

    let recomputed_batch_root = if kind == NOTE_MEMBERSHIP_KIND_DEPOSIT {
        assert(path_count == 0, 'NOTE_DEPOSIT_PATH');
        output_note_leaf(note_commitment_value, asset_id, amount, withdraw_authority)
    } else {
        assert(kind == NOTE_MEMBERSHIP_KIND_SETTLEMENT_OUTPUT, 'NOTE_KIND');
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
                assert(direction == 1, 'NOTE_DIR');
                root = output_note_node(sibling, root);
            }
            path_cursor += 1;
        }
        root
    };
    assert(recomputed_batch_root == batch_root, 'NOTE_BATCH_ROOT');

    let mut root = state_transition_root(state_transition_root_domain, prefix_root, batch_root);
    let suffix_end = suffix_cursor + suffix_count;
    while suffix_cursor < suffix_end {
        root =
            state_transition_root(
                state_transition_root_domain, root, *suffix_roots.at(suffix_cursor),
            );
        suffix_cursor += 1;
    }
    assert(root == prior_note_root, 'NOTE_PRIOR_ROOT');
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
    assert(residual_note_flag == 0, 'E');
    assert(residual_note_commitment == 0, 'E');
    assert(residual_note_asset_id == 0, 'E');
    assert(residual_note_amount == 0, 'E');
    assert(residual_note_owner_key == 0, 'E');
    assert(residual_note_spend_authority == 0, 'E');
    assert(residual_note_withdraw_authority == 0, 'E');
    assert(residual_note_blinding == 0, 'E');
    assert(residual_note_nonce == 0, 'E');
    assert(residual_note_metadata_commitment == 0, 'E');
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

fn assert_unique_nonzero(values: Span<felt252>, message: felt252) {
    let mut left = 0;
    while left < values.len() {
        let current = *values.at(left);
        let mut right = left + 1;
        while right < values.len() {
            let other = *values.at(right);
            if current != 0 && other != 0 {
                assert(current != other, message);
            }
            right += 1;
        }
        left += 1;
    };
}

fn felt_to_u128(value: felt252) -> u128 {
    value.try_into().expect('E')
}

fn protocol_fee_root(
    domain: felt252,
    base_asset_id: felt252,
    quote_asset_id: felt252,
    protocol_fee_recipient: felt252,
    base_fee_amount: u128,
    quote_fee_amount: u128,
) -> felt252 {
    let mut state = domain;
    let mut fee_count: felt252 = 0;
    if base_fee_amount != 0 {
        state = poseidon_hash2(state, base_asset_id);
        state = poseidon_hash2(state, protocol_fee_recipient);
        state = poseidon_hash2(state, base_fee_amount.into());
        fee_count += 1;
    }
    if quote_fee_amount != 0 {
        state = poseidon_hash2(state, quote_asset_id);
        state = poseidon_hash2(state, protocol_fee_recipient);
        state = poseidon_hash2(state, quote_fee_amount.into());
        fee_count += 1;
    }
    poseidon_hash2(state, fee_count)
}

fn fee_bps_for_order_type(
    order_type: felt252, _parent_order_commitment: felt252, taker_fee_bps: u128,
) -> u128 {
    if order_type == ORDER_TYPE_HEARTBEAT_COVER {
        return 0;
    }
    assert(order_type == ORDER_TYPE_LIMIT_BATCH, 'E');
    taker_fee_bps
}

fn ceil_fee_amount(amount: u128, fee_bps: u128) -> u128 {
    if amount == 0 || fee_bps == 0 {
        return 0;
    }
    (amount * fee_bps + FEE_BPS_DENOMINATOR - 1) / FEE_BPS_DENOMINATOR
}

fn assert_relay_mode(relay_mode: felt252, order_type: felt252, parent_order_commitment: felt252) {
    if relay_mode == RELAY_MODE_SELF {
        assert(parent_order_commitment == 0 || order_type == ORDER_TYPE_LIMIT_BATCH, 'E');
    } else {
        assert(relay_mode == RELAY_MODE_ZYLITH, 'E');
        assert(order_type == ORDER_TYPE_LIMIT_BATCH, 'E');
        assert(parent_order_commitment != 0, 'E');
    }
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
    relay_mode: felt252,
    limit_price: felt252,
    amount: felt252,
    min_fill: felt252,
    time_in_force: felt252,
    execution_preference: felt252,
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
    let with_relay_mode = poseidon_hash2(with_order_type, relay_mode);
    let with_limit = poseidon_hash2(with_relay_mode, limit_price);
    let with_amount = poseidon_hash2(with_limit, amount);
    let with_min_fill = poseidon_hash2(with_amount, min_fill);
    let with_time_in_force = poseidon_hash2(with_min_fill, time_in_force);
    let with_execution_preference = poseidon_hash2(with_time_in_force, execution_preference);
    let with_expiry = poseidon_hash2(with_execution_preference, expiry_epoch);
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
        assert(parent_child_index == 0, 'E');
        assert(parent_secret_commitment == 0, 'E');
        assert(parent_cancel_authority == 0, 'E');
        assert(parent_authorization_secret == 0, 'E');
    } else {
        assert(parent_child_index != 0, 'E');
        assert(parent_secret_commitment != 0, 'E');
        assert(parent_cancel_authority != 0, 'E');
        assert(parent_authorization_secret != 0, 'E');
        assert(
            renewal_parent_secret_commitment(
                parent_authorization_secret,
            ) == parent_secret_commitment,
            'E',
        );
        assert(
            renewal_parent_commitment(
                parent_secret_commitment, parent_cancel_authority,
            ) == parent_order_commitment,
            'E',
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
    price_base_scale: felt252,
    taker_fee_bps: felt252,
    protocol_fee_recipient: felt252,
    output_bundle_ref: felt252,
    multi_pair_commitment: felt252,
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
    state = poseidon_hash2(state, price_base_scale);
    state = poseidon_hash2(state, taker_fee_bps);
    state = poseidon_hash2(state, protocol_fee_recipient);
    state = poseidon_hash2(state, output_bundle_ref);
    state = poseidon_hash2(state, multi_pair_commitment);
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

fn assert_pair_config(
    pair_id: felt252, base_asset_id: felt252, quote_asset_id: felt252, price_base_scale: felt252,
) {
    if pair_id == PAIR_ID_STRK_USDC {
        assert(base_asset_id == ASSET_ID_STRK, 'E');
        assert(quote_asset_id == ASSET_ID_USDC, 'E');
        assert(price_base_scale == ASSET_SCALE_18, 'E');
    } else if pair_id == PAIR_ID_ETH_USDC {
        assert(base_asset_id == ASSET_ID_ETH, 'E');
        assert(quote_asset_id == ASSET_ID_USDC, 'E');
        assert(price_base_scale == ASSET_SCALE_18, 'E');
    } else if pair_id == PAIR_ID_STRKBTC_USDC {
        assert(base_asset_id == ASSET_ID_STRKBTC, 'E');
        assert(quote_asset_id == ASSET_ID_USDC, 'E');
        assert(price_base_scale == ASSET_SCALE_8, 'E');
    } else if pair_id == PAIR_ID_STRK_ETH {
        assert(base_asset_id == ASSET_ID_STRK, 'E');
        assert(quote_asset_id == ASSET_ID_ETH, 'E');
        assert(price_base_scale == ASSET_SCALE_18, 'E');
    } else if pair_id == PAIR_ID_STRK_STRKBTC {
        assert(base_asset_id == ASSET_ID_STRK, 'E');
        assert(quote_asset_id == ASSET_ID_STRKBTC, 'E');
        assert(price_base_scale == ASSET_SCALE_18, 'E');
    } else if pair_id == PAIR_ID_WBTC_STRKBTC {
        assert(base_asset_id == ASSET_ID_WBTC, 'E');
        assert(quote_asset_id == ASSET_ID_STRKBTC, 'E');
        assert(price_base_scale == ASSET_SCALE_8, 'E');
    } else if pair_id == PAIR_ID_USDC_USDT {
        assert(base_asset_id == ASSET_ID_USDC, 'E');
        assert(quote_asset_id == ASSET_ID_USDT, 'E');
        assert(price_base_scale == ASSET_SCALE_6, 'E');
    } else {
        assert(false, 'E');
    }
}

fn public_note_consolidation_commitment(
    seed: felt252,
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
    let mut state = poseidon_hash2(seed, consolidation_id);
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
    seed: felt252,
    batch_id: felt252,
    note_commitment: felt252,
    asset_id: felt252,
    amount: felt252,
    withdraw_authority: felt252,
    prior_nullifier_root: felt252,
    consumed_nullifier_root: felt252,
    new_nullifier_root: felt252,
) -> felt252 {
    let mut state = poseidon_hash2(seed, batch_id);
    state = poseidon_hash2(state, note_commitment);
    state = poseidon_hash2(state, asset_id);
    state = poseidon_hash2(state, amount);
    state = poseidon_hash2(state, withdraw_authority);
    state = poseidon_hash2(state, prior_nullifier_root);
    state = poseidon_hash2(state, consumed_nullifier_root);
    state = poseidon_hash2(state, new_nullifier_root);
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
    assert(left.len() == right.len(), 'E');
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
    assert(first.len() == second.len(), 'E');
    assert(first.len() == third.len(), 'E');
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
    assert(first.len() == second.len(), 'E');
    assert(first.len() == third.len(), 'E');
    assert(first.len() == fourth.len(), 'E');
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
    assert(note_commitments.len() == asset_ids.len(), 'E');
    assert(note_commitments.len() == amounts.len(), 'E');
    assert(note_commitments.len() == withdraw_authorities.len(), 'E');
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
    _note_commitment_domain: felt252,
    output_bundle_ref: felt252,
    _batch_id: felt252,
    _output_note_root: felt252,
    note_commitments: Span<felt252>,
    _asset_ids: Span<felt252>,
    _amounts: Span<felt252>,
    _withdraw_authorities: Span<felt252>,
    _owner_keys: Span<felt252>,
    _spend_authorities: Span<felt252>,
    _blindings: Span<felt252>,
    _nonces: Span<felt252>,
    _metadata_commitments: Span<felt252>,
    recovery_key_tags: Span<felt252>,
    recovery_auth_tags: Span<felt252>,
    recovery_ciphertext_fields: Span<felt252>,
    recovery_dummy_commitments: Span<felt252>,
) {
    let mut bundle_state = OUTPUT_RECOVERY_BUNDLE_DOMAIN;
    let mut output_index: usize = 0;
    while output_index < note_commitments.len() {
        let key_tag = *recovery_key_tags.at(output_index);
        let auth_tag = *recovery_auth_tags.at(output_index);
        assert(key_tag != 0, 'E');
        assert(auth_tag != 0, 'E');
        let mut record_commitment = poseidon_hash2(OUTPUT_RECOVERY_RECORD_DOMAIN, key_tag);
        record_commitment = poseidon_hash2(record_commitment, auth_tag);
        let field_cursor = output_index * OUTPUT_RECOVERY_FIELD_COUNT;
        let mut field_index: usize = 0;
        while field_index < OUTPUT_RECOVERY_FIELD_COUNT {
            let ciphertext = *recovery_ciphertext_fields.at(field_cursor + field_index);
            assert(ciphertext != 0, 'E');
            record_commitment = poseidon_hash2(record_commitment, ciphertext);
            field_index += 1;
        }
        bundle_state = poseidon_hash2(bundle_state, record_commitment);
        output_index += 1;
    }

    let mut dummy_index: usize = 0;
    while dummy_index < recovery_dummy_commitments.len() {
        let commitment = *recovery_dummy_commitments.at(dummy_index);
        assert(commitment != 0, 'E');
        bundle_state = poseidon_hash2(bundle_state, commitment);
        dummy_index += 1;
    }
    let total_count: felt252 = (note_commitments.len() + recovery_dummy_commitments.len()).into();
    assert(poseidon_hash2(bundle_state, total_count) == output_bundle_ref, 'E');
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
