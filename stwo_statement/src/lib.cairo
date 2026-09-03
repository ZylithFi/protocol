use core::array::{Array, ArrayTrait};
use core::integer::u256;
use core::poseidon::hades_permutation;
use core::traits::{Into, TryInto};
mod admission_executable;
mod auction_result_executable;

mod executable;
mod liquidity_position_executable;
mod multi_pair_executable;

const ORDER_SIDE_BUY: felt252 = 0;
const ORDER_SIDE_SELL: felt252 = 1;
const ORDER_TYPE_LIMIT_BATCH: felt252 = 0;
const ORDER_TYPE_HEARTBEAT_COVER: felt252 = 2;
const RELAY_MODE_SELF: felt252 = 0;
const RELAY_MODE_ZYLITH: felt252 = 1;
const TIF_CURRENT_BATCH_ONLY: felt252 = 0;
const TIF_FILL_OR_KILL: felt252 = 1;
const FEE_BPS_DENOMINATOR: u128 = 10000;
const MAX_LIQUIDITY_POSITION_ROTATION_BPS: u128 = 1000;
const MIN_LIQUIDITY_SLICE_POINTS: usize = 3;
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
const STATEMENT_TYPE_LIQUIDITY_POSITION: felt252 = 7;
const STATEMENT_TYPE_MULTI_PAIR: felt252 = 8;
const MULTI_PAIR_DELTA_DIRECTION_IN: felt252 = 0;
const MULTI_PAIR_DELTA_DIRECTION_OUT: felt252 = 1;
const MULTI_PAIR_DELTA_SOURCE_USER: felt252 = 0;
const MULTI_PAIR_DELTA_SOURCE_LIQUIDITY_POSITION: felt252 = 1;
const MULTI_PAIR_DELTA_SOURCE_PROTOCOL_BACKSTOP: felt252 = 2;
const MULTI_PAIR_DELTA_SOURCE_FEE: felt252 = 3;
const MULTI_PAIR_WITNESS_DIGEST_DOMAIN: felt252 = 'zylith_mpair_in_v1';
const ADMISSION_ROOT_DOMAIN: felt252 = 0x7a796c6974685f61646d69745f726f6f745f7631;
const ADMISSION_LEAF_DOMAIN: felt252 = 0x7a796c6974685f61646d69745f6c6561665f7631;
const MAX_ORDER_FUNDING_INPUTS: usize = 4;
const MAX_LIQUIDITY_SLICE_POINTS: usize = 8;
const MAX_SETTLEMENT_ORDERS: usize = 64;
const MAX_MULTI_PAIR_FILLS: usize = 64;
const MAX_MULTI_PAIR_ASSETS: usize = 8;
const MAX_MULTI_PAIR_ASSET_DELTAS: usize = 256;
const MAX_MULTI_PAIR_CANDIDATE_SOLUTIONS: usize = 64;
const MAX_SETTLEMENT_INPUT_NOTES: usize = MAX_SETTLEMENT_ORDERS * MAX_ORDER_FUNDING_INPUTS;
const MAX_SETTLEMENT_OUTPUT_NOTES: usize = MAX_SETTLEMENT_ORDERS * 2 + 4;
const MAX_SETTLEMENT_LIQUIDITY_SLICE_POINTS: usize = MAX_SETTLEMENT_ORDERS
    * MAX_LIQUIDITY_SLICE_POINTS;
const MAX_LIQUIDITY_POSITION_TRANSITIONS: usize = MAX_SETTLEMENT_ORDERS * 2 + 4;
const SETTLEMENT_HEADER_FIELD_COUNT: usize = 38;
const SETTLEMENT_VECTOR_COUNT_BEFORE_LP_TRANSITION_KINDS: usize = 87;
const LP_TRANSITION_KIND_UPDATE: felt252 = 1;
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
const LIQUIDITY_SLICE_DOMAIN: felt252 =
    0x2bc4890bf4accafb4b8f647c96e53cdd702a9b2e8b405a4d4b83b87ef46c69a;
const PUBLIC_SETTLEMENT_DOMAIN: felt252 =
    0x0283f626418aa97a073f64500f7e35dd8bf7c01ff8611917c3c38e5be92eb205;
const PUBLIC_NOTE_CONSOLIDATION_DOMAIN: felt252 = 0x7a796c6974685f6e6f74655f636f6e736f6c5f7631;
const PUBLIC_NOTE_WITHDRAWAL_DOMAIN: felt252 = 0x7a796c6974685f6e6f74655f77697468647261775f7631;
const CONSUMED_NOTE_ROOT_DOMAIN: felt252 =
    0x5ca3bbd6a01ed8e6017182aa4b43ec8d9e4055d9d4133b008c3ea9916b347dd;
const CONSUMED_NULLIFIER_ROOT_DOMAIN: felt252 =
    0x52259833b97a525483b8fff0635ce1f9fdfd08b5a8db2486d4a05378989b0f0;
const RENEWAL_CHILD_ROOT_DOMAIN: felt252 =
    0x7fa9bd33f1b9cd81a22d77d4dc7ea4d33abd249f7585d0e451b0fafa39dfc3d;
const LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN: felt252 =
    0x0301dfad9cc240f421fd32f6b74d72002abc7f4056b885950bc5bc779213e5f7;
const OUTPUT_NOTE_ROOT_DOMAIN: felt252 =
    0x322d8a4d6fe2953496989824ec66bcb9d011aa052bb4be4593670c1ea7908dc;
const FEE_ROOT_DOMAIN: felt252 = 0x79a9e0b9d4a6b4cac728c0e5f6298e37533fa1348f020f3575a78c5adf7d44b;
const STATE_TRANSITION_ROOT_DOMAIN: felt252 =
    0x01f14f0555b0b80fd6af9553623a021c472d8c930dfcb5b204b35b26f0d2b1b2;
const NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL: felt252 =
    0x03fd7c748b95292c230aa528dc391912cd4557ad3e157e94ab06b22af433f967;
const NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL: felt252 =
    0x02de7e98b8f1ba580329d7cfcf51a36f6eb4f8611cae6f82b34e116bb9c2588c;
const LIQUIDITY_POSITION_COMMITMENT_DOMAIN: felt252 =
    0x02071bb2771567a347c3962774f06dc558dc0ee716fdc1a2c0ccfcef6f18315c;
const LIQUIDITY_POSITION_NULLIFIER_DOMAIN: felt252 =
    0x07a730a37f9232ecf717ca8008e67018f774a2c77c2bb769e980a0b498f52c5d;
const LIQUIDITY_POSITION_LIFECYCLE_AUTHORIZATION_DOMAIN: felt252 =
    0x0247b2f404b5d0205004808c447cfe1ff67eba08dbf0c900481e146213967ac4;
const LIQUIDITY_POSITION_ORACLE_GUARD_DOMAIN: felt252 =
    0x02b02f1a361e4c4e1b4643c1b5b7c7f801a33ddc8f565d84b2e54516c714ca8a;
const LIQUIDITY_POSITION_SPARSE_LEAF_DOMAIN: felt252 =
    0x00214870277bfdd1d326efda4be11f228447d744f972b333e3e8e231c4fbc2f7;
const LIQUIDITY_POSITION_SPARSE_NODE_DOMAIN: felt252 =
    0x009624defa24956e7bc9e82f3957efcebb61f0c81ce1e912afd31a827f7389a4;
const LIQUIDITY_POSITION_CURVE_ROTATION_DOMAIN: felt252 =
    0x079253f59ce2c99b4338cabecd7dfcdef680993a817c39ac60389e560b759601;
const LIQUIDITY_POSITION_SPARSE_TREE_DEPTH: usize = 128;
const LIQUIDITY_POSITION_FIELD_COUNT: usize = 27;

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
    let liquidity_slice_domain = read_next(data, ref index);
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
    let relay_fee_bps = read_next(data, ref index);
    let protocol_fee_recipient = read_next(data, ref index);
    let relay_fee_recipient = read_next(data, ref index);
    let matched_order_count = read_next(data, ref index);
    let output_bundle_ref = read_next(data, ref index);
    let prior_note_root = read_next(data, ref index);
    let prior_nullifier_root = read_next(data, ref index);
    let prior_renewal_root = read_next(data, ref index);
    let prior_fee_root = read_next(data, ref index);
    let prior_liquidity_position_root = read_next(data, ref index);
    let claimed_liquidity_position_transition_root = read_next(data, ref index);
    let consumed_note_root_domain = read_next(data, ref index);
    let consumed_nullifier_root_domain = read_next(data, ref index);
    let renewal_child_root_domain = read_next(data, ref index);
    let liquidity_position_transition_root_domain = read_next(data, ref index);
    let output_note_root_domain = read_next(data, ref index);
    let fee_root_domain = read_next(data, ref index);
    let state_transition_root_domain = read_next(data, ref index);
    let nullifier_sparse_leaf_domain = read_next(data, ref index);
    let nullifier_sparse_node_domain = read_next(data, ref index);
    assert(note_commitment_domain == NOTE_COMMITMENT_DOMAIN, 'E');
    assert(spend_authority_domain == SPEND_AUTHORITY_DOMAIN, 'E');
    assert(nullifier_domain == NULLIFIER_DOMAIN, 'E');
    assert(order_commitment_domain == ORDER_COMMITMENT_DOMAIN, 'E');
    assert(liquidity_slice_domain == LIQUIDITY_SLICE_DOMAIN, 'E');
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
    assert(
        liquidity_position_transition_root_domain == LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN, 'E',
    );
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
    let matched_liquidity_slice_commitments = read_vector(data, ref index);
    let matched_liquidity_slice_point_counts = read_vector(data, ref index);
    let matched_liquidity_slice_prices = read_vector(data, ref index);
    let matched_liquidity_slice_base_amounts = read_vector(data, ref index);
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
    let liquidity_position_transition_kinds = read_vector(data, ref index);
    let liquidity_position_consumed_commitments = read_vector(data, ref index);
    let liquidity_position_nullifiers = read_vector(data, ref index);
    let liquidity_position_output_commitments = read_vector(data, ref index);
    let liquidity_position_prior_fields = read_vector(data, ref index);
    let liquidity_position_output_fields = read_vector(data, ref index);
    let liquidity_position_sides = read_vector(data, ref index);
    let liquidity_position_filled_base_amounts = read_vector(data, ref index);
    let liquidity_position_clearing_prices = read_vector(data, ref index);
    let liquidity_position_price_base_scales = read_vector(data, ref index);
    let liquidity_position_market_reference_prices = read_vector(data, ref index);
    let liquidity_position_market_confirmation_prices = read_vector(data, ref index);
    let liquidity_position_market_observed_at_unix_ms = read_vector(data, ref index);
    let liquidity_position_market_current_time_unix_ms = read_vector(data, ref index);
    let liquidity_position_oracle_guard_ids = read_vector(data, ref index);
    let liquidity_position_oracle_guard_max_staleness_ms = read_vector(data, ref index);
    let liquidity_position_oracle_guard_max_divergence_bps = read_vector(data, ref index);
    let liquidity_position_state_position_ids = read_vector(data, ref index);
    let liquidity_position_state_key_lows = read_vector(data, ref index);
    let liquidity_position_state_key_highs = read_vector(data, ref index);
    let liquidity_position_state_prior_commitments = read_vector(data, ref index);
    let liquidity_position_state_output_commitments = read_vector(data, ref index);
    let liquidity_position_state_path_counts = read_vector(data, ref index);
    let liquidity_position_state_path_values = read_vector(data, ref index);
    let liquidity_position_state_path_directions = read_vector(data, ref index);
    let liquidity_position_lifecycle_signature_rs = read_vector(data, ref index);
    let liquidity_position_lifecycle_signature_ss = read_vector(data, ref index);
    let liquidity_position_lifecycle_base_amounts = read_vector(data, ref index);
    let liquidity_position_lifecycle_quote_amounts = read_vector(data, ref index);
    let liquidity_position_open_input_counts = read_vector(data, ref index);
    let liquidity_position_open_input_note_commitments = read_vector(data, ref index);
    let liquidity_position_open_input_asset_ids = read_vector(data, ref index);
    let liquidity_position_open_input_amounts = read_vector(data, ref index);
    let liquidity_position_open_input_owner_keys = read_vector(data, ref index);
    let liquidity_position_open_input_spend_authorities = read_vector(data, ref index);
    let liquidity_position_open_input_withdraw_authorities = read_vector(data, ref index);
    let liquidity_position_open_input_blindings = read_vector(data, ref index);
    let liquidity_position_open_input_nonces = read_vector(data, ref index);
    let liquidity_position_open_input_metadata_commitments = read_vector(data, ref index);
    let liquidity_position_lifecycle_output_counts = read_vector(data, ref index);
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
    let liquidity_position_open_input_count = sum_bounded_counts(
        liquidity_position_open_input_counts.span(), MAX_ORDER_FUNDING_INPUTS, 'LP_OPEN_INPUT',
    );
    let total_consumed_input_count = funding_input_count + liquidity_position_open_input_count;
    let total_slice_points = sum_slice_point_counts(matched_liquidity_slice_point_counts.span());
    assert_settlement_bounds(
        matched_order_commitments.len(),
        total_consumed_input_count,
        output_note_commitments.len(),
        total_slice_points,
    );
    assert_all_lengths_match(
        matched_order_commitments.len(),
        array![
            matched_fill_amounts.len().into(), matched_sides.len().into(),
            matched_order_types.len().into(), matched_relay_modes.len().into(),
            matched_limit_prices.len().into(), matched_order_amounts.len().into(),
            matched_min_fills.len().into(), matched_liquidity_slice_commitments.len().into(),
            matched_liquidity_slice_point_counts.len().into(), matched_time_in_force.len().into(),
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
        'E',
    );
    assert_all_lengths_match(
        total_consumed_input_count,
        array![
            consumed_note_commitments.len().into(), consumed_nullifiers.len().into(),
            note_membership_kinds.len().into(), note_membership_prefix_roots.len().into(),
            note_membership_batch_roots.len().into(), note_membership_path_counts.len().into(),
            note_membership_suffix_counts.len().into(),
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
        liquidity_position_open_input_count,
        array![
            liquidity_position_open_input_note_commitments.len().into(),
            liquidity_position_open_input_asset_ids.len().into(),
            liquidity_position_open_input_amounts.len().into(),
            liquidity_position_open_input_owner_keys.len().into(),
            liquidity_position_open_input_spend_authorities.len().into(),
            liquidity_position_open_input_withdraw_authorities.len().into(),
            liquidity_position_open_input_blindings.len().into(),
            liquidity_position_open_input_nonces.len().into(),
            liquidity_position_open_input_metadata_commitments.len().into(),
        ]
            .span(),
        'LP_OPEN_INPUT',
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
    if matched_order_commitments.len() == 0 && liquidity_position_transition_kinds.len() == 0 {
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
    assert(matched_liquidity_slice_prices.len() == total_slice_points, 'E');
    assert(matched_liquidity_slice_base_amounts.len() == total_slice_points, 'E');

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
    assert(liquidity_position_transition_kinds.len() <= MAX_LIQUIDITY_POSITION_TRANSITIONS, 'E');
    assert_unique(output_note_commitments.span(), 'E');

    let clearing_price_u128 = felt_to_u128(clearing_price);
    let price_base_scale_u128 = felt_to_u128(price_base_scale);
    let taker_fee_bps_u128 = felt_to_u128(taker_fee_bps);
    let relay_fee_bps_u128 = felt_to_u128(relay_fee_bps);
    assert(taker_fee_bps_u128 <= FEE_BPS_DENOMINATOR, 'E');
    assert(relay_fee_bps_u128 <= FEE_BPS_DENOMINATOR, 'E');
    assert(protocol_fee_recipient != 0, 'E');
    assert(relay_fee_recipient != 0, 'E');
    let mut index_order = 0;
    let mut total_buy_base: u128 = 0;
    let mut total_sell_base: u128 = 0;
    let mut expected_base_fee: u128 = 0;
    let mut expected_quote_fee: u128 = 0;
    let mut expected_base_relay_fee: u128 = 0;
    let mut expected_quote_relay_fee: u128 = 0;
    let mut slice_cursor: usize = 0;
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
        let liquidity_slice_commitment = *matched_liquidity_slice_commitments.at(index_order);
        let liquidity_slice_point_count_felt = *matched_liquidity_slice_point_counts
            .at(index_order);
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
        let liquidity_slice_point_count: usize = liquidity_slice_point_count_felt
            .try_into()
            .expect('E');

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
        let (curve_total_amount, curve_capacity_at_price, curve_quote_funding_required) =
            assert_liquidity_slice(
            pair_id,
            order_type,
            side,
            liquidity_slice_domain,
            liquidity_slice_commitment,
            liquidity_slice_point_count,
            slice_cursor,
            clearing_price_u128,
            price_base_scale_u128,
            matched_liquidity_slice_prices.span(),
            matched_liquidity_slice_base_amounts.span(),
        );
        let _unused_curve_total_amount = curve_total_amount;
        let _unused_curve_capacity_at_price = curve_capacity_at_price;
        let _unused_curve_quote_funding_required = curve_quote_funding_required;
        slice_cursor += liquidity_slice_point_count;
        assert(time_in_force == TIF_CURRENT_BATCH_ONLY || time_in_force == TIF_FILL_OR_KILL, 'E');
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
            liquidity_slice_commitment,
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
        let order_relay_fee_bps = relay_fee_bps_for_order(
            relay_mode, order_type, parent_order_commitment, relay_fee_bps_u128,
        );
        assert(order_fee_bps + order_relay_fee_bps <= FEE_BPS_DENOMINATOR, 'E');
        let (expected_primary_amount, expected_residual_amount) = if side == ORDER_SIDE_BUY {
            assert(limit_price >= clearing_price_u128, 'E');
            assert(output_note_asset_id == base_asset_id, 'E');

            let spend_amount = quote_amount_for_base_amount(
                filled_amount, clearing_price_u128, price_base_scale_u128,
            );
            assert(funding_note_amount >= spend_amount, 'E');
            let fee_amount = ceil_fee_amount(filled_amount, order_fee_bps);
            let relay_fee_amount = ceil_fee_amount(filled_amount, order_relay_fee_bps);
            assert(fee_amount + relay_fee_amount <= filled_amount, 'E');
            total_buy_base = total_buy_base + filled_amount;
            expected_base_fee = expected_base_fee + fee_amount;
            expected_base_relay_fee = expected_base_relay_fee + relay_fee_amount;
            (filled_amount - fee_amount - relay_fee_amount, funding_note_amount - spend_amount)
        } else {
            assert(side == ORDER_SIDE_SELL, 'E');
            assert(limit_price <= clearing_price_u128, 'E');
            assert(output_note_asset_id == quote_asset_id, 'E');
            assert(funding_note_amount >= filled_amount, 'E');

            let gross_quote = quote_amount_for_base_amount(
                filled_amount, clearing_price_u128, price_base_scale_u128,
            );
            let fee_amount = ceil_fee_amount(gross_quote, order_fee_bps);
            let relay_fee_amount = ceil_fee_amount(gross_quote, order_relay_fee_bps);
            assert(fee_amount + relay_fee_amount <= gross_quote, 'E');
            total_sell_base = total_sell_base + filled_amount;
            expected_quote_fee = expected_quote_fee + fee_amount;
            expected_quote_relay_fee = expected_quote_relay_fee + relay_fee_amount;
            (gross_quote - fee_amount - relay_fee_amount, funding_note_amount - filled_amount)
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

    let (
        computed_liquidity_position_transition_root,
        computed_new_liquidity_position_root,
        liquidity_position_buy_base,
        liquidity_position_sell_base,
    ) =
        assert_liquidity_position_fill_transition_witnesses(
        prior_liquidity_position_root,
        liquidity_position_transition_root_domain,
        state_transition_root_domain,
        pair_id,
        batch_epoch,
        base_asset_id,
        quote_asset_id,
        clearing_price,
        price_base_scale,
        liquidity_position_transition_kinds.span(),
        liquidity_position_consumed_commitments.span(),
        liquidity_position_nullifiers.span(),
        liquidity_position_output_commitments.span(),
        liquidity_position_prior_fields.span(),
        liquidity_position_output_fields.span(),
        liquidity_position_sides.span(),
        liquidity_position_filled_base_amounts.span(),
        liquidity_position_clearing_prices.span(),
        liquidity_position_price_base_scales.span(),
        liquidity_position_market_reference_prices.span(),
        liquidity_position_market_confirmation_prices.span(),
        liquidity_position_market_observed_at_unix_ms.span(),
        liquidity_position_market_current_time_unix_ms.span(),
        liquidity_position_oracle_guard_ids.span(),
        liquidity_position_oracle_guard_max_staleness_ms.span(),
        liquidity_position_oracle_guard_max_divergence_bps.span(),
        liquidity_position_state_position_ids.span(),
        liquidity_position_state_key_lows.span(),
        liquidity_position_state_key_highs.span(),
        liquidity_position_state_prior_commitments.span(),
        liquidity_position_state_output_commitments.span(),
        liquidity_position_state_path_counts.span(),
        liquidity_position_state_path_values.span(),
        liquidity_position_state_path_directions.span(),
        liquidity_position_lifecycle_signature_rs.span(),
        liquidity_position_lifecycle_signature_ss.span(),
        liquidity_position_lifecycle_base_amounts.span(),
        liquidity_position_lifecycle_quote_amounts.span(),
        liquidity_position_open_input_counts.span(),
        liquidity_position_open_input_note_commitments.span(),
        liquidity_position_open_input_asset_ids.span(),
        liquidity_position_open_input_amounts.span(),
        liquidity_position_open_input_owner_keys.span(),
        liquidity_position_open_input_spend_authorities.span(),
        liquidity_position_open_input_withdraw_authorities.span(),
        liquidity_position_open_input_blindings.span(),
        liquidity_position_open_input_nonces.span(),
        liquidity_position_open_input_metadata_commitments.span(),
        liquidity_position_lifecycle_output_counts.span(),
        note_commitment_domain,
        nullifier_domain,
        prior_note_root,
        consumed_note_commitments.span(),
        consumed_nullifiers.span(),
        note_membership_kinds.span(),
        note_membership_prefix_roots.span(),
        note_membership_batch_roots.span(),
        note_membership_path_counts.span(),
        note_membership_path_values.span(),
        note_membership_path_directions.span(),
        note_membership_suffix_counts.span(),
        note_membership_suffix_roots.span(),
        ref funding_input_cursor,
        ref note_membership_path_cursor,
        ref note_membership_suffix_cursor,
        output_note_commitments.span(),
        output_note_asset_ids.span(),
        output_note_amounts.span(),
        output_note_withdraw_authorities.span(),
        output_note_owner_keys.span(),
        output_note_spend_authorities.span(),
        output_note_blindings.span(),
        output_note_nonces.span(),
        output_note_metadata_commitments.span(),
        ref public_output_cursor,
    );
    assert(
        computed_liquidity_position_transition_root == claimed_liquidity_position_transition_root,
        'LP_TRANSITION',
    );
    total_buy_base = total_buy_base + liquidity_position_buy_base;
    total_sell_base = total_sell_base + liquidity_position_sell_base;
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
    assert_fee_output(
        ref public_output_cursor,
        note_commitment_domain,
        base_asset_id,
        expected_base_relay_fee,
        relay_fee_recipient,
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
        expected_quote_relay_fee,
        relay_fee_recipient,
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
        relay_fee_recipient,
        expected_base_fee,
        expected_quote_fee,
        expected_base_relay_fee,
        expected_quote_relay_fee,
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
    let new_liquidity_position_root = read_next(data, ref index);
    assert_liquidity_position_root_transition(
        state_transition_root_domain,
        prior_liquidity_position_root,
        computed_liquidity_position_transition_root,
        new_liquidity_position_root,
        liquidity_position_transition_kinds.len(),
    );
    assert(new_liquidity_position_root == computed_new_liquidity_position_root, 'LP_ROOT');
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
    assert(recomputed_public_settlement == transcript_commitment, 'E');

    assert(slice_cursor == total_slice_points, 'E');
    assert(index == data.len(), 'E');

    transcript_commitment
}

pub fn verify_settlement_note_fee_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_SETTLEMENT, 'E');

    let note_commitment_domain = read_next(data, ref index);
    skip_fields(data, ref index, 1);
    let nullifier_domain = read_next(data, ref index);
    skip_fields(data, ref index, 2);
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
    let relay_fee_bps = read_next(data, ref index);
    let protocol_fee_recipient = read_next(data, ref index);
    let relay_fee_recipient = read_next(data, ref index);
    let matched_order_count = read_next(data, ref index);
    let output_bundle_ref = read_next(data, ref index);
    let prior_note_root = read_next(data, ref index);
    let prior_nullifier_root = read_next(data, ref index);
    let prior_renewal_root = read_next(data, ref index);
    let prior_fee_root = read_next(data, ref index);
    let prior_liquidity_position_root = read_next(data, ref index);
    let claimed_liquidity_position_transition_root = read_next(data, ref index);
    let consumed_note_root_domain = read_next(data, ref index);
    let consumed_nullifier_root_domain = read_next(data, ref index);
    let renewal_child_root_domain = read_next(data, ref index);
    let liquidity_position_transition_root_domain = read_next(data, ref index);
    let output_note_root_domain = read_next(data, ref index);
    let fee_root_domain = read_next(data, ref index);
    let state_transition_root_domain = read_next(data, ref index);
    let nullifier_sparse_leaf_domain = read_next(data, ref index);
    let nullifier_sparse_node_domain = read_next(data, ref index);
    assert(note_commitment_domain == NOTE_COMMITMENT_DOMAIN, 'E');
    assert(nullifier_domain == NULLIFIER_DOMAIN, 'E');
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
    assert(
        liquidity_position_transition_root_domain == LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN, 'E',
    );
    assert(output_note_root_domain == OUTPUT_NOTE_ROOT_DOMAIN, 'E');
    assert(fee_root_domain == FEE_ROOT_DOMAIN, 'E');
    assert(state_transition_root_domain == STATE_TRANSITION_ROOT_DOMAIN, 'E');
    assert(nullifier_sparse_leaf_domain == NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL, 'E');
    assert(nullifier_sparse_node_domain == NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL, 'E');
    assert(base_asset_id != quote_asset_id, 'E');

    let matched_order_commitments = read_vector(data, ref index);
    let matched_fill_amounts = read_vector(data, ref index);
    let matched_sides = read_vector(data, ref index);
    let matched_order_types = read_vector(data, ref index);
    let matched_relay_modes = read_vector(data, ref index);
    skip_vectors(data, ref index, 10);
    let matched_parent_order_commitments = read_vector(data, ref index);
    skip_vectors(data, ref index, 5);
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
    skip_vectors(data, ref index, 2);
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
    skip_vectors(data, ref index, 14);
    let renewal_child_nullifiers = read_vector(data, ref index);
    skip_vectors(data, ref index, 10);
    let liquidity_position_transition_kinds = read_vector(data, ref index);
    skip_vectors(data, ref index, 28);
    let liquidity_position_open_input_counts = read_vector(data, ref index);
    skip_vectors(data, ref index, 9);
    let liquidity_position_lifecycle_output_counts = read_vector(data, ref index);
    let output_note_commitments = read_vector(data, ref index);
    let output_note_asset_ids = read_vector(data, ref index);
    let output_note_amounts = read_vector(data, ref index);
    let output_note_withdraw_authorities = read_vector(data, ref index);
    let output_note_owner_keys = read_vector(data, ref index);
    let output_note_spend_authorities = read_vector(data, ref index);
    let output_note_blindings = read_vector(data, ref index);
    let output_note_nonces = read_vector(data, ref index);
    let output_note_metadata_commitments = read_vector(data, ref index);
    skip_vectors(data, ref index, 4);

    let matched_len: felt252 = matched_order_commitments.len().into();
    assert(matched_len == matched_order_count, 'E');
    let funding_input_count = sum_funding_input_counts(matched_funding_input_counts.span());
    let liquidity_position_open_input_count = sum_bounded_counts(
        liquidity_position_open_input_counts.span(), MAX_ORDER_FUNDING_INPUTS, 'LP_OPEN_INPUT',
    );
    let total_consumed_input_count = funding_input_count + liquidity_position_open_input_count;
    assert_settlement_bounds(
        matched_order_commitments.len(),
        total_consumed_input_count,
        output_note_commitments.len(),
        0,
    );
    assert_all_lengths_match(
        matched_order_commitments.len(),
        array![
            matched_fill_amounts.len().into(), matched_sides.len().into(),
            matched_order_types.len().into(), matched_relay_modes.len().into(),
            matched_parent_order_commitments.len().into(), matched_funding_note_refs.len().into(),
            matched_funding_input_counts.len().into(), matched_funding_note_amounts.len().into(),
            matched_funding_note_owner_keys.len().into(), matched_funding_nullifiers.len().into(),
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
        total_consumed_input_count,
        array![consumed_note_commitments.len().into(), consumed_nullifiers.len().into()].span(),
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
    assert(output_note_commitments.len() == output_note_asset_ids.len(), 'E');
    assert(output_note_commitments.len() == output_note_amounts.len(), 'E');
    assert(output_note_commitments.len() == output_note_withdraw_authorities.len(), 'E');
    assert(output_note_commitments.len() == output_note_owner_keys.len(), 'E');
    assert(output_note_commitments.len() == output_note_spend_authorities.len(), 'E');
    assert(output_note_commitments.len() == output_note_blindings.len(), 'E');
    assert(output_note_commitments.len() == output_note_nonces.len(), 'E');
    assert(output_note_commitments.len() == output_note_metadata_commitments.len(), 'E');
    if matched_order_commitments.len() == 0 && liquidity_position_transition_kinds.len() == 0 {
        assert(consumed_note_commitments.len() == 0, 'E');
        assert(consumed_nullifiers.len() == 0, 'E');
        assert(renewal_child_nullifiers.len() == 0, 'E');
        assert(output_note_commitments.len() == 0, 'E');
        assert(output_note_owner_keys.len() == 0, 'E');
    }
    assert_unique(matched_order_commitments.span(), 'E');
    assert_unique(consumed_note_commitments.span(), 'E');
    assert_unique(consumed_nullifiers.span(), 'E');
    assert_unique(renewal_child_nullifiers.span(), 'E');
    assert(liquidity_position_transition_kinds.len() <= MAX_LIQUIDITY_POSITION_TRANSITIONS, 'E');
    assert_unique(output_note_commitments.span(), 'E');

    let clearing_price_u128 = felt_to_u128(clearing_price);
    let price_base_scale_u128 = felt_to_u128(price_base_scale);
    let taker_fee_bps_u128 = felt_to_u128(taker_fee_bps);
    let relay_fee_bps_u128 = felt_to_u128(relay_fee_bps);
    assert(taker_fee_bps_u128 <= FEE_BPS_DENOMINATOR, 'E');
    assert(relay_fee_bps_u128 <= FEE_BPS_DENOMINATOR, 'E');
    assert(protocol_fee_recipient != 0, 'E');
    assert(relay_fee_recipient != 0, 'E');
    let mut index_order = 0;
    let mut total_buy_base: u128 = 0;
    let mut total_sell_base: u128 = 0;
    let mut expected_base_fee: u128 = 0;
    let mut expected_quote_fee: u128 = 0;
    let mut expected_base_relay_fee: u128 = 0;
    let mut expected_quote_relay_fee: u128 = 0;
    let mut funding_input_cursor = 0;
    let mut public_output_cursor = 0;

    while index_order < matched_order_commitments.len() {
        let order_commitment = *matched_order_commitments.at(index_order);
        let filled_amount_felt = *matched_fill_amounts.at(index_order);
        let side = *matched_sides.at(index_order);
        let order_type = *matched_order_types.at(index_order);
        let relay_mode = *matched_relay_modes.at(index_order);
        let parent_order_commitment = *matched_parent_order_commitments.at(index_order);
        let funding_note_ref = *matched_funding_note_refs.at(index_order);
        let funding_input_count_felt = *matched_funding_input_counts.at(index_order);
        let funding_note_amount_felt = *matched_funding_note_amounts.at(index_order);
        let funding_note_owner_key = *matched_funding_note_owner_keys.at(index_order);
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
        let funding_note_amount = felt_to_u128(funding_note_amount_felt);
        let output_note_amount = felt_to_u128(output_note_amount_felt);

        assert(order_commitment != 0, 'E');
        assert(filled_amount_felt != 0, 'E');
        assert(funding_note_ref != 0, 'E');
        assert(output_note_commitment != 0, 'E');
        assert(funding_note_owner_key != 0, 'E');
        assert(funding_note_amount_felt != 0, 'E');
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
        assert_relay_mode(relay_mode, order_type, parent_order_commitment);
        assert(order_type == ORDER_TYPE_LIMIT_BATCH, 'E');
        assert(residual_note_flag == 0 || residual_note_flag == 1, 'E');

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
        let order_relay_fee_bps = relay_fee_bps_for_order(
            relay_mode, order_type, parent_order_commitment, relay_fee_bps_u128,
        );
        assert(order_fee_bps + order_relay_fee_bps <= FEE_BPS_DENOMINATOR, 'E');
        let (expected_primary_amount, expected_residual_amount) = if side == ORDER_SIDE_BUY {
            assert(output_note_asset_id == base_asset_id, 'E');

            let spend_amount = quote_amount_for_base_amount(
                filled_amount, clearing_price_u128, price_base_scale_u128,
            );
            assert(funding_note_amount >= spend_amount, 'E');
            let fee_amount = ceil_fee_amount(filled_amount, order_fee_bps);
            let relay_fee_amount = ceil_fee_amount(filled_amount, order_relay_fee_bps);
            assert(fee_amount + relay_fee_amount <= filled_amount, 'E');
            total_buy_base = total_buy_base + filled_amount;
            expected_base_fee = expected_base_fee + fee_amount;
            expected_base_relay_fee = expected_base_relay_fee + relay_fee_amount;
            (filled_amount - fee_amount - relay_fee_amount, funding_note_amount - spend_amount)
        } else {
            assert(side == ORDER_SIDE_SELL, 'E');
            assert(output_note_asset_id == quote_asset_id, 'E');
            assert(funding_note_amount >= filled_amount, 'E');

            let gross_quote = quote_amount_for_base_amount(
                filled_amount, clearing_price_u128, price_base_scale_u128,
            );
            let fee_amount = ceil_fee_amount(gross_quote, order_fee_bps);
            let relay_fee_amount = ceil_fee_amount(gross_quote, order_relay_fee_bps);
            assert(fee_amount + relay_fee_amount <= gross_quote, 'E');
            total_sell_base = total_sell_base + filled_amount;
            expected_quote_fee = expected_quote_fee + fee_amount;
            expected_quote_relay_fee = expected_quote_relay_fee + relay_fee_amount;
            (gross_quote - fee_amount - relay_fee_amount, funding_note_amount - filled_amount)
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

    let (liquidity_position_buy_base, liquidity_position_sell_base) =
        settlement_liquidity_position_fill_totals(
        data,
    );
    let computed_liquidity_position_transition_root = claimed_liquidity_position_transition_root;
    let liquidity_position_lifecycle_output_count = sum_bounded_counts(
        liquidity_position_lifecycle_output_counts.span(), MAX_ORDER_FUNDING_INPUTS, 'LP_OUTPUT',
    );
    assert(
        public_output_cursor
            + liquidity_position_lifecycle_output_count <= output_note_commitments.len(),
        'LP_OUTPUT',
    );
    public_output_cursor += liquidity_position_lifecycle_output_count;

    total_buy_base = total_buy_base + liquidity_position_buy_base;
    total_sell_base = total_sell_base + liquidity_position_sell_base;
    assert(total_buy_base == total_sell_base, 'E');
    assert(funding_input_cursor <= consumed_note_commitments.len(), 'E');
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
    assert_fee_output(
        ref public_output_cursor,
        note_commitment_domain,
        base_asset_id,
        expected_base_relay_fee,
        relay_fee_recipient,
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
        expected_quote_relay_fee,
        relay_fee_recipient,
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
    let fee_root = protocol_fee_root(
        fee_root_domain,
        base_asset_id,
        quote_asset_id,
        protocol_fee_recipient,
        relay_fee_recipient,
        expected_base_fee,
        expected_quote_fee,
        expected_base_relay_fee,
        expected_quote_relay_fee,
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
    let new_liquidity_position_root = read_next(data, ref index);
    assert_liquidity_position_root_transition(
        state_transition_root_domain,
        prior_liquidity_position_root,
        computed_liquidity_position_transition_root,
        new_liquidity_position_root,
        liquidity_position_transition_kinds.len(),
    );
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
    assert(recomputed_public_settlement == transcript_commitment, 'E');

    assert(index == data.len(), 'E');

    transcript_commitment
}

pub fn verify_settlement_order_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_SETTLEMENT, 'E');

    let note_commitment_domain = read_next(data, ref index);
    let spend_authority_domain = read_next(data, ref index);
    let nullifier_domain = read_next(data, ref index);
    let order_commitment_domain = read_next(data, ref index);
    let liquidity_slice_domain = read_next(data, ref index);
    skip_fields(data, ref index, 1);
    let batch_id = read_next(data, ref index);
    let pair_id = read_next(data, ref index);
    let batch_epoch = read_next(data, ref index);
    skip_fields(data, ref index, 2);
    let transcript_commitment = read_next(data, ref index);
    let base_asset_id = read_next(data, ref index);
    let quote_asset_id = read_next(data, ref index);
    let clearing_price = read_next(data, ref index);
    let price_base_scale = read_next(data, ref index);
    skip_fields(data, ref index, 4);
    let matched_order_count = read_next(data, ref index);
    skip_fields(data, ref index, 16);

    assert(note_commitment_domain == NOTE_COMMITMENT_DOMAIN, 'E');
    assert(spend_authority_domain == SPEND_AUTHORITY_DOMAIN, 'E');
    assert(nullifier_domain == NULLIFIER_DOMAIN, 'E');
    assert(order_commitment_domain == ORDER_COMMITMENT_DOMAIN, 'E');
    assert(liquidity_slice_domain == LIQUIDITY_SLICE_DOMAIN, 'E');
    assert(batch_id != 0, 'E');
    assert(pair_id != 0, 'E');
    assert(batch_epoch != 0, 'E');
    assert(transcript_commitment != 0, 'E');
    assert(base_asset_id != 0, 'E');
    assert(quote_asset_id != 0, 'E');
    assert(base_asset_id != quote_asset_id, 'E');
    if matched_order_count != 0 {
        assert(clearing_price != 0, 'E');
    }
    assert(price_base_scale != 0, 'E');
    assert_pair_config(pair_id, base_asset_id, quote_asset_id, price_base_scale);

    let matched_order_commitments = read_vector(data, ref index);
    let matched_fill_amounts = read_vector(data, ref index);
    let matched_sides = read_vector(data, ref index);
    let matched_order_types = read_vector(data, ref index);
    let matched_relay_modes = read_vector(data, ref index);
    let matched_liquidity_slice_commitments = read_vector(data, ref index);
    let matched_liquidity_slice_point_counts = read_vector(data, ref index);
    let matched_liquidity_slice_prices = read_vector(data, ref index);
    let matched_liquidity_slice_base_amounts = read_vector(data, ref index);
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
    skip_vectors(data, ref index, 19);
    skip_vectors(data, ref index, 15);
    let renewal_parent_order_commitments = read_vector(data, ref index);
    let renewal_child_nullifiers = read_vector(data, ref index);
    skip_vectors(data, ref index, 10);
    skip_vectors(data, ref index, 53);
    skip_fields(data, ref index, 3);
    assert(index == data.len(), 'E');

    let matched_len: felt252 = matched_order_commitments.len().into();
    assert(matched_len == matched_order_count, 'E');
    let funding_input_count = sum_funding_input_counts(matched_funding_input_counts.span());
    let total_slice_points = sum_slice_point_counts(matched_liquidity_slice_point_counts.span());
    assert_admission_bounds(
        matched_order_commitments.len(), funding_input_count, total_slice_points,
    );
    assert(matched_liquidity_slice_prices.len() == total_slice_points, 'E');
    assert(matched_liquidity_slice_base_amounts.len() == total_slice_points, 'E');
    assert_all_lengths_match(
        matched_order_commitments.len(),
        array![
            matched_fill_amounts.len().into(), matched_sides.len().into(),
            matched_order_types.len().into(), matched_relay_modes.len().into(),
            matched_liquidity_slice_commitments.len().into(),
            matched_liquidity_slice_point_counts.len().into(), matched_limit_prices.len().into(),
            matched_order_amounts.len().into(), matched_min_fills.len().into(),
            matched_time_in_force.len().into(), matched_expiry_epochs.len().into(),
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
            matched_res_withdraw_auths.len().into(),
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
    assert_unique(matched_order_commitments.span(), 'E');

    assert_auction_order_preimages(
        clearing_price.try_into().expect('E'),
        price_base_scale.try_into().expect('E'),
        matched_order_commitments.span(),
        matched_sides.span(),
        matched_order_types.span(),
        matched_relay_modes.span(),
        matched_liquidity_slice_commitments.span(),
        matched_liquidity_slice_point_counts.span(),
        matched_liquidity_slice_prices.span(),
        matched_liquidity_slice_base_amounts.span(),
        matched_limit_prices.span(),
        matched_order_amounts.span(),
        matched_min_fills.span(),
        matched_time_in_force.span(),
        matched_expiry_epochs.span(),
        matched_order_nonces.span(),
        matched_parent_order_commitments.span(),
        matched_parent_child_indexes.span(),
        matched_parent_secret_commitments.span(),
        matched_parent_cancel_authorities.span(),
        matched_parent_authorization_secrets.span(),
        matched_auditor_flags.span(),
        matched_funding_note_refs.span(),
        matched_funding_input_counts.span(),
        matched_funding_note_commitments.span(),
        matched_funding_note_asset_ids.span(),
        matched_funding_input_amounts.span(),
        matched_funding_input_owner_keys.span(),
        matched_funding_note_spend_authorities.span(),
        matched_funding_note_withdraw_authorities.span(),
        matched_funding_note_blindings.span(),
        matched_funding_note_nonces.span(),
        matched_funding_note_metadata_commitments.span(),
        matched_funding_note_amounts.span(),
        matched_funding_note_owner_keys.span(),
        matched_funding_authorization_rs.span(),
        matched_funding_authorization_ss.span(),
        matched_funding_nullifiers.span(),
        matched_recipient_owner_keys.span(),
        matched_recipient_spend_authorities.span(),
        matched_recipient_withdraw_authorities.span(),
        matched_res_withdraw_auths.span(),
        note_commitment_domain,
        spend_authority_domain,
        nullifier_domain,
        order_commitment_domain,
        liquidity_slice_domain,
        batch_id,
        pair_id,
        batch_epoch,
        base_asset_id,
        quote_asset_id,
    );

    let clearing_price_u128 = felt_to_u128(clearing_price);
    let price_base_scale_u128 = felt_to_u128(price_base_scale);
    let mut order_index = 0;
    let mut slice_cursor: usize = 0;
    let mut renewal_cursor = 0;
    while order_index < matched_order_commitments.len() {
        let side = *matched_sides.at(order_index);
        let order_type = *matched_order_types.at(order_index);
        assert(order_type == ORDER_TYPE_LIMIT_BATCH, 'E');
        let point_count: usize = (*matched_liquidity_slice_point_counts.at(order_index))
            .try_into()
            .expect('E');
        let filled_amount = felt_to_u128(*matched_fill_amounts.at(order_index));
        let order_amount = felt_to_u128(*matched_order_amounts.at(order_index));
        let min_fill = felt_to_u128(*matched_min_fills.at(order_index));
        let limit_price = felt_to_u128(*matched_limit_prices.at(order_index));
        assert(filled_amount != 0, 'E');
        assert(filled_amount <= order_amount, 'E');
        assert(filled_amount >= min_fill, 'E');
        if *matched_time_in_force.at(order_index) == TIF_FILL_OR_KILL {
            assert(filled_amount == order_amount, 'E');
        }
        if side == ORDER_SIDE_BUY {
            assert(limit_price >= clearing_price_u128, 'E');
        } else {
            assert(side == ORDER_SIDE_SELL, 'E');
            assert(limit_price <= clearing_price_u128, 'E');
        }
        let (_curve_total_amount, curve_capacity_at_price, _quote_funding_required) =
            assert_liquidity_slice(
            pair_id,
            order_type,
            side,
            liquidity_slice_domain,
            *matched_liquidity_slice_commitments.at(order_index),
            point_count,
            slice_cursor,
            clearing_price_u128,
            price_base_scale_u128,
            matched_liquidity_slice_prices.span(),
            matched_liquidity_slice_base_amounts.span(),
        );
        let _unused_curve_capacity_at_price = curve_capacity_at_price;
        let parent_order_commitment = *matched_parent_order_commitments.at(order_index);
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
                        parent_order_commitment,
                        *matched_parent_child_indexes.at(order_index),
                        *matched_parent_authorization_secrets.at(order_index),
                    ),
                'E',
            );
            renewal_cursor += 1;
        }
        slice_cursor += point_count;
        order_index += 1;
    }
    assert(slice_cursor == total_slice_points, 'E');
    assert(renewal_cursor == renewal_child_nullifiers.len(), 'E');

    transcript_commitment
}

pub fn verify_settlement_output_recovery_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_SETTLEMENT, 'E');

    let note_commitment_domain = read_next(data, ref index);
    skip_fields(data, ref index, 4);
    let public_settlement_domain = read_next(data, ref index);
    let batch_id = read_next(data, ref index);
    skip_fields(data, ref index, 4);
    let transcript_commitment = read_next(data, ref index);
    skip_fields(data, ref index, 9);
    let output_bundle_ref = read_next(data, ref index);
    skip_fields(data, ref index, 10);
    let output_note_root_domain = read_next(data, ref index);
    skip_fields(data, ref index, 4);

    assert(note_commitment_domain == NOTE_COMMITMENT_DOMAIN, 'E');
    assert(public_settlement_domain == PUBLIC_SETTLEMENT_DOMAIN, 'E');
    assert(batch_id != 0, 'E');
    assert(transcript_commitment != 0, 'E');
    assert(output_bundle_ref != 0, 'E');
    assert(output_note_root_domain == OUTPUT_NOTE_ROOT_DOMAIN, 'E');

    skip_vectors(data, ref index, 127);
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
    skip_fields(data, ref index, 3);
    assert(index == data.len(), 'E');

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

    transcript_commitment
}

pub fn verify_settlement_input_membership_statement(data: Span<felt252>) -> felt252 {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_SETTLEMENT, 'E');

    let note_commitment_domain = read_next(data, ref index);
    skip_fields(data, ref index, 1);
    let nullifier_domain = read_next(data, ref index);
    skip_fields(data, ref index, 8);
    let transcript_commitment = read_next(data, ref index);
    let base_asset_id = read_next(data, ref index);
    let quote_asset_id = read_next(data, ref index);
    skip_fields(data, ref index, 6);
    let matched_order_count = read_next(data, ref index);
    skip_fields(data, ref index, 1);
    let prior_note_root = read_next(data, ref index);
    skip_fields(data, ref index, 11);
    let state_transition_root_domain = read_next(data, ref index);
    skip_fields(data, ref index, 2);

    assert(note_commitment_domain == NOTE_COMMITMENT_DOMAIN, 'E');
    assert(nullifier_domain == NULLIFIER_DOMAIN, 'E');
    assert(transcript_commitment != 0, 'E');
    assert(base_asset_id != 0, 'E');
    assert(quote_asset_id != 0, 'E');
    assert(base_asset_id != quote_asset_id, 'E');
    assert(state_transition_root_domain == STATE_TRANSITION_ROOT_DOMAIN, 'E');

    let matched_order_commitments = read_vector(data, ref index);
    skip_vectors(data, ref index, 1);
    let matched_sides = read_vector(data, ref index);
    skip_vectors(data, ref index, 19);
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
    skip_vectors(data, ref index, 26);
    let consumed_note_commitments = read_vector(data, ref index);
    let consumed_nullifiers = read_vector(data, ref index);
    skip_vectors(data, ref index, 5);
    let note_membership_kinds = read_vector(data, ref index);
    let note_membership_prefix_roots = read_vector(data, ref index);
    let note_membership_batch_roots = read_vector(data, ref index);
    let note_membership_path_counts = read_vector(data, ref index);
    let note_membership_path_values = read_vector(data, ref index);
    let note_membership_path_directions = read_vector(data, ref index);
    let note_membership_suffix_counts = read_vector(data, ref index);
    let note_membership_suffix_roots = read_vector(data, ref index);
    skip_vectors(data, ref index, 65);
    skip_fields(data, ref index, 3);
    assert(index == data.len(), 'E');

    let matched_len: felt252 = matched_order_commitments.len().into();
    assert(matched_len == matched_order_count, 'E');
    assert_all_lengths_match(
        matched_order_commitments.len(),
        array![
            matched_sides.len().into(), matched_funding_input_counts.len().into(),
            matched_funding_note_amounts.len().into(), matched_funding_note_owner_keys.len().into(),
        ]
            .span(),
        'E',
    );
    let funding_input_count = sum_funding_input_counts(matched_funding_input_counts.span());
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
    assert(funding_input_count <= consumed_note_commitments.len(), 'E');
    assert_all_lengths_match(
        consumed_note_commitments.len(),
        array![
            consumed_nullifiers.len().into(), note_membership_kinds.len().into(),
            note_membership_prefix_roots.len().into(), note_membership_batch_roots.len().into(),
            note_membership_path_counts.len().into(), note_membership_suffix_counts.len().into(),
        ]
            .span(),
        'E',
    );
    assert(note_membership_path_values.len() == note_membership_path_directions.len(), 'E');

    let mut order_index = 0;
    let mut funding_input_cursor = 0;
    let mut note_membership_path_cursor = 0;
    let mut note_membership_suffix_cursor = 0;
    while order_index < matched_order_commitments.len() {
        let side = *matched_sides.at(order_index);
        let funding_note_amount = felt_to_u128(*matched_funding_note_amounts.at(order_index));
        let funding_note_owner_key = *matched_funding_note_owner_keys.at(order_index);
        let funding_input_count_for_order: usize = (*matched_funding_input_counts.at(order_index))
            .try_into()
            .expect('E');
        assert(funding_input_count_for_order != 0, 'E');
        assert(funding_input_count_for_order <= MAX_ORDER_FUNDING_INPUTS, 'E');
        assert(funding_input_cursor + funding_input_count_for_order <= funding_input_count, 'E');
        let first_spend_authority = *matched_funding_note_spend_authorities
            .at(funding_input_cursor);
        assert(first_spend_authority != 0, 'E');
        let mut funding_index = 0;
        let mut recomputed_funding_amount: u128 = 0;
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
            let funding_note_nonce = *matched_funding_note_nonces.at(flat_index);
            let funding_note_metadata_commitment = *matched_funding_note_metadata_commitments
                .at(flat_index);

            assert(funding_note_commitment != 0, 'E');
            assert(funding_input_amount_felt != 0, 'E');
            assert(funding_input_owner_key == funding_note_owner_key, 'E');
            assert(funding_note_spend_authority == first_spend_authority, 'E');
            assert(funding_note_withdraw_authority != 0, 'E');
            assert(funding_note_blinding != 0, 'E');
            assert(funding_note_nonce != 0, 'E');
            assert(funding_note_metadata_commitment != 0, 'E');
            if side == ORDER_SIDE_BUY {
                assert(funding_note_asset_id == quote_asset_id, 'E');
            } else {
                assert(side == ORDER_SIDE_SELL, 'E');
                assert(funding_note_asset_id == base_asset_id, 'E');
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
                    funding_note_nonce,
                    funding_note_metadata_commitment,
                ) == funding_note_commitment,
                'E',
            );
            assert(funding_note_commitment == *consumed_note_commitments.at(flat_index), 'E');
            assert(
                note_nullifier(
                    nullifier_domain, funding_note_commitment, funding_note_blinding,
                ) == *consumed_nullifiers
                    .at(flat_index),
                'E',
            );
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
            recomputed_funding_amount += felt_to_u128(funding_input_amount_felt);
            funding_index += 1;
        }
        assert(recomputed_funding_amount == funding_note_amount, 'E');
        funding_input_cursor += funding_input_count_for_order;
        order_index += 1;
    }
    assert(funding_input_cursor == funding_input_count, 'E');
    assert(
        note_membership_path_cursor == prefix_count_sum(
            note_membership_path_counts.span(), funding_input_count, 'NOTE_PATH',
        ),
        'NOTE_PATH',
    );
    assert(
        note_membership_suffix_cursor == prefix_count_sum(
            note_membership_suffix_counts.span(), funding_input_count, 'NOTE_SUFFIX',
        ),
        'NOTE_SUFFIX',
    );

    transcript_commitment
}

pub fn verify_nullifier_statement(data: Span<felt252>) -> (felt252, felt252, felt252, felt252) {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    assert(statement_type == STATEMENT_TYPE_SETTLEMENT, 'E');
    skip_fields(data, ref index, 11);
    let transcript_commitment = read_next(data, ref index);
    skip_fields(data, ref index, 11);
    let prior_nullifier_root = read_next(data, ref index);
    skip_fields(data, ref index, 5);
    let consumed_nullifier_root_domain = read_next(data, ref index);
    skip_fields(data, ref index, 5);
    let nullifier_sparse_leaf_domain = read_next(data, ref index);
    let nullifier_sparse_node_domain = read_next(data, ref index);

    assert(transcript_commitment != 0, 'E');
    assert(consumed_nullifier_root_domain == CONSUMED_NULLIFIER_ROOT_DOMAIN, 'E');
    assert(nullifier_sparse_leaf_domain == NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL, 'E');
    assert(nullifier_sparse_node_domain == NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL, 'E');

    skip_vectors(data, ref index, 60);
    let consumed_note_commitments = read_vector(data, ref index);
    let consumed_nullifiers = read_vector(data, ref index);
    let nullifier_sparse_key_lows = read_vector(data, ref index);
    let nullifier_sparse_key_highs = read_vector(data, ref index);
    let nullifier_sparse_path_counts = read_vector(data, ref index);
    let nullifier_sparse_path_values = read_vector(data, ref index);
    let nullifier_sparse_path_directions = read_vector(data, ref index);
    skip_vectors(data, ref index, 73);
    let claimed_new_nullifier_root = read_next(data, ref index);
    read_next(data, ref index);
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
    skip_fields(data, ref index, 11);
    let transcript_commitment = read_next(data, ref index);
    skip_fields(data, ref index, 12);
    let prior_renewal_root = read_next(data, ref index);
    skip_fields(data, ref index, 5);
    let renewal_child_root_domain = read_next(data, ref index);
    skip_fields(data, ref index, 4);
    let nullifier_sparse_leaf_domain = read_next(data, ref index);
    let nullifier_sparse_node_domain = read_next(data, ref index);

    assert(transcript_commitment != 0, 'E');
    assert(renewal_child_root_domain == RENEWAL_CHILD_ROOT_DOMAIN, 'E');
    assert(nullifier_sparse_leaf_domain == NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL, 'E');
    assert(nullifier_sparse_node_domain == NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL, 'E');

    let matched_order_commitments = read_vector(data, ref index);
    skip_vectors(data, ref index, 14);
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
    skip_vectors(data, ref index, 53);
    read_next(data, ref index);
    let claimed_new_renewal_root = read_next(data, ref index);
    read_next(data, ref index);
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

fn verify_compact_liquidity_position_statement(
    data: Span<felt252>, ref index: usize,
) -> (felt252, felt252, felt252, felt252) {
    let transcript_commitment = read_next(data, ref index);
    let prior_liquidity_position_root = read_next(data, ref index);
    let claimed_liquidity_position_transition_root = read_next(data, ref index);
    let claimed_new_liquidity_position_root = read_next(data, ref index);
    let liquidity_position_transition_root_domain = read_next(data, ref index);
    let state_transition_root_domain = read_next(data, ref index);

    assert(transcript_commitment != 0, 'E');
    assert(
        liquidity_position_transition_root_domain == LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN, 'E',
    );
    assert(state_transition_root_domain == STATE_TRANSITION_ROOT_DOMAIN, 'E');

    let liquidity_position_transition_kinds = read_vector(data, ref index);
    let liquidity_position_consumed_commitments = read_vector(data, ref index);
    let liquidity_position_nullifiers = read_vector(data, ref index);
    let liquidity_position_output_commitments = read_vector(data, ref index);
    let liquidity_position_state_position_ids = read_vector(data, ref index);
    let liquidity_position_state_key_lows = read_vector(data, ref index);
    let liquidity_position_state_key_highs = read_vector(data, ref index);
    let liquidity_position_state_prior_commitments = read_vector(data, ref index);
    let liquidity_position_state_output_commitments = read_vector(data, ref index);
    let liquidity_position_state_path_counts = read_vector(data, ref index);
    let liquidity_position_state_path_values = read_vector(data, ref index);
    let liquidity_position_state_path_directions = read_vector(data, ref index);
    assert(index == data.len(), 'E');

    let (liquidity_position_transition_root, computed_new_liquidity_position_root) =
        assert_liquidity_position_root_transition_witnesses(
        prior_liquidity_position_root,
        liquidity_position_transition_root_domain,
        state_transition_root_domain,
        liquidity_position_transition_kinds.span(),
        liquidity_position_consumed_commitments.span(),
        liquidity_position_nullifiers.span(),
        liquidity_position_output_commitments.span(),
        liquidity_position_state_position_ids.span(),
        liquidity_position_state_key_lows.span(),
        liquidity_position_state_key_highs.span(),
        liquidity_position_state_prior_commitments.span(),
        liquidity_position_state_output_commitments.span(),
        liquidity_position_state_path_counts.span(),
        liquidity_position_state_path_values.span(),
        liquidity_position_state_path_directions.span(),
    );
    assert(liquidity_position_transition_root == claimed_liquidity_position_transition_root, 'E');
    assert_liquidity_position_root_transition(
        state_transition_root_domain,
        prior_liquidity_position_root,
        liquidity_position_transition_root,
        claimed_new_liquidity_position_root,
        liquidity_position_transition_kinds.len(),
    );
    assert(claimed_new_liquidity_position_root == computed_new_liquidity_position_root, 'LP_ROOT');

    (
        transcript_commitment,
        prior_liquidity_position_root,
        liquidity_position_transition_root,
        claimed_new_liquidity_position_root,
    )
}

pub fn verify_liquidity_position_statement(
    data: Span<felt252>,
) -> (felt252, felt252, felt252, felt252) {
    let mut index: usize = 0;

    let statement_type = read_next(data, ref index);
    if statement_type == STATEMENT_TYPE_LIQUIDITY_POSITION {
        return verify_compact_liquidity_position_statement(data, ref index);
    }
    assert(statement_type == STATEMENT_TYPE_SETTLEMENT, 'E');
    let note_commitment_domain = read_next(data, ref index);
    skip_fields(data, ref index, 1);
    let nullifier_domain = read_next(data, ref index);
    skip_fields(data, ref index, 4);
    let pair_id = read_next(data, ref index);
    let batch_epoch = read_next(data, ref index);
    skip_fields(data, ref index, 2);
    let transcript_commitment = read_next(data, ref index);
    let base_asset_id = read_next(data, ref index);
    let quote_asset_id = read_next(data, ref index);
    let clearing_price = read_next(data, ref index);
    let price_base_scale = read_next(data, ref index);
    skip_fields(data, ref index, 6);
    let prior_note_root = read_next(data, ref index);
    skip_fields(data, ref index, 3);
    let prior_liquidity_position_root = read_next(data, ref index);
    let claimed_liquidity_position_transition_root = read_next(data, ref index);
    skip_fields(data, ref index, 3);
    let liquidity_position_transition_root_domain = read_next(data, ref index);
    skip_fields(data, ref index, 2);
    let state_transition_root_domain = read_next(data, ref index);
    skip_fields(data, ref index, 2);

    assert(transcript_commitment != 0, 'E');
    assert(note_commitment_domain == NOTE_COMMITMENT_DOMAIN, 'E');
    assert(nullifier_domain == NULLIFIER_DOMAIN, 'E');
    assert(
        liquidity_position_transition_root_domain == LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN, 'E',
    );
    assert(state_transition_root_domain == STATE_TRANSITION_ROOT_DOMAIN, 'E');

    let matched_order_commitments = read_vector(data, ref index);
    skip_vectors(data, ref index, 21);
    let matched_funding_input_counts = read_vector(data, ref index);
    skip_vectors(data, ref index, 27);
    let matched_residual_note_flags = read_vector(data, ref index);
    skip_vectors(data, ref index, 9);
    let matched_output_cursor_start = matched_public_output_count(
        matched_order_commitments.span(), matched_residual_note_flags.span(),
    );
    let matched_consumed_input_cursor_start = matched_consumed_input_count(
        matched_order_commitments.span(), matched_funding_input_counts.span(),
    );
    let consumed_note_commitments = read_vector(data, ref index);
    let consumed_nullifiers = read_vector(data, ref index);
    skip_vectors(data, ref index, 5);
    let note_membership_kinds = read_vector(data, ref index);
    let note_membership_prefix_roots = read_vector(data, ref index);
    let note_membership_batch_roots = read_vector(data, ref index);
    let note_membership_path_counts = read_vector(data, ref index);
    let note_membership_path_values = read_vector(data, ref index);
    let note_membership_path_directions = read_vector(data, ref index);
    let note_membership_suffix_counts = read_vector(data, ref index);
    let note_membership_suffix_roots = read_vector(data, ref index);
    skip_vectors(data, ref index, 12);
    let liquidity_position_transition_kinds = read_vector(data, ref index);
    let liquidity_position_consumed_commitments = read_vector(data, ref index);
    let liquidity_position_nullifiers = read_vector(data, ref index);
    let liquidity_position_output_commitments = read_vector(data, ref index);
    let liquidity_position_prior_fields = read_vector(data, ref index);
    let liquidity_position_output_fields = read_vector(data, ref index);
    let liquidity_position_sides = read_vector(data, ref index);
    let liquidity_position_filled_base_amounts = read_vector(data, ref index);
    let liquidity_position_clearing_prices = read_vector(data, ref index);
    let liquidity_position_price_base_scales = read_vector(data, ref index);
    let liquidity_position_market_reference_prices = read_vector(data, ref index);
    let liquidity_position_market_confirmation_prices = read_vector(data, ref index);
    let liquidity_position_market_observed_at_unix_ms = read_vector(data, ref index);
    let liquidity_position_market_current_time_unix_ms = read_vector(data, ref index);
    let liquidity_position_oracle_guard_ids = read_vector(data, ref index);
    let liquidity_position_oracle_guard_max_staleness_ms = read_vector(data, ref index);
    let liquidity_position_oracle_guard_max_divergence_bps = read_vector(data, ref index);
    let liquidity_position_state_position_ids = read_vector(data, ref index);
    let liquidity_position_state_key_lows = read_vector(data, ref index);
    let liquidity_position_state_key_highs = read_vector(data, ref index);
    let liquidity_position_state_prior_commitments = read_vector(data, ref index);
    let liquidity_position_state_output_commitments = read_vector(data, ref index);
    let liquidity_position_state_path_counts = read_vector(data, ref index);
    let liquidity_position_state_path_values = read_vector(data, ref index);
    let liquidity_position_state_path_directions = read_vector(data, ref index);
    let liquidity_position_lifecycle_signature_rs = read_vector(data, ref index);
    let liquidity_position_lifecycle_signature_ss = read_vector(data, ref index);
    let liquidity_position_lifecycle_base_amounts = read_vector(data, ref index);
    let liquidity_position_lifecycle_quote_amounts = read_vector(data, ref index);
    let liquidity_position_open_input_counts = read_vector(data, ref index);
    let liquidity_position_open_input_note_commitments = read_vector(data, ref index);
    let liquidity_position_open_input_asset_ids = read_vector(data, ref index);
    let liquidity_position_open_input_amounts = read_vector(data, ref index);
    let liquidity_position_open_input_owner_keys = read_vector(data, ref index);
    let liquidity_position_open_input_spend_authorities = read_vector(data, ref index);
    let liquidity_position_open_input_withdraw_authorities = read_vector(data, ref index);
    let liquidity_position_open_input_blindings = read_vector(data, ref index);
    let liquidity_position_open_input_nonces = read_vector(data, ref index);
    let liquidity_position_open_input_metadata_commitments = read_vector(data, ref index);
    let liquidity_position_lifecycle_output_counts = read_vector(data, ref index);
    let output_note_commitments = read_vector(data, ref index);
    let output_note_asset_ids = read_vector(data, ref index);
    let output_note_amounts = read_vector(data, ref index);
    let output_note_withdraw_authorities = read_vector(data, ref index);
    let output_note_owner_keys = read_vector(data, ref index);
    let output_note_spend_authorities = read_vector(data, ref index);
    let output_note_blindings = read_vector(data, ref index);
    let output_note_nonces = read_vector(data, ref index);
    let output_note_metadata_commitments = read_vector(data, ref index);
    skip_vectors(data, ref index, 4);
    read_next(data, ref index);
    read_next(data, ref index);
    let claimed_new_liquidity_position_root = read_next(data, ref index);
    assert(index == data.len(), 'E');

    let mut funding_input_cursor = matched_consumed_input_cursor_start;
    let mut note_membership_path_cursor = prefix_count_sum(
        note_membership_path_counts.span(), matched_consumed_input_cursor_start, 'NOTE_PATH',
    );
    let mut note_membership_suffix_cursor = prefix_count_sum(
        note_membership_suffix_counts.span(), matched_consumed_input_cursor_start, 'NOTE_SUFFIX',
    );
    let mut public_output_cursor = matched_output_cursor_start;
    let (
        liquidity_position_transition_root,
        computed_new_liquidity_position_root,
        _buy_base,
        _sell_base,
    ) =
        assert_liquidity_position_fill_transition_witnesses(
        prior_liquidity_position_root,
        liquidity_position_transition_root_domain,
        state_transition_root_domain,
        pair_id,
        batch_epoch,
        base_asset_id,
        quote_asset_id,
        clearing_price,
        price_base_scale,
        liquidity_position_transition_kinds.span(),
        liquidity_position_consumed_commitments.span(),
        liquidity_position_nullifiers.span(),
        liquidity_position_output_commitments.span(),
        liquidity_position_prior_fields.span(),
        liquidity_position_output_fields.span(),
        liquidity_position_sides.span(),
        liquidity_position_filled_base_amounts.span(),
        liquidity_position_clearing_prices.span(),
        liquidity_position_price_base_scales.span(),
        liquidity_position_market_reference_prices.span(),
        liquidity_position_market_confirmation_prices.span(),
        liquidity_position_market_observed_at_unix_ms.span(),
        liquidity_position_market_current_time_unix_ms.span(),
        liquidity_position_oracle_guard_ids.span(),
        liquidity_position_oracle_guard_max_staleness_ms.span(),
        liquidity_position_oracle_guard_max_divergence_bps.span(),
        liquidity_position_state_position_ids.span(),
        liquidity_position_state_key_lows.span(),
        liquidity_position_state_key_highs.span(),
        liquidity_position_state_prior_commitments.span(),
        liquidity_position_state_output_commitments.span(),
        liquidity_position_state_path_counts.span(),
        liquidity_position_state_path_values.span(),
        liquidity_position_state_path_directions.span(),
        liquidity_position_lifecycle_signature_rs.span(),
        liquidity_position_lifecycle_signature_ss.span(),
        liquidity_position_lifecycle_base_amounts.span(),
        liquidity_position_lifecycle_quote_amounts.span(),
        liquidity_position_open_input_counts.span(),
        liquidity_position_open_input_note_commitments.span(),
        liquidity_position_open_input_asset_ids.span(),
        liquidity_position_open_input_amounts.span(),
        liquidity_position_open_input_owner_keys.span(),
        liquidity_position_open_input_spend_authorities.span(),
        liquidity_position_open_input_withdraw_authorities.span(),
        liquidity_position_open_input_blindings.span(),
        liquidity_position_open_input_nonces.span(),
        liquidity_position_open_input_metadata_commitments.span(),
        liquidity_position_lifecycle_output_counts.span(),
        note_commitment_domain,
        nullifier_domain,
        prior_note_root,
        consumed_note_commitments.span(),
        consumed_nullifiers.span(),
        note_membership_kinds.span(),
        note_membership_prefix_roots.span(),
        note_membership_batch_roots.span(),
        note_membership_path_counts.span(),
        note_membership_path_values.span(),
        note_membership_path_directions.span(),
        note_membership_suffix_counts.span(),
        note_membership_suffix_roots.span(),
        ref funding_input_cursor,
        ref note_membership_path_cursor,
        ref note_membership_suffix_cursor,
        output_note_commitments.span(),
        output_note_asset_ids.span(),
        output_note_amounts.span(),
        output_note_withdraw_authorities.span(),
        output_note_owner_keys.span(),
        output_note_spend_authorities.span(),
        output_note_blindings.span(),
        output_note_nonces.span(),
        output_note_metadata_commitments.span(),
        ref public_output_cursor,
    );
    assert(liquidity_position_transition_root == claimed_liquidity_position_transition_root, 'E');
    assert_liquidity_position_root_transition(
        state_transition_root_domain,
        prior_liquidity_position_root,
        liquidity_position_transition_root,
        claimed_new_liquidity_position_root,
        liquidity_position_transition_kinds.len(),
    );
    assert(claimed_new_liquidity_position_root == computed_new_liquidity_position_root, 'LP_ROOT');

    (
        transcript_commitment,
        prior_liquidity_position_root,
        liquidity_position_transition_root,
        claimed_new_liquidity_position_root,
    )
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
    let liquidity_slice_domain = settlement_liquidity_slice_domain(settlement_payload.span());
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
    let liquidity_slice_commitments = read_vector(data, ref index);
    let liquidity_slice_point_counts = read_vector(data, ref index);
    let liquidity_slice_prices = read_vector(data, ref index);
    let liquidity_slice_base_amounts = read_vector(data, ref index);
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
            sides.len().into(), order_types.len().into(), liquidity_slice_commitments.len().into(),
            relay_modes.len().into(), liquidity_slice_point_counts.len().into(),
            limit_prices.len().into(), order_amounts.len().into(), min_fills.len().into(),
            time_in_force.len().into(), expiry_epochs.len().into(), order_nonces.len().into(),
            auditor_flags.len().into(), parent_order_commitments.len().into(),
            parent_child_indexes.len().into(), parent_secret_commitments.len().into(),
            parent_cancel_authorities.len().into(), parent_authorization_secrets.len().into(),
            funding_note_refs.len().into(), funding_input_counts.len().into(),
            funding_note_amounts.len().into(), funding_note_owner_keys.len().into(),
            funding_authorization_rs.len().into(), funding_authorization_ss.len().into(),
            funding_nullifiers.len().into(), recipient_owner_keys.len().into(),
            recipient_spend_authorities.len().into(), recipient_withdraw_authorities.len().into(),
            res_auths_span.len().into(),
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
    let total_slice_points = sum_slice_point_counts(liquidity_slice_point_counts.span());
    assert_admission_bounds(order_commitments.len(), funding_input_count, total_slice_points);
    assert(liquidity_slice_prices.len() == total_slice_points, 'ADM_CURVE_PRICES');
    assert(liquidity_slice_base_amounts.len() == total_slice_points, 'ADM_CURVE_AMTS');
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
            liquidity_slice_commitments.span(),
            liquidity_slice_point_counts.span(),
            liquidity_slice_prices.span(),
            liquidity_slice_base_amounts.span(),
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
            liquidity_slice_domain,
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
        liquidity_slice_commitments.span(),
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
    assert(statement_type == STATEMENT_TYPE_AUCTION_RESULT, 'AR_TYPE');

    let settlement_payload = read_vector(data, ref index);
    let transcript_commitment = settlement_transcript_commitment(settlement_payload.span());
    let order_commitment_root = settlement_order_commitment_root(settlement_payload.span());
    let clearing_price = settlement_clearing_price(settlement_payload.span());
    let price_base_scale = settlement_price_base_scale(settlement_payload.span());
    let liquidity_slice_domain = settlement_liquidity_slice_domain(settlement_payload.span());
    let batch_id = settlement_batch_id(settlement_payload.span());
    let pair_id = settlement_pair_id(settlement_payload.span());
    let matched_order_commitments = settlement_matched_order_commitments(settlement_payload.span());
    let matched_fill_amounts = settlement_matched_fill_amounts(settlement_payload.span());
    let (liquidity_position_buy_fill, liquidity_position_sell_fill) =
        settlement_liquidity_position_fill_totals(
        settlement_payload.span(),
    );
    let clearing_price_u128 = felt_to_u128(clearing_price);
    let price_base_scale_u128 = felt_to_u128(price_base_scale);
    assert(price_base_scale_u128 != 0, 'AR_SCALE');
    let admission_root = read_next(data, ref index);

    let order_commitments = read_vector(data, ref index);
    let sides = read_vector(data, ref index);
    let order_types = read_vector(data, ref index);
    let relay_modes = read_vector(data, ref index);
    let liquidity_slice_commitments = read_vector(data, ref index);
    let liquidity_slice_point_counts = read_vector(data, ref index);
    let liquidity_slice_prices = read_vector(data, ref index);
    let liquidity_slice_base_amounts = read_vector(data, ref index);
    let limit_prices = read_vector(data, ref index);
    let order_amounts = read_vector(data, ref index);
    let min_fills = read_vector(data, ref index);
    let time_in_force = read_vector(data, ref index);
    let funding_note_amounts = read_vector(data, ref index);
    let funding_note_owner_keys = read_vector(data, ref index);
    let allocation_fill_amounts = read_vector(data, ref index);

    assert_all_lengths_match(
        order_commitments.len(),
        array![
            sides.len().into(), order_types.len().into(), relay_modes.len().into(),
            liquidity_slice_commitments.len().into(), liquidity_slice_point_counts.len().into(),
            limit_prices.len().into(), order_amounts.len().into(), min_fills.len().into(),
            time_in_force.len().into(), funding_note_amounts.len().into(),
            funding_note_owner_keys.len().into(), allocation_fill_amounts.len().into(),
        ]
            .span(),
        'AR_LEN',
    );
    let total_slice_points = sum_slice_point_counts(liquidity_slice_point_counts.span());
    assert_admission_bounds(
        order_commitments.len(),
        order_commitments.len() * MAX_ORDER_FUNDING_INPUTS,
        total_slice_points,
    );
    assert(liquidity_slice_prices.len() == total_slice_points, 'AR_CPRICES');
    assert(liquidity_slice_base_amounts.len() == total_slice_points, 'AR_CAMTS');
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
            liquidity_slice_commitments.span(),
            limit_prices.span(),
            order_amounts.span(),
            min_fills.span(),
            time_in_force.span(),
            funding_note_amounts.span(),
            funding_note_owner_keys.span(),
        ) == admission_root,
        'AR_ADMIT',
    );
    assert_curve_commitments_for_summary(
        pair_id,
        clearing_price_u128,
        price_base_scale_u128,
        sides.span(),
        order_types.span(),
        liquidity_slice_domain,
        liquidity_slice_commitments.span(),
        liquidity_slice_point_counts.span(),
        liquidity_slice_prices.span(),
        liquidity_slice_base_amounts.span(),
    );
    if matched_order_commitments.len() == 0
        && liquidity_position_buy_fill == 0
        && liquidity_position_sell_fill == 0 {
        assert_all_zero(allocation_fill_amounts.span(), 'AR_ZERO');
        assert_no_executable_auction(
            price_base_scale_u128,
            sides.span(),
            order_types.span(),
            liquidity_slice_point_counts.span(),
            liquidity_slice_prices.span(),
            liquidity_slice_base_amounts.span(),
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
            liquidity_slice_point_counts.span(),
            liquidity_slice_prices.span(),
            liquidity_slice_base_amounts.span(),
            limit_prices.span(),
            order_amounts.span(),
            min_fills.span(),
            time_in_force.span(),
            funding_note_amounts.span(),
            allocation_fill_amounts.span(),
            matched_order_commitments.span(),
            matched_fill_amounts.span(),
            liquidity_position_buy_fill,
            liquidity_position_sell_fill,
        );
        assert_best_clearing_price(
            clearing_price_u128,
            price_base_scale_u128,
            liquidity_position_buy_fill,
            liquidity_position_sell_fill,
            sides.span(),
            order_types.span(),
            liquidity_slice_point_counts.span(),
            liquidity_slice_prices.span(),
            liquidity_slice_base_amounts.span(),
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
    assert(settlement_payload.len() > 15, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(15)
}

fn settlement_price_base_scale(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 16, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(16)
}

fn settlement_transcript_commitment(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 12, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(12)
}

fn settlement_order_commitment_root(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 10, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(10)
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

fn settlement_liquidity_slice_domain(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 5, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(5)
}

fn settlement_batch_id(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 7, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(7)
}

fn settlement_pair_id(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 8, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(8)
}

fn settlement_batch_epoch(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 9, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(9)
}

fn settlement_base_asset_id(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 13, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(13)
}

fn settlement_quote_asset_id(settlement_payload: Span<felt252>) -> felt252 {
    assert(settlement_payload.len() > 14, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    *settlement_payload.at(14)
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

fn settlement_liquidity_position_fill_totals(settlement_payload: Span<felt252>) -> (u128, u128) {
    assert(settlement_payload.len() > SETTLEMENT_HEADER_FIELD_COUNT, 'E');
    assert(*settlement_payload.at(0) == STATEMENT_TYPE_SETTLEMENT, 'E');
    let mut index: usize = SETTLEMENT_HEADER_FIELD_COUNT;
    skip_vectors(settlement_payload, ref index, SETTLEMENT_VECTOR_COUNT_BEFORE_LP_TRANSITION_KINDS);

    let kinds = read_vector(settlement_payload, ref index);
    let _consumed_commitments = read_vector(settlement_payload, ref index);
    let _nullifiers = read_vector(settlement_payload, ref index);
    let _output_commitments = read_vector(settlement_payload, ref index);
    let _prior_position_fields = read_vector(settlement_payload, ref index);
    let _output_position_fields = read_vector(settlement_payload, ref index);
    let position_sides = read_vector(settlement_payload, ref index);
    let filled_base_amounts = read_vector(settlement_payload, ref index);

    assert_all_lengths_match(
        kinds.len(),
        array![position_sides.len().into(), filled_base_amounts.len().into()].span(),
        'LP_AUCTION',
    );

    let mut buy_fill: u128 = 0;
    let mut sell_fill: u128 = 0;
    let mut lp_index = 0;
    while lp_index < kinds.len() {
        let filled = felt_to_u128(*filled_base_amounts.at(lp_index));
        if *kinds.at(lp_index) == LP_TRANSITION_KIND_UPDATE {
            let side = *position_sides.at(lp_index);
            if side == ORDER_SIDE_BUY {
                buy_fill = buy_fill + filled;
            } else {
                assert(side == ORDER_SIDE_SELL, 'LP_AUCTION');
                sell_fill = sell_fill + filled;
            }
        } else {
            assert(filled == 0, 'LP_AUCTION');
        }
        lp_index += 1;
    }

    (buy_fill, sell_fill)
}

fn assert_auction_order_preimages(
    clearing_price: u128,
    price_base_scale: u128,
    order_commitments: Span<felt252>,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    relay_modes: Span<felt252>,
    liquidity_slice_commitments: Span<felt252>,
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
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
    liquidity_slice_domain: felt252,
    batch_id: felt252,
    pair_id: felt252,
    batch_epoch: felt252,
    base_asset_id: felt252,
    quote_asset_id: felt252,
) {
    let mut index = 0;
    let mut slice_cursor: usize = 0;
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
        let point_count: usize = (*liquidity_slice_point_counts.at(index)).try_into().expect('E');

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
        let (curve_total_amount, _curve_capacity_at_price, curve_quote_funding_required) =
            assert_liquidity_slice(
            pair_id,
            order_type,
            side,
            liquidity_slice_domain,
            *liquidity_slice_commitments.at(index),
            point_count,
            slice_cursor,
            clearing_price,
            price_base_scale,
            liquidity_slice_prices,
            liquidity_slice_base_amounts,
        );
        let _unused_curve_total_amount = curve_total_amount;
        let _unused_curve_quote_funding_required = curve_quote_funding_required;

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
            *liquidity_slice_commitments.at(index),
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
        slice_cursor += point_count;
        index += 1;
    }
    assert(slice_cursor == liquidity_slice_prices.len(), 'E');
    assert(funding_input_cursor == funding_note_commitments.len(), 'E');
}

fn assert_auction_allocation(
    clearing_price: u128,
    price_base_scale: u128,
    order_commitments: Span<felt252>,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
    allocation_fill_amounts: Span<felt252>,
    matched_order_commitments: Span<felt252>,
    matched_fill_amounts: Span<felt252>,
    liquidity_position_buy_fill: u128,
    liquidity_position_sell_fill: u128,
) {
    let active_flags = stable_active_flags(
        clearing_price,
        price_base_scale,
        sides,
        order_types,
        liquidity_slice_point_counts,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
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
    let mut slice_cursor: usize = 0;

    while index < order_commitments.len() {
        let point_count: usize = (*liquidity_slice_point_counts.at(index)).try_into().expect('E');
        let fill = felt_to_u128(*allocation_fill_amounts.at(index));
        let expected_fill = expected_fill_with_active_flags_and_cursor(
            index,
            slice_cursor,
            point_count,
            active_flags.span(),
            if *sides.at(index) == ORDER_SIDE_BUY {
                liquidity_position_sell_fill
            } else {
                liquidity_position_buy_fill
            },
            clearing_price,
            price_base_scale,
            sides,
            order_types,
            liquidity_slice_point_counts,
            liquidity_slice_prices,
            liquidity_slice_base_amounts,
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
        slice_cursor += point_count;
        index += 1;
    }

    assert(matched_index == matched_order_commitments.len(), 'E');
    assert(
        total_buy_fill
            + liquidity_position_buy_fill == total_sell_fill
            + liquidity_position_sell_fill,
        'E',
    );
    let (max_matched, _imbalance) = auction_score_at_price_with_liquidity(
        clearing_price,
        price_base_scale,
        clearing_price,
        liquidity_position_buy_fill,
        liquidity_position_sell_fill,
        sides,
        order_types,
        liquidity_slice_point_counts,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    assert(total_buy_fill + liquidity_position_buy_fill == max_matched, 'E');
}

fn stable_active_flags(
    clearing_price: u128,
    price_base_scale: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
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
        liquidity_slice_point_counts,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
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
            liquidity_slice_point_counts,
            liquidity_slice_prices,
            liquidity_slice_base_amounts,
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
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> Array<felt252> {
    let mut flags = array![];
    let mut index = 0;
    let mut slice_cursor: usize = 0;
    while index < sides.len() {
        let point_count: usize = (*liquidity_slice_point_counts.at(index)).try_into().expect('E');
        let max_fill = max_fill_at_candidate_with_cursor(
            clearing_price,
            price_base_scale,
            *sides.at(index),
            *order_types.at(index),
            point_count,
            slice_cursor,
            liquidity_slice_prices,
            liquidity_slice_base_amounts,
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
        slice_cursor += point_count;
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
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> Array<felt252> {
    let mut next = array![];
    let mut index = 0;
    let mut slice_cursor: usize = 0;
    while index < active_flags.len() {
        let point_count: usize = (*liquidity_slice_point_counts.at(index)).try_into().expect('E');
        if *active_flags.at(index) == 0 {
            next.append(0);
        } else {
            let fill = expected_fill_with_active_flags_and_cursor(
                index,
                slice_cursor,
                point_count,
                active_flags,
                0,
                clearing_price,
                price_base_scale,
                sides,
                order_types,
                liquidity_slice_point_counts,
                liquidity_slice_prices,
                liquidity_slice_base_amounts,
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
        slice_cursor += point_count;
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
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> u128 {
    let target_slice_cursor = slice_cursor_for_order(liquidity_slice_point_counts, target_index);
    let target_point_count: usize = (*liquidity_slice_point_counts.at(target_index))
        .try_into()
        .expect('E');
    expected_fill_with_active_flags_and_cursor(
        target_index,
        target_slice_cursor,
        target_point_count,
        active_flags,
        0,
        clearing_price,
        price_base_scale,
        sides,
        order_types,
        liquidity_slice_point_counts,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    )
}

fn expected_fill_with_active_flags_and_cursor(
    target_index: usize,
    target_slice_cursor: usize,
    target_point_count: usize,
    active_flags: Span<felt252>,
    opposite_liquidity_position_capacity: u128,
    clearing_price: u128,
    price_base_scale: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
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
    let max_fill = max_fill_at_candidate_with_cursor(
        clearing_price,
        price_base_scale,
        target_side,
        *order_types.at(target_index),
        target_point_count,
        target_slice_cursor,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
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
        liquidity_slice_point_counts,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    )
        + opposite_liquidity_position_capacity;
    let priority_capacity = active_priority_capacity_before(
        target_index,
        active_flags,
        clearing_price,
        price_base_scale,
        sides,
        order_types,
        liquidity_slice_point_counts,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
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
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) -> u128 {
    let mut index = 0;
    let mut capacity: u128 = 0;
    let mut slice_cursor: usize = 0;
    while index < sides.len() {
        let point_count: usize = (*liquidity_slice_point_counts.at(index)).try_into().expect('E');
        if *active_flags.at(index) == 1 && *sides.at(index) == side {
            capacity +=
                max_fill_at_candidate_with_cursor(
                    clearing_price,
                    price_base_scale,
                    *sides.at(index),
                    *order_types.at(index),
                    point_count,
                    slice_cursor,
                    liquidity_slice_prices,
                    liquidity_slice_base_amounts,
                    *limit_prices.at(index),
                    *order_amounts.at(index),
                    *min_fills.at(index),
                    *time_in_force.at(index),
                    *funding_note_amounts.at(index),
                );
        }
        slice_cursor += point_count;
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
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
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
    let mut slice_cursor: usize = 0;

    while index < sides.len() {
        let point_count: usize = (*liquidity_slice_point_counts.at(index)).try_into().expect('E');
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
                    max_fill_at_candidate_with_cursor(
                        clearing_price,
                        price_base_scale,
                        *sides.at(index),
                        *order_types.at(index),
                        point_count,
                        slice_cursor,
                        liquidity_slice_prices,
                        liquidity_slice_base_amounts,
                        *limit_prices.at(index),
                        *order_amounts.at(index),
                        *min_fills.at(index),
                        *time_in_force.at(index),
                        *funding_note_amounts.at(index),
                    );
            }
        }
        slice_cursor += point_count;
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
    price_base_scale: u128,
    liquidity_position_buy_fill: u128,
    liquidity_position_sell_fill: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
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
    let mut slice_cursor: usize = 0;

    while order_index < sides.len() {
        let point_count: usize = (*liquidity_slice_point_counts.at(order_index))
            .try_into()
            .expect('E');
        if *order_types.at(order_index) != ORDER_TYPE_HEARTBEAT_COVER {
            let candidate = felt_to_u128(*limit_prices.at(order_index));
            if candidate_seen_before(
                order_types,
                liquidity_slice_point_counts,
                liquidity_slice_prices,
                limit_prices,
                order_index,
                candidate,
            ) == 0 {
                let (matched, imbalance) = auction_score_at_price_with_liquidity(
                    candidate,
                    price_base_scale,
                    clearing_price,
                    liquidity_position_buy_fill,
                    liquidity_position_sell_fill,
                    sides,
                    order_types,
                    liquidity_slice_point_counts,
                    liquidity_slice_prices,
                    liquidity_slice_base_amounts,
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
        slice_cursor += point_count;
        order_index += 1;
    }

    if best_initialized == 0
        && (liquidity_position_buy_fill != 0 || liquidity_position_sell_fill != 0) {
        let (matched, imbalance) = auction_score_at_price_with_liquidity(
            clearing_price,
            price_base_scale,
            clearing_price,
            liquidity_position_buy_fill,
            liquidity_position_sell_fill,
            sides,
            order_types,
            liquidity_slice_point_counts,
            liquidity_slice_prices,
            liquidity_slice_base_amounts,
            limit_prices,
            order_amounts,
            min_fills,
            time_in_force,
            funding_note_amounts,
        );
        best_initialized = 1;
        best_low_price = clearing_price;
        best_high_price = clearing_price;
        best_matched = matched;
        best_imbalance = imbalance;
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
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
    limit_prices: Span<felt252>,
    order_amounts: Span<felt252>,
    min_fills: Span<felt252>,
    time_in_force: Span<felt252>,
    funding_note_amounts: Span<felt252>,
) {
    let mut order_index = 0;
    let mut slice_cursor: usize = 0;
    while order_index < sides.len() {
        let point_count: usize = (*liquidity_slice_point_counts.at(order_index))
            .try_into()
            .expect('E');
        if *order_types.at(order_index) != ORDER_TYPE_HEARTBEAT_COVER {
            let candidate = felt_to_u128(*limit_prices.at(order_index));
            if candidate_seen_before(
                order_types,
                liquidity_slice_point_counts,
                liquidity_slice_prices,
                limit_prices,
                order_index,
                candidate,
            ) == 0 {
                let (matched, _imbalance) = auction_score_at_price(
                    candidate,
                    price_base_scale,
                    sides,
                    order_types,
                    liquidity_slice_point_counts,
                    liquidity_slice_prices,
                    liquidity_slice_base_amounts,
                    limit_prices,
                    order_amounts,
                    min_fills,
                    time_in_force,
                    funding_note_amounts,
                );
                assert(matched == 0, 'E');
            }
        }
        slice_cursor += point_count;
        order_index += 1;
    }
}

fn candidate_seen_before(
    order_types: Span<felt252>,
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    limit_prices: Span<felt252>,
    candidate_order_index: usize,
    candidate: u128,
) -> felt252 {
    let mut order_index = 0;
    let mut slice_cursor: usize = 0;
    while order_index < candidate_order_index {
        let point_count: usize = (*liquidity_slice_point_counts.at(order_index))
            .try_into()
            .expect('E');
        if *order_types.at(order_index) != ORDER_TYPE_HEARTBEAT_COVER {
            if felt_to_u128(*limit_prices.at(order_index)) == candidate {
                return 1;
            }
        }
        slice_cursor += point_count;
        order_index += 1;
    }
    0
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
    relay_mode: felt252,
    liquidity_slice_commitment: felt252,
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
    state = poseidon_hash2(state, relay_mode);
    state = poseidon_hash2(state, liquidity_slice_commitment);
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
    relay_modes: Span<felt252>,
    liquidity_slice_commitments: Span<felt252>,
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
                    *relay_modes.at(index),
                    *liquidity_slice_commitments.at(index),
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
    pair_id: felt252,
    clearing_price: u128,
    price_base_scale: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    liquidity_slice_domain: felt252,
    liquidity_slice_commitments: Span<felt252>,
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
) {
    let mut index = 0;
    let mut slice_cursor: usize = 0;
    while index < liquidity_slice_commitments.len() {
        let point_count: usize = (*liquidity_slice_point_counts.at(index)).try_into().expect('E');
        let (_total, _eligible, _quote_required) = assert_liquidity_slice(
            pair_id,
            *order_types.at(index),
            *sides.at(index),
            liquidity_slice_domain,
            *liquidity_slice_commitments.at(index),
            point_count,
            slice_cursor,
            clearing_price,
            price_base_scale,
            liquidity_slice_prices,
            liquidity_slice_base_amounts,
        );
        slice_cursor += point_count;
        index += 1;
    }
    assert(slice_cursor == liquidity_slice_prices.len(), 'E');
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
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
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
        liquidity_slice_point_counts,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
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
        liquidity_slice_point_counts,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
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
        liquidity_slice_point_counts,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
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

fn auction_score_at_price_with_liquidity(
    price: u128,
    price_base_scale: u128,
    clearing_price: u128,
    liquidity_position_buy_fill: u128,
    liquidity_position_sell_fill: u128,
    sides: Span<felt252>,
    order_types: Span<felt252>,
    liquidity_slice_point_counts: Span<felt252>,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
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
        liquidity_slice_point_counts,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    );
    let lp_buy = if price == clearing_price {
        liquidity_position_buy_fill
    } else {
        0
    };
    let lp_sell = if price == clearing_price {
        liquidity_position_sell_fill
    } else {
        0
    };
    let buy_demand = active_capacity_total(
        active_flags.span(),
        ORDER_SIDE_BUY,
        price,
        price_base_scale,
        sides,
        order_types,
        liquidity_slice_point_counts,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    )
        + lp_buy;
    let sell_supply = active_capacity_total(
        active_flags.span(),
        ORDER_SIDE_SELL,
        price,
        price_base_scale,
        sides,
        order_types,
        liquidity_slice_point_counts,
        liquidity_slice_prices,
        liquidity_slice_base_amounts,
        limit_prices,
        order_amounts,
        min_fills,
        time_in_force,
        funding_note_amounts,
    )
        + lp_sell;

    let matched = u128_min(buy_demand, sell_supply);
    let imbalance = u128_abs_diff(buy_demand, sell_supply);
    (matched, imbalance)
}

fn max_fill_at_candidate_with_cursor(
    price: u128,
    price_base_scale: u128,
    side: felt252,
    order_type: felt252,
    point_count: usize,
    slice_cursor: usize,
    liquidity_slice_prices: Span<felt252>,
    liquidity_slice_base_amounts: Span<felt252>,
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
    assert(point_count == 0, 'E');
    assert(slice_cursor <= liquidity_slice_prices.len(), 'E');
    assert(slice_cursor <= liquidity_slice_base_amounts.len(), 'E');
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

fn slice_cursor_for_order(point_counts: Span<felt252>, order_index: usize) -> usize {
    let mut cursor = 0;
    let mut index = 0;
    while index < order_index {
        let count: usize = (*point_counts.at(index)).try_into().expect('E');
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
                || source == MULTI_PAIR_DELTA_SOURCE_LIQUIDITY_POSITION
                || source == MULTI_PAIR_DELTA_SOURCE_PROTOCOL_BACKSTOP
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
    let left: u128 = (product % modulus).try_into().expect('LP_SEED');
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

fn sum_bounded_counts(counts: Span<felt252>, max_per_item: usize, message: felt252) -> usize {
    assert(counts.len() <= MAX_LIQUIDITY_POSITION_TRANSITIONS, message);
    let mut index = 0;
    let mut total = 0;
    while index < counts.len() {
        let count: usize = (*counts.at(index)).try_into().expect(message);
        assert(count <= max_per_item, message);
        total += count;
        index += 1;
    }
    total
}

fn sum_slice_point_counts(counts: Span<felt252>) -> usize {
    assert(counts.len() <= MAX_SETTLEMENT_ORDERS, 'E');
    let mut index = 0;
    let mut total = 0;
    while index < counts.len() {
        let count: usize = (*counts.at(index)).try_into().expect('E');
        total += count;
        index += 1;
    }
    total
}

fn assert_admission_bounds(
    order_count: usize, funding_input_count: usize, slice_point_count: usize,
) {
    assert(order_count <= MAX_SETTLEMENT_ORDERS, 'E');
    assert(funding_input_count <= MAX_SETTLEMENT_INPUT_NOTES, 'E');
    assert(slice_point_count <= MAX_SETTLEMENT_LIQUIDITY_SLICE_POINTS, 'E');
}

fn assert_settlement_bounds(
    order_count: usize,
    funding_input_count: usize,
    output_note_count: usize,
    slice_point_count: usize,
) {
    assert_admission_bounds(order_count, funding_input_count, slice_point_count);
    assert(output_note_count <= MAX_SETTLEMENT_OUTPUT_NOTES, 'E');
}

fn assert_liquidity_slice(
    pair_id: felt252,
    order_type: felt252,
    side: felt252,
    liquidity_slice_domain: felt252,
    expected_commitment: felt252,
    point_count: usize,
    cursor: usize,
    clearing_price: u128,
    price_base_scale: u128,
    prices: Span<felt252>,
    base_amounts: Span<felt252>,
) -> (u128, u128, u128) {
    assert(order_type == ORDER_TYPE_LIMIT_BATCH || order_type == ORDER_TYPE_HEARTBEAT_COVER, 'E');
    assert(side == ORDER_SIDE_BUY || side == ORDER_SIDE_SELL, 'E');
    assert(liquidity_slice_domain != 0, 'E');
    assert(expected_commitment == 0, 'E');
    assert(point_count == 0, 'E');
    assert(cursor <= prices.len(), 'E');
    assert(cursor <= base_amounts.len(), 'E');
    let _unused_pair_id = pair_id;
    let _unused_clearing_price = clearing_price;
    let _unused_price_base_scale = price_base_scale;
    (0, 0, 0)
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

fn liquidity_position_commitment(fields: Span<felt252>) -> felt252 {
    assert(fields.len() == LIQUIDITY_POSITION_FIELD_COUNT, 'LP_FIELDS');
    let mut state = LIQUIDITY_POSITION_COMMITMENT_DOMAIN;
    let mut index = 0;
    while index < fields.len() {
        state = poseidon_hash2(state, *fields.at(index));
        index += 1;
    }
    state
}

fn liquidity_position_nullifier(position_commitment: felt252, blinding: felt252) -> felt252 {
    assert(position_commitment != 0, 'LP_COMMITMENT');
    assert(blinding != 0, 'LP_BLINDING');
    poseidon_hash2(
        poseidon_hash2(LIQUIDITY_POSITION_NULLIFIER_DOMAIN, position_commitment), blinding,
    )
}

fn assert_liquidity_position_fill(
    prior_fields: Span<felt252>,
    output_fields: Span<felt252>,
    position_side: felt252,
    filled_base_amount_felt: felt252,
    clearing_price_felt: felt252,
    price_base_scale_felt: felt252,
) -> (felt252, felt252, felt252) {
    assert(prior_fields.len() == LIQUIDITY_POSITION_FIELD_COUNT, 'LP_FIELDS');
    assert(output_fields.len() == LIQUIDITY_POSITION_FIELD_COUNT, 'LP_FIELDS');
    assert(*prior_fields.at(2) == 0, 'LP_BACKING');
    assert(*output_fields.at(2) == 0, 'LP_BACKING');
    assert(*prior_fields.at(3) == 1, 'LP_STATUS');
    assert(*output_fields.at(3) == 1, 'LP_STATUS');

    let mut field_index = 0;
    while field_index < LIQUIDITY_POSITION_FIELD_COUNT {
        if field_index == 8
            || field_index == 9
            || field_index == 25 {} else {
                assert(*prior_fields.at(field_index) == *output_fields.at(field_index), 'LP_FIELD');
            }
        field_index += 1;
    }

    let filled_base_amount = felt_to_u128(filled_base_amount_felt);
    let clearing_price = felt_to_u128(clearing_price_felt);
    let price_base_scale = felt_to_u128(price_base_scale_felt);
    let lower_price = felt_to_u128(*prior_fields.at(10));
    let upper_price = felt_to_u128(*prior_fields.at(11));
    let max_fill_base = felt_to_u128(*prior_fields.at(12));
    assert(filled_base_amount != 0, 'LP_FILL');
    assert(max_fill_base != 0, 'LP_FILL');
    assert(filled_base_amount <= max_fill_base, 'LP_FILL');
    assert(price_base_scale != 0, 'LP_PRICE_SCALE');
    assert(clearing_price >= lower_price, 'LP_PRICE');
    assert(clearing_price <= upper_price, 'LP_PRICE');

    let prior_base_reserve = felt_to_u128(*prior_fields.at(8));
    let prior_quote_reserve = felt_to_u128(*prior_fields.at(9));
    let output_base_reserve = felt_to_u128(*output_fields.at(8));
    let output_quote_reserve = felt_to_u128(*output_fields.at(9));
    let prior_blinding = *prior_fields.at(25);
    let output_blinding = *output_fields.at(25);
    assert(prior_blinding != 0, 'LP_BLINDING');
    assert(output_blinding != 0, 'LP_BLINDING');
    assert(output_blinding != prior_blinding, 'LP_BLINDING');

    let quote_amount = quote_amount_for_base_amount(
        filled_base_amount, clearing_price, price_base_scale,
    );
    if position_side == ORDER_SIDE_BUY {
        assert(prior_quote_reserve >= quote_amount, 'LP_RESERVE');
        assert(output_quote_reserve == prior_quote_reserve - quote_amount, 'LP_QUOTE');
        assert(output_base_reserve == prior_base_reserve + filled_base_amount, 'LP_BASE');
    } else {
        assert(position_side == ORDER_SIDE_SELL, 'LP_SIDE');
        assert(prior_base_reserve >= filled_base_amount, 'LP_RESERVE');
        assert(output_base_reserve == prior_base_reserve - filled_base_amount, 'LP_BASE');
        assert(output_quote_reserve == prior_quote_reserve + quote_amount, 'LP_QUOTE');
    }

    let prior_commitment = liquidity_position_commitment(prior_fields);
    let output_commitment = liquidity_position_commitment(output_fields);
    (
        prior_commitment,
        liquidity_position_nullifier(prior_commitment, prior_blinding),
        output_commitment,
    )
}

fn liquidity_position_sparse_leaf(position_id: felt252, commitment: felt252) -> felt252 {
    assert(position_id != 0, 'LP_ID');
    assert(commitment != 0, 'LP_COMMITMENT');
    poseidon_hash2(poseidon_hash2(LIQUIDITY_POSITION_SPARSE_LEAF_DOMAIN, position_id), commitment)
}

fn liquidity_position_sparse_node(left: felt252, right: felt252, level: usize) -> felt252 {
    let state = poseidon_hash2(LIQUIDITY_POSITION_SPARSE_NODE_DOMAIN, level.into());
    poseidon_hash2(poseidon_hash2(state, left), right)
}

fn liquidity_position_sparse_root_from_empty(
    position_id: felt252, key_low: u128, key_high: u128, commitment: felt252,
) -> felt252 {
    assert_sparse_key_in_field(key_low, key_high);
    assert(position_id == key_low.into() + key_high.into() * TWO_POW_128, 'LP_KEY');
    let mut root = liquidity_position_sparse_leaf(position_id, commitment);
    let mut empty = 0;
    let mut remaining_key = key_low;
    let mut level = 0;
    while level < LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
        root =
            if remaining_key % 2 == 0 {
                liquidity_position_sparse_node(root, empty, level)
            } else {
                liquidity_position_sparse_node(empty, root, level)
            };
        remaining_key /= 2;
        empty = liquidity_position_sparse_node(empty, empty, level);
        level += 1;
    }
    root
}

fn liquidity_position_root_from_path(
    leaf: felt252, expected_key_low: u128, path: Span<felt252>, directions: Span<felt252>,
) -> felt252 {
    assert(path.len() == LIQUIDITY_POSITION_SPARSE_TREE_DEPTH, 'LP_PATH');
    assert(directions.len() == LIQUIDITY_POSITION_SPARSE_TREE_DEPTH, 'LP_PATH');
    let mut root = leaf;
    let mut key_low = expected_key_low;
    let mut level = 0;
    while level < LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
        let expected_direction: felt252 = (key_low % 2).into();
        let direction = *directions.at(level);
        assert(direction == expected_direction, 'LP_DIRECTION');
        let sibling = *path.at(level);
        root =
            if direction == 0 {
                liquidity_position_sparse_node(root, sibling, level)
            } else {
                liquidity_position_sparse_node(sibling, root, level)
            };
        key_low /= 2;
        level += 1;
    }
    root
}

fn liquidity_position_path_is_canonical_empty(path: Span<felt252>) -> bool {
    if path.len() != LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
        return false;
    }
    let mut empty = 0;
    let mut level = 0;
    while level < LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
        if *path.at(level) != empty {
            return false;
        }
        empty = liquidity_position_sparse_node(empty, empty, level);
        level += 1;
    }
    true
}

fn assert_liquidity_position_sparse_update(
    prior_root: felt252,
    position_id: felt252,
    key_low_felt: felt252,
    key_high_felt: felt252,
    prior_commitment: felt252,
    output_commitment: felt252,
    path: Span<felt252>,
    directions: Span<felt252>,
) -> felt252 {
    assert(position_id != 0, 'LP_ID');
    assert(prior_commitment != 0 || output_commitment != 0, 'LP_EMPTY_UPDATE');
    let key_low: u128 = key_low_felt.try_into().expect('LP_KEY');
    let key_high: u128 = key_high_felt.try_into().expect('LP_KEY');
    assert_sparse_key_in_field(key_low, key_high);
    assert(position_id == key_low.into() + key_high.into() * TWO_POW_128, 'LP_KEY');
    if prior_root == 0 {
        assert(prior_commitment == 0, 'LP_PRIOR');
        assert(output_commitment != 0, 'LP_OUTPUT');
        assert(path.len() == 0, 'LP_PATH');
        assert(directions.len() == 0, 'LP_PATH');
        return liquidity_position_sparse_root_from_empty(
            position_id, key_low, key_high, output_commitment,
        );
    }

    let prior_leaf = if prior_commitment == 0 {
        0
    } else {
        liquidity_position_sparse_leaf(position_id, prior_commitment)
    };
    assert(
        liquidity_position_root_from_path(prior_leaf, key_low, path, directions) == prior_root,
        'LP_ROOT',
    );
    let output_leaf = if output_commitment == 0 {
        0
    } else {
        liquidity_position_sparse_leaf(position_id, output_commitment)
    };
    let output_root = liquidity_position_root_from_path(output_leaf, key_low, path, directions);
    if output_commitment == 0 && liquidity_position_path_is_canonical_empty(path) {
        return 0;
    }
    output_root
}

fn assert_liquidity_position_sparse_update_from_cursor(
    prior_root: felt252,
    position_id: felt252,
    key_low_felt: felt252,
    key_high_felt: felt252,
    prior_commitment: felt252,
    output_commitment: felt252,
    path_count_felt: felt252,
    ref path_cursor: usize,
    path_values: Span<felt252>,
    path_directions: Span<felt252>,
) -> felt252 {
    assert(position_id != 0, 'LP_ID');
    assert(prior_commitment != 0 || output_commitment != 0, 'LP_EMPTY_UPDATE');
    let key_low: u128 = key_low_felt.try_into().expect('LP_KEY');
    let key_high: u128 = key_high_felt.try_into().expect('LP_KEY');
    assert_sparse_key_in_field(key_low, key_high);
    assert(position_id == key_low.into() + key_high.into() * TWO_POW_128, 'LP_KEY');
    let path_count: usize = path_count_felt.try_into().expect('LP_PATH');
    assert(path_cursor + path_count <= path_values.len(), 'LP_PATH');
    assert(path_cursor + path_count <= path_directions.len(), 'LP_PATH');

    let output_root = if prior_root == 0 {
        assert(prior_commitment == 0, 'LP_PRIOR');
        assert(output_commitment != 0, 'LP_OUTPUT');
        assert(path_count == 0, 'LP_PATH');
        liquidity_position_sparse_root_from_empty(position_id, key_low, key_high, output_commitment)
    } else {
        assert(path_count == LIQUIDITY_POSITION_SPARSE_TREE_DEPTH, 'LP_PATH');
        let prior_leaf = if prior_commitment == 0 {
            0
        } else {
            liquidity_position_sparse_leaf(position_id, prior_commitment)
        };
        assert(
            liquidity_position_root_from_path_at(
                prior_leaf, key_low, path_cursor, path_values, path_directions,
            ) == prior_root,
            'LP_ROOT',
        );
        let output_leaf = if output_commitment == 0 {
            0
        } else {
            liquidity_position_sparse_leaf(position_id, output_commitment)
        };
        let next_root = liquidity_position_root_from_path_at(
            output_leaf, key_low, path_cursor, path_values, path_directions,
        );
        if output_commitment == 0
            && liquidity_position_path_is_canonical_empty_at(path_cursor, path_values) {
            0
        } else {
            next_root
        }
    };
    path_cursor += path_count;
    output_root
}

fn liquidity_position_root_from_path_at(
    leaf: felt252,
    expected_key_low: u128,
    path_cursor: usize,
    path: Span<felt252>,
    directions: Span<felt252>,
) -> felt252 {
    assert(path_cursor + LIQUIDITY_POSITION_SPARSE_TREE_DEPTH <= path.len(), 'LP_PATH');
    assert(path_cursor + LIQUIDITY_POSITION_SPARSE_TREE_DEPTH <= directions.len(), 'LP_PATH');
    let mut root = leaf;
    let mut key_low = expected_key_low;
    let mut level = 0;
    while level < LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
        let expected_direction: felt252 = (key_low % 2).into();
        let direction = *directions.at(path_cursor + level);
        assert(direction == expected_direction, 'LP_DIRECTION');
        let sibling = *path.at(path_cursor + level);
        root =
            if direction == 0 {
                liquidity_position_sparse_node(root, sibling, level)
            } else {
                liquidity_position_sparse_node(sibling, root, level)
            };
        key_low /= 2;
        level += 1;
    }
    root
}

fn liquidity_position_path_is_canonical_empty_at(path_cursor: usize, path: Span<felt252>) -> bool {
    if path_cursor + LIQUIDITY_POSITION_SPARSE_TREE_DEPTH > path.len() {
        return false;
    }
    let mut empty = 0;
    let mut level = 0;
    while level < LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
        if *path.at(path_cursor + level) != empty {
            return false;
        }
        empty = liquidity_position_sparse_node(empty, empty, level);
        level += 1;
    }
    true
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

fn assert_liquidity_position_transitions(
    kinds: Span<felt252>,
    consumed_commitments: Span<felt252>,
    nullifiers: Span<felt252>,
    output_commitments: Span<felt252>,
) {
    assert(kinds.len() == consumed_commitments.len(), 'E');
    assert(kinds.len() == nullifiers.len(), 'E');
    assert(kinds.len() == output_commitments.len(), 'E');
    assert(kinds.len() <= MAX_LIQUIDITY_POSITION_TRANSITIONS, 'E');
    let mut index = 0;
    while index < kinds.len() {
        let kind = *kinds.at(index);
        let consumed = *consumed_commitments.at(index);
        let nullifier = *nullifiers.at(index);
        let output = *output_commitments.at(index);
        if kind == 0 {
            assert(consumed == 0, 'E');
            assert(nullifier == 0, 'E');
            assert(output != 0, 'E');
        } else if kind == 1 || kind == 4 {
            assert(consumed != 0, 'E');
            assert(nullifier != 0, 'E');
            assert(output != 0, 'E');
        } else if kind == 2 {
            assert(consumed != 0, 'E');
            assert(nullifier != 0, 'E');
            assert(output == 0, 'E');
        } else {
            assert(false, 'E');
        }
        index += 1;
    }
    assert_unique_nonzero(nullifiers, 'E');
    assert_unique_nonzero(output_commitments, 'E');
}

fn assert_liquidity_position_fill_transition_witnesses(
    prior_root: felt252,
    transition_root_domain: felt252,
    state_transition_root_domain: felt252,
    batch_pair_id: felt252,
    batch_epoch: felt252,
    batch_base_asset_id: felt252,
    batch_quote_asset_id: felt252,
    batch_clearing_price: felt252,
    batch_price_base_scale: felt252,
    kinds: Span<felt252>,
    consumed_commitments: Span<felt252>,
    nullifiers: Span<felt252>,
    output_commitments: Span<felt252>,
    prior_position_fields: Span<felt252>,
    output_position_fields: Span<felt252>,
    position_sides: Span<felt252>,
    filled_base_amounts: Span<felt252>,
    clearing_prices: Span<felt252>,
    price_base_scales: Span<felt252>,
    market_reference_prices: Span<felt252>,
    market_confirmation_prices: Span<felt252>,
    market_observed_at_unix_ms: Span<felt252>,
    market_current_time_unix_ms: Span<felt252>,
    oracle_guard_ids: Span<felt252>,
    oracle_guard_max_staleness_ms: Span<felt252>,
    oracle_guard_max_divergence_bps: Span<felt252>,
    state_position_ids: Span<felt252>,
    state_key_lows: Span<felt252>,
    state_key_highs: Span<felt252>,
    state_prior_commitments: Span<felt252>,
    state_output_commitments: Span<felt252>,
    state_path_counts: Span<felt252>,
    state_path_values: Span<felt252>,
    state_path_directions: Span<felt252>,
    lifecycle_signature_rs: Span<felt252>,
    lifecycle_signature_ss: Span<felt252>,
    lifecycle_base_amounts: Span<felt252>,
    lifecycle_quote_amounts: Span<felt252>,
    open_input_counts: Span<felt252>,
    open_input_note_commitments: Span<felt252>,
    open_input_asset_ids: Span<felt252>,
    open_input_amounts: Span<felt252>,
    open_input_owner_keys: Span<felt252>,
    open_input_spend_authorities: Span<felt252>,
    open_input_withdraw_authorities: Span<felt252>,
    open_input_blindings: Span<felt252>,
    open_input_nonces: Span<felt252>,
    open_input_metadata_commitments: Span<felt252>,
    lifecycle_output_counts: Span<felt252>,
    note_commitment_domain: felt252,
    nullifier_domain: felt252,
    prior_note_root: felt252,
    consumed_note_commitments: Span<felt252>,
    consumed_nullifiers: Span<felt252>,
    note_membership_kinds: Span<felt252>,
    note_membership_prefix_roots: Span<felt252>,
    note_membership_batch_roots: Span<felt252>,
    note_membership_path_counts: Span<felt252>,
    note_membership_path_values: Span<felt252>,
    note_membership_path_directions: Span<felt252>,
    note_membership_suffix_counts: Span<felt252>,
    note_membership_suffix_roots: Span<felt252>,
    ref consumed_input_cursor: usize,
    ref note_membership_path_cursor: usize,
    ref note_membership_suffix_cursor: usize,
    output_note_commitments: Span<felt252>,
    output_note_asset_ids: Span<felt252>,
    output_note_amounts: Span<felt252>,
    output_note_withdraw_authorities: Span<felt252>,
    output_note_owner_keys: Span<felt252>,
    output_note_spend_authorities: Span<felt252>,
    output_note_blindings: Span<felt252>,
    output_note_nonces: Span<felt252>,
    output_note_metadata_commitments: Span<felt252>,
    ref public_output_cursor: usize,
) -> (felt252, felt252, u128, u128) {
    assert_liquidity_position_transitions(
        kinds, consumed_commitments, nullifiers, output_commitments,
    );
    assert_all_lengths_match(
        kinds.len(),
        array![
            position_sides.len().into(), filled_base_amounts.len().into(),
            clearing_prices.len().into(), price_base_scales.len().into(),
            market_reference_prices.len().into(), market_confirmation_prices.len().into(),
            market_observed_at_unix_ms.len().into(), market_current_time_unix_ms.len().into(),
            oracle_guard_ids.len().into(), oracle_guard_max_staleness_ms.len().into(),
            oracle_guard_max_divergence_bps.len().into(), state_position_ids.len().into(),
            state_key_lows.len().into(), state_key_highs.len().into(),
            state_prior_commitments.len().into(), state_output_commitments.len().into(),
            state_path_counts.len().into(), lifecycle_signature_rs.len().into(),
            lifecycle_signature_ss.len().into(), lifecycle_base_amounts.len().into(),
            lifecycle_quote_amounts.len().into(), open_input_counts.len().into(),
            lifecycle_output_counts.len().into(),
        ]
            .span(),
        'E',
    );
    assert(prior_position_fields.len() == kinds.len() * LIQUIDITY_POSITION_FIELD_COUNT, 'E');
    assert(output_position_fields.len() == kinds.len() * LIQUIDITY_POSITION_FIELD_COUNT, 'E');
    assert(state_path_values.len() == state_path_directions.len(), 'E');
    assert(open_input_note_commitments.len() == open_input_asset_ids.len(), 'LP_OPEN_INPUT');
    assert(open_input_note_commitments.len() == open_input_amounts.len(), 'LP_OPEN_INPUT');
    assert(open_input_note_commitments.len() == open_input_owner_keys.len(), 'LP_OPEN_INPUT');
    assert(
        open_input_note_commitments.len() == open_input_spend_authorities.len(), 'LP_OPEN_INPUT',
    );
    assert(
        open_input_note_commitments.len() == open_input_withdraw_authorities.len(), 'LP_OPEN_INPUT',
    );
    assert(open_input_note_commitments.len() == open_input_blindings.len(), 'LP_OPEN_INPUT');
    assert(open_input_note_commitments.len() == open_input_nonces.len(), 'LP_OPEN_INPUT');
    assert(
        open_input_note_commitments.len() == open_input_metadata_commitments.len(), 'LP_OPEN_INPUT',
    );
    assert(output_note_commitments.len() == output_note_asset_ids.len(), 'E');
    assert(output_note_commitments.len() == output_note_amounts.len(), 'E');
    assert(output_note_commitments.len() == output_note_withdraw_authorities.len(), 'E');
    assert(output_note_commitments.len() == output_note_owner_keys.len(), 'E');
    assert(output_note_commitments.len() == output_note_spend_authorities.len(), 'E');
    assert(output_note_commitments.len() == output_note_blindings.len(), 'E');
    assert(output_note_commitments.len() == output_note_nonces.len(), 'E');
    assert(output_note_commitments.len() == output_note_metadata_commitments.len(), 'E');
    assert(state_transition_root_domain == STATE_TRANSITION_ROOT_DOMAIN, 'E');

    let transition_root = four_field_root(
        transition_root_domain, kinds, consumed_commitments, nullifiers, output_commitments,
    );
    let mut running_root = prior_root;
    let mut path_cursor = 0;
    let mut open_input_cursor = 0;
    let mut buy_base: u128 = 0;
    let mut sell_base: u128 = 0;
    let mut index = 0;
    while index < kinds.len() {
        let kind = *kinds.at(index);
        let mut prior_commitment: felt252 = 0;
        let mut nullifier: felt252 = 0;
        let mut output_commitment: felt252 = 0;
        let mut position_id: felt252 = 0;

        if kind == 0 {
            assert_empty_liquidity_position_at(prior_position_fields, index);
            assert_non_fill_transition_fields_are_zero(
                index,
                position_sides,
                filled_base_amounts,
                clearing_prices,
                price_base_scales,
                market_reference_prices,
                market_confirmation_prices,
                market_observed_at_unix_ms,
                market_current_time_unix_ms,
                oracle_guard_ids,
                oracle_guard_max_staleness_ms,
                oracle_guard_max_divergence_bps,
                lifecycle_base_amounts,
                lifecycle_quote_amounts,
            );
            assert_live_liquidity_position_at(output_position_fields, index);
            assert_liquidity_position_pair_at(
                output_position_fields,
                index,
                batch_pair_id,
                batch_base_asset_id,
                batch_quote_asset_id,
            );
            assert(
                liquidity_position_field(output_position_fields, index, 23) == batch_epoch,
                'LP_EPOCH',
            );
            output_commitment = liquidity_position_commitment_at(output_position_fields, index);
            position_id = liquidity_position_field(output_position_fields, index, 1);
            assert(*consumed_commitments.at(index) == 0, 'LP_COMMITMENT');
            assert(*nullifiers.at(index) == 0, 'LP_NULLIFIER');
            assert(*output_commitments.at(index) == output_commitment, 'LP_OUTPUT');

            let (funding_base, funding_quote) = assert_liquidity_position_open_inputs_at(
                index,
                output_position_fields,
                note_commitment_domain,
                nullifier_domain,
                prior_note_root,
                open_input_counts,
                open_input_note_commitments,
                open_input_asset_ids,
                open_input_amounts,
                open_input_owner_keys,
                open_input_spend_authorities,
                open_input_withdraw_authorities,
                open_input_blindings,
                open_input_nonces,
                open_input_metadata_commitments,
                consumed_note_commitments,
                consumed_nullifiers,
                note_membership_kinds,
                note_membership_prefix_roots,
                note_membership_batch_roots,
                note_membership_path_counts,
                note_membership_path_values,
                note_membership_path_directions,
                note_membership_suffix_counts,
                note_membership_suffix_roots,
                ref open_input_cursor,
                ref consumed_input_cursor,
                ref note_membership_path_cursor,
                ref note_membership_suffix_cursor,
                state_transition_root_domain,
            );
            let (change_base, change_quote) = assert_liquidity_position_lifecycle_outputs_at(
                index,
                output_position_fields,
                note_commitment_domain,
                lifecycle_output_counts,
                output_note_commitments,
                output_note_asset_ids,
                output_note_amounts,
                output_note_withdraw_authorities,
                output_note_owner_keys,
                output_note_spend_authorities,
                output_note_blindings,
                output_note_nonces,
                output_note_metadata_commitments,
                ref public_output_cursor,
            );
            assert(
                funding_base == felt_to_u128(
                    liquidity_position_field(output_position_fields, index, 8),
                )
                    + change_base,
                'LP_OPEN_BASE',
            );
            assert(
                funding_quote == felt_to_u128(
                    liquidity_position_field(output_position_fields, index, 9),
                )
                    + change_quote,
                'LP_OPEN_QUOTE',
            );
            assert_liquidity_position_lifecycle_authorization_at(
                0,
                position_id,
                0,
                output_commitment,
                batch_epoch,
                0,
                0,
                liquidity_position_field(output_position_fields, index, 7),
                *lifecycle_signature_rs.at(index),
                *lifecycle_signature_ss.at(index),
            );
        } else if kind == 1 {
            assert_fill_transition_lifecycle_fields_are_zero(
                index,
                lifecycle_signature_rs,
                lifecycle_signature_ss,
                lifecycle_base_amounts,
                lifecycle_quote_amounts,
                open_input_counts,
                lifecycle_output_counts,
            );
            assert(*clearing_prices.at(index) == batch_clearing_price, 'LP_PRICE');
            assert(*price_base_scales.at(index) == batch_price_base_scale, 'LP_PRICE_SCALE');
            assert_live_liquidity_position_at(prior_position_fields, index);
            assert_liquidity_position_pair_at(
                prior_position_fields,
                index,
                batch_pair_id,
                batch_base_asset_id,
                batch_quote_asset_id,
            );
            assert_oracle_context_for_position_fill_at(
                prior_position_fields,
                index,
                *clearing_prices.at(index),
                *market_reference_prices.at(index),
                *market_confirmation_prices.at(index),
                *market_observed_at_unix_ms.at(index),
                *market_current_time_unix_ms.at(index),
                *oracle_guard_ids.at(index),
                *oracle_guard_max_staleness_ms.at(index),
                *oracle_guard_max_divergence_bps.at(index),
            );
            let (fill_prior_commitment, fill_nullifier, fill_output_commitment) =
                assert_liquidity_position_fill_at(
                prior_position_fields,
                output_position_fields,
                index,
                *position_sides.at(index),
                *filled_base_amounts.at(index),
                batch_epoch,
                *clearing_prices.at(index),
                *price_base_scales.at(index),
                *market_reference_prices.at(index),
            );
            prior_commitment = fill_prior_commitment;
            nullifier = fill_nullifier;
            output_commitment = fill_output_commitment;
            position_id = liquidity_position_field(prior_position_fields, index, 1);
            let filled_base_amount = felt_to_u128(*filled_base_amounts.at(index));
            if *position_sides.at(index) == ORDER_SIDE_BUY {
                buy_base += filled_base_amount;
            } else {
                assert(*position_sides.at(index) == ORDER_SIDE_SELL, 'LP_SIDE');
                sell_base += filled_base_amount;
            }
        } else if kind == 2 {
            assert_empty_liquidity_position_at(output_position_fields, index);
            assert_non_fill_transition_fields_are_zero(
                index,
                position_sides,
                filled_base_amounts,
                clearing_prices,
                price_base_scales,
                market_reference_prices,
                market_confirmation_prices,
                market_observed_at_unix_ms,
                market_current_time_unix_ms,
                oracle_guard_ids,
                oracle_guard_max_staleness_ms,
                oracle_guard_max_divergence_bps,
                lifecycle_base_amounts,
                lifecycle_quote_amounts,
            );
            assert(*open_input_counts.at(index) == 0, 'LP_OPEN_INPUT');
            assert_live_liquidity_position_at(prior_position_fields, index);
            assert_liquidity_position_pair_at(
                prior_position_fields,
                index,
                batch_pair_id,
                batch_base_asset_id,
                batch_quote_asset_id,
            );
            prior_commitment = liquidity_position_commitment_at(prior_position_fields, index);
            nullifier =
                liquidity_position_nullifier(
                    prior_commitment, liquidity_position_field(prior_position_fields, index, 25),
                );
            position_id = liquidity_position_field(prior_position_fields, index, 1);
            let expected_base = felt_to_u128(
                liquidity_position_field(prior_position_fields, index, 8),
            );
            let expected_quote = felt_to_u128(
                liquidity_position_field(prior_position_fields, index, 9),
            );
            let (output_base, output_quote) = assert_liquidity_position_lifecycle_outputs_at(
                index,
                prior_position_fields,
                note_commitment_domain,
                lifecycle_output_counts,
                output_note_commitments,
                output_note_asset_ids,
                output_note_amounts,
                output_note_withdraw_authorities,
                output_note_owner_keys,
                output_note_spend_authorities,
                output_note_blindings,
                output_note_nonces,
                output_note_metadata_commitments,
                ref public_output_cursor,
            );
            assert(output_base == expected_base, 'LP_CLOSE_BASE');
            assert(output_quote == expected_quote, 'LP_CLOSE_QUOTE');
            assert_liquidity_position_lifecycle_authorization_at(
                2,
                position_id,
                prior_commitment,
                0,
                batch_epoch,
                expected_base.into(),
                expected_quote.into(),
                liquidity_position_field(prior_position_fields, index, 7),
                *lifecycle_signature_rs.at(index),
                *lifecycle_signature_ss.at(index),
            );
        } else {
            assert(kind == 4, 'LP_KIND');
            assert_non_fill_transition_fields_are_zero(
                index,
                position_sides,
                filled_base_amounts,
                clearing_prices,
                price_base_scales,
                market_reference_prices,
                market_confirmation_prices,
                market_observed_at_unix_ms,
                market_current_time_unix_ms,
                oracle_guard_ids,
                oracle_guard_max_staleness_ms,
                oracle_guard_max_divergence_bps,
                lifecycle_base_amounts,
                lifecycle_quote_amounts,
            );
            assert(*open_input_counts.at(index) == 0, 'LP_OPEN_INPUT');
            assert(*lifecycle_output_counts.at(index) == 0, 'LP_LIFECYCLE_OUTPUT');
            assert_live_liquidity_position_at(prior_position_fields, index);
            assert_live_liquidity_position_at(output_position_fields, index);
            assert_liquidity_position_pair_at(
                prior_position_fields,
                index,
                batch_pair_id,
                batch_base_asset_id,
                batch_quote_asset_id,
            );
            assert_liquidity_position_reconfiguration_at(
                prior_position_fields, output_position_fields, index,
            );
            prior_commitment = liquidity_position_commitment_at(prior_position_fields, index);
            output_commitment = liquidity_position_commitment_at(output_position_fields, index);
            nullifier =
                liquidity_position_nullifier(
                    prior_commitment, liquidity_position_field(prior_position_fields, index, 25),
                );
            position_id = liquidity_position_field(prior_position_fields, index, 1);
            assert_liquidity_position_lifecycle_authorization_at(
                4,
                position_id,
                prior_commitment,
                output_commitment,
                batch_epoch,
                0,
                0,
                liquidity_position_field(prior_position_fields, index, 7),
                *lifecycle_signature_rs.at(index),
                *lifecycle_signature_ss.at(index),
            );
        }
        assert(*consumed_commitments.at(index) == prior_commitment, 'LP_COMMITMENT');
        assert(*nullifiers.at(index) == nullifier, 'LP_NULLIFIER');
        assert(*output_commitments.at(index) == output_commitment, 'LP_OUTPUT');
        assert(*state_position_ids.at(index) == position_id, 'LP_ID');
        assert(*state_prior_commitments.at(index) == prior_commitment, 'LP_STATE_PRIOR');
        assert(*state_output_commitments.at(index) == output_commitment, 'LP_STATE_OUTPUT');
        running_root =
            assert_liquidity_position_sparse_update_from_cursor(
                running_root,
                *state_position_ids.at(index),
                *state_key_lows.at(index),
                *state_key_highs.at(index),
                *state_prior_commitments.at(index),
                *state_output_commitments.at(index),
                *state_path_counts.at(index),
                ref path_cursor,
                state_path_values,
                state_path_directions,
            );
        index += 1;
    }
    assert(path_cursor == state_path_values.len(), 'LP_PATH');
    assert(path_cursor == state_path_directions.len(), 'LP_PATH');
    assert(open_input_cursor == open_input_note_commitments.len(), 'LP_OPEN_INPUT');
    (transition_root, running_root, buy_base, sell_base)
}

fn assert_liquidity_position_root_transition_witnesses(
    prior_root: felt252,
    transition_root_domain: felt252,
    state_transition_root_domain: felt252,
    kinds: Span<felt252>,
    consumed_commitments: Span<felt252>,
    nullifiers: Span<felt252>,
    output_commitments: Span<felt252>,
    state_position_ids: Span<felt252>,
    state_key_lows: Span<felt252>,
    state_key_highs: Span<felt252>,
    state_prior_commitments: Span<felt252>,
    state_output_commitments: Span<felt252>,
    state_path_counts: Span<felt252>,
    state_path_values: Span<felt252>,
    state_path_directions: Span<felt252>,
) -> (felt252, felt252) {
    assert_liquidity_position_transitions(
        kinds, consumed_commitments, nullifiers, output_commitments,
    );
    assert_all_lengths_match(
        kinds.len(),
        array![
            state_position_ids.len().into(), state_key_lows.len().into(),
            state_key_highs.len().into(), state_prior_commitments.len().into(),
            state_output_commitments.len().into(), state_path_counts.len().into(),
        ]
            .span(),
        'LP_ROOT',
    );
    assert(state_path_values.len() == state_path_directions.len(), 'LP_PATH');
    assert(state_transition_root_domain == STATE_TRANSITION_ROOT_DOMAIN, 'E');

    let transition_root = four_field_root(
        transition_root_domain, kinds, consumed_commitments, nullifiers, output_commitments,
    );
    let mut running_root = prior_root;
    let mut path_cursor = 0;
    let mut index = 0;
    while index < kinds.len() {
        let kind = *kinds.at(index);
        let consumed = *consumed_commitments.at(index);
        let output = *output_commitments.at(index);
        if kind == 0 {
            assert(*state_prior_commitments.at(index) == 0, 'LP_STATE_PRIOR');
            assert(*state_output_commitments.at(index) == output, 'LP_STATE_OUTPUT');
        } else if kind == 2 {
            assert(*state_prior_commitments.at(index) == consumed, 'LP_STATE_PRIOR');
            assert(*state_output_commitments.at(index) == 0, 'LP_STATE_OUTPUT');
        } else {
            assert(kind == 1 || kind == 4, 'LP_KIND');
            assert(*state_prior_commitments.at(index) == consumed, 'LP_STATE_PRIOR');
            assert(*state_output_commitments.at(index) == output, 'LP_STATE_OUTPUT');
        }
        running_root =
            assert_liquidity_position_sparse_update_from_cursor(
                running_root,
                *state_position_ids.at(index),
                *state_key_lows.at(index),
                *state_key_highs.at(index),
                *state_prior_commitments.at(index),
                *state_output_commitments.at(index),
                *state_path_counts.at(index),
                ref path_cursor,
                state_path_values,
                state_path_directions,
            );
        index += 1;
    }
    assert(path_cursor == state_path_values.len(), 'LP_PATH');
    assert(path_cursor == state_path_directions.len(), 'LP_PATH');
    (transition_root, running_root)
}

fn assert_empty_liquidity_position_at(fields: Span<felt252>, position_index: usize) {
    let mut field_index = 0;
    while field_index < LIQUIDITY_POSITION_FIELD_COUNT {
        assert(liquidity_position_field(fields, position_index, field_index) == 0, 'LP_EMPTY');
        field_index += 1;
    }
}

fn assert_live_liquidity_position_at(fields: Span<felt252>, position_index: usize) {
    assert(liquidity_position_field(fields, position_index, 0) == 1, 'LP_VERSION');
    assert(liquidity_position_field(fields, position_index, 1) != 0, 'LP_ID');
    assert(liquidity_position_field(fields, position_index, 2) == 0, 'LP_BACKING');
    assert(liquidity_position_field(fields, position_index, 3) == 1, 'LP_STATUS');
    assert(liquidity_position_field(fields, position_index, 4) != 0, 'LP_PAIR');
    assert(liquidity_position_field(fields, position_index, 5) != 0, 'LP_BASE_ASSET');
    assert(liquidity_position_field(fields, position_index, 6) != 0, 'LP_QUOTE_ASSET');
    assert(
        liquidity_position_field(
            fields, position_index, 5,
        ) != liquidity_position_field(fields, position_index, 6),
        'LP_ASSET',
    );
    assert(liquidity_position_field(fields, position_index, 7) != 0, 'LP_OWNER');
    let base_reserve = felt_to_u128(liquidity_position_field(fields, position_index, 8));
    let quote_reserve = felt_to_u128(liquidity_position_field(fields, position_index, 9));
    assert(base_reserve != 0 || quote_reserve != 0, 'LP_RESERVE');
    let lower_price = felt_to_u128(liquidity_position_field(fields, position_index, 10));
    let upper_price = felt_to_u128(liquidity_position_field(fields, position_index, 11));
    assert(lower_price != 0, 'LP_PRICE');
    assert(lower_price < upper_price, 'LP_PRICE');
    assert(felt_to_u128(liquidity_position_field(fields, position_index, 12)) != 0, 'LP_FILL');
    let curve_kind = liquidity_position_field(fields, position_index, 13);
    assert(curve_kind == 0 || curve_kind == 1 || curve_kind == 2, 'LP_POLICY');
    let band_count = felt_to_u128(liquidity_position_field(fields, position_index, 14));
    assert(band_count >= 3, 'LP_POLICY');
    assert(band_count <= 8, 'LP_POLICY');
    assert(
        felt_to_u128(liquidity_position_field(fields, position_index, 15)) <= FEE_BPS_DENOMINATOR,
        'LP_SPREAD',
    );
    assert(
        felt_to_u128(liquidity_position_field(fields, position_index, 16)) <= FEE_BPS_DENOMINATOR,
        'LP_POLICY',
    );
    assert(
        felt_to_u128(liquidity_position_field(fields, position_index, 17)) <= FEE_BPS_DENOMINATOR,
        'LP_POLICY',
    );
    assert(
        felt_to_u128(liquidity_position_field(fields, position_index, 18)) <= FEE_BPS_DENOMINATOR,
        'LP_POLICY',
    );
    assert(
        felt_to_u128(
            liquidity_position_field(fields, position_index, 20),
        ) <= MAX_LIQUIDITY_POSITION_ROTATION_BPS,
        'LP_ROTATE',
    );
    assert(
        felt_to_u128(
            liquidity_position_field(fields, position_index, 21),
        ) <= MAX_LIQUIDITY_POSITION_ROTATION_BPS,
        'LP_ROTATE',
    );
    assert(
        felt_to_u128(liquidity_position_field(fields, position_index, 22)) <= FEE_BPS_DENOMINATOR,
        'LP_ROTATE',
    );
    let opened_epoch = felt_to_u128(liquidity_position_field(fields, position_index, 23));
    let expiry_epoch = felt_to_u128(liquidity_position_field(fields, position_index, 24));
    assert(opened_epoch != 0, 'LP_EPOCH');
    assert(expiry_epoch > opened_epoch, 'LP_EPOCH');
    assert(liquidity_position_field(fields, position_index, 25) != 0, 'LP_BLINDING');
    assert(liquidity_position_field(fields, position_index, 26) != 0, 'LP_METADATA');
}

fn assert_liquidity_position_pair_at(
    fields: Span<felt252>,
    position_index: usize,
    pair_id: felt252,
    base_asset_id: felt252,
    quote_asset_id: felt252,
) {
    assert(liquidity_position_field(fields, position_index, 4) == pair_id, 'LP_PAIR');
    assert(liquidity_position_field(fields, position_index, 5) == base_asset_id, 'LP_BASE_ASSET');
    assert(liquidity_position_field(fields, position_index, 6) == quote_asset_id, 'LP_QUOTE_ASSET');
}

fn assert_non_fill_transition_fields_are_zero(
    position_index: usize,
    position_sides: Span<felt252>,
    filled_base_amounts: Span<felt252>,
    clearing_prices: Span<felt252>,
    price_base_scales: Span<felt252>,
    market_reference_prices: Span<felt252>,
    market_confirmation_prices: Span<felt252>,
    market_observed_at_unix_ms: Span<felt252>,
    market_current_time_unix_ms: Span<felt252>,
    oracle_guard_ids: Span<felt252>,
    oracle_guard_max_staleness_ms: Span<felt252>,
    oracle_guard_max_divergence_bps: Span<felt252>,
    lifecycle_base_amounts: Span<felt252>,
    lifecycle_quote_amounts: Span<felt252>,
) {
    assert_non_fill_execution_fields_are_zero(
        position_index,
        position_sides,
        filled_base_amounts,
        clearing_prices,
        price_base_scales,
        market_reference_prices,
        market_confirmation_prices,
        market_observed_at_unix_ms,
        market_current_time_unix_ms,
        oracle_guard_ids,
        oracle_guard_max_staleness_ms,
        oracle_guard_max_divergence_bps,
    );
    assert(*lifecycle_base_amounts.at(position_index) == 0, 'LP_LIFECYCLE_AMOUNT');
    assert(*lifecycle_quote_amounts.at(position_index) == 0, 'LP_LIFECYCLE_AMOUNT');
}

fn assert_non_fill_execution_fields_are_zero(
    position_index: usize,
    position_sides: Span<felt252>,
    filled_base_amounts: Span<felt252>,
    clearing_prices: Span<felt252>,
    price_base_scales: Span<felt252>,
    market_reference_prices: Span<felt252>,
    market_confirmation_prices: Span<felt252>,
    market_observed_at_unix_ms: Span<felt252>,
    market_current_time_unix_ms: Span<felt252>,
    oracle_guard_ids: Span<felt252>,
    oracle_guard_max_staleness_ms: Span<felt252>,
    oracle_guard_max_divergence_bps: Span<felt252>,
) {
    assert(*position_sides.at(position_index) == 0, 'LP_FILL');
    assert(*filled_base_amounts.at(position_index) == 0, 'LP_FILL');
    assert(*clearing_prices.at(position_index) == 0, 'LP_PRICE');
    assert(*price_base_scales.at(position_index) == 0, 'LP_PRICE_SCALE');
    assert(*market_reference_prices.at(position_index) == 0, 'LP_ORACLE');
    assert(*market_confirmation_prices.at(position_index) == 0, 'LP_ORACLE');
    assert(*market_observed_at_unix_ms.at(position_index) == 0, 'LP_ORACLE');
    assert(*market_current_time_unix_ms.at(position_index) == 0, 'LP_ORACLE');
    assert(*oracle_guard_ids.at(position_index) == 0, 'LP_ORACLE');
    assert(*oracle_guard_max_staleness_ms.at(position_index) == 0, 'LP_ORACLE');
    assert(*oracle_guard_max_divergence_bps.at(position_index) == 0, 'LP_ORACLE');
}

fn assert_fill_transition_lifecycle_fields_are_zero(
    position_index: usize,
    lifecycle_signature_rs: Span<felt252>,
    lifecycle_signature_ss: Span<felt252>,
    lifecycle_base_amounts: Span<felt252>,
    lifecycle_quote_amounts: Span<felt252>,
    open_input_counts: Span<felt252>,
    lifecycle_output_counts: Span<felt252>,
) {
    assert(*lifecycle_signature_rs.at(position_index) == 0, 'LP_FILL_AUTH_R');
    assert(*lifecycle_signature_ss.at(position_index) == 0, 'LP_FILL_AUTH_S');
    assert(*lifecycle_base_amounts.at(position_index) == 0, 'LP_LIFECYCLE_AMOUNT');
    assert(*lifecycle_quote_amounts.at(position_index) == 0, 'LP_LIFECYCLE_AMOUNT');
    assert(*open_input_counts.at(position_index) == 0, 'LP_OPEN_INPUT');
    assert(*lifecycle_output_counts.at(position_index) == 0, 'LP_LIFECYCLE_OUTPUT');
}

fn assert_liquidity_position_lifecycle_authorization_at(
    kind: felt252,
    position_id: felt252,
    prior_commitment: felt252,
    output_commitment: felt252,
    epoch: felt252,
    base_amount: felt252,
    quote_amount: felt252,
    owner_authority: felt252,
    signature_r: felt252,
    signature_s: felt252,
) {
    assert(owner_authority != 0, 'LP_OWNER');
    assert(signature_r != 0, 'LP_AUTH_R');
    assert(signature_s != 0, 'LP_AUTH_S');
    let message = liquidity_position_lifecycle_message_hash(
        kind, position_id, prior_commitment, output_commitment, epoch, base_amount, quote_amount,
    );
    assert_stwo_spend_authorization(
        message, owner_authority, signature_r, signature_s, 'LP_AUTH_SIG',
    );
}

fn liquidity_position_lifecycle_message_hash(
    kind: felt252,
    position_id: felt252,
    prior_commitment: felt252,
    output_commitment: felt252,
    epoch: felt252,
    base_amount: felt252,
    quote_amount: felt252,
) -> felt252 {
    let mut state = LIQUIDITY_POSITION_LIFECYCLE_AUTHORIZATION_DOMAIN;
    state = poseidon_hash2(state, kind);
    state = poseidon_hash2(state, position_id);
    state = poseidon_hash2(state, prior_commitment);
    state = poseidon_hash2(state, output_commitment);
    state = poseidon_hash2(state, epoch);
    state = poseidon_hash2(state, base_amount);
    poseidon_hash2(state, quote_amount)
}

fn assert_relative_difference_within_bps(left: u128, right: u128, limit_bps: u128) {
    assert(left != 0, 'LP_ORACLE');
    assert(right != 0, 'LP_ORACLE');
    let denominator = if left < right {
        left
    } else {
        right
    };
    let difference = if left >= right {
        left - right
    } else {
        right - left
    };
    assert(difference * FEE_BPS_DENOMINATOR <= limit_bps * denominator, 'LP_ORACLE');
}

fn assert_oracle_context_for_position_fill_at(
    fields: Span<felt252>,
    position_index: usize,
    clearing_price_felt: felt252,
    reference_price_felt: felt252,
    confirmation_price_felt: felt252,
    observed_at_unix_ms_felt: felt252,
    current_time_unix_ms_felt: felt252,
    oracle_guard_id: felt252,
    oracle_guard_max_staleness_ms_felt: felt252,
    oracle_guard_max_divergence_bps_felt: felt252,
) {
    let curve_kind = liquidity_position_field(fields, position_index, 13);
    assert(curve_kind == 0 || curve_kind == 1 || curve_kind == 2, 'LP_POLICY');
    let oracle_guard_commitment = liquidity_position_field(fields, position_index, 19);
    if oracle_guard_commitment == 0 {
        assert(curve_kind != 1, 'LP_ORACLE');
        assert(oracle_guard_id == 0, 'LP_ORACLE');
        assert(oracle_guard_max_staleness_ms_felt == 0, 'LP_ORACLE');
        assert(oracle_guard_max_divergence_bps_felt == 0, 'LP_ORACLE');
        return;
    }
    assert(oracle_guard_id != 0, 'LP_ORACLE');
    let oracle_guard_max_staleness_ms = felt_to_u128(oracle_guard_max_staleness_ms_felt);
    let oracle_guard_max_divergence_bps = felt_to_u128(oracle_guard_max_divergence_bps_felt);
    assert(oracle_guard_max_staleness_ms != 0, 'LP_ORACLE');
    assert(oracle_guard_max_divergence_bps <= FEE_BPS_DENOMINATOR, 'LP_ORACLE');
    let mut guard_state = LIQUIDITY_POSITION_ORACLE_GUARD_DOMAIN;
    guard_state = poseidon_hash2(guard_state, oracle_guard_id);
    guard_state = poseidon_hash2(guard_state, oracle_guard_max_staleness_ms_felt);
    guard_state = poseidon_hash2(guard_state, oracle_guard_max_divergence_bps_felt);
    assert(guard_state == oracle_guard_commitment, 'LP_ORACLE');

    let reference_price = felt_to_u128(reference_price_felt);
    let confirmation_price = felt_to_u128(confirmation_price_felt);
    let observed_at_unix_ms = felt_to_u128(observed_at_unix_ms_felt);
    let current_time_unix_ms = felt_to_u128(current_time_unix_ms_felt);
    assert(reference_price != 0, 'LP_ORACLE');
    assert(confirmation_price != 0, 'LP_ORACLE');
    assert(current_time_unix_ms >= observed_at_unix_ms, 'LP_ORACLE');
    assert(
        current_time_unix_ms - observed_at_unix_ms <= oracle_guard_max_staleness_ms, 'LP_ORACLE',
    );
    let mut policy_limit = oracle_guard_max_divergence_bps;
    let max_price_deviation_bps = felt_to_u128(
        liquidity_position_field(fields, position_index, 18),
    );
    if max_price_deviation_bps != 0 && max_price_deviation_bps < policy_limit {
        policy_limit = max_price_deviation_bps;
    }
    assert_relative_difference_within_bps(reference_price, confirmation_price, policy_limit);
    if max_price_deviation_bps != 0 {
        assert_relative_difference_within_bps(
            felt_to_u128(clearing_price_felt), reference_price, max_price_deviation_bps,
        );
    }
}

fn liquidity_position_canonical_fill_capacity_at(
    fields: Span<felt252>,
    position_index: usize,
    position_side: felt252,
    batch_epoch_felt: felt252,
    clearing_price: u128,
    price_base_scale: u128,
    market_reference_price_felt: felt252,
) -> u128 {
    let batch_epoch = felt_to_u128(batch_epoch_felt);
    let opened_epoch = felt_to_u128(liquidity_position_field(fields, position_index, 23));
    let expiry_epoch = felt_to_u128(liquidity_position_field(fields, position_index, 24));
    assert(batch_epoch >= opened_epoch, 'LP_EPOCH');
    assert(batch_epoch <= expiry_epoch, 'LP_EPOCH');
    assert(price_base_scale != 0, 'LP_PRICE_SCALE');

    let rotation_seed = liquidity_position_rotation_seed_at(
        fields, position_index, batch_epoch_felt,
    );
    let skip_epoch_bps = felt_to_u128(liquidity_position_field(fields, position_index, 22));
    if rotation_seed % FEE_BPS_DENOMINATOR < skip_epoch_bps {
        return 0;
    }

    let reference_price = liquidity_position_reference_price_at(
        fields, position_index, market_reference_price_felt,
    );
    let inventory_reference_price = liquidity_position_inventory_adjusted_reference_price_at(
        fields, position_index, reference_price, price_base_scale,
    );
    let effective_reference_price = liquidity_position_rotated_reference_price_at(
        fields, position_index, inventory_reference_price, rotation_seed,
    );

    let lower_price = felt_to_u128(liquidity_position_field(fields, position_index, 10));
    let upper_price = felt_to_u128(liquidity_position_field(fields, position_index, 11));
    let spread_bps = felt_to_u128(liquidity_position_field(fields, position_index, 15));
    let half_width_bps = (spread_bps + 1) / 2;
    assert(half_width_bps < FEE_BPS_DENOMINATOR, 'LP_SPREAD');

    if position_side == ORDER_SIDE_BUY {
        let quote_reserve = felt_to_u128(liquidity_position_field(fields, position_index, 9));
        let bid_high = u128_min(
            upper_price,
            mul_div_floor_u128(
                effective_reference_price,
                FEE_BPS_DENOMINATOR - half_width_bps,
                FEE_BPS_DENOMINATOR,
            ),
        );
        if quote_reserve == 0 || bid_high <= lower_price {
            return 0;
        }
        return liquidity_position_curve_capacity_from_ladder(
            fields,
            position_index,
            ORDER_SIDE_BUY,
            lower_price,
            bid_high,
            price_base_scale,
            rotation_seed,
            u128_rotate_left(rotation_seed, 41),
            quote_reserve,
            clearing_price,
        );
    }

    assert(position_side == ORDER_SIDE_SELL, 'LP_SIDE');
    let base_reserve = felt_to_u128(liquidity_position_field(fields, position_index, 8));
    let ask_low = u128_max(
        lower_price,
        mul_div_ceil_u128(
            effective_reference_price, FEE_BPS_DENOMINATOR + half_width_bps, FEE_BPS_DENOMINATOR,
        ),
    );
    if base_reserve == 0 || upper_price <= ask_low {
        return 0;
    }
    liquidity_position_curve_capacity_from_ladder(
        fields,
        position_index,
        ORDER_SIDE_SELL,
        ask_low,
        upper_price,
        price_base_scale,
        u128_rotate_left(rotation_seed, 17),
        u128_rotate_left(rotation_seed, 73),
        base_reserve,
        clearing_price,
    )
}

fn liquidity_position_rotation_seed_at(
    fields: Span<felt252>, position_index: usize, batch_epoch_felt: felt252,
) -> u128 {
    let mut state = LIQUIDITY_POSITION_CURVE_ROTATION_DOMAIN;
    state = poseidon_hash2(state, liquidity_position_field(fields, position_index, 1));
    state = poseidon_hash2(state, liquidity_position_field(fields, position_index, 25));
    state = poseidon_hash2(state, batch_epoch_felt);
    let modulus = u256 { low: 0, high: 1 };
    let state_u256: u256 = state.into();
    (state_u256 % modulus).try_into().expect('LP_SEED')
}

fn liquidity_position_reference_price_at(
    fields: Span<felt252>, position_index: usize, market_reference_price_felt: felt252,
) -> u128 {
    let curve_kind = liquidity_position_field(fields, position_index, 13);
    let oracle_guard_commitment = liquidity_position_field(fields, position_index, 19);
    if oracle_guard_commitment != 0 {
        let reference_price = felt_to_u128(market_reference_price_felt);
        assert(reference_price != 0, 'LP_ORACLE');
        return reference_price;
    }
    assert(curve_kind != 1, 'LP_ORACLE');
    let lower_price = felt_to_u128(liquidity_position_field(fields, position_index, 10));
    let upper_price = felt_to_u128(liquidity_position_field(fields, position_index, 11));
    lower_price + (upper_price - lower_price) / 2
}

fn liquidity_position_inventory_adjusted_reference_price_at(
    fields: Span<felt252>, position_index: usize, reference_price: u128, price_base_scale: u128,
) -> u128 {
    let curve_kind = liquidity_position_field(fields, position_index, 13);
    let inventory_skew_bps = felt_to_u128(liquidity_position_field(fields, position_index, 17));
    if curve_kind != 2 || inventory_skew_bps == 0 {
        return reference_price;
    }

    let base_reserve = felt_to_u128(liquidity_position_field(fields, position_index, 8));
    let quote_reserve = felt_to_u128(liquidity_position_field(fields, position_index, 9));
    let base_value = quote_amount_for_base_amount(base_reserve, reference_price, price_base_scale);
    let total_value = base_value + quote_reserve;
    if total_value == 0 {
        return reference_price;
    }

    let actual_base_ratio = mul_div_floor_u128(base_value, FEE_BPS_DENOMINATOR, total_value);
    let target_base_ratio = felt_to_u128(liquidity_position_field(fields, position_index, 16));
    let imbalance = u128_abs_diff(actual_base_ratio, target_base_ratio);
    let max_price_deviation_bps = felt_to_u128(
        liquidity_position_field(fields, position_index, 18),
    );
    let shift_bps = u128_min(
        mul_div_floor_u128(imbalance, inventory_skew_bps, FEE_BPS_DENOMINATOR),
        max_price_deviation_bps,
    );
    let delta = mul_div_floor_u128(reference_price, shift_bps, FEE_BPS_DENOMINATOR);
    let adjusted = if actual_base_ratio > target_base_ratio {
        if delta >= reference_price {
            1
        } else {
            reference_price - delta
        }
    } else {
        reference_price + delta
    };
    let lower_price = felt_to_u128(liquidity_position_field(fields, position_index, 10));
    let upper_price = felt_to_u128(liquidity_position_field(fields, position_index, 11));
    u128_clamp(adjusted, lower_price, upper_price)
}

fn liquidity_position_rotated_reference_price_at(
    fields: Span<felt252>, position_index: usize, reference_price: u128, rotation_seed: u128,
) -> u128 {
    let max_rotation_bps = felt_to_u128(liquidity_position_field(fields, position_index, 20));
    if max_rotation_bps == 0 {
        return reference_price;
    }
    let width = max_rotation_bps * 2 + 1;
    let sample = rotation_seed % width;
    let (increase, bps) = if sample >= max_rotation_bps {
        (true, sample - max_rotation_bps)
    } else {
        (false, max_rotation_bps - sample)
    };
    let delta = mul_div_floor_u128(reference_price, bps, FEE_BPS_DENOMINATOR);
    let rotated = if increase {
        reference_price + delta
    } else {
        if delta >= reference_price {
            1
        } else {
            reference_price - delta
        }
    };
    let lower_price = felt_to_u128(liquidity_position_field(fields, position_index, 10));
    let upper_price = felt_to_u128(liquidity_position_field(fields, position_index, 11));
    u128_clamp(rotated, lower_price, upper_price)
}

fn liquidity_position_curve_capacity_from_ladder(
    fields: Span<felt252>,
    position_index: usize,
    position_side: felt252,
    low: u128,
    high: u128,
    price_base_scale: u128,
    ladder_seed: u128,
    depth_seed: u128,
    reserve_amount: u128,
    clearing_price: u128,
) -> u128 {
    assert(low < high, 'LP_LADDER');
    let band_count: usize = liquidity_position_field(fields, position_index, 14)
        .try_into()
        .expect('LP_POLICY');
    assert(band_count >= MIN_LIQUIDITY_SLICE_POINTS, 'LP_POLICY');
    assert(band_count <= MAX_LIQUIDITY_SLICE_POINTS, 'LP_POLICY');

    let max_depth_rotation_bps = felt_to_u128(liquidity_position_field(fields, position_index, 21));
    let available_amount = liquidity_position_rotated_depth(
        reserve_amount, max_depth_rotation_bps, depth_seed,
    );
    let mut prices: Array<u128> = array![];
    let mut raw_amounts: Array<u128> = array![];
    let mut previous_price: u128 = 0;
    let mut point_index = 0;
    while point_index < band_count {
        let price = liquidity_position_rotated_price_ladder_point(
            fields, position_index, low, high, ladder_seed, point_index, band_count,
        );
        if point_index != 0 {
            assert(previous_price < price, 'LP_LADDER');
        }
        previous_price = price;
        let split = liquidity_position_split_amount_at(available_amount, band_count, point_index);
        let base_amount = if position_side == ORDER_SIDE_BUY {
            base_amount_affordable_for_quote(split, price, price_base_scale)
        } else {
            assert(position_side == ORDER_SIDE_SELL, 'LP_SIDE');
            split
        };
        if base_amount != 0 {
            prices.append(price);
            raw_amounts.append(base_amount);
        }
        point_index += 1;
    }
    if raw_amounts.len() < MIN_LIQUIDITY_SLICE_POINTS {
        return 0;
    }

    let adjusted_amounts = liquidity_position_cap_curve_amounts(
        raw_amounts.span(), felt_to_u128(liquidity_position_field(fields, position_index, 12)),
    );
    let mut capacity: u128 = 0;
    let mut retained_points = 0;
    let mut index = 0;
    while index < adjusted_amounts.len() {
        let amount = *adjusted_amounts.at(index);
        if amount != 0 {
            retained_points += 1;
            let price = *prices.at(index);
            let eligible = if position_side == ORDER_SIDE_BUY {
                price >= clearing_price
            } else {
                price <= clearing_price
            };
            if eligible {
                capacity += amount;
            }
        }
        index += 1;
    }
    if retained_points < MIN_LIQUIDITY_SLICE_POINTS {
        return 0;
    }
    capacity
}

fn liquidity_position_rotated_price_ladder_point(
    fields: Span<felt252>,
    position_index: usize,
    low: u128,
    high: u128,
    seed: u128,
    point_index: usize,
    band_count: usize,
) -> u128 {
    let denominator = usize_to_u128(band_count - 1);
    let distance = (high - low) * usize_to_u128(point_index) / denominator;
    let mut price = low + distance;
    let max_price_rotation_bps = felt_to_u128(liquidity_position_field(fields, position_index, 20));
    if point_index > 0 && point_index + 1 < band_count && max_price_rotation_bps > 0 {
        let mut max_jitter = (high - low) / u128_max(denominator * 4, 1);
        if max_jitter < 1 {
            max_jitter = 1;
        }
        let jitter = u128_rotate_left(seed, point_index) % max_jitter;
        let high_minus_one = high - 1;
        let remaining = high_minus_one - price;
        price += u128_min(jitter, remaining);
    }
    price
}

fn liquidity_position_split_amount_at(total: u128, count: usize, index: usize) -> u128 {
    let divisor = usize_to_u128(count);
    let quotient = total / divisor;
    let remainder = total % divisor;
    if usize_to_u128(index) < remainder {
        return quotient + 1;
    }
    quotient
}

fn liquidity_position_rotated_depth(total: u128, max_reduction_bps: u128, seed: u128) -> u128 {
    if max_reduction_bps == 0 {
        return total;
    }
    let reduction_bps = seed % (max_reduction_bps + 1);
    mul_div_floor_u128(total, FEE_BPS_DENOMINATOR - reduction_bps, FEE_BPS_DENOMINATOR)
}

fn liquidity_position_cap_curve_amounts(
    raw_amounts: Span<u128>, max_total_base: u128,
) -> Array<u128> {
    let mut total: u128 = 0;
    let mut index = 0;
    while index < raw_amounts.len() {
        total += *raw_amounts.at(index);
        index += 1;
    }
    let mut adjusted: Array<u128> = array![];
    if total <= max_total_base {
        let mut copy_index = 0;
        while copy_index < raw_amounts.len() {
            adjusted.append(*raw_amounts.at(copy_index));
            copy_index += 1;
        }
        return adjusted;
    }

    let mut used: u128 = 0;
    let mut scaled: Array<u128> = array![];
    let mut scale_index = 0;
    while scale_index < raw_amounts.len() {
        let amount = mul_div_floor_u128(*raw_amounts.at(scale_index), max_total_base, total);
        used += amount;
        scaled.append(amount);
        scale_index += 1;
    }
    let mut remainder = max_total_base - used;
    let mut remainder_index = 0;
    while remainder_index < scaled.len() {
        let mut amount = *scaled.at(remainder_index);
        if remainder != 0 {
            amount += 1;
            remainder -= 1;
        }
        adjusted.append(amount);
        remainder_index += 1;
    }
    adjusted
}

fn assert_liquidity_position_open_inputs_at(
    position_index: usize,
    position_fields: Span<felt252>,
    note_commitment_domain: felt252,
    nullifier_domain: felt252,
    prior_note_root: felt252,
    open_input_counts: Span<felt252>,
    open_input_note_commitments: Span<felt252>,
    open_input_asset_ids: Span<felt252>,
    open_input_amounts: Span<felt252>,
    open_input_owner_keys: Span<felt252>,
    open_input_spend_authorities: Span<felt252>,
    open_input_withdraw_authorities: Span<felt252>,
    open_input_blindings: Span<felt252>,
    open_input_nonces: Span<felt252>,
    open_input_metadata_commitments: Span<felt252>,
    consumed_note_commitments: Span<felt252>,
    consumed_nullifiers: Span<felt252>,
    note_membership_kinds: Span<felt252>,
    note_membership_prefix_roots: Span<felt252>,
    note_membership_batch_roots: Span<felt252>,
    note_membership_path_counts: Span<felt252>,
    note_membership_path_values: Span<felt252>,
    note_membership_path_directions: Span<felt252>,
    note_membership_suffix_counts: Span<felt252>,
    note_membership_suffix_roots: Span<felt252>,
    ref open_input_cursor: usize,
    ref consumed_input_cursor: usize,
    ref note_membership_path_cursor: usize,
    ref note_membership_suffix_cursor: usize,
    state_transition_root_domain: felt252,
) -> (u128, u128) {
    let count: usize = (*open_input_counts.at(position_index)).try_into().expect('LP_OPEN_INPUT');
    assert(count != 0, 'LP_OPEN_INPUT');
    assert(count <= MAX_ORDER_FUNDING_INPUTS, 'LP_OPEN_INPUT');
    assert(open_input_cursor + count <= open_input_note_commitments.len(), 'LP_OPEN_INPUT');
    let owner_authority = liquidity_position_field(position_fields, position_index, 7);
    let base_asset_id = liquidity_position_field(position_fields, position_index, 5);
    let quote_asset_id = liquidity_position_field(position_fields, position_index, 6);
    let mut base_total: u128 = 0;
    let mut quote_total: u128 = 0;
    let end = open_input_cursor + count;
    while open_input_cursor < end {
        assert(consumed_input_cursor < consumed_note_commitments.len(), 'LP_OPEN_INPUT');
        let note_commitment_value = *open_input_note_commitments.at(open_input_cursor);
        let asset_id = *open_input_asset_ids.at(open_input_cursor);
        let amount_felt = *open_input_amounts.at(open_input_cursor);
        let owner_key = *open_input_owner_keys.at(open_input_cursor);
        let spend_authority = *open_input_spend_authorities.at(open_input_cursor);
        let withdraw_authority = *open_input_withdraw_authorities.at(open_input_cursor);
        let blinding = *open_input_blindings.at(open_input_cursor);
        let nonce = *open_input_nonces.at(open_input_cursor);
        let metadata = *open_input_metadata_commitments.at(open_input_cursor);
        assert(note_commitment_value != 0, 'LP_OPEN_INPUT');
        assert(asset_id == base_asset_id || asset_id == quote_asset_id, 'LP_OPEN_INPUT');
        assert(amount_felt != 0, 'LP_OPEN_INPUT');
        assert(owner_key != 0, 'LP_OPEN_INPUT');
        assert(spend_authority == owner_authority, 'LP_OPEN_INPUT');
        assert(withdraw_authority != 0, 'LP_OPEN_INPUT');
        assert(blinding != 0, 'LP_OPEN_INPUT');
        assert(nonce != 0, 'LP_OPEN_INPUT');
        assert(metadata != 0, 'LP_OPEN_INPUT');
        assert(
            note_commitment(
                note_commitment_domain,
                asset_id,
                amount_felt,
                owner_key,
                spend_authority,
                withdraw_authority,
                blinding,
                nonce,
                metadata,
            ) == note_commitment_value,
            'LP_OPEN_INPUT',
        );
        assert(
            note_commitment_value == *consumed_note_commitments.at(consumed_input_cursor),
            'LP_OPEN_CONSUMED',
        );
        assert(
            note_nullifier(
                nullifier_domain, note_commitment_value, blinding,
            ) == *consumed_nullifiers
                .at(consumed_input_cursor),
            'LP_OPEN_INPUT',
        );
        assert_note_membership(
            note_commitment_value,
            asset_id,
            amount_felt,
            withdraw_authority,
            prior_note_root,
            *note_membership_kinds.at(consumed_input_cursor),
            *note_membership_prefix_roots.at(consumed_input_cursor),
            *note_membership_batch_roots.at(consumed_input_cursor),
            *note_membership_path_counts.at(consumed_input_cursor),
            ref note_membership_path_cursor,
            note_membership_path_values,
            note_membership_path_directions,
            *note_membership_suffix_counts.at(consumed_input_cursor),
            ref note_membership_suffix_cursor,
            note_membership_suffix_roots,
            state_transition_root_domain,
        );
        let amount = felt_to_u128(amount_felt);
        if asset_id == base_asset_id {
            base_total += amount;
        } else {
            quote_total += amount;
        }
        open_input_cursor += 1;
        consumed_input_cursor += 1;
    }
    (base_total, quote_total)
}

fn assert_liquidity_position_lifecycle_outputs_at(
    position_index: usize,
    position_fields: Span<felt252>,
    note_commitment_domain: felt252,
    lifecycle_output_counts: Span<felt252>,
    output_note_commitments: Span<felt252>,
    output_note_asset_ids: Span<felt252>,
    output_note_amounts: Span<felt252>,
    output_note_withdraw_authorities: Span<felt252>,
    output_note_owner_keys: Span<felt252>,
    output_note_spend_authorities: Span<felt252>,
    output_note_blindings: Span<felt252>,
    output_note_nonces: Span<felt252>,
    output_note_metadata_commitments: Span<felt252>,
    ref public_output_cursor: usize,
) -> (u128, u128) {
    let count: usize = (*lifecycle_output_counts.at(position_index))
        .try_into()
        .expect('LP_LIFECYCLE_OUTPUT');
    assert(public_output_cursor + count <= output_note_commitments.len(), 'LP_LIFECYCLE_OUTPUT');
    let owner_authority = liquidity_position_field(position_fields, position_index, 7);
    let base_asset_id = liquidity_position_field(position_fields, position_index, 5);
    let quote_asset_id = liquidity_position_field(position_fields, position_index, 6);
    let mut base_total: u128 = 0;
    let mut quote_total: u128 = 0;
    let end = public_output_cursor + count;
    while public_output_cursor < end {
        let output_commitment = *output_note_commitments.at(public_output_cursor);
        let asset_id = *output_note_asset_ids.at(public_output_cursor);
        let amount_felt = *output_note_amounts.at(public_output_cursor);
        let withdraw_authority = *output_note_withdraw_authorities.at(public_output_cursor);
        let owner_key = *output_note_owner_keys.at(public_output_cursor);
        let spend_authority = *output_note_spend_authorities.at(public_output_cursor);
        let blinding = *output_note_blindings.at(public_output_cursor);
        let nonce = *output_note_nonces.at(public_output_cursor);
        let metadata = *output_note_metadata_commitments.at(public_output_cursor);
        assert(output_commitment != 0, 'LP_LIFECYCLE_OUTPUT');
        assert(asset_id == base_asset_id || asset_id == quote_asset_id, 'LP_LIFECYCLE_OUTPUT');
        assert(amount_felt != 0, 'LP_LIFECYCLE_OUTPUT');
        assert(owner_key != 0, 'LP_LIFECYCLE_OUTPUT');
        assert(spend_authority == owner_authority, 'LP_LIFECYCLE_OUTPUT');
        assert(withdraw_authority != 0, 'LP_LIFECYCLE_OUTPUT');
        assert(blinding != 0, 'LP_LIFECYCLE_OUTPUT');
        assert(nonce != 0, 'LP_LIFECYCLE_OUTPUT');
        assert(metadata != 0, 'LP_LIFECYCLE_OUTPUT');
        let recomputed_commitment = note_commitment(
            note_commitment_domain,
            asset_id,
            amount_felt,
            owner_key,
            spend_authority,
            withdraw_authority,
            blinding,
            nonce,
            metadata,
        );
        assert_canonical_public_output(
            ref public_output_cursor,
            recomputed_commitment,
            asset_id,
            felt_to_u128(amount_felt),
            withdraw_authority,
            output_note_commitments,
            output_note_asset_ids,
            output_note_amounts,
            output_note_withdraw_authorities,
        );
        let amount = felt_to_u128(amount_felt);
        if asset_id == base_asset_id {
            base_total += amount;
        } else {
            quote_total += amount;
        }
    }
    (base_total, quote_total)
}

fn assert_liquidity_position_reconfiguration_at(
    prior_fields: Span<felt252>, output_fields: Span<felt252>, position_index: usize,
) {
    let mut field_index = 0;
    while field_index < LIQUIDITY_POSITION_FIELD_COUNT {
        if field_index == 10
            || field_index == 11
            || field_index == 12
            || field_index == 13
            || field_index == 14
            || field_index == 15
            || field_index == 16
            || field_index == 17
            || field_index == 18
            || field_index == 19
            || field_index == 20
            || field_index == 21
            || field_index == 22
            || field_index == 24
            || field_index == 25
            || field_index == 26 {} else {
                assert(
                    liquidity_position_field(
                        prior_fields, position_index, field_index,
                    ) == liquidity_position_field(output_fields, position_index, field_index),
                    'LP_RECONFIG',
                );
            }
        field_index += 1;
    }
    assert(
        liquidity_position_field(
            output_fields, position_index, 25,
        ) != liquidity_position_field(prior_fields, position_index, 25),
        'LP_BLINDING',
    );
}

fn assert_matching_liquidity_position_fields_except(
    prior_fields: Span<felt252>,
    output_fields: Span<felt252>,
    position_index: usize,
    except_a: usize,
    except_b: usize,
    except_c: usize,
    except_d: usize,
    except_e: usize,
    except_f: usize,
) {
    let mut field_index = 0;
    while field_index < LIQUIDITY_POSITION_FIELD_COUNT {
        if field_index == except_a
            || field_index == except_b
            || field_index == except_c
            || field_index == except_d
            || field_index == except_e
            || field_index == except_f {} else {
                assert(
                    liquidity_position_field(
                        prior_fields, position_index, field_index,
                    ) == liquidity_position_field(output_fields, position_index, field_index),
                    'LP_FIELD',
                );
            }
        field_index += 1;
    }
}

fn assert_liquidity_position_fill_at(
    prior_fields: Span<felt252>,
    output_fields: Span<felt252>,
    position_index: usize,
    position_side: felt252,
    filled_base_amount_felt: felt252,
    batch_epoch_felt: felt252,
    clearing_price_felt: felt252,
    price_base_scale_felt: felt252,
    market_reference_price_felt: felt252,
) -> (felt252, felt252, felt252) {
    assert(liquidity_position_field(prior_fields, position_index, 2) == 0, 'LP_BACKING');
    assert(liquidity_position_field(output_fields, position_index, 2) == 0, 'LP_BACKING');
    assert(liquidity_position_field(prior_fields, position_index, 3) == 1, 'LP_STATUS');
    assert(liquidity_position_field(output_fields, position_index, 3) == 1, 'LP_STATUS');

    let mut field_index = 0;
    while field_index < LIQUIDITY_POSITION_FIELD_COUNT {
        if field_index == 8
            || field_index == 9
            || field_index == 25 {} else {
                assert(
                    liquidity_position_field(
                        prior_fields, position_index, field_index,
                    ) == liquidity_position_field(output_fields, position_index, field_index),
                    'LP_FIELD',
                );
            }
        field_index += 1;
    }

    let filled_base_amount = felt_to_u128(filled_base_amount_felt);
    let clearing_price = felt_to_u128(clearing_price_felt);
    let price_base_scale = felt_to_u128(price_base_scale_felt);
    let lower_price = felt_to_u128(liquidity_position_field(prior_fields, position_index, 10));
    let upper_price = felt_to_u128(liquidity_position_field(prior_fields, position_index, 11));
    let max_fill_base = felt_to_u128(liquidity_position_field(prior_fields, position_index, 12));
    assert(filled_base_amount != 0, 'LP_FILL');
    assert(max_fill_base != 0, 'LP_FILL');
    assert(filled_base_amount <= max_fill_base, 'LP_FILL');
    assert(price_base_scale != 0, 'LP_PRICE_SCALE');
    assert(clearing_price >= lower_price, 'LP_PRICE');
    assert(clearing_price <= upper_price, 'LP_PRICE');
    let canonical_capacity = liquidity_position_canonical_fill_capacity_at(
        prior_fields,
        position_index,
        position_side,
        batch_epoch_felt,
        clearing_price,
        price_base_scale,
        market_reference_price_felt,
    );
    assert(filled_base_amount <= canonical_capacity, 'LP_CAPACITY');

    let prior_base_reserve = felt_to_u128(
        liquidity_position_field(prior_fields, position_index, 8),
    );
    let prior_quote_reserve = felt_to_u128(
        liquidity_position_field(prior_fields, position_index, 9),
    );
    let output_base_reserve = felt_to_u128(
        liquidity_position_field(output_fields, position_index, 8),
    );
    let output_quote_reserve = felt_to_u128(
        liquidity_position_field(output_fields, position_index, 9),
    );
    let prior_blinding = liquidity_position_field(prior_fields, position_index, 25);
    let output_blinding = liquidity_position_field(output_fields, position_index, 25);
    assert(prior_blinding != 0, 'LP_BLINDING');
    assert(output_blinding != 0, 'LP_BLINDING');
    assert(output_blinding != prior_blinding, 'LP_BLINDING');

    let quote_amount = quote_amount_for_base_amount(
        filled_base_amount, clearing_price, price_base_scale,
    );
    if position_side == ORDER_SIDE_BUY {
        assert(prior_quote_reserve >= quote_amount, 'LP_RESERVE');
        assert(output_quote_reserve == prior_quote_reserve - quote_amount, 'LP_QUOTE');
        assert(output_base_reserve == prior_base_reserve + filled_base_amount, 'LP_BASE');
    } else {
        assert(position_side == ORDER_SIDE_SELL, 'LP_SIDE');
        assert(prior_base_reserve >= filled_base_amount, 'LP_RESERVE');
        assert(output_base_reserve == prior_base_reserve - filled_base_amount, 'LP_BASE');
        assert(output_quote_reserve == prior_quote_reserve + quote_amount, 'LP_QUOTE');
    }

    let prior_commitment = liquidity_position_commitment_at(prior_fields, position_index);
    let output_commitment = liquidity_position_commitment_at(output_fields, position_index);
    (
        prior_commitment,
        liquidity_position_nullifier(prior_commitment, prior_blinding),
        output_commitment,
    )
}

fn liquidity_position_commitment_at(fields: Span<felt252>, position_index: usize) -> felt252 {
    assert(fields.len() >= (position_index + 1) * LIQUIDITY_POSITION_FIELD_COUNT, 'LP_FIELDS');
    let mut state = LIQUIDITY_POSITION_COMMITMENT_DOMAIN;
    let mut field_index = 0;
    while field_index < LIQUIDITY_POSITION_FIELD_COUNT {
        state =
            poseidon_hash2(state, liquidity_position_field(fields, position_index, field_index));
        field_index += 1;
    }
    state
}

fn liquidity_position_field(
    fields: Span<felt252>, position_index: usize, field_index: usize,
) -> felt252 {
    assert(field_index < LIQUIDITY_POSITION_FIELD_COUNT, 'LP_FIELDS');
    *fields.at(position_index * LIQUIDITY_POSITION_FIELD_COUNT + field_index)
}

fn assert_liquidity_position_root_transition(
    state_transition_root_domain: felt252,
    prior_root: felt252,
    transition_root: felt252,
    new_root: felt252,
    transition_count: usize,
) {
    if transition_count == 0 {
        assert(new_root == prior_root, 'E');
    } else {
        assert(state_transition_root_domain == STATE_TRANSITION_ROOT_DOMAIN, 'E');
        assert(transition_root != 0, 'E');
        assert(new_root != 0, 'E');
    }
}

fn felt_to_u128(value: felt252) -> u128 {
    value.try_into().expect('E')
}

fn protocol_fee_root(
    domain: felt252,
    base_asset_id: felt252,
    quote_asset_id: felt252,
    protocol_fee_recipient: felt252,
    relay_fee_recipient: felt252,
    base_fee_amount: u128,
    quote_fee_amount: u128,
    base_relay_fee_amount: u128,
    quote_relay_fee_amount: u128,
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
    if base_relay_fee_amount != 0 {
        state = poseidon_hash2(state, base_asset_id);
        state = poseidon_hash2(state, relay_fee_recipient);
        state = poseidon_hash2(state, base_relay_fee_amount.into());
        fee_count += 1;
    }
    if quote_relay_fee_amount != 0 {
        state = poseidon_hash2(state, quote_asset_id);
        state = poseidon_hash2(state, relay_fee_recipient);
        state = poseidon_hash2(state, quote_relay_fee_amount.into());
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

fn relay_fee_bps_for_order(
    relay_mode: felt252,
    order_type: felt252,
    parent_order_commitment: felt252,
    _relay_fee_bps: u128,
) -> u128 {
    assert_relay_mode(relay_mode, order_type, parent_order_commitment);
    0
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
    liquidity_slice_commitment: felt252,
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
    let with_relay_mode = poseidon_hash2(with_order_type, relay_mode);
    let with_slice = poseidon_hash2(with_relay_mode, liquidity_slice_commitment);
    let with_limit = poseidon_hash2(with_slice, limit_price);
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
    relay_fee_bps: felt252,
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
    let mut state = poseidon_hash2(seed, batch_id);
    state = poseidon_hash2(state, pair_id);
    state = poseidon_hash2(state, batch_epoch);
    state = poseidon_hash2(state, order_commitment_root);
    state = poseidon_hash2(state, encrypted_order_set_commitment);
    state = poseidon_hash2(state, clearing_price);
    state = poseidon_hash2(state, price_base_scale);
    state = poseidon_hash2(state, taker_fee_bps);
    state = poseidon_hash2(state, relay_fee_bps);
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

#[cfg(test)]
mod tests {
    use core::array::{Array, ArrayTrait};
    use super::{
        ASSET_ID_STRK, ASSET_ID_USDC, ASSET_SCALE_18, CONSUMED_NOTE_ROOT_DOMAIN,
        CONSUMED_NULLIFIER_ROOT_DOMAIN, EMPTY_OUTPUT_NOTE_ROOT_DOMAIN, FEE_ROOT_DOMAIN,
        LIQUIDITY_POSITION_SPARSE_TREE_DEPTH, LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN,
        LIQUIDITY_SLICE_DOMAIN, MAX_SETTLEMENT_INPUT_NOTES, MAX_SETTLEMENT_LIQUIDITY_SLICE_POINTS,
        MAX_SETTLEMENT_ORDERS, MAX_SETTLEMENT_OUTPUT_NOTES, NOTE_COMMITMENT_DOMAIN,
        NULLIFIER_DOMAIN, NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL,
        NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL, ORDER_COMMITMENT_DOMAIN, ORDER_SIDE_SELL,
        OUTPUT_NOTE_ROOT_DOMAIN, OUTPUT_RECOVERY_BUNDLE_DOMAIN, OUTPUT_RECOVERY_FIELD_COUNT,
        PAIR_ID_STRK_USDC, PUBLIC_SETTLEMENT_DOMAIN, RENEWAL_CHILD_ROOT_DOMAIN,
        SPEND_AUTHORITY_DOMAIN, STATEMENT_TYPE_SETTLEMENT, STATE_TRANSITION_ROOT_DOMAIN,
        assert_admission_bounds, assert_fee_output, assert_liquidity_position_fill,
        assert_liquidity_position_sparse_update, assert_liquidity_position_transitions,
        assert_output_recovery_bundle, assert_settlement_bounds, ceil_fee_amount,
        fee_bps_for_order_type, liquidity_position_commitment, liquidity_position_nullifier,
        liquidity_position_sparse_leaf, liquidity_position_sparse_node,
        liquidity_position_sparse_root_from_empty, matched_public_output_count, note_commitment,
        poseidon_hash2, protocol_fee_root, public_settlement_commitment, relay_fee_bps_for_order,
        single_field_root, state_transition_root, verify_liquidity_position_statement,
        verify_nullifier_statement, verify_renewal_statement, verify_settlement_statement,
    };

    #[test]
    fn settlement_statement_accepts_root_only_noop_payload() {
        let output_bundle_ref = poseidon_hash2(OUTPUT_RECOVERY_BUNDLE_DOMAIN, 0);
        let output_note_root = poseidon_hash2(EMPTY_OUTPUT_NOTE_ROOT_DOMAIN, output_bundle_ref);
        let consumed_note_root = single_field_root(CONSUMED_NOTE_ROOT_DOMAIN, array![].span());
        let consumed_nullifier_root = single_field_root(
            CONSUMED_NULLIFIER_ROOT_DOMAIN, array![].span(),
        );
        let renewal_child_root = single_field_root(RENEWAL_CHILD_ROOT_DOMAIN, array![].span());
        let fee_root = protocol_fee_root(
            FEE_ROOT_DOMAIN, ASSET_ID_STRK, ASSET_ID_USDC, 0x4010, 0x4020, 0, 0, 0, 0,
        );
        let new_note_root = state_transition_root(
            STATE_TRANSITION_ROOT_DOMAIN, 0, output_note_root,
        );
        let new_fee_root = state_transition_root(STATE_TRANSITION_ROOT_DOMAIN, 0, fee_root);
        let transcript_commitment = public_settlement_commitment(
            PUBLIC_SETTLEMENT_DOMAIN,
            0x2001,
            PAIR_ID_STRK_USDC,
            0x2003,
            0x2004,
            0x2005,
            0,
            ASSET_SCALE_18,
            4,
            0,
            0x4010,
            0x4020,
            output_bundle_ref,
            0,
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
            0,
        );
        let payload = empty_settlement_test_payload(transcript_commitment);
        assert(verify_settlement_statement(payload.span()) == transcript_commitment, 'E');
    }

    #[test]
    fn statement_bounds_accept_current_protocol_caps() {
        assert_admission_bounds(
            MAX_SETTLEMENT_ORDERS,
            MAX_SETTLEMENT_INPUT_NOTES,
            MAX_SETTLEMENT_LIQUIDITY_SLICE_POINTS,
        );
        assert_settlement_bounds(
            MAX_SETTLEMENT_ORDERS,
            MAX_SETTLEMENT_INPUT_NOTES,
            MAX_SETTLEMENT_OUTPUT_NOTES,
            MAX_SETTLEMENT_LIQUIDITY_SLICE_POINTS,
        );
    }

    #[test]
    #[should_panic]
    fn statement_bounds_reject_oversized_order_set() {
        assert_admission_bounds(MAX_SETTLEMENT_ORDERS + 1, 0, 0);
    }

    #[test]
    #[should_panic]
    fn statement_bounds_reject_oversized_output_set() {
        assert_settlement_bounds(0, 0, MAX_SETTLEMENT_OUTPUT_NOTES + 1, 0);
    }

    #[test]
    fn only_user_limit_orders_pay_taker_fees_heartbeat_is_protocol_owned() {
        assert(fee_bps_for_order_type(0, 0, 4) == 4, 'E');
        assert(fee_bps_for_order_type(2, 0, 4) == 0, 'E');
    }

    #[test]
    fn relay_fee_is_disabled_for_self_relayed_orders() {
        assert(relay_fee_bps_for_order(0, 0, 0, 2) == 0, 'E');
        assert(relay_fee_bps_for_order(0, 0, 0x1234, 2) == 0, 'E');
    }

    #[test]
    fn relay_fee_is_disabled_for_hosted_renewal_children() {
        assert(relay_fee_bps_for_order(1, 0, 0x1234, 2) == 0, 'E');
    }

    #[test]
    fn fee_amount_rounds_up_nonzero_dust_fills() {
        assert(ceil_fee_amount(0, 4) == 0, 'E');
        assert(ceil_fee_amount(1, 0) == 0, 'E');
        assert(ceil_fee_amount(1, 1) == 1, 'E');
        assert(ceil_fee_amount(10000, 1) == 1, 'E');
        assert(ceil_fee_amount(10001, 1) == 2, 'E');
    }

    #[test]
    #[should_panic]
    fn relay_fee_rejects_direct_zylith_relay_orders() {
        relay_fee_bps_for_order(1, 0, 0, 2);
    }

    #[test]
    #[should_panic]
    fn fee_bps_rejects_reserved_order_type() {
        fee_bps_for_order_type(1, 0, 4);
    }

    #[test]
    #[should_panic]
    fn output_recovery_bundle_rejects_zero_key_tag() {
        let note_commitments = array![0x1001];
        let recovery_key_tags = array![0];
        let recovery_auth_tags = array![0x2001];
        let recovery_ciphertext_fields = recovery_ciphertext_test_fields();
        let recovery_dummy_commitments = array![];

        assert_output_recovery_bundle(
            NOTE_COMMITMENT_DOMAIN,
            0x9999,
            0x2001,
            0x3001,
            note_commitments.span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            recovery_key_tags.span(),
            recovery_auth_tags.span(),
            recovery_ciphertext_fields.span(),
            recovery_dummy_commitments.span(),
        );
    }

    #[test]
    #[should_panic]
    fn output_recovery_bundle_rejects_mismatched_bundle_ref() {
        let note_commitments = array![0x1001];
        let recovery_key_tags = array![0x1002];
        let recovery_auth_tags = array![0x2001];
        let recovery_ciphertext_fields = recovery_ciphertext_test_fields();
        let recovery_dummy_commitments = array![];

        assert_output_recovery_bundle(
            NOTE_COMMITMENT_DOMAIN,
            0x9999,
            0x2001,
            0x3001,
            note_commitments.span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            recovery_key_tags.span(),
            recovery_auth_tags.span(),
            recovery_ciphertext_fields.span(),
            recovery_dummy_commitments.span(),
        );
    }

    #[test]
    fn fee_root_separates_protocol_and_relay_rows() {
        let root = protocol_fee_root(0x3005, 0x2006, 0x2007, 0x4010, 0x4020, 10, 20, 30, 40);
        let mut expected = 0x3005;
        expected = poseidon_hash2(expected, 0x2006);
        expected = poseidon_hash2(expected, 0x4010);
        expected = poseidon_hash2(expected, 10);
        expected = poseidon_hash2(expected, 0x2007);
        expected = poseidon_hash2(expected, 0x4010);
        expected = poseidon_hash2(expected, 20);
        expected = poseidon_hash2(expected, 0x2006);
        expected = poseidon_hash2(expected, 0x4020);
        expected = poseidon_hash2(expected, 30);
        expected = poseidon_hash2(expected, 0x2007);
        expected = poseidon_hash2(expected, 0x4020);
        expected = poseidon_hash2(expected, 40);
        expected = poseidon_hash2(expected, 4);
        assert(root == expected, 'E');
    }

    #[test]
    fn settlement_fee_fixture_accepts_canonical_fee_output() {
        let protocol_recipient = 0x4010;
        let owner_key = 0x5010;
        let blinding = 0x6010;
        let nonce = 0x7010;
        let metadata_commitment = 0x8010;
        let commitment = fee_output_commitment(
            ASSET_ID_STRK, 10, protocol_recipient, owner_key, blinding, nonce, metadata_commitment,
        );
        let mut cursor: usize = 0;

        assert_fee_output(
            ref cursor,
            NOTE_COMMITMENT_DOMAIN,
            ASSET_ID_STRK,
            10_u128,
            protocol_recipient,
            array![commitment].span(),
            array![ASSET_ID_STRK].span(),
            array![10].span(),
            array![protocol_recipient].span(),
            array![owner_key].span(),
            array![protocol_recipient].span(),
            array![blinding].span(),
            array![nonce].span(),
            array![metadata_commitment].span(),
        );

        assert(cursor == 1, 'BAD_FEE_CURSOR');
    }

    #[test]
    #[should_panic]
    fn settlement_fee_fixture_rejects_duplicate_fee_row() {
        let protocol_recipient = 0x4010;
        let owner_key = 0x5010;
        let blinding = 0x6010;
        let nonce = 0x7010;
        let metadata_commitment = 0x8010;
        let commitment = fee_output_commitment(
            ASSET_ID_STRK, 10, protocol_recipient, owner_key, blinding, nonce, metadata_commitment,
        );
        let mut cursor: usize = 0;
        let output_note_commitments = array![commitment, commitment];
        let output_note_asset_ids = array![ASSET_ID_STRK, ASSET_ID_STRK];
        let output_note_amounts = array![10, 10];
        let output_note_withdraw_authorities = array![protocol_recipient, protocol_recipient];
        let output_note_owner_keys = array![owner_key, owner_key];
        let output_note_spend_authorities = array![protocol_recipient, protocol_recipient];
        let output_note_blindings = array![blinding, blinding];
        let output_note_nonces = array![nonce, nonce];
        let output_note_metadata_commitments = array![metadata_commitment, metadata_commitment];

        assert_fee_output(
            ref cursor,
            NOTE_COMMITMENT_DOMAIN,
            ASSET_ID_STRK,
            10_u128,
            protocol_recipient,
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

        assert(cursor == output_note_commitments.len(), 'DUP_FEE_ROW');
    }

    #[test]
    #[should_panic]
    fn settlement_fee_fixture_rejects_omitted_fee_row() {
        let mut cursor: usize = 0;

        assert_fee_output(
            ref cursor,
            NOTE_COMMITMENT_DOMAIN,
            ASSET_ID_STRK,
            10_u128,
            0x4010,
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
            array![].span(),
        );
    }

    #[test]
    #[should_panic]
    fn settlement_fee_fixture_rejects_nonzero_padding_row() {
        let protocol_recipient = 0x4010;
        let owner_key = 0x5010;
        let blinding = 0x6010;
        let nonce = 0x7010;
        let metadata_commitment = 0x8010;
        let commitment = fee_output_commitment(
            ASSET_ID_STRK, 10, protocol_recipient, owner_key, blinding, nonce, metadata_commitment,
        );
        let mut cursor: usize = 0;
        let output_note_commitments = array![commitment];

        assert_fee_output(
            ref cursor,
            NOTE_COMMITMENT_DOMAIN,
            ASSET_ID_STRK,
            0_u128,
            protocol_recipient,
            output_note_commitments.span(),
            array![ASSET_ID_STRK].span(),
            array![10].span(),
            array![protocol_recipient].span(),
            array![owner_key].span(),
            array![protocol_recipient].span(),
            array![blinding].span(),
            array![nonce].span(),
            array![metadata_commitment].span(),
        );

        assert(cursor == output_note_commitments.len(), 'PADDED_FEE');
    }

    #[test]
    #[should_panic]
    fn settlement_fee_fixture_rejects_wrong_recipient() {
        let expected_recipient = 0x4010;
        let wrong_recipient = 0x4999;
        let owner_key = 0x5010;
        let blinding = 0x6010;
        let nonce = 0x7010;
        let metadata_commitment = 0x8010;
        let commitment = fee_output_commitment(
            ASSET_ID_STRK, 10, wrong_recipient, owner_key, blinding, nonce, metadata_commitment,
        );
        let mut cursor: usize = 0;

        assert_fee_output(
            ref cursor,
            NOTE_COMMITMENT_DOMAIN,
            ASSET_ID_STRK,
            10_u128,
            expected_recipient,
            array![commitment].span(),
            array![ASSET_ID_STRK].span(),
            array![10].span(),
            array![wrong_recipient].span(),
            array![owner_key].span(),
            array![wrong_recipient].span(),
            array![blinding].span(),
            array![nonce].span(),
            array![metadata_commitment].span(),
        );
    }

    #[test]
    #[should_panic]
    fn settlement_statement_rejects_public_transcript_mismatch() {
        let payload = empty_settlement_test_payload(0xdead);
        verify_settlement_statement(payload.span());
    }

    #[test]
    fn renewal_statement_accepts_root_only_noop_payload() {
        let output_bundle_ref = poseidon_hash2(OUTPUT_RECOVERY_BUNDLE_DOMAIN, 0);
        let output_note_root = poseidon_hash2(EMPTY_OUTPUT_NOTE_ROOT_DOMAIN, output_bundle_ref);
        let consumed_note_root = single_field_root(CONSUMED_NOTE_ROOT_DOMAIN, array![].span());
        let consumed_nullifier_root = single_field_root(
            CONSUMED_NULLIFIER_ROOT_DOMAIN, array![].span(),
        );
        let renewal_child_root = single_field_root(RENEWAL_CHILD_ROOT_DOMAIN, array![].span());
        let fee_root = protocol_fee_root(
            FEE_ROOT_DOMAIN, ASSET_ID_STRK, ASSET_ID_USDC, 0x4010, 0x4020, 0, 0, 0, 0,
        );
        let new_note_root = state_transition_root(
            STATE_TRANSITION_ROOT_DOMAIN, 0, output_note_root,
        );
        let new_fee_root = state_transition_root(STATE_TRANSITION_ROOT_DOMAIN, 0, fee_root);
        let transcript_commitment = public_settlement_commitment(
            PUBLIC_SETTLEMENT_DOMAIN,
            0x2001,
            PAIR_ID_STRK_USDC,
            0x2003,
            0x2004,
            0x2005,
            0,
            ASSET_SCALE_18,
            4,
            0,
            0x4010,
            0x4020,
            output_bundle_ref,
            0,
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
            0,
        );
        let payload = empty_settlement_test_payload(transcript_commitment);
        let (transcript, prior_renewal_root, child_root, new_renewal_root) =
            verify_renewal_statement(
            payload.span(),
        );
        assert(transcript == transcript_commitment, 'E');
        assert(prior_renewal_root == 0, 'E');
        assert(child_root == renewal_child_root, 'E');
        assert(new_renewal_root == 0, 'E');
    }

    #[test]
    fn nullifier_statement_accepts_root_only_noop_payload() {
        let output_bundle_ref = poseidon_hash2(OUTPUT_RECOVERY_BUNDLE_DOMAIN, 0);
        let output_note_root = poseidon_hash2(EMPTY_OUTPUT_NOTE_ROOT_DOMAIN, output_bundle_ref);
        let consumed_note_root = single_field_root(CONSUMED_NOTE_ROOT_DOMAIN, array![].span());
        let consumed_nullifier_root = single_field_root(
            CONSUMED_NULLIFIER_ROOT_DOMAIN, array![].span(),
        );
        let renewal_child_root = single_field_root(RENEWAL_CHILD_ROOT_DOMAIN, array![].span());
        let fee_root = protocol_fee_root(
            FEE_ROOT_DOMAIN, ASSET_ID_STRK, ASSET_ID_USDC, 0x4010, 0x4020, 0, 0, 0, 0,
        );
        let new_note_root = state_transition_root(
            STATE_TRANSITION_ROOT_DOMAIN, 0, output_note_root,
        );
        let new_fee_root = state_transition_root(STATE_TRANSITION_ROOT_DOMAIN, 0, fee_root);
        let transcript_commitment = public_settlement_commitment(
            PUBLIC_SETTLEMENT_DOMAIN,
            0x2001,
            PAIR_ID_STRK_USDC,
            0x2003,
            0x2004,
            0x2005,
            0,
            ASSET_SCALE_18,
            4,
            0,
            0x4010,
            0x4020,
            output_bundle_ref,
            0,
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
            0,
        );
        let payload = empty_settlement_test_payload(transcript_commitment);
        let (transcript, prior_nullifier_root, consumed_root, new_nullifier_root) =
            verify_nullifier_statement(
            payload.span(),
        );
        assert(transcript == transcript_commitment, 'E');
        assert(prior_nullifier_root == 0, 'E');
        assert(consumed_root == consumed_nullifier_root, 'E');
        assert(new_nullifier_root == 0, 'E');
    }

    #[test]
    fn liquidity_position_statement_accepts_root_only_noop_payload() {
        let payload = empty_settlement_test_payload(0xabc);
        let (transcript, prior_root, transition_root, new_root) =
            verify_liquidity_position_statement(
            payload.span(),
        );
        assert(transcript == 0xabc, 'E');
        assert(prior_root == 0, 'E');
        assert(transition_root == empty_liquidity_position_transition_root(), 'E');
        assert(new_root == 0, 'E');
    }

    #[test]
    fn liquidity_position_statement_skips_matched_order_output_slots() {
        let order_commitments = array![0x111, 0x222, 0x333];
        let residual_flags = array![1, 0, 1];
        assert(
            matched_public_output_count(order_commitments.span(), residual_flags.span()) == 5,
            'LP_CURSOR',
        );
    }

    #[test]
    #[should_panic]
    fn liquidity_position_statement_rejects_bad_matched_residual_flag() {
        matched_public_output_count(array![0x111].span(), array![2].span());
    }

    #[test]
    fn liquidity_position_commitment_matches_rust_vector() {
        let fields = array![
            1, 0x101, 0, 1, 0x0387fc5397888d1335169b0673ef596fdcaee362c83f6f861fca2d9dbf43e90c,
            0x0083191fc191d03c3f6f70ea7a1420780d860230dda0edfc2ae9ab762c72b2fe,
            0x01e565426a7cff134da7e67f4587da64258d8e50b249f60444b53d8aebb4987c,
            0x7c4179ae1f3635d460a48af1ddaf3bf76150511dcf96f0d6d6ac3f2e375a15d, 10000000000000000000,
            25000000000, 2000000000, 3000000000, 1000000000000000000, 2, 5, 20, 5000, 100, 500, 0,
            25, 25, 0, 10, 1000, 0x201, 0x55,
        ];
        assert(
            liquidity_position_commitment(
                fields.span(),
            ) == 0x63ba7d2f1fc696103b62ded77dc0819e41b4a2d922a9cb9e14f99f01638b09f,
            'LP_VECTOR',
        );
        assert(liquidity_position_sparse_leaf(0x101, 0x202) != 0, 'LP_LEAF');
        assert(
            liquidity_position_sparse_node(
                0x1, 0x2, 0,
            ) != liquidity_position_sparse_node(0x2, 0x1, 0),
            'LP_NODE_ORDER',
        );
    }

    #[test]
    fn liquidity_position_sparse_insert_and_delete_match_rust_vector() {
        let position_id = 0x101;
        let commitment = 0x63ba7d2f1fc696103b62ded77dc0819e41b4a2d922a9cb9e14f99f01638b09f;
        let expected_root = 0x2409122e00db26d1c1e687913bf313331d9a801e216f1e210aecc64e87daa1;
        assert(
            liquidity_position_sparse_root_from_empty(
                position_id, 0x101, 0, commitment,
            ) == expected_root,
            'LP_ROOT_VECTOR',
        );
        let empty_path = array![];
        let empty_directions = array![];
        assert(
            assert_liquidity_position_sparse_update(
                0, position_id, 0x101, 0, 0, commitment, empty_path.span(), empty_directions.span(),
            ) == expected_root,
            'LP_INSERT_VECTOR',
        );

        let mut path = array![];
        let mut directions = array![];
        let mut empty = 0;
        let mut key_low: u128 = 0x101;
        let mut level = 0;
        while level < LIQUIDITY_POSITION_SPARSE_TREE_DEPTH {
            path.append(empty);
            directions.append((key_low % 2).into());
            empty = liquidity_position_sparse_node(empty, empty, level);
            key_low /= 2;
            level += 1;
        }
        assert(
            assert_liquidity_position_sparse_update(
                expected_root, position_id, 0x101, 0, commitment, 0, path.span(), directions.span(),
            ) == 0,
            'LP_DELETE_VECTOR',
        );
    }

    #[test]
    fn liquidity_position_fill_accounting_matches_rust_vector() {
        let prior_fields = liquidity_position_fixture_fields(
            10000000000000000000, 25000000000, 0x201,
        );
        let output_fields = liquidity_position_fixture_fields(
            9000000000000000000, 27500000000, 0x301,
        );

        let (prior_commitment, nullifier, output_commitment) = assert_liquidity_position_fill(
            prior_fields.span(),
            output_fields.span(),
            ORDER_SIDE_SELL,
            1000000000000000000,
            2500000000,
            ASSET_SCALE_18,
        );

        assert(
            prior_commitment == 0x63ba7d2f1fc696103b62ded77dc0819e41b4a2d922a9cb9e14f99f01638b09f,
            'LP_PRIOR_VECTOR',
        );
        assert(
            nullifier == 0x12c928f97543badee97d8ed6431564e7467d5e4d0030d103df7a0f841dca3dd,
            'LP_NULLIFIER_VECTOR',
        );
        assert(
            output_commitment == 0x4ff8f59d4388441da3d5049229f48221ab3759059a4cecd951921fd974365cb,
            'LP_OUTPUT_VECTOR',
        );
        assert(
            liquidity_position_nullifier(prior_commitment, 0x201) == nullifier,
            'LP_NULLIFIER_HELPER',
        );
    }

    #[test]
    #[should_panic]
    fn liquidity_position_fill_rejects_wrong_reserve_accounting() {
        let prior_fields = liquidity_position_fixture_fields(
            10000000000000000000, 25000000000, 0x201,
        );
        let output_fields = liquidity_position_fixture_fields(
            9000000000000000000, 27492500000, 0x301,
        );

        assert_liquidity_position_fill(
            prior_fields.span(),
            output_fields.span(),
            ORDER_SIDE_SELL,
            1000000000000000000,
            2500000000,
            ASSET_SCALE_18,
        );
    }

    #[test]
    fn liquidity_position_transition_shape_accepts_open_output() {
        assert_liquidity_position_transitions(
            array![0].span(), array![0].span(), array![0].span(), array![0x123].span(),
        );
    }

    #[test]
    #[should_panic]
    fn nullifier_statement_rejects_duplicate_consumed_nullifier_fixture() {
        let payload = duplicate_nullifier_statement_test_payload();
        verify_nullifier_statement(payload.span());
    }

    fn empty_settlement_test_payload(transcript_commitment: felt252) -> Array<felt252> {
        let mut payload = array![
            STATEMENT_TYPE_SETTLEMENT, NOTE_COMMITMENT_DOMAIN, SPEND_AUTHORITY_DOMAIN,
            NULLIFIER_DOMAIN, ORDER_COMMITMENT_DOMAIN, LIQUIDITY_SLICE_DOMAIN,
            PUBLIC_SETTLEMENT_DOMAIN, 0x2001, PAIR_ID_STRK_USDC, 0x2003, 0x2004, 0x2005,
            transcript_commitment, ASSET_ID_STRK, ASSET_ID_USDC, 0, ASSET_SCALE_18, 4, 0, 0x4010,
            0x4020, 0, poseidon_hash2(OUTPUT_RECOVERY_BUNDLE_DOMAIN, 0), 0, 0, 0, 0, 0,
            empty_liquidity_position_transition_root(), CONSUMED_NOTE_ROOT_DOMAIN,
            CONSUMED_NULLIFIER_ROOT_DOMAIN, RENEWAL_CHILD_ROOT_DOMAIN,
            LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN, OUTPUT_NOTE_ROOT_DOMAIN, FEE_ROOT_DOMAIN,
            STATE_TRANSITION_ROOT_DOMAIN, NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL,
            NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL,
        ];
        append_empty_test_vectors(ref payload, 143);
        payload
    }

    fn empty_liquidity_position_transition_root() -> felt252 {
        single_field_root(LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN, array![].span())
    }

    fn liquidity_position_fixture_fields(
        base_reserve: felt252, quote_reserve: felt252, blinding: felt252,
    ) -> Array<felt252> {
        array![
            1, 0x101, 0, 1, 0x0387fc5397888d1335169b0673ef596fdcaee362c83f6f861fca2d9dbf43e90c,
            0x0083191fc191d03c3f6f70ea7a1420780d860230dda0edfc2ae9ab762c72b2fe,
            0x01e565426a7cff134da7e67f4587da64258d8e50b249f60444b53d8aebb4987c,
            0x7c4179ae1f3635d460a48af1ddaf3bf76150511dcf96f0d6d6ac3f2e375a15d, base_reserve,
            quote_reserve, 2000000000, 3000000000, 1000000000000000000, 2, 5, 20, 5000, 100, 500, 0,
            25, 25, 0, 10, 1000, blinding, 0x55,
        ]
    }

    fn duplicate_nullifier_statement_test_payload() -> Array<felt252> {
        let mut payload = array![
            STATEMENT_TYPE_SETTLEMENT, NOTE_COMMITMENT_DOMAIN, SPEND_AUTHORITY_DOMAIN,
            NULLIFIER_DOMAIN, ORDER_COMMITMENT_DOMAIN, LIQUIDITY_SLICE_DOMAIN,
            PUBLIC_SETTLEMENT_DOMAIN, 0x2001, PAIR_ID_STRK_USDC, 0x2003, 0x2004, 0x2005, 0xabc,
            ASSET_ID_STRK, ASSET_ID_USDC, 0, ASSET_SCALE_18, 4, 0, 0x4010, 0x4020, 0,
            poseidon_hash2(OUTPUT_RECOVERY_BUNDLE_DOMAIN, 0), 0, 0, 0, 0, 0,
            empty_liquidity_position_transition_root(), CONSUMED_NOTE_ROOT_DOMAIN,
            CONSUMED_NULLIFIER_ROOT_DOMAIN, RENEWAL_CHILD_ROOT_DOMAIN,
            LIQUIDITY_POSITION_TRANSITION_ROOT_DOMAIN, OUTPUT_NOTE_ROOT_DOMAIN, FEE_ROOT_DOMAIN,
            STATE_TRANSITION_ROOT_DOMAIN, NULLIFIER_SPARSE_LEAF_DOMAIN_CANONICAL,
            NULLIFIER_SPARSE_NODE_DOMAIN_CANONICAL,
        ];
        append_empty_test_vectors(ref payload, 60);
        append_test_vector(ref payload, array![0x111, 0x222].span());
        append_test_vector(ref payload, array![0x333, 0x333].span());
        append_test_vector(ref payload, array![0x333, 0x333].span());
        append_test_vector(ref payload, array![0, 0].span());
        append_test_vector(ref payload, array![0, 0].span());
        append_test_vector(ref payload, array![].span());
        append_test_vector(ref payload, array![].span());
        append_empty_test_vectors(ref payload, 37);
        payload.append(0);
        payload.append(0);
        payload.append(0);
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

    fn append_test_vector(ref payload: Array<felt252>, values: Span<felt252>) {
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

    fn fee_output_commitment(
        asset_id: felt252,
        amount: felt252,
        withdraw_authority: felt252,
        owner_key: felt252,
        blinding: felt252,
        nonce: felt252,
        metadata_commitment: felt252,
    ) -> felt252 {
        note_commitment(
            NOTE_COMMITMENT_DOMAIN,
            asset_id,
            amount,
            owner_key,
            withdraw_authority,
            withdraw_authority,
            blinding,
            nonce,
            metadata_commitment,
        )
    }

    fn recovery_ciphertext_test_fields() -> Array<felt252> {
        let mut fields = array![];
        let mut index: usize = 0;
        loop {
            if index == OUTPUT_RECOVERY_FIELD_COUNT {
                break;
            }
            fields.append(0x5000 + index.into());
            index += 1;
        }
        fields
    }
}
