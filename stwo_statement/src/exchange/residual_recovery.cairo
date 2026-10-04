//! permissionless conversion of the latest residual order authority into exact exits.

use core::cmp::min;
use core::ecdsa::check_ecdsa_signature;
use super::common::{
    RESIDUAL_NOTE_LEAF_DOMAIN, SpongeTrait, TWO_POW_120, next, next_bool, next_u128, next_u32,
    next_u64, note_nullifier, poseidon2, read_membership_root, residual_note_commitment, sponge4,
    sponge6,
};

pub const STATEMENT_TYPE_RESIDUAL_RECOVERY: felt252 = 16;
const OWNER_DOMAIN: felt252 = 'zylith_owner_v1';
const OUTPUT_BLINDING_DOMAIN: felt252 = 'zylith_out_blind_v1';
const OUTPUT_KIND_RESIDUAL: felt252 = 4;
const RECOVERY_AUTH_DOMAIN: felt252 = 'zylith_res_recover_auth_v1';
const RECOVERY_DOMAIN: felt252 = 'zylith_res_recovery_v1';
const CAPACITY_FILLED: u32 = 2;
const CAPACITY_FROZEN: u32 = 4;
const FEE_DENOMINATOR: u128 = 10000;

pub fn verify_residual_recovery_statement(data: Span<felt252>) -> felt252 {
    let mut data = data;
    assert(next(ref data) == STATEMENT_TYPE_RESIDUAL_RECOVERY, 'RR_TYPE');
    let chain_context = next(ref data);
    let note_root = next(ref data);
    let output_asset_id = next(ref data);
    let fee_bps = next_u128(ref data);
    let capacity_generation = next_u64(ref data);
    let capacity_status = next_u32(ref data);
    let capacity_total = next_u128(ref data);
    let capacity_consumed = next_u128(ref data);
    let capacity_quote = next_u128(ref data);
    let capacity_scale = next_u128(ref data);
    let input_exit_commitment = next(ref data);
    let input_exit_authority = next(ref data);
    let output_exit_commitment = next(ref data);
    let output_exit_authority = next(ref data);
    assert(chain_context != 0 && note_root != 0 && output_asset_id != 0, 'RR_HEADER');
    assert(fee_bps <= 100, 'RR_FEE');

    let input_asset_id = next(ref data);
    let pair_id = next(ref data);
    let sell = next_bool(ref data);
    let external = next_bool(ref data);
    let remaining = next_u128(ref data);
    let limit = next_u128(ref data);
    let funding = next_u128(ref data);
    let reserved = next_u128(ref data);
    let reserved_offset = next_u128(ref data);
    let reserved_seq = next_u32(ref data);
    let expiry = next_u64(ref data);
    let order_id = next(ref data);
    let generation = next_u32(ref data);
    let owner_public_key = next(ref data);
    let spend_authority = next(ref data);
    let withdraw_authority = next(ref data);
    let cancel_authority = next(ref data);
    let nonce = next(ref data);
    let blinding = next(ref data);
    assert(
        input_asset_id != 0
            && pair_id != 0
            && remaining < TWO_POW_120
            && limit != 0
            && limit < TWO_POW_120
            && funding < TWO_POW_120
            && expiry != 0
            && order_id != 0
            && generation != 0
            && owner_public_key != 0
            && spend_authority != 0
            && withdraw_authority != 0
            && cancel_authority != 0
            && nonce != 0
            && blinding != 0,
        'RR_NOTE',
    );
    let owner_digest = sponge6(
        OWNER_DOMAIN,
        owner_public_key,
        spend_authority,
        withdraw_authority,
        cancel_authority,
        nonce,
    );
    assert(
        blinding == sponge4(OUTPUT_BLINDING_DOMAIN, nonce, generation.into(), OUTPUT_KIND_RESIDUAL),
        'RR_BLINDING',
    );
    let residual_commitment = residual_note_commitment(
        chain_context,
        input_asset_id,
        pair_id,
        sell,
        external,
        remaining.into(),
        limit,
        funding.into(),
        reserved.into(),
        reserved_offset.into(),
        reserved_seq.into(),
        expiry.into(),
        order_id,
        generation.into(),
        owner_digest,
        blinding,
    );
    let leaf = poseidon2(RESIDUAL_NOTE_LEAF_DOMAIN, residual_commitment);
    assert(read_membership_root(ref data, leaf) == note_root, 'RR_MEMBERSHIP');
    let nullifier = note_nullifier(residual_commitment, blinding);

    let (allocated, quote) = if reserved == 0 {
        assert(
            reserved_seq == 0
                && reserved_offset == 0
                && capacity_generation == 0
                && capacity_status == 0
                && capacity_total == 0
                && capacity_consumed == 0
                && capacity_quote == 0
                && capacity_scale == 0,
            'RR_CAPACITY',
        );
        (0, 0)
    } else {
        assert(reserved_seq != 0, 'RR_CAPACITY');
        assert(
            capacity_status == CAPACITY_FILLED || capacity_status == CAPACITY_FROZEN, 'RR_CAPACITY',
        );
        assert(
            capacity_generation != 0
                && capacity_scale != 0
                && capacity_scale < TWO_POW_120
                && capacity_total != 0
                && capacity_total < TWO_POW_120
                && capacity_consumed < TWO_POW_120
                && capacity_quote < TWO_POW_120
                && capacity_consumed <= capacity_total
                && reserved_offset
                + reserved <= capacity_total,
            'RR_CAPACITY',
        );
        let after_offset = if capacity_consumed > reserved_offset {
            capacity_consumed - reserved_offset
        } else {
            0
        };
        let allocated = min(after_offset, reserved);
        let quote = if allocated == 0 {
            0
        } else {
            assert(capacity_consumed != 0, 'RR_CAPACITY');
            let (floor, has_remainder) = super::common::felt_div_rem(
                allocated.into() * capacity_quote.into(), capacity_consumed,
            );
            floor + (!sell && has_remainder).into()
        };
        (allocated.into(), quote)
    };
    let (input_amount, gross_output) = if sell {
        (funding.into() - allocated, quote)
    } else {
        (funding.into() - quote, allocated)
    };
    let input_amount = next_amount(input_amount, 'RR_INPUT');
    let gross_output = next_amount(gross_output, 'RR_OUTPUT');
    let fee = if gross_output == 0 || fee_bps == 0 {
        0
    } else {
        let (floor, remainder) = super::common::felt_div_rem(
            gross_output.into() * fee_bps.into(), FEE_DENOMINATOR,
        );
        floor + remainder.into()
    };
    let output_amount = next_amount(gross_output.into() - fee, 'RR_OUTPUT');
    assert_exit(input_amount, input_exit_commitment, input_exit_authority);
    assert_exit(output_amount, output_exit_commitment, output_exit_authority);

    let mut commitment = SpongeTrait::new();
    commitment.absorb_pair(RECOVERY_DOMAIN, chain_context);
    commitment.absorb_pair(note_root, nullifier);
    commitment.absorb_pair(pair_id, sell.into());
    commitment.absorb_pair(fee_bps.into(), reserved_seq.into());
    commitment.absorb(capacity_generation.into());
    commitment.absorb_pair(capacity_status.into(), capacity_total.into());
    commitment.absorb_pair(capacity_consumed.into(), capacity_quote.into());
    commitment.absorb_pair(capacity_scale.into(), input_asset_id);
    commitment.absorb_pair(input_amount.into(), output_asset_id);
    commitment.absorb_pair(output_amount.into(), fee);
    commitment.absorb_pair(input_exit_commitment, input_exit_authority);
    commitment.absorb_pair(output_exit_commitment, output_exit_authority);
    let commitment = commitment.finish();
    let mut authorization = SpongeTrait::new();
    authorization.absorb_pair(RECOVERY_AUTH_DOMAIN, commitment);
    let authorization = authorization.finish();
    let r = next(ref data);
    let s = next(ref data);
    assert(data.len() == 0, 'RR_TRAILING');
    assert(check_ecdsa_signature(authorization, withdraw_authority, r, s), 'RR_AUTHORIZATION');
    commitment
}

#[inline(always)]
fn next_amount(value: felt252, error: felt252) -> u128 {
    let amount: u128 = value.try_into().expect(error);
    assert(amount < TWO_POW_120, error);
    amount
}

#[inline(always)]
fn assert_exit(amount: u128, commitment: felt252, authority: felt252) {
    if amount == 0 {
        assert(commitment == 0 && authority == 0, 'RR_EXIT');
    } else {
        assert(commitment != 0 && authority != 0, 'RR_EXIT');
    }
}
