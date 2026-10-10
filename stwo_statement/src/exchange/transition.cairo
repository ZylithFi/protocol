//! the exchange transition statement: everything one proof-bearing transaction does to the book
//! (see `zylith_core::exchange::transition`, which builds its witness).
//!
//! each fact is proven once. a new order's ranges, funding membership, nullifiers and
//! authorization are checked when it is admitted; afterwards its book leaf carries them and later
//! transitions only re-absorb it. m0's signatures, freshness, the nullifier set and the outcome
//! records are checked by the contract in the same transaction, against the commitments this
//! statement outputs.
//!
//! arithmetic runs on felts: every product multiplies a value below 2^128 by one below 2^120, so
//! it stays far below the field size and a remainder is checked with one u128 range check.

use core::cmp::{max, min};
use core::dict::{Felt252Dict, Felt252DictTrait};
use core::ecdsa::check_ecdsa_signature;
use super::certificate::{
    Asset, Market, assert_assets_used, assert_canonical_weights, assert_distinct_market_pairs,
    precision_allowance,
};
use super::common::{
    PairSpongeTrait, RESIDUAL_NOTE_LEAF_DOMAIN, Sponge, SpongeTrait, TWO_POW_120, TWO_POW_128,
    TWO_POW_160, TWO_POW_48, TWO_POW_64, assert_nonnegative, felt_div_rem, felt_lt, next, next_bool,
    next_u128, next_u32, next_u64, note_commitment, note_nullifier, nullifier_padding_value,
    order_output_blindings, output_aux_blindings, output_note_leaf, output_padding_record,
    padded_len, poseidon2, read_membership_root, residual_note_commitment, shift_ceil_64, sponge3,
    sponge4, sponge5, sponge6, sponge7, u128_of,
};

pub const STATEMENT_TYPE_TRANSITION: felt252 = 14;
const OWNER_DOMAIN: felt252 = 'zylith_owner_v1';
const ORDER_ID_DOMAIN: felt252 = 'zylith_order_v2';
const FUNDING_SET_DOMAIN: felt252 = 'zylith_funding_v1';
const ORDER_AUTH_DOMAIN: felt252 = 'zylith_order_auth_v1';
const CANCEL_DOMAIN: felt252 = 'zylith_cancel_v1';
const BOOK_DOMAIN: felt252 = 'zylith_book_v1';
const M0_DOMAIN: felt252 = 'zylith_m0_v1';
const OUTCOMES_DOMAIN: felt252 = 'zylith_outcomes_v1';
const CAPACITY_DOMAIN: felt252 = 'zylith_capacity_v1';
const NULLIFIERS_DOMAIN: felt252 = 'zylith_nullifiers_v1';
const RETIRED_NULLIFIERS_DOMAIN: felt252 = 'zylith_retired_v1';
const OUTPUTS_DOMAIN: felt252 = 'zylith_outputs_v1';
const OUTPUT_BLINDING_DOMAIN: felt252 = 'zylith_out_blind_v1';
const TRANSITION_DOMAIN: felt252 = 'zylith_transition_v1';
const OUTPUT_KIND_FEE: felt252 = 3;
const MAX_ASSETS: u32 = 8;
const MAX_MARKETS: u32 = 8;
const MAX_FUNDING_NOTES: u32 = 4;
const MAX_FEE_BPS: u128 = 100;
const REFERENCE_METHOD_DIRECT_BBO: u8 = 0;
const REFERENCE_METHOD_SYNTHETIC_CROSS_BBO: u8 = 1;
const FEE_BPS_DENOMINATOR: u128 = 10000;
const MIN_OUTPUT_BUCKET: u32 = 16;
const MIN_NULLIFIER_BUCKET: u32 = 8;
const MAX_BOOK_ORDERS: u32 = 1024;
const MAX_ORDER_AMOUNT: u128 = 0x3fffffffffffffffffffffffffff;
const MAX_ORDER_LIFETIME_MS: u64 = 2592000000;
const TOLERANCE_UNITS: felt252 = 3;
const REMOVAL_NONE: u32 = 0;
const REMOVAL_CANCEL: u32 = 1;
const REMOVAL_EXPIRE: u32 = 2;
const REMOVAL_RECOVERED: u32 = 3;

#[derive(Copy, Drop)]
struct Outcome {
    seq: felt252,
    pair_id: felt252,
    sell: bool,
    market: u32,
    consumed: u128,
    pool_quote: u128,
    m1: u128,
    m1_scale: u128,
}

#[derive(Copy, Drop)]
struct Context {
    chain_context: felt252,
    seq: felt252,
    close_time: u64,
    note_root: felt252,
}

/// a crossing slot's constants.
#[derive(Copy, Drop)]
struct Slot {
    pair_id: felt252,
    sell: bool,
    market: Market,
    midpoint: felt252,
    scale: felt252,
    reduced: felt252,
    bound: u128,
    input_id: felt252,
    output_id: felt252,
}

/// the slot's running totals.
#[derive(Copy, Drop)]
struct SlotTotals {
    filled_base: felt252,
    filled_quote: felt252,
    participants: felt252,
    capacity: felt252,
    dual: felt252,
    fee: felt252,
    reserved: felt252,
    bound_hit: bool,
}

/// what the order loops carry: kept small, since every loop iteration passes it along.
#[derive(Destruct)]
struct State {
    prior_book: Sponge,
    new_book: Sponge,
    outputs: Sponge,
    nullifiers: felt252,
    retired_nullifiers: felt252,
    prior_count: u32,
    new_count: u32,
    output_count: u32,
    nullifier_count: u32,
    retired_nullifier_count: u32,
    outcome_left: Felt252Dict<felt252>,
    outcome_user_quote: Felt252Dict<felt252>,
    order_ids: Felt252Dict<bool>,
    spent_nullifiers: Felt252Dict<bool>,
}

/// an order's effect on the stream after the per-order rules.
#[derive(Copy, Drop)]
struct Settled {
    remaining: felt252,
    funding: felt252,
    reserved: felt252,
    reserved_offset: felt252,
    reserved_seq: felt252,
    proceeds: felt252,
    refund: felt252,
    removed: bool,
}

pub fn verify_transition_statement(data: Span<felt252>) -> felt252 {
    let mut data = data;
    assert(next(ref data) == STATEMENT_TYPE_TRANSITION, 'EX_TYPE');
    let chain_context = next(ref data);
    let seq = next(ref data);
    let close_time_felt = next(ref data);
    let fee_recipient = next(ref data);
    // private: blinds the fee notes' published amounts.
    let fee_key = next(ref data);
    // private: derives every harmless padding value inside the proof.
    let padding_seed = next(ref data);
    let note_root = next(ref data);
    let claimed_prior_book_root = next(ref data);
    // the root is derived independently from the public output records by the settlement contract.
    let claimed_output_root = next(ref data);
    let seq_u32 = u128_of(seq, 'EX_SEQ');
    assert(
        chain_context != 0
            && fee_recipient != 0
            && fee_key != 0
            && padding_seed != 0
            && seq_u32 != 0,
        'EX_HEADER',
    );
    assert(seq_u32 < 0x100000000, 'EX_SEQ');
    let close_time: u64 = close_time_felt.try_into().expect('EX_CLOSE');
    assert(close_time != 0 && close_time < TWO_POW_48, 'EX_CLOSE');
    let ctx = Context { chain_context, seq, close_time, note_root };

    // assets in strictly increasing id order, with the certificate's weights and prices.
    let asset_count = next_u32(ref data);
    assert(asset_count >= 2 && asset_count <= MAX_ASSETS, 'EX_ASSETS');
    let mut assets: Array<Asset> = array![];
    let mut previous_asset: felt252 = 0;
    for index in 0..asset_count {
        let id = next(ref data);
        assert(id != 0, 'EX_ASSET_ID');
        if index != 0 {
            assert(felt_lt(previous_asset, id), 'EX_ASSET_ORDER');
        }
        previous_asset = id;
        let weight = next_u128(ref data);
        let price = next_u128(ref data);
        assets.append(Asset { id, weight, price });
    }
    let assets = assets.span();

    // m0: one attested midpoint per market, markets in strictly increasing pair order.
    let objective_numeraire = next(ref data);
    assert(objective_numeraire != 0, 'EX_NUMERAIRE');
    let market_count = next_u32(ref data);
    assert(market_count != 0 && market_count <= MAX_MARKETS, 'EX_MARKETS');
    let mut markets: Array<Market> = array![];
    let mut m0 = SpongeTrait::new();
    m0.absorb_pair(M0_DOMAIN, chain_context);
    m0.absorb_pair(seq, close_time_felt);
    m0.absorb(objective_numeraire);
    m0.absorb(market_count.into());
    let mut previous_pair: felt252 = 0;
    for index in 0..market_count {
        let pair_id = next(ref data);
        assert(pair_id != 0, 'EX_PAIR');
        if index != 0 {
            assert(felt_lt(previous_pair, pair_id), 'EX_MARKET_ORDER');
        }
        previous_pair = pair_id;
        let base = next_u32(ref data);
        let quote = next_u32(ref data);
        assert(base < asset_count && quote < asset_count && base != quote, 'EX_MARKET_ASSET');
        let midpoint = next_u128(ref data);
        let scale = next_u128(ref data);
        assert(midpoint != 0 && midpoint < TWO_POW_120, 'EX_MIDPOINT');
        assert(scale != 0 && scale < TWO_POW_120, 'EX_SCALE');
        let observed_at = next(ref data);
        let valid_until = next(ref data);
        let observed: u64 = observed_at.try_into().expect('EX_OBSERVED');
        let valid: u64 = valid_until.try_into().expect('EX_VALID');
        assert(observed != 0 && observed <= close_time && close_time <= valid, 'EX_M0_WINDOW');
        assert(valid < TWO_POW_48, 'EX_M0_WINDOW');
        let fee_bps = next_u128(ref data);
        assert(fee_bps <= MAX_FEE_BPS, 'EX_FEE_BPS');
        let min_order_quote_amount = next_u128(ref data);
        assert(min_order_quote_amount != 0, 'EX_MIN_ORDER_VALUE');
        let reference_methodology: u8 = next(ref data).try_into().expect('EX_REF_METHOD');
        let derivation_base_market_id = next(ref data);
        let derivation_quote_market_id = next(ref data);
        let derivation_base_bid = next_u128(ref data);
        let derivation_base_ask = next_u128(ref data);
        let derivation_quote_bid = next_u128(ref data);
        let derivation_quote_ask = next_u128(ref data);
        let max_leg_skew_ms = next_u64(ref data);
        let base_id = (*assets.at(base)).id;
        let quote_id = (*assets.at(quote)).id;
        m0.absorb_pair(pair_id, base_id);
        m0.absorb_pair(quote_id, midpoint.into());
        m0.absorb_pair(scale.into(), observed_at);
        m0.absorb_pair(valid_until, fee_bps.into());
        m0.absorb_pair(min_order_quote_amount.into(), reference_methodology.into());
        m0.absorb(derivation_base_market_id);
        m0.absorb_pair(derivation_quote_market_id, derivation_base_bid.into());
        m0.absorb_pair(derivation_base_ask.into(), derivation_quote_bid.into());
        m0.absorb_pair(derivation_quote_ask.into(), max_leg_skew_ms.into());
        markets
            .append(
                Market {
                    pair_id,
                    base,
                    quote,
                    base_id,
                    quote_id,
                    midpoint,
                    scale,
                    fee_bps,
                    min_order_quote_amount,
                    observed_at_ms: observed,
                    reference_methodology,
                    derivation_base_market_id,
                    derivation_quote_market_id,
                    derivation_base_bid,
                    derivation_base_ask,
                    derivation_quote_bid,
                    derivation_quote_ask,
                    max_leg_skew_ms,
                },
            );
    }
    let markets = markets.span();
    let markets_commitment = m0.finish();
    assert_distinct_market_pairs(markets);
    assert_reference_derivations(markets);
    assert_assets_used(asset_count, markets);
    assert_canonical_weights(ref data, assets, markets, objective_numeraire);

    // earlier transitions' external outcomes this transition applies.
    let outcome_count = next_u32(ref data);
    let mut outcomes: Array<Outcome> = array![];
    let mut outcome_sponge = SpongeTrait::new();
    outcome_sponge.absorb(OUTCOMES_DOMAIN);
    let mut state = State {
        prior_book: SpongeTrait::new(),
        new_book: SpongeTrait::new(),
        outputs: SpongeTrait::new(),
        nullifiers: poseidon2(NULLIFIERS_DOMAIN, chain_context),
        retired_nullifiers: poseidon2(RETIRED_NULLIFIERS_DOMAIN, chain_context),
        prior_count: 0,
        new_count: 0,
        output_count: 0,
        nullifier_count: 0,
        retired_nullifier_count: 0,
        outcome_left: Default::default(),
        outcome_user_quote: Default::default(),
        order_ids: Default::default(),
        spent_nullifiers: Default::default(),
    };
    state.prior_book.absorb_pair(BOOK_DOMAIN, chain_context);
    state.new_book.absorb_pair(BOOK_DOMAIN, chain_context);
    state.outputs.absorb_pair(OUTPUTS_DOMAIN, chain_context);
    for index in 0..outcome_count {
        let outcome_seq = next(ref data);
        let outcome_seq_u = u128_of(outcome_seq, 'EX_OUTCOME_SEQ');
        assert(outcome_seq_u != 0 && outcome_seq_u < seq_u32, 'EX_OUTCOME_SEQ');
        let pair_id = next(ref data);
        let sell = next_bool(ref data);
        let consumed = next_u128(ref data);
        let pool_quote = next_u128(ref data);
        let m1 = next_u128(ref data);
        let m1_scale = next_u128(ref data);
        assert(consumed < TWO_POW_120 && pool_quote < TWO_POW_120, 'EX_OUTCOME_AMOUNT');
        assert(m1 != 0 && m1 < TWO_POW_120 && m1_scale != 0 && m1_scale < TWO_POW_120, 'EX_M1');
        let market = find_market(markets, pair_id).expect('EX_OUTCOME_MARKET');
        outcome_sponge.absorb_pair(outcome_seq, pair_id);
        outcome_sponge.absorb_pair(sell.into(), consumed.into());
        outcome_sponge.absorb_pair(pool_quote.into(), m1.into());
        outcome_sponge.absorb(m1_scale.into());
        state.outcome_left.insert(index.into(), consumed.into());
        outcomes
            .append(
                Outcome {
                    seq: outcome_seq, pair_id, sell, market, consumed, pool_quote, m1, m1_scale,
                },
            );
    }
    outcome_sponge.absorb(outcome_count.into());
    let outcomes_commitment = outcome_sponge.finish();
    let outcomes = outcomes.span();

    // the claimed external capacity of every slot, checked by the slot's orders.
    let slot_count = market_count * 2;
    let mut claimed_bounds: Array<u128> = array![];
    let mut claimed_totals: Array<u128> = array![];
    for _ in 0..slot_count {
        claimed_bounds.append(next_u128(ref data));
        claimed_totals.append(next_u128(ref data));
    }
    let claimed_bounds = claimed_bounds.span();
    let claimed_totals = claimed_totals.span();

    let mut capacities = PairSpongeTrait::start(CAPACITY_DOMAIN, chain_context);
    let mut capacity_count: u32 = 0;

    // the stream: groups strictly increasing by (pair, side).
    let mut slots: Array<SlotTotals> = array![];
    let group_count = next_u32(ref data);
    let mut previous_group: Option<(felt252, bool)> = Option::None;
    for _ in 0..group_count {
        let pair_id = next(ref data);
        let sell = next_bool(ref data);
        let market_plus_one = next_u32(ref data);
        let existing_count = next_u32(ref data);
        let new_count = next_u32(ref data);
        assert(existing_count + new_count != 0, 'EX_EMPTY_GROUP');
        if let Option::Some((previous_pair, previous_sell)) = previous_group {
            let increasing = felt_lt(previous_pair, pair_id)
                || (previous_pair == pair_id && !previous_sell && sell);
            assert(increasing, 'EX_GROUP_ORDER');
        }
        previous_group = Option::Some((pair_id, sell));
        if market_plus_one == 0 {
            // no market this transition: the group passes through untouched.
            assert(find_market(markets, pair_id).is_none(), 'EX_HIDDEN_MARKET');
            assert(new_count == 0, 'EX_NEW_WITHOUT_MARKET');
            for _ in 0..existing_count {
                pass_through(ref data, ref state, pair_id, sell);
            }
            continue;
        }
        let market_index = market_plus_one - 1;
        let market = *markets.at(market_index);
        assert(market.pair_id == pair_id, 'EX_GROUP_MARKET');
        let slot_index = market_index * 2 + if sell {
            1
        } else {
            0
        };
        while slots.len() < slot_index {
            let index = slots.len();
            assert(*claimed_bounds.at(index) == 0, 'EX_BOUND_EMPTY');
            assert(*claimed_totals.at(index) == 0, 'EX_CAPACITY_TOTAL');
            slots.append(empty_slot());
        }
        let slot = slot_constants(
            market,
            pair_id,
            sell,
            *assets.at(market.base),
            *assets.at(market.quote),
            *claimed_bounds.at(slot_index),
        );
        let mut totals = empty_slot();
        for _ in 0..existing_count {
            existing_order(ref data, ref state, ref totals, ctx, slot, outcomes);
        }
        for _ in 0..new_count {
            new_order(ref data, ref state, ref totals, ctx, slot);
        }
        if totals.reserved != 0 {
            assert(totals.bound_hit, 'EX_BOUND_UNUSED');
            capacities.absorb_pair(pair_id, sell.into());
            capacities.absorb_pair(slot.bound.into(), totals.reserved);
            capacity_count += 1;
        } else {
            assert(slot.bound == 0, 'EX_BOUND_EMPTY');
        }
        assert(totals.reserved == (*claimed_totals.at(slot_index)).into(), 'EX_CAPACITY_TOTAL');
        slots.append(totals);
    }
    while slots.len() < slot_count {
        let index = slots.len();
        assert(*claimed_bounds.at(index) == 0, 'EX_BOUND_EMPTY');
        assert(*claimed_totals.at(index) == 0, 'EX_CAPACITY_TOTAL');
        slots.append(empty_slot());
    }
    let slots = slots.span();
    assert(state.new_count <= MAX_BOOK_ORDERS, 'EX_BOOK_FULL');

    // a partially cleared market may retain only the three explicit integer rounding envelopes
    // per participant. a zero-fill allocation may never use that allowance.
    let mut index: u32 = 0;
    while index != market_count {
        let buys = *slots.at(index * 2);
        let sells = *slots.at(index * 2 + 1);
        let buy_residual = buys.capacity - buys.filled_base;
        let sell_residual = sells.capacity - sells.filled_base;
        let direct_dust = (buys.participants + sells.participants) * TOLERANCE_UNITS;
        assert(
            buy_residual == 0
                || sell_residual == 0
                || (!felt_lt(direct_dust, buy_residual) || !felt_lt(direct_dust, sell_residual))
                && (buys.filled_base != 0 || sells.filled_base != 0),
            'EX_DIRECT_RESIDUAL',
        );
        index += 1;
    }

    // fees per asset: the slots' fees on their output asset, the outcomes' rounding dust and
    // the clearing's conservation dust.
    let mut fees: Array<felt252> = array![];
    let mut dual: felt252 = 0;
    let mut objective: felt252 = 0;
    let mut tolerance: felt252 = 0;
    let mut asset_index: u32 = 0;
    while asset_index != asset_count {
        let mut fee: felt252 = 0;
        let mut inputs: felt252 = 0;
        let mut outputs: felt252 = 0;
        let mut participants_quoted: felt252 = 0;
        let mut index: u32 = 0;
        while index != market_count {
            let market = *markets.at(index);
            let buys = *slots.at(index * 2);
            let sells = *slots.at(index * 2 + 1);
            // buyers pay quote and receive base; sellers pay base and receive quote.
            if market.base == asset_index {
                inputs += sells.filled_base;
                outputs += buys.filled_base;
                fee += buys.fee;
            }
            if market.quote == asset_index {
                inputs += buys.filled_quote;
                outputs += sells.filled_quote;
                fee += sells.fee;
                participants_quoted += buys.participants + sells.participants;
            }
            index += 1;
        }
        let dust = inputs - outputs;
        assert_nonnegative(dust, 'EX_CONSERVATION');
        fee += dust;
        for outcome_index in 0..outcomes.len() {
            let outcome = *outcomes.at(outcome_index);
            if (*markets.at(outcome.market)).quote == asset_index {
                let user_quote = state.outcome_user_quote.get(outcome_index.into());
                let outcome_dust = if outcome.sell {
                    outcome.pool_quote.into() - user_quote
                } else {
                    user_quote - outcome.pool_quote.into()
                };
                u128_of(outcome_dust, 'EX_OUTCOME_QUOTE');
                fee += outcome_dust;
            }
        }
        fees.append(fee);
        dual += shift_ceil_64((*assets.at(asset_index)).price.into() * participants_quoted);
        asset_index += 1;
    }
    for outcome_index in 0..outcomes.len() {
        assert(state.outcome_left.get(outcome_index.into()) == 0, 'EX_OUTCOME_UNALLOCATED');
    }

    // weak duality: the certified bound may exceed the allocation's objective only by the
    // protocol tolerance.
    let mut index: u32 = 0;
    while index != market_count {
        let market = *markets.at(index);
        let buys = *slots.at(index * 2);
        let sells = *slots.at(index * 2 + 1);
        let base_weight: felt252 = (*assets.at(market.base)).weight.into();
        let participant_weight = base_weight + (*assets.at(market.quote)).weight.into() + 1;
        dual += buys.dual + sells.dual;
        objective += base_weight * (buys.filled_base + sells.filled_base);
        tolerance += participant_weight * (buys.participants + sells.participants);
        tolerance += precision_allowance(market, buys.capacity + sells.capacity);
        index += 1;
    }
    let bound: u256 = dual.into();
    let accepted: u256 = (objective + tolerance * TOLERANCE_UNITS).into();
    assert(bound <= accepted, 'EX_NOT_OPTIMAL');

    // fee notes, one per asset that earned any, their amounts padded by a blinding only the
    // operator's fee key derives.
    let mut asset_index: u32 = 0;
    while asset_index != asset_count {
        let fee = *fees.at(asset_index);
        if fee != 0 {
            let asset_id = (*assets.at(asset_index)).id;
            let blinding = sponge5(OUTPUT_BLINDING_DOMAIN, fee_key, seq, OUTPUT_KIND_FEE, asset_id);
            let commitment = note_commitment(
                asset_id, fee, fee_recipient, fee_recipient, fee_recipient, blinding, seq, asset_id,
            );
            let leaf = output_note_leaf(commitment, asset_id, fee, fee_recipient);
            let (enc_remaining, enc_reserved, enc_offset) = output_aux_blindings(blinding);
            absorb_output_record(
                ref state.outputs, leaf, fee + blinding, enc_remaining, enc_reserved, enc_offset,
            );
            state.output_count += 1;
        }
        asset_index += 1;
    }

    // padding is derived in-proof from a private seed. the operator cannot substitute a
    // spendable leaf or a user's nullifier while the published list sizes stay hidden.
    let output_total = padded_len(state.output_count, MIN_OUTPUT_BUCKET);
    for index in state.output_count..output_total {
        let (leaf, enc, enc_remaining, enc_reserved, enc_offset) = output_padding_record(
            padding_seed, index.into(),
        );
        absorb_output_record(ref state.outputs, leaf, enc, enc_remaining, enc_reserved, enc_offset);
    }
    state.outputs.absorb(output_total.into());
    let outputs_commitment = state.outputs.finish();
    let nullifier_total = padded_len(state.nullifier_count, MIN_NULLIFIER_BUCKET);
    let mut nullifiers = state.nullifiers;
    for index in state.nullifier_count..nullifier_total {
        nullifiers = poseidon2(nullifiers, nullifier_padding_value(padding_seed, index.into()));
    }
    let nullifiers_commitment = poseidon2(nullifiers, nullifier_total.into());
    let retired_nullifiers_commitment = poseidon2(
        state.retired_nullifiers, state.retired_nullifier_count.into(),
    );
    assert(data.len() == 0, 'EX_TRAILING');

    assert(
        {
            state.prior_book.absorb(state.prior_count.into());
            state.prior_book.finish()
        } == claimed_prior_book_root,
        'EX_PRIOR_BOOK',
    );
    state.new_book.absorb(state.new_count.into());
    let new_book_root = state.new_book.finish();
    let capacity_commitment = capacities.finish_odd(capacity_count.into());
    let mut commitment = SpongeTrait::new();
    commitment.absorb_pair(TRANSITION_DOMAIN, chain_context);
    commitment.absorb_pair(seq, close_time_felt);
    commitment.absorb_pair(claimed_prior_book_root, new_book_root);
    commitment.absorb_pair(note_root, markets_commitment);
    commitment.absorb_pair(outcomes_commitment, capacity_commitment);
    commitment.absorb_pair(nullifiers_commitment, retired_nullifiers_commitment);
    commitment.absorb(outputs_commitment);
    commitment.absorb_pair(claimed_output_root, fee_recipient);
    commitment.finish()
}

#[inline(always)]
fn find_market(markets: Span<Market>, pair_id: felt252) -> Option<u32> {
    let mut index: u32 = 0;
    while index != markets.len() {
        if (*markets.at(index)).pair_id == pair_id {
            return Option::Some(index);
        }
        index += 1;
    }
    Option::None
}

#[inline(always)]
fn empty_slot() -> SlotTotals {
    SlotTotals {
        filled_base: 0,
        filled_quote: 0,
        participants: 0,
        capacity: 0,
        dual: 0,
        fee: 0,
        reserved: 0,
        bound_hit: false,
    }
}

/// the certificate's reduced cost for the slot: buyers pay the ceiling of the quote leg,
/// sellers receive the floor.
fn slot_constants(
    market: Market, pair_id: felt252, sell: bool, base: Asset, quote: Asset, bound: u128,
) -> Slot {
    let (sell_term, has_remainder) = felt_div_rem(
        market.midpoint.into() * quote.price.into(), market.scale,
    );
    let sell_term: u128 = sell_term.try_into().expect('EX_SELL_TERM');
    let buy_term = if has_remainder {
        sell_term + 1
    } else {
        sell_term
    };
    let scaled_weight = base.weight * TWO_POW_64;
    let reduced: felt252 = if sell {
        let positive = scaled_weight + base.price;
        if positive > sell_term {
            (positive - sell_term).into()
        } else {
            0
        }
    } else {
        let positive = scaled_weight + buy_term;
        if positive > base.price {
            (positive - base.price).into()
        } else {
            0
        }
    };
    let (input_id, output_id) = if sell {
        (market.base_id, market.quote_id)
    } else {
        (market.quote_id, market.base_id)
    };
    Slot {
        pair_id,
        sell,
        market,
        midpoint: market.midpoint.into(),
        scale: market.scale.into(),
        reduced,
        bound,
        input_id,
        output_id,
    }
}

#[inline(always)]
fn leaf_p1(remaining: felt252, sell: bool, external: bool) -> felt252 {
    let flags: felt252 = sell.into() + external.into() * 2;
    remaining + flags * TWO_POW_128
}

#[inline(always)]
fn leaf_p3(reserved: felt252, reserved_seq: felt252, expiry: felt252) -> felt252 {
    reserved + reserved_seq * TWO_POW_128 + expiry * TWO_POW_160
}

#[inline(always)]
fn absorb_leaf(
    ref sponge: Sponge,
    pair_id: felt252,
    p1: felt252,
    p2: felt252,
    p3: felt252,
    owner_digest: felt252,
    order_id: felt252,
    reserved_offset: felt252,
    residual_commitment: felt252,
    residual_generation: felt252,
) {
    sponge.absorb_pair(pair_id, p1);
    sponge.absorb_pair(p2, p3);
    sponge.absorb_pair(owner_digest, order_id);
    sponge.absorb_pair(reserved_offset, residual_commitment);
    sponge.absorb(residual_generation);
}

/// an existing order's fixed 21-felt record: its book leaf and this transition's witness. the
/// range checks give each packed leaf field exactly one opening.
#[derive(Copy, Drop)]
struct Record {
    external: bool,
    remaining: felt252,
    limit: u128,
    funding: felt252,
    reserved: felt252,
    reserved_offset: felt252,
    reserved_seq: felt252,
    expiry: felt252,
    owner_digest: felt252,
    order_id: felt252,
    residual_commitment: felt252,
    residual_generation: felt252,
    outcome_plus_one: u32,
    removal: u32,
    cancel_r: felt252,
    cancel_s: felt252,
    fill: felt252,
    quote: felt252,
    capacity: felt252,
    external_amount: felt252,
    owner_present: bool,
}

#[inline(always)]
fn read_record(ref data: Span<felt252>) -> Record {
    let boxed = data.multi_pop_front::<21>().expect('EX_SHORT');
    let [
        external,
        remaining,
        limit,
        funding,
        reserved,
        reserved_offset,
        reserved_seq,
        expiry,
        owner_digest,
        order_id,
        residual_commitment,
        residual_generation,
        outcome_plus_one,
        removal,
        cancel_r,
        cancel_s,
        fill,
        quote,
        capacity,
        external_amount,
        owner_present,
    ] =
        boxed
        .unbox();
    assert(external * (external - 1) == 0, 'EX_BOOL');
    assert(owner_present * (owner_present - 1) == 0, 'EX_BOOL');
    assert(u128_of(remaining, 'EX_U128') <= MAX_ORDER_AMOUNT, 'EX_ORDER_AMOUNT');
    assert(u128_of(funding, 'EX_U128') <= MAX_ORDER_AMOUNT, 'EX_ORDER_FUNDING');
    u128_of(reserved, 'EX_U128');
    u128_of(reserved_offset, 'EX_U128');
    let reserved_seq_u: u32 = reserved_seq.try_into().expect('EX_U32');
    let residual_generation_u: u32 = residual_generation.try_into().expect('EX_U32');
    assert(residual_commitment != 0 && residual_generation_u != 0, 'EX_RESIDUAL');
    assert((reserved == 0) == (reserved_seq_u == 0), 'EX_RESERVATION');
    if reserved == 0 {
        assert(reserved_offset == 0, 'EX_RESERVATION');
    }
    Record {
        external: external == 1,
        remaining,
        limit: u128_of(limit, 'EX_U128'),
        funding,
        reserved,
        reserved_offset,
        reserved_seq,
        expiry,
        owner_digest,
        order_id,
        residual_commitment,
        residual_generation,
        outcome_plus_one: outcome_plus_one.try_into().expect('EX_U32'),
        removal: removal.try_into().expect('EX_U32'),
        cancel_r,
        cancel_s,
        fill,
        quote,
        capacity,
        external_amount,
        owner_present: owner_present == 1,
    }
}

#[inline(always)]
fn assert_unique_order_id(ref state: State, order_id: felt252) {
    assert(!state.order_ids.get(order_id), 'EX_DUP_ORDER_ID');
    state.order_ids.insert(order_id, true);
}

#[inline(always)]
fn assert_unique_nullifier(ref state: State, nullifier: felt252) {
    assert(!state.spent_nullifiers.get(nullifier), 'EX_DUP_NULLIFIER');
    state.spent_nullifiers.insert(nullifier, true);
}

#[inline(always)]
fn pass_through(ref data: Span<felt252>, ref state: State, pair_id: felt252, sell: bool) {
    let record = read_record(ref data);
    assert_unique_order_id(ref state, record.order_id);
    let p1 = leaf_p1(record.remaining, sell, record.external);
    let p2 = record.limit.into() + record.funding * TWO_POW_128;
    let p3 = leaf_p3(record.reserved, record.reserved_seq, record.expiry);
    absorb_leaf(
        ref state.prior_book,
        pair_id,
        p1,
        p2,
        p3,
        record.owner_digest,
        record.order_id,
        record.reserved_offset,
        record.residual_commitment,
        record.residual_generation,
    );
    absorb_leaf(
        ref state.new_book,
        pair_id,
        p1,
        p2,
        p3,
        record.owner_digest,
        record.order_id,
        record.reserved_offset,
        record.residual_commitment,
        record.residual_generation,
    );
    state.prior_count += 1;
    state.new_count += 1;
    // nothing may happen to it.
    assert(
        record.outcome_plus_one == 0
            && record.removal == 0
            && record.cancel_r == 0
            && record.cancel_s == 0
            && record.fill == 0
            && record.quote == 0
            && record.capacity == 0
            && record.external_amount == 0
            && !record.owner_present,
        'EX_PASS_THROUGH',
    );
}

#[inline(always)]
fn existing_order(
    ref data: Span<felt252>,
    ref state: State,
    ref totals: SlotTotals,
    ctx: Context,
    slot: Slot,
    outcomes: Span<Outcome>,
) {
    let record = read_record(ref data);
    let external = record.external;
    let limit = record.limit;
    let expiry = record.expiry;
    let owner_digest = record.owner_digest;
    let order_id = record.order_id;
    assert_unique_order_id(ref state, order_id);
    absorb_leaf(
        ref state.prior_book,
        slot.pair_id,
        leaf_p1(record.remaining, slot.sell, external),
        limit.into() + record.funding * TWO_POW_128,
        leaf_p3(record.reserved, record.reserved_seq, expiry),
        owner_digest,
        order_id,
        record.reserved_offset,
        record.residual_commitment,
        record.residual_generation,
    );
    state.prior_count += 1;

    // 1. an earlier transition's external outcome, allocated greedily in book order.
    let mut remaining = record.remaining;
    let mut funding = record.funding;
    let mut reserved = record.reserved;
    let mut reserved_offset = record.reserved_offset;
    let mut reserved_seq = record.reserved_seq;
    let mut external_out: felt252 = 0;
    let outcome_plus_one = record.outcome_plus_one;
    if outcome_plus_one != 0 {
        let index = outcome_plus_one - 1;
        let outcome = *outcomes.at(index);
        assert(reserved != 0, 'EX_OUTCOME_UNRESERVED');
        assert(outcome.seq == reserved_seq, 'EX_OUTCOME_SEQ');
        assert(outcome.pair_id == slot.pair_id && outcome.sell == slot.sell, 'EX_OUTCOME_SLOT');
        let left = state.outcome_left.get(index.into());
        let reserved_u: u128 = reserved.try_into().unwrap();
        let left_u: u128 = left.try_into().unwrap();
        let consumed = min(reserved_u, left_u);
        state.outcome_left.insert(index.into(), left - consumed.into());
        let (quote, has_remainder) = felt_div_rem(
            consumed.into() * outcome.m1.into(), outcome.m1_scale,
        );
        remaining -= consumed.into();
        let user_quote = if slot.sell {
            funding -= consumed.into();
            external_out = quote;
            quote
        } else {
            let paid = quote + has_remainder.into();
            funding -= paid;
            u128_of(funding, 'EX_OUTCOME_FUNDING');
            external_out = consumed.into();
            paid
        };
        state
            .outcome_user_quote
            .insert(index.into(), state.outcome_user_quote.get(index.into()) + user_quote);
        reserved = 0;
        reserved_offset = 0;
        reserved_seq = 0;
    } else if reserved != 0 {
        // a reservation whose outcome this transition lists must be settled by it.
        for outcome in outcomes {
            let outcome = *outcome;
            assert(
                !(outcome.seq == reserved_seq
                    && outcome.pair_id == slot.pair_id
                    && outcome.sell == slot.sell),
                'EX_OUTCOME_SKIPPED',
            );
        }
    }

    // 2. cancellation and expiry, for an unreserved order.
    let removal = record.removal;
    let expiry_u: u64 = expiry.try_into().expect('EX_EXPIRY');
    if removal == REMOVAL_CANCEL {
        assert(reserved == 0, 'EX_CANCEL_RESERVED');
    } else if removal == REMOVAL_EXPIRE {
        assert(reserved == 0 && ctx.close_time >= expiry_u, 'EX_NOT_EXPIRED');
    } else if removal == REMOVAL_RECOVERED {
        assert(reserved == 0, 'EX_RECOVERY_RESERVED');
    } else {
        assert(removal == REMOVAL_NONE, 'EX_REMOVAL');
        if reserved == 0 {
            assert(ctx.close_time < expiry_u, 'EX_EXPIRED_KEPT');
        }
    }

    // 3-5. cross, reserve and settle.
    let participates = removal == REMOVAL_NONE && reserved == 0;
    let settled = settle(
        ref totals,
        slot,
        ctx,
        external,
        remaining,
        limit,
        funding,
        reserved,
        reserved_offset,
        reserved_seq,
        removal != REMOVAL_NONE,
        participates,
        if removal == REMOVAL_RECOVERED {
            0
        } else {
            external_out
        },
        record.fill,
        record.quote,
        record.capacity,
        record.external_amount,
    );

    let state_changed = settled.remaining != record.remaining
        || settled.funding != record.funding
        || settled.reserved != record.reserved
        || settled.reserved_offset != record.reserved_offset
        || settled.reserved_seq != record.reserved_seq;
    let owner_present = record.owner_present;
    let needs_owner = settled.proceeds != 0
        || settled.refund != 0
        || removal != REMOVAL_NONE
        || state_changed;
    assert(owner_present == needs_owner, 'EX_OWNER_PRESENCE');
    let mut new_residual_commitment = record.residual_commitment;
    let mut new_residual_generation = record.residual_generation;
    if owner_present {
        let (owner_public_key, spend_authority, withdraw_authority, cancel_authority, nonce) =
            read_owner(
            ref data,
        );
        assert(
            sponge6(
                OWNER_DOMAIN,
                owner_public_key,
                spend_authority,
                withdraw_authority,
                cancel_authority,
                nonce,
            ) == owner_digest,
            'EX_OWNER',
        );
        if state_changed || removal != REMOVAL_NONE {
            let (_, _, old_blinding) = order_output_blindings(nonce, record.residual_generation);
            let old_commitment = residual_note_commitment(
                ctx.chain_context,
                slot.input_id,
                slot.pair_id,
                slot.sell,
                external,
                record.remaining,
                limit,
                record.funding,
                record.reserved,
                record.reserved_offset,
                record.reserved_seq,
                expiry,
                order_id,
                record.residual_generation,
                owner_digest,
                old_blinding,
            );
            assert(old_commitment == record.residual_commitment, 'EX_RESIDUAL');
            let old_nullifier = note_nullifier(old_commitment, old_blinding);
            assert_unique_nullifier(ref state, old_nullifier);
            if removal == REMOVAL_RECOVERED {
                state.retired_nullifiers = poseidon2(state.retired_nullifiers, old_nullifier);
                state.retired_nullifier_count += 1;
            } else {
                state.nullifiers = poseidon2(state.nullifiers, old_nullifier);
                state.nullifier_count += 1;
            }
        }
        if removal == REMOVAL_CANCEL {
            assert(
                check_ecdsa_signature(
                    sponge3(CANCEL_DOMAIN, ctx.chain_context, order_id),
                    cancel_authority,
                    record.cancel_r,
                    record.cancel_s,
                ),
                'EX_CANCEL_SIGNATURE',
            );
        }
        if removal != REMOVAL_RECOVERED {
            emit_order_outputs(
                ref state,
                ctx,
                slot,
                settled,
                order_id,
                owner_public_key,
                spend_authority,
                withdraw_authority,
                nonce,
            );
        }
        if !settled.removed && state_changed {
            new_residual_commitment =
                emit_residual_output(
                    ref state,
                    ctx,
                    slot,
                    settled,
                    limit,
                    expiry,
                    external,
                    order_id,
                    owner_digest,
                    nonce,
                );
            new_residual_generation = ctx.seq;
        }
    }
    if !settled.removed {
        absorb_leaf(
            ref state.new_book,
            slot.pair_id,
            leaf_p1(settled.remaining, slot.sell, external),
            limit.into() + settled.funding * TWO_POW_128,
            leaf_p3(settled.reserved, settled.reserved_seq, expiry),
            owner_digest,
            order_id,
            settled.reserved_offset,
            new_residual_commitment,
            new_residual_generation,
        );
        state.new_count += 1;
    }
}

#[inline(always)]
fn new_order(
    ref data: Span<felt252>, ref state: State, ref totals: SlotTotals, ctx: Context, slot: Slot,
) {
    let external = next_bool(ref data);
    let amount = next_u128(ref data);
    let limit = next_u128(ref data);
    let expiry = next_u64(ref data);
    assert(amount != 0 && amount <= MAX_ORDER_AMOUNT, 'EX_AMOUNT');
    assert(limit != 0 && limit < TWO_POW_120, 'EX_LIMIT');
    assert(
        ctx.close_time < expiry && expiry <= ctx.close_time
            + MAX_ORDER_LIFETIME_MS && expiry < TWO_POW_48,
        'EX_NEW_EXPIRY',
    );
    let (owner_public_key, spend_authority, withdraw_authority, cancel_authority, nonce) =
        read_owner(
        ref data,
    );
    assert(
        owner_public_key != 0
            && spend_authority != 0
            && withdraw_authority != 0
            && cancel_authority != 0
            && nonce != 0,
        'EX_OWNER',
    );
    let owner_digest = sponge6(
        OWNER_DOMAIN,
        owner_public_key,
        spend_authority,
        withdraw_authority,
        cancel_authority,
        nonce,
    );
    let flags: felt252 = slot.sell.into() + external.into() * 2;
    let order_id = sponge7(
        ORDER_ID_DOMAIN,
        slot.pair_id,
        flags,
        amount.into(),
        limit.into(),
        expiry.into(),
        owner_digest,
    );
    assert_unique_order_id(ref state, order_id);

    // lock the funding notes: each is a member of the note root, its nullifier becomes public.
    assert(ctx.note_root != 0, 'EX_NOTE_ROOT');
    let note_count = next_u32(ref data);
    assert(note_count != 0 && note_count <= MAX_FUNDING_NOTES, 'EX_FUNDING_COUNT');
    let mut funding_set = SpongeTrait::new();
    funding_set.absorb(FUNDING_SET_DOMAIN);
    let mut funding: u128 = 0;
    let mut funding_spend_authority: felt252 = 0;
    for index in 0..note_count {
        let note_amount = next_u128(ref data);
        let note_owner = next(ref data);
        let note_spend_authority = next(ref data);
        let note_withdraw_authority = next(ref data);
        let note_blinding = next(ref data);
        let note_nonce = next(ref data);
        let note_metadata = next(ref data);
        assert(note_amount != 0 && note_blinding != 0 && note_nonce != 0, 'EX_FUNDING_NOTE');
        if index == 0 {
            funding_spend_authority = note_spend_authority;
        } else {
            assert(note_spend_authority == funding_spend_authority, 'EX_FUNDING_AUTHORITY');
        }
        let commitment = note_commitment(
            slot.input_id,
            note_amount.into(),
            note_owner,
            note_spend_authority,
            note_withdraw_authority,
            note_blinding,
            note_nonce,
            note_metadata,
        );
        let leaf = output_note_leaf(
            commitment, slot.input_id, note_amount.into(), note_withdraw_authority,
        );
        assert(read_membership_root(ref data, leaf) == ctx.note_root, 'EX_FUNDING_MEMBERSHIP');
        let nullifier = note_nullifier(commitment, note_blinding);
        assert_unique_nullifier(ref state, nullifier);
        state.nullifiers = poseidon2(state.nullifiers, nullifier);
        state.nullifier_count += 1;
        funding_set.absorb(commitment);
        funding += note_amount;
    }
    assert(funding <= MAX_ORDER_AMOUNT, 'EX_FUNDING_RANGE');
    let (quote_floor, quote_remainder) = felt_div_rem(
        amount.into() * limit.into(), slot.market.scale,
    );
    let quote_floor: u128 = quote_floor.try_into().expect('EX_ORDER_VALUE');
    let quote_value = quote_floor + if quote_remainder {
        1
    } else {
        0
    };
    assert(quote_value >= slot.market.min_order_quote_amount, 'EX_ORDER_VALUE');
    let required_funding = if slot.sell {
        amount
    } else {
        quote_value
    };
    assert(funding >= required_funding, 'EX_FUNDING_SHORT');
    funding_set.absorb(note_count.into());
    let r = next(ref data);
    let s = next(ref data);
    assert(
        check_ecdsa_signature(
            sponge4(ORDER_AUTH_DOMAIN, ctx.chain_context, order_id, funding_set.finish()),
            funding_spend_authority,
            r,
            s,
        ),
        'EX_ORDER_AUTHORIZATION',
    );

    let fill = next(ref data);
    let quote = next(ref data);
    let clearing_capacity = next(ref data);
    let external_amount = next(ref data);
    let settled = settle(
        ref totals,
        slot,
        ctx,
        external,
        amount.into(),
        limit,
        funding.into(),
        0,
        0,
        0,
        false,
        true,
        0,
        fill,
        quote,
        clearing_capacity,
        external_amount,
    );
    emit_order_outputs(
        ref state,
        ctx,
        slot,
        settled,
        order_id,
        owner_public_key,
        spend_authority,
        withdraw_authority,
        nonce,
    );
    if !settled.removed {
        let residual_commitment = emit_residual_output(
            ref state,
            ctx,
            slot,
            settled,
            limit,
            expiry.into(),
            external,
            order_id,
            owner_digest,
            nonce,
        );
        absorb_leaf(
            ref state.new_book,
            slot.pair_id,
            leaf_p1(settled.remaining, slot.sell, external),
            limit.into() + settled.funding * TWO_POW_128,
            leaf_p3(settled.reserved, settled.reserved_seq, expiry.into()),
            owner_digest,
            order_id,
            settled.reserved_offset,
            residual_commitment,
            ctx.seq,
        );
        state.new_count += 1;
    }
}

#[inline(always)]
fn read_owner(ref data: Span<felt252>) -> (felt252, felt252, felt252, felt252, felt252) {
    (next(ref data), next(ref data), next(ref data), next(ref data), next(ref data))
}

/// crosses a participating order at m0, reserves its external residual and settles proceeds,
/// fees and a finished order's refund.
#[inline(always)]
fn settle(
    ref totals: SlotTotals,
    slot: Slot,
    ctx: Context,
    external: bool,
    remaining: felt252,
    limit: u128,
    funding: felt252,
    reserved: felt252,
    reserved_offset: felt252,
    reserved_seq: felt252,
    removing: bool,
    participates: bool,
    external_out: felt252,
    fill: felt252,
    quote: felt252,
    clearing_capacity: felt252,
    external_amount: felt252,
) -> Settled {
    let market = slot.market;
    let mut remaining = remaining;
    let mut funding = funding;
    let mut reserved = reserved;
    let mut reserved_offset = reserved_offset;
    let mut reserved_seq = reserved_seq;
    let mut internal_out: felt252 = 0;
    if !participates {
        assert(
            fill == 0 && quote == 0 && clearing_capacity == 0 && external_amount == 0,
            'EX_IDLE_ALLOCATION',
        );
    } else {
        let eligible = if slot.sell {
            limit <= market.midpoint
        } else {
            market.midpoint <= limit
        };
        // the fill, below the remaining amount, and its quote leg rounded against the order.
        let fill_u = u128_of(fill, 'EX_FILL');
        let residual_base = remaining - fill;
        let residual_base_u = u128_of(residual_base, 'EX_FILL');
        let quote_u = u128_of(quote, 'EX_QUOTE');
        let rounding = if slot.sell {
            fill * slot.midpoint - quote * slot.scale
        } else {
            quote * slot.scale - fill * slot.midpoint
        };
        assert(u128_of(rounding, 'EX_QUOTE_ROUNDING') < market.scale, 'EX_QUOTE_ROUNDING');
        if fill_u != 0 {
            assert(eligible && quote_u != 0, 'EX_FILL_PRICE');
        }
        let consumed = if slot.sell {
            fill
        } else {
            quote
        };
        let residual_input = funding - consumed;
        let residual_input_u = u128_of(residual_input, 'EX_FUNDING');

        // the clearing capacity: zero when the limit rejects the midpoint, else the remaining
        // amount bounded by what the funding pays for at the midpoint.
        if !eligible {
            assert(clearing_capacity == 0, 'EX_CAPACITY');
        } else {
            u128_of(clearing_capacity, 'EX_CAPACITY');
            u128_of(remaining - clearing_capacity, 'EX_CAPACITY');
            if slot.sell {
                u128_of(funding - clearing_capacity, 'EX_CAPACITY');
                assert(
                    (remaining - clearing_capacity) * (funding - clearing_capacity) == 0,
                    'EX_CAPACITY',
                );
            } else {
                let slack = funding * slot.scale - clearing_capacity * slot.midpoint;
                if clearing_capacity == remaining {
                    assert_nonnegative(slack, 'EX_CAPACITY');
                } else {
                    assert(u128_of(slack, 'EX_CAPACITY') < market.midpoint, 'EX_CAPACITY');
                }
            }
        }

        // the residual's external reservation. a reservable residual always reserves a positive
        // amount, so a zero amount claims the residual is not reservable.
        let reservable = external
            && residual_base_u != 0
            && if slot.sell {
                residual_input_u != 0
            } else {
                let paid: u256 = (residual_input * slot.scale).into();
                paid >= limit.into()
            };
        if reservable {
            u128_of(external_amount, 'EX_EXTERNAL');
            u128_of(residual_base - external_amount, 'EX_EXTERNAL');
            if slot.sell {
                assert(limit <= slot.bound, 'EX_BOUND');
                u128_of(residual_input - external_amount, 'EX_EXTERNAL');
                assert(
                    (residual_base - external_amount) * (residual_input - external_amount) == 0,
                    'EX_EXTERNAL',
                );
            } else {
                assert(limit >= slot.bound, 'EX_BOUND');
                let slack = residual_input * slot.scale - external_amount * slot.bound.into();
                if external_amount == residual_base {
                    assert_nonnegative(slack, 'EX_EXTERNAL');
                } else {
                    assert(u128_of(slack, 'EX_EXTERNAL') < slot.bound, 'EX_EXTERNAL');
                }
            }
            if limit == slot.bound {
                totals.bound_hit = true;
            }
            reserved_offset = totals.reserved;
            totals.reserved += external_amount;
            reserved = external_amount;
            reserved_seq = ctx.seq;
        } else {
            assert(external_amount == 0, 'EX_EXTERNAL');
        }

        if clearing_capacity != 0 {
            totals.dual += shift_ceil_64(clearing_capacity * slot.reduced);
            totals.participants += 1;
            totals.capacity += clearing_capacity;
        }
        totals.filled_base += fill;
        totals.filled_quote += quote;
        remaining = residual_base;
        funding = residual_input;
        internal_out = if slot.sell {
            quote
        } else {
            fill
        };
    }

    // proceeds net of the pair's fee on each leg.
    let fee = ceil_fee(internal_out, market.fee_bps) + ceil_fee(external_out, market.fee_bps);
    totals.fee += fee;
    let proceeds = internal_out + external_out - fee;
    let removed = reserved == 0 && (removing || remaining == 0 || funding == 0);
    let refund = if removed {
        funding
    } else {
        0
    };
    Settled {
        remaining, funding, reserved, reserved_offset, reserved_seq, proceeds, refund, removed,
    }
}

#[inline(always)]
fn ceil_fee(amount: felt252, fee_bps: u128) -> felt252 {
    if amount == 0 || fee_bps == 0 {
        return 0;
    }
    let (fee, has_remainder) = felt_div_rem(amount * fee_bps.into(), FEE_BPS_DENOMINATOR);
    fee + has_remainder.into()
}

fn assert_reference_derivations(markets: Span<Market>) {
    for market in markets {
        let market = *market;
        assert(
            market.derivation_base_bid.into() < TWO_POW_120
                && market.derivation_base_ask.into() < TWO_POW_120
                && market.derivation_quote_bid.into() < TWO_POW_120
                && market.derivation_quote_ask.into() < TWO_POW_120,
            'EX_REF_BOUND',
        );
        if market.reference_methodology == REFERENCE_METHOD_DIRECT_BBO {
            assert(
                market.derivation_base_market_id == 0
                    && market.derivation_quote_market_id == 0
                    && market.derivation_base_bid != 0
                    && market.derivation_base_bid <= market.derivation_base_ask
                    && market.derivation_quote_bid == 0
                    && market.derivation_quote_ask == 0
                    && market.max_leg_skew_ms == 0,
                'EX_DIRECT_REF',
            );
            assert(
                market.midpoint == (market.derivation_base_bid + market.derivation_base_ask) / 2,
                'EX_DIRECT_MID',
            );
        } else {
            assert(
                market.reference_methodology == REFERENCE_METHOD_SYNTHETIC_CROSS_BBO,
                'EX_REF_METHOD',
            );
            assert(
                market.derivation_base_market_id != 0
                    && market.derivation_quote_market_id != 0
                    && market.derivation_base_market_id != market.derivation_quote_market_id
                    && market.max_leg_skew_ms != 0,
                'EX_SYNTH_REF',
            );
            let base = market_by_pair(markets, market.derivation_base_market_id);
            let quote = market_by_pair(markets, market.derivation_quote_market_id);
            assert(
                base.reference_methodology == REFERENCE_METHOD_DIRECT_BBO
                    && quote.reference_methodology == REFERENCE_METHOD_DIRECT_BBO
                    && base.base_id == market.base_id
                    && quote.base_id == market.quote_id
                    && base.quote_id == quote.quote_id
                    && base.scale == market.scale
                    && quote.scale == market.scale,
                'EX_SYNTH_LEGS',
            );
            assert(
                market.derivation_base_bid == base.derivation_base_bid
                    && market.derivation_base_ask == base.derivation_base_ask
                    && market.derivation_quote_bid == quote.derivation_base_bid
                    && market.derivation_quote_ask == quote.derivation_base_ask,
                'EX_SYNTH_BBO',
            );
            let earlier = min(base.observed_at_ms, quote.observed_at_ms);
            let later = max(base.observed_at_ms, quote.observed_at_ms);
            assert(later - earlier <= market.max_leg_skew_ms, 'EX_SYNTH_SKEW');
            assert(market.observed_at_ms == earlier, 'EX_SYNTH_TIME');
            let (bid, _) = felt_div_rem(
                market.derivation_base_bid.into() * market.scale.into(),
                market.derivation_quote_ask,
            );
            let (ask_floor, ask_remainder) = felt_div_rem(
                market.derivation_base_ask.into() * market.scale.into(),
                market.derivation_quote_bid,
            );
            let ask = ask_floor + ask_remainder.into();
            let bid = u128_of(bid, 'EX_SYNTH_BID');
            let ask = u128_of(ask, 'EX_SYNTH_ASK');
            assert(bid != 0 && bid <= ask, 'EX_SYNTH_BBO');
            assert(market.midpoint == (bid + ask) / 2, 'EX_SYNTH_MID');
        }
    }
}

fn market_by_pair(markets: Span<Market>, pair_id: felt252) -> Market {
    let mut found: Option<Market> = Option::None;
    for market in markets {
        if (*market).pair_id == pair_id {
            assert(found.is_none(), 'EX_SYNTH_DUP');
            found = Option::Some(*market);
        }
    }
    found.expect('EX_SYNTH_LEG')
}

#[inline(always)]
fn emit_order_outputs(
    ref state: State,
    ctx: Context,
    slot: Slot,
    settled: Settled,
    order_id: felt252,
    owner_public_key: felt252,
    spend_authority: felt252,
    withdraw_authority: felt252,
    nonce: felt252,
) {
    let (proceeds_blinding, refund_blinding, _) = order_output_blindings(nonce, ctx.seq);
    if settled.proceeds != 0 {
        emit_note_output(
            ref state,
            ctx.seq,
            slot.output_id,
            settled.proceeds,
            proceeds_blinding,
            order_id,
            owner_public_key,
            spend_authority,
            withdraw_authority,
        );
    }
    if settled.refund != 0 {
        emit_note_output(
            ref state,
            ctx.seq,
            slot.input_id,
            settled.refund,
            refund_blinding,
            order_id,
            owner_public_key,
            spend_authority,
            withdraw_authority,
        );
    }
}

#[inline(always)]
fn emit_note_output(
    ref state: State,
    seq: felt252,
    asset_id: felt252,
    amount: felt252,
    blinding: felt252,
    metadata: felt252,
    owner_public_key: felt252,
    spend_authority: felt252,
    withdraw_authority: felt252,
) {
    let commitment = note_commitment(
        asset_id,
        amount,
        owner_public_key,
        spend_authority,
        withdraw_authority,
        blinding,
        seq,
        metadata,
    );
    let leaf = output_note_leaf(commitment, asset_id, amount, withdraw_authority);
    // the published amount is padded by the output's secret blinding.
    let (enc_remaining, enc_reserved, enc_offset) = output_aux_blindings(blinding);
    absorb_output_record(
        ref state.outputs, leaf, amount + blinding, enc_remaining, enc_reserved, enc_offset,
    );
    state.output_count += 1;
}

#[inline(always)]
fn absorb_output_record(
    ref outputs: Sponge,
    leaf: felt252,
    enc: felt252,
    enc_remaining: felt252,
    enc_reserved: felt252,
    enc_reserved_offset: felt252,
) {
    outputs.absorb_pair(leaf, enc);
    outputs.absorb_pair(enc_remaining, enc_reserved);
    outputs.absorb(enc_reserved_offset);
}

#[inline(always)]
fn emit_residual_output(
    ref state: State,
    ctx: Context,
    slot: Slot,
    settled: Settled,
    limit: u128,
    expiry: felt252,
    external: bool,
    order_id: felt252,
    owner_digest: felt252,
    nonce: felt252,
) -> felt252 {
    let (_, _, blinding) = order_output_blindings(nonce, ctx.seq);
    let commitment = residual_note_commitment(
        ctx.chain_context,
        slot.input_id,
        slot.pair_id,
        slot.sell,
        external,
        settled.remaining,
        limit,
        settled.funding,
        settled.reserved,
        settled.reserved_offset,
        settled.reserved_seq,
        expiry,
        order_id,
        ctx.seq,
        owner_digest,
        blinding,
    );
    let leaf = poseidon2(RESIDUAL_NOTE_LEAF_DOMAIN, commitment);
    let (remaining_blinding, reserved_blinding, offset_blinding) = output_aux_blindings(blinding);
    let enc_remaining = settled.remaining + remaining_blinding;
    let enc_reserved = settled.reserved + reserved_blinding;
    let enc_offset = settled.reserved_offset + offset_blinding;
    absorb_output_record(
        ref state.outputs,
        leaf,
        settled.funding + blinding,
        enc_remaining,
        enc_reserved,
        enc_offset,
    );
    state.output_count += 1;
    commitment
}
