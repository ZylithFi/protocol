//! the global clearing certificate's market-level checks: canonical weights derived from
//! m0 and the price-grid precision allowance (see `zylith_core::exact_clearing`).

use core::cmp::max;
use super::common::{TWO_POW_64, next_u128, next_u32};

const MAX_WEIGHT_MINUS_ONE: u128 = 0xfffffffffffffff;
const MAX_REFERENCE_COMPONENT: u128 = 0xffffffffffffffff;

#[derive(Copy, Drop)]
pub struct Asset {
    pub id: felt252,
    pub weight: u128,
    pub price: u128,
}

#[derive(Copy, Drop)]
pub struct Market {
    pub pair_id: felt252,
    pub base: u32,
    pub quote: u32,
    pub base_id: felt252,
    pub quote_id: felt252,
    pub midpoint: u128,
    pub scale: u128,
    pub fee_bps: u128,
    pub min_order_quote_amount: u128,
    pub observed_at_ms: u64,
    pub reference_methodology: u8,
    pub derivation_base_market_id: felt252,
    pub derivation_quote_market_id: felt252,
    pub derivation_base_bid: u128,
    pub derivation_base_ask: u128,
    pub derivation_quote_bid: u128,
    pub derivation_quote_ask: u128,
    pub max_leg_skew_ms: u64,
}

/// `ceil(capacity * (2 * scale + midpoint) / (scale * 2^64))`.
pub fn precision_allowance(market: Market, capacity: felt252) -> felt252 {
    if capacity == 0 {
        return 0;
    }
    let capacity: u256 = capacity.into();
    let spread: u256 = (market.scale * 2 + market.midpoint).into();
    let denominator: u256 = market.scale.into() * TWO_POW_64.into();
    let (quotient, remainder) = DivRem::div_rem(capacity * spread, denominator.try_into().unwrap());
    let quotient: felt252 = quotient.try_into().expect('EX_ALLOWANCE');
    quotient + (remainder != 0).into()
}

pub fn assert_distinct_market_pairs(markets: Span<Market>) {
    let count = markets.len();
    let mut left: u32 = 0;
    while left != count {
        let mut right = left + 1;
        while right != count {
            let a = *markets.at(left);
            let b = *markets.at(right);
            assert(a.base != b.base || a.quote != b.quote, 'EX_MARKET_DUPLICATE');
            right += 1;
        }
        left += 1;
    }
}

/// every asset is traded by some market, so no weight is unconstrained.
pub fn assert_assets_used(asset_count: u32, markets: Span<Market>) {
    let mut asset: u32 = 0;
    while asset != asset_count {
        let mut used = false;
        for market in markets {
            if (*market).base == asset || (*market).quote == asset {
                used = true;
            }
        }
        assert(used, 'EX_ASSET_UNUSED');
        asset += 1;
    }
}

/// binds every objective weight to a direct asset/usdc observation from the same authenticated
/// price batch. non-usdc markets retain their independent direct execution midpoints and do not
/// constrain the objective vector.
///
/// - usdc has value one and every other asset uses the lowest-index direct usdc market;
/// - one maximum covers the full usdc-denominated vector;
/// - `weight = max(1, floor((2^60 - 1) * value / value(max)))`.
pub fn assert_canonical_weights(
    ref data: Span<felt252>, assets: Span<Asset>, markets: Span<Market>, numeraire_id: felt252,
) {
    let count = assets.len();
    let mut numerators: Array<u128> = array![];
    let mut denominators: Array<u128> = array![];
    let mut roots: Array<u32> = array![];
    let mut depths: Array<u32> = array![];
    let mut parents: Array<u32> = array![];
    let mut maxima: Array<u32> = array![];
    for _ in 0..count {
        let numerator = next_u128(ref data);
        let denominator = next_u128(ref data);
        assert(numerator != 0 && numerator <= MAX_REFERENCE_COMPONENT, 'EX_VALUE');
        assert(denominator != 0 && denominator <= MAX_REFERENCE_COMPONENT, 'EX_VALUE');
        numerators.append(numerator);
        denominators.append(denominator);
        roots.append(next_u32(ref data));
        depths.append(next_u32(ref data));
        parents.append(next_u32(ref data));
        maxima.append(next_u32(ref data));
    }
    let numerators = numerators.span();
    let denominators = denominators.span();
    let roots = roots.span();
    let depths = depths.span();
    let parents = parents.span();
    let maxima = maxima.span();

    let mut numeraire: Option<u32> = Option::None;
    let mut index: u32 = 0;
    while index != count {
        if (*assets.at(index)).id == numeraire_id {
            assert(numeraire.is_none(), 'EX_USDC_DUPLICATE');
            numeraire = Option::Some(index);
        }
        index += 1;
    }
    let numeraire = numeraire.expect('EX_USDC_MISSING');
    let mut asset: u32 = 0;
    while asset != count {
        let value_numerator: u256 = (*numerators.at(asset)).into();
        let value_denominator: u256 = (*denominators.at(asset)).into();
        let root = *roots.at(asset);
        let depth = *depths.at(asset);
        assert(root == numeraire, 'EX_USDC_ROOT');
        if asset == numeraire {
            assert(depth == 0, 'EX_ROOT_DEPTH');
            assert(*numerators.at(asset) == 1 && *denominators.at(asset) == 1, 'EX_USDC_VALUE');
        } else {
            assert(depth == 1, 'EX_PARENT_DEPTH');
            let parent_market = *parents.at(asset);
            assert(parent_market < markets.len(), 'EX_PARENT_MARKET');
            let market = *markets.at(parent_market);
            let asset_is_base = if market.base == asset && market.quote == numeraire {
                true
            } else {
                assert(market.quote == asset && market.base == numeraire, 'EX_PARENT_MARKET');
                false
            };
            let mut earlier: u32 = 0;
            while earlier != parent_market {
                let candidate = *markets.at(earlier);
                assert(
                    !(candidate.base == asset && candidate.quote == numeraire)
                        && !(candidate.quote == asset && candidate.base == numeraire),
                    'EX_PARENT_ORDER',
                );
                earlier += 1;
            }
            if asset_is_base {
                assert(
                    value_numerator
                        * market.scale.into() == value_denominator
                        * market.midpoint.into(),
                    'EX_USDC_VALUE',
                );
            } else {
                assert(
                    value_numerator
                        * market.midpoint.into() == value_denominator
                        * market.scale.into(),
                    'EX_USDC_VALUE',
                );
            }
        }
        let maximum = *maxima.at(asset);
        assert(maximum < count, 'EX_MAX_COMPONENT');
        assert(*maxima.at(numeraire) == maximum, 'EX_MAX_SHARED');
        let max_numerator: u256 = (*numerators.at(maximum)).into();
        let max_denominator: u256 = (*denominators.at(maximum)).into();
        // value(max) >= value(asset).
        assert(
            max_numerator * value_denominator >= value_numerator * max_denominator, 'EX_MAX_VALUE',
        );
        // weight = max(1, floor((2^60 - 1) * n * max_d / (d * max_n))).
        let scaled = value_numerator * max_denominator * MAX_WEIGHT_MINUS_ONE.into();
        let divisor = value_denominator * max_numerator;
        let (quotient, _) = DivRem::div_rem(scaled, divisor.try_into().unwrap());
        let quotient: u128 = quotient.try_into().expect('EX_WEIGHT');
        assert((*assets.at(asset)).weight == max(quotient, 1), 'EX_WEIGHT');
        asset += 1;
    }
}
