use core::poseidon::poseidon_hash_span;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use zylith_exchange_statement::exchange::certificate::{Market, precision_allowance};
use zylith_exchange_statement::exchange::common::{
    SpongeTrait, TWO_POW_120, TWO_POW_64, felt_div_rem,
};

const MAX_AMOUNT: u128 = 0x3fffffffffffffffffffffffffff;

#[test]
#[fuzzer(runs: 512, seed: 51932)]
fn five_field_absorption_matches_the_standard_hash(
    a: felt252, b: felt252, c: felt252, d: felt252, e: felt252, prefix: u8,
) {
    let mut sponge = SpongeTrait::new();
    let mut fields = array![];
    let prefix_length: u32 = (prefix % 8).into();
    for i in 0_u32..prefix_length {
        let value = a + Into::<u32, felt252>::into(i);
        sponge.absorb(value);
        fields.append(value);
    }
    // three odd-sized records exercise both pending states and repeated batch absorption.
    for i in 0_u32..3 {
        let last = e + i.into();
        sponge.absorb5(a, b, c, d, last);
        fields.append(a);
        fields.append(b);
        fields.append(c);
        fields.append(d);
        fields.append(last);
        assert(sponge.finish() == poseidon_hash_span(fields.span()), 'record hash mismatch');
    }
    // continuation must retain the same pending field, including pair absorption after a batch.
    sponge.absorb_pair(b, c);
    fields.append(b);
    fields.append(c);
    sponge.absorb(d);
    fields.append(d);
    assert(sponge.finish() == poseidon_hash_span(fields.span()), 'continued hash mismatch');
}

#[test]
fn five_field_absorption_handles_zero_maximum_and_empty_prefixes() {
    for value in array![0, -1, 0x100000000000000000000000000000000].span() {
        for prefix in 0_u32..8 {
            let mut sponge = SpongeTrait::new();
            let mut fields = array![];
            for _ in 0..prefix {
                sponge.absorb(*value);
                fields.append(*value);
            }
            assert(sponge.finish() == poseidon_hash_span(fields.span()), 'prefix mismatch');
            for _ in 0_u32..8 {
                sponge.absorb5(*value, *value, *value, *value, *value);
                for _ in 0_u32..5 {
                    fields.append(*value);
                }
                assert(
                    sponge.finish() == poseidon_hash_span(fields.span()), 'boundary hash mismatch',
                );
            }
        }
    }
}

#[test]
#[fuzzer(runs: 512, seed: 51933)]
fn nine_field_absorption_matches_the_standard_hash(
    a: felt252,
    b: felt252,
    c: felt252,
    d: felt252,
    e: felt252,
    f: felt252,
    g: felt252,
    h: felt252,
    i: felt252,
    prefix: u8,
) {
    let mut sponge = SpongeTrait::new();
    let mut fields = array![];
    let prefix_length: u32 = (prefix % 8).into();
    for _ in 0_u32..prefix_length {
        sponge.absorb(a);
        fields.append(a);
    }
    for _ in 0_u32..3 {
        sponge.absorb9(a, b, c, d, e, f, g, h, i);
        for field in array![a, b, c, d, e, f, g, h, i].span() {
            fields.append(*field);
        }
        assert(sponge.finish() == poseidon_hash_span(fields.span()), 'book hash mismatch');
    }
    sponge.absorb5(a, b, c, d, e);
    for field in array![a, b, c, d, e].span() {
        fields.append(*field);
    }
    sponge.absorb_pair(f, g);
    fields.append(f);
    fields.append(g);
    sponge.absorb(h);
    fields.append(h);
    assert(sponge.finish() == poseidon_hash_span(fields.span()), 'mixed record mismatch');
}

#[test]
#[fuzzer(runs: 512, seed: 51934)]
fn seventeen_field_absorption_matches_the_standard_hash(
    a: felt252,
    b: felt252,
    c: felt252,
    d: felt252,
    e: felt252,
    f: felt252,
    g: felt252,
    h: felt252,
    i: felt252,
    j: felt252,
    k: felt252,
    l: felt252,
    m: felt252,
    n: felt252,
    o: felt252,
    p: felt252,
    q: felt252,
    prefix: u8,
) {
    let mut sponge = SpongeTrait::new();
    let mut fields = array![];
    let prefix_length: u32 = (prefix % 8).into();
    for _ in 0..prefix_length {
        sponge.absorb(a);
        fields.append(a);
    }
    for _ in 0_u32..3 {
        sponge.absorb17(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q);
        for value in array![a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q].span() {
            fields.append(*value);
        }
        assert(sponge.finish() == poseidon_hash_span(fields.span()), 'market hash mismatch');
    }
    sponge.absorb9(a, b, c, d, e, f, g, h, i);
    for value in array![a, b, c, d, e, f, g, h, i].span() {
        fields.append(*value);
    }
    sponge.absorb5(j, k, l, m, n);
    for value in array![j, k, l, m, n].span() {
        fields.append(*value);
    }
    sponge.absorb_pair(o, p);
    fields.append(o);
    fields.append(p);
    sponge.absorb(q);
    fields.append(q);
    assert(sponge.finish() == poseidon_hash_span(fields.span()), 'market continuation');
}

#[test]
fn seventeen_field_absorption_covers_field_and_prefix_boundaries() {
    for value in array![0, -1, 0x100000000000000000000000000000000].span() {
        for prefix in 0_u32..4 {
            let mut sponge = SpongeTrait::new();
            let mut fields = array![];
            for _ in 0..prefix {
                sponge.absorb(*value);
                fields.append(*value);
            }
            for _ in 0_u32..3 {
                sponge
                    .absorb17(
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                        *value,
                    );
                for _ in 0_u32..17 {
                    fields.append(*value);
                }
                assert(sponge.finish() == poseidon_hash_span(fields.span()), 'market boundary');
            }
        }
    }
}

#[starknet::interface]
trait IAdmissionValueHarness<TContractState> {
    fn check(
        self: @TContractState,
        amount: u128,
        limit: u128,
        scale: u128,
        minimum: u128,
        funding: u128,
        sell: bool,
    );
}

#[starknet::contract]
mod AdmissionValueHarness {
    use zylith_exchange_statement::exchange::transition::assert_admission_value;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl Check of super::IAdmissionValueHarness<ContractState> {
        fn check(
            self: @ContractState,
            amount: u128,
            limit: u128,
            scale: u128,
            minimum: u128,
            funding: u128,
            sell: bool,
        ) {
            assert_admission_value(amount, limit, scale, minimum, funding, sell);
        }
    }
}

fn market(scale: u128, midpoint: u128) -> Market {
    Market {
        pair_id: 1,
        base: 0,
        quote: 1,
        base_id: 1,
        quote_id: 2,
        midpoint,
        scale,
        fee_bps: 0,
        min_order_quote_amount: 1,
        observed_at_ms: 1,
        reference_methodology: 0,
        derivation_base_market_id: 0,
        derivation_quote_market_id: 0,
        derivation_base_bid: midpoint,
        derivation_base_ask: midpoint,
        derivation_quote_bid: 0,
        derivation_quote_ask: 0,
        max_leg_skew_ms: 0,
    }
}

fn reference_div_rem(value: felt252, divisor: u128) -> (felt252, bool) {
    let wide: u256 = value.into();
    let divisor: u256 = divisor.into();
    let (quotient, remainder) = DivRem::div_rem(wide, divisor.try_into().unwrap());
    (quotient.try_into().unwrap(), remainder != 0)
}

#[test]
#[fuzzer(runs: 512, seed: 51927)]
fn division_matches_the_wide_reference(value: felt252, divisor: u128) {
    let divisor = if divisor == 0 {
        1
    } else {
        divisor
    };
    assert(felt_div_rem(value, divisor) == reference_div_rem(value, divisor), 'division mismatch');
}

#[test]
#[fuzzer(runs: 512, seed: 51930)]
fn native_division_matches_the_wide_reference(value: u128, divisor: u128) {
    let divisor = if divisor == 0 {
        1
    } else {
        divisor
    };
    assert(
        felt_div_rem(value.into(), divisor) == reference_div_rem(value.into(), divisor),
        'native mismatch',
    );
}

#[test]
fn division_checks_both_sides_of_the_native_boundary() {
    let values = array![
        0, 1, 0xffffffffffffffffffffffffffffffff, 0x100000000000000000000000000000000,
        0x100000000000000000000000000000001, -1,
    ];
    for value in values.span() {
        for divisor in array![1_u128, 2, 3, 10000, TWO_POW_64, 0xffffffffffffffffffffffffffffffff]
            .span() {
            assert(
                felt_div_rem(*value, *divisor) == reference_div_rem(*value, *divisor),
                'division boundary',
            );
        }
    }
}

#[test]
#[should_panic(expected: 'EX_DIVISOR')]
fn native_division_rejects_zero_divisor() {
    felt_div_rem(1, 0);
}

#[test]
#[should_panic(expected: 'EX_DIVISOR')]
fn wide_division_rejects_zero_divisor() {
    felt_div_rem(0x100000000000000000000000000000000, 0);
}

fn reference_allowance(scale: u128, midpoint: u128, capacity: u128) -> felt252 {
    let numerator: u256 = capacity.into() * Into::<u128, u256>::into(2 * scale + midpoint);
    let denominator: u256 = scale.into() * Into::<u128, u256>::into(TWO_POW_64);
    let (quotient, remainder) = DivRem::div_rem(numerator, denominator.try_into().unwrap());
    let quotient: felt252 = quotient.try_into().unwrap();
    quotient + (remainder != 0).into()
}

#[test]
#[fuzzer(runs: 512, seed: 51928)]
fn allowance_matches_wide_division(scale: u128, midpoint: u128, capacity: u128) {
    let scale = scale % (TWO_POW_120 - 1) + 1;
    let midpoint = midpoint % (TWO_POW_120 - 1) + 1;
    assert(
        precision_allowance(
            market(scale, midpoint), capacity.into(),
        ) == reference_allowance(scale, midpoint, capacity),
        'allowance mismatch',
    );
}

#[test]
#[fuzzer(runs: 512, seed: 51931)]
fn small_allowance_matches_wide_division(scale: u64, midpoint: u64, capacity: u64) {
    let scale: u128 = if scale == 0 {
        1
    } else {
        scale.into()
    };
    let midpoint: u128 = if midpoint == 0 {
        1
    } else {
        midpoint.into()
    };
    assert(
        precision_allowance(
            market(scale, midpoint), capacity.into(),
        ) == reference_allowance(scale, midpoint, capacity.into()),
        'small allowance mismatch',
    );
}

#[test]
fn allowance_covers_zero_exact_multiples_and_both_remainders() {
    for capacity in array![0_u128, 1, TWO_POW_64 - 1, TWO_POW_64, TWO_POW_64 + 1, MAX_AMOUNT]
        .span() {
        for scale in array![1_u128, 3, TWO_POW_64 + 1, TWO_POW_120 - 1].span() {
            for midpoint in array![1_u128, 2, 7, TWO_POW_120 - 1].span() {
                assert(
                    precision_allowance(
                        market(*scale, *midpoint), (*capacity).into(),
                    ) == reference_allowance(*scale, *midpoint, *capacity),
                    'allowance boundary',
                );
            }
        }
    }
}

#[test]
#[feature("safe_dispatcher")]
#[fuzzer(runs: 512, seed: 51929)]
fn admission_acceptance_matches_rounded_quote(
    amount: u128, limit: u128, scale: u128, minimum: u128, funding: u128, mode: u8,
) {
    let amount = amount % MAX_AMOUNT + 1;
    let limit = limit % (TWO_POW_120 - 1) + 1;
    let scale = scale % (TWO_POW_120 - 1) + 1;
    let minimum = if mode % 2 == 0 {
        1
    } else if minimum == 0 {
        1
    } else {
        minimum
    };
    let funding = funding % (MAX_AMOUNT + 1);
    let sell = mode % 4 < 2;
    let product: u256 = amount.into() * Into::<u128, u256>::into(limit);
    let (floor, remainder) = DivRem::div_rem(
        product, Into::<u128, u256>::into(scale).try_into().unwrap(),
    );
    let rounding: u256 = if remainder != 0 {
        1
    } else {
        0
    };
    let rounded = floor + rounding;
    let required = if sell {
        amount.into()
    } else {
        rounded
    };
    let expected = rounded <= 0xffffffffffffffffffffffffffffffff
        && rounded >= minimum.into()
        && Into::<u128, u256>::into(funding) >= required;
    let (contract_address, _) = declare("AdmissionValueHarness")
        .unwrap()
        .contract_class()
        .deploy(@array![])
        .unwrap();
    let result = IAdmissionValueHarnessSafeDispatcher { contract_address }
        .check(amount, limit, scale, minimum, funding, sell);
    assert(result.is_ok() == expected, 'admission mismatch');
}

#[test]
#[feature("safe_dispatcher")]
fn admission_rejects_short_funding_minimum_boundary_and_quote_overflow() {
    let (contract_address, _) = declare("AdmissionValueHarness")
        .unwrap()
        .contract_class()
        .deploy(@array![])
        .unwrap();
    let harness = IAdmissionValueHarnessSafeDispatcher { contract_address };
    assert(harness.check(2, 4, 3, 3, 3, false).is_ok(), 'valid ceil');
    assert(harness.check(2, 4, 3, 3, 2, false).is_err(), 'short buy');
    assert(harness.check(2, 4, 3, 4, 3, false).is_err(), 'minimum ceil');
    assert(harness.check(2, 3, 2, 4, 2, true).is_err(), 'exact below minimum');
    assert(harness.check(2, 3, 2, 3, 2, true).is_ok(), 'exact minimum');
    assert(harness.check(2, 3, 2, 3, 1, true).is_err(), 'short sell');
    assert(
        harness.check(TWO_POW_64, TWO_POW_64, 1, 1, TWO_POW_64, true).is_err(), 'quote overflow',
    );
    assert(
        harness
            .check(
                TWO_POW_64 - 1,
                TWO_POW_64 + 1,
                1,
                0xffffffffffffffffffffffffffffffff,
                TWO_POW_64 - 1,
                true,
            )
            .is_ok(),
        'maximum quote',
    );
    assert(
        harness
            .check(
                MAX_AMOUNT,
                TWO_POW_120 - 1,
                TWO_POW_120 - 1,
                0xffffffffffffffffffffffffffffffff,
                MAX_AMOUNT,
                true,
            )
            .is_err(),
        'large minimum',
    );
}
