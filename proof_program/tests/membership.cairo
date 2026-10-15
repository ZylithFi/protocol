use zylith_exchange_statement::exchange::common::{
    NOTE_ACCUMULATOR_LEAF_DOMAIN, TWO_POW_128, note_accumulator_node, poseidon2,
    read_accumulator_root, read_subtree_root,
};
use zylith_exchange_statement::exchange::transition::{
    read_admission_allocation, read_admission_terms, read_batch_positions, read_funding_batches,
    read_funding_note, read_funding_subtree,
};

const TWO_POW_110: u128 = 0x4000000000000000000000000000;

#[test]
#[fuzzer(runs: 256, seed: 51944)]
fn packed_admission_terms_preserve_every_field(
    amount: u128, limit: u128, expiry: u64, external: bool, count: u8, inherited: bool,
) {
    let amount = amount % TWO_POW_110;
    let limit = limit % 0x1000000000000000000000000000000;
    let count = count % 8;
    let expiry = expiry % 0x1000000000000;
    let mut data = array![
        amount.into() + limit.into() * TWO_POW_128,
        expiry.into()
            + (external.into() + count.into() * 2 + inherited.into() * 16) * 0x1000000000000,
        777,
    ]
        .span();
    assert(
        read_admission_terms(
            ref data,
        ) == (amount, limit, expiry, external, count.into(), inherited),
        'admission fields',
    );
    assert(data == array![777].span(), 'admission framing');
}

#[test]
#[fuzzer(runs: 256, seed: 51945)]
fn packed_admission_allocation_preserves_every_field(
    fill: u128, quote: u128, capacity: u128, external: u128,
) {
    let fill = fill % TWO_POW_110;
    let capacity = capacity % TWO_POW_110;
    let external = external % TWO_POW_110;
    let mut data = array![
        quote.into() + fill.into() * TWO_POW_128, capacity.into() + external.into() * TWO_POW_128,
        777,
    ]
        .span();
    assert(
        read_admission_allocation(
            ref data,
        ) == (fill.into(), quote.into(), capacity.into(), external.into()),
        'allocation fields',
    );
    assert(data == array![777].span(), 'allocation framing');
}

#[test]
#[should_panic(expected: ('EX_ADMISSION_ENCODING',))]
fn packed_admission_rejects_high_bits() {
    let mut data = array![0, 0x20000000000000].span();
    read_admission_terms(ref data);
}

#[test]
#[should_panic(expected: ('EX_ALLOCATION_ENCODING',))]
fn packed_allocation_rejects_fill_high_bits() {
    let mut data = array![0x400000000000000000000000000000000000000000000000000000000000, 0].span();
    read_admission_allocation(ref data);
}

#[test]
#[should_panic(expected: ('EX_ALLOCATION_ENCODING',))]
fn packed_allocation_rejects_external_high_bits() {
    let mut data = array![0, 0x400000000000000000000000000000000000000000000000000000000000].span();
    read_admission_allocation(ref data);
}

#[test]
#[should_panic(expected: ('EX_SHORT',))]
fn packed_allocation_requires_both_fields() {
    let mut data = array![0].span();
    read_admission_allocation(ref data);
}

#[test]
fn packed_admission_and_allocation_cover_maximum_widths() {
    let mut terms = array![
        (TWO_POW_110 - 1).into() + 0xffffffffffffffffffffffffffffff * TWO_POW_128, 0x1fffffffffffff,
    ]
        .span();
    assert(
        read_admission_terms(
            ref terms,
        ) == (TWO_POW_110 - 1, 0xffffffffffffffffffffffffffffff, 0xffffffffffff, true, 7, true),
        'maximum admission',
    );
    let mut allocation = array![
        0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        (TWO_POW_110 - 1).into() + (TWO_POW_110 - 1).into() * TWO_POW_128,
    ]
        .span();
    assert(
        read_admission_allocation(
            ref allocation,
        ) == (
            (TWO_POW_110 - 1).into(),
            0xffffffffffffffffffffffffffffffff,
            (TWO_POW_110 - 1).into(),
            (TWO_POW_110 - 1).into(),
        ),
        'maximum allocation',
    );
    assert(terms.is_empty() && allocation.is_empty(), 'maximum framing');
}

#[test]
#[fuzzer(runs: 128, seed: 51946)]
fn packed_batch_positions_preserve_word_boundaries(first: u32, count: u8) {
    let count: u32 = (count % 22).into();
    let mut expected = array![];
    let mut words = array![];
    let mut packed = 0;
    let mut shift = 1;
    for i in 0..count {
        let position: u64 = (first.into() + i.into()) % 0x100000000;
        expected.append(position.try_into().unwrap());
        packed += position.into() * shift;
        if i % 4 == 3 || i + 1 == count {
            words.append(packed);
            packed = 0;
            shift = 1;
        } else {
            shift *= 0x100000000;
        }
    }
    words.append(777);
    let mut data = words.span();
    assert(read_batch_positions(ref data, count).span() == expected.span(), 'batch positions');
    assert(data == array![777].span(), 'batch word framing');
}

#[test]
#[should_panic(expected: ('EX_U128',))]
fn packed_batch_positions_reject_bits_above_four_indices() {
    let mut data = array![TWO_POW_128].span();
    read_batch_positions(ref data, 4);
}

#[test]
#[should_panic(expected: ('EX_BATCH_ENCODING',))]
fn packed_batch_positions_reject_unused_final_word_slots() {
    let mut data = array![0, 0x100000000].span();
    read_batch_positions(ref data, 5);
}

#[test]
#[should_panic(expected: ('EX_SHORT',))]
fn packed_batch_positions_require_every_word() {
    let mut data = array![0].span();
    read_batch_positions(ref data, 8);
}

#[test]
#[fuzzer(runs: 256, seed: 51942)]
fn compact_subtree_matches_full_directions(
    leaf: felt252, salt: felt252, depth: u8, position: u16, reference: u16,
) {
    let depth: u32 = (depth % 17).into();
    let mut position: u32 = position.into();
    for _ in depth..16 {
        position /= 2;
    }
    let reference: u32 = (reference % 4096).into();
    let mut compact = array![(depth + position * 32).into() + reference.into() * 0x200000];
    let mut full = array![depth.into()];
    for level in 0..depth {
        let sibling = salt + level.into();
        let (parent, right) = DivRem::div_rem(position, 2);
        compact.append(sibling);
        full.append(sibling);
        full.append(right.into());
        position = parent;
    }
    let mut full = full.span();
    let mut compact = compact.span();
    let (root, actual_reference) = read_funding_subtree(ref compact, leaf);
    assert(root == read_subtree_root(ref full, leaf), 'subtree mismatch');
    assert(actual_reference == reference, 'reference mismatch');
    assert(compact.is_empty() && full.is_empty(), 'subtree trailing');
}

#[test]
#[fuzzer(runs: 256, seed: 51943)]
fn packed_note_preserves_every_field(amount: u128, nonce: u64, flags: u8, key: felt252) {
    let flags: u128 = (flags % 4).into();
    let mut data = array![
        amount.into()
            + nonce.into() * 0x100000000000000000000000000000000
            + flags.into() * 0x1000000000000000000000000000000000000000000000000,
    ];
    let (withdraw_flag, owner_flag) = DivRem::div_rem(flags, 2_u128.try_into().unwrap());
    if owner_flag != 0 {
        data.append(key);
    }
    if withdraw_flag != 0 {
        data.append(key + 1);
    }
    data.append(123);
    data.append(456);
    let mut data = data.span();
    let (actual_amount, owner, withdraw, blinding, actual_nonce, metadata) = read_funding_note(
        ref data, 11, 22,
    );
    assert(actual_amount == amount && actual_nonce == nonce.into(), 'numeric fields');
    assert(owner == if owner_flag != 0 {
        key
    } else {
        11
    }, 'owner field');
    assert(withdraw == if withdraw_flag != 0 {
        key + 1
    } else {
        22
    }, 'withdraw field');
    assert(blinding == 123 && metadata == 456 && data.is_empty(), 'remaining fields');
}

#[test]
#[should_panic(expected: ('EX_FUNDING_ENCODING',))]
fn packed_note_rejects_unused_high_bits() {
    let mut data = array![0x4000000000000000000000000000000000000000000000000, 123, 456].span();
    read_funding_note(ref data, 11, 22);
}

#[test]
#[should_panic(expected: ('EX_SHORT',))]
fn packed_note_requires_explicit_keys() {
    let mut data = array![0x3000000000000000000000000000000000000000000000000, 123, 456].span();
    read_funding_note(ref data, 11, 22);
}

#[test]
#[should_panic(expected: ('EX_BATCH_REFERENCE',))]
fn packed_membership_rejects_reference_high_bits() {
    let mut data = array![0x200000000].span();
    read_funding_subtree(ref data, 123);
}

#[test]
fn packed_note_covers_maximum_integer_widths() {
    let mut data = array![0x3ffffffffffffffffffffffffffffffffffffffffffffffff, 33, 44, 123, 456]
        .span();
    let (amount, owner, withdraw, blinding, nonce, metadata) = read_funding_note(ref data, 11, 22);
    assert(amount == 0xffffffffffffffffffffffffffffffff, 'maximum amount');
    assert(nonce == 0xffffffffffffffff, 'maximum nonce');
    assert(owner == 33 && withdraw == 44 && blinding == 123 && metadata == 456, 'explicit fields');
    assert(data.is_empty(), 'note trailing');
}

#[test]
#[should_panic(expected: ('EX_SUBTREE_POSITION',))]
fn zero_depth_cannot_hide_position_bits() {
    let mut data = array![32].span();
    read_funding_subtree(ref data, 123);
}

#[test]
#[should_panic(expected: ('EX_SUBTREE_DEPTH',))]
fn subtree_depth_above_sixteen_fails() {
    let mut data = array![17].span();
    read_funding_subtree(ref data, 123);
}

#[test]
#[fuzzer(runs: 128, seed: 51940)]
fn singleton_frontier_matches_the_full_path(position: u32, batch: felt252, salt: felt252) {
    let mut proof = array![1, position.into(), batch, 32];
    let mut full = array![];
    let mut index = position;
    for level in 0_u32..32 {
        let sibling = salt + level.into();
        let (parent, right) = DivRem::div_rem(index, 2);
        proof.append(sibling);
        full.append(sibling);
        full.append(right.into());
        index = parent;
    }
    let mut full = full.span();
    let expected = read_accumulator_root(ref full, batch);
    let mut proof = proof.span();
    let roots = read_funding_batches(ref proof, expected);
    assert(roots == array![batch].span(), 'singleton roots');
    assert(full.is_empty() && proof.is_empty(), 'singleton trailing');
}

#[test]
#[fuzzer(runs: 128, seed: 51941)]
fn adjacent_batches_share_the_frontier(first: felt252, second: felt252) {
    let mut proof = array![2, 0x100000000, first, second, 31];
    let mut expected = note_accumulator_node(
        poseidon2(NOTE_ACCUMULATOR_LEAF_DOMAIN, first),
        poseidon2(NOTE_ACCUMULATOR_LEAF_DOMAIN, second),
        0,
    );
    for level in 1_u32..32 {
        proof.append(0);
        expected = note_accumulator_node(expected, 0, level);
    }
    let mut proof = proof.span();
    let roots = read_funding_batches(ref proof, expected);
    assert(roots == array![first, second].span(), 'adjacent roots');
    assert(proof.is_empty(), 'adjacent trailing');
}

#[test]
fn sparse_frontier_covers_both_ends_of_the_u32_index_space() {
    let mut proof = array![2, 0xffffffff00000000, 123, 456, 62];
    let mut left = poseidon2(NOTE_ACCUMULATOR_LEAF_DOMAIN, 123);
    let mut right = poseidon2(NOTE_ACCUMULATOR_LEAF_DOMAIN, 456);
    for level in 0_u32..31 {
        proof.append(0);
        proof.append(0);
        left = note_accumulator_node(left, 0, level);
        right = note_accumulator_node(0, right, level);
    }
    let expected = note_accumulator_node(left, right, 31);
    let mut proof = proof.span();
    let roots = read_funding_batches(ref proof, expected);
    assert(roots == array![123, 456].span(), 'sparse roots');
    assert(proof.is_empty(), 'sparse trailing');
}

#[test]
#[should_panic(expected: ('EX_SHORT',))]
fn missing_frontier_sibling_fails() {
    let mut data = array![1, 0, 123, 0].span();
    read_funding_batches(ref data, 1);
}

#[test]
#[should_panic(expected: ('EX_FUNDING_MEMBERSHIP',))]
fn changed_frontier_root_fails() {
    let mut proof = array![1, 0, 123, 32];
    for _ in 0_u32..32 {
        proof.append(0);
    }
    let mut proof = proof.span();
    read_funding_batches(ref proof, 1);
}

#[test]
#[should_panic(expected: ('EX_BATCH_ORDER',))]
fn duplicate_batch_positions_fail() {
    let mut data = array![2, 0x700000007, 123, 456, 0].span();
    read_funding_batches(ref data, 1);
}

#[test]
#[should_panic(expected: ('EX_BATCH_ORDER',))]
fn descending_batch_positions_fail() {
    let mut data = array![2, 0x600000007, 123, 456, 0].span();
    read_funding_batches(ref data, 1);
}

#[test]
#[should_panic(expected: ('EX_BATCH_ENCODING',))]
fn batch_position_high_bits_fail() {
    let mut data = array![1, 0x100000000, 123, 0].span();
    read_funding_batches(ref data, 1);
}

#[test]
#[should_panic(expected: ('EX_BATCH_SIBLINGS',))]
fn empty_proof_cannot_carry_siblings() {
    let mut data = array![0, 1, 0].span();
    read_funding_batches(ref data, 0);
}

#[test]
#[should_panic(expected: ('EX_FUNDING_MEMBERSHIP',))]
fn empty_proof_cannot_claim_a_note_root() {
    let mut data = array![0, 0].span();
    read_funding_batches(ref data, 1);
}
