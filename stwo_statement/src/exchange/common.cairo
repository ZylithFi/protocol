//! primitives the exchange statements share, mirroring `zylith_core::exchange::model`.

use core::poseidon::hades_permutation;

pub const NOTE_COMMITMENT_DOMAIN: felt252 =
    0x43aeae569e031a74671a28c60a017d2a53bbb5ffa6f6a7711c076348fb186c;
pub const NULLIFIER_DOMAIN: felt252 =
    0x6cd79aee4dd094aadf944f50e83fad66ce717a58d59d73a92df351aac6d14e3;
pub const OUTPUT_NOTE_LEAF_DOMAIN: felt252 =
    0x0f0c89949c6cba4ac7f170f7f00809b458b997f2e394481c7ab58cc68aa49b3;
pub const OUTPUT_NOTE_NODE_DOMAIN: felt252 =
    0x03c6998f476a618431be1c1764a6724f13c0739be395bab4c1217bc0a65b2ee7;
pub const NOTE_ACCUMULATOR_LEAF_DOMAIN: felt252 = 0x7a796c6974685f6e6f74655f6163635f6c6561665f7631;
pub const NOTE_ACCUMULATOR_NODE_DOMAIN: felt252 = 0x7a796c6974685f6e6f74655f6163635f6e6f64655f7631;
pub const RESIDUAL_NOTE_DOMAIN: felt252 = 'zylith_residual_v1';
pub const RESIDUAL_NOTE_LEAF_DOMAIN: felt252 = 'zylith_res_leaf_v1';
pub const NOTE_ACCUMULATOR_DEPTH: u32 = 32;
pub const MAX_OUTPUT_SUBTREE_DEPTH: u32 = 16;

pub const TWO_POW_64: u128 = 0x10000000000000000;
pub const TWO_POW_64_FELT: felt252 = 0x10000000000000000;
pub const TWO_POW_120: u128 = 0x1000000000000000000000000000000;
pub const TWO_POW_128: felt252 = 0x100000000000000000000000000000000;
pub const TWO_POW_160: felt252 = 0x10000000000000000000000000000000000000000;
pub const TWO_POW_48: u64 = 0x1000000000000;
/// a felt below 2^241 has a u256 high limb below 2^113.
pub const TWO_POW_113: u128 = 0x20000000000000000000000000000;

#[inline(always)]
pub fn poseidon2(x: felt252, y: felt252) -> felt252 {
    let (result, _, _) = hades_permutation(x, y, 2);
    result
}

/// a poseidon sponge over a felt sequence; `finish` equals `poseidon_hash_span` of everything
/// absorbed.
#[derive(Copy, Drop)]
pub struct Sponge {
    s0: felt252,
    s1: felt252,
    s2: felt252,
    pending: felt252,
    has_pending: bool,
}

#[generate_trait]
pub impl SpongeImpl of SpongeTrait {
    fn new() -> Sponge {
        Sponge { s0: 0, s1: 0, s2: 0, pending: 0, has_pending: false }
    }

    #[inline(always)]
    fn absorb(ref self: Sponge, value: felt252) {
        if self.has_pending {
            let (s0, s1, s2) = hades_permutation(self.s0 + self.pending, self.s1 + value, self.s2);
            self.s0 = s0;
            self.s1 = s1;
            self.s2 = s2;
            self.has_pending = false;
        } else {
            self.pending = value;
            self.has_pending = true;
        }
    }

    #[inline(always)]
    fn absorb_pair(ref self: Sponge, first: felt252, second: felt252) {
        if self.has_pending {
            let (s0, s1, s2) = hades_permutation(self.s0 + self.pending, self.s1 + first, self.s2);
            self.s0 = s0;
            self.s1 = s1;
            self.s2 = s2;
            self.pending = second;
        } else {
            let (s0, s1, s2) = hades_permutation(self.s0 + first, self.s1 + second, self.s2);
            self.s0 = s0;
            self.s1 = s1;
            self.s2 = s2;
        }
    }

    fn finish(self: Sponge) -> felt252 {
        let (result, _, _) = if self.has_pending {
            hades_permutation(self.s0 + self.pending, self.s1 + 1, self.s2)
        } else {
            hades_permutation(self.s0 + 1, self.s1, self.s2)
        };
        result
    }
}

/// a sponge over an even-length prefix: the hot loops absorb only pairs, so it carries three
/// felts. `finish_odd` absorbs one trailing felt, matching `poseidon_hash_span` of the whole
/// sequence either way.
#[derive(Copy, Drop)]
pub struct PairSponge {
    s0: felt252,
    s1: felt252,
    s2: felt252,
}

#[generate_trait]
pub impl PairSpongeImpl of PairSpongeTrait {
    #[inline(always)]
    fn start(first: felt252, second: felt252) -> PairSponge {
        let (s0, s1, s2) = hades_permutation(first, second, 0);
        PairSponge { s0, s1, s2 }
    }

    #[inline(always)]
    fn absorb_pair(ref self: PairSponge, first: felt252, second: felt252) {
        let (s0, s1, s2) = hades_permutation(self.s0 + first, self.s1 + second, self.s2);
        self.s0 = s0;
        self.s1 = s1;
        self.s2 = s2;
    }

    fn finish_odd(self: PairSponge, last: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(self.s0 + last, self.s1 + 1, self.s2);
        result
    }
}

pub fn sponge3(a: felt252, b: felt252, c: felt252) -> felt252 {
    let (s0, s1, s2) = hades_permutation(a, b, 0);
    let (result, _, _) = hades_permutation(s0 + c, s1 + 1, s2);
    result
}

pub fn sponge4(a: felt252, b: felt252, c: felt252, d: felt252) -> felt252 {
    let (s0, s1, s2) = hades_permutation(a, b, 0);
    let (s0, s1, s2) = hades_permutation(s0 + c, s1 + d, s2);
    let (result, _, _) = hades_permutation(s0 + 1, s1, s2);
    result
}

pub fn sponge5(a: felt252, b: felt252, c: felt252, d: felt252, e: felt252) -> felt252 {
    let (s0, s1, s2) = hades_permutation(a, b, 0);
    let (s0, s1, s2) = hades_permutation(s0 + c, s1 + d, s2);
    let (result, _, _) = hades_permutation(s0 + e, s1 + 1, s2);
    result
}

pub fn sponge6(a: felt252, b: felt252, c: felt252, d: felt252, e: felt252, f: felt252) -> felt252 {
    let (s0, s1, s2) = hades_permutation(a, b, 0);
    let (s0, s1, s2) = hades_permutation(s0 + c, s1 + d, s2);
    let (s0, s1, s2) = hades_permutation(s0 + e, s1 + f, s2);
    let (result, _, _) = hades_permutation(s0 + 1, s1, s2);
    result
}

pub fn sponge7(
    a: felt252, b: felt252, c: felt252, d: felt252, e: felt252, f: felt252, g: felt252,
) -> felt252 {
    let (s0, s1, s2) = hades_permutation(a, b, 0);
    let (s0, s1, s2) = hades_permutation(s0 + c, s1 + d, s2);
    let (s0, s1, s2) = hades_permutation(s0 + e, s1 + f, s2);
    let (result, _, _) = hades_permutation(s0 + g, s1 + 1, s2);
    result
}

pub fn residual_note_commitment(
    chain_context: felt252,
    input_asset_id: felt252,
    pair_id: felt252,
    sell: bool,
    external: bool,
    remaining: felt252,
    limit: u128,
    funding: felt252,
    reserved: felt252,
    reserved_offset: felt252,
    reserved_seq: felt252,
    expiry: felt252,
    order_id: felt252,
    generation: felt252,
    owner_digest: felt252,
    blinding: felt252,
) -> felt252 {
    let mut commitment = SpongeTrait::new();
    commitment.absorb_pair(RESIDUAL_NOTE_DOMAIN, chain_context);
    commitment.absorb_pair(input_asset_id, pair_id);
    commitment.absorb_pair(if sell {
        1
    } else {
        0
    }, if external {
        1
    } else {
        0
    });
    commitment.absorb_pair(remaining, limit.into());
    commitment.absorb_pair(funding, reserved);
    commitment.absorb_pair(reserved_offset, reserved_seq);
    commitment.absorb_pair(expiry, order_id);
    commitment.absorb_pair(generation, owner_digest);
    commitment.absorb(blinding);
    commitment.finish()
}

#[inline(always)]
pub fn next(ref data: Span<felt252>) -> felt252 {
    *data.pop_front().expect('EX_SHORT')
}

#[inline(always)]
pub fn next_u128(ref data: Span<felt252>) -> u128 {
    next(ref data).try_into().expect('EX_U128')
}

#[inline(always)]
pub fn next_u64(ref data: Span<felt252>) -> u64 {
    next(ref data).try_into().expect('EX_U64')
}

#[inline(always)]
pub fn next_u32(ref data: Span<felt252>) -> u32 {
    next(ref data).try_into().expect('EX_U32')
}

#[inline(always)]
pub fn next_bool(ref data: Span<felt252>) -> bool {
    let value = next(ref data);
    assert(value * (value - 1) == 0, 'EX_BOOL');
    value == 1
}

#[inline(always)]
pub fn u128_of(value: felt252, error: felt252) -> u128 {
    value.try_into().expect(error)
}

/// asserts `value` is a nonnegative integer below 2^241.
pub fn assert_nonnegative(value: felt252, error: felt252) {
    let wide: u256 = value.into();
    assert(wide.high < TWO_POW_113, error);
}

/// `ceil(value / 2^64)` of a nonnegative felt below 2^249.
pub fn shift_ceil_64(value: felt252) -> felt252 {
    let wide: u256 = value.into();
    let (low_high, low_low) = DivRem::div_rem(wide.low, TWO_POW_64.try_into().unwrap());
    let shifted = wide.high.into() * TWO_POW_64_FELT + low_high.into();
    if low_low == 0 {
        shifted
    } else {
        shifted + 1
    }
}

/// `floor(value / divisor)` and whether it had a remainder, for a nonnegative felt value.
pub fn felt_div_rem(value: felt252, divisor: u128) -> (felt252, bool) {
    let wide: u256 = value.into();
    let (quotient, remainder) = DivRem::div_rem(
        wide, Into::<u128, u256>::into(divisor).try_into().expect('EX_DIVISOR'),
    );
    (quotient.try_into().expect('EX_QUOTIENT'), remainder != 0)
}

pub fn felt_lt(left: felt252, right: felt252) -> bool {
    let left: u256 = left.into();
    let right: u256 = right.into();
    left < right
}

pub fn note_commitment(
    asset_id: felt252,
    amount: felt252,
    owner_public_key: felt252,
    spend_authority: felt252,
    withdraw_authority: felt252,
    blinding: felt252,
    nonce: felt252,
    metadata_commitment: felt252,
) -> felt252 {
    let state = poseidon2(NOTE_COMMITMENT_DOMAIN, asset_id);
    let state = poseidon2(state, amount);
    let state = poseidon2(state, owner_public_key);
    let state = poseidon2(state, spend_authority);
    let state = poseidon2(state, withdraw_authority);
    let state = poseidon2(state, blinding);
    let state = poseidon2(state, nonce);
    poseidon2(state, metadata_commitment)
}

pub fn note_nullifier(commitment: felt252, blinding: felt252) -> felt252 {
    poseidon2(poseidon2(NULLIFIER_DOMAIN, commitment), blinding)
}

pub fn output_note_leaf(
    commitment: felt252, asset_id: felt252, amount: felt252, withdraw_authority: felt252,
) -> felt252 {
    let state = poseidon2(OUTPUT_NOTE_LEAF_DOMAIN, commitment);
    let state = poseidon2(state, asset_id);
    let state = poseidon2(state, amount);
    poseidon2(state, withdraw_authority)
}

/// one permutation whose capacity element carries the domain.
#[inline(always)]
pub fn tagged_hash(left: felt252, right: felt252, tag: felt252) -> felt252 {
    let (result, _, _) = hades_permutation(left, right, tag);
    result
}

pub fn output_note_node(left: felt252, right: felt252) -> felt252 {
    tagged_hash(left, right, OUTPUT_NOTE_NODE_DOMAIN)
}

/// the merkle root over a power-of-two list of output leaves.
pub fn output_tree_root(leaves: Span<felt252>) -> felt252 {
    let mut level = leaves;
    while level.len() > 1 {
        let mut next_level: Array<felt252> = array![];
        let mut index = 0;
        while index != level.len() {
            next_level.append(output_note_node(*level.at(index), *level.at(index + 1)));
            index += 2;
        }
        level = next_level.span();
    }
    let root = *level.at(0);
    root
}

fn note_accumulator_node(left: felt252, right: felt252, level: u32) -> felt252 {
    if left == 0 && right == 0 {
        return 0;
    }
    tagged_hash(left, right, NOTE_ACCUMULATOR_NODE_DOMAIN + level.into())
}

/// reads a note's subtree and accumulator paths and returns the accumulator root they open to.
pub fn read_membership_root(ref data: Span<felt252>, leaf: felt252) -> felt252 {
    let subtree_depth = next_u32(ref data);
    assert(subtree_depth <= MAX_OUTPUT_SUBTREE_DEPTH, 'EX_SUBTREE_DEPTH');
    let mut node = leaf;
    for _ in 0..subtree_depth {
        let sibling = next(ref data);
        node =
            if next_bool(ref data) {
                output_note_node(sibling, node)
            } else {
                output_note_node(node, sibling)
            };
    }
    let mut node = poseidon2(NOTE_ACCUMULATOR_LEAF_DOMAIN, node);
    let mut level: u32 = 0;
    while level != NOTE_ACCUMULATOR_DEPTH {
        let sibling = next(ref data);
        node =
            if next_bool(ref data) {
                note_accumulator_node(sibling, node, level)
            } else {
                note_accumulator_node(node, sibling, level)
            };
        level += 1;
    }
    node
}

/// the next power of two at or above `count`, and at least `minimum`.
pub fn padded_len(count: u32, minimum: u32) -> u32 {
    let mut size = minimum;
    while size < count {
        size *= 2;
    }
    size
}
