//! the user's withdrawal statement (see `zylith_core::exchange::withdrawal`): a note is a member
//! of a known accumulator root, its nullifier is revealed, and its withdraw authority signed the
//! exit inside the proof, so the authority itself stays private.

use core::ecdsa::check_ecdsa_signature;
use super::common::{
    SpongeTrait, TWO_POW_120, next, next_u128, note_commitment, note_nullifier, output_note_leaf,
    read_membership_root, sponge5,
};

pub const STATEMENT_TYPE_WITHDRAWAL_V2: felt252 = 15;
const WITHDRAW_AUTH_DOMAIN: felt252 = 'zylith_withdraw_v2';
const WITHDRAWAL_DOMAIN: felt252 = 'zylith_withdrawal_v2';

pub fn verify_exchange_withdrawal_statement(data: Span<felt252>) -> felt252 {
    let mut data = data;
    assert(next(ref data) == STATEMENT_TYPE_WITHDRAWAL_V2, 'WD_TYPE');
    let chain_context = next(ref data);
    let note_root = next(ref data);
    let exit_commitment = next(ref data);
    let exit_authority = next(ref data);
    assert(
        chain_context != 0 && note_root != 0 && exit_commitment != 0 && exit_authority != 0,
        'WD_HEADER',
    );
    let asset_id = next(ref data);
    let amount = next_u128(ref data);
    let owner_public_key = next(ref data);
    let spend_authority = next(ref data);
    let withdraw_authority = next(ref data);
    let blinding = next(ref data);
    let nonce = next(ref data);
    let metadata = next(ref data);
    assert(amount != 0 && amount < TWO_POW_120, 'WD_AMOUNT');
    assert(blinding != 0 && nonce != 0, 'WD_NOTE');
    let commitment = note_commitment(
        asset_id,
        amount.into(),
        owner_public_key,
        spend_authority,
        withdraw_authority,
        blinding,
        nonce,
        metadata,
    );
    let leaf = output_note_leaf(commitment, asset_id, amount.into(), withdraw_authority);
    assert(read_membership_root(ref data, leaf) == note_root, 'WD_MEMBERSHIP');
    let nullifier = note_nullifier(commitment, blinding);
    let r = next(ref data);
    let s = next(ref data);
    assert(data.len() == 0, 'WD_TRAILING');
    assert(
        check_ecdsa_signature(
            sponge5(
                WITHDRAW_AUTH_DOMAIN, chain_context, nullifier, exit_commitment, exit_authority,
            ),
            withdraw_authority,
            r,
            s,
        ),
        'WD_AUTHORIZATION',
    );
    let mut commitment = SpongeTrait::new();
    commitment.absorb_pair(WITHDRAWAL_DOMAIN, chain_context);
    commitment.absorb_pair(note_root, nullifier);
    commitment.absorb_pair(asset_id, amount.into());
    commitment.absorb_pair(exit_commitment, exit_authority);
    commitment.finish()
}
