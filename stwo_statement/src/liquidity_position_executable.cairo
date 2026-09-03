use core::array::Array;
use super::verify_liquidity_position_statement;

#[executable]
pub fn main(input: Array<felt252>) -> felt252 {
    let (transcript_commitment, _, _, _) = verify_liquidity_position_statement(input.span());
    transcript_commitment
}
