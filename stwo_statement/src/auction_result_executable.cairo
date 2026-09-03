use core::array::Array;
use super::verify_auction_result_statement;

#[executable]
pub fn main(input: Array<felt252>) -> felt252 {
    let (_, _, _, transcript_commitment) = verify_auction_result_statement(input.span());
    transcript_commitment
}
