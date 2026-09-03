use core::array::Array;
use super::verify_multi_pair_statement;

#[executable]
pub fn main(input: Array<felt252>) -> felt252 {
    verify_multi_pair_statement(input.span())
}
