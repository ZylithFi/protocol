use core::array::Array;
use super::verify_admission_statement;

#[executable]
pub fn main(input: Array<felt252>) -> felt252 {
    let (_, _, admission_root) = verify_admission_statement(input.span());
    admission_root
}
