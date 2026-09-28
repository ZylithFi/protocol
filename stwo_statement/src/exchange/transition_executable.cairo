use super::transition::verify_transition_statement;

#[executable]
pub fn main(input: Span<felt252>) -> felt252 {
    verify_transition_statement(input)
}
