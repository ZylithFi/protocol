use super::residual_recovery::verify_residual_recovery_statement;

#[executable]
pub fn main(input: Span<felt252>) -> felt252 {
    verify_residual_recovery_statement(input)
}
