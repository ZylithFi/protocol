use super::withdrawal::verify_exchange_withdrawal_statement;

#[executable]
pub fn main(input: Span<felt252>) -> felt252 {
    verify_exchange_withdrawal_statement(input)
}
