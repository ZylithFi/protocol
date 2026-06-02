use core::array::Array;
use super::{
    verify_admission_statement, verify_auction_result_statement,
    verify_note_consolidation_statement, verify_settlement_statement,
};

const STATEMENT_TYPE_SETTLEMENT: felt252 = 1;
const STATEMENT_TYPE_ADMISSION: felt252 = 3;
const STATEMENT_TYPE_AUCTION_RESULT: felt252 = 4;
const STATEMENT_TYPE_NOTE_CONSOLIDATION: felt252 = 5;

#[executable]
pub fn main(input: Array<felt252>) -> felt252 {
    let data = input.span();
    assert(data.len() != 0, 'E');
    let statement_type = *data.at(0);
    if statement_type == STATEMENT_TYPE_ADMISSION {
        let (_batch_id, _order_commitment_root, admission_root) = verify_admission_statement(data);
        admission_root
    } else if statement_type == STATEMENT_TYPE_AUCTION_RESULT {
        let (
            _batch_id,
            _order_commitment_root,
            _admission_root,
            transcript_commitment,
            _privacy_gate_config_commitment,
        ) =
            verify_auction_result_statement(
            data,
        );
        transcript_commitment
    } else if statement_type == STATEMENT_TYPE_NOTE_CONSOLIDATION {
        verify_note_consolidation_statement(data)
    } else {
        assert(statement_type == STATEMENT_TYPE_SETTLEMENT, 'E');
        verify_settlement_statement(data)
    }
}
