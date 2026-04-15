#[allow(starknet::store_no_default_variant)]
#[derive(Drop, Serde, Copy, Clone, PartialEq, starknet::Store)]
pub enum BatchStatus {
    Open,
    Prepared,
    Settled,
    Cancelled,
}

#[derive(Drop, Serde)]
pub struct BatchView {
    pub batch_id: felt252,
    pub pair_id: felt252,
    pub epoch_id: u64,
    pub close_time_unix_ms: u64,
    pub status: BatchStatus,
    pub order_count: u64,
    pub output_bundle_ref: felt252,
    pub transcript_commitment: felt252,
    pub clearing_price: u128,
}

#[derive(Drop, Serde)]
pub struct SettlementRecord {
    pub batch_id: felt252,
    pub transcript_commitment: felt252,
    pub proof_artifact_commitment: felt252,
    pub clearing_price: u128,
    pub matched_order_count: u64,
    pub output_bundle_ref: felt252,
    pub consumed_note_count: u64,
    pub consumed_nullifier_count: u64,
    pub created_output_count: u64,
    pub fee_entry_count: u64,
}

#[derive(Drop, Serde)]
pub struct DepositRecord {
    pub deposit_id: u64,
    pub asset_id: felt252,
    pub amount: u128,
    pub deposit_nonce: u64,
    pub note_commitment: felt252,
}

#[derive(Drop, Serde)]
pub struct WithdrawalRecord {
    pub withdrawal_id: u64,
    pub asset_id: felt252,
    pub amount: u128,
    pub recipient: starknet::ContractAddress,
    pub note_commitment: felt252,
}
