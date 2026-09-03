#[starknet::interface]
pub trait IShieldedAssetAdapter<TContractState> {
    fn propose_admin(ref self: TContractState, new_admin: starknet::ContractAddress);
    fn accept_admin(ref self: TContractState);
    fn set_auction_verifier(ref self: TContractState, verifier: starknet::ContractAddress);
    fn register_supported_asset(
        ref self: TContractState, asset_id: felt252, token_address: starknet::ContractAddress,
    );
    fn stage_verified_note_strk20_exit(
        ref self: TContractState,
        asset_id: felt252,
        amount: u128,
        note_commitment: felt252,
        withdraw_authority: felt252,
        exit_commitment: felt252,
    );
    fn asset_token(self: @TContractState, asset_id: felt252) -> starknet::ContractAddress;
    fn is_asset_supported(self: @TContractState, asset_id: felt252) -> bool;
    fn admin_address(self: @TContractState) -> starknet::ContractAddress;
    fn pending_admin_address(self: @TContractState) -> starknet::ContractAddress;
    fn admin_transfer_pending(self: @TContractState) -> bool;
    fn auction_verifier_address(self: @TContractState) -> starknet::ContractAddress;
}
