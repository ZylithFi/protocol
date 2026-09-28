use starknet::ContractAddress;

#[derive(Copy, Drop, Serde, Debug)]
pub struct SignedAmount {
    pub mag: u128,
    pub sign: bool,
}

#[derive(Copy, Drop, Serde, PartialEq)]
pub struct PoolKey {
    pub token0: ContractAddress,
    pub token1: ContractAddress,
    pub fee: u128,
    pub tick_spacing: u128,
    pub extension: ContractAddress,
}

#[derive(Copy, Drop, Serde)]
pub struct RouteNode {
    pub pool_key: PoolKey,
    pub sqrt_ratio_limit: u256,
    pub skip_ahead: u128,
}

#[derive(Copy, Drop, Serde)]
pub struct TokenAmount {
    pub token: ContractAddress,
    pub amount: SignedAmount,
}

#[derive(Drop, Serde)]
pub struct Swap {
    pub route: Array<RouteNode>,
    pub token_amount: TokenAmount,
}

#[derive(Copy, Drop, Serde)]
pub struct Delta {
    pub amount0: SignedAmount,
    pub amount1: SignedAmount,
}

#[starknet::interface]
pub trait IEkuboLocker<TContractState> {
    fn locked(ref self: TContractState, id: u32, data: Span<felt252>) -> Span<felt252>;
}

#[starknet::interface]
pub trait IEkuboCore<TContractState> {
    fn lock(ref self: TContractState, data: Span<felt252>) -> Span<felt252>;
    fn withdraw(
        ref self: TContractState,
        token_address: ContractAddress,
        recipient: ContractAddress,
        amount: u128,
    );
    fn pay(ref self: TContractState, token_address: ContractAddress);
}

#[starknet::interface]
pub trait IEkuboRouter<TContractState> {
    fn multi_multihop_swap(ref self: TContractState, swaps: Array<Swap>) -> Array<Array<Delta>>;
}

#[starknet::interface]
pub trait IEkuboClear<TContractState> {
    fn clear(ref self: TContractState, token: ContractAddress) -> u256;
    fn clear_minimum(ref self: TContractState, token: ContractAddress, minimum: u256) -> u256;
}
