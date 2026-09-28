use starknet::ContractAddress;
use zylith_protocol::ekubo_abi::Swap;
use zylith_protocol::exchange::MarketAttestation;

#[derive(Drop, Serde)]
struct ExecutionData {
    initiator: ContractAddress,
    exchange: ContractAddress,
    seq: u32,
    pair_id: felt252,
    sell: bool,
    fill_base: u128,
    minimum_profit_quote: u128,
    m1: MarketAttestation,
    base_balance_before: u128,
    quote_balance_before: u128,
    swaps: Array<Swap>,
}

/// the searcher leg of an external capacity: inside one ekubo lock it borrows the asset the
/// exchange's escrow receives, trades the residual with the escrow at m1 through
/// `settle_external_fill`, hedges on ekubo, repays the loan and keeps only the quote surplus.
#[starknet::interface]
pub trait IEkuboExternalMatchRouter<TContractState> {
    fn execute_external_fill(
        ref self: TContractState,
        exchange: ContractAddress,
        seq: u32,
        pair_id: felt252,
        sell: bool,
        fill_base: u128,
        minimum_profit_quote: u128,
        m1: MarketAttestation,
        swaps: Array<Swap>,
    ) -> u128;
    fn ekubo_core(self: @TContractState) -> ContractAddress;
    fn ekubo_router(self: @TContractState) -> ContractAddress;
    fn exchange(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod EkuboExternalMatchRouter {
    use core::num::traits::Zero;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use zylith_protocol::ekubo_abi::{
        IEkuboClearDispatcher, IEkuboClearDispatcherTrait, IEkuboCoreDispatcher,
        IEkuboCoreDispatcherTrait, IEkuboLocker, IEkuboRouterDispatcher,
        IEkuboRouterDispatcherTrait, Swap,
    };
    use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
    use zylith_protocol::exchange::{
        IExchangeDispatcher, IExchangeDispatcherTrait, MarketAttestation,
    };
    use zylith_protocol::privacy_deposit_bridge::{
        IPrivacyDepositBridgeDispatcher, IPrivacyDepositBridgeDispatcherTrait,
    };
    use super::{ExecutionData, IEkuboExternalMatchRouter};

    #[storage]
    struct Storage {
        core: ContractAddress,
        router: ContractAddress,
        exchange: ContractAddress,
        bridge: ContractAddress,
        execution_active: bool,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        core: ContractAddress,
        router: ContractAddress,
        exchange: ContractAddress,
        bridge: ContractAddress,
    ) {
        assert(!core.is_zero() && !router.is_zero(), 'BAD_EKUBO');
        assert(!exchange.is_zero() && !bridge.is_zero(), 'BAD_EXCHANGE');
        self.core.write(core);
        self.router.write(router);
        self.exchange.write(exchange);
        self.bridge.write(bridge);
    }

    #[abi(embed_v0)]
    impl EkuboExternalMatchRouterImpl of IEkuboExternalMatchRouter<ContractState> {
        fn execute_external_fill(
            ref self: ContractState,
            exchange: ContractAddress,
            seq: u32,
            pair_id: felt252,
            sell: bool,
            fill_base: u128,
            minimum_profit_quote: u128,
            m1: MarketAttestation,
            swaps: Array<Swap>,
        ) -> u128 {
            assert(!self.execution_active.read(), 'EXECUTION_ACTIVE');
            assert(exchange == self.exchange.read(), 'BAD_EXCHANGE');
            assert(fill_base != 0, 'BAD_FILL_BASE');
            assert(!swaps.is_empty(), 'EMPTY_SWAPS');
            let (base_token, quote_token) = pair_tokens(@self, pair_id);
            validate_swaps(@swaps, sell, base_token, fill_base);
            let self_address = get_contract_address();
            let execution = ExecutionData {
                initiator: get_caller_address(),
                exchange,
                seq,
                pair_id,
                sell,
                fill_base,
                minimum_profit_quote,
                m1,
                base_balance_before: token_balance(base_token, self_address),
                quote_balance_before: token_balance(quote_token, self_address),
                swaps,
            };
            let mut callback_data = array![];
            Serde::serialize(@execution, ref callback_data);
            self.execution_active.write(true);
            let mut result = IEkuboCoreDispatcher { contract_address: self.core.read() }
                .lock(callback_data.span());
            self.execution_active.write(false);
            Serde::<u128>::deserialize(ref result).expect('BAD_LOCK_RESULT')
        }

        fn ekubo_core(self: @ContractState) -> ContractAddress {
            self.core.read()
        }

        fn ekubo_router(self: @ContractState) -> ContractAddress {
            self.router.read()
        }

        fn exchange(self: @ContractState) -> ContractAddress {
            self.exchange.read()
        }
    }

    #[abi(embed_v0)]
    impl LockerImpl of IEkuboLocker<ContractState> {
        fn locked(ref self: ContractState, id: u32, data: Span<felt252>) -> Span<felt252> {
            let _ = id;
            assert(get_caller_address() == self.core.read(), 'ONLY_CORE');
            assert(self.execution_active.read(), 'NO_EXECUTION');
            let mut data = data;
            let execution: ExecutionData = Serde::deserialize(ref data).expect('BAD_EXEC_DATA');
            assert(data.is_empty(), 'TRAILING_EXEC_DATA');
            let (base_token, quote_token) = pair_tokens(@self, execution.pair_id);
            let self_address = get_contract_address();
            let core = IEkuboCoreDispatcher { contract_address: self.core.read() };

            // borrow what the escrow receives, trade it for the residual at m1, hedge the
            // residual on ekubo and repay: sells receive base and repay quote, buys receive
            // quote and repay base.
            let (debt_token, debt_amount, hedge_input_token) = if execution.sell {
                (quote_token, floor_quote(execution.fill_base, execution.m1), base_token)
            } else {
                (base_token, execution.fill_base, quote_token)
            };
            core.withdraw(debt_token, self_address, debt_amount);
            IERC20Dispatcher { contract_address: debt_token }
                .approve(self.bridge.read(), debt_amount.into());
            let (_, _, escrow_input_amount, _) = IExchangeDispatcher {
                contract_address: execution.exchange,
            }
                .settle_external_fill(
                    execution.seq,
                    execution.pair_id,
                    execution.sell,
                    execution.fill_base,
                    execution.m1,
                );
            let router = self.router.read();
            IERC20Dispatcher { contract_address: hedge_input_token }
                .transfer(router, escrow_input_amount.into());
            IEkuboRouterDispatcher { contract_address: router }
                .multi_multihop_swap(execution.swaps);
            let clear = IEkuboClearDispatcher { contract_address: router };
            clear.clear(hedge_input_token);
            clear.clear_minimum(debt_token, debt_amount.into());
            IERC20Dispatcher { contract_address: debt_token }
                .approve(self.core.read(), debt_amount.into());
            core.pay(debt_token);

            let base_after = token_balance(base_token, self_address);
            let quote_after = token_balance(quote_token, self_address);
            assert(base_after == execution.base_balance_before, 'BASE_BALANCE_DELTA');
            assert(quote_after >= execution.quote_balance_before, 'QUOTE_BALANCE_LOSS');
            let profit = quote_after - execution.quote_balance_before;
            assert(profit >= execution.minimum_profit_quote, 'PROFIT_TOO_LOW');
            if profit != 0 {
                IERC20Dispatcher { contract_address: quote_token }
                    .transfer(execution.initiator, profit.into());
            }
            let mut output = array![];
            Serde::serialize(@profit, ref output);
            output.span()
        }
    }

    fn pair_tokens(self: @ContractState, pair_id: felt252) -> (ContractAddress, ContractAddress) {
        let pair = IExchangeDispatcher { contract_address: self.exchange.read() }
            .pair_config(pair_id);
        let bridge = IPrivacyDepositBridgeDispatcher { contract_address: self.bridge.read() };
        let base_token = bridge.asset_token(pair.base_asset_id);
        let quote_token = bridge.asset_token(pair.quote_asset_id);
        assert(!base_token.is_zero() && !quote_token.is_zero(), 'BAD_PAIR_TOKENS');
        (base_token, quote_token)
    }

    fn validate_swaps(
        swaps: @Array<Swap>, sell: bool, base_token: ContractAddress, fill_base: u128,
    ) {
        let mut total_base = 0_u128;
        for swap in swaps.span() {
            assert(!swap.route.is_empty(), 'EMPTY_SWAP_ROUTE');
            assert(*swap.token_amount.token == base_token, 'BAD_SWAP_TOKEN');
            // a sell hedges by selling exactly the base it bought; a buy by buying exactly the
            // base it sold.
            assert(*swap.token_amount.amount.sign == !sell, 'BAD_SWAP_DIRECTION');
            total_base += *swap.token_amount.amount.mag;
        }
        assert(total_base == fill_base, 'BAD_SWAP_AMOUNT');
    }

    fn floor_quote(base: u128, m1: MarketAttestation) -> u128 {
        let product: u256 = base.into() * m1.midpoint.into();
        let amount: u128 = (product / m1.scale.into()).try_into().expect('QUOTE_OVERFLOW');
        assert(amount != 0, 'BAD_QUOTE_AMOUNT');
        amount
    }

    fn token_balance(token: ContractAddress, account: ContractAddress) -> u128 {
        let balance = IERC20Dispatcher { contract_address: token }.balance_of(account);
        assert(balance.high == 0, 'BALANCE_OVERFLOW');
        balance.low
    }
}
