use starknet::ContractAddress;
use zylith_protocol::ekubo_abi::Swap;

#[derive(Drop, Serde)]
struct ExecutionData {
    initiator: ContractAddress,
    request_id: felt252,
    fill_base_amount: u128,
    minimum_profit_quote_amount: u128,
    base_balance_before: u128,
    quote_balance_before: u128,
    swaps: Array<Swap>,
}

#[starknet::interface]
pub trait IEkuboExternalMatchRouter<TContractState> {
    fn execute_external_match(
        ref self: TContractState,
        external_match_executor: ContractAddress,
        request_id: felt252,
        fill_base_amount: u128,
        minimum_profit_quote_amount: u128,
        swaps: Array<Swap>,
    ) -> u128;
    fn ekubo_core(self: @TContractState) -> ContractAddress;
    fn ekubo_router(self: @TContractState) -> ContractAddress;
    fn external_match_executor(self: @TContractState) -> ContractAddress;
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
    use zylith_protocol::external_match_executor::{
        IExternalMatchExecutorDispatcher, IExternalMatchExecutorDispatcherTrait,
    };
    use zylith_protocol::privacy_deposit_bridge::{
        IPrivacyDepositBridgeDispatcher, IPrivacyDepositBridgeDispatcherTrait,
    };
    use super::{ExecutionData, IEkuboExternalMatchRouter};

    const BUY_SIDE: felt252 = 0;
    const SELL_SIDE: felt252 = 1;

    #[storage]
    struct Storage {
        core: ContractAddress,
        router: ContractAddress,
        executor: ContractAddress,
        execution_active: bool,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        core: ContractAddress,
        router: ContractAddress,
        executor: ContractAddress,
    ) {
        assert(!core.is_zero(), 'BAD_CORE');
        assert(!router.is_zero(), 'BAD_ROUTER');
        assert(!executor.is_zero(), 'BAD_EXECUTOR');
        self.core.write(core);
        self.router.write(router);
        self.executor.write(executor);
    }

    #[abi(embed_v0)]
    impl EkuboExternalMatchRouterImpl of IEkuboExternalMatchRouter<ContractState> {
        fn execute_external_match(
            ref self: ContractState,
            external_match_executor: ContractAddress,
            request_id: felt252,
            fill_base_amount: u128,
            minimum_profit_quote_amount: u128,
            swaps: Array<Swap>,
        ) -> u128 {
            assert(!self.execution_active.read(), 'EXECUTION_ACTIVE');
            assert(external_match_executor == self.executor.read(), 'BAD_EXECUTOR');
            assert(request_id != 0, 'BAD_REQUEST_ID');
            assert(fill_base_amount != 0, 'BAD_FILL_BASE');
            assert(!swaps.is_empty(), 'EMPTY_SWAPS');

            let executor = IExternalMatchExecutorDispatcher {
                contract_address: external_match_executor,
            };
            let request = executor.external_match_request(request_id);
            let bridge = IPrivacyDepositBridgeDispatcher {
                contract_address: executor.bridge_address(),
            };
            let (base_asset_id, quote_asset_id) = if request.side == BUY_SIDE {
                (request.output_asset_id, request.input_asset_id)
            } else {
                assert(request.side == SELL_SIDE, 'BAD_SIDE');
                (request.input_asset_id, request.output_asset_id)
            };
            let base_token = bridge.asset_token(base_asset_id);
            let quote_token = bridge.asset_token(quote_asset_id);
            assert(!base_token.is_zero(), 'BAD_BASE_TOKEN');
            assert(!quote_token.is_zero(), 'BAD_QUOTE_TOKEN');

            validate_swaps(@swaps, request.side, base_token, fill_base_amount);
            let self_address = get_contract_address();
            let execution = ExecutionData {
                initiator: get_caller_address(),
                request_id,
                fill_base_amount,
                minimum_profit_quote_amount,
                base_balance_before: token_balance(base_token, self_address),
                quote_balance_before: token_balance(quote_token, self_address),
                swaps,
            };
            let mut callback_data = array![];
            Serde::serialize(@execution, ref callback_data);
            self.execution_active.write(true);
            let result = IEkuboCoreDispatcher { contract_address: self.core.read() }
                .lock(callback_data.span());
            self.execution_active.write(false);
            let mut result = result;
            Serde::<u128>::deserialize(ref result).expect('BAD_LOCK_RESULT')
        }

        fn ekubo_core(self: @ContractState) -> ContractAddress {
            self.core.read()
        }

        fn ekubo_router(self: @ContractState) -> ContractAddress {
            self.router.read()
        }

        fn external_match_executor(self: @ContractState) -> ContractAddress {
            self.executor.read()
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

            let executor = IExternalMatchExecutorDispatcher {
                contract_address: self.executor.read(),
            };
            let request = executor.external_match_request(execution.request_id);
            let bridge = IPrivacyDepositBridgeDispatcher {
                contract_address: executor.bridge_address(),
            };
            let (base_asset_id, quote_asset_id, debt_asset_id, debt_amount) = if request
                .side == BUY_SIDE {
                (
                    request.output_asset_id,
                    request.input_asset_id,
                    request.output_asset_id,
                    execution.fill_base_amount,
                )
            } else {
                assert(request.side == SELL_SIDE, 'BAD_SIDE');
                let quote_amount = midpoint_quote_amount(
                    execution.fill_base_amount,
                    request.reference_midpoint_price,
                    request.price_base_scale,
                );
                (
                    request.input_asset_id,
                    request.output_asset_id,
                    request.output_asset_id,
                    quote_amount,
                )
            };
            let base_token = bridge.asset_token(base_asset_id);
            let quote_token = bridge.asset_token(quote_asset_id);
            let debt_token = bridge.asset_token(debt_asset_id);
            validate_swaps(@execution.swaps, request.side, base_token, execution.fill_base_amount);

            let self_address = get_contract_address();
            let core = IEkuboCoreDispatcher { contract_address: self.core.read() };
            core.withdraw(debt_token, self_address, debt_amount);

            let fill_input_token = if request.side == BUY_SIDE {
                base_token
            } else {
                quote_token
            };
            let fill_input_amount = if request.side == BUY_SIDE {
                execution.fill_base_amount
            } else {
                debt_amount
            };
            IERC20Dispatcher { contract_address: fill_input_token }
                .approve(bridge.contract_address, fill_input_amount.into());
            executor.settle_external_match_fill(execution.request_id, execution.fill_base_amount);

            let router = self.router.read();
            let hedge_input_token = if request.side == BUY_SIDE {
                quote_token
            } else {
                base_token
            };
            let hedge_input_amount = if request.side == BUY_SIDE {
                debt_amount * request.reference_midpoint_price / request.price_base_scale
            } else {
                execution.fill_base_amount
            };
            IERC20Dispatcher { contract_address: hedge_input_token }
                .transfer(router, hedge_input_amount.into());
            IEkuboRouterDispatcher { contract_address: router }
                .multi_multihop_swap(execution.swaps);

            let clear = IEkuboClearDispatcher { contract_address: router };
            clear.clear(hedge_input_token);
            let hedge_output_token = if request.side == BUY_SIDE {
                base_token
            } else {
                quote_token
            };
            clear.clear_minimum(hedge_output_token, debt_amount.into());

            IERC20Dispatcher { contract_address: debt_token }
                .approve(self.core.read(), debt_amount.into());
            core.pay(debt_token);

            let base_after = token_balance(base_token, self_address);
            let quote_after = token_balance(quote_token, self_address);
            assert(base_after == execution.base_balance_before, 'BASE_BALANCE_DELTA');
            assert(quote_after >= execution.quote_balance_before, 'QUOTE_BALANCE_LOSS');
            let profit = quote_after - execution.quote_balance_before;
            assert(profit >= execution.minimum_profit_quote_amount, 'PROFIT_TOO_LOW');
            if profit != 0 {
                IERC20Dispatcher { contract_address: quote_token }
                    .transfer(execution.initiator, profit.into());
            }

            let mut output = array![];
            Serde::serialize(@profit, ref output);
            output.span()
        }
    }

    fn validate_swaps(
        swaps: @Array<Swap>, side: felt252, base_token: ContractAddress, fill_base_amount: u128,
    ) {
        let mut total_base_amount = 0_u128;
        let mut index = 0;
        while index < swaps.len() {
            let swap = swaps.at(index);
            assert(!swap.route.is_empty(), 'EMPTY_SWAP_ROUTE');
            assert(*swap.token_amount.token == base_token, 'BAD_SWAP_TOKEN');
            if side == BUY_SIDE {
                assert(*swap.token_amount.amount.sign, 'BUY_NOT_EXACT_OUTPUT');
            } else {
                assert(side == SELL_SIDE, 'BAD_SIDE');
                assert(!*swap.token_amount.amount.sign, 'SELL_NOT_EXACT_INPUT');
            }
            total_base_amount += *swap.token_amount.amount.mag;
            index += 1;
        }
        assert(total_base_amount == fill_base_amount, 'BAD_SWAP_AMOUNT');
    }

    fn midpoint_quote_amount(base: u128, price: u128, scale: u128) -> u128 {
        assert(scale != 0, 'BAD_PRICE_SCALE');
        let amount = base * price / scale;
        assert(amount != 0, 'BAD_QUOTE_AMOUNT');
        amount
    }

    fn token_balance(token: ContractAddress, account: ContractAddress) -> u128 {
        let balance = IERC20Dispatcher { contract_address: token }.balance_of(account);
        assert(balance.high == 0, 'BALANCE_OVERFLOW');
        balance.low
    }
}
