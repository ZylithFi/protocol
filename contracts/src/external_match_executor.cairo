use starknet::ContractAddress;

#[derive(Copy, Drop, Serde)]
pub struct ExternalMatchRequestView {
    pub batch_id: felt252,
    pub pair_id: felt252,
    pub side: felt252,
    pub input_asset_id: felt252,
    pub output_asset_id: felt252,
    pub max_base_amount: u128,
    pub reference_midpoint_price: u128,
    pub price_base_scale: u128,
    pub valid_until_unix_ms: u64,
    pub match_deadline_unix_ms: u64,
    pub consumed_base_amount: u128,
    pub closed: bool,
    pub settlement_consumed: bool,
}

#[starknet::interface]
pub trait IExternalMatchExecutor<TContractState> {
    fn register_authorized_external_match_requests(
        ref self: TContractState,
        batch_id: felt252,
        request_root: felt252,
        request_ids: Span<felt252>,
        pair_ids: Span<felt252>,
        base_asset_ids: Span<felt252>,
        quote_asset_ids: Span<felt252>,
        sides: Span<felt252>,
        max_base_amounts: Span<felt252>,
        midpoint_prices: Span<felt252>,
        price_base_scales: Span<felt252>,
        valid_until_values: Span<felt252>,
    );
    fn settle_external_match_fill(
        ref self: TContractState, request_id: felt252, fill_base_amount: u128,
    ) -> u128;
    fn close_external_match_request(ref self: TContractState, request_id: felt252) -> u128;
    fn consume_closed_external_match_request(
        ref self: TContractState, request_id: felt252, expected_consumed_base_amount: u128,
    ) -> ExternalMatchRequestView;
    fn consumed_base_amount(self: @TContractState, request_id: felt252) -> u128;
    fn request_is_registered(self: @TContractState, request_id: felt252) -> bool;
    fn request_count(self: @TContractState) -> u64;
    fn request_id_at(self: @TContractState, index: u64) -> felt252;
    fn request_ids(self: @TContractState, start: u64, limit: u32) -> Span<felt252>;
    fn external_match_request(
        self: @TContractState, request_id: felt252,
    ) -> ExternalMatchRequestView;
    fn request_registrar(self: @TContractState) -> ContractAddress;
    fn bridge_address(self: @TContractState) -> ContractAddress;
    fn settlement_verifier(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod ExternalMatchExecutor {
    use core::num::traits::Zero;
    use core::poseidon::hades_permutation;
    use core::traits::TryInto;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
    use zylith_protocol::privacy_deposit_bridge::{
        IPrivacyDepositBridgeDispatcher, IPrivacyDepositBridgeDispatcherTrait,
    };

    const BUY_SIDE: felt252 = 0;
    const SELL_SIDE: felt252 = 1;
    const EXTERNAL_MATCH_WINDOW_MS: u64 = 10000;
    const EXTERNAL_MATCH_AUTHORIZATION_DOMAIN: felt252 =
        0x4944e3edf8c94cdca9ba99f3c9c626587e0f5108b1d4428ff2c8f23ceb69ed7;
    const EXTERNAL_MATCH_REQUEST_LEAF_DOMAIN: felt252 =
        0x20fb26bf6509d9087ab80295aca27ea56e22e440ffb6b50d276fc8d2fcf51d2;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        bridge: ContractAddress,
        registrar: ContractAddress,
        settlement_verifier: ContractAddress,
        request_registered: Map<felt252, bool>,
        request_side: Map<felt252, felt252>,
        request_batch_id: Map<felt252, felt252>,
        request_pair_id: Map<felt252, felt252>,
        request_input_asset_id: Map<felt252, felt252>,
        request_output_asset_id: Map<felt252, felt252>,
        request_max_base_amount: Map<felt252, u128>,
        request_reference_midpoint_price: Map<felt252, u128>,
        request_price_base_scale: Map<felt252, u128>,
        request_valid_until_unix_ms: Map<felt252, u64>,
        request_match_deadline_unix_ms: Map<felt252, u64>,
        consumed_base_by_request: Map<felt252, u128>,
        request_ids: Map<u64, felt252>,
        request_count: u64,
        request_closed: Map<felt252, bool>,
        request_settlement_consumed: Map<felt252, bool>,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        admin: ContractAddress,
        bridge: ContractAddress,
        registrar: ContractAddress,
        settlement_verifier: ContractAddress,
    ) {
        assert(!admin.is_zero(), 'BAD_ADMIN');
        assert(!bridge.is_zero(), 'BAD_BRIDGE');
        assert(!registrar.is_zero(), 'BAD_REGISTRAR');
        assert(!settlement_verifier.is_zero(), 'BAD_SETTLEMENT');
        self.admin.write(admin);
        self.bridge.write(bridge);
        self.registrar.write(registrar);
        self.settlement_verifier.write(settlement_verifier);
    }

    #[abi(embed_v0)]
    impl ExternalMatchExecutorImpl of super::IExternalMatchExecutor<ContractState> {
        fn register_authorized_external_match_requests(
            ref self: ContractState,
            batch_id: felt252,
            request_root: felt252,
            request_ids: Span<felt252>,
            pair_ids: Span<felt252>,
            base_asset_ids: Span<felt252>,
            quote_asset_ids: Span<felt252>,
            sides: Span<felt252>,
            max_base_amounts: Span<felt252>,
            midpoint_prices: Span<felt252>,
            price_base_scales: Span<felt252>,
            valid_until_values: Span<felt252>,
        ) {
            assert_registrar(@self);
            assert(batch_id != 0, 'BAD_BATCH_ID');
            assert(request_root != 0, 'BAD_REQUEST_ROOT');
            assert_request_vectors(
                request_ids,
                pair_ids,
                base_asset_ids,
                quote_asset_ids,
                sides,
                max_base_amounts,
                midpoint_prices,
                price_base_scales,
                valid_until_values,
            );
            assert(
                authorization_root(
                    batch_id,
                    request_ids,
                    pair_ids,
                    base_asset_ids,
                    quote_asset_ids,
                    sides,
                    max_base_amounts,
                    midpoint_prices,
                    price_base_scales,
                    valid_until_values,
                ) == request_root,
                'BAD_REQUEST_ROOT',
            );
            let mut index = 0;
            while index < request_ids.len() {
                let side = *sides.at(index);
                let (input_asset_id, output_asset_id) = if side == BUY_SIDE {
                    (*quote_asset_ids.at(index), *base_asset_ids.at(index))
                } else {
                    (*base_asset_ids.at(index), *quote_asset_ids.at(index))
                };
                register_request(
                    ref self,
                    *request_ids.at(index),
                    batch_id,
                    *pair_ids.at(index),
                    side,
                    input_asset_id,
                    output_asset_id,
                    felt_to_u128(*max_base_amounts.at(index)),
                    felt_to_u128(*midpoint_prices.at(index)),
                    felt_to_u128(*price_base_scales.at(index)),
                    felt_to_u64(*valid_until_values.at(index)),
                );
                index += 1;
            }
        }

        fn settle_external_match_fill(
            ref self: ContractState, request_id: felt252, fill_base_amount: u128,
        ) -> u128 {
            assert(request_id != 0, 'BAD_REQUEST_ID');
            assert(fill_base_amount != 0, 'BAD_FILL_BASE');
            assert(self.request_registered.read(request_id), 'UNKNOWN_REQUEST');
            assert(!self.request_closed.read(request_id), 'REQUEST_CLOSED');
            let valid_until_unix_ms = self.request_match_deadline_unix_ms.read(request_id);
            let now_unix_ms = get_block_timestamp() * 1000;
            assert(now_unix_ms <= valid_until_unix_ms, 'REQUEST_EXPIRED');

            let max_base_amount = self.request_max_base_amount.read(request_id);
            let previously_consumed = self.consumed_base_by_request.read(request_id);
            let new_consumed = previously_consumed + fill_base_amount;
            assert(new_consumed <= max_base_amount, 'REQUEST_OVERFILLED');

            let reference_midpoint_price = self.request_reference_midpoint_price.read(request_id);
            let price_base_scale = self.request_price_base_scale.read(request_id);
            let fill_quote_amount = fill_base_amount * reference_midpoint_price / price_base_scale;
            assert(fill_quote_amount != 0, 'BAD_FILL_QUOTE');

            self.consumed_base_by_request.write(request_id, new_consumed);

            let side = self.request_side.read(request_id);
            let input_asset_id = self.request_input_asset_id.read(request_id);
            let output_asset_id = self.request_output_asset_id.read(request_id);
            let (input_amount, output_amount) = if side == BUY_SIDE {
                (fill_quote_amount, fill_base_amount)
            } else {
                assert(side == SELL_SIDE, 'BAD_SIDE');
                (fill_base_amount, fill_quote_amount)
            };
            let bridge = IPrivacyDepositBridgeDispatcher { contract_address: self.bridge.read() };
            bridge
                .settle_external_match_asset_swap(
                    get_caller_address(),
                    input_asset_id,
                    output_asset_id,
                    input_amount,
                    output_amount,
                );
            new_consumed
        }

        fn close_external_match_request(ref self: ContractState, request_id: felt252) -> u128 {
            assert_registrar(@self);
            assert(self.request_registered.read(request_id), 'UNKNOWN_REQUEST');
            assert(!self.request_closed.read(request_id), 'REQUEST_CLOSED');
            let consumed = self.consumed_base_by_request.read(request_id);
            let max_base_amount = self.request_max_base_amount.read(request_id);
            let now_unix_ms = get_block_timestamp() * 1000;
            assert(
                consumed == max_base_amount
                    || now_unix_ms > self.request_match_deadline_unix_ms.read(request_id),
                'REQUEST_ACTIVE',
            );
            self.request_closed.write(request_id, true);
            consumed
        }

        fn consume_closed_external_match_request(
            ref self: ContractState, request_id: felt252, expected_consumed_base_amount: u128,
        ) -> super::ExternalMatchRequestView {
            assert(get_caller_address() == self.settlement_verifier.read(), 'UNAUTHORIZED');
            assert(self.request_registered.read(request_id), 'UNKNOWN_REQUEST');
            assert(self.request_closed.read(request_id), 'REQUEST_OPEN');
            assert(!self.request_settlement_consumed.read(request_id), 'REQUEST_SETTLED');
            assert(
                self.consumed_base_by_request.read(request_id) == expected_consumed_base_amount,
                'CONSUMED_MISMATCH',
            );
            self.request_settlement_consumed.write(request_id, true);
            request_view(@self, request_id)
        }

        fn consumed_base_amount(self: @ContractState, request_id: felt252) -> u128 {
            self.consumed_base_by_request.read(request_id)
        }

        fn request_is_registered(self: @ContractState, request_id: felt252) -> bool {
            self.request_registered.read(request_id)
        }

        fn request_count(self: @ContractState) -> u64 {
            self.request_count.read()
        }

        fn request_id_at(self: @ContractState, index: u64) -> felt252 {
            assert(index < self.request_count.read(), 'BAD_REQUEST_INDEX');
            self.request_ids.read(index)
        }

        fn request_ids(self: @ContractState, start: u64, limit: u32) -> Span<felt252> {
            assert(limit <= 256, 'BAD_REQUEST_LIMIT');
            let count = self.request_count.read();
            let mut ids = array![];
            let mut index = start;
            let end = core::cmp::min(start + limit.into(), count);
            while index < end {
                ids.append(self.request_ids.read(index));
                index += 1;
            }
            ids.span()
        }

        fn external_match_request(
            self: @ContractState, request_id: felt252,
        ) -> super::ExternalMatchRequestView {
            assert(self.request_registered.read(request_id), 'UNKNOWN_REQUEST');
            request_view(self, request_id)
        }

        fn request_registrar(self: @ContractState) -> ContractAddress {
            self.registrar.read()
        }

        fn bridge_address(self: @ContractState) -> ContractAddress {
            self.bridge.read()
        }

        fn settlement_verifier(self: @ContractState) -> ContractAddress {
            self.settlement_verifier.read()
        }
    }

    fn assert_registrar(self: @ContractState) {
        assert(get_caller_address() == self.registrar.read(), 'UNAUTHORIZED');
    }

    fn register_request(
        ref self: ContractState,
        request_id: felt252,
        batch_id: felt252,
        pair_id: felt252,
        side: felt252,
        input_asset_id: felt252,
        output_asset_id: felt252,
        max_base_amount: u128,
        reference_midpoint_price: u128,
        price_base_scale: u128,
        valid_until_unix_ms: u64,
    ) {
        assert(request_id != 0, 'BAD_REQUEST_ID');
        assert(batch_id != 0, 'BAD_BATCH_ID');
        assert(pair_id != 0, 'BAD_PAIR_ID');
        assert(side == BUY_SIDE || side == SELL_SIDE, 'BAD_SIDE');
        assert(input_asset_id != 0, 'BAD_INPUT_ASSET');
        assert(output_asset_id != 0, 'BAD_OUTPUT_ASSET');
        assert(input_asset_id != output_asset_id, 'BAD_ASSET_PAIR');
        assert(max_base_amount != 0, 'BAD_MAX_BASE');
        assert(reference_midpoint_price != 0, 'BAD_MIDPOINT');
        assert(price_base_scale != 0, 'BAD_PRICE_SCALE');
        assert(valid_until_unix_ms != 0, 'BAD_EXPIRY');
        assert(!self.request_registered.read(request_id), 'REQUEST_EXISTS');
        self.request_registered.write(request_id, true);
        self.request_batch_id.write(request_id, batch_id);
        self.request_pair_id.write(request_id, pair_id);
        self.request_side.write(request_id, side);
        self.request_input_asset_id.write(request_id, input_asset_id);
        self.request_output_asset_id.write(request_id, output_asset_id);
        self.request_max_base_amount.write(request_id, max_base_amount);
        self.request_reference_midpoint_price.write(request_id, reference_midpoint_price);
        self.request_price_base_scale.write(request_id, price_base_scale);
        self.request_valid_until_unix_ms.write(request_id, valid_until_unix_ms);
        let now_unix_ms = get_block_timestamp() * 1000;
        self
            .request_match_deadline_unix_ms
            .write(request_id, now_unix_ms + EXTERNAL_MATCH_WINDOW_MS);
        let request_index = self.request_count.read();
        self.request_ids.write(request_index, request_id);
        self.request_count.write(request_index + 1);
    }

    fn assert_request_vectors(
        request_ids: Span<felt252>,
        pair_ids: Span<felt252>,
        base_ids: Span<felt252>,
        quote_ids: Span<felt252>,
        sides: Span<felt252>,
        max_amounts: Span<felt252>,
        midpoints: Span<felt252>,
        scales: Span<felt252>,
        expiries: Span<felt252>,
    ) {
        let length = request_ids.len();
        assert(length != 0 && length <= 16, 'BAD_REQUEST_COUNT');
        assert(length == pair_ids.len() && length == base_ids.len(), 'REQUEST_LEN');
        assert(length == quote_ids.len() && length == sides.len(), 'REQUEST_LEN');
        assert(length == max_amounts.len() && length == midpoints.len(), 'REQUEST_LEN');
        assert(length == scales.len() && length == expiries.len(), 'REQUEST_LEN');
        let mut index = 0;
        while index < length {
            assert(*request_ids.at(index) != 0, 'BAD_REQUEST_ID');
            assert(*pair_ids.at(index) != 0, 'BAD_PAIR_ID');
            assert(*base_ids.at(index) != 0 && *quote_ids.at(index) != 0, 'BAD_ASSET');
            assert(*base_ids.at(index) != *quote_ids.at(index), 'BAD_ASSET_PAIR');
            assert(*sides.at(index) == BUY_SIDE || *sides.at(index) == SELL_SIDE, 'BAD_SIDE');
            assert(felt_to_u128(*max_amounts.at(index)) != 0, 'BAD_MAX_BASE');
            assert(felt_to_u128(*midpoints.at(index)) != 0, 'BAD_MIDPOINT');
            assert(felt_to_u128(*scales.at(index)) != 0, 'BAD_PRICE_SCALE');
            assert(felt_to_u64(*expiries.at(index)) != 0, 'BAD_EXPIRY');
            let mut duplicate = index + 1;
            while duplicate < length {
                assert(*request_ids.at(index) != *request_ids.at(duplicate), 'DUP_REQUEST_ID');
                duplicate += 1;
            }
            index += 1;
        }
    }

    fn authorization_root(
        batch_id: felt252,
        request_ids: Span<felt252>,
        pair_ids: Span<felt252>,
        base_ids: Span<felt252>,
        quote_ids: Span<felt252>,
        sides: Span<felt252>,
        max_amounts: Span<felt252>,
        midpoints: Span<felt252>,
        scales: Span<felt252>,
        expiries: Span<felt252>,
    ) -> felt252 {
        let seed = poseidon_hash2(EXTERNAL_MATCH_AUTHORIZATION_DOMAIN, request_ids.len().into());
        let mut accumulator = 0;
        let mut index = 0;
        while index < request_ids.len() {
            let mut leaf = poseidon_hash2(
                EXTERNAL_MATCH_REQUEST_LEAF_DOMAIN, *request_ids.at(index),
            );
            leaf = poseidon_hash2(leaf, batch_id);
            leaf = poseidon_hash2(leaf, *pair_ids.at(index));
            leaf = poseidon_hash2(leaf, *base_ids.at(index));
            leaf = poseidon_hash2(leaf, *quote_ids.at(index));
            leaf = poseidon_hash2(leaf, *sides.at(index));
            leaf = poseidon_hash2(leaf, *max_amounts.at(index));
            leaf = poseidon_hash2(leaf, *midpoints.at(index));
            leaf = poseidon_hash2(leaf, *scales.at(index));
            leaf = poseidon_hash2(leaf, *expiries.at(index));
            accumulator += leaf;
            index += 1;
        }
        poseidon_hash2(seed, accumulator)
    }

    fn poseidon_hash2(left: felt252, right: felt252) -> felt252 {
        let (result, _, _) = hades_permutation(left, right, 2);
        result
    }

    fn felt_to_u128(value: felt252) -> u128 {
        value.try_into().expect('VALUE_NOT_U128')
    }

    fn felt_to_u64(value: felt252) -> u64 {
        value.try_into().expect('VALUE_NOT_U64')
    }

    fn request_view(self: @ContractState, request_id: felt252) -> super::ExternalMatchRequestView {
        super::ExternalMatchRequestView {
            batch_id: self.request_batch_id.read(request_id),
            pair_id: self.request_pair_id.read(request_id),
            side: self.request_side.read(request_id),
            input_asset_id: self.request_input_asset_id.read(request_id),
            output_asset_id: self.request_output_asset_id.read(request_id),
            max_base_amount: self.request_max_base_amount.read(request_id),
            reference_midpoint_price: self.request_reference_midpoint_price.read(request_id),
            price_base_scale: self.request_price_base_scale.read(request_id),
            valid_until_unix_ms: self.request_valid_until_unix_ms.read(request_id),
            match_deadline_unix_ms: self.request_match_deadline_unix_ms.read(request_id),
            consumed_base_amount: self.consumed_base_by_request.read(request_id),
            closed: self.request_closed.read(request_id),
            settlement_consumed: self.request_settlement_consumed.read(request_id),
        }
    }
}
