use core::integer::u256;
use starknet::ContractAddress;

#[starknet::interface]
pub trait IMockERC20<TContractState> {
    fn mint(ref self: TContractState, recipient: ContractAddress, amount: u256);
}

#[starknet::interface]
pub trait IConfigurableMockERC20<TContractState> {
    fn mint(ref self: TContractState, recipient: ContractAddress, amount: u256);
    fn set_short_transfer(ref self: TContractState, enabled: bool);
    fn set_short_transfer_from(ref self: TContractState, enabled: bool);
}

#[starknet::interface]
pub trait IMockPrivacyPool<TContractState> {
    fn deposit_to_open_note(
        ref self: TContractState, note_id: felt252, token: ContractAddress, amount: u128,
    );
    fn open_note_amount(self: @TContractState, note_id: felt252) -> u128;
    fn open_note_token(self: @TContractState, note_id: felt252) -> ContractAddress;
}

#[starknet::contract]
pub mod MockPrivacyPool {
    use core::integer::u256;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};

    #[storage]
    struct Storage {
        open_note_amounts: Map<felt252, u128>,
        open_note_tokens: Map<felt252, ContractAddress>,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl MockPrivacyPoolImpl of super::IMockPrivacyPool<ContractState> {
        fn deposit_to_open_note(
            ref self: ContractState, note_id: felt252, token: ContractAddress, amount: u128,
        ) {
            assert(note_id != 0, 'BAD_OPEN_NOTE');
            assert(amount > 0, 'BAD_AMOUNT');
            let erc20 = IERC20Dispatcher { contract_address: token };
            erc20.transfer_from(get_caller_address(), get_contract_address(), as_u256(amount));
            self.open_note_amounts.write(note_id, amount);
            self.open_note_tokens.write(note_id, token);
        }

        fn open_note_amount(self: @ContractState, note_id: felt252) -> u128 {
            self.open_note_amounts.read(note_id)
        }

        fn open_note_token(self: @ContractState, note_id: felt252) -> ContractAddress {
            self.open_note_tokens.read(note_id)
        }
    }

    fn as_u256(amount: u128) -> u256 {
        u256 { low: amount, high: 0 }
    }
}

#[starknet::contract]
pub mod MockERC20 {
    use core::integer::u256;
    use core::num::traits::Zero;
    use core::poseidon::hades_permutation;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess};
    use starknet::{ContractAddress, get_caller_address};
    use zylith_protocol::erc20::IERC20;

    #[storage]
    struct Storage {
        balances: Map<ContractAddress, u128>,
        allowances: Map<felt252, u128>,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl MockERC20Impl of super::IMockERC20<ContractState> {
        fn mint(ref self: ContractState, recipient: ContractAddress, amount: u256) {
            let value = amount.low;
            assert(amount.high == 0, 'AMOUNT_TOO_LARGE');
            let current = self.balances.read(recipient);
            self.balances.write(recipient, current + value);
        }
    }

    #[abi(embed_v0)]
    impl ERC20Impl of IERC20<ContractState> {
        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) {
            let owner = get_caller_address();
            let value = amount.low;
            assert(amount.high == 0, 'AMOUNT_TOO_LARGE');
            self.allowances.write(allowance_key(owner, spender), value);
        }

        fn allowance(
            self: @ContractState, owner: ContractAddress, spender: ContractAddress,
        ) -> u256 {
            as_u256(self.allowances.read(allowance_key(owner, spender)))
        }

        fn balance_of(self: @ContractState, owner: ContractAddress) -> u256 {
            as_u256(self.balances.read(owner))
        }

        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) {
            let sender = get_caller_address();
            move_balance(ref self, sender, recipient, amount);
        }

        fn transfer_from(
            ref self: ContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256,
        ) {
            let caller = get_caller_address();
            if caller != sender {
                let value = amount.low;
                assert(amount.high == 0, 'AMOUNT_TOO_LARGE');
                let key = allowance_key(sender, caller);
                let current_allowance = self.allowances.read(key);
                assert(current_allowance >= value, 'INSUFFICIENT_ALLOWANCE');
                self.allowances.write(key, current_allowance - value);
            }
            move_balance(ref self, sender, recipient, amount);
        }
    }

    fn move_balance(
        ref self: ContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256,
    ) {
        let value = amount.low;
        assert(amount.high == 0, 'AMOUNT_TOO_LARGE');
        assert(!recipient.is_zero(), 'BAD_RECIPIENT');
        let sender_balance = self.balances.read(sender);
        assert(sender_balance >= value, 'INSUFFICIENT_BALANCE');
        let recipient_balance = self.balances.read(recipient);
        self.balances.write(sender, sender_balance - value);
        self.balances.write(recipient, recipient_balance + value);
    }

    fn as_u256(value: u128) -> u256 {
        u256 { low: value, high: 0 }
    }

    fn allowance_key(owner: ContractAddress, spender: ContractAddress) -> felt252 {
        let (result, _, _) = hades_permutation(owner.into(), spender.into(), 2);
        result
    }
}

#[starknet::contract]
pub mod ConfigurableMockERC20 {
    use core::integer::u256;
    use core::num::traits::Zero;
    use core::poseidon::hades_permutation;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};
    use zylith_protocol::erc20::IERC20;

    #[storage]
    struct Storage {
        balances: Map<ContractAddress, u128>,
        allowances: Map<felt252, u128>,
        short_transfer: bool,
        short_transfer_from: bool,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl ConfigurableMockERC20Impl of super::IConfigurableMockERC20<ContractState> {
        fn mint(ref self: ContractState, recipient: ContractAddress, amount: u256) {
            let value = amount.low;
            assert(amount.high == 0, 'AMOUNT_TOO_LARGE');
            let current = self.balances.read(recipient);
            self.balances.write(recipient, current + value);
        }

        fn set_short_transfer(ref self: ContractState, enabled: bool) {
            self.short_transfer.write(enabled);
        }

        fn set_short_transfer_from(ref self: ContractState, enabled: bool) {
            self.short_transfer_from.write(enabled);
        }
    }

    #[abi(embed_v0)]
    impl ERC20Impl of IERC20<ContractState> {
        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) {
            let owner = get_caller_address();
            let value = amount.low;
            assert(amount.high == 0, 'AMOUNT_TOO_LARGE');
            self.allowances.write(allowance_key(owner, spender), value);
        }

        fn allowance(
            self: @ContractState, owner: ContractAddress, spender: ContractAddress,
        ) -> u256 {
            as_u256(self.allowances.read(allowance_key(owner, spender)))
        }

        fn balance_of(self: @ContractState, owner: ContractAddress) -> u256 {
            as_u256(self.balances.read(owner))
        }

        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) {
            let sender = get_caller_address();
            move_balance(ref self, sender, recipient, amount, self.short_transfer.read());
        }

        fn transfer_from(
            ref self: ContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256,
        ) {
            let caller = get_caller_address();
            if caller != sender {
                let value = amount.low;
                assert(amount.high == 0, 'AMOUNT_TOO_LARGE');
                let key = allowance_key(sender, caller);
                let current_allowance = self.allowances.read(key);
                assert(current_allowance >= value, 'INSUFFICIENT_ALLOWANCE');
                self.allowances.write(key, current_allowance - value);
            }
            move_balance(ref self, sender, recipient, amount, self.short_transfer_from.read());
        }
    }

    fn move_balance(
        ref self: ContractState,
        sender: ContractAddress,
        recipient: ContractAddress,
        amount: u256,
        short_credit: bool,
    ) {
        let value = amount.low;
        assert(amount.high == 0, 'AMOUNT_TOO_LARGE');
        assert(!recipient.is_zero(), 'BAD_RECIPIENT');
        let sender_balance = self.balances.read(sender);
        assert(sender_balance >= value, 'INSUFFICIENT_BALANCE');
        let recipient_balance = self.balances.read(recipient);
        let credited = if short_credit {
            assert(value > 1, 'BAD_SHORT_AMOUNT');
            value - 1
        } else {
            value
        };
        self.balances.write(sender, sender_balance - value);
        self.balances.write(recipient, recipient_balance + credited);
    }

    fn as_u256(value: u128) -> u256 {
        u256 { low: value, high: 0 }
    }

    fn allowance_key(owner: ContractAddress, spender: ContractAddress) -> felt252 {
        let (result, _, _) = hades_permutation(owner.into(), spender.into(), 2);
        result
    }
}
