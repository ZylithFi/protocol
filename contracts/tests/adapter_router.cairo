use core::integer::u256;
use core::traits::TryInto;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
    stop_cheat_caller_address,
};
use starknet::{ContractAddress, SyscallResultTrait};
use zylith_protocol::commitment_registry::{
    ICommitmentRegistryDispatcher, ICommitmentRegistryDispatcherTrait,
};
use zylith_protocol::deposit_router::{IDepositRouterDispatcher, IDepositRouterDispatcherTrait};
use zylith_protocol::erc20::{IERC20Dispatcher, IERC20DispatcherTrait};
use zylith_protocol::mock_erc20::{IMockERC20Dispatcher, IMockERC20DispatcherTrait};
use zylith_protocol::shielded_asset_adapter::{
    IShieldedAssetAdapterDispatcher, IShieldedAssetAdapterDispatcherTrait,
};

const ASSET_ID: felt252 = 'USDC';
const NOTE_COMMITMENT: felt252 = 0x12345;

fn deploy_commitment_registry() -> ContractAddress {
    let class = declare("CommitmentRegistry").unwrap().contract_class();
    let calldata = array![];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_mock_erc20() -> ContractAddress {
    let class = declare("MockERC20").unwrap().contract_class();
    let calldata = array![];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_shielded_asset_adapter(admin: ContractAddress) -> ContractAddress {
    let class = declare("ShieldedAssetAdapter").unwrap().contract_class();
    let calldata = array![admin.into()];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn deploy_deposit_router(
    commitment_registry: ContractAddress, shielded_asset_adapter: ContractAddress,
) -> ContractAddress {
    let class = declare("DepositRouter").unwrap().contract_class();
    let calldata = array![commitment_registry.into(), shielded_asset_adapter.into()];
    let (address, _) = class.deploy(@calldata).unwrap_syscall();
    address
}

fn as_address(value: felt252) -> ContractAddress {
    value.try_into().unwrap()
}

fn as_u256(value: u128) -> u256 {
    u256 { low: value, high: 0 }
}

#[test]
fn deposit_router_registers_note_commitments_and_live_notes() {
    let admin = as_address(0x111);
    let owner = as_address(0x222);
    let token_address = deploy_mock_erc20();
    let commitment_registry = deploy_commitment_registry();
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let deposit_router = deploy_deposit_router(commitment_registry, shielded_asset_adapter);

    let token = IMockERC20Dispatcher { contract_address: token_address };
    let erc20 = IERC20Dispatcher { contract_address: token_address };
    let registry = ICommitmentRegistryDispatcher { contract_address: commitment_registry };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let router = IDepositRouterDispatcher { contract_address: deposit_router };

    token.mint(owner, as_u256(1_000));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(token_address, owner);
    erc20.approve(shielded_asset_adapter, as_u256(500));
    stop_cheat_caller_address(token_address);

    start_cheat_caller_address(deposit_router, owner);
    router.register_shielded_deposit(ASSET_ID, 500, 7, NOTE_COMMITMENT, owner);
    stop_cheat_caller_address(deposit_router);

    assert(registry.is_note_commitment_registered(NOTE_COMMITMENT), 'NOTE_NOT_REGISTERED');
    assert(adapter.note_is_live(NOTE_COMMITMENT), 'NOTE_NOT_LIVE');
    assert(adapter.note_amount(NOTE_COMMITMENT) == 500, 'BAD_NOTE_AMOUNT');
    assert(adapter.note_withdraw_authority(NOTE_COMMITMENT) == owner, 'BAD_AUTHORITY');
}

#[test]
#[should_panic]
fn shielded_asset_adapter_rejects_wrong_withdraw_caller() {
    let admin = as_address(0x111);
    let owner = as_address(0x222);
    let wrong_caller = as_address(0x333);
    let recipient = as_address(0x444);
    let token_address = deploy_mock_erc20();
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);

    let token = IMockERC20Dispatcher { contract_address: token_address };
    let erc20 = IERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };

    token.mint(owner, as_u256(1_000));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(token_address, owner);
    erc20.approve(shielded_asset_adapter, as_u256(500));
    stop_cheat_caller_address(token_address);

    adapter.register_erc20_deposit(owner, ASSET_ID, 500, 7, NOTE_COMMITMENT, owner);

    start_cheat_caller_address(shielded_asset_adapter, wrong_caller);
    adapter.withdraw_to_l2(NOTE_COMMITMENT, recipient);
}

#[test]
#[should_panic]
fn deposit_router_rejects_mismatched_withdraw_authority() {
    let admin = as_address(0x111);
    let owner = as_address(0x222);
    let other_authority = as_address(0x333);
    let token_address = deploy_mock_erc20();
    let commitment_registry = deploy_commitment_registry();
    let shielded_asset_adapter = deploy_shielded_asset_adapter(admin);
    let deposit_router = deploy_deposit_router(commitment_registry, shielded_asset_adapter);

    let token = IMockERC20Dispatcher { contract_address: token_address };
    let erc20 = IERC20Dispatcher { contract_address: token_address };
    let adapter = IShieldedAssetAdapterDispatcher { contract_address: shielded_asset_adapter };
    let router = IDepositRouterDispatcher { contract_address: deposit_router };

    token.mint(owner, as_u256(1_000));

    start_cheat_caller_address(shielded_asset_adapter, admin);
    adapter.register_supported_asset(ASSET_ID, token_address);
    stop_cheat_caller_address(shielded_asset_adapter);

    start_cheat_caller_address(token_address, owner);
    erc20.approve(shielded_asset_adapter, as_u256(500));
    stop_cheat_caller_address(token_address);

    start_cheat_caller_address(deposit_router, owner);
    router.register_shielded_deposit(ASSET_ID, 500, 7, NOTE_COMMITMENT, other_authority);
}
