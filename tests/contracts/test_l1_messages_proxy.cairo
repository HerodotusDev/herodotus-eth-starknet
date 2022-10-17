%lang starknet
from starkware.cairo.common.uint256 import Uint256
from openzeppelin.token.erc20.library import ERC20

@contract_interface
namespace L1MessagesProxy {
    func initialize(
        l1_messages_sender: felt,
        l1_headers_store_addr: felt,
        owner: felt,
        relay_asset_addr: felt,
        minimum_required_in_asset_to_relay: felt,
    ) {
    }

    func get_l1_messages_sender() -> (res: felt) {
    }

    func get_l1_headers_store_addr() -> (res: felt) {
    }

    func get_owner() -> (res: felt) {
    }

    func change_contract_addresses(new_sender_addr: felt, new_headers_store_addr: felt) {
    }

    func change_owner(new_owner: felt) {
    }
}

// ERC20 token interface
@contract_interface
namespace IERC20 {
    func name() -> (name: felt) {
    }

    func symbol() -> (symbol: felt) {
    }

    func decimals() -> (decimals: felt) {
    }

    func totalSupply() -> (totalSupply: Uint256) {
    }

    func balanceOf(account: felt) -> (balance: Uint256) {
    }

    func allowance(owner: felt, spender: felt) -> (remaining: Uint256) {
    }

    func transfer(recipient: felt, amount: Uint256) -> (success: felt) {
    }

    func transferFrom(sender: felt, recipient: felt, amount: Uint256) -> (success: felt) {
    }

    func approve(spender: felt, amount: Uint256) -> (success: felt) {
    }
}

@external
func __setup__{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local contract_address: felt;
    %{
        context.contract_address = deploy_contract("src/L1MessagesProxy.cairo").contract_address
        ids.contract_address = context.contract_address
    %}
    local l1_messages_sender;
    local l1_headers_store_addr;
    local dead_relay_asset;
    local owner = 123;
    %{
        ids.l1_messages_sender = 0xbeaf
        ids.l1_headers_store_addr = 0xdead
        ids.dead_relay_asset = 0xdead
    %}
    L1MessagesProxy.initialize(
        contract_address=contract_address,
        l1_messages_sender=l1_messages_sender,
        l1_headers_store_addr=l1_headers_store_addr,
        owner=owner,
        relay_asset_addr=dead_relay_asset,
        minimum_required_in_asset_to_relay=1,
    );
    return ();
}

@external
func test_initializer{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local contract_address: felt;
    %{ ids.contract_address = context.contract_address %}
    local l1_messages_sender;
    local l1_headers_store_addr;
    local dead_relay_asset;
    local owner = 123;
    %{
        ids.l1_messages_sender = 0xbeaf
        ids.l1_headers_store_addr = 0xdead
        ids.dead_relay_asset = 0xdead
    %}

    let (res_l1_messages_sender) = L1MessagesProxy.get_l1_messages_sender(contract_address);
    assert res_l1_messages_sender = l1_messages_sender;

    let (res_l1_headers_store_addr) = L1MessagesProxy.get_l1_headers_store_addr(contract_address);
    assert res_l1_headers_store_addr = l1_headers_store_addr;

    let (res_owner) = L1MessagesProxy.get_owner(contract_address);
    assert res_owner = owner;

    return ();
}

@external
func test_change_contract_addresses{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local contract_address: felt;
    local new_l1_messages_sender;
    local new_l1_headers_store_addr;
    %{
        ids.contract_address = context.contract_address
        ids.new_l1_messages_sender = 0xdada
        ids.new_l1_headers_store_addr = 0xfefe

        stop_prank_callable = start_prank(123, target_contract_address=context.contract_address)
    %}
    L1MessagesProxy.change_contract_addresses(
        contract_address, new_l1_messages_sender, new_l1_headers_store_addr
    );
    %{ stop_prank_callable() %}
    let (res_l1_messages_sender) = L1MessagesProxy.get_l1_messages_sender(contract_address);
    assert res_l1_messages_sender = new_l1_messages_sender;

    let (res_l1_headers_store_addr) = L1MessagesProxy.get_l1_headers_store_addr(contract_address);
    assert res_l1_headers_store_addr = new_l1_headers_store_addr;
    return ();
}

@external
func test_change_contract_addresses_invalid_caller{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local contract_address: felt;
    local new_l1_messages_sender;
    local new_l1_headers_store_addr;
    %{
        ids.contract_address = context.contract_address
        ids.new_l1_messages_sender = 0xdada
        ids.new_l1_headers_store_addr = 0xfefe

        expect_revert()
    %}
    L1MessagesProxy.change_contract_addresses(
        contract_address, new_l1_messages_sender, new_l1_headers_store_addr
    );
    return ();
}

@external
func test_change_owner{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local contract_address: felt;
    local new_owner;
    %{
        ids.contract_address = context.contract_address
        ids.new_owner = 0xbeaf
    %}
    %{ stop_prank_callable = start_prank(123, target_contract_address=context.contract_address) %}
    L1MessagesProxy.change_owner(contract_address, new_owner);
    %{ stop_prank_callable() %}
    return ();
}

@external
func test_change_owner_invalid_caller{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local contract_address: felt;
    local new_owner;
    %{
        ids.contract_address = context.contract_address
        ids.new_owner = 0xbeaf
    %}

    %{ expect_revert() %}
    L1MessagesProxy.change_owner(contract_address, new_owner);
    return ();
}

@external
func test_receive_from_l1_with_optimistic_relay_slashing{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_messages_proxy;
    local erc20;
    local relayer_account_contract_address = 456;
    local required_stake_amount = 100;
    %{
        from utils.helpers import str_to_felt
        ids.l1_messages_proxy = context.contract_address
        ids.erc20 = deploy_contract(
            "lib/cairo_contracts/src/openzeppelin/token/erc20/presets/ERC20.cairo",
            [
                str_to_felt("FakeUSDC"),             # name
                str_to_felt("FUSDC"),                # symbol
                18,                                  # decimals
                1000, 0,                             # initial supply
                ids.relayer_account_contract_address # recipient
            ]
        ).contract_address
    %}

    let (contract_balance_before_stake) = IERC20.balanceOf(
        contract_address=erc20, account=l1_messages_proxy
    );
    assert contract_balance_before_stake = Uint256(0, 0);

    let (get_relayer_balance) = IERC20.balanceOf(
        contract_address=erc20, account=relayer_account_contract_address
    );
    assert get_relayer_balance = Uint256(1000, 0);

    IERC20.approve(
        contract_address=erc20, spender=l1_messages_proxy, amount=Uint256(required_stake_amount, 0)
    );

    // TODO: find a way to sign transactions and extract public key from an account.

    return ();
}
