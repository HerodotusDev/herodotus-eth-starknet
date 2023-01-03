%lang starknet
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256
from openzeppelin.token.erc20.library import ERC20

from lib.types import Keccak256Hash

@contract_interface
namespace L1MessagesProxy {
    func initialize(
        l1_messages_sender: felt,
        l1_headers_store_addr: felt,
        owner: felt,
        relay_asset_addr: felt,
        required_in_asset_to_relay: felt,
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

    func stake(relayer_public_key: felt) {
    }

    func unstake() {
    }

    func relay_optimistic(
        parent_hash_word_1: felt,
        parent_hash_word_2: felt,
        parent_hash_word_3: felt,
        parent_hash_word_4: felt,
        block_number: felt,
        signature_len: felt,
        signature: felt*,
    ) {
    }

    func receive_from_l1(
        from_address: felt,
        parent_hash_word_1: felt,
        parent_hash_word_2: felt,
        parent_hash_word_3: felt,
        parent_hash_word_4: felt,
        block_number: felt,
        caller_origin_addr: felt,
    ) {
    }

    func increase_required_stake_amount(new_required_stake_amount: felt) {
    }

    func get_relayer_required_stake_amount() -> (res: felt) {
    }
}

@contract_interface
namespace L1HeadersStore {
    func receive_from_l1(parent_hash_len: felt, parent_hash: felt*, block_number: felt) {
    }

    func get_commitments_parent_hash(block_number: felt) -> (res: Keccak256Hash) {
    }
}

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
    local l1_messages_proxy_address;
    local l1_headers_store_addr;
    local relay_asset_addr;
    local l1_messages_sender;
    local owner;
    local required_in_asset_to_relay;
    local relayer_pub_key;
    %{
        from starkware.crypto.signature.signature import (
            sign,
            pedersen_hash,
            private_to_stark_key,
        )
        from utils.helpers import str_to_felt

        priv_key = 12345678
        pub_key = private_to_stark_key(priv_key)
        ids.relayer_pub_key = pub_key
        context.relayer_pub_key = pub_key

        context.l1_messages_proxy_address = deploy_contract("src/L1MessagesProxy.cairo").contract_address
        ids.l1_messages_proxy_address = context.l1_messages_proxy_address

        context.l1_headers_store_addr = deploy_contract("src/L1HeadersStore.cairo", [ids.l1_messages_proxy_address]).contract_address
        ids.l1_headers_store_addr = context.l1_headers_store_addr

        context.erc20 = deploy_contract(
            "lib/cairo_contracts/src/openzeppelin/token/erc20/presets/ERC20.cairo",
            [
                str_to_felt("FakeUSDC"),             # name
                str_to_felt("FUSDC"),                # symbol
                18,                                  # decimals
                1000, 0,                             # initial supply
                context.relayer_pub_key              # recipient
            ]
        ).contract_address
        ids.relay_asset_addr = context.erc20

        ids.l1_messages_sender = 0xbeaf
        context.l1_messages_sender = ids.l1_messages_sender
        ids.owner = 123
        context.owner = ids.owner
        ids.required_in_asset_to_relay = 100
    %}
    L1MessagesProxy.initialize(
        contract_address=l1_messages_proxy_address,
        l1_messages_sender=l1_messages_sender,
        l1_headers_store_addr=l1_headers_store_addr,
        owner=owner,
        relay_asset_addr=relay_asset_addr,
        required_in_asset_to_relay=required_in_asset_to_relay,
    );
    return ();
}

@external
func test_initializer{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_messages_proxy_address;
    local l1_headers_store_addr;
    local relay_asset_addr;
    local l1_messages_sender;
    local owner;
    %{
        ids.l1_messages_proxy_address = context.l1_messages_proxy_address
        ids.l1_headers_store_addr = context.l1_headers_store_addr
        ids.relay_asset_addr = context.erc20
        ids.l1_messages_sender = context.l1_messages_sender
        ids.owner = context.owner
    %}

    let (res_l1_messages_sender) = L1MessagesProxy.get_l1_messages_sender(
        contract_address=l1_messages_proxy_address
    );
    assert res_l1_messages_sender = l1_messages_sender;

    let (res_l1_headers_store_addr) = L1MessagesProxy.get_l1_headers_store_addr(
        contract_address=l1_messages_proxy_address
    );
    assert res_l1_headers_store_addr = l1_headers_store_addr;

    let (res_owner) = L1MessagesProxy.get_owner(contract_address=l1_messages_proxy_address);
    assert res_owner = owner;

    return ();
}

@external
func test_change_contract_addresses{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_messages_proxy_address: felt;
    local new_l1_messages_sender;
    local new_l1_headers_store_addr;
    %{
        ids.l1_messages_proxy_address = context.l1_messages_proxy_address
        ids.new_l1_messages_sender = 0xdada
        ids.new_l1_headers_store_addr = 0xfefe

        stop_prank_callable = start_prank(123, target_contract_address=context.l1_messages_proxy_address)
    %}
    L1MessagesProxy.change_contract_addresses(
        contract_address=l1_messages_proxy_address,
        new_sender_addr=new_l1_messages_sender,
        new_headers_store_addr=new_l1_headers_store_addr,
    );
    %{ stop_prank_callable() %}
    let (res_l1_messages_sender) = L1MessagesProxy.get_l1_messages_sender(
        contract_address=l1_messages_proxy_address
    );
    assert res_l1_messages_sender = new_l1_messages_sender;

    let (res_l1_headers_store_addr) = L1MessagesProxy.get_l1_headers_store_addr(
        contract_address=l1_messages_proxy_address
    );
    assert res_l1_headers_store_addr = new_l1_headers_store_addr;
    return ();
}

@external
func test_change_contract_addresses_invalid_caller{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_messages_proxy_address;
    local new_l1_messages_sender;
    local new_l1_headers_store_addr;
    %{
        ids.l1_messages_proxy_address = context.l1_messages_proxy_address
        ids.new_l1_messages_sender = 0xdada
        ids.new_l1_headers_store_addr = 0xfefe

        expect_revert()
    %}
    L1MessagesProxy.change_contract_addresses(
        contract_address=l1_messages_proxy_address,
        new_sender_addr=new_l1_messages_sender,
        new_headers_store_addr=new_l1_headers_store_addr,
    );
    return ();
}

@external
func test_change_owner{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_messages_proxy_address;
    local new_owner;
    %{
        ids.l1_messages_proxy_address = context.l1_messages_proxy_address
        ids.new_owner = 0xbeaf
    %}
    %{ stop_prank_callable = start_prank(123, target_contract_address=context.l1_messages_proxy_address) %}
    L1MessagesProxy.change_owner(contract_address=l1_messages_proxy_address, new_owner=new_owner);
    %{ stop_prank_callable() %}
    return ();
}

@external
func test_change_owner_invalid_caller{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_messages_proxy_address: felt;
    local new_owner;
    %{
        ids.l1_messages_proxy_address = context.l1_messages_proxy_address
        ids.new_owner = 0xbeaf
    %}

    %{ expect_revert() %}
    L1MessagesProxy.change_owner(contract_address=l1_messages_proxy_address, new_owner=new_owner);
    return ();
}

@external
func test_receive_from_l1_with_optimistic_relay_slashing{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_messages_proxy;
    local erc20;
    local l1_headers_store_addr;
    local required_stake_amount = 100;
    local relayer_public_key;
    local l1_messages_sender;
    %{
        ids.l1_messages_proxy = context.l1_messages_proxy_address
        ids.erc20 = context.erc20
        ids.relayer_public_key = context.relayer_pub_key
        ids.l1_headers_store_addr = context.l1_headers_store_addr
        ids.l1_messages_sender = context.l1_messages_sender
    %}

    let (contract_balance_before_stake) = IERC20.balanceOf(
        contract_address=erc20, account=l1_messages_proxy
    );
    assert contract_balance_before_stake = Uint256(0, 0);

    let (get_relayer_balance) = IERC20.balanceOf(
        contract_address=erc20, account=relayer_public_key
    );
    assert get_relayer_balance = Uint256(1000, 0);

    %{ stop_prank_callable = start_prank(ids.relayer_public_key, target_contract_address=context.erc20) %}
    IERC20.approve(
        contract_address=erc20, spender=l1_messages_proxy, amount=Uint256(required_stake_amount, 0)
    );
    %{ stop_prank_callable() %}

    let (get_contract_balance_before_stake) = IERC20.balanceOf(
        contract_address=erc20, account=l1_messages_proxy
    );
    assert get_contract_balance_before_stake = Uint256(0, 0);

    %{ stop_prank_callable = start_prank(ids.relayer_public_key, target_contract_address=context.l1_messages_proxy_address) %}
    L1MessagesProxy.stake(
        contract_address=l1_messages_proxy, relayer_public_key=relayer_public_key
    );
    %{ stop_prank_callable() %}

    let (get_contract_balance_after_stake) = IERC20.balanceOf(
        contract_address=erc20, account=l1_messages_proxy
    );
    assert get_contract_balance_after_stake = Uint256(required_stake_amount, 0);

    // Optimistic relay params
    local word1;
    local word2;
    local word3;
    local word4;
    local block_number;
    let (signature: felt*) = alloc();
    %{
        from web3.types import HexBytes
        from utils.helpers import chunk_bytes_input, bytes_to_int_little
        from starkware.cairo.common.hash_state import compute_hash_on_elements
        from starkware.crypto.signature.signature import sign
        from mocks.blocks import mocked_blocks

        message = bytearray.fromhex(HexBytes("0x464164fb85afb044734da3b2ba9b0b0afb59fd18448277f309505261f58fcb8").hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words = map(bytes_to_int_little, chunked_message)
        word1, word2, word3, word4 = list(map(bytes_to_int_little, chunked_message))
        ids.word1 = word1
        ids.word2 = word2
        ids.word3 = word3
        ids.word4 = word4
        ids.block_number = mocked_blocks[0]["number"]
        message_hash = compute_hash_on_elements([word1, word2, word3, word4, ids.block_number])

        priv_key = 12345678
        sig_r, sig_s = sign(message_hash, priv_key)
        segments.write_arg(ids.signature, [sig_r, sig_s])
    %}
    %{ stop_prank_callable = start_prank(ids.relayer_public_key, target_contract_address=context.l1_messages_proxy_address) %}
    L1MessagesProxy.relay_optimistic(
        contract_address=l1_messages_proxy,
        parent_hash_word_1=word1,
        parent_hash_word_2=word2,
        parent_hash_word_3=word3,
        parent_hash_word_4=word4,
        block_number=block_number,
        signature_len=2,
        signature=signature,
    );
    %{ stop_prank_callable() %}

    local parent_hash_0;
    local parent_hash_1;
    local parent_hash_2;
    local parent_hash_3;
    local reward_account = 888;
    %{
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_little, chunked_message))
        send_message_to_l2(
            fn_name='receive_from_l1',
            from_address=context.l1_messages_sender,
            to_address=context.l1_messages_proxy_address,
            payload={
                "parent_hash_word_1": formatted_words_correct[0],
                "parent_hash_word_2": formatted_words_correct[1],
                "parent_hash_word_3": formatted_words_correct[2],
                "parent_hash_word_4": formatted_words_correct[3],
                "block_number": ids.block_number,
                "caller_origin_addr": ids.reward_account,
            }
        )
    %}
    let (hash) = L1HeadersStore.get_commitments_parent_hash(
        contract_address=l1_headers_store_addr, block_number=block_number
    );
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        got = '0x' + ''.join(v.to_bytes(8, 'little').hex() for v in extracted)
        expected = mocked_blocks[0]["parentHash"].hex()
        assert got == expected
    %}

    // Check that the rewarder was rewarded
    let (get_rewarder_balance_after_slash_call) = IERC20.balanceOf(
        contract_address=erc20, account=reward_account
    );
    assert get_rewarder_balance_after_slash_call = Uint256(required_stake_amount, 0);

    // Check that the relayer has been correctly slashed
    let (get_relayer_balance_after_slash_call) = IERC20.balanceOf(
        contract_address=erc20, account=relayer_public_key
    );
    // 1000 is the starting balance (initial liquidity) of the relayer
    tempvar expected = 1000 - required_stake_amount;
    assert get_relayer_balance_after_slash_call = Uint256(expected, 0);
    return ();
}

@external
func test_unstake{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_messages_proxy;
    local erc20;
    local l1_headers_store_addr;
    local required_stake_amount = 100;
    local relayer_public_key;
    local l1_messages_sender;
    %{
        ids.l1_messages_proxy = context.l1_messages_proxy_address
        ids.erc20 = context.erc20
        ids.relayer_public_key = context.relayer_pub_key
        ids.l1_headers_store_addr = context.l1_headers_store_addr
        ids.l1_messages_sender = context.l1_messages_sender
    %}

    %{ stop_prank_callable = start_prank(ids.relayer_public_key, target_contract_address=context.erc20) %}
    IERC20.approve(
        contract_address=erc20,
        spender=l1_messages_proxy,
        amount=Uint256(required_stake_amount * 2, 0),
    );
    %{ stop_prank_callable() %}

    %{ stop_prank_callable = start_prank(ids.relayer_public_key, target_contract_address=context.l1_messages_proxy_address) %}
    L1MessagesProxy.stake(
        contract_address=l1_messages_proxy, relayer_public_key=relayer_public_key
    );
    %{ stop_prank_callable() %}
    let (get_relayer_balance_after_stake_call) = IERC20.balanceOf(
        contract_address=erc20, account=relayer_public_key
    );
    tempvar expected = 1000 - (required_stake_amount);
    assert get_relayer_balance_after_stake_call = Uint256(expected, 0);

    // Staking again should revert as the relayer is still staking
    %{ stop_prank_callable = start_prank(ids.relayer_public_key, target_contract_address=context.l1_messages_proxy_address) %}
    %{ expect_revert() %}
    L1MessagesProxy.stake(
        contract_address=l1_messages_proxy, relayer_public_key=relayer_public_key
    );
    %{ stop_prank_callable() %}

    // Unstake
    %{ stop_prank_callable = start_prank(ids.relayer_public_key, target_contract_address=context.l1_messages_proxy_address) %}
    L1MessagesProxy.unstake(contract_address=l1_messages_proxy);
    %{ stop_prank_callable() %}

    // Owner increases the required amount
    %{ stop_prank_callable = start_prank(context.owner, target_contract_address=context.l1_messages_proxy_address) %}
    L1MessagesProxy.increase_required_stake_amount(
        contract_address=l1_messages_proxy, new_required_stake_amount=required_stake_amount * 2
    );
    %{ stop_prank_callable() %}
    let (new_staking_amount) = L1MessagesProxy.get_relayer_required_stake_amount(
        contract_address=l1_messages_proxy
    );
    assert new_staking_amount = required_stake_amount * 2;

    // Try staking again
    %{ stop_prank_callable = start_prank(ids.relayer_public_key, target_contract_address=context.l1_messages_proxy_address) %}
    L1MessagesProxy.stake(
        contract_address=l1_messages_proxy, relayer_public_key=relayer_public_key
    );
    %{ stop_prank_callable() %}

    let (get_relayer_balance_after_stake_call) = IERC20.balanceOf(
        contract_address=erc20, account=relayer_public_key
    );
    tempvar expected = 1000 - (required_stake_amount * 3);
    assert get_relayer_balance_after_stake_call = Uint256(expected, 0);
    return ();
}
