import pytest

from typing import NamedTuple

from starkware.starkware_utils.error_handling import StarkException
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.contract import StarknetContract
from starkware.starknet.compiler.compile import get_selector_from_name
from starkware.cairo.common.hash_state import compute_hash_on_elements

from utils.Signer import Signer

from utils.create_account import create_account
from utils.helpers import chunk_bytes_input, bytes_to_int_little, str_to_felt, uint
from mocks.blocks import mocked_blocks
from web3.types import HexBytes

class TestsDeps(NamedTuple):
    starknet: Starknet
    messages_proxy: StarknetContract
    account: StarknetContract
    signer: Signer

async def setup():
    starknet = await Starknet.empty()
    messages_proxy = await starknet.deploy(source="contracts/starknet/L1MessagesProxy.cairo", cairo_path=["contracts"])
    account, signer = await create_account(starknet)

    return TestsDeps(
       starknet=starknet,
       messages_proxy=messages_proxy,
       account=account,
       signer=signer)

@pytest.mark.asyncio
async def test_receive_from_l1_with_optimistic_relay_slashing():
    starknet, messages_proxy, account, signer = await setup()

    l1_messages_sender = 0xbeaf

    l1_headers_store = await starknet.deploy(source="contracts/starknet/L1HeadersStore.cairo", cairo_path=["contracts"], constructor_calldata=[messages_proxy.contract_address])

    l1_headers_store_addr = l1_headers_store.contract_address
    owner = account.contract_address

    reward_account, reward_account_signer = await create_account(starknet)
    relayer_account, relayer_account_signer = await create_account(starknet)

    erc20 = await starknet.deploy(
        ".tox/py37/lib/python3.7/site-packages/openzeppelin/token/erc20/presets/ERC20.cairo",
        constructor_calldata=[
            str_to_felt("FakeUSDC"), # name
            str_to_felt("FUSDC"),     # symbol
            18,                        # decimals
            1000, 0,           # initial supply
            relayer_account.contract_address  # recipient
        ]
    )

    required_stake_amount = 100

    await signer.send_transaction(
        account, messages_proxy.contract_address, 'initialize', [l1_messages_sender, l1_headers_store_addr, owner, erc20.contract_address, required_stake_amount])

    get_contract_balance_before_stake_call = await erc20.balanceOf(messages_proxy.contract_address).call()
    assert get_contract_balance_before_stake_call.result.balance == uint(0)

    get_relayer_balance_before_stake_call = await erc20.balanceOf(relayer_account.contract_address).call()
    assert get_relayer_balance_before_stake_call.result.balance == uint(1000)

    await relayer_account_signer.send_transaction(relayer_account, erc20.contract_address, 'approve', [messages_proxy.contract_address, required_stake_amount, 0])

    await relayer_account_signer.send_transaction(
        relayer_account, messages_proxy.contract_address, 'stake', [relayer_account_signer.public_key]
    )
    get_contract_balance_after_stake_call = await erc20.balanceOf(messages_proxy.contract_address).call()
    assert get_contract_balance_after_stake_call.result.balance == uint(required_stake_amount)

    message = bytearray.fromhex(HexBytes("0x464164fb85afb044734da3b2ba9b0b0afb59fd18448277f309505261f58fcb8").hex()[2:])
    chunked_message = chunk_bytes_input(message)
    formatted_words = map(bytes_to_int_little, chunked_message)
    word1, word2, word3, word4 = list(map(bytes_to_int_little, chunked_message))

    message_hash = compute_hash_on_elements([word1, word2, word3, word4, mocked_blocks[0]["number"]])
    sig_r, sig_s = relayer_account_signer.sign(message_hash)

    # Relay a wrong hash intentionally
    await relayer_account_signer.send_transaction(
        relayer_account, messages_proxy.contract_address, 'relay_optimistic', [word1, word2, word3, word4, mocked_blocks[0]["number"], 2, sig_r, sig_s]
    )

    message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
    chunked_message = chunk_bytes_input(message)
    formatted_words_correct = list(map(bytes_to_int_little, chunked_message))
    
    # send message to l2
    await starknet.send_message_to_l2(
        l1_messages_sender,
        messages_proxy.contract_address,
        get_selector_from_name('receive_from_l1'),
        formatted_words_correct + [mocked_blocks[0]["number"]] + [reward_account.contract_address])
    
    parent_hash_call = await l1_headers_store.get_parent_hash(mocked_blocks[0]["number"]).call()
    set_parent_hash = '0x' + ''.join(v.to_bytes(8, 'little').hex() for v in parent_hash_call.result.res)

    assert set_parent_hash == mocked_blocks[0]["parentHash"].hex()

    # Check that the rewarder was rewarded
    get_rewarder_balance_after_slash_call = await erc20.balanceOf(reward_account.contract_address).call()
    assert get_rewarder_balance_after_slash_call.result.balance == uint(required_stake_amount)

    # Check if the relayer has been correctly slashed
    get_relayer_balance_after_slash_call = await erc20.balanceOf(relayer_account.contract_address).call()
    assert get_relayer_balance_after_slash_call.result.balance == uint(1000 - required_stake_amount)

    # Owner increases the required amount
    await signer.send_transaction(
        account, messages_proxy.contract_address, 'increase_required_stake_amount', [required_stake_amount * 2]
    )

    # Try staking again
    await relayer_account_signer.send_transaction(relayer_account, erc20.contract_address, 'approve', [messages_proxy.contract_address, required_stake_amount * 2, 0])
    await relayer_account_signer.send_transaction(
        relayer_account, messages_proxy.contract_address, 'stake', [relayer_account_signer.public_key]
    )
    get_relayer_balance_after_stake_call = await erc20.balanceOf(relayer_account.contract_address).call()
    assert get_relayer_balance_after_stake_call.result.balance == uint(1000 - (required_stake_amount * 3))

#TODO: implement unstake() test

@pytest.mark.asyncio
async def test_change_contract_addresses():
    starknet, messages_proxy, account, signer = await setup()

    l1_messages_sender = 0xbeaf
    l1_headers_store_addr = 0xdead
    owner = account.contract_address
    await signer.send_transaction(
        account, messages_proxy.contract_address, 'initialize', [l1_messages_sender, l1_headers_store_addr, owner, 0xdead, 1])
    
    new_l1_messages_sender = 0xdada
    new_l1_headers_store_addr = 0xfefe
    await signer.send_transaction(
        account, messages_proxy.contract_address, 'change_contract_addresses', [new_l1_messages_sender, new_l1_headers_store_addr])
    
    set_l1_messages_sender_call = await messages_proxy.get_l1_messages_sender().call()
    assert set_l1_messages_sender_call.result.res == new_l1_messages_sender

    set_l1_headers_store_addr_call = await messages_proxy.get_l1_headers_store_addr().call()
    assert set_l1_headers_store_addr_call.result.res == new_l1_headers_store_addr


@pytest.mark.asyncio
async def test_change_owner_invalid_caller():
    starknet, messages_proxy, account, signer = await setup()

    l1_messages_sender = 0xbeaf
    l1_headers_store_addr = 0xdead
    owner = account.contract_address
    await signer.send_transaction(
        account, messages_proxy.contract_address, 'initialize', [l1_messages_sender, l1_headers_store_addr, owner, 0xdead, 1])

    new_account, new_signer = await create_account(starknet)
    with pytest.raises(StarkException):
        await new_signer.send_transaction(
        new_account, messages_proxy.contract_address, 'change_owner', [new_account.contract_address])
    

@pytest.mark.asyncio
async def test_change_owner():
    starknet, messages_proxy, account, signer = await setup()

    l1_messages_sender = 0xbeaf
    l1_headers_store_addr = 0xdead
    owner = account.contract_address
    await signer.send_transaction(
        account, messages_proxy.contract_address, 'initialize', [l1_messages_sender, l1_headers_store_addr, owner, 0xdead, 1])

    new_owner = 0xbeaf
    await signer.send_transaction(
        account, messages_proxy.contract_address, 'change_owner', [new_owner])
    
    set_owner_call = await messages_proxy.get_owner().call()
    assert set_owner_call.result.res == new_owner

@pytest.mark.asyncio
async def test_initializer():
    starknet, messages_proxy, account, signer = await setup()

    l1_messages_sender = 0xbeaf
    l1_headers_store_addr = 0xdead
    owner = account.contract_address
    await signer.send_transaction(
        account, messages_proxy.contract_address, 'initialize', [l1_messages_sender, l1_headers_store_addr, owner, 0xdead, 1])

    set_l1_messages_sender_call = await messages_proxy.get_l1_messages_sender().call()
    assert set_l1_messages_sender_call.result.res == l1_messages_sender

    set_l1_headers_store_addr_call = await messages_proxy.get_l1_headers_store_addr().call()
    assert set_l1_headers_store_addr_call.result.res == l1_headers_store_addr

    set_owner_call = await messages_proxy.get_owner().call()
    assert set_owner_call.result.res == owner

@pytest.mark.asyncio
async def test_change_contract_addresses_invalid_caller():
    starknet, messages_proxy, account, signer = await setup()

    l1_messages_sender = 0xbeaf
    l1_headers_store_addr = 0xdead
    owner = account.contract_address
    await signer.send_transaction(
        account, messages_proxy.contract_address, 'initialize', [l1_messages_sender, l1_headers_store_addr, owner, 0xdead, 1])
    
    new_account, new_signer = await create_account(starknet)
    with pytest.raises(StarkException):
        await new_signer.send_transaction(
        new_account, messages_proxy.contract_address, 'change_contract_addresses', [0xdada, 0xfefe])
