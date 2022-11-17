%lang starknet
from starkware.cairo.common.alloc import alloc

from lib.types import Keccak256Hash, Address

@contract_interface
namespace L1HeadersStore {
    func receive_from_l1(parent_hash_len: felt, parent_hash: felt*, block_number: felt) {
    }

    func get_parent_hash(block_number: felt) -> (res: Keccak256Hash) {
    }

    func get_latest_l1_block() -> (res: felt) {
    }

    func process_block(
        options_set: felt,
        block_number: felt,
        block_header_rlp_bytes_len: felt,
        block_header_rlp_len: felt,
        block_header_rlp: felt*,
    ) {
    }

    func process_till_block(
        options_set: felt,
        start_block_number: felt,
        block_headers_lens_bytes_len: felt,
        block_headers_lens_bytes: felt*,
        block_headers_lens_words_len: felt,
        block_headers_lens_words: felt*,
        block_headers_concat_len: felt,
        block_headers_concat: felt*,
    ) {
    }

    func get_state_root(block_number: felt) -> (res: Keccak256Hash) {
    }

    func get_transactions_root(block_number: felt) -> (res: Keccak256Hash) {
    }

    func get_receipts_root(block_number: felt) -> (res: Keccak256Hash) {
    }

    func get_uncles_hash(block_number: felt) -> (res: Keccak256Hash) {
    }

    func get_beneficiary(block_number: felt) -> (res: Address) {
    }

    func get_difficulty(block_number: felt) -> (res: felt) {
    }

    func get_base_fee(block_number: felt) -> (res: felt) {
    }

    func get_timestamp(block_number: felt) -> (res: felt) {
    }

    func get_gas_used(block_number: felt) -> (res: felt) {
    }
}

@external
func __setup__{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    %{
        from starkware.crypto.signature.signature import (
            private_to_stark_key,
        )
        priv_key = 12345678
        pub_key = private_to_stark_key(priv_key)
        context.relayer_pub_key = pub_key
        context.l1_headers_store_addr = deploy_contract("src/L1HeadersStore.cairo", [pub_key]).contract_address
    %}
    return ();
}

@external
func test_submit_hash{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_little
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_little, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    return ();
}

@external
func test_submit_hash_update_latest_block{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    %{ ids.l1_headers_store = context.l1_headers_store_addr; %}
    let (original_latest) = L1HeadersStore.get_latest_l1_block(contract_address=l1_headers_store);
    assert original_latest = 0;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_little
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_little, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = 10

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    let (current_latest) = L1HeadersStore.get_latest_l1_block(contract_address=l1_headers_store);
    assert current_latest = block_number;
    return ();
}

@external
func test_process_block{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_big, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();
    local block_number_process_block;
    %{
        from utils.types import Data
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[1]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
        ids.block_number_process_block = block['number']
    %}
    L1HeadersStore.process_block(
        contract_address=l1_headers_store,
        options_set=0,
        block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
    );
    // Get parent hash
    let (hash) = L1HeadersStore.get_parent_hash(
        contract_address=l1_headers_store, block_number=block_number_process_block
    );
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        got = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        expected = mocked_blocks[1]["parentHash"].hex()
        assert got == expected
    %}
    return ();
}

@external
func test_process_invalid_block{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_big, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();
    local block_number_process_block;
    %{
        from utils.types import Data
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
        ids.block_number_process_block = block['number']
    %}

    %{ expect_revert() %}
    L1HeadersStore.process_block(
        contract_address=l1_headers_store,
        options_set=0,
        block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
    );
    return ();
}

@external
func test_set_uncles_hash{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_big, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();
    local block_number_process_block;
    local options_set;
    %{
        from utils.types import Data, BlockHeaderIndexes
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[1]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
        ids.block_number_process_block = block['number']
        ids.options_set = 2 ** BlockHeaderIndexes.OMMERS_HASH
    %}
    L1HeadersStore.process_block(
        contract_address=l1_headers_store,
        options_set=options_set,
        block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
    );
    let (hash) = L1HeadersStore.get_uncles_hash(
        contract_address=l1_headers_store, block_number=block_number_process_block
    );
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        got = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        expected = mocked_blocks[1]["sha3Uncles"].hex()
        assert got == expected
    %}
    return ();
}

@external
func test_set_beneficiary{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_big, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();
    local block_number_process_block;
    local options_set;
    %{
        from utils.types import Data, BlockHeaderIndexes
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[1]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
        ids.block_number_process_block = block['number']
        ids.options_set = 2 ** BlockHeaderIndexes.BENEFICIARY
    %}
    L1HeadersStore.process_block(
        contract_address=l1_headers_store,
        options_set=options_set,
        block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
    );
    let (beneficiary) = L1HeadersStore.get_beneficiary(
        contract_address=l1_headers_store, block_number=block_number_process_block
    );
    %{
        from web3 import Web3
        extracted = [ids.beneficiary.word_1, ids.beneficiary.word_2, ids.beneficiary.word_3]
        l = list(map(lambda x: str(hex(x)[2:]), extracted))
        formatted_hash = '0x' + ''.join(l)
        assert Web3.toBytes(hexstr=formatted_hash) == bytes.fromhex(block["miner"][2:])
    %}
    return ();
}

@external
func test_set_state_root{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_big, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();
    local block_number_process_block;
    local options_set;
    %{
        from utils.types import Data, BlockHeaderIndexes
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[1]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
        ids.block_number_process_block = block['number']
        ids.options_set = 2 ** BlockHeaderIndexes.STATE_ROOT
    %}
    L1HeadersStore.process_block(
        contract_address=l1_headers_store,
        options_set=options_set,
        block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
    );
    let (hash) = L1HeadersStore.get_state_root(
        contract_address=l1_headers_store, block_number=block_number_process_block
    );
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        got = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        expected = mocked_blocks[1]["stateRoot"].hex()
        assert got == expected
    %}
    return ();
}

@external
func test_set_transactions_root{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_big, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();
    local block_number_process_block;
    local options_set;
    %{
        from utils.types import Data, BlockHeaderIndexes
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[1]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
        ids.block_number_process_block = block['number']
        ids.options_set = 2 ** BlockHeaderIndexes.TRANSACTION_ROOT
    %}
    L1HeadersStore.process_block(
        contract_address=l1_headers_store,
        options_set=options_set,
        block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
    );
    let (hash) = L1HeadersStore.get_transactions_root(
        contract_address=l1_headers_store, block_number=block_number_process_block
    );
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        got = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        expected = mocked_blocks[1]["transactionsRoot"].hex()
        assert got == expected
    %}
    return ();
}

@external
func test_set_receipts_root{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_big, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();
    local block_number_process_block;
    local options_set;
    %{
        from utils.types import Data, BlockHeaderIndexes
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[1]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
        ids.block_number_process_block = block['number']
        ids.options_set = 2 ** BlockHeaderIndexes.RECEIPTS_ROOT
    %}
    L1HeadersStore.process_block(
        contract_address=l1_headers_store,
        options_set=options_set,
        block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
    );
    let (hash) = L1HeadersStore.get_receipts_root(
        contract_address=l1_headers_store, block_number=block_number_process_block
    );
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        got = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        expected = mocked_blocks[1]["receiptsRoot"].hex()
        assert got == expected
    %}
    return ();
}

@external
func test_set_difficulty{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_big, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();
    local block_number_process_block;
    local options_set;
    %{
        from utils.types import Data, BlockHeaderIndexes
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[1]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
        ids.block_number_process_block = block['number']
        ids.options_set = 2 ** BlockHeaderIndexes.DIFFICULTY
    %}
    L1HeadersStore.process_block(
        contract_address=l1_headers_store,
        options_set=options_set,
        block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
    );
    let (difficulty) = L1HeadersStore.get_difficulty(
        contract_address=l1_headers_store, block_number=block_number_process_block
    );
    %{ assert ids.difficulty == mocked_blocks[1]["difficulty"] %}
    return ();
}

@external
func test_set_gas_used{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_big, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();
    local block_number_process_block;
    local options_set;
    %{
        from utils.types import Data, BlockHeaderIndexes
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[1]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
        ids.block_number_process_block = block['number']
        ids.options_set = 2 ** BlockHeaderIndexes.GAS_USED
    %}
    L1HeadersStore.process_block(
        contract_address=l1_headers_store,
        options_set=options_set,
        block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
    );
    let (gas_used) = L1HeadersStore.get_gas_used(
        contract_address=l1_headers_store, block_number=block_number_process_block
    );
    %{ assert ids.gas_used == mocked_blocks[1]["gasUsed"] %}
    return ();
}

@external
func test_set_timestamp{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_big, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();
    local block_number_process_block;
    local options_set;
    %{
        from utils.types import Data, BlockHeaderIndexes
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[1]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
        ids.block_number_process_block = block['number']
        ids.options_set = 2 ** BlockHeaderIndexes.TIMESTAMP
    %}
    L1HeadersStore.process_block(
        contract_address=l1_headers_store,
        options_set=options_set,
        block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
    );
    let (timestamp) = L1HeadersStore.get_timestamp(
        contract_address=l1_headers_store, block_number=block_number_process_block
    );
    %{ assert ids.timestamp == mocked_blocks[1]["timestamp"] %}
    return ();
}

@external
func test_set_base_fee{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]["parentHash"].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_big, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();
    local block_number_process_block;
    local options_set;
    %{
        from utils.types import Data, BlockHeaderIndexes
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[1]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
        ids.block_number_process_block = block['number']
        ids.options_set = 2 ** BlockHeaderIndexes.BASE_FEE
    %}
    L1HeadersStore.process_block(
        contract_address=l1_headers_store,
        options_set=options_set,
        block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
    );
    let (base_fee) = L1HeadersStore.get_base_fee(
        contract_address=l1_headers_store, block_number=block_number_process_block
    );
    %{ assert ids.base_fee == mocked_blocks[1]["baseFeePerGas"] %}
    return ();
}

@external
func test_process_till_block{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr;
        message = bytearray.fromhex(mocked_blocks[0]['hash'].hex()[2:])
        chunked_message = chunk_bytes_input(message)
        formatted_words_correct = list(map(bytes_to_int_big, chunked_message))

        segments.write_arg(ids.parent_hash, formatted_words_correct)
        assert len(formatted_words_correct) == 4
        ids.block_number = mocked_blocks[0]["number"] + 1

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local options_set;
    local start_block_number;
    let (block_headers_lens_bytes: felt*) = alloc();
    let (block_headers_lens_words: felt*) = alloc();
    local block_headers_concat_len;
    let (block_headers_concat: felt*) = alloc();
    local oldest_block;
    %{
        from utils.types import Data, BlockHeaderIndexes
        from utils.block_header import build_block_header
        newer_block = mocked_blocks[0]
        newer_block_header = build_block_header(newer_block)
        newer_block_rlp = Data.from_bytes(newer_block_header.raw_rlp()).to_ints()

        older_block = mocked_blocks[1]
        older_block_header = build_block_header(older_block)
        older_block_rlp = Data.from_bytes(older_block_header.raw_rlp()).to_ints()

        oldest_block = mocked_blocks[2]
        oldest_block_header = build_block_header(oldest_block)
        oldest_block_rlp = Data.from_bytes(oldest_block_header.raw_rlp()).to_ints()

        ids.oldest_block = oldest_block['number']

        segments.write_arg(ids.block_headers_lens_bytes, [newer_block_rlp.length, older_block_rlp.length, oldest_block_rlp.length])
        segments.write_arg(ids.block_headers_lens_words, [len(newer_block_rlp.values), len(older_block_rlp.values), len(oldest_block_rlp.values)])
        ids.block_headers_concat_len = len([*newer_block_rlp.values, *older_block_rlp.values, *oldest_block_rlp.values])
        segments.write_arg(ids.block_headers_concat, [*newer_block_rlp.values, *older_block_rlp.values, *oldest_block_rlp.values])

        ids.start_block_number = newer_block['number'] + 1
        ids.options_set = 2 ** BlockHeaderIndexes.STATE_ROOT
    %}
    L1HeadersStore.process_till_block(
        contract_address=l1_headers_store,
        options_set=options_set,
        start_block_number=start_block_number,
        block_headers_lens_bytes_len=3,
        block_headers_lens_bytes=block_headers_lens_bytes,
        block_headers_lens_words_len=3,
        block_headers_lens_words=block_headers_lens_words,
        block_headers_concat_len=block_headers_concat_len,
        block_headers_concat=block_headers_concat,
    );
    // newer_block_parent_hash
    tempvar block_n = start_block_number - 1;
    let (hash) = L1HeadersStore.get_parent_hash(
        contract_address=l1_headers_store, block_number=block_n
    );
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        got = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        expected = '0x0000000000000000000000000000000000000000000000000000000000000000'
        assert got == expected
    %}
    let (state_root) = L1HeadersStore.get_state_root(
        contract_address=l1_headers_store, block_number=oldest_block
    );
    %{
        extracted = [ids.state_root.word_1, ids.state_root.word_2, ids.state_root.word_3, ids.state_root.word_4]
        got = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        expected = oldest_block["stateRoot"].hex()
        assert got == expected
    %}
    return ();
}
