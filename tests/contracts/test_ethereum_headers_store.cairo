%lang starknet
%builtins pedersen range_check

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash_state import hash_felts
from starkware.cairo.common.hash import hash2

from lib.types import Keccak256Hash, Address

@contract_interface
namespace L1HeadersStore {
    func receive_from_l1(parent_hash_len: felt, parent_hash: felt*, block_number: felt) {
    }

    func get_commitments_parent_hash(block_number: felt) -> (res: Keccak256Hash) {
    }

    func get_latest_commitments_l1_block() -> (res: felt) {
    }

    func process_block(
        reference_block_number: felt,
        reference_proof_leaf_index: felt,
        reference_proof_leaf_value: felt,
        reference_proof_len: felt,
        reference_proof: felt*,
        reference_header_rlp_bytes_len: felt,
        reference_header_rlp_len: felt,
        reference_header_rlp: felt*,
        block_header_rlp_bytes_len: felt,
        block_header_rlp_len: felt,
        block_header_rlp: felt*,
        mmr_peaks_len: felt,
        mmr_peaks: felt*,
    ) {
    }

    func process_block_from_message(
        reference_block_number: felt,
        block_header_rlp_bytes_len: felt,
        block_header_rlp_len: felt,
        block_header_rlp: felt*,
        mmr_peaks_len: felt,
        mmr_peaks: felt*,
    ) {
    }

    func process_till_block(
        reference_block_number: felt,
        reference_proof_leaf_index: felt,
        reference_proof_leaf_value: felt,
        reference_proof_len: felt,
        reference_proof: felt*,
        reference_header_rlp_bytes_len: felt,
        reference_header_rlp_len: felt,
        reference_header_rlp: felt*,
        block_headers_lens_bytes_len: felt,
        block_headers_lens_bytes: felt*,
        block_headers_lens_words_len: felt,
        block_headers_lens_words: felt*,
        block_headers_concat_len: felt,
        block_headers_concat: felt*,
        mmr_peaks_len: felt,
        mmr_peaks: felt*,
        mmr_pos: felt,
    ) {
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
        context.l1_headers_store_addr = deploy_contract("src/connections/ethereum/HeadersStore.cairo", [pub_key]).contract_address
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
    let (original_latest) = L1HeadersStore.get_latest_commitments_l1_block(
        contract_address=l1_headers_store
    );
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
    let (current_latest) = L1HeadersStore.get_latest_commitments_l1_block(
        contract_address=l1_headers_store
    );
    assert current_latest = block_number;
    return ();
}

@external
func test_process_block{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
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

        # +1 below is to use child block number (reference block).
        ids.block_number_process_block = block['number'] + 1
    %}
    let (local mmr_peaks: felt*) = alloc();

    // Add first node to MMR (reference block is in contract storage).
    L1HeadersStore.process_block_from_message(
        contract_address=l1_headers_store,
        reference_block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
        mmr_peaks_len=0,
        mmr_peaks=mmr_peaks,
    );

    let (pedersen_hash) = hash_felts{hash_ptr=pedersen_ptr}(
        data=block_header_rlp, length=block_header_rlp_len
    );
    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, pedersen_hash);
    assert mmr_peaks[0] = node1;
    let (local proof: felt*) = alloc();

    local block_2_header_rlp_bytes_len;
    local block_2_header_rlp_len;
    let (block_2_header_rlp: felt*) = alloc();
    local block_2_number_process_block;
    %{
        from utils.types import Data
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[2]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_2_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_2_header_rlp, block_rlp.values)
        ids.block_2_header_rlp_len = len(block_rlp.values)

        # +1 below is to use child block number (reference block).
        ids.block_2_number_process_block = block['number'] + 1
    %}

    L1HeadersStore.process_block(
        contract_address=l1_headers_store,
        reference_block_number=block_2_number_process_block,
        reference_proof_leaf_index=1,
        reference_proof_leaf_value=pedersen_hash,
        reference_proof_len=0,
        reference_proof=proof,
        reference_header_rlp_bytes_len=block_header_rlp_bytes_len,
        reference_header_rlp_len=block_header_rlp_len,
        reference_header_rlp=block_header_rlp,
        block_header_rlp_bytes_len=block_2_header_rlp_bytes_len,
        block_header_rlp_len=block_2_header_rlp_len,
        block_header_rlp=block_2_header_rlp,
        mmr_peaks_len=1,
        mmr_peaks=mmr_peaks,
    );
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
        # Invalid child (expected)
        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
        ids.block_number_process_block = block['number']
    %}

    let (local mmr_peaks: felt*) = alloc();
    %{ expect_revert() %}

    L1HeadersStore.process_block_from_message(
        contract_address=l1_headers_store,
        reference_block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
        mmr_peaks_len=0,
        mmr_peaks=mmr_peaks,
    );
    return ();
}

@external
func test_process_till_block{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;
    local l1_headers_store;

    let (trusted_parent_hash: felt*) = alloc();
    local trusted_parent_hash_for_block;
    %{
        from utils.types import Data
        from mocks.blocks import mocked_blocks

        ids.l1_headers_store = context.l1_headers_store_addr

        # Parent hash of 11456152
        parent_hash_words = Data.from_hex(mocked_blocks[0]["parentHash"].hex()).to_ints().values
        segments.write_arg(ids.trusted_parent_hash, parent_hash_words)

        assert len(parent_hash_words) == 4
        ids.trusted_parent_hash_for_block = mocked_blocks[0]["number"]

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=trusted_parent_hash,
        block_number=trusted_parent_hash_for_block,
    );
    %{ stop_prank_callable() %}

    local known_parent_hash_for_block_number;
    local block_header_to_be_processed_from_msg_rlp_bytes_len;
    local block_header_to_be_processed_from_msg_rlp_len;
    let (block_header_to_be_processed_from_msg_rlp: felt*) = alloc();

    %{
        from utils.types import Data
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks

        block = mocked_blocks[1] # 11456151
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_to_be_processed_from_msg_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_to_be_processed_from_msg_rlp, block_rlp.values)
        ids.block_header_to_be_processed_from_msg_rlp_len = len(block_rlp.values)

        # +1 below is to use child block number (reference block).
        ids.known_parent_hash_for_block_number = mocked_blocks[0]['number']
    %}

    let (mmr_peaks: felt*) = alloc();
    // Add first node to MMR (reference block is in contract storage).
    L1HeadersStore.process_block_from_message(
        contract_address=l1_headers_store,
        reference_block_number=known_parent_hash_for_block_number,
        block_header_rlp_bytes_len=block_header_to_be_processed_from_msg_rlp_bytes_len,
        block_header_rlp_len=block_header_to_be_processed_from_msg_rlp_len,
        block_header_rlp=block_header_to_be_processed_from_msg_rlp,
        mmr_peaks_len=0,
        mmr_peaks=mmr_peaks,
    );

    let (local proof: felt*) = alloc();
    let (pedersen_hash) = hash_felts{hash_ptr=pedersen_ptr}(
        data=block_header_to_be_processed_from_msg_rlp, length=block_header_to_be_processed_from_msg_rlp_len
    );
    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, pedersen_hash);
    assert mmr_peaks[0] = node1;

    let (block_headers_lens_bytes: felt*) = alloc();
    let (block_headers_lens_words: felt*) = alloc();
    let (block_headers_concat: felt*) = alloc();
    local block_headers_concat_len;

    local start_block_number;
    local older_block_rlp_len;
    let (older_block_rlp: felt*) = alloc();
    local older_block_2_rlp_len;
    let (older_block_2_rlp: felt*) = alloc();
    local oldest_block_rlp_len;
    let (oldest_block_rlp: felt*) = alloc();
    %{
        from utils.types import Data
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks

        ids.start_block_number = mocked_blocks[1]['number']

        older_block = mocked_blocks[2]
        older_block_header = build_block_header(older_block)
        older_block_rlp = Data.from_bytes(older_block_header.raw_rlp()).to_ints()

        ids.older_block_rlp_len = len(older_block_rlp.values)
        segments.write_arg(ids.older_block_rlp, older_block_rlp.values)


        older_block_2 = mocked_blocks[3]
        older_block_2_header = build_block_header(older_block_2)
        older_block_2_rlp = Data.from_bytes(older_block_2_header.raw_rlp()).to_ints()

        ids.older_block_2_rlp_len = len(older_block_2_rlp.values)
        segments.write_arg(ids.older_block_2_rlp, older_block_2_rlp.values)

        oldest_block = mocked_blocks[4]
        oldest_block_header = build_block_header(oldest_block)
        oldest_block_rlp = Data.from_bytes(oldest_block_header.raw_rlp()).to_ints()

        ids.oldest_block_rlp_len = len(oldest_block_rlp.values)
        segments.write_arg(ids.oldest_block_rlp, oldest_block_rlp.values)

        segments.write_arg(ids.block_headers_lens_bytes, [older_block_rlp.length, older_block_2_rlp.length, oldest_block_rlp.length])
        segments.write_arg(ids.block_headers_lens_words, [len(older_block_rlp.values), len(older_block_2_rlp.values), len(oldest_block_rlp.values)])
        ids.block_headers_concat_len = len([*older_block_rlp.values, *older_block_2_rlp.values, *oldest_block_rlp.values])
        segments.write_arg(ids.block_headers_concat, [*older_block_rlp.values, *older_block_2_rlp.values, *oldest_block_rlp.values])
    %}
    let (pedersen_hash_older_block) = hash_felts{hash_ptr=pedersen_ptr}(
        data=older_block_rlp, length=older_block_rlp_len
    );
    let (mmr_peaks_2: felt*) = alloc();
    let (node2) = hash2{hash_ptr=pedersen_ptr}(2, pedersen_hash_older_block);
    let (node3_1) = hash2{hash_ptr=pedersen_ptr}(node1, node2);
    let (node3) = hash2{hash_ptr=pedersen_ptr}(3, node3_1);
    assert mmr_peaks_2[0] = node3;

    let (mmr_peaks_3: felt*) = alloc();
    let (pedersen_hash_older_block_2) = hash_felts{hash_ptr=pedersen_ptr}(
        data=older_block_2_rlp, length=older_block_2_rlp_len
    );
    assert mmr_peaks_3[0] = node3;
    let (node4) = hash2{hash_ptr=pedersen_ptr}(4, pedersen_hash_older_block_2);
    assert mmr_peaks_3[1] = node4;

    let (mmr_peaks_concat: felt*) = alloc();
    assert mmr_peaks_concat[0] = mmr_peaks[0];
    assert mmr_peaks_concat[1] = mmr_peaks_2[0];
    assert mmr_peaks_concat[2] = mmr_peaks_3[0];
    assert mmr_peaks_concat[3] = mmr_peaks_3[1];

    let (mmr_peaks_lens: felt*) = alloc();
    %{ segments.write_arg(ids.mmr_peaks_lens, [1, 1, 2]) %}

    L1HeadersStore.process_till_block(
        contract_address=l1_headers_store,
        reference_block_number=start_block_number,
        reference_proof_leaf_index=1,
        reference_proof_leaf_value=pedersen_hash,
        reference_proof_len=0,
        reference_proof=proof,
        reference_header_rlp_bytes_len=block_header_to_be_processed_from_msg_rlp_bytes_len,
        reference_header_rlp_len=block_header_to_be_processed_from_msg_rlp_len,
        reference_header_rlp=block_header_to_be_processed_from_msg_rlp,
        block_headers_lens_bytes_len=3,
        block_headers_lens_bytes=block_headers_lens_bytes,
        block_headers_lens_words_len=3,
        block_headers_lens_words=block_headers_lens_words,
        block_headers_concat_len=block_headers_concat_len,
        block_headers_concat=block_headers_concat,
        mmr_peaks_len=1,
        mmr_peaks=mmr_peaks,
        mmr_pos=1,
    );
    return ();
}
