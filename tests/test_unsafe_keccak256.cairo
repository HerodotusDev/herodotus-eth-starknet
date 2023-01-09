%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc

from lib.unsafe_keccak import keccak256
from lib.types import IntsSequence, Keccak256Hash
from starkware.cairo.common.cairo_keccak.keccak import keccak_as_words, finalize_keccak

@view
func test_against_web3_unsafe{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    local keccak_input_length;
    local input_len;
    let (input: felt*) = alloc();
    %{
        from utils.helpers import (concat_arr, bytes_to_int)
        from utils.types import Data
        from rlp import encode
        from web3 import Web3
        bytes_to_int_big = lambda word: bytes_to_int(word)

        keccak_input = [
            b'\xf9\x02\x18\xa0\x03\xb0\x16\xcc',
            b'\x93\x87\xcb\x3c\xef\x86\xd9\xd4',
            b'\xaf\xb5\x2c\x37\x89\x52\x8c\x53',
            b'\x0c\x00\x20\x87\x95\xac\x93\x7c',
            b'\x00\x00\x00\x00\x00\x00\x00\x77',
        ]
        web3_computed_hash = Web3.keccak(concat_arr(keccak_input)).hex()
        ids.keccak_input_length = len(concat_arr(keccak_input))
        ipt = list(map(bytes_to_int_big, keccak_input))
        segments.write_arg(ids.input, ipt)
        ids.input_len = len(ipt)
    %}
    let (hash) = test_keccak256_std_unsafe(keccak_input_length, input_len, input);
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        output = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        assert output == web3_computed_hash
    %}
    return ();
}

func test_keccak256_std_unsafe{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    keccak_input_length: felt, input_len: felt, input: felt*
) -> (res: Keccak256Hash) {
    alloc_locals;
    let (local keccak_ptr: felt*) = alloc();
    let keccak_ptr_start = keccak_ptr;

    local keccak_input: IntsSequence = IntsSequence(input, input_len, keccak_input_length);

    let (keccak_hash) = keccak256{keccak_ptr=keccak_ptr}(keccak_input);

    local hash: Keccak256Hash = Keccak256Hash(
        word_1=keccak_hash[0], word_2=keccak_hash[1], word_3=keccak_hash[2], word_4=keccak_hash[3]
    );

    return (hash,);
}

// Input little endian
// Output little endian
func test_keccak256_std_safe{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    keccak_input_length: felt, input_len: felt, input: felt*
) -> (res: Keccak256Hash) {
    alloc_locals;
    let (local keccak_ptr: felt*) = alloc();
    let keccak_ptr_start = keccak_ptr;

    local input_ints_sequence: IntsSequence = IntsSequence(input, input_len, keccak_input_length);
    let (keccak_hash) = keccak_as_words{keccak_ptr=keccak_ptr}(
        input_ints_sequence.element, input_ints_sequence.element_size_bytes
    );
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr);
    local hash: Keccak256Hash = Keccak256Hash(
        word_1=keccak_hash[0], word_2=keccak_hash[1], word_3=keccak_hash[2], word_4=keccak_hash[3]
    );
    return (hash,);
}

@view
func test_hash_header_unsafe{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    local keccak_input_length;
    local input_len;
    let (input: felt*) = alloc();
    %{
        from utils.types import Data
        from web3 import Web3
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        block_rlp_chunked = Data.from_bytes(block_rlp).to_ints()
        assert block_header.hash() == block["hash"]
        ids.keccak_input_length = block_rlp_chunked.length
        segments.write_arg(ids.input, block_rlp_chunked.values)
        ids.input_len = len(block_rlp_chunked.values)
    %}
    let (hash) = test_keccak256_std_unsafe(keccak_input_length, input_len, input);
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        output = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        assert output == block["hash"].hex()
    %}
    return ();
}

@view
func test_against_safe_implementation{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    local keccak_input_length;
    local input_len;
    let (input_le: felt*) = alloc();
    let (input_be: felt*) = alloc();
    %{
        from utils.helpers import (concat_arr, bytes_to_int, Encoding)
        from utils.types import Data
        from web3 import Web3
        bytes_to_int_le = lambda word: bytes_to_int(word, Encoding.LITTLE)
        bytes_to_int_be = lambda word: bytes_to_int(word)

        keccak_input = [
            b'\xf9\x02\x18\xa0\x03\xb0\x16\xcc',
            b'\x93\x87\xcb\x3c\xef\x86\xd9\xd4',
            b'\xaf\xb5\x2c\x37\x89\x52\x8c\x53',
            b'\x0c\x00\x20\x87\x95\xac\x93\x7c',
            b'\x00\x00\x00\x00\x00\x00\x00\x77',
        ]
        web3_computed_hash = Web3.keccak(concat_arr(keccak_input)).hex()
        ids.keccak_input_length = len(concat_arr(keccak_input))
        ipt_le = list(map(bytes_to_int_le, keccak_input))
        ipt_be = list(map(bytes_to_int_be, keccak_input))
        segments.write_arg(ids.input_le, ipt_le)
        segments.write_arg(ids.input_be, ipt_be)
        ids.input_len = len(ipt_le)
        assert len(ipt_le) == len(ipt_be)
    %}
    let (hash_unsafe) = test_keccak256_std_unsafe(keccak_input_length, input_len, input_be);
    %{
        extracted_unsafe = [ids.hash_unsafe.word_1, ids.hash_unsafe.word_2, ids.hash_unsafe.word_3, ids.hash_unsafe.word_4]
        output_unsafe = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted_unsafe)
    %}
    let (hash_safe) = test_keccak256_std_safe(keccak_input_length, input_len, input_le);
    %{
        extracted_safe = [ids.hash_safe.word_1, ids.hash_safe.word_2, ids.hash_safe.word_3, ids.hash_safe.word_4]
        output_safe = '0x' + ''.join(v.to_bytes(8, 'little').hex() for v in extracted_safe)

        # unsafe_keccak expects big endiandness
        # keccak_as_words expects little endiandness
        # which is why we have slightly different input (endianwise)
        # to lead to the same (correct) keccak hash
        assert output_unsafe == output_safe
    %}
    return ();
}
