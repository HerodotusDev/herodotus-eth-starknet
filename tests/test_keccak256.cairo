%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.alloc import alloc

from lib.keccak import keccak256
from lib.types import IntsSequence
from python_utils import setup_python_defs
from lib.comp_arr import arr_eq

struct Keccak256Hash {
    word_1: felt,
    word_2: felt,
    word_3: felt,
    word_4: felt,
}

@view
func test_small_input{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    let (local input: felt*) = alloc();
    local keccak_input_length;
    local input_len;
    %{
        from web3 import Web3
        from utils.helpers import (concat_arr, bytes_to_int, Encoding)
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
        ipt = list(map(bytes_to_int_be, keccak_input))
        segments.write_arg(ids.input, ipt)
        ids.input_len = len(ipt)
    %}
    let (hash) = test_keccak256(keccak_input_length, input_len, input);
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        output = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        assert output == web3_computed_hash
    %}
    return ();
}

// Expects big endian as input
func test_keccak256{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    keccak_input_length: felt, input_len: felt, input: felt*
) -> (res: Keccak256Hash) {
    alloc_locals;
    let (local keccak_ptr: felt*) = alloc();
    let keccak_ptr_start = keccak_ptr;

    local input_ints_sequence: IntsSequence = IntsSequence(input, input_len, keccak_input_length);

    let (keccak_hash) = keccak256{keccak_ptr=keccak_ptr}(input_ints_sequence);

    local hash: Keccak256Hash = Keccak256Hash(
        word_1=keccak_hash[0],
        word_2=keccak_hash[1],
        word_3=keccak_hash[2],
        word_4=keccak_hash[3]
        );

    return (hash,);
}

@view
func test_small_tricky_input{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    let (local input: felt*) = alloc();
    local keccak_input_length;
    local input_len;
    %{
        from web3 import Web3
        from utils.helpers import (concat_arr, bytes_to_int, Encoding)
        bytes_to_int_be = lambda word: bytes_to_int(word)
        keccak_input = [
            b'\xf9\x02\x18\xa0\x03\xb0\x16\xcc',
            b'\x93\x87\xcb\x3c\xef\x86\xd9\xd4',
            b'\xaf\xb5\x2c\x37\x89\x52\x8c\x53',
            b'\x0c\x00\x20\x87\x95\xac\x93\x7c',
            b'\x00\x77',
        ]
        web3_computed_hash = Web3.keccak(concat_arr(keccak_input)).hex()
        ids.keccak_input_length = len(concat_arr(keccak_input))
        ipt = list(map(bytes_to_int_be, keccak_input))
        segments.write_arg(ids.input, ipt)
        ids.input_len = len(ipt)
    %}
    let (hash) = test_keccak256(keccak_input_length, input_len, input);
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        output = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        assert output == web3_computed_hash
    %}
    return ();
}

@view
func test_huge_input{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    let (local input: felt*) = alloc();
    local keccak_input_length;
    local input_len;
    %{
        from web3 import Web3
        from utils.helpers import (concat_arr, bytes_to_int, Encoding)
        bytes_to_int_be = lambda word: bytes_to_int(word)
        keccak_input = [
            b'\xf9\x02\x18\xa0\x03\xb0\x16\xcc',
            b'\x93\x87\xcb\x3c\xef\x86\xd9\xd4',
            b'\xaf\xb5\x2c\x37\x89\x52\x8c\x53',
            b'\x0c\x00\x20\x87\x95\xac\x93\x7c',
            b'\xe0\x45\x59\x6a\xa0\x1d\xcc\x4d',
            b'\xe8\xde\xc7\x5d\x7a\xab\x85\xb5',
            b'\x67\xb6\xcc\xd4\x1a\xd3\x12\x45',
            b'\x1b\x94\x8a\x74\x13\xf0\xa1\x42',
            b'\xfd\x40\xd4\x93\x47\x94\xfb\xb6',
            b'\x1b\x8b\x98\xa5\x9f\xbc\x4b\xd7',
            b'\x9c\x23\x21\x2a\xdd\xbe\xfa\xeb',
            b'\x28\x9f\xa0\xd4\x5c\xea\x1d\x5c',
            b'\xae\x78\x38\x6f\x79\xe0\xd5\x22',
            b'\xe0\xa1\xd9\x1b\x2d\xa9\x5f\xf8',
            b'\x4b\x5d\xe2\x58\xf2\xc9\x89\x3d',
            b'\x3f\x49\xb1\xa0\x14\x07\x4f\x25',
            b'\x3a\x03\x23\x23\x1d\x34\x9a\x3f',
            b'\x9c\x64\x6a\xf7\x71\xc1\xde\xc2',
            b'\xf2\x34\xbb\x80\xaf\xed\x54\x60',
            b'\xf5\x72\xfe\xd1\xa0\x5a\x6f\x5b',
            b'\x9a\xc7\x5a\xe1\xe1\xf8\xc4\xaf',
            b'\xef\xb9\x34\x7e\x14\x1b\xc5\xc9',
            b'\x55\xb2\xed\x65\x34\x1d\xf3\xe1',
            b'\xd5\x99\xfc\xad\x91\xb9\x01\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x00\x00\x00\x00\x00\x00\x00\x00',
            b'\x84\x76\xfe\x29\x0a\x83\xae\xce',
            b'\x98\x83\x7a\x12\x00\x83\x17\xed',
            b'\xcf\x84\x61\x97\xc0\x24\x99\xd8',
            b'\x83\x01\x0a\x0c\x84\x67\x65\x74',
            b'\x68\x88\x67\x6f\x31\x2e\x31\x37',
            b'\x2e\x31\x85\x6c\x69\x6e\x75\x78',
            b'\xa0\x73\x2d\x0e\xad\x04\x88\x3a',
            b'\x10\x97\x64\x63\xe5\xd4\xf7\x14',
            b'\xc0\xb2\xa8\x1a\x74\x61\x34\xe9',
            b'\xc2\x34\x1f\x59\xb6\xc7\x61\x0c',
            b'\x03\x88\x3f\x40\xad\x5a\x09\xe2',
            b'\xd5\x00\x18',
        ]
        web3_computed_hash = Web3.keccak(concat_arr(keccak_input)).hex()
        ids.keccak_input_length = len(concat_arr(keccak_input))
        ipt = list(map(bytes_to_int_be, keccak_input))
        segments.write_arg(ids.input, ipt)
        ids.input_len = len(ipt)
    %}
    let (hash) = test_keccak256(keccak_input_length, input_len, input);
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        output = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        assert output == web3_computed_hash
    %}
    return ();
}

@view
func test_blockheader_input{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    let (local input: felt*) = alloc();
    local keccak_input_length;
    local input_len;
    %{
        from utils.helpers import (concat_arr, bytes_to_int, chunk_bytes_input)
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        bytes_to_int_be = lambda word: bytes_to_int(word)

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()

        assert block_header.hash() == block["hash"]
        block_rlp_chunked = chunk_bytes_input(block_rlp)

        ids.keccak_input_length = len(concat_arr(block_rlp_chunked))
        ipt = list(map(bytes_to_int_be, block_rlp_chunked))
        segments.write_arg(ids.input, ipt)
        ids.input_len = len(ipt)
    %}
    let (hash) = test_keccak256(keccak_input_length, input_len, input);
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        output = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        assert output == block["hash"].hex()
    %}
    return ();
}
