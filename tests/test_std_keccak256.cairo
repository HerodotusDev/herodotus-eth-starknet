%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.alloc import alloc

from starkware.cairo.common.cairo_keccak.keccak import keccak_as_words, finalize_keccak

from lib.types import IntsSequence
from lib.keccak_std_be import keccak256_auto_finalize

struct Keccak256Hash {
    word_1: felt,
    word_2: felt,
    word_3: felt,
    word_4: felt,
}

@view
func test_against_web3{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    local keccak_input_length;
    local input_len;
    let (input: felt*) = alloc();
    %{
        from utils.helpers import (concat_arr, bytes_to_int, Encoding)
        from utils.types import Data
        from rlp import encode
        from web3 import Web3
        bytes_to_int_le = lambda word: bytes_to_int(word, Encoding.LITTLE)

        keccak_input = [
            b'\xf9\x02\x18\xa0\x03\xb0\x16\xcc',
            b'\x93\x87\xcb\x3c\xef\x86\xd9\xd4',
            b'\xaf\xb5\x2c\x37\x89\x52\x8c\x53',
            b'\x0c\x00\x20\x87\x95\xac\x93\x7c',
            b'\x00\x00\x00\x00\x00\x00\x00\x77',
        ]
        ids.keccak_input_length = len(concat_arr(keccak_input))
        ipt = list(map(bytes_to_int_le, keccak_input))
        segments.write_arg(ids.input, ipt)
        ids.input_len = len(ipt)
    %}
    let (hash) = test_keccak256_std(keccak_input_length, input_len, input);
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        output = '0x' + ''.join(v.to_bytes(8, 'little').hex() for v in extracted)
        web3_computed_hash = Web3.keccak(concat_arr(keccak_input)).hex()
        assert output == web3_computed_hash
    %}
    return ();
}

// Input little endian
// Output little endian
func test_keccak256_std{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
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
        word_1=keccak_hash[0],
        word_2=keccak_hash[1],
        word_3=keccak_hash[2],
        word_4=keccak_hash[3]
        );
    return (hash,);
}

@view
func test_against_web3_multiple_inputs{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    local keccak_input_length;
    local input_len;
    let (input: felt*) = alloc();
    local keccak_input_2_length;
    local input_2_len;
    let (input_2: felt*) = alloc();
    %{
        from utils.helpers import (concat_arr, bytes_to_int, Encoding)
        from utils.types import Data
        from rlp import encode
        from web3 import Web3
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        bytes_to_int_le = lambda word: bytes_to_int(word, Encoding.LITTLE)

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()

        block_rlp_chunked = Data.from_bytes(block_rlp).to_ints(Encoding.LITTLE)
        ids.keccak_input_2_length = block_rlp_chunked.length
        segments.write_arg(ids.input_2, block_rlp_chunked.values)
        ids.input_2_len = len(block_rlp_chunked.values)

        keccak_input = [
            b'\xf9\x02\x18\xa0\x03\xb0\x16\xcc',
            b'\x93\x87\xcb\x3c\xef\x86\xd9\xd4',
            b'\xaf\xb5\x2c\x37\x89\x52\x8c\x53',
            b'\x0c\x00\x20\x87\x95\xac\x93\x7c',
            b'\x00\x00\x00\x00\x00\x00\x00\x77',
        ]
        ids.keccak_input_length =  len(concat_arr(keccak_input))
        ipt = list(map(bytes_to_int_le, keccak_input))
        segments.write_arg(ids.input, ipt)
        ids.input_len = len(ipt)
    %}
    let (hash1, hash2) = test_keccak256_std_multiple(
        keccak_input_length, input_len, input, keccak_input_2_length, input_2_len, input_2
    );
    %{
        extracted1 = [ids.hash1.word_1, ids.hash1.word_2, ids.hash1.word_3, ids.hash1.word_4]
        extracted2 = [ids.hash2.word_1, ids.hash2.word_2, ids.hash2.word_3, ids.hash2.word_4]

        output_1 = '0x' + ''.join(v.to_bytes(8, 'little').hex() for v in extracted1)
        output_2 = '0x' + ''.join(v.to_bytes(8, 'little').hex() for v in extracted2)

        web3_computed_hash_1 = Web3.keccak(concat_arr(keccak_input)).hex()
        web3_computed_hash_2 = block["hash"].hex()
        assert output_1 == web3_computed_hash_1
        assert output_2 == web3_computed_hash_2
    %}
    return ();
}

// Input little endian
// Output little endian
func test_keccak256_std_multiple{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    keccak_input_1_length: felt,
    input_1_len: felt,
    input_1: felt*,
    keccak_input_2_length: felt,
    input_2_len: felt,
    input_2: felt*,
) -> (res_1: Keccak256Hash, res_2: Keccak256Hash) {
    alloc_locals;
    let (local keccak_ptr: felt*) = alloc();
    let keccak_ptr_start = keccak_ptr;

    local input_ints_sequence_1: IntsSequence = IntsSequence(input_1, input_1_len, keccak_input_1_length);
    let (keccak_hash_1) = keccak_as_words{keccak_ptr=keccak_ptr}(
        input_ints_sequence_1.element, input_ints_sequence_1.element_size_bytes
    );

    local input_ints_sequence_2: IntsSequence = IntsSequence(input_2, input_2_len, keccak_input_2_length);
    let (keccak_hash_2) = keccak_as_words{keccak_ptr=keccak_ptr}(
        input_ints_sequence_2.element, input_ints_sequence_2.element_size_bytes
    );

    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr);

    local hash_1: Keccak256Hash = Keccak256Hash(
        word_1=keccak_hash_1[0],
        word_2=keccak_hash_1[1],
        word_3=keccak_hash_1[2],
        word_4=keccak_hash_1[3]
        );

    local hash_2: Keccak256Hash = Keccak256Hash(
        word_1=keccak_hash_2[0],
        word_2=keccak_hash_2[1],
        word_3=keccak_hash_2[2],
        word_4=keccak_hash_2[3]
        );

    return (hash_1, hash_2);
}

@view
func test_against_web3_be{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    local keccak_input_length;
    local input_len;
    let (input: felt*) = alloc();
    %{
        from utils.helpers import (concat_arr, bytes_to_int, Encoding)
        from utils.types import Data
        from rlp import encode
        from web3 import Web3
        bytes_to_int_be = lambda word: bytes_to_int(word)

        keccak_input = [
            b'\xf9\x02\x18\xa0\x03\xb0\x16\xcc',
            b'\x93\x87\xcb\x3c\xef\x86\xd9\xd4',
            b'\xaf\xb5\x2c\x37\x89\x52\x8c\x53',
            b'\x0c\x00\x20\x87\x95\xac\x93\x7c',
            b'\x00\x00\x00\x00\x00\x00\x00\x77',
        ]
        ids.keccak_input_length =  len(concat_arr(keccak_input))
        ipt = list(map(bytes_to_int_be, keccak_input))
        segments.write_arg(ids.input, ipt)
        ids.input_len = len(ipt)
    %}
    let (hash) = test_keccak256_std_be(keccak_input_length, input_len, input);
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        output = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        web3_computed_hash = Web3.keccak(concat_arr(keccak_input)).hex()
        assert output == web3_computed_hash
    %}
    return ();
}

// Input big endian
// Output big endian
func test_keccak256_std_be{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    keccak_input_length: felt, input_len: felt, input: felt*
) -> (res: Keccak256Hash) {
    alloc_locals;
    let (local keccak_ptr: felt*) = alloc();

    local input_be: IntsSequence = IntsSequence(input, input_len, keccak_input_length);
    let (local result) = keccak256_auto_finalize{keccak_ptr=keccak_ptr}(input_be);

    local hash: Keccak256Hash = Keccak256Hash(
        word_1=result[0],
        word_2=result[1],
        word_3=result[2],
        word_4=result[3]
        );

    return (hash,);
}

@view
func test_hash_header{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    local keccak_input_length;
    local input_len;
    let (input: felt*) = alloc();
    %{
        from utils.helpers import (bytes_to_int, Encoding)
        from utils.types import Data
        from web3 import Web3
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        bytes_to_int_le = lambda word: bytes_to_int(word, Encoding.LITTLE)

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        block_rlp_chunked = Data.from_bytes(block_rlp).to_ints(Encoding.LITTLE)
        ids.keccak_input_length = block_rlp_chunked.length
        segments.write_arg(ids.input, block_rlp_chunked.values)
        ids.input_len = len(block_rlp_chunked.values)
        assert block_header.hash() == block["hash"]
    %}
    let (hash) = test_keccak256_std(keccak_input_length, input_len, input);
    %{
        extracted = [ids.hash.word_1, ids.hash.word_2, ids.hash.word_3, ids.hash.word_4]
        output = '0x' + ''.join(v.to_bytes(8, 'little').hex() for v in extracted)
        assert output == block["hash"].hex()
    %}
    return ();
}
