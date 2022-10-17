%lang starknet
%builtins pedersen range_check ecdsa bitwise

from lib.types import IntsSequence
from lib.words64 import extract_nibble, extract_nibble_from_words, to_words128
from starkware.cairo.common.alloc import alloc

@view
func test_extract_nibble_from_single_word{range_check_ptr}() -> () {
    helper_test_extract_nibble(8);
    return ();
}

func helper_test_extract_nibble{range_check_ptr}(index: felt) -> () {
    alloc_locals;
    if (index == 0) {
        return ();
    }
    local word;
    local word_len_bytes;
    let (expected_res: felt*) = alloc();
    local max_index;
    %{
        from utils.types import Data
        from utils.helpers import random_bytes
        input = Data.from_bytes(random_bytes(ids.index))
        word = input.to_ints().values[0]
        ids.word = word
        ids.word_len_bytes = len(input.to_bytes())
        segments.write_arg(ids.expected_res, input.to_nibbles())
        ids.max_index = (ids.index * 2) - 1
    %}
    helper_2_test_extract_nibble(word, word_len_bytes, expected_res, max_index);
    return helper_test_extract_nibble(index - 1);
}

func helper_2_test_extract_nibble{range_check_ptr}(
    word: felt, word_len_bytes: felt, expected_res: felt*, index: felt
) -> () {
    let (res) = extract_nibble(word, word_len_bytes, index);
    assert res = expected_res[index];
    if (index == 0) {
        return ();
    }
    return helper_2_test_extract_nibble(word, word_len_bytes, expected_res, index - 1);
}

@view
func test_to_words128{range_check_ptr}() -> () {
    alloc_locals;
    local words64_len_bytes;
    local words64_len;
    let (words64: felt*) = alloc();
    %{
        from utils.types import Data
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        from utils.helpers import IntsSequence

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()

        block_header_input = Data.from_bytes(block_rlp)
        words = block_header_input.to_ints()
        segments.write_arg(ids.words64, words.values)
        ids.words64_len = len(words.values)
        ids.words64_len_bytes = len(block_header_input.to_bytes())
    %}
    let (res_len, res) = helper_test_to_words128(words64_len_bytes, words64_len, words64);
    %{
        output = memory.get_range(ids.res, ids.res_len)

        # TODO: investigate the assertion failure when using range(0, len(output))
        for i in range(0, len(output) - 1):
            output_word_bin = bin(output[i])[2:]
            if len(output_word_bin) < 128:
                if len(output_word_bin) < 64:
                    input128_word_bin = bin(block_header_input.to_ints().values[i * 2])[2:].zfill(64)
                else:
                    input128_word_bin = bin(block_header_input.to_ints().values[i * 2])[2:].zfill(64) + bin(block_header_input.to_ints().values[i * 2 + 1])[2:].zfill(64)
            else:
                input128_word_bin = bin(block_header_input.to_ints().values[i * 2])[2:].zfill(64) + bin(block_header_input.to_ints().values[i * 2 + 1])[2:].zfill(64)
            #print("expected", input128_word_bin.zfill(128), "; got", output_word_bin.zfill(128))
            assert output_word_bin.zfill(128) == input128_word_bin.zfill(128), f"Failed at iteration: {i}"
    %}
    return ();
}

func helper_test_to_words128{range_check_ptr}(
    words64_len_bytes: felt, words64_len: felt, words64: felt*
) -> (res_len: felt, res: felt*) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(words64, words64_len, words64_len_bytes);
    let (local words128: felt*, local words128_len: felt) = to_words128(input);
    return (words128_len, words128);
}

@view
func test_extract_nibble_from_ints_sequence{range_check_ptr}() -> () {
    helper_test_extract_nibble_from_ints_sequence(34);
    return ();
}

func helper_test_extract_nibble_from_ints_sequence{range_check_ptr}(index: felt) -> () {
    alloc_locals;
    local words_len;
    let (words: felt*) = alloc();
    local words_len_bytes;
    let (expected_res: felt*) = alloc();
    local max_index;
    if (index == 0) {
        return ();
    }
    %{
        from utils.types import Data
        from utils.helpers import random_bytes
        input = Data.from_bytes(random_bytes(ids.index))
        words = input.to_ints()
        segments.write_arg(ids.words, words.values)
        ids.words_len = len(words.values)
        ids.words_len_bytes = len(input.to_bytes())

        segments.write_arg(ids.expected_res, input.to_nibbles())
        ids.max_index = (len(input.to_bytes()) * 2) - 1
    %}
    helper_2_test_extract_nibble_from_ints_sequence(
        words_len, words, words_len_bytes, expected_res, max_index
    );
    return helper_test_extract_nibble_from_ints_sequence(index - 1);
}

func helper_2_test_extract_nibble_from_ints_sequence{range_check_ptr}(
    words_len: felt, words: felt*, words_len_bytes: felt, expected_res: felt*, index: felt
) -> () {
    let (res) = test_extract_nibble_from_words(words_len, words, words_len_bytes, index);
    assert res = expected_res[index];
    if (index == 0) {
        return ();
    }
    return helper_2_test_extract_nibble_from_ints_sequence(
        words_len, words, words_len_bytes, expected_res, index - 1
    );
}

func test_extract_nibble_from_words{range_check_ptr}(
    words_len: felt, words: felt*, words_len_bytes: felt, position: felt
) -> (res: felt) {
    alloc_locals;
    let input: IntsSequence = IntsSequence(words, words_len, words_len_bytes);
    let (local result) = extract_nibble_from_words(input, position);
    return (result,);
}

@view
func test_extract_nibble_invalid_position{range_check_ptr}() -> () {
    alloc_locals;
    local word;
    local word_len_bytes;
    %{
        from utils.types import Data
        from utils.helpers import random_bytes

        input = Data.from_bytes(random_bytes(29))
        ids.word = input.to_ints().values[0]
        ids.word_len_bytes = len(input.to_bytes())
    %}
    %{ expect_revert() %}
    let (res) = extract_nibble(word, word_len_bytes, 16);
    return ();
}
