%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starknet.types import IntsSequence
from starknet.lib.words64 import extract_nibble, extract_nibble_from_words, to_words128
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
    let (expected_res : felt*) = alloc();
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

func helper_2_test_extract_nibble{range_check_ptr}(word: felt, word_len_bytes: felt, expected_res : felt*, index: felt) -> () {
    let (res) = extract_nibble(word, word_len_bytes, index);
    assert res = expected_res[index];
    if (index == 0) {
        return ();
    }
    return helper_2_test_extract_nibble(word, word_len_bytes, expected_res, index - 1);
}

func test_extract_nibble_from_words{range_check_ptr}(
    words_len: felt, words: felt*, words_len_bytes: felt, position: felt
) -> (res: felt) {
    alloc_locals;
    let input: IntsSequence = IntsSequence(words, words_len, words_len_bytes);
    let (local result) = extract_nibble_from_words(input, position);
    return (result,);
}

func test_to_words128{range_check_ptr}(
    words64_len_bytes: felt, words64_len: felt, words64: felt*
) -> (res_len: felt, res: felt*) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(words64, words64_len, words64_len_bytes);
    let (local words128: felt*, local words128_len: felt) = to_words128(input);
    return (words128_len, words128);
}
