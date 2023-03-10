from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_le, unsigned_div_rem

from lib.bitshift import bitshift_right, bitshift_left
from lib.words64 import extract_byte, extract_bytes
from lib.types import IntsSequence

func remove_leading_bytes{range_check_ptr}(
    input: IntsSequence,
    number_of_bytes: felt
) -> (res: IntsSequence) {
    alloc_locals;
    assert_le(number_of_bytes, input.element_size_bytes);

    let (local start_from_word, local start_from_byte) = unsigned_div_rem(number_of_bytes, 8);

    let (local dst: felt*) = alloc();
    let (local dst_len: felt) = remove_leading_bytes_rec(
        input,
        start_from_byte,
        dst,
        0,
        start_from_word
    ); 
    local res: IntsSequence = IntsSequence(dst, dst_len, input.element_size_bytes - number_of_bytes);
    return (res, );
}

// TODO optimize by skipping unneccessary words
func remove_leading_bytes_rec{range_check_ptr}(
    input: IntsSequence,
    removed_bytes_per_word: felt,
    acc: felt*,
    acc_len: felt,
    current_index: felt
) -> (final_acc_len: felt) {
    alloc_locals;
    
    if (current_index == input.element_size_words) {
        return (acc_len, );
    }

    let (local current_word_left_shifted) = bitshift_left(input.element[current_index], removed_bytes_per_word * 8);
    local new_word;

    if (current_index != input.element_size_words - 1) {
        local next_word_cpy = input.element[current_index + 1];
        let (local next_word_first_byte) = extract_bytes(next_word_cpy, 8, 0, removed_bytes_per_word);
        new_word = current_word_left_shifted + next_word_first_byte;
    } else {
        let (local last_word) = bitshift_right(current_word_left_shifted, removed_bytes_per_word * 8);
        new_word = last_word;
    }

    assert acc[acc_len] = new_word;

    return remove_leading_bytes_rec(
        input=input,
        removed_bytes_per_word=removed_bytes_per_word,
        acc=acc,
        acc_len=acc_len + 1,
        current_index=current_index + 1
    );
}

func remove_leading_byte{pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
    input: IntsSequence
) -> (res: IntsSequence) {
    alloc_locals;
    let (local dst: felt*) = alloc();
    let (local dst_len) = remove_leading_byte_rec(input, dst, 0, 0);
    local no_leading_byte: IntsSequence = IntsSequence(dst, dst_len, input.element_size_bytes - 1);
    return (no_leading_byte,);
}

// TODO inspect: for some reason we lose the last nibble
func remove_leading_byte_rec{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(input: IntsSequence, acc: felt*, acc_len: felt, current_index: felt) -> (felt,) {
    alloc_locals;
    if (acc_len == input.element_size_words) {
        return (acc_len,);
    }

    let (local current_word_left_shifted) = bitshift_left(input.element[current_index], 8);

    local new_word;

    if (current_index != input.element_size_words - 1) {
        local next_word_cpy = input.element[current_index + 1];
        let (local next_word_first_byte) = extract_byte(next_word_cpy, 8, 0);
        new_word = current_word_left_shifted + next_word_first_byte;
    } else {
        let (local last_word) = bitshift_right(current_word_left_shifted, 8);
        new_word = last_word;
    }

    assert acc[current_index] = new_word;

    return remove_leading_byte_rec(
        input=input, acc=acc, acc_len=acc_len + 1, current_index=current_index + 1
    );
}
