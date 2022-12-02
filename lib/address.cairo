from starkware.cairo.common.math import assert_le, unsigned_div_rem
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.pow import pow

from lib.types import Address
from lib.bitshift import bitshift_right, bitshift_left

func address_words64_to_160bit{range_check_ptr}(input: Address) -> (res: felt) {
    alloc_locals;

    let result = (input.word_1 * 2 ** 96) + (input.word_2 * 2 ** 32) + input.word_3;
    return (result,);
}

func address_160bit_to_words64{range_check_ptr}(input: felt) -> (res: Address) {
    alloc_locals;

    let (tmp, third_word) = unsigned_div_rem(input, 2 ** 32);  // 2 ** 8 * 4

    let third_word_max_size = 2 ** 32 - 1;
    assert_le(third_word, third_word_max_size);

    let (first_word, second_word) = unsigned_div_rem(tmp, 2 ** 64);  // 2 ** 8 * 8
    local res: Address = Address(first_word, second_word, third_word);
    return (res,);
}
