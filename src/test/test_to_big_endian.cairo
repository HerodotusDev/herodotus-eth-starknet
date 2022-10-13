%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starknet.lib.swap_endianness import swap_endianness_64, swap_endianness_four_words
from starknet.types import IntsSequence

@view
func test_swap_endianness_full_word{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() {
    alloc_locals;
    local input_as_big_endian;
    local input_as_little_endian;
    local input_str_len;
    %{
        def byteswap_64bit_word(word: int, size: int):
            swapped_bytes = ((word & 0xFF00FF00FF00FF00) >> 8) | ((word & 0x00FF00FF00FF00FF) << 8)
            swapped_2byte_pair = ((swapped_bytes & 0xFFFF0000FFFF0000) >> 16) | ((swapped_bytes & 0x0000FFFF0000FFFF) << 16)
            swapped_4byte_pair = (swapped_2byte_pair >> 32) | ((swapped_2byte_pair << 32) % 2**64)

            # Some Shiva-inspired code here
            if (size == 8):
                return swapped_4byte_pair
            else:
                return swapped_4byte_pair >> ((8-size)*8)

        input_str = 'f90218a089abcdef'
        ids.input_str_len = int(len(input_str) / 2)
        input_as_big_endian = int.from_bytes(bytearray.fromhex(input_str), 'big')
        ids.input_as_big_endian = input_as_big_endian

        input_as_little_endian = int.from_bytes(bytearray.fromhex(input_str), 'little')
        ids.input_as_little_endian = input_as_little_endian
        big_to_little_python = byteswap_64bit_word(input_as_big_endian, int(len(input_str)/2))

        assert big_to_little_python == input_as_little_endian

    %}
    let (big_to_little) = test_to_big_endian(input_as_big_endian, input_str_len);
    %{
        big_to_little_cairo = ids.big_to_little
        assert big_to_little_python == big_to_little_cairo

        little_to_big_python = byteswap_64bit_word(input_as_little_endian, int(len(input_str)/2))

        assert little_to_big_python == ids.input_as_big_endian
    %}
    let (little_to_big) = test_to_big_endian(input_as_little_endian, input_str_len);
    %{
        little_to_big_cairo = ids.little_to_big
        assert little_to_big_python == little_to_big_cairo
    %}
    return ();
}

@view
func test_swap_endianness_small_words{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(i: felt) -> () {
    helper_test_swap_endianness_small_words(8);
    return ();
}

func helper_test_swap_endianness_small_words{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(i: felt) -> () {
    if (i == 0) {
        return ();
    }
    alloc_locals;
    local input_as_big_endian;
    local input_as_little_endian;
    local input_str_len;
    %{
        def byteswap_64bit_word(word: int, size: int):
            swapped_bytes = ((word & 0xFF00FF00FF00FF00) >> 8) | ((word & 0x00FF00FF00FF00FF) << 8)
            swapped_2byte_pair = ((swapped_bytes & 0xFFFF0000FFFF0000) >> 16) | ((swapped_bytes & 0x0000FFFF0000FFFF) << 16)
            swapped_4byte_pair = (swapped_2byte_pair >> 32) | ((swapped_2byte_pair << 32) % 2**64)

            # Some Shiva-inspired code here
            if (size == 8):
                return swapped_4byte_pair
            else:
                return swapped_4byte_pair >> ((8-size)*8)

        input_str = 'f90218a089abcdef'[0:16-(0*2)]
        ids.input_str_len = int(len(input_str) / 2)
        input_as_big_endian = int.from_bytes(bytearray.fromhex(input_str), 'big')
        ids.input_as_big_endian = input_as_big_endian

        input_as_little_endian = int.from_bytes(bytearray.fromhex(input_str), 'little')
        ids.input_as_little_endian = input_as_little_endian
        big_to_little_python = byteswap_64bit_word(input_as_big_endian, int(len(input_str)/2))

        assert big_to_little_python == input_as_little_endian

    %}
    let (big_to_little) = test_to_big_endian(input_as_big_endian, input_str_len);
    %{
        big_to_little_cairo = ids.big_to_little
        assert big_to_little_python == big_to_little_cairo

        little_to_big_python = byteswap_64bit_word(input_as_little_endian, int(len(input_str)/2))

        assert little_to_big_python == ids.input_as_big_endian
    %}
    let (little_to_big) = test_to_big_endian(input_as_little_endian, input_str_len);
    %{
        little_to_big_cairo = ids.little_to_big
        assert little_to_big_python == little_to_big_cairo
    %}
    return helper_test_swap_endianness_small_words(i - 1);
}

func test_to_big_endian{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(word: felt, size: felt) -> (
    res: felt
) {
    let (res) = swap_endianness_64(word, size);
    return (res,);
}

// @view
// func test_many_words_to_big_endian{ range_check_ptr, bitwise_ptr : BitwiseBuiltin* }(input_len: felt, input: felt*, input_size_bytes: felt) -> (res_len_bytes: felt, res_len:felt, res: felt*):
//     let input_seq: IntsSequence = IntsSequence(input, input_len, input_size_bytes)

// let (res) = swap_endianness_many_words(input_seq)

// return (res.element_size_bytes, res.element_size_words, res.element)
// end

func test_four_words_to_big_endian{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    input_len: felt, input: felt*, input_size_bytes: felt
) -> (res_len_bytes: felt, res_len: felt, res: felt*) {
    let input_seq: IntsSequence = IntsSequence(input, input_len, input_size_bytes);

    let (res) = swap_endianness_four_words(input_seq);

    return (res.element_size_bytes, res.element_size_words, res.element);
}
