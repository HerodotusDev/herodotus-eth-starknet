%lang starknet
%builtins pedersen range_check ecdsa

from lib.bitshift import bitshift_right, bitshift_left

@view
func test_bitshift_right{range_check_ptr}() -> () {
    alloc_locals;
    local input;
    local bits_shifted;
    %{
        from random import randint
        from utils.helpers import random_bytes, bytes_to_int
        bytes_to_int_big = lambda word: bytes_to_int(word)

        input_bytes = random_bytes(8)
        ids.input = bytes_to_int_big(input_bytes)
        ids.bits_shifted = randint(0, 64)
    %}
    let (shifted) = bitshift_right(input, bits_shifted);
    %{
        assert ids.input >> ids.bits_shifted == ids.shifted
    %}
    return ();
}

@view
func test_bitshift_left{range_check_ptr}() -> () {
    alloc_locals;
    local input;
    local bits_shifted;
    %{
        from random import randint
        from utils.helpers import random_bytes, bytes_to_int
        bytes_to_int_big = lambda word: bytes_to_int(word)
        
        input_bytes = random_bytes(8)
        ids.input = bytes_to_int_big(input_bytes)
        ids.bits_shifted = randint(0, 64)
    %}
    let (shifted) = bitshift_left(input, bits_shifted);
    %{
        expected = (ids.input << ids.bits_shifted) & (2**64 - 1)
        assert expected == ids.shifted
    %}
    return ();
}
