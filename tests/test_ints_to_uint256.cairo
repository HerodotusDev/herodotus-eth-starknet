%lang starknet
%builtins range_check bitwise

from starkware.cairo.common.alloc import alloc

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256
from lib.types import IntsSequence
from lib.ints_to_uint256 import ints_to_uint256

@view
func test_covert_0{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    let (array: felt*) = alloc();
    %{ segments.write_arg(ids.array, [0]) %}

    local input: IntsSequence = IntsSequence(array, 1, 1);
    let (local out: Uint256) = ints_to_uint256(ints=input);

    assert out = Uint256(0, 0);
    return ();
}

@view
func test_covert_1{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    let (array: felt*) = alloc();
    %{ segments.write_arg(ids.array, [1]) %}

    local input: IntsSequence = IntsSequence(array, 1, 1);
    let (local out: Uint256) = ints_to_uint256(ints=input);

    assert out = Uint256(1, 0);
    return ();
}

@external
func setup_covert_random() {
    %{
        given(
            rand_felt = strategy.felts()
        )
    %}
    return ();
}

@view
func test_covert_random{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(rand_felt: felt) -> () {
    alloc_locals;
    let (array: felt*) = alloc();
    %{ segments.write_arg(ids.array, [ids.rand_felt]) %}
    local input: IntsSequence = IntsSequence(array, 1, 1);
    let (local out: Uint256) = ints_to_uint256(ints=input);
    assert out = Uint256(rand_felt, 0);
    return ();
}

@view
func test_covert_out_of_bound{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    let (array: felt*) = alloc();
    local num;
    %{
        from random import randint
        num = randint(2**256, 2**512)
        segments.write_arg(ids.array, [num])
        ids.num = num
    %}
    local input: IntsSequence = IntsSequence(array, 1, 1);
    %{ expect_revert() %}
    let (local out: Uint256) = ints_to_uint256(ints=input);
    %{ assert ids.out.low == num %}
    return ();
}
