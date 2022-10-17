%lang starknet
%builtins pedersen range_check ecdsa

from starkware.cairo.common.alloc import alloc
from lib.comp_arr import arr_eq

@view
func test_comp_arr_not_eq() -> () {
    let (a: felt*) = alloc();
    let (b: felt*) = alloc();
    %{
        segments.write_arg(ids.a, [10, 30, 50])
        segments.write_arg(ids.b, [70, 90, 110])
    %}
    let (res) = arr_eq(a=a, a_len=3, b=b, b_len=3);
    assert res = 0;
    return ();
}

@view
func test_comp_arr_eq() -> () {
    let (a: felt*) = alloc();
    let (b: felt*) = alloc();
    %{
        segments.write_arg(ids.a, [10, 30, 50])
        segments.write_arg(ids.b, [10, 30, 50])
    %}
    let (res) = arr_eq(a=a, a_len=3, b=b, b_len=3);
    assert res = 1;
    return ();
}

@view
func test_comp_arr_empty() -> () {
    let (a: felt*) = alloc();
    let (b: felt*) = alloc();
    let (res) = arr_eq(a=a, a_len=0, b=b, b_len=0);
    assert res = 1;
    return ();
}

@view
func test_comp_arr_different_size() -> () {
    let (a: felt*) = alloc();
    let (b: felt*) = alloc();
    %{ segments.write_arg(ids.b, [10, 20, 30]) %}
    let (res) = arr_eq(a=a, a_len=0, b=b, b_len=3);
    assert res = 0;
    return ();
}
