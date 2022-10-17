%lang starknet
%builtins pedersen range_check ecdsa

from lib.bitset import bitset_get
from starkware.cairo.common.math_cmp import is_in_range

func call_bitset_get{range_check_ptr}(bitset: felt, position: felt) -> (res: felt) {
    let (res: felt) = bitset_get(bitset, position);
    return (res=res);
}

func call_bitset_get_recursive{range_check_ptr}(bitset: felt, position: felt) -> () {
    alloc_locals;

    let (r: felt) = call_bitset_get(bitset, position);

    assert r = 1;

    if (position == 0) {
        return ();
    }
    local next_bitset;
    %{ ids.next_bitset = 2 ** (ids.position - 1) %}
    return call_bitset_get_recursive(next_bitset, position - 1);
}

func call_bitset_get_recursive_assert_1{range_check_ptr}(bitset: felt, position: felt) -> () {
    alloc_locals;

    let (r: felt) = call_bitset_get(bitset, position);

    assert r = 1;

    if (position == 0) {
        return ();
    }
    return call_bitset_get_recursive_assert_1(bitset, position - 1);
}

func call_bitset_get_recursive_assert_0{range_check_ptr}(bitset: felt, position: felt) -> () {
    alloc_locals;

    let (r: felt) = call_bitset_get(bitset, position);

    assert r = 0;

    if (position == 0) {
        return ();
    }
    return call_bitset_get_recursive_assert_0(bitset, position - 1);
}

func call_bitset_get_random_recursive{range_check_ptr}(bitset: felt, position: felt, sum: felt) -> (
    sum: felt
) {
    alloc_locals;

    let (r: felt) = call_bitset_get(bitset, position);

    local updated_sum;
    %{ ids.updated_sum = ids.sum + (ids.r * 2 ** ids.position) %}
    if (position == 0) {
        return (sum=updated_sum);
    }
    return call_bitset_get_random_recursive(bitset, position - 1, updated_sum);
}

@view
func test_bitset{range_check_ptr}() -> () {
    let last_bitset = 2 ** 15;
    call_bitset_get_recursive(last_bitset, 15);
    return ();
}

@view
func test_bitset_random{range_check_ptr}(random_bitset: felt) -> () {
    if (is_in_range(random_bitset, 1, 2 ** 16 - 1) == 0) {
        %{ reject() %}
        return ();
    }

    let (sum: felt) = call_bitset_get_random_recursive(random_bitset, 15, 0);
    assert sum = random_bitset;
    return ();
}

@view
func test_bitset_all_zeroes{range_check_ptr}() -> () {
    let bitset = 0;
    call_bitset_get_recursive_assert_0(bitset, 15);
    return ();
}

@view
func test_bitset_all_ones{range_check_ptr}() -> () {
    let bitset = 2 ** 16 - 1;
    call_bitset_get_recursive_assert_1(bitset, 15);
    return ();
}
