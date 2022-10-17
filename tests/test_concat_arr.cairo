%lang starknet
%builtins pedersen range_check ecdsa

from starkware.cairo.common.alloc import alloc
from lib.concat_arr import concat_arr

@view
func test_concat_arr{range_check_ptr}() -> () {
    let (acc: felt*) = alloc();
    let (arr: felt*) = alloc();
    %{
        segments.write_arg(ids.acc, [10, 30, 50])
        segments.write_arg(ids.arr, [70, 90, 110])
    %}
    let (res, res_len) = concat_arr(acc=acc, acc_len=3, arr=arr, arr_len=3);
    assert res_len = 6;
    assert res[0] = 10;
    assert res[1] = 30;
    assert res[2] = 50;
    assert res[3] = 70;
    assert res[4] = 90;
    assert res[5] = 110;
    return ();
}
