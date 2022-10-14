%lang starknet
%builtins pedersen range_check ecdsa

from starkware.cairo.common.math_cmp import is_le

@view
func test_is_le{range_check_ptr}() -> () {
    let a = 0;
    let b = 0;
    let res = is_le(a - b, -1);
    %{
        assert ids.res == int(ids.a < ids.b)
    %}
    return ();
}
