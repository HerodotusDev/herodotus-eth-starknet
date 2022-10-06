%lang starknet
%builtins pedersen range_check ecdsa

from starknet.lib.address import address_words64_to_160bit, address_160bit_to_words64
from starknet.types import Address
from starkware.cairo.common.alloc import alloc

@view
func test_address_words64_to_160bit{range_check_ptr}() -> (
) {
    alloc_locals;

    let (ipt : felt*) = alloc();
    %{
        from utils.types import Data

        example_addr = '0x9cB1e11D87013e70038f80381A70b6a6C4eCf519'

        arr = Data.from_hex(example_addr).to_ints().values
        assert len(arr) == 3
        
        segments.write_arg(ids.ipt, [arr[0], arr[1], arr[2]])
    %}

    local input: Address = Address(ipt[0], ipt[1], ipt[2]);
    let (res) = address_words64_to_160bit(input);

    // int(example_addr[2:], 16)
    assert res = 894569402460634410951006940476311615390570312985;

    return ();
}

@view
func test_address_160bit_to_words64{range_check_ptr}() -> () {
    alloc_locals;

    // int(example_addr[2:], 16)
    let (res) = address_160bit_to_words64(894569402460634410951006940476311615390570312985);
    %{
        from utils.types import Data

        example_addr = '0x9cB1e11D87013e70038f80381A70b6a6C4eCf519'

        output = list([ids.res.word_1, ids.res.word_2, ids.res.word_3])
        expected_output = Data.from_hex(example_addr).to_ints().values

        assert output == expected_output    
    %}
    return ();
}
