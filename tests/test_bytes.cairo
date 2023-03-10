%lang starknet
%builtins pedersen range_check ecdsa bitwise

from lib.types import IntsSequence
from lib.bytes import (
    remove_leading_bytes
)

from starkware.cairo.common.alloc import alloc 

@view
func test_remove_2_leading_bytes{range_check_ptr}() -> () {
    alloc_locals;

    let (local input_words) = alloc();

    assert input_words[0] = 0xa0a7aaf2512769da;
    assert input_words[1] = 0x4e444e3de247be25;
    assert input_words[2] = 0x64225c2e7a8f74cf;
    assert input_words[3] = 0xe528e46e17d24868;

    local input: IntsSequence = IntsSequence(input_words, 4, 32);
    let (local result) = remove_leading_bytes(input, 2);

    assert result.element[0] = 0xaaf2512769da4e44;
    assert result.element[1] = 0x4e3de247be256422;
    assert result.element[2] = 0x5c2e7a8f74cfe528;
    assert result.element[3] = 0xe46e17d24868;

    return ();
}

@view
func test_remove_8_leading_bytes{range_check_ptr}() -> () {
    alloc_locals;

    let (local input_words) = alloc();

    assert input_words[0] = 0xa0a7aaf2512769da;
    assert input_words[1] = 0x4e444e3de247be25;
    assert input_words[2] = 0x64225c2e7a8f74cf;
    assert input_words[3] = 0xe528e46e17d24868;

    local input: IntsSequence = IntsSequence(input_words, 4, 32);
    let (local result) = remove_leading_bytes(input, 8);

    assert result.element[0] = 0x4e444e3de247be25;
    assert result.element[1] = 0x64225c2e7a8f74cf;
    assert result.element[2] = 0xe528e46e17d24868;

    return ();
}

@view
func test_remove_12_leading_bytes{range_check_ptr}() -> () {
    alloc_locals;

    let (local input_words) = alloc();

    assert input_words[0] = 0xa0a7aaf2512769da;
    assert input_words[1] = 0x4e444e3de247be25;
    assert input_words[2] = 0x64225c2e7a8f74cf;
    assert input_words[3] = 0xe528e46e17d24868;

    local input: IntsSequence = IntsSequence(input_words, 4, 32);
    let (local result) = remove_leading_bytes(input, 12);

    assert result.element[0] = 0xe247be2564225c2e;
    assert result.element[1] = 0x7a8f74cfe528e46e;
    assert result.element[2] = 0x17d24868;

    return ();
}