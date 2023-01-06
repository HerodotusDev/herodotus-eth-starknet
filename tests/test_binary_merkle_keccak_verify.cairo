%lang starknet
%builtins pedersen range_check ecdsa bitwise

from lib.types import Keccak256Hash
from lib.binary_merkle_keccak_verify import merkle_keccak_verify

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin


@view
func test_verify_valid_proof{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;

    let (proof: felt*) = alloc();
    local proof_len;
    %{
        input = [
            0x0e9d9b06cc31b047, 0x050c49ec81881e51,
            0xa03a17ede73f4357, 0x080383bb1574fc46,
            0x4dd5a8e20d546b64, 0xe2bab88c49a0eab0,
            0x4bd94273502c6599, 0x497419c3127b8336,
            0xffffffffffffffff, 0x0743adc9d583bfa2,
            0xb00637c627deada5, 0x03689fa7d6722898,
            0x16e154ae053dae4f, 0x361c56100ee0434d,
            0x9ce07e52a64f39fe, 0xe38d72c54f5ff39d,
            0x5c26dd9eae3e78c9, 0xffffffffffffffff
        ]
        segments.write_arg(ids.proof, input)
        ids.proof_len = len(input)
    %}
    // 19 BE 2A 01 F9 CB DD B7 CF 3C 6C 59 F5 84 49 B8 42 52 24 1E 39 57 2E 91 5E 0F 59 B3 07 43 3A AA
    local expected_root: Keccak256Hash = Keccak256Hash(
        0x19BE2A01F9CBDDB7,
        0xCF3C6C59F58449B8,
        0x4252241E39572E91,
        0x5E0F59B307433AAA
    );

    merkle_keccak_verify(expected_root, proof_len, proof);
    return ();
}