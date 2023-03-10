%lang starknet
%builtins pedersen range_check ecdsa bitwise

from lib.types import Keccak256Hash
from lib.binary_merkle_keccak_verify import merkle_keccak_verify, determine_value_index

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
    // 27 32 c8 ed 62 44 9a e3 4e b7 23 97 af d9 ec e2 70 a9 ad 5b 1e 18 93 69 b9 98 c5 ba a4 75 5d cf
    local expected_root: Keccak256Hash = Keccak256Hash(
        0x2732c8ed62449ae3,
        0x4eb72397afd9ece2,
        0x70a9ad5b1e189369,
        0xb998c5baa4755dcf
    );

    merkle_keccak_verify(expected_root, proof_len, proof);
    return ();
}

@view
func test_determine_value_index{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
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

    let (local left_index, local right_index) = determine_value_index(proof_len, proof);

    assert left_index = 4;
    assert right_index = 5;

    return ();
}