from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc

from lib.types import Keccak256Hash, IntsSequence
from lib.comp_arr import arr_eq

from lib.unsafe_keccak import keccak256
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak


const POSITION_HINT_SYMBOL = 0xffffffffffffffff;

func merkle_keccak_verify{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    root: Keccak256Hash,
    proof_len: felt,
    proof: felt*
) {
    alloc_locals;

    let (local keccak_ptr: felt*) = alloc();

    let (local initial_sibling_computation_input_words) = alloc();

    assert initial_sibling_computation_input_words[0] = proof[0];
    assert initial_sibling_computation_input_words[1] = proof[1];
    assert initial_sibling_computation_input_words[2] = proof[2];
    assert initial_sibling_computation_input_words[3] = proof[3];
    assert initial_sibling_computation_input_words[4] = proof[4];
    assert initial_sibling_computation_input_words[5] = proof[5];
    assert initial_sibling_computation_input_words[6] = proof[6];
    assert initial_sibling_computation_input_words[7] = proof[7];

    local initial_sibling_computation_input: IntsSequence = IntsSequence(initial_sibling_computation_input_words, 8, 64); 

    let (local initial_sibling_words: felt*) = keccak256{keccak_ptr=keccak_ptr}(initial_sibling_computation_input);
    local initial_sibling: Keccak256Hash = Keccak256Hash(initial_sibling_words[0], initial_sibling_words[1], initial_sibling_words[2], initial_sibling_words[3]);
    
    let (local final_sibling: Keccak256Hash) = merkle_keccak_verify_rec{keccak_ptr=keccak_ptr}(
        root,
        proof_len,
        proof,
        initial_sibling,
        1,
        8
    );

    let (local final_sibling_words: felt*) = alloc();

    assert final_sibling_words[0] = final_sibling.word_1;
    assert final_sibling_words[1] = final_sibling.word_2;
    assert final_sibling_words[2] = final_sibling.word_3;
    assert final_sibling_words[3] = final_sibling.word_4;

    let (local root_words: felt*) = alloc();

    assert root_words[0] = root.word_1;
    assert root_words[1] = root.word_2;
    assert root_words[2] = root.word_3;
    assert root_words[3] = root.word_4;

    let (local is_root_matched) = arr_eq(root_words, 4, final_sibling_words, 4);

    assert is_root_matched = 1;
    return ();
}

func merkle_keccak_verify_rec{range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*}(
    root: Keccak256Hash,
    proof_len: felt,
    proof: felt*,
    current_sibling: Keccak256Hash,
    current_index: felt,
    next_element_start: felt) -> (final_sibling: Keccak256Hash
) {
    alloc_locals;

    if(next_element_start == proof_len - 1) {
        return (current_sibling, );
    }

    let (local current_row_hash_words: felt*) = alloc();
    local is_left_sibling = POSITION_HINT_SYMBOL - proof[next_element_start] + 1;

    local debug = proof[next_element_start];

    local next_element_jump;
    if(is_left_sibling == 1) {
        assert current_row_hash_words[0] = current_sibling.word_1;
        assert current_row_hash_words[1] = current_sibling.word_2;
        assert current_row_hash_words[2] = current_sibling.word_3;
        assert current_row_hash_words[3] = current_sibling.word_4;

        assert current_row_hash_words[4] = proof[next_element_start + 1];
        assert current_row_hash_words[5] = proof[next_element_start + 2];
        assert current_row_hash_words[6] = proof[next_element_start + 3];
        assert current_row_hash_words[7] = proof[next_element_start + 4];

        next_element_jump = 5;
    } else {
        local separator = proof[next_element_start + 4];
        assert separator = POSITION_HINT_SYMBOL;

        assert current_row_hash_words[0] = proof[next_element_start];
        assert current_row_hash_words[1] = proof[next_element_start + 1];
        assert current_row_hash_words[2] = proof[next_element_start + 2];
        assert current_row_hash_words[3] = proof[next_element_start + 3];

        assert current_row_hash_words[4] = current_sibling.word_1;
        assert current_row_hash_words[5] = current_sibling.word_2;
        assert current_row_hash_words[6] = current_sibling.word_3;
        assert current_row_hash_words[7] = current_sibling.word_4;

        next_element_jump = 4;
    }

    local keccak_input: IntsSequence = IntsSequence(current_row_hash_words, 8, 64); 
    let (local keccak_output_words: felt*) = keccak256{keccak_ptr=keccak_ptr}(keccak_input);
    local keccak_output: Keccak256Hash = Keccak256Hash(
        keccak_output_words[0],
        keccak_output_words[1],
        keccak_output_words[2],
        keccak_output_words[3]
    );

    return merkle_keccak_verify_rec(
        root,
        proof_len,
        proof,
        keccak_output,
        current_index + 1,
        next_element_start + next_element_jump
    );
}