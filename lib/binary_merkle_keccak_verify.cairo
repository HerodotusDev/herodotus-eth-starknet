from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import unsigned_div_rem
from starkware.cairo.common.pow import pow

from lib.types import Keccak256Hash, IntsSequence
from lib.comp_arr import arr_eq

from lib.unsafe_keccak import keccak256
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak


const POSITION_HINT_SYMBOL = 0xFFFFFFFFFFFFFFFF;

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

func determine_value_index{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    proof_len: felt,
    proof: felt*
) -> (left_value_pos: felt, right_value_pos: felt) {
    alloc_locals;

    let (proof_nodes, r) = unsigned_div_rem(proof_len - 8, 5);
    assert r = 0;
    local proof_size = proof_nodes + 1;

    let (local moves) = alloc();
    let (local moves_len: felt) = determine_value_index_get_moves(
        proof_size,
        proof_len,
        proof,
        0,
        moves,
        proof_len - 1
    );
    let (bottom_row_size) = pow(2, proof_size);
    let (local left_pos, right_pos) = determine_value_index_divide_and_conquer(
        moves_len,
        moves,
        bottom_row_size,
        0,
        bottom_row_size,
        0
    );

    return (left_pos, right_pos);
}

func determine_value_index_get_moves{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    proof_size: felt,
    proof_len: felt,
    proof: felt*,
    moves_len: felt,
    moves: felt*,
    current_index: felt
) -> (moves_len: felt) {
    alloc_locals;
    if(moves_len == proof_size) {
        return (moves_len, );
    }

    local is_right_move;
    local current_value = proof[current_index];

    if(proof[current_index] == POSITION_HINT_SYMBOL) {
        is_right_move = 1;
    } else {
        is_right_move = 0;
    }

    assert moves[moves_len] = is_right_move;

    return determine_value_index_get_moves(
        proof_size,
        proof_len,
        proof,
        moves_len + 1,
        moves,
        current_index - 5
    );
}

func determine_value_index_divide_and_conquer{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    moves_len: felt,
    moves: felt*,
    bottom_row_size: felt,
    current_left_sibling_pos: felt,
    current_right_sibling_pos: felt,
    current_move_index: felt
) -> (left_sibling_pos: felt, right_sibling_pos: felt) {
    alloc_locals;
    if(moves_len - 1 == current_move_index) {
        return (current_left_sibling_pos, current_right_sibling_pos + 1);
    }

    local current_move = moves[current_move_index];

    // 1 -> Right, 0 -> Left
    if(current_move == 1) {
        return determine_value_index_divide_and_conquer(
            moves_len,
            moves,
            bottom_row_size,
            bottom_row_size / 2,
            current_right_sibling_pos,
            current_move_index + 1
        );
    } else {
        return determine_value_index_divide_and_conquer(
            moves_len,
            moves,
            bottom_row_size,
            current_left_sibling_pos,
            current_right_sibling_pos / 2,
            current_move_index + 1
        );
    }
}