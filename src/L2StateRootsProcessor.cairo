%lang starknet
%builtins pedersen range_check bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy

from lib.bitshift import bitshift_right, bitshift_left
from lib.words64 import extract_byte

from lib.types import (
    Keccak256Hash,
    PedersenHash,
    IntsSequence,
    reconstruct_ints_sequence_list,
    RLPItem,
)
from lib.blockheader_rlp_extractor import decode_transactions_root, decode_receipts_root
from lib.extract_from_rlp import getElement, to_list, extract_data
from lib.trie_proofs import verify_proof

//###################################################
//        STORAGE
//###################################################

// Stores the Starknet state roots.
@storage_var
func _state_roots(block_number: felt) -> (res: PedersenHash) {
}

//###################################################
//        VIEW FUNCTIONS
//###################################################

// Returns the transactions state root of a given block number
@view
func get_block_state_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    block_number: felt
) -> (res: PedersenHash) {
    return _state_roots.read(block_number);
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    return ();
}

//
// Process the transactions state root of a specified block header
// and stores it in the contract's storage.
//
@external
func process_state_root{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(
    l1_header_rlp_len: felt,
    l1_header_rlp: felt*,
    l1_header_rlp_bytes_len: felt,
    path_size_bytes: felt,
    path_len: felt,
    path: felt*,
    transaction_inclusion_proof_sizes_bytes_len: felt,
    transaction_inclusion_proof_sizes_bytes: felt*,
    transaction_inclusion_proof_sizes_words_len: felt,
    transaction_inclusion_proof_sizes_words: felt*,
    transaction_inclusion_proof_concat_len: felt,
    transaction_inclusion_proof_concat: felt*,
    receipt_inclusion_proof_sizes_bytes_len: felt,
    receipt_inclusion_proof_sizes_bytes: felt*,
    receipt_inclusion_proof_sizes_words_len: felt,
    receipt_inclusion_proof_sizes_words: felt*,
    receipt_inclusion_proof_concat_len: felt,
    receipt_inclusion_proof_concat: felt*,
) {
    alloc_locals;
    local block_header: IntsSequence = IntsSequence(l1_header_rlp, l1_header_rlp_len, l1_header_rlp_bytes_len);

    let (local decoded_txns_root: Keccak256Hash) = decode_transactions_root(block_header);
    let (txns_root_words: felt*) = alloc();
    assert txns_root_words[0] = decoded_txns_root.word_1;
    assert txns_root_words[1] = decoded_txns_root.word_2;
    assert txns_root_words[2] = decoded_txns_root.word_3;
    assert txns_root_words[3] = decoded_txns_root.word_4;
    // Form the keccak256 hash of the tree root.
    local txns_root: IntsSequence = IntsSequence(txns_root_words, 4, 32);

    let (local decoded_receipts_root: Keccak256Hash) = decode_receipts_root(block_header);
    let (receipts_root_words: felt*) = alloc();
    assert receipts_root_words[0] = decoded_receipts_root.word_1;
    assert receipts_root_words[1] = decoded_receipts_root.word_2;
    assert receipts_root_words[2] = decoded_receipts_root.word_3;
    assert receipts_root_words[3] = decoded_receipts_root.word_4;
    // Form the keccak256 hash of the tree root.
    local receipts_root: IntsSequence = IntsSequence(receipts_root_words, 4, 32);

    // Format receipt inclusion proof to the expected data type.
    let (local receipt_inclusion_proof: IntsSequence*) = alloc();
    reconstruct_ints_sequence_list(
        receipt_inclusion_proof_concat,
        receipt_inclusion_proof_concat_len,
        receipt_inclusion_proof_sizes_words,
        receipt_inclusion_proof_sizes_words_len,
        receipt_inclusion_proof_sizes_bytes,
        receipt_inclusion_proof_sizes_bytes_len,
        receipt_inclusion_proof,
        0,
        0,
        0,
    );

    local path_arg: IntsSequence = IntsSequence(path, path_len, path_size_bytes);

    let (local receipt_tree_leaf: IntsSequence) = verify_proof(
        path_arg, receipts_root, receipt_inclusion_proof, receipt_inclusion_proof_sizes_bytes_len
    );
    let (local valid_receipt_rlp: IntsSequence) = remove_leading_byte(receipt_tree_leaf);
    let (local receipt_list: RLPItem*, list_len) = to_list(valid_receipt_rlp);

    let (local tx_status: IntsSequence) = extract_data(
        receipt_list[0].dataPosition, receipt_list[0].length, valid_receipt_rlp
    );
    assert tx_status.element[0] = 1;

    let (local event_section: IntsSequence) = extract_data(
        receipt_list[3].dataPosition, receipt_list[3].length, valid_receipt_rlp
    );
    let (local global_root: IntsSequence) = decode_global_root_from_event(event_section);
    let (local block_number: felt) = decode_block_number_from_event(event_section);
    let (local recipient: IntsSequence) = decode_recipient_from_event(event_section);
    // Goerli L2 contract 0xde29d060d45901fb19ed6c6e959eb22d8626708e
    assert recipient.element[0] = 0xde29d060d45901fb;
    assert recipient.element[1] = 0x19ed6c6e959eb22d;
    assert recipient.element[2] = 0x8626708e;

    local state_root_pedersen: PedersenHash = PedersenHash(
        global_root.element[0],
        global_root.element[1],
        global_root.element[2],
        global_root.element[3]
        );

    _state_roots.write(block_number, state_root_pedersen);
    return ();
}

func decode_recipient_from_event{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(event_section: IntsSequence) -> (recipient: IntsSequence) {
    alloc_locals;
    local event_data_section_1 = event_section.element[0];
    local event_data_section_2 = event_section.element[1];
    local event_data_section_3 = event_section.element[2];

    let (local recipient_1_head) = bitshift_left(event_data_section_1, 8 * 3);
    let (local recipient_1_tail) = bitshift_right(event_data_section_2, 8 * 5);
    local first_word = recipient_1_head + recipient_1_tail;

    let (local recipient_2_head) = bitshift_left(event_data_section_2, 8 * 3);
    let (local recipient_2_tail) = bitshift_right(event_data_section_3, 8 * 5);
    local second_word = recipient_2_head + recipient_2_tail;

    let (local recipient_3_head) = bitshift_left(event_data_section_3, 8 * 3);
    let (local third_word) = bitshift_right(recipient_3_head, 8 * 4);

    let (local recipient_elements: felt*) = alloc();
    assert recipient_elements[0] = first_word;
    assert recipient_elements[1] = second_word;
    assert recipient_elements[2] = third_word;
    assert recipient_elements[3] = 0000000000000000;
    local recipient: IntsSequence = IntsSequence(recipient_elements, 4, 32);
    return (recipient,);
}

func decode_global_root_from_event{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(event_section: IntsSequence) -> (global_root: IntsSequence) {
    alloc_locals;
    local event_data_section_1 = event_section.element[18];
    local event_data_section_2 = event_section.element[19];
    local event_data_section_3 = event_section.element[20];
    local event_data_section_4 = event_section.element[21];
    local event_data_section_5 = event_section.element[22];

    let (local global_root_1_head) = bitshift_left(event_data_section_1, 8 * 5);
    let (local global_root_1_tail) = bitshift_right(event_data_section_2, 8 * 3);
    local first_word = global_root_1_head + global_root_1_tail;

    let (local global_root_2_head) = bitshift_left(event_data_section_2, 8 * 5);
    let (local global_root_2_tail) = bitshift_right(event_data_section_3, 8 * 3);
    local second_word = global_root_2_head + global_root_2_tail;

    let (local global_root_3_head) = bitshift_left(event_data_section_3, 8 * 5);
    let (local global_root_3_tail) = bitshift_right(event_data_section_4, 8 * 3);
    local third_word = global_root_3_head + global_root_3_tail;

    let (local global_root_4_head) = bitshift_left(event_data_section_4, 8 * 5);
    let (local global_root_4_tail) = bitshift_right(event_data_section_5, 8 * 3);
    local fourth_word = global_root_4_head + global_root_4_tail;

    let (local global_root_elements: felt*) = alloc();
    assert global_root_elements[0] = first_word;
    assert global_root_elements[1] = second_word;
    assert global_root_elements[2] = third_word;
    assert global_root_elements[3] = fourth_word;
    local global_root: IntsSequence = IntsSequence(global_root_elements, 4, 32);
    return (global_root,);
}

func decode_block_number_from_event{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(event_section: IntsSequence) -> (block_number: felt) {
    alloc_locals;
    local block_number_section = event_section.element[26];
    return (block_number=block_number_section);
}

func decode_selector_from_calldata{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(calldata: IntsSequence) -> (selector: felt) {
    alloc_locals;
    local selector_calldata_section = calldata.element[0];
    let (local selector) = bitshift_right(selector_calldata_section, 8 * 4);
    return (selector,);
}

func decode_block_number_from_calldata{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(calldata: IntsSequence) -> (block_number: felt) {
    alloc_locals;
    local block_number_calldata_section = calldata.element[28];  // 1st half of the word belongs to the state root
    let (local block_number) = bitshift_right(block_number_calldata_section, 8 * 4);
    return (block_number,);
}

func decode_state_root_from_calldata{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(calldata: IntsSequence) -> (state_root: IntsSequence) {
    alloc_locals;
    local state_root_calldata_section_1 = calldata.element[20];  // 2nd half of the word is already the state root
    local state_root_calldata_section_2 = calldata.element[21];  // Whole word
    local state_root_calldata_section_3 = calldata.element[22];  // Whole word
    local state_root_calldata_section_4 = calldata.element[23];  // Whole word
    local state_root_calldata_section_5 = calldata.element[24];  // 1st half of the word belongs to the state root

    let (local word_1_head) = bitshift_left(state_root_calldata_section_1, 32);
    let (local word_1_tail) = bitshift_right(state_root_calldata_section_2, 32);
    local state_root_word_1 = word_1_head + word_1_tail;

    let (local word_2_head) = bitshift_left(state_root_calldata_section_2, 32);
    let (local word_2_tail) = bitshift_right(state_root_calldata_section_3, 32);
    local state_root_word_2 = word_2_head + word_2_tail;

    let (local word_3_head) = bitshift_left(state_root_calldata_section_3, 32);
    let (local word_3_tail) = bitshift_right(state_root_calldata_section_4, 32);
    local state_root_word_3 = word_3_head + word_3_tail;

    let (local word_4_head) = bitshift_left(state_root_calldata_section_4, 32);
    let (local word_4_tail) = bitshift_right(state_root_calldata_section_5, 32);
    local state_root_word_4 = word_4_head + word_4_tail;

    let (local state_root_elements: felt*) = alloc();

    assert state_root_elements[0] = state_root_word_1;
    assert state_root_elements[1] = state_root_word_2;
    assert state_root_elements[2] = state_root_word_3;
    assert state_root_elements[3] = state_root_word_4;

    local state_root: IntsSequence = IntsSequence(state_root_elements, 4, 32);
    return (state_root,);
}

func remove_leading_byte{pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
    input: IntsSequence
) -> (res: IntsSequence) {
    alloc_locals;
    let (local dst: felt*) = alloc();
    let (local dst_len) = remove_leading_byte_rec(input, dst, 0, 0);
    local no_leading_byte: IntsSequence = IntsSequence(dst, dst_len, input.element_size_bytes - 1);
    return (no_leading_byte,);
}

// TODO inspect: for some reason we loose the last nibble
func remove_leading_byte_rec{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(input: IntsSequence, acc: felt*, acc_len: felt, current_index: felt) -> (felt,) {
    alloc_locals;
    if (acc_len == input.element_size_words) {
        return (acc_len,);
    }

    let (local current_word_left_shifted) = bitshift_left(input.element[current_index], 8);

    local new_word;

    if (current_index != input.element_size_words - 1) {
        local next_word_cpy = input.element[current_index + 1];
        let (local next_word_first_byte) = extract_byte(next_word_cpy, 8, 0);
        new_word = current_word_left_shifted + next_word_first_byte;
    } else {
        let (local last_word) = bitshift_right(current_word_left_shifted, 8);
        new_word = last_word;
    }

    assert acc[current_index] = new_word;

    return remove_leading_byte_rec(
        input=input, acc=acc, acc_len=acc_len + 1, current_index=current_index + 1
    );
}
