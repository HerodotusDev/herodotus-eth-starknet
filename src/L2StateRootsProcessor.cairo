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
    IntsSequence,
    StorageSlot,
    reconstruct_ints_sequence_list,
    RLPItem,
)
from lib.blockheader_rlp_extractor import decode_transactions_root
from lib.extract_from_rlp import getElement, to_list, extract_data
from lib.trie_proofs import verify_proof

//###################################################
//        CONTRACTS INTERFACES
//###################################################

@contract_interface
namespace IL1HeadersStore {
    func call_mmr_verify_past_proof(
        index: felt,
        value: felt,
        proof_len: felt,
        proof: felt*,
        peaks_len: felt,
        peaks: felt*,
        inclusion_tx_hash: felt,
        mmr_pos: felt,
    ) {
    }
}

//###################################################
//        STORAGE
//###################################################

//
// Stores the L1 headers store contract address.
//
@storage_var
func _l1_headers_store_addr() -> (res: felt) {
}

// Stores the Starknet state roots.
@storage_var
func _state_roots(block_number: felt) -> (res: Keccak256Hash) {
}

//###################################################
//        VIEW FUNCTIONS
//###################################################

// Returns the transactions state root of a given block number
@view
func get_block_state_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    block_number: felt
) -> (res: Keccak256Hash) {
    return _state_roots.read(block_number);
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    l1_headers_store_addr: felt
) {
    _l1_headers_store_addr.write(l1_headers_store_addr);
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
    mmr_inclusion_header_leaf_index: felt,
    mmr_inclusion_header_leaf_value: felt,
    mmr_inclusion_header_proof_len: felt,
    mmr_inclusion_header_proof: felt*,
    mmr_inclusion_header_peaks_len: felt,
    mmr_inclusion_header_peaks: felt*,
    mmr_inclusion_header_inclusion_tx_hash: felt,
    mmr_inclusion_header_pos: felt,
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
    transaction_inclusion_proofs_concat_len: felt,
    transaction_inclusion_proofs_concat: felt*,
) {
    alloc_locals;
    let (local headers_store_addr) = _l1_headers_store_addr.read();

    // Verify the header inclusion in the headers store's MMR.
    IL1HeadersStore.call_mmr_verify_past_proof(
        contract_address=headers_store_addr,
        index=mmr_inclusion_header_leaf_index,
        value=mmr_inclusion_header_leaf_value,
        proof_len=mmr_inclusion_header_proof_len,
        proof=mmr_inclusion_header_proof,
        peaks_len=mmr_inclusion_header_peaks_len,
        peaks=mmr_inclusion_header_peaks,
        inclusion_tx_hash=mmr_inclusion_header_inclusion_tx_hash,
        mmr_pos=mmr_inclusion_header_pos,
    );

    local block_header: IntsSequence = IntsSequence(l1_header_rlp, l1_header_rlp_len, l1_header_rlp_bytes_len);
    let (local decoded_root: Keccak256Hash) = decode_transactions_root(block_header);

    let (root_words: felt*) = alloc();
    assert root_words[0] = decoded_root.word_1;
    assert root_words[1] = decoded_root.word_2;
    assert root_words[2] = decoded_root.word_3;
    assert root_words[3] = decoded_root.word_4;

    // Form the keccak256 hash of the tree root.
    local txns_root: IntsSequence = IntsSequence(root_words, 4, 32);

    // Format the proof to the expected data type.
    let (local transaction_inclusion_proof: IntsSequence*) = alloc();
    reconstruct_ints_sequence_list(
        transaction_inclusion_proofs_concat,
        transaction_inclusion_proofs_concat_len,
        transaction_inclusion_proof_sizes_words,
        transaction_inclusion_proof_sizes_words_len,
        transaction_inclusion_proof_sizes_bytes,
        transaction_inclusion_proof_sizes_bytes_len,
        transaction_inclusion_proof,
        0,
        0,
        0,
    );

    local path_arg: IntsSequence = IntsSequence(path, path_len, path_size_bytes);

    let (local tx_tree_leaf: IntsSequence) = verify_proof(
        path_arg,
        txns_root,
        transaction_inclusion_proof,
        transaction_inclusion_proof_sizes_bytes_len,
    );

    let (local valid_rlp: IntsSequence) = remove_leading_byte(tx_tree_leaf);

    local valid_rlp_size_words = valid_rlp.element_size_words;
    local valid_rlp_size_bytes = valid_rlp.element_size_bytes;
    local valid_rlp_values: felt* = valid_rlp.element;

    // %{  
    //     from utils.types import Data, IntsSequence 
    //     leaf_values = memory.get_range(ids.valid_rlp_values, ids.valid_rlp_size_words)
    //     print("Leaf values hex: ", list(map(lambda x: hex(x), leaf_values)))
    //     leaf = Data.from_ints(IntsSequence(leaf_values, ids.valid_rlp_size_bytes))
    //     print('leaf updated', leaf.to_hex())
    // %}

    let (local list: RLPItem*, list_len) = to_list(valid_rlp);

    let (local calldata: IntsSequence) = extract_data(list[7].dataPosition, list[7].length, valid_rlp);
    
    local calldata_size_words = calldata.element_size_words;
    local calldata_size_bytes = calldata.element_size_bytes;
    local calldata_elements: felt* = calldata.element;
    %{
        from utils.types import Data, IntsSequence 
        calldata_values = memory.get_range(ids.calldata_elements, ids.calldata_size_words)
        print("Decoded calldata: ", calldata_values)
    %}

    local state_root_calldata_section_1 = calldata_elements[20]; // 2nd half of the word is already the state root
    local state_root_calldata_section_2 = calldata_elements[21]; // Whole word
    local state_root_calldata_section_3 = calldata_elements[22]; // Whole word
    local state_root_calldata_section_4 = calldata_elements[23]; // Whole word
    local state_root_calldata_section_5 = calldata_elements[24]; // 1st half of the worl belongs to the state root

    %{
        from utils.types import Data, IntsSequence 
        state_root_words = [ids.starknet_state_root_word_1, ids.starknet_state_root_word_2, ids.starknet_state_root_word_3, ids.starknet_state_root_word_4] 
        state_root = Data.from_ints(IntsSequence(state_root_words, 32))
        print("State root: ", state_root)
    %}

    // local tx_type = res.element[0];
    // %{ print('Tx type', ids.tx_type) %}
    // // let starknet_block_number = tx_calldata[0];
    // // let starknet_state_root = tx_calldata[1];

    // // TODO: use an MMR instead (?)
    // // Store the state root of the block into this contract storage.
    // // _state_roots.write(starknet_block_number, starknet_state_root);
    return ();
}

func remove_leading_byte{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(input: IntsSequence) -> (res: IntsSequence) {
    alloc_locals;
    let (local dst: felt*) = alloc();
    let (local dst_len) = remove_leading_byte_rec(input, dst, 0, 0);
    local no_leading_byte: IntsSequence = IntsSequence(dst, dst_len, input.element_size_bytes - 1);
    return (no_leading_byte, );
}

// TODO inspect: for some reason we loose the last nibble
func remove_leading_byte_rec{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(  
    input: IntsSequence,
    acc: felt*,
    acc_len: felt,
    current_index: felt) -> (felt) {
    alloc_locals;
    if(acc_len == input.element_size_words) {
        return(acc_len, );
    }

    let (local current_word_left_shifted) = bitshift_left(input.element[current_index], 8);

    local new_word;

    if(current_index != input.element_size_words - 1) {
        local next_word_cpy = input.element[current_index + 1];
        let (local next_word_first_byte) = extract_byte(next_word_cpy, 8, 0);
        new_word = current_word_left_shifted + next_word_first_byte;
    } else {
        let (local last_word) = bitshift_right(current_word_left_shifted, 8);
        new_word = last_word;
    }

    assert acc[current_index] = new_word;

    return remove_leading_byte_rec(
        input=input,
        acc=acc,
        acc_len=acc_len + 1,
        current_index=current_index + 1);
}



