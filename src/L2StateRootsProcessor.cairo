%lang starknet
%builtins pedersen range_check bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc

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
    %{
        print("verifying mmr")
    %}

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

        %{
        print("verified mmr")
    %}

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

    %{ print('verifying the mpt proof...') %}
    let (local tx_info_rlp: IntsSequence) = verify_proof(
        path_arg,
        txns_root,
        transaction_inclusion_proof,
        transaction_inclusion_proof_sizes_bytes_len,
    );

    %{ print('verified the mpt proof...') %}

    local leaf_size_bytes: felt = tx_info_rlp.element_size_bytes;
    local leaf_size_words: felt = tx_info_rlp.element_size_words;
    local leaf_values: felt* = tx_info_rlp.element;

    %{  
        from utils.types import Data, IntsSequence 
        leaf_values = memory.get_range(ids.leaf_values, ids.leaf_size_words)
        leaf = Data.from_ints(IntsSequence(leaf_values, ids.leaf_size_bytes))
        print('leaf ', leaf.to_hex())
    %}


    // Extract and decode calldata from tx_info_rlp.
    // TODO: find a way to extract the calldata elements correctly
    // let (tx_calldata: RLPItem) = getElement{range_check_ptr=range_check_ptr}(tx_info_rlp, 4);
    let (local list: RLPItem*, list_len) = to_list(tx_info_rlp);
    %{ print('items len', ids.list_len) %}

    let (local res: IntsSequence) = extract_data(list[0].dataPosition, list[0].length, tx_info_rlp);
    local tx_type = res.element[0];
    %{ print('Tx type', ids.tx_type) %}
    // let starknet_block_number = tx_calldata[0];
    // let starknet_state_root = tx_calldata[1];

    // TODO: use an MMR instead (?)
    // Store the state root of the block into this contract storage.
    // _state_roots.write(starknet_block_number, starknet_state_root);
    return ();
}
