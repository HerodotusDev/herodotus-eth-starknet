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
from lib.extract_from_rlp import getElement
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
    l1_inclusion_header_leaf_index: felt,
    l1_inclusion_header_leaf_value: felt,
    l1_inclusion_header_proof_len: felt,
    l1_inclusion_header_proof: felt*,
    l1_inclusion_header_peaks_len: felt,
    l1_inclusion_header_peaks: felt*,
    l1_inclusion_header_inclusion_tx_hash: felt,
    l1_inclusion_header_mmr_pos: felt,
    l1_inclusion_header_rlp_len: felt,
    l1_inclusion_header_rlp: felt*,
    l1_inclusion_header_rlp_bytes_len: felt,
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
        index=l1_inclusion_header_leaf_index,
        value=l1_inclusion_header_leaf_value,
        proof_len=l1_inclusion_header_proof_len,
        proof=l1_inclusion_header_proof,
        peaks_len=l1_inclusion_header_peaks_len,
        peaks=l1_inclusion_header_peaks,
        inclusion_tx_hash=l1_inclusion_header_inclusion_tx_hash,
        mmr_pos=l1_inclusion_header_mmr_pos,
    );

    local input: IntsSequence = IntsSequence(l1_inclusion_header_rlp, l1_inclusion_header_rlp_len, l1_inclusion_header_rlp_bytes_len);
    let (local transactions_root: Keccak256Hash) = decode_transactions_root(input);
    let (root: felt*) = alloc();
    assert root[0] = transactions_root.word_1;
    assert root[1] = transactions_root.word_2;
    assert root[2] = transactions_root.word_3;
    assert root[3] = transactions_root.word_4;

    // Form the keccak256 hash of the tree root.
    local state_root: IntsSequence = IntsSequence(root, 4, 32);
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
    local root_hash_size_bytes;
    local root_hash_len;
    let (root_hash: felt*) = alloc();
    %{
        # This hint is a temporary substitute, it can be replaced by the actual txns root once we've got the correct mocked daata.

        from utils.types import Data
        txns_root = Data.from_hex('0x199c2e6b850bcc9beaea25bf1bacc5741a7aad954d28af9b23f4b53f5404937b')
        txns_root_values = txns_root.to_ints().values
        segments.write_arg(ids.root_hash, txns_root_values)
        ids.root_hash_len = len(txns_root_values)
        ids.root_hash_size_bytes = txns_root.to_ints().length
    %}
    local root_hash_arg: IntsSequence = IntsSequence(root_hash, root_hash_len, root_hash_size_bytes);

    let (local tx_info_rlp: IntsSequence) = verify_proof(
        path_arg,
        root_hash_arg,
        transaction_inclusion_proof,
        transaction_inclusion_proof_sizes_bytes_len,
    );
    // Extract and decode calldata from tx_info_rlp.
    // TODO: find a way to extract the calldata elements correctly
    let (tx_calldata: RLPItem) = getElement{range_check_ptr=range_check_ptr}(tx_info_rlp, 4);
    // let starknet_block_number = tx_calldata[0];
    // let starknet_state_root = tx_calldata[1];

    // TODO: use an MMR instead (?)
    // Store the state root of the block into this contract storage.
    // _state_roots.write(starknet_block_number, starknet_state_root);
    return ();
}
