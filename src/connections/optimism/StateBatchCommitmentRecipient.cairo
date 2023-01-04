%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc

from lib.types import Keccak256Hash, IntsSequence, Address, RLPItem, reconstruct_ints_sequence_list
from lib.blockheader_rlp_extractor import decode_receipts_root
from lib.trie_proofs import verify_proof
from lib.bytes import remove_leading_byte
from lib.extract_from_rlp import to_list

@contract_interface
namespace IEthereumHeadersStore {
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

@storage_var
func _ethereum_headers_store_addr() -> (res: felt) {
}

@storage_var
func _state_commitment_chain_addr() -> (res: Address) {
}

@storage_var
func _batch_roots(batch_index: felt) -> (root: Keccak256Hash) {
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ethereum_headers_store_addr: felt,
    state_commitment_chain_addr: Address
) {
    _ethereum_headers_store_addr.write(ethereum_headers_store_addr);
    _state_commitment_chain_addr.write(state_commitment_chain_addr);
    return ();
}

@external
func verify_batch_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
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
    receipt_inclusion_proof_sizes_bytes_len: felt,
    receipt_inclusion_proof_sizes_bytes: felt*,
    receipt_inclusion_proof_sizes_words_len: felt,
    receipt_inclusion_proof_sizes_words: felt*,
    receipt_inclusion_proof_concat_len: felt,
    receipt_inclusion_proof_concat: felt*,
) {
    alloc_locals;
    let (local headers_store_addr) = _ethereum_headers_store_addr.read();

    // Verify the header inclusion in the headers store's MMR.
    IEthereumHeadersStore.call_mmr_verify_past_proof(
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

    return ();
}

@external
func receive_batch_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
) {
    return ();
}

@external
func relay_batch_root_optimistic{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
) {
    return ();
}

