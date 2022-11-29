%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math_cmp import is_le

from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak

from lib.unsafe_keccak import keccak256
from lib.types import Keccak256Hash, Address, IntsSequence, slice_arr
from lib.blockheader_rlp_extractor import (
    decode_parent_hash,
    decode_state_root,
    decode_transactions_root,
    decode_receipts_root,
    decode_difficulty,
    decode_beneficiary,
    decode_uncles_hash,
    decode_base_fee,
    decode_timestamp,
    decode_gas_used,
)
from lib.bitset import bitset_get
from lib.swap_endianness import swap_endianness_64
from starkware.cairo.common.hash_state import hash_felts
from cairo_mmr.src.mmr import append, get_root, get_last_pos, verify_proof as mmr_verify_proof

// Temporary auth var for authenticating mocked L1 handlers
@storage_var
func _l1_messages_origin() -> (res: felt) {
}

@storage_var
func _commitments_latest_l1_block() -> (res: felt) {
}

@storage_var
func _commitments_block_parent_hash(block_number: felt) -> (res: Keccak256Hash) {
}

//###################################################
//                   VIEW FUNCTIONS
//###################################################

@view
func get_commitments_parent_hash{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    block_number: felt
) -> (res: Keccak256Hash) {
    return _commitments_block_parent_hash.read(block_number);
}

@view
func get_latest_commitments_l1_block{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
}() -> (res: felt) {
    return _commitments_latest_l1_block.read();
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    l1_messages_origin: felt
) {
    _l1_messages_origin.write(l1_messages_origin);
    return ();
}

@external
func receive_from_l1{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    parent_hash_len: felt, parent_hash: felt*, block_number: felt
) {
    alloc_locals;

    // Auth
    let (caller) = get_caller_address();
    let (l1_messages_origin) = _l1_messages_origin.read();
    assert caller = l1_messages_origin;

    // Save block's parenthash
    local hash: Keccak256Hash = Keccak256Hash(
        word_1=parent_hash[0],
        word_2=parent_hash[1],
        word_3=parent_hash[2],
        word_4=parent_hash[3]
        );
    _commitments_block_parent_hash.write(block_number, hash);

    let (local current_latest) = _commitments_latest_l1_block.read();
    local update_latest = is_le(current_latest, block_number);

    if (update_latest == 1) {
        _commitments_latest_l1_block.write(block_number);
        return ();
    }
    return ();
}

@external
func process_block{
    pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(
    reference_block_number: felt,
    reference_proof_leaf_index: felt,
    reference_proof_leaf_value: felt,
    reference_proof_len: felt,
    reference_proof: felt*,
    reference_proof_peaks_len: felt,
    reference_proof_peaks: felt*,
    reference_header_rlp_bytes_len: felt,
    reference_header_rlp_len: felt,
    reference_header_rlp: felt*,
    block_header_rlp_bytes_len: felt,
    block_header_rlp_len: felt,
    block_header_rlp: felt*,
    mmr_peaks_len: felt,
    mmr_peaks: felt*,
) {
    alloc_locals;

    mmr_verify_proof(
        index=reference_proof_leaf_index,
        value=reference_proof_leaf_value,
        proof_len=reference_proof_len,
        proof=reference_proof,
        peaks_len=reference_proof_peaks_len,
        peaks=reference_proof_peaks,
    );

    local rlp: IntsSequence = IntsSequence(reference_header_rlp, reference_header_rlp_len, reference_header_rlp_bytes_len);
    let (local child_block_parent_hash: Keccak256Hash) = decode_parent_hash(rlp);
    validate_provided_header_rlp(
        child_block_parent_hash, block_header_rlp_bytes_len, block_header_rlp_len, block_header_rlp
    );

    let (pedersen_hash_reference_block) = hash_felts{hash_ptr=pedersen_ptr}(
        data=reference_header_rlp, length=reference_header_rlp_len
    );

    assert pedersen_hash_reference_block = reference_proof_leaf_value;

    let (pedersen_hash) = hash_felts{hash_ptr=pedersen_ptr}(
        data=block_header_rlp, length=block_header_rlp_len
    );

    append(elem=pedersen_hash, peaks_len=mmr_peaks_len, peaks=mmr_peaks);
    return ();
}

@external
func process_block_from_message{
    pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(
    reference_block_number: felt,
    block_header_rlp_bytes_len: felt,
    block_header_rlp_len: felt,
    block_header_rlp: felt*,
    mmr_peaks_len: felt,
    mmr_peaks: felt*,
) {
    alloc_locals;

    let (local child_block_parent_hash: Keccak256Hash) = _commitments_block_parent_hash.read(
        reference_block_number
    );

    validate_provided_header_rlp(
        child_block_parent_hash, block_header_rlp_bytes_len, block_header_rlp_len, block_header_rlp
    );

    let (pedersen_hash) = hash_felts{hash_ptr=pedersen_ptr}(
        data=block_header_rlp, length=block_header_rlp_len
    );

    append(elem=pedersen_hash, peaks_len=mmr_peaks_len, peaks=mmr_peaks);
    return ();
}

// @external
// func process_till_block{
//     pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
// }(
//     start_block_number: felt,
//     block_headers_lens_bytes_len: felt,
//     block_headers_lens_bytes: felt*,
//     block_headers_lens_words_len: felt,
//     block_headers_lens_words: felt*,
//     block_headers_concat_len: felt,
//     block_headers_concat: felt*,
// ) {
//     alloc_locals;
//     assert block_headers_lens_bytes_len = block_headers_lens_words_len;

// let (local parent_hash: Keccak256Hash) = _commitments_block_parent_hash.read(
//         block_number=start_block_number
//     );

// let (local keccak_ptr: felt*) = alloc();
//     let keccak_ptr_start = keccak_ptr;

// let (
//         local save_block_number: felt, local save_parent_hash: Keccak256Hash
//     ) = process_till_block_rec{keccak_ptr=keccak_ptr}(
//         start_block_number,
//         parent_hash,
//         block_headers_lens_bytes_len,
//         block_headers_lens_bytes,
//         block_headers_lens_words_len,
//         block_headers_lens_words,
//         block_headers_concat_len,
//         block_headers_concat,
//         0,
//         0,
//     );
//     // finalize_keccak(keccak_ptr_start, keccak_ptr)

// // _commitments_block_parent_hash.write(save_block_number, save_parent_hash);

// let (local last_header: felt*) = alloc();
//     slice_arr(
//         block_headers_concat_len - block_headers_lens_words[block_headers_lens_words_len - 1],
//         block_headers_lens_words[block_headers_lens_words_len - 1],
//         block_headers_concat,
//         block_headers_concat_len,
//         last_header,
//         0,
//         0,
//     );

// // TODO: fix me (pass dynamically as function argument):
//     let (local peaks: felt*) = alloc();

// process_block(
//         save_block_number - 1,
//         block_headers_lens_bytes[block_headers_lens_bytes_len - 1],
//         block_headers_lens_words[block_headers_lens_words_len - 1],
//         last_header,
//         0,
//         peaks,
//     );
//     return ();
// }

// func process_till_block_rec{
//     keccak_ptr: felt*,
//     pedersen_ptr: HashBuiltin*,
//     syscall_ptr: felt*,
//     bitwise_ptr: BitwiseBuiltin*,
//     range_check_ptr,
// }(
//     start_block_number: felt,
//     current_parent_hash: Keccak256Hash,
//     block_headers_lens_bytes_len: felt,
//     block_headers_lens_bytes: felt*,
//     block_headers_lens_words_len: felt,
//     block_headers_lens_words: felt*,
//     block_headers_concat_len: felt,
//     block_headers_concat: felt*,
//     current_index: felt,
//     offset: felt,
// ) -> (save_block_number: felt, save_parent_hash: Keccak256Hash) {
//     alloc_locals;
//     // Skips last header as this will be processed by process_block
//     if (current_index == block_headers_lens_bytes_len - 1) {
//         return (start_block_number - current_index, current_parent_hash);
//     }

// let (local current_header: felt*) = alloc();
//     let (offset_updated) = slice_arr(
//         offset,
//         block_headers_lens_words[current_index],
//         block_headers_concat,
//         block_headers_concat_len,
//         current_header,
//         0,
//         0,
//     );

// local bitwise_ptr: BitwiseBuiltin* = bitwise_ptr;

// local current_header_ints_sequence: IntsSequence = IntsSequence(current_header, block_headers_lens_words[current_index], block_headers_lens_bytes[current_index]);

// let (provided_rlp_hash) = keccak256{keccak_ptr=keccak_ptr}(current_header_ints_sequence);

// assert current_parent_hash.word_1 = provided_rlp_hash[0];
//     assert current_parent_hash.word_2 = provided_rlp_hash[1];
//     assert current_parent_hash.word_3 = provided_rlp_hash[2];
//     assert current_parent_hash.word_4 = provided_rlp_hash[3];

// local current_header_rlp: IntsSequence = IntsSequence(current_header, block_headers_lens_words[current_index], block_headers_lens_bytes[current_index]);
//     let (local parent_hash: Keccak256Hash) = decode_parent_hash(current_header_rlp);

// return process_till_block_rec(
//         start_block_number,
//         parent_hash,
//         block_headers_lens_bytes_len,
//         block_headers_lens_bytes,
//         block_headers_lens_words_len,
//         block_headers_lens_words,
//         block_headers_concat_len,
//         block_headers_concat,
//         current_index + 1,
//         offset_updated,
//     );
// }

func validate_provided_header_rlp{
    pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(
    child_block_parent_hash: Keccak256Hash,
    block_header_rlp_bytes_len: felt,
    block_header_rlp_len: felt,
    block_header_rlp: felt*,
) {
    alloc_locals;
    local bitwise_ptr: BitwiseBuiltin* = bitwise_ptr;
    let (local keccak_ptr: felt*) = alloc();
    let keccak_ptr_start = keccak_ptr;

    local header_ints_sequence: IntsSequence = IntsSequence(block_header_rlp, block_header_rlp_len, block_header_rlp_bytes_len);

    let (provided_rlp_hash) = keccak256{keccak_ptr=keccak_ptr}(header_ints_sequence);
    // finalize_keccak(keccak_ptr_start, keccak_ptr)

    // Ensure child block parenthash matches provided rlp hash
    assert child_block_parent_hash.word_1 = provided_rlp_hash[0];
    assert child_block_parent_hash.word_2 = provided_rlp_hash[1];
    assert child_block_parent_hash.word_3 = provided_rlp_hash[2];
    assert child_block_parent_hash.word_4 = provided_rlp_hash[3];
    return ();
}
