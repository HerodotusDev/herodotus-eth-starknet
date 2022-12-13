%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.starknet.common.syscalls import get_caller_address, get_tx_info
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math_cmp import is_le

from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak

from lib.unsafe_keccak import keccak256
from lib.types import Keccak256Hash, Address, IntsSequence, slice_arr
from lib.blockheader_rlp_extractor import decode_parent_hash, decode_block_number
from lib.bitset import bitset_get
from lib.swap_endianness import swap_endianness_64
from starkware.cairo.common.hash_state import hash_felts
from cairo_mmr.src.historical_mmr import (
    append as mmr_append,
    verify_past_proof as mmr_verify_past_proof,
    get_last_pos as mmr_get_last_pos,
    get_inclusion_tx_hash_to_root as mmr_get_inclusion_tx_hash_to_root,
)

@event
func accumulator_update(
    pedersen_hash: felt,
    processed_block_number: felt,
    keccak_hash_word_1: felt,
    keccak_hash_word_2: felt,
    keccak_hash_word_3: felt,
    keccak_hash_word_4: felt,
) {
}

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
    inclusion_tx_hash: felt,
    mmr_pos: felt,
) {
    alloc_locals;

    validate_parent_block_and_proof_integrity(
        reference_proof_leaf_index,
        reference_proof_leaf_value,
        reference_proof_len,
        reference_proof,
        reference_proof_peaks_len,
        reference_proof_peaks,
        reference_header_rlp_bytes_len,
        reference_header_rlp_len,
        reference_header_rlp,
        block_header_rlp_bytes_len,
        block_header_rlp_len,
        block_header_rlp,
        inclusion_tx_hash,
        mmr_pos,
    );

    update_mmr(
        block_header_rlp_bytes_len, block_header_rlp_len, block_header_rlp, mmr_peaks_len, mmr_peaks
    );
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

    update_mmr(
        block_header_rlp_bytes_len, block_header_rlp_len, block_header_rlp, mmr_peaks_len, mmr_peaks
    );
    return ();
}

@external
func process_till_block{
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
    block_headers_lens_bytes_len: felt,
    block_headers_lens_bytes: felt*,
    block_headers_lens_words_len: felt,
    block_headers_lens_words: felt*,
    block_headers_concat_len: felt,
    block_headers_concat: felt*,
    mmr_peaks_lens_len: felt,
    mmr_peaks_lens: felt*,
    mmr_peaks_concat_len: felt,
    mmr_peaks_concat: felt*,
    inclusion_tx_hash: felt,
    mmr_pos: felt,
) {
    alloc_locals;
    assert block_headers_lens_bytes_len = block_headers_lens_words_len;

    // Verify the reference block proof and check its parent block
    validate_parent_block_and_proof_integrity(
        reference_proof_leaf_index,
        reference_proof_leaf_value,
        reference_proof_len,
        reference_proof,
        reference_proof_peaks_len,
        reference_proof_peaks,
        reference_header_rlp_bytes_len,
        reference_header_rlp_len,
        reference_header_rlp,
        block_headers_lens_bytes[0],
        block_headers_lens_words[0],
        block_headers_concat,
        inclusion_tx_hash,
        mmr_pos,
    );

    let (local current_peaks: felt*) = alloc();
    let (local updated_peaks_offset) = slice_arr(
        0, mmr_peaks_lens[0], mmr_peaks_concat, mmr_peaks_concat_len, current_peaks, 0, 0
    );

    // Add the first block
    update_mmr(
        block_headers_lens_bytes[0],
        block_headers_lens_words[0],
        block_headers_concat,
        mmr_peaks_lens[0],
        current_peaks,
    );

    // Process the remaining blocks and recursively update the MMR tree.
    process_till_block_rec(
        block_headers_lens_bytes_len,
        block_headers_lens_bytes,
        block_headers_lens_words_len,
        block_headers_lens_words,
        block_headers_concat_len,
        block_headers_concat,
        mmr_peaks_lens_len,
        mmr_peaks_lens,
        mmr_peaks_concat_len,
        mmr_peaks_concat,
        0,
        0,
        0,
        updated_peaks_offset,
    );
    return ();
}

@external
func get_mmr_last_pos{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    let (last_pos) = mmr_get_last_pos();
    return (res=last_pos);
}

@external
func call_mmr_verify_past_proof{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    index: felt,
    value: felt,
    proof_len: felt,
    proof: felt*,
    peaks_len: felt,
    peaks: felt*,
    inclusion_tx_hash: felt,
    mmr_pos: felt,
) {
    mmr_verify_past_proof(
        index, value, proof_len, proof, peaks_len, peaks, inclusion_tx_hash, mmr_pos
    );
    return ();
}

@external
func call_get_inclusion_tx_hash_to_root{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
}(tx_hash: felt) -> (res: felt) {
    let (res) = mmr_get_inclusion_tx_hash_to_root(tx_hash);
    return (res=res);
}

func validate_parent_block{
    pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(
    child_header_rlp_bytes_len: felt,
    child_header_rlp_len: felt,
    child_header_rlp: felt*,
    parent_header_rlp_bytes_len: felt,
    parent_header_rlp_len: felt,
    parent_header_rlp: felt*,
) {
    alloc_locals;

    local child_rlp: IntsSequence = IntsSequence(child_header_rlp, child_header_rlp_len, child_header_rlp_bytes_len);
    let (local child_block_parent_hash: Keccak256Hash) = decode_parent_hash(child_rlp);

    local parent_rlp: IntsSequence = IntsSequence(parent_header_rlp, parent_header_rlp_len, parent_header_rlp_bytes_len);

    validate_provided_header_rlp(
        child_block_parent_hash,
        parent_header_rlp_bytes_len,
        parent_header_rlp_len,
        parent_header_rlp,
    );

    return ();
}

func validate_parent_block_and_proof_integrity{
    pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(
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
    inclusion_tx_hash: felt,
    mmr_pos: felt,
) {
    alloc_locals;

    call_mmr_verify_past_proof(
        index=reference_proof_leaf_index,
        value=reference_proof_leaf_value,
        proof_len=reference_proof_len,
        proof=reference_proof,
        peaks_len=reference_proof_peaks_len,
        peaks=reference_proof_peaks,
        inclusion_tx_hash=inclusion_tx_hash,
        mmr_pos=mmr_pos,
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
    return ();
}

func update_mmr{
    pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(
    block_header_rlp_bytes_len: felt,
    block_header_rlp_len: felt,
    block_header_rlp: felt*,
    mmr_peaks_len: felt,
    mmr_peaks: felt*,
) {
    alloc_locals;

    let (pedersen_hash) = hash_felts{hash_ptr=pedersen_ptr}(
        data=block_header_rlp, length=block_header_rlp_len
    );
    let (info) = get_tx_info();
    mmr_append(
        elem=pedersen_hash, peaks_len=mmr_peaks_len, peaks=mmr_peaks, tx_hash=info.transaction_hash
    );
    let (local keccak_ptr: felt*) = alloc();
    let keccak_ptr_start = keccak_ptr;

    local header_ints_sequence: IntsSequence = IntsSequence(block_header_rlp, block_header_rlp_len, block_header_rlp_bytes_len);
    let (local processed_block_number: felt) = decode_block_number(header_ints_sequence);

    let (local keccak_hash) = keccak256{keccak_ptr=keccak_ptr}(header_ints_sequence);

    local word_1 = keccak_hash[0];
    local word_2 = keccak_hash[1];
    local word_3 = keccak_hash[2];
    local word_4 = keccak_hash[3];

    // Emit the update event
    accumulator_update.emit(pedersen_hash, processed_block_number, word_1, word_2, word_3, word_4);
    return ();
}

func process_till_block_rec{
    pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(
    block_headers_lens_bytes_len: felt,
    block_headers_lens_bytes: felt*,
    block_headers_lens_words_len: felt,
    block_headers_lens_words: felt*,
    block_headers_concat_len: felt,
    block_headers_concat: felt*,
    mmr_peaks_lens_len: felt,
    mmr_peaks_lens: felt*,
    mmr_peaks_concat_len: felt,
    mmr_peaks_concat: felt*,
    header_index: felt,
    child_offset: felt,
    parent_offset: felt,
    peaks_offset: felt,
) {
    alloc_locals;

    if (header_index == block_headers_lens_bytes_len - 1) {
        return ();
    }

    let (local current_child: felt*) = alloc();
    let (local updated_child_offset) = slice_arr(
        child_offset,
        block_headers_lens_words[header_index],
        block_headers_concat,
        block_headers_concat_len,
        current_child,
        0,
        0,
    );

    let (local current_parent: felt*) = alloc();
    let (local updated_parent_offset) = slice_arr(
        updated_child_offset,
        block_headers_lens_words[header_index + 1],
        block_headers_concat,
        block_headers_concat_len,
        current_parent,
        0,
        0,
    );

    validate_parent_block(
        child_header_rlp_bytes_len=block_headers_lens_bytes[header_index],
        child_header_rlp_len=block_headers_lens_words[header_index],
        child_header_rlp=current_child,
        parent_header_rlp_bytes_len=block_headers_lens_bytes[header_index + 1],
        parent_header_rlp_len=block_headers_lens_words[header_index + 1],
        parent_header_rlp=current_parent,
    );

    let (local current_peaks: felt*) = alloc();
    let (local updated_peaks_offset) = slice_arr(
        peaks_offset,
        mmr_peaks_lens[peaks_offset],
        mmr_peaks_concat,
        mmr_peaks_concat_len,
        current_peaks,
        0,
        0,
    );
    update_mmr(
        block_headers_lens_bytes[header_index + 1],
        block_headers_lens_words[header_index + 1],
        current_parent,
        mmr_peaks_lens[peaks_offset],
        current_peaks,
    );

    return process_till_block_rec(
        block_headers_lens_bytes_len,
        block_headers_lens_bytes,
        block_headers_lens_words_len,
        block_headers_lens_words,
        block_headers_concat_len,
        block_headers_concat,
        mmr_peaks_lens_len,
        mmr_peaks_lens,
        mmr_peaks_concat_len,
        mmr_peaks_concat,
        header_index + 1,
        updated_child_offset,
        updated_parent_offset,
        updated_peaks_offset,
    );
}

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
