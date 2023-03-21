%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_not_zero
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.hash_state import hash_felts

from lib.types import (
    Keccak256Hash,
    StorageSlot,
    Address,
    IntsSequence,
    RLPItem,
    reconstruct_ints_sequence_list,
)

from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from lib.blockheader_rlp_extractor import decode_state_root, decode_block_number
from lib.unsafe_keccak import keccak256
from lib.trie_proofs import verify_proof
from lib.ints_to_uint256 import ints_to_uint256
from lib.bitset import bitset_get
from lib.extract_from_rlp import to_list, extract_list_values, extractElement, extract_data
from lib.address import address_words64_to_160bit
from lib.swap_endianness import swap_endianness_64

@contract_interface
namespace IL1HeadersStore {
    func call_mmr_verify_proof(
        index: felt,
        value: felt,
        proof_len: felt,
        proof: felt*,
        peaks_len: felt,
        peaks: felt*,
        pos: felt,
        root: felt,
    ) {
    }

    func get_tree_size_to_root(tree_size: felt) -> (res: felt) {
    }
}

//
// Stores the L1 headers store contract address.
//
@storage_var
func _l1_headers_store_addr() -> (res: felt) {
}

//
// @dev
// Stores the storage hash for a verified account at a specified block number.
// @param account: The address of the account whose storage hash should be stored.
// @param block: The block number at which the storage hash was verified.
// @return res: The storage hash for the verified account at the specified block number.
//
@storage_var
func _verified_account_storage_hash(account: felt, block: felt) -> (res: Keccak256Hash) {
}

//
// @dev Stores the code hash for a verified account at a specified block number.
//
// @param account: The address of the account whose code hash should be stored.
// @param block: The block number at which the code hash was verified.
// @return res: The code hash for the verified account at the specified block number.
//
@storage_var
func _verified_account_code_hash(account: felt, block: felt) -> (res: Keccak256Hash) {
}

//
// @dev Stores the balance for a verified account at a specified block number.
// @param account: The address of the account whose balance should be stored.
// @param block: The block number at which the balance was verified.
// @return res: The balance for the verified account at the specified block number.
//
@storage_var
func _verified_account_balance(account: felt, block: felt) -> (res: felt) {
}

//
// @dev Stores the nonce for a verified account at a specified block number.
// @param account: The address of the account whose nonce should be stored.
// @param block: The block number at which the nonce was verified.
// @return res: The nonce for the verified account at the specified block number.
//
@storage_var
func _verified_account_nonce(account: felt, block: felt) -> (res: felt) {
}

//
// @dev Gets the address of the L1 headers store contract.
// @return res: The address of the L1 headers store contract.
//
@view
func get_l1_headers_store_addr{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ) -> (res: felt) {
    return _l1_headers_store_addr.read();
}

//
// @dev Gets the storage root hash for a verified account at a specified block number.
//
// @param account_160: The address of the account whose storage root hash should be retrieved.
// @param block: The block number at which the storage root hash was verified.
// @return res: The storage root hash for the verified account at the specified block number.
//
@view
func get_verified_account_storage_hash{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
}(account_160: felt, block: felt) -> (res: Keccak256Hash) {
    return _verified_account_storage_hash.read(account_160, block);
}

//
// @dev
// Gets the code hash for a verified account at a specified block number.
//
// @param account_160: The address of the account whose code hash should be retrieved.
// @param block: The block number at which the code hash was verified.
// @return res: The code hash for the verified account at the specified block number.
//
@view
func get_verified_account_code_hash{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
}(account_160: felt, block: felt) -> (res: Keccak256Hash) {
    return _verified_account_code_hash.read(account_160, block);
}

//
// @dev Gets the balance for a verified account at a specified block number.
// @param account_160: The address of the account whose balance should be retrieved.
// @param block: The block number at which the balance was verified.
// @return res: The balance for the verified account at the specified block number.
//
@view
func get_verified_account_balance{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    account_160: felt, block: felt
) -> (res: felt) {
    return _verified_account_balance.read(account_160, block);
}

//
// @dev Gets the nonce for a verified account at a specified block number.
// @param account_160: The address of the account whose nonce should be retrieved.
// @param block: The block number at which the nonce was verified.
// @return res: The nonce for the verified account at the specified block number.
//
@view
func get_verified_account_nonce{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    account_160: felt, block: felt
) -> (res: felt) {
    return _verified_account_nonce.read(account_160, block);
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    l1_headers_store_addr: felt
) {
    _l1_headers_store_addr.write(l1_headers_store_addr);
    return ();
}

//
// Proves the existence and state of an account at a specified block number.
// @param options_set: A felt in the range of 0 to 16 that specifies which elements of the decoded proof should be saved in state.
// Bit 0 indicates whether the storage hash should be saved,
// bit 1 indicates whether the code hash should be saved,
// bit 2 indicates whether the nonce should be saved,
// and bit 3 indicates whether the balance should be saved.
// @param block_number: The block number at which the account's existence and state should be verified.
// @param account: The address of the account whose existence and state should be verified.
// @param proof_sizes_bytes_len: The length of the `proof_sizes_bytes` array, in words.
// @param proof_sizes_bytes: An array of integers that specifies the size of each proof element, in bytes.
// @param proof_sizes_words_len: The length of the `proof_sizes_words` array, in words.
// @param proof_sizes_words: An array of integers that specifies the size of each proof element, in words.
// @param proofs_concat_len: The length of the `proofs_concat` array, in words.
// @param proofs_concat: An array that contains the concatenated proofs for each element of the account state.
// @param block_proof_leaf_index: The index of the leaf node in the Merkle proof for the block header.
// @param block_proof_leaf_value: The value of the leaf node in the Merkle proof for the block header.
// @param block_proof_len: The length of the `block_proof` array, in words.
// @param block_proof: An array that contains the Merkle proof for the block header.
// @param mmr_peaks_len: The number of peaks.
// @param mmr_peaks: An array that contains the latest MMR peaks hashes.
// @param block_header_rlp_len: The length of the `block_header_rlp` array, in words.
// @param block_header_rlp: An array that contains the RLP-encoded block header.
// @param block_header_rlp_bytes_len: The length of the RLP-encoded block header, in bytes.
// @param mmr_pos The MMR pos (i.e., tree size) for the proof.
//
@external
func prove_account{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(
    options_set: felt,
    block_number: felt,
    account: Address,
    proof_sizes_bytes_len: felt,
    proof_sizes_bytes: felt*,
    proof_sizes_words_len: felt,
    proof_sizes_words: felt*,
    proofs_concat_len: felt,
    proofs_concat: felt*,
    block_proof_leaf_index: felt,
    block_proof_leaf_value: felt,
    block_proof_len: felt,
    block_proof: felt*,
    mmr_peaks_len: felt,
    mmr_peaks: felt*,
    block_header_rlp_len: felt,
    block_header_rlp: felt*,
    block_header_rlp_bytes_len: felt,
    mmr_pos: felt,
) {
    alloc_locals;
    let (local account_raw) = alloc();
    assert account_raw[0] = account.word_1;
    assert account_raw[1] = account.word_2;
    assert account_raw[2] = account.word_3;
    local account_ints_sequence: IntsSequence = IntsSequence(account_raw, 3, 20);

    let (local keccak_ptr: felt*) = alloc();
    let keccak_ptr_start = keccak_ptr;
    let (local path_raw) = keccak256{keccak_ptr=keccak_ptr}(account_ints_sequence);
    // finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    local path: IntsSequence = IntsSequence(path_raw, 4, 32);
    let (local headers_store_addr) = _l1_headers_store_addr.read();

    // Root hash for `mmr_pos` must have been written to storage before.
    // @notice `mmr_pos` is the tree size at the time of inclusion of the
    // last element within the proof.
    let (mmr_root) = IL1HeadersStore.get_tree_size_to_root(
        contract_address=headers_store_addr, tree_size=mmr_pos
    );
    assert_not_zero(mmr_root);

    // TODO: assert block_number === decode(block_proof).block_number

    IL1HeadersStore.call_mmr_verify_proof(
        contract_address=headers_store_addr,
        index=block_proof_leaf_index,
        value=block_proof_leaf_value,
        proof_len=block_proof_len,
        proof=block_proof,
        peaks_len=mmr_peaks_len,
        peaks=mmr_peaks,
        pos=mmr_pos,
        root=mmr_root,
    );
    let (pedersen_hash) = hash_felts{hash_ptr=pedersen_ptr}(
        data=block_header_rlp, length=block_header_rlp_len
    );

    assert pedersen_hash = block_proof_leaf_value;

    local rlp: IntsSequence = IntsSequence(
        block_header_rlp, block_header_rlp_len, block_header_rlp_bytes_len
    );

    let (local decoded_block_number: felt) = decode_block_number(rlp);
    assert decoded_block_number = block_number;

    let (local state_root_raw: Keccak256Hash) = decode_state_root(rlp);

    assert_not_zero(state_root_raw.word_1);
    assert_not_zero(state_root_raw.word_2);
    assert_not_zero(state_root_raw.word_3);
    assert_not_zero(state_root_raw.word_4);
    let (local state_root_elements) = alloc();

    assert state_root_elements[0] = state_root_raw.word_1;
    assert state_root_elements[1] = state_root_raw.word_2;
    assert state_root_elements[2] = state_root_raw.word_3;
    assert state_root_elements[3] = state_root_raw.word_4;

    local state_root: IntsSequence = IntsSequence(state_root_elements, 4, 32);

    let (local proof: IntsSequence*) = alloc();
    reconstruct_ints_sequence_list(
        proofs_concat,
        proofs_concat_len,
        proof_sizes_words,
        proof_sizes_words_len,
        proof_sizes_bytes,
        proof_sizes_bytes_len,
        proof,
        0,
        0,
        0,
    );

    let (local result: IntsSequence) = verify_proof(path, state_root, proof, proof_sizes_bytes_len);
    let (local result_items: RLPItem*, result_items_len: felt) = to_list(result);
    let (local result_values: IntsSequence*, result_values_len: felt) = extract_list_values(
        result, result_items, result_items_len
    );

    let (local address_160) = address_words64_to_160bit(account);

    let (local save_storage_hash) = bitset_get(options_set, 0);
    if (save_storage_hash == 1) {
        local storage_hash: Keccak256Hash = Keccak256Hash(
            result_values[2].element[0],
            result_values[2].element[1],
            result_values[2].element[2],
            result_values[2].element[3],
        );
        _verified_account_storage_hash.write(address_160, block_number, storage_hash);
        tempvar syscall_ptr = syscall_ptr;
        tempvar range_check_ptr = range_check_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
    } else {
        tempvar syscall_ptr = syscall_ptr;
        tempvar range_check_ptr = range_check_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
    }

    local syscall_ptr: felt* = syscall_ptr;
    local range_check_ptr: felt = range_check_ptr;
    local pedersen_ptr: HashBuiltin* = pedersen_ptr;

    let (local save_code_hash) = bitset_get(options_set, 1);
    if (save_code_hash == 1) {
        local code_hash: Keccak256Hash = Keccak256Hash(
            result_values[3].element[0],
            result_values[3].element[1],
            result_values[3].element[2],
            result_values[3].element[3],
        );
        _verified_account_code_hash.write(address_160, block_number, code_hash);
        tempvar syscall_ptr = syscall_ptr;
        tempvar range_check_ptr = range_check_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
    } else {
        tempvar syscall_ptr = syscall_ptr;
        tempvar range_check_ptr = range_check_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
    }

    local syscall_ptr: felt* = syscall_ptr;
    local range_check_ptr: felt = range_check_ptr;
    local pedersen_ptr: HashBuiltin* = pedersen_ptr;

    let (local save_nonce) = bitset_get(options_set, 2);
    if (save_nonce == 1) {
        if (result_values[0].element_size_bytes == 0) {
            tempvar temp_nonce = 0;
        } else {
            tempvar temp_nonce = result_values[0].element[0];
        }

        local nonce = temp_nonce;

        _verified_account_nonce.write(address_160, block_number, nonce);
        tempvar syscall_ptr = syscall_ptr;
        tempvar range_check_ptr = range_check_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
    } else {
        tempvar syscall_ptr = syscall_ptr;
        tempvar range_check_ptr = range_check_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
    }

    local syscall_ptr: felt* = syscall_ptr;
    local range_check_ptr: felt = range_check_ptr;
    local pedersen_ptr: HashBuiltin* = pedersen_ptr;

    let (local save_balance) = bitset_get(options_set, 3);
    if (save_balance == 1) {
        if (result_values[1].element_size_bytes == 0) {
            tempvar temp_balance = 0;
        } else {
            tempvar temp_balance = result_values[1].element[0];
        }

        local balance = temp_balance;

        _verified_account_balance.write(address_160, block_number, balance);
        tempvar syscall_ptr = syscall_ptr;
        tempvar range_check_ptr = range_check_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
    } else {
        tempvar syscall_ptr = syscall_ptr;
        tempvar range_check_ptr = range_check_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
    }

    return ();
}

//
// @dev Gets the value of a storage slot for a given account at a specified block number.
//
// @param block: The block number at which the storage slot's value should be retrieved.
// @param account_160: The address of the account whose storage slot value should be retrieved.
// @param slot: The storage slot for which the value should be retrieved.
// @param proof_sizes_bytes_len: The length of the `proof_sizes_bytes` array, in words.
// @param proof_sizes_bytes: An array of integers that specifies the size of each proof element, in bytes.
// @param proof_sizes_words_len: The length of the `proof_sizes_words` array, in words.
// @param proof_sizes_words: An array of integers that specifies the size of each proof element, in words.
// @param proofs_concat_len: The length of the `proofs_concat` array, in words.
// @param proofs_concat: An array that contains the concatenated proofs for each element of the account state.
// @return res_bytes_len: The length of the returned storage slot value, in bytes.
// @return res_len: The length of the returned storage slot value, in words.
// @return res: An array containing the value of the storage slot for the given account at the specified block number.
//
@view
func get_storage{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(
    block: felt,
    account_160: felt,
    slot: StorageSlot,
    proof_sizes_bytes_len: felt,
    proof_sizes_bytes: felt*,
    proof_sizes_words_len: felt,
    proof_sizes_words: felt*,
    proofs_concat_len: felt,
    proofs_concat: felt*,
) -> (res_bytes_len: felt, res_len: felt, res: felt*) {
    alloc_locals;
    let (local account_state_root: Keccak256Hash) = _verified_account_storage_hash.read(
        account_160, block
    );

    assert_not_zero(account_state_root.word_1);
    assert_not_zero(account_state_root.word_2);
    assert_not_zero(account_state_root.word_3);
    assert_not_zero(account_state_root.word_4);

    let (storage_root_elements) = alloc();
    assert storage_root_elements[0] = account_state_root.word_1;
    assert storage_root_elements[1] = account_state_root.word_2;
    assert storage_root_elements[2] = account_state_root.word_3;
    assert storage_root_elements[3] = account_state_root.word_4;

    local storage_root: IntsSequence = IntsSequence(storage_root_elements, 4, 32);

    let (local slot_raw) = alloc();
    assert slot_raw[0] = slot.word_1;
    assert slot_raw[1] = slot.word_2;
    assert slot_raw[2] = slot.word_3;
    assert slot_raw[3] = slot.word_4;

    local slot_ints_sequence: IntsSequence = IntsSequence(slot_raw, 4, 32);

    let (local keccak_ptr: felt*) = alloc();
    let keccak_ptr_start = keccak_ptr;
    let (local path_raw) = keccak256{keccak_ptr=keccak_ptr}(slot_ints_sequence);
    // finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    local path: IntsSequence = IntsSequence(path_raw, 4, 32);

    let (local proof: IntsSequence*) = alloc();
    reconstruct_ints_sequence_list(
        proofs_concat,
        proofs_concat_len,
        proof_sizes_words,
        proof_sizes_words_len,
        proof_sizes_bytes,
        proof_sizes_bytes_len,
        proof,
        0,
        0,
        0,
    );
    let (local result: IntsSequence) = verify_proof(
        path, storage_root, proof, proof_sizes_bytes_len
    );
    // Removed length prefix from rlp
    let (local slot_value) = extractElement(result, 0);
    return (slot_value.element_size_bytes, slot_value.element_size_words, slot_value.element);
}

//
// @dev Gets the value of a storage slot for a given account at a specified block number.
// @param block: The block number at which the storage slot's value should be retrieved.
// @param account_160: The address of the account whose storage slot value should be retrieved.
// @param slot: The storage slot for which the value should be retrieved.
// @param proof_sizes_bytes_len: The length of the `proof_sizes_bytes` array, in words.
// @param proof_sizes_bytes: An array of integers that specifies the size of each proof element, in bytes.
// @param proof_sizes_words_len: The length of the `proof_sizes_words` array, in words.
// @param proof_sizes_words: An array of integers that specifies the size of each proof element, in words.
// @param proofs_concat_len: The length of the `proofs_concat` array, in words.
// @param proofs_concat: An array that contains the concatenated proofs for each element of the account state.
// @return res_bytes_len: The length of the returned storage slot value, in bytes.
// @return res_len: The length of the returned storage slot value, in words.
// @return res: An array containing the value of the storage slot for the given account at the specified block number.
//
@view
func get_storage_uint{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(
    block: felt,
    account_160: felt,
    slot: StorageSlot,
    proof_sizes_bytes_len: felt,
    proof_sizes_bytes: felt*,
    proof_sizes_words_len: felt,
    proof_sizes_words: felt*,
    proofs_concat_len: felt,
    proofs_concat: felt*,
) -> (res: Uint256) {
    alloc_locals;
    let (
        local ints_res_bytes_len: felt, local ints_res_len: felt, local ints_res: felt*
    ) = get_storage(
        block,
        account_160,
        slot,
        proof_sizes_bytes_len,
        proof_sizes_bytes,
        proof_sizes_words_len,
        proof_sizes_words,
        proofs_concat_len,
        proofs_concat,
    );

    local res_ints_sequence: IntsSequence = IntsSequence(
        ints_res, ints_res_len, ints_res_bytes_len
    );
    let (local result_raw) = ints_to_uint256(res_ints_sequence);
    local result: Uint256 = Uint256(result_raw.low, result_raw.high);
    return (result,);
}
