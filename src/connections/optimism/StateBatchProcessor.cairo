%lang starknet
%builtins pedersen range_check ecdsa bitwise

from lib.types import Keccak256Hash
from lib.binary_merkle_keccak_verify import merkle_keccak_verify, determine_value_index

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.hash_state import hash_felts
from starkware.cairo.common.alloc import alloc

from cairo_mmr.src.historical_mmr import (
    append as mmr_append,
    verify_past_proof as mmr_verify_past_proof,
    get_last_pos as mmr_get_last_pos,
    get_inclusion_tx_hash_to_root as mmr_get_inclusion_tx_hash_to_root,
)

from starkware.starknet.common.syscalls import get_tx_info

@contract_interface
namespace IStateBatchCommitmentsRecipient {
    func get_batch_root(batch_index: felt) -> (batch_root: Keccak256Hash) {
    }
    func get_batch_start_index(batch_index: felt) -> (batch_start: felt) {
    }
}

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

// Temporary auth var for authenticating mocked L1 handlers.
@storage_var
func _batch_commitments_recipient() -> (res: felt) {
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    batch_commitments_recipient: felt
) {
    _batch_commitments_recipient.write(batch_commitments_recipient);
    return ();
}

@external
func set_state_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr }(
    append_left: felt,
    batch_index: felt,
    batch_merkle_proof_len: felt,
    batch_merkle_proof: felt*,
    mmr_peaks_len: felt,
    mmr_peaks: felt*
) {
    alloc_locals;

    let (local batch_commitments_recipient) = _batch_commitments_recipient.read();

    let (local batch_root: Keccak256Hash) = IStateBatchCommitmentsRecipient.get_batch_root(batch_commitments_recipient, batch_index);
    let (local batch_start_index) = IStateBatchCommitmentsRecipient.get_batch_start_index(batch_commitments_recipient, batch_index);

    local is_empty_root = (batch_root.word_1 * batch_root.word_2 * batch_root.word_3 * batch_root.word_4) + 1;
    if(is_empty_root == 1) {
        assert 1 = 0;
    }

    merkle_keccak_verify(batch_root, batch_merkle_proof_len, batch_merkle_proof);
    let (left_sibling_index: felt, right_sibling_index: felt) = determine_value_index(batch_merkle_proof_len, batch_merkle_proof);

    local appended_elem: felt;

    if(append_left == 1) {
        let (local hash_input) = alloc();

        assert hash_input[0] = batch_merkle_proof[0];
        assert hash_input[1] = batch_merkle_proof[1];
        assert hash_input[2] = batch_merkle_proof[2];
        assert hash_input[3] = batch_merkle_proof[3];
        assert hash_input[4] = left_sibling_index;

        let (local hashed) = hash_felts{hash_ptr=pedersen_ptr}(hash_input, 5);
        appended_elem = hashed;
    } else {
        let (local hash_input) = alloc();

        assert hash_input[0] = batch_merkle_proof[4];
        assert hash_input[1] = batch_merkle_proof[5];
        assert hash_input[2] = batch_merkle_proof[6];
        assert hash_input[3] = batch_merkle_proof[7];
        assert hash_input[4] = right_sibling_index;

        let (local hashed) = hash_felts{hash_ptr=pedersen_ptr}(hash_input, 5);
        appended_elem = hashed;
    }

    let (info) = get_tx_info();
    mmr_append(
        elem=appended_elem, peaks_len=mmr_peaks_len, peaks=mmr_peaks, tx_hash=info.transaction_hash
    );
    return ();
}

