%lang starknet
%builtins pedersen range_check ecdsa bitwise

from lib.types import Keccak256Hash
from lib.binary_merkle_keccak_verify import merkle_keccak_verify

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

from cairo_mmr.src.historical_mmr import (
    append as mmr_append,
    verify_past_proof as mmr_verify_past_proof,
    get_last_pos as mmr_get_last_pos,
    get_inclusion_tx_hash_to_root as mmr_get_inclusion_tx_hash_to_root,
)

@contract_interface
namespace IStateBatchCommitmentsRecipient {
    func get_batch_root(batch_index: felt) -> (batch_root: Keccak256Hash) {
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
    batch_index: felt,
    batch_merkle_proof_len: felt,
    batch_merkle_proof: felt*,
    mmr_peaks_len: felt,
    mmr_peaks: felt*
) {
    alloc_locals;

    let (local batch_commitments_recipient) = _batch_commitments_recipient.read();
    let (local batch_root: Keccak256Hash) = IStateBatchCommitmentsRecipient(batch_commitments_recipient, batch_index);

    assert batch_index.word_1 != 0;
    assert batch_index.word_2 != 0;
    assert batch_index.word_3 != 0;
    assert batch_index.word_4 != 0;

    merkle_keccak_verify(batch_root, batch_merkle_proof_len, batch_merkle_proof);

    mmr_append(
        elem=pedersen_hash, peaks_len=mmr_peaks_len, peaks=mmr_peaks, tx_hash=info.transaction_hash
    );

    return ();
}

