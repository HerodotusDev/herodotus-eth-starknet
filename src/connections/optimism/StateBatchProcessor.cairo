%lang starknet
%builtins pedersen range_check ecdsa bitwise

from lib.types import Keccak256Hash

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

