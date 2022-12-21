%lang starknet
%builtins pedersen range_check

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.hash_state import hash_felts
from starkware.cairo.common.hash import hash2
from starkware.starknet.common.syscalls import get_tx_info

from lib.types import Keccak256Hash, Address, StorageSlot

@contract_interface
namespace L1HeadersStore {
    func receive_from_l1(parent_hash_len: felt, parent_hash: felt*, block_number: felt) {
    }

    func process_block_from_message(
        reference_block_number: felt,
        block_header_rlp_bytes_len: felt,
        block_header_rlp_len: felt,
        block_header_rlp: felt*,
        mmr_peaks_len: felt,
        mmr_peaks: felt*,
    ) {
    }

    func get_mmr_last_pos() -> (res: felt) {
    }
}

@contract_interface
namespace L2StateRootsProcessor {
    func process_state_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
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
        slot: StorageSlot,
        transaction_inclusion_proof_sizes_bytes_len: felt,
        transaction_inclusion_proof_sizes_bytes: felt*,
        transaction_inclusion_proof_sizes_words_len: felt,
        transaction_inclusion_proof_sizes_words: felt*,
        transaction_inclusion_proofs_concat_len: felt,
        transaction_inclusion_proofs_concat: felt*,
    ) {
    }
}

@external
func __setup__{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    %{
        from starkware.crypto.signature.signature import (
            private_to_stark_key,
        )
        priv_key = 12345678
        pub_key = private_to_stark_key(priv_key)
        context.relayer_pub_key = pub_key
        context.l1_headers_store_addr = deploy_contract("src/L1HeadersStoreV2.cairo", [pub_key]).contract_address
        context.state_roots_processor = deploy_contract("src/L2StateRootsProcessor.cairo",  [context.l1_headers_store_addr]).contract_address
    %}
    return ();
}
