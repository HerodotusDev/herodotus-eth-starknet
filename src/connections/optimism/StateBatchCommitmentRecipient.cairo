%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc

from lib.types import Keccak256Hash, IntsSequence, Address, RLPItem, reconstruct_ints_sequence_list
from lib.blockheader_rlp_extractor import decode_receipts_root
from lib.trie_proofs import verify_proof
from lib.bytes import remove_leading_byte
from lib.extract_from_rlp import to_list, extract_data
from lib.bitshift import bitshift_right, bitshift_left

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

// L1 address allowed to send messages to this contract
@storage_var
func _l1_messages_sender() -> (res: felt) {
}

@storage_var
func _batch_roots(batch_index: felt) -> (root: Keccak256Hash) {
}

@storage_var
func _batch_start(batch_index: felt) -> (start_at_element: felt) {
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ethereum_headers_store_addr: felt,
    l1_messages_sender: felt,
    state_commitment_chain_addr: Address
) {
    _ethereum_headers_store_addr.write(ethereum_headers_store_addr);
    _l1_messages_sender.write(l1_messages_sender);
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

    let (local tx_status: IntsSequence) = extract_data(
        receipt_list[0].dataPosition, receipt_list[0].length, valid_receipt_rlp
    );
    assert tx_status.element[0] = 1;

    let (local logs_rlp: IntsSequence) = extract_data(
        receipt_list[3].dataPosition, receipt_list[3].length, valid_receipt_rlp
    );
    let (local logs_elements: RLPItem*, list_len) = to_list(logs_rlp);

    let (local recipient: IntsSequence) =  extract_data(
        logs_elements[0].dataPosition, logs_elements[0].length, logs_rlp
    );
    let (local expected_recipient) = _state_commitment_chain_addr.read();

    assert recipient.element[0] = expected_recipient.word_1;
    assert recipient.element[1] = expected_recipient.word_2;
    assert recipient.element[2] = expected_recipient.word_3;

    let (local event_topics: IntsSequence) =  extract_data(
        logs_elements[1].dataPosition, logs_elements[1].length, logs_rlp
    );

    let (local event_selector: IntsSequence) = decode_event_selector_from_log_topic(event_topics);
    assert event_selector.element[0] = 0x16be4c5129a4e03c;
    assert event_selector.element[1] = 0xf3350262e181dc02;
    assert event_selector.element[2] = 0xddfb4a6008d92536;
    assert event_selector.element[3] = 0x8c0899fcd97ca9c5;

    let (local batch_index: felt) = decode_batch_index_from_log_topic(event_topics);

    let (local log_data: IntsSequence) = extract_data(
        logs_elements[2].dataPosition, logs_elements[2].length, logs_rlp
    );

    let (local batch_root: Keccak256Hash) = decode_batch_root_from_log_data(log_data);
    let (local batch_should_start_at_element: felt) = decode_batch_start_element_index_from_log_data(log_data);

    _batch_roots.write(batch_index, batch_root);
    _batch_start.write(batch_index, batch_should_start_at_element);

    return ();
}

@l1_handler
func receive_batch_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    from_address: felt,
    batch_index: felt,
    batch_start: felt,
    batch_root_word_1: felt,
    batch_root_word_2: felt,
    batch_root_word_3: felt,
    batch_root_word_4: felt
) {
    alloc_locals;
    let (l1_sender) = _l1_messages_sender.read();
    assert from_address = l1_sender;

    local batch_root: Keccak256Hash = Keccak256Hash(
        batch_root_word_1,
        batch_root_word_2,
        batch_root_word_3,
        batch_root_word_4
    );

    _batch_roots.write(batch_index, batch_root);
    _batch_start.write(batch_index, batch_start);
    return ();
}

@external
func relay_batch_root_optimistic{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
) {
    return ();
}

@view
func get_batch_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    batch_index: felt
) -> (batch_root: Keccak256Hash) {
    let (batch_root: Keccak256Hash) = _batch_roots.read(batch_index);
    return (batch_root,);
}

@view
func get_batch_start_index{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    batch_index: felt
) -> (batch_start: felt) {
    let (batch_start: felt) = _batch_start.read(batch_index);
    return (batch_start,);
}

func decode_event_selector_from_log_topic{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(topic: IntsSequence) -> (event_selector: IntsSequence) {
    alloc_locals;
    local preprocessed: IntsSequence = IntsSequence(topic.element, 5, 33); 
    let (local topic_no_abi_len: IntsSequence) = remove_leading_byte(preprocessed);

    let (local res_words) = alloc();
    assert res_words[0] = topic_no_abi_len.element[0];
    assert res_words[1] = topic_no_abi_len.element[1];
    assert res_words[2] = topic_no_abi_len.element[2];
    assert res_words[3] = topic_no_abi_len.element[3];

    local res: IntsSequence = IntsSequence(res_words, 4, 32);
    return (res, );
}

func decode_batch_index_from_log_topic{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(topic: IntsSequence) -> (batch_index: felt) {
    return (topic.element[7], );
}

func decode_batch_root_from_log_data{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(log_data: IntsSequence) -> (batch_root: Keccak256Hash) {
    alloc_locals;
    local res: Keccak256Hash = Keccak256Hash(log_data.element[0], log_data.element[1], log_data.element[2], log_data.element[3]);
    return (res, );
}

func decode_batch_start_element_index_from_log_data{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(log_data: IntsSequence) -> (start_element_index: felt) {
    alloc_locals;
    local res: felt = log_data.element[11];
    return (res, );
}

