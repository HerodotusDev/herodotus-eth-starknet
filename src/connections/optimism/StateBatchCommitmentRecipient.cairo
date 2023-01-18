%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc

from lib.types import Keccak256Hash, IntsSequence, Address, RLPItem, reconstruct_ints_sequence_list
from lib.blockheader_rlp_extractor import decode_receipts_root
from lib.trie_proofs import verify_proof
from lib.bytes import remove_leading_byte, remove_leading_bytes
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

@storage_var
func _l2output_oracle_addr() -> (res: Address) {
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

@storage_var
func _bedrock_outputs_block_numbers(l2_output_index: felt) -> (res: felt) {
}

@storage_var
func _bedrock_outputs_roots(l2_output_index: felt) -> (root: Keccak256Hash) {
}


@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ethereum_headers_store_addr: felt,
    l1_messages_sender: felt,
    state_commitment_chain_addr: Address,
    l2output_oracle_addr: Address
) {
    _ethereum_headers_store_addr.write(ethereum_headers_store_addr);
    _l1_messages_sender.write(l1_messages_sender);
    _state_commitment_chain_addr.write(state_commitment_chain_addr);
    _l2output_oracle_addr.write(l2output_oracle_addr);
    return ();
}

@external
func verify_l2_output_root_bedrock{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
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
    let (local block_header: IntsSequence) = access_l1_header_from_mmr(
        mmr_inclusion_header_leaf_index=mmr_inclusion_header_leaf_index,
        mmr_inclusion_header_leaf_value=mmr_inclusion_header_leaf_value,
        mmr_inclusion_header_proof_len=mmr_inclusion_header_proof_len,
        mmr_inclusion_header_proof=mmr_inclusion_header_proof,
        mmr_inclusion_header_peaks_len=mmr_inclusion_header_peaks_len,
        mmr_inclusion_header_peaks=mmr_inclusion_header_peaks,
        mmr_inclusion_header_inclusion_tx_hash=mmr_inclusion_header_inclusion_tx_hash,
        mmr_inclusion_header_pos=mmr_inclusion_header_pos,
        l1_header_rlp_len=l1_header_rlp_len,
        l1_header_rlp=l1_header_rlp,
        l1_header_rlp_bytes_len=l1_header_rlp_bytes_len,
    );

    let (local receipt_tree_leaf: IntsSequence) = verify_receipt_proof_against_header(
        block_header=block_header,
        path_size_bytes=path_size_bytes,
        path_len=path_len,
        path=path,
        receipt_inclusion_proof_sizes_bytes_len=receipt_inclusion_proof_sizes_bytes_len,
        receipt_inclusion_proof_sizes_bytes=receipt_inclusion_proof_sizes_bytes,
        receipt_inclusion_proof_sizes_words_len=receipt_inclusion_proof_sizes_words_len,
        receipt_inclusion_proof_sizes_words=receipt_inclusion_proof_sizes_words,
        receipt_inclusion_proof_concat_len=receipt_inclusion_proof_concat_len,
        receipt_inclusion_proof_concat=receipt_inclusion_proof_concat,
    );

    let (local valid_receipt_rlp: IntsSequence) = remove_leading_byte(receipt_tree_leaf);
    let (local receipt_rlp_items: RLPItem*, receipt_rlp_items_len: felt) = to_list(valid_receipt_rlp);

    assert_tx_succeed(
        receipt_rlp_items=receipt_rlp_items,
        receipt_rlp_items_len=receipt_rlp_items_len,
        receipt_rlp=valid_receipt_rlp
    );

    let (local logs_rlp: IntsSequence) = extract_data(
        receipt_rlp_items[3].dataPosition, receipt_rlp_items[3].length, valid_receipt_rlp
    );
    let (local logs_rlp_items: RLPItem*, logs_rlp_items_len: felt) = to_list(logs_rlp);

    let (local expected_recipient) = _l2output_oracle_addr.read();
    assert_proper_recipient(
        expected_recipient=expected_recipient,
        logs_rlp_items=logs_rlp_items,
        logs_rlp_items_len=logs_rlp_items_len,
        logs_rlp=logs_rlp
    );

    let (local event_topics: IntsSequence) =  extract_data(
        logs_rlp_items[1].dataPosition, logs_rlp_items[1].length, logs_rlp
    );
    let (local event_selector: IntsSequence) = decode_event_selector_from_log_topic(event_topics);


    // Assert event selector is correct -> 0xa7aaf2512769da4e444e3de247be2564225c2e7a8f74cfe528e46e17d24868e2
    assert event_selector.element[0] = 0xa7aaf2512769da4e;
    assert event_selector.element[1] = 0x444e3de247be2564;
    assert event_selector.element[2] = 0x225c2e7a8f74cfe5;
    assert event_selector.element[3] = 0x28e46e17d24868e2;

    let (local output_index: felt) = decode_l2_output_index_from_log_topic(event_topics);
    let (local output_root: Keccak256Hash) = decode_l2_output_root_from_log_topic(event_topics);
    let (local l2_block_number: felt) = decode_l2_block_number_from_log_topic(event_topics);

    _bedrock_outputs_block_numbers.write(output_index, l2_block_number);
    _bedrock_outputs_roots.write(output_index, output_root);
    return ();
}

@external
func verify_batch_root_pre_bedrock{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
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
    let (local block_header: IntsSequence) = access_l1_header_from_mmr(
        mmr_inclusion_header_leaf_index=mmr_inclusion_header_leaf_index,
        mmr_inclusion_header_leaf_value=mmr_inclusion_header_leaf_value,
        mmr_inclusion_header_proof_len=mmr_inclusion_header_proof_len,
        mmr_inclusion_header_proof=mmr_inclusion_header_proof,
        mmr_inclusion_header_peaks_len=mmr_inclusion_header_peaks_len,
        mmr_inclusion_header_peaks=mmr_inclusion_header_peaks,
        mmr_inclusion_header_inclusion_tx_hash=mmr_inclusion_header_inclusion_tx_hash,
        mmr_inclusion_header_pos=mmr_inclusion_header_pos,
        l1_header_rlp_len=l1_header_rlp_len,
        l1_header_rlp=l1_header_rlp,
        l1_header_rlp_bytes_len=l1_header_rlp_bytes_len,
    );

    let (local receipt_tree_leaf: IntsSequence) = verify_receipt_proof_against_header(
        block_header=block_header,
        path_size_bytes=path_size_bytes,
        path_len=path_len,
        path=path,
        receipt_inclusion_proof_sizes_bytes_len=receipt_inclusion_proof_sizes_bytes_len,
        receipt_inclusion_proof_sizes_bytes=receipt_inclusion_proof_sizes_bytes,
        receipt_inclusion_proof_sizes_words_len=receipt_inclusion_proof_sizes_words_len,
        receipt_inclusion_proof_sizes_words=receipt_inclusion_proof_sizes_words,
        receipt_inclusion_proof_concat_len=receipt_inclusion_proof_concat_len,
        receipt_inclusion_proof_concat=receipt_inclusion_proof_concat,
    );

    let (local valid_receipt_rlp: IntsSequence) = remove_leading_byte(receipt_tree_leaf);
    let (local receipt_rlp_items: RLPItem*, receipt_rlp_items_len: felt) = to_list(valid_receipt_rlp);

    assert_tx_succeed(
        receipt_rlp_items=receipt_rlp_items,
        receipt_rlp_items_len=receipt_rlp_items_len,
        receipt_rlp=valid_receipt_rlp
    );

    let (local logs_rlp: IntsSequence) = extract_data(
        receipt_rlp_items[3].dataPosition, receipt_rlp_items[3].length, valid_receipt_rlp
    );
    let (local logs_rlp_items: RLPItem*, logs_rlp_items_len: felt) = to_list(logs_rlp);

    let (local expected_recipient) = _state_commitment_chain_addr.read();
    assert_proper_recipient(
        expected_recipient=expected_recipient,
        logs_rlp_items=logs_rlp_items,
        logs_rlp_items_len=logs_rlp_items_len,
        logs_rlp=logs_rlp
    );

    let (local event_topics: IntsSequence) =  extract_data(
        logs_rlp_items[1].dataPosition, logs_rlp_items[1].length, logs_rlp
    );

    let (local event_selector: IntsSequence) = decode_event_selector_from_log_topic(event_topics);
    assert event_selector.element[0] = 0x16be4c5129a4e03c;
    assert event_selector.element[1] = 0xf3350262e181dc02;
    assert event_selector.element[2] = 0xddfb4a6008d92536;
    assert event_selector.element[3] = 0x8c0899fcd97ca9c5;

    let (local batch_index: felt) = decode_batch_index_from_log_topic(event_topics);

    let (local log_data: IntsSequence) = extract_data(
        logs_rlp_items[2].dataPosition, logs_rlp_items[2].length, logs_rlp
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

func decode_l2_output_root_from_log_topic{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(topic: IntsSequence) -> (root: Keccak256Hash) {
    alloc_locals;
    let (local data: IntsSequence) = remove_leading_bytes(topic, 34);

    local res: Keccak256Hash = Keccak256Hash(
        data.element[0],
        data.element[1],
        data.element[2],
        data.element[3]
    );
    return (res, );
}

func decode_l2_output_index_from_log_topic{
    range_check_ptr
}(topic: IntsSequence) -> (output_index: felt) {
    alloc_locals;

    local data: felt = topic.element[12];
    let (res) = bitshift_right(data, 5 * 8);
    return (res, );
}

func decode_l2_block_number_from_log_topic{
    range_check_ptr
}(topic: IntsSequence) -> (output_index: felt) {
    alloc_locals;
    return (topic.element[16], );
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

func access_l1_header_from_mmr{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
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
) -> (block_header: IntsSequence) {
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
    return (block_header, );
}

func verify_receipt_proof_against_header{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
    block_header: IntsSequence,
    path_size_bytes: felt,
    path_len: felt,
    path: felt*,
    receipt_inclusion_proof_sizes_bytes_len: felt,
    receipt_inclusion_proof_sizes_bytes: felt*,
    receipt_inclusion_proof_sizes_words_len: felt,
    receipt_inclusion_proof_sizes_words: felt*,
    receipt_inclusion_proof_concat_len: felt,
    receipt_inclusion_proof_concat: felt*,
) -> (receipt_tree_leaf: IntsSequence) {
    alloc_locals;

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

    return (receipt_tree_leaf, );
}

func assert_tx_succeed{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
    receipt_rlp_items: RLPItem*,
    receipt_rlp_items_len: felt,
    receipt_rlp: IntsSequence,
) {
    alloc_locals;
    let (local tx_status: IntsSequence) = extract_data(
        receipt_rlp_items[0].dataPosition, receipt_rlp_items[0].length, receipt_rlp
    );
    assert tx_status.element[0] = 1;
    return ();
}

func assert_proper_recipient{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(
    expected_recipient: Address,
    logs_rlp_items: RLPItem*,
    logs_rlp_items_len: felt,
    logs_rlp: IntsSequence
) {
    alloc_locals;
    let (local recipient: IntsSequence) =  extract_data(
        logs_rlp_items[0].dataPosition, logs_rlp_items[0].length, logs_rlp
    );

    assert recipient.element[0] = expected_recipient.word_1;
    assert recipient.element[1] = expected_recipient.word_2;
    assert recipient.element[2] = expected_recipient.word_3;
    return ();
}