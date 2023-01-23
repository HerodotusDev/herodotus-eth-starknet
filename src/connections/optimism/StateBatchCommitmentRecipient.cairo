%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc

from lib.types import Keccak256Hash, IntsSequence, Address, RLPItem, reconstruct_ints_sequence_list, BedrockOutputRootPreimage
from lib.blockheader_rlp_extractor import decode_receipts_root
from lib.trie_proofs import verify_proof
from lib.bytes import remove_leading_byte, remove_leading_bytes
from lib.extract_from_rlp import to_list, extract_data
from lib.bitshift import bitshift_right, bitshift_left
from lib.comp_arr import arr_eq
from lib.unsafe_keccak import keccak256

from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak

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

    func receive_from_l1(parent_hash_len: felt, parent_hash: felt*, block_number: felt) {
    }
}

@storage_var
func _ethereum_headers_store_addr() -> (res: felt) {
}

@storage_var
func _optimism_headers_store_addr() -> (res: felt) {
}

@storage_var
func _l2output_oracle_addr() -> (res: Address) {
}

@storage_var
func _initialized() -> (res: felt) {
}

@external
func initialize{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ethereum_headers_store_addr: felt,
    optimism_headers_store_addr: felt,
    l2output_oracle_addr: Address
) {
    let (initialized) = _initialized.read();
    assert initialized = 0;

    _ethereum_headers_store_addr.write(ethereum_headers_store_addr);
    _optimism_headers_store_addr.write(optimism_headers_store_addr);
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
    output_root_preimage: BedrockOutputRootPreimage,
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

    let (local output_root_preimage_hash: Keccak256Hash) = calculate_output_root_preimage_hash(output_root_preimage);

    assert output_root_preimage_hash.word_1 = output_root.word_1;
    assert output_root_preimage_hash.word_2 = output_root.word_2;
    assert output_root_preimage_hash.word_3 = output_root.word_3;
    assert output_root_preimage_hash.word_4 = output_root.word_4;

    let (optimism_headers_store) = _optimism_headers_store_addr.read();

    let (local block_hash_words) = alloc();
    assert block_hash_words[0] = output_root_preimage.l2_block_hash.word_1;
    assert block_hash_words[1] = output_root_preimage.l2_block_hash.word_2;
    assert block_hash_words[2] = output_root_preimage.l2_block_hash.word_3;
    assert block_hash_words[3] = output_root_preimage.l2_block_hash.word_4;

    IEthereumHeadersStore.receive_from_l1(
        optimism_headers_store,
        4,
        block_hash_words,
        l2_block_number,
    );
    return ();
}

func calculate_output_root_preimage_hash{
    pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*, range_check_ptr
}(preimage: BedrockOutputRootPreimage) -> (preimage_hash: Keccak256Hash) {
    alloc_locals;

    let (local preimage_hash_input_words) = alloc();

    assert preimage_hash_input_words[0] = preimage.version.word_1;
    assert preimage_hash_input_words[1] = preimage.version.word_2;
    assert preimage_hash_input_words[2] = preimage.version.word_3;
    assert preimage_hash_input_words[3] = preimage.version.word_4;

    assert preimage_hash_input_words[4] = preimage.l2_block_state_root.word_1;
    assert preimage_hash_input_words[5] = preimage.l2_block_state_root.word_2;
    assert preimage_hash_input_words[6] = preimage.l2_block_state_root.word_3;
    assert preimage_hash_input_words[7] = preimage.l2_block_state_root.word_4;

    assert preimage_hash_input_words[8] = preimage.l2_withdrawals_storage_root.word_1;
    assert preimage_hash_input_words[9] = preimage.l2_withdrawals_storage_root.word_2;
    assert preimage_hash_input_words[10] = preimage.l2_withdrawals_storage_root.word_3;
    assert preimage_hash_input_words[11] = preimage.l2_withdrawals_storage_root.word_4;

    assert preimage_hash_input_words[12] = preimage.l2_block_hash.word_1;
    assert preimage_hash_input_words[13] = preimage.l2_block_hash.word_2;
    assert preimage_hash_input_words[14] = preimage.l2_block_hash.word_3;
    assert preimage_hash_input_words[15] = preimage.l2_block_hash.word_4;

    let (local keccak_ptr) = alloc();

    local preimage_hash_input: IntsSequence = IntsSequence(preimage_hash_input_words, 16, 128);

    %{
        from utils.types import Data
        expected = "0x00000000000000000000000000000000000000000000000000000000000000000ba2190732990103e5750c0ff0490a47c519186ee437927a8bf9f45f595ef129f3e48738f5ebd8d819d77bfda1c5d59a1816cda540ee217ffc842fdf9198dbc35802a3b8720151a3b3a32bd318b04c2f47e65a0bf922b8a3638fd59f13f8a42a"
        print(list(map(lambda x: hex(x), Data.from_hex(expected).to_ints().values)))
        input_words = list(map(lambda x: hex(x), memory.get_range(ids.preimage_hash_input_words, 16)))
        print(input_words)
    %}

    let (local preimage_hash: felt*) = keccak256{keccak_ptr=keccak_ptr}(preimage_hash_input);
    local res: Keccak256Hash = Keccak256Hash(preimage_hash[0], preimage_hash[1], preimage_hash[2], preimage_hash[3]);
    return (res, );
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