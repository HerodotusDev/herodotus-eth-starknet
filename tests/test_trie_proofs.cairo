%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc

from lib.types import IntsSequence, RLPItem, reconstruct_ints_sequence_list, Keccak256Hash
from lib.trie_proofs import count_shared_prefix_len, get_next_hash, verify_proof

@view
func test_count_shared_prefix_len{range_check_ptr}() -> () {
    alloc_locals;
    local path_offset;
    local path_values_len;
    let (path_values : felt*) = alloc();

    local path_size_bytes;
    local element_rlp_values_len;
    let (element_rlp_values : felt*) = alloc();
    local element_rlp_size_bytes;

    local node_path_item_firstByte;
    local node_path_item_data_pos;
    local node_path_item_length;
    %{
        from mocks.trie_proofs import trie_proofs, transaction_proofs, receipts_proofs
        from utils.types import Data
        from web3 import Web3
        from utils.rlp import to_list, extract_list_values
        from utils.benchmarks.trie_proofs import (
            count_shared_prefix_len,
            merkle_patricia_input_decode,
            get_next_hash,
            verify_proof,
            RLPItem)

        # Inputs
        proof = trie_proofs[1]['accountProof']
        element_rlp = Data.from_hex(proof[len(proof) - 1])

        path = Data.from_hex(Web3.keccak(hexstr=trie_proofs[1]['address']).hex())
        path_offset = 7
        ids.path_offset = path_offset

        # Get expected values
        node_path_items = to_list(element_rlp.to_ints())
        node_path_items_extracted = extract_list_values(element_rlp.to_ints(), node_path_items)
        node_path_nibbles = merkle_patricia_input_decode(node_path_items_extracted[0])
        expected_shared_prefix = path_offset + count_shared_prefix_len(path_offset, path.to_nibbles(), node_path_nibbles)  

        path_values = path.to_ints().values
        segments.write_arg(ids.path_values, path_values)
        ids.path_values_len = len(path_values)
        ids.path_size_bytes = path.to_ints().length

        element_rlp_values = element_rlp.to_ints().values
        segments.write_arg(ids.element_rlp_values, element_rlp_values)
        ids.element_rlp_values_len = len(element_rlp_values)
        ids.element_rlp_size_bytes = element_rlp.to_ints().length

        ids.node_path_item_firstByte = node_path_items[0].firstByte
        ids.node_path_item_data_pos = node_path_items[0].dataPosition
        ids.node_path_item_length = node_path_items[0].length
    %}
    let (res) = helper_test_count_shared_prefix_len(
        path_offset,
        path_values_len,
        path_values,
        path_size_bytes,
        element_rlp_values_len,
        element_rlp_values,
        element_rlp_size_bytes,
        node_path_item_firstByte,
        node_path_item_data_pos,
        node_path_item_length,
    );
    %{
        assert ids.res == expected_shared_prefix
    %}
    return ();
}


func helper_test_count_shared_prefix_len{range_check_ptr}(
    path_offset: felt,
    path_values_len: felt,
    path_values: felt*,
    path_size_bytes: felt,
    element_rlp_values_len: felt,
    element_rlp_values: felt*,
    element_rlp_size_bytes: felt,
    node_path_item_firstByte: felt,
    node_path_item_data_pos: felt,
    node_path_item_length: felt,
) -> (res: felt) {
    alloc_locals;

    let path: IntsSequence = IntsSequence(path_values, path_values_len, path_size_bytes);
    let element_rlp: IntsSequence = IntsSequence(
        element_rlp_values, element_rlp_values_len, element_rlp_size_bytes
    );

    let node_path_item: RLPItem = RLPItem(
        node_path_item_firstByte, node_path_item_data_pos, node_path_item_length
    );

    let (local res) = count_shared_prefix_len(path_offset, path, element_rlp, node_path_item);
    return (res,);
}

@view
func test_get_next_element_hash{range_check_ptr}() -> () {
    alloc_locals;
    local rlp_input_values_len;
    let (rlp_input_values : felt*) = alloc();
    local rlp_input_values_size_bytes;

    local rlp_node_first_byte;
    local rlp_node_data_pos;
    local rlp_node_data_length;
    %{
        from mocks.trie_proofs import trie_proofs, transaction_proofs, receipts_proofs
        from utils.types import Data
        from web3 import Web3
        from utils.rlp import to_list, extract_list_values
        from utils.benchmarks.trie_proofs import (
            count_shared_prefix_len,
            merkle_patricia_input_decode,
            get_next_hash,
            verify_proof,
            RLPItem)
        from utils.helpers import IntsSequence

        # Inputs
        proof = trie_proofs[1]['accountProof']
        element_rlp = Data.from_hex(proof[len(proof) - 2])
        rlp_item = RLPItem(160, dataPosition=173, length=32)

        # Get expected result
        expected_result = get_next_hash(element_rlp.to_ints(), rlp_item)

        element_rlp_values = element_rlp.to_ints().values
        segments.write_arg(ids.rlp_input_values, element_rlp_values)
        ids.rlp_input_values_len = len(element_rlp_values)
        ids.rlp_input_values_size_bytes = element_rlp.to_ints().length

        ids.rlp_node_first_byte = rlp_item.firstByte
        ids.rlp_node_data_pos = rlp_item.dataPosition
        ids.rlp_node_data_length = rlp_item.length
    %}
    let (res) = test_get_next_hash(
        rlp_input_values_len,
        rlp_input_values,
        rlp_input_values_size_bytes,
        rlp_node_first_byte,
        rlp_node_data_pos,
        rlp_node_data_length
    );
    %{
        output = memory.get_range(ids.res.element, 4)
        assert Data.from_ints(IntsSequence(output, 32)) == Data.from_ints(expected_result)
    %}
    return ();
}

func test_get_next_hash{range_check_ptr}(
    rlp_input_values_len: felt,
    rlp_input_values: felt*,
    rlp_input_values_size_bytes: felt,
    rlp_node_first_byte: felt,
    rlp_node_data_pos: felt,
    rlp_node_data_length: felt,
) -> (res: IntsSequence) {
    alloc_locals;

    let rlp_input: IntsSequence = IntsSequence(
        rlp_input_values, rlp_input_values_len, rlp_input_values_size_bytes
    );
    let rlp_node: RLPItem = RLPItem(rlp_node_first_byte, rlp_node_data_pos, rlp_node_data_length);

    let (local res: IntsSequence) = get_next_hash(rlp_input, rlp_node);
    return (res,);
}

@view
func test_verify_valid_account_proof{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    local path_size_bytes;
    local path_len;
    let (path: felt*) = alloc();
    local root_hash_size_bytes;
    local root_hash_len;
    let (root_hash: felt*) = alloc();

    local proof_sizes_bytes_len;
    let (proof_sizes_bytes: felt*) = alloc();
    local proof_sizes_words_len;

    let (proof_sizes_words: felt*) = alloc();
    local proofs_concat_len;
    let (proofs_concat: felt*) = alloc();
    %{
        from mocks.trie_proofs import trie_proofs, transaction_proofs, receipts_proofs
        from utils.types import Data
        from web3 import Web3
        from utils.rlp import to_list, extract_list_values
        from utils.benchmarks.trie_proofs import (
            count_shared_prefix_len,
            merkle_patricia_input_decode,
            get_next_hash,
            verify_proof,
            RLPItem)
        from utils.helpers import IntsSequence

        block_state_root = Data.from_hex('0x2045bf4ea5561e88a4d0d9afbc316354e49fe892ac7e961a5e68f1f4b9561152')
        proof_path = Data.from_hex(Web3.keccak(hexstr=trie_proofs[1]['address']).hex())
        proof = list(map(lambda element: Data.from_hex(element).to_ints(), trie_proofs[1]['accountProof']))

        flat_proof = []
        flat_proof_sizes_bytes = []
        flat_proof_sizes_words = []
        for proof_element in proof:
            flat_proof += proof_element.values
            flat_proof_sizes_bytes += [proof_element.length]
            flat_proof_sizes_words += [len(proof_element.values)]

        path_values = proof_path.to_ints().values
        segments.write_arg(ids.path, path_values)
        ids.path_len = len(path_values)
        ids.path_size_bytes = proof_path.to_ints().length

        block_state_root_values = block_state_root.to_ints().values
        segments.write_arg(ids.root_hash, block_state_root_values)
        ids.root_hash_len = len(block_state_root_values)
        ids.root_hash_size_bytes = block_state_root.to_ints().length

        ids.proof_sizes_bytes_len = len(flat_proof_sizes_bytes)
        segments.write_arg(ids.proof_sizes_bytes, flat_proof_sizes_bytes)
        ids.proof_sizes_words_len = len(flat_proof_sizes_words)
        segments.write_arg(ids.proof_sizes_words, flat_proof_sizes_words)

        ids.proofs_concat_len = len(flat_proof)
        segments.write_arg(ids.proofs_concat, flat_proof)
    %}
    let (res_size_bytes: felt, res_len: felt, res: felt*) = test_verify_proof(
        path_size_bytes,
        path_len,
        path,
        root_hash_size_bytes,
        root_hash_len,
        root_hash,

        proof_sizes_bytes_len,
        proof_sizes_bytes,

        proof_sizes_words_len,
        proof_sizes_words,

        proofs_concat_len,
        proofs_concat,
    );
    %{
        # Python implementation as a reference
        expected_key = Data.from_ints(verify_proof(
            proof_path.to_ints(),
            block_state_root.to_ints(),
            proof)
        )
        output = memory.get_range(ids.res, ids.res_len)
        result = Data.from_ints(IntsSequence(output, ids.res_size_bytes))
        assert result == expected_key
    %}
    return ();
}

@view
func test_verify_valid_storage_proof{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    local path_size_bytes;
    local path_len;
    let (path: felt*) = alloc();
    local root_hash_size_bytes;
    local root_hash_len;
    let (root_hash: felt*) = alloc();

    local proof_sizes_bytes_len;
    let (proof_sizes_bytes: felt*) = alloc();
    local proof_sizes_words_len;

    let (proof_sizes_words: felt*) = alloc();
    local proofs_concat_len;
    let (proofs_concat: felt*) = alloc();
    %{
        from mocks.trie_proofs import trie_proofs, transaction_proofs, receipts_proofs
        from utils.types import Data
        from web3 import Web3
        from utils.rlp import to_list, extract_list_values
        from utils.benchmarks.trie_proofs import (
            count_shared_prefix_len,
            merkle_patricia_input_decode,
            get_next_hash,
            verify_proof,
            RLPItem)
        from utils.helpers import IntsSequence

        account_state_root = Data.from_hex('0x199c2e6b850bcc9beaea25bf1bacc5741a7aad954d28af9b23f4b53f5404937b')
        proof_path = Data.from_hex(Web3.keccak(hexstr=trie_proofs[1]['storageProof'][0]['key']).hex())
        proof = list(map(lambda element: Data.from_hex(element).to_ints(), trie_proofs[1]['storageProof'][0]['proof']))

        flat_proof = []
        flat_proof_sizes_bytes = []
        flat_proof_sizes_words = []
        for proof_element in proof:
            flat_proof += proof_element.values
            flat_proof_sizes_bytes += [proof_element.length]
            flat_proof_sizes_words += [len(proof_element.values)]

        path_values = proof_path.to_ints().values
        segments.write_arg(ids.path, path_values)
        ids.path_len = len(path_values)
        ids.path_size_bytes = proof_path.to_ints().length

        account_state_root_values = account_state_root.to_ints().values
        segments.write_arg(ids.root_hash, account_state_root_values)
        ids.root_hash_len = len(account_state_root_values)
        ids.root_hash_size_bytes = account_state_root.to_ints().length

        ids.proof_sizes_bytes_len = len(flat_proof_sizes_bytes)
        segments.write_arg(ids.proof_sizes_bytes, flat_proof_sizes_bytes)
        ids.proof_sizes_words_len = len(flat_proof_sizes_words)
        segments.write_arg(ids.proof_sizes_words, flat_proof_sizes_words)

        ids.proofs_concat_len = len(flat_proof)
        segments.write_arg(ids.proofs_concat, flat_proof)
    %}
    let (res_size_bytes: felt, res_len: felt, res: felt*) = test_verify_proof(
        path_size_bytes,
        path_len,
        path,
        root_hash_size_bytes,
        root_hash_len,
        root_hash,
        proof_sizes_bytes_len,
        proof_sizes_bytes,
        proof_sizes_words_len,
        proof_sizes_words,
        proofs_concat_len,
        proofs_concat,
    );
    %{
        # Python implementation as a reference
        expected_key = Data.from_ints(verify_proof(
            proof_path.to_ints(),
            account_state_root.to_ints(),
            proof)
        )
        output = memory.get_range(ids.res, ids.res_len)
        result = Data.from_ints(IntsSequence(output, ids.res_size_bytes))
        assert result == expected_key
    %}
    return ();
}

@view
func test_verify_valid_transaction_proof{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    local path_size_bytes;
    local path_len;
    let (path: felt*) = alloc();
    local root_hash_size_bytes;
    local root_hash_len;
    let (root_hash: felt*) = alloc();

    local proof_sizes_bytes_len;
    let (proof_sizes_bytes: felt*) = alloc();
    local proof_sizes_words_len;

    let (proof_sizes_words: felt*) = alloc();
    local proofs_concat_len;
    let (proofs_concat: felt*) = alloc();
    %{
        from mocks.trie_proofs import trie_proofs, transaction_proofs, receipts_proofs
        from utils.types import Data
        from web3 import Web3
        from utils.rlp import to_list, extract_list_values
        from utils.benchmarks.trie_proofs import (
            count_shared_prefix_len,
            merkle_patricia_input_decode,
            get_next_hash,
            verify_proof,
            RLPItem)
        from utils.helpers import IntsSequence
        from rlp import encode


        txns_root = Data.from_hex('0x51a8f471a6eed8d7da6aa588eb4e9a0764770f5c20b0e1e05c1210abbb05dd78')
        proof_path = proof_path = Data.from_hex("0x" + encode(Data.from_hex(transaction_proofs[0]['transaction']['transactionIndex']).to_bytes()).hex())
        proof = list(map(lambda element: Data.from_hex(element).to_ints(), transaction_proofs[0]['txProof']))

        flat_proof = []
        flat_proof_sizes_bytes = []
        flat_proof_sizes_words = []
        for proof_element in proof:
            flat_proof += proof_element.values
            flat_proof_sizes_bytes += [proof_element.length]
            flat_proof_sizes_words += [len(proof_element.values)]

        path_values = proof_path.to_ints().values
        segments.write_arg(ids.path, path_values)
        ids.path_len = len(path_values)
        ids.path_size_bytes = proof_path.to_ints().length

        txns_root_values = txns_root.to_ints().values
        segments.write_arg(ids.root_hash, txns_root_values)
        ids.root_hash_len = len(txns_root_values)
        ids.root_hash_size_bytes = txns_root.to_ints().length

        ids.proof_sizes_bytes_len = len(flat_proof_sizes_bytes)
        segments.write_arg(ids.proof_sizes_bytes, flat_proof_sizes_bytes)
        ids.proof_sizes_words_len = len(flat_proof_sizes_words)
        segments.write_arg(ids.proof_sizes_words, flat_proof_sizes_words)

        ids.proofs_concat_len = len(flat_proof)
        segments.write_arg(ids.proofs_concat, flat_proof)
    %}
    let (res_size_bytes: felt, res_len: felt, res: felt*) = test_verify_proof(
        path_size_bytes,
        path_len,
        path,
        root_hash_size_bytes,
        root_hash_len,
        root_hash,
        proof_sizes_bytes_len,
        proof_sizes_bytes,
        proof_sizes_words_len,
        proof_sizes_words,
        proofs_concat_len,
        proofs_concat,
    );
    %{
        # Python implementation as a reference
        expected_key = Data.from_ints(verify_proof(
            proof_path.to_ints(),
            txns_root.to_ints(),
            proof)
        )
        output = memory.get_range(ids.res, ids.res_len)
        result = Data.from_ints(IntsSequence(output, ids.res_size_bytes))
        assert result == expected_key
    %}
    return ();
}

@view
func test_verify_valid_storage_proof_non_zero_value{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() -> () {
    alloc_locals;
    local path_size_bytes;
    local path_len;
    let (path: felt*) = alloc();
    local root_hash_size_bytes;
    local root_hash_len;
    let (root_hash: felt*) = alloc();

    local proof_sizes_bytes_len;
    let (proof_sizes_bytes: felt*) = alloc();
    local proof_sizes_words_len;

    let (proof_sizes_words: felt*) = alloc();
    local proofs_concat_len;
    let (proofs_concat: felt*) = alloc();
    %{
        from mocks.trie_proofs import trie_proofs, transaction_proofs, receipts_proofs
        from utils.types import Data
        from web3 import Web3
        from utils.rlp import to_list, extract_list_values
        from utils.benchmarks.trie_proofs import (
            count_shared_prefix_len,
            merkle_patricia_input_decode,
            get_next_hash,
            verify_proof,
            RLPItem)
        from utils.helpers import IntsSequence
        from rlp import encode

        account_state_root = Data.from_hex('0x199c2e6b850bcc9beaea25bf1bacc5741a7aad954d28af9b23f4b53f5404937b')
        proof_path = Data.from_hex(Web3.keccak(hexstr=trie_proofs[2]['storageProof'][0]['key']).hex())
        proof = list(map(lambda element: Data.from_hex(element).to_ints(), trie_proofs[2]['storageProof'][0]['proof']))

        flat_proof = []
        flat_proof_sizes_bytes = []
        flat_proof_sizes_words = []
        for proof_element in proof:
            flat_proof += proof_element.values
            flat_proof_sizes_bytes += [proof_element.length]
            flat_proof_sizes_words += [len(proof_element.values)]

        path_values = proof_path.to_ints().values
        segments.write_arg(ids.path, path_values)
        ids.path_len = len(path_values)
        ids.path_size_bytes = proof_path.to_ints().length

        account_state_root_values = account_state_root.to_ints().values
        segments.write_arg(ids.root_hash, account_state_root_values)
        ids.root_hash_len = len(account_state_root_values)
        ids.root_hash_size_bytes = account_state_root.to_ints().length

        ids.proof_sizes_bytes_len = len(flat_proof_sizes_bytes)
        segments.write_arg(ids.proof_sizes_bytes, flat_proof_sizes_bytes)
        ids.proof_sizes_words_len = len(flat_proof_sizes_words)
        segments.write_arg(ids.proof_sizes_words, flat_proof_sizes_words)

        ids.proofs_concat_len = len(flat_proof)
        segments.write_arg(ids.proofs_concat, flat_proof)
    %}
    let (res_size_bytes: felt, res_len: felt, res: felt*) = test_verify_proof(
        path_size_bytes,
        path_len,
        path,
        root_hash_size_bytes,
        root_hash_len,
        root_hash,
        proof_sizes_bytes_len,
        proof_sizes_bytes,
        proof_sizes_words_len,
        proof_sizes_words,
        proofs_concat_len,
        proofs_concat,
    );
    %{
        # Python implementation as a reference
        expected_key = Data.from_ints(verify_proof(
            proof_path.to_ints(),
            account_state_root.to_ints(),
            proof)
        )
        output = memory.get_range(ids.res, ids.res_len)
        result = Data.from_ints(IntsSequence(output, ids.res_size_bytes))
        assert result == expected_key
    %}
    return ();
}

func test_verify_proof{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    path_size_bytes: felt,
    path_len: felt,
    path: felt*,
    root_hash_size_bytes: felt,
    root_hash_len: felt,
    root_hash: felt*,
    proof_sizes_bytes_len: felt,
    proof_sizes_bytes: felt*,
    proof_sizes_words_len: felt,
    proof_sizes_words: felt*,
    proofs_concat_len: felt,
    proofs_concat: felt*,
) -> (res_size_bytes: felt, res_len: felt, res: felt*) {
    alloc_locals;
    local path_arg: IntsSequence = IntsSequence(path, path_len, path_size_bytes);
    local root_hash_arg: IntsSequence = IntsSequence(root_hash, root_hash_len, root_hash_size_bytes);

    let (local proof_arg: IntsSequence*) = alloc();
    reconstruct_ints_sequence_list(
        proofs_concat,
        proofs_concat_len,
        proof_sizes_words,
        proof_sizes_words_len,
        proof_sizes_bytes,
        proof_sizes_bytes_len,
        proof_arg,
        0,
        0,
        0,
    );

    let (local result: IntsSequence) = verify_proof(
        path_arg, root_hash_arg, proof_arg, proof_sizes_bytes_len
    );

    return (result.element_size_bytes, result.element_size_words, result.element);
}
