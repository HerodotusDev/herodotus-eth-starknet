%lang starknet
%builtins pedersen range_check

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.hash_state import hash_felts
from starkware.cairo.common.hash import hash2

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

    // Returns the last saved MMR root.
    func get_mmr_root() -> (res: felt) {
    }

    // Returns the last saved MMR position (tree size).
    func get_mmr_last_pos() -> (res: felt) {
    }
}

@contract_interface
namespace FactsRegistry {
    func prove_account(
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
    }

    func get_verified_account_storage_hash(account_160: felt, block: felt) -> (res: Keccak256Hash) {
    }

    func get_verified_account_code_hash(account_160: felt, block: felt) -> (res: Keccak256Hash) {
    }

    func get_verified_account_balance(account_160: felt, block: felt) -> (res: felt) {
    }

    func get_verified_account_nonce(account_160: felt, block: felt) -> (res: felt) {
    }

    func get_storage(
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
    }

    func get_storage_uint(
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
        context.l1_headers_store_addr = deploy_contract("src/connections/ethereum/HeadersStore.cairo", [pub_key]).contract_address
        context.facts_registry = deploy_contract("src/connections/common/EvmFactsRegistry.cairo",  [context.l1_headers_store_addr]).contract_address
    %}
    return ();
}

func registry_initialized{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    alloc_locals;
    local l1_headers_store;
    let (parent_hash: felt*) = alloc();
    local block_number;
    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big, IntsSequence
        from mocks.blocks import mocked_blocks
        from utils.types import Data, Encoding, BlockHeaderIndexes
        from utils.block_header import build_block_header

        ids.l1_headers_store = context.l1_headers_store_addr

        block = mocked_blocks[7]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        block_parent_hash = Data.from_hex("0x62a8a05ef6fcd39a11b2d642d4b7ab177056e1eb4bde4454f67285164ef8ce65")
        assert block_parent_hash.to_hex() == block_header.hash().hex()
        parent_hash = block_parent_hash.to_ints(Encoding.BIG).values
        segments.write_arg(ids.parent_hash, parent_hash)
        ids.block_number = mocked_blocks[7]['number'] + 1

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.l1_headers_store_addr)
    %}
    L1HeadersStore.receive_from_l1(
        contract_address=l1_headers_store,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    %{ stop_prank_callable() %}
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();
    local block_number_process_block;
    %{
        from utils.types import Data
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks
        block = mocked_blocks[7]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)

        # +1 below is to use child block number (reference block).
        ids.block_number_process_block = block['number'] + 1

        # Save in ctxt for later retrieval
        context.saved_block_header_rlp = block_rlp
        context.saved_block_header_rlp_len = ids.block_header_rlp_len
        context.saved_block_header_rlp_bytes_len = ids.block_header_rlp_bytes_len
    %}
    let (local mmr_peaks: felt*) = alloc();
    // Add first node to MMR (reference block is in contract storage).
    L1HeadersStore.process_block_from_message(
        contract_address=l1_headers_store,
        reference_block_number=block_number_process_block,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
        mmr_peaks_len=0,
        mmr_peaks=mmr_peaks,
    );

    let (pedersen_hash) = hash_felts{hash_ptr=pedersen_ptr}(
        data=block_header_rlp, length=block_header_rlp_len
    );
    return (res=pedersen_hash);
}

@external
func test_prove_account{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;
    let (local mmr_peaks: felt*) = alloc();
    let (pedersen_hash) = registry_initialized();
    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, pedersen_hash);
    assert mmr_peaks[0] = node1;
    let (local block_proof: felt*) = alloc();

    let (block_header_rlp: felt*) = alloc();
    local block_header_rlp_len;
    local block_header_rlp_bytes_len;
    %{
        # Retrieve from ctxt
        segments.write_arg(ids.block_header_rlp, context.saved_block_header_rlp.values)
        ids.block_header_rlp_len = context.saved_block_header_rlp_len
        ids.block_header_rlp_bytes_len = context.saved_block_header_rlp_bytes_len
    %}

    local l1_headers_store;
    %{ ids.l1_headers_store = context.l1_headers_store_addr %}
    local facts_registry;
    %{ ids.facts_registry = context.facts_registry %}
    local options_set;
    local block_number;
    local proof_sizes_bytes_len;
    let (proof_sizes_bytes: felt*) = alloc();
    local proof_sizes_words_len;
    let (proof_sizes_words: felt*) = alloc();
    local proofs_concat_len;
    let (proofs_concat: felt*) = alloc();
    local account_word_1;
    local account_word_2;
    local account_word_3;
    %{
        from mocks.trie_proofs import trie_proofs
        ids.options_set = 15 # saves everything in state
        ids.block_number = mocked_blocks[7]['number']

        proof = list(map(lambda element: Data.from_hex(element).to_ints(), trie_proofs[1]['accountProof']))
        flat_proof = []
        flat_proof_sizes_bytes = []
        flat_proof_sizes_words = []
        for proof_element in proof:
            flat_proof += proof_element.values
            flat_proof_sizes_bytes += [proof_element.length]
            flat_proof_sizes_words += [len(proof_element.values)]

        l1_account_address = Data.from_hex(trie_proofs[1]['address'])
        account_words64 = l1_account_address.to_ints()

        ids.account_word_1 = account_words64.values[0]
        ids.account_word_2 = account_words64.values[1]
        ids.account_word_3 = account_words64.values[2]
        ids.proof_sizes_bytes_len = len(flat_proof_sizes_bytes)
        segments.write_arg(ids.proof_sizes_bytes, flat_proof_sizes_bytes)
        ids.proof_sizes_words_len = len(flat_proof_sizes_words)
        segments.write_arg(ids.proof_sizes_words, flat_proof_sizes_words)
        ids.proofs_concat_len = len(flat_proof)
        segments.write_arg(ids.proofs_concat, flat_proof)
    %}
    local account: Address = Address(account_word_1, account_word_2, account_word_3);
    let (mmr_last_pos) = L1HeadersStore.get_mmr_last_pos(contract_address=l1_headers_store);
    FactsRegistry.prove_account(
        contract_address=facts_registry,
        options_set=options_set,
        block_number=block_number,
        account=account,
        proof_sizes_bytes_len=proof_sizes_bytes_len,
        proof_sizes_bytes=proof_sizes_bytes,
        proof_sizes_words_len=proof_sizes_words_len,
        proof_sizes_words=proof_sizes_words,
        proofs_concat_len=proofs_concat_len,
        proofs_concat=proofs_concat,
        block_proof_leaf_index=1,
        block_proof_leaf_value=pedersen_hash,
        block_proof_len=0,
        block_proof=block_proof,
        mmr_peaks_len=1,
        mmr_peaks=mmr_peaks,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        mmr_pos=mmr_last_pos,
    );

    local account_160;
    local block;
    %{
        ids.account_160 = int(l1_account_address.to_hex()[2:], 16)
        ids.block = mocked_blocks[7]['number']
    %}
    let (storage_hash) = FactsRegistry.get_verified_account_storage_hash(
        contract_address=facts_registry, account_160=account_160, block=block
    );
    let (code_hash) = FactsRegistry.get_verified_account_code_hash(
        contract_address=facts_registry, account_160=account_160, block=block
    );
    let (account_balance) = FactsRegistry.get_verified_account_balance(
        contract_address=facts_registry, account_160=account_160, block=block
    );
    let (account_nonce) = FactsRegistry.get_verified_account_nonce(
        contract_address=facts_registry, account_160=account_160, block=block
    );
    %{
        extracted = [ids.storage_hash.word_1, ids.storage_hash.word_2, ids.storage_hash.word_3, ids.storage_hash.word_4]
        storage_hash = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        assert storage_hash == trie_proofs[1]['storageHash']
        extracted = [ids.code_hash.word_1, ids.code_hash.word_2, ids.code_hash.word_3, ids.code_hash.word_4]
        code_hash = '0x' + ''.join(v.to_bytes(8, 'big').hex() for v in extracted)
        assert code_hash == trie_proofs[1]['codeHash']
        assert ids.account_balance == int(trie_proofs[1]['balance'][2:], 16)
        assert ids.account_nonce == int(trie_proofs[1]['nonce'][2:], 16)
    %}
    return ();
}

@external
func test_get_storage{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;
    let (local mmr_peaks: felt*) = alloc();
    let (pedersen_hash) = registry_initialized();
    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, pedersen_hash);
    assert mmr_peaks[0] = node1;
    let (local block_proof: felt*) = alloc();

    let (block_header_rlp: felt*) = alloc();
    local block_header_rlp_len;
    local block_header_rlp_bytes_len;
    %{
        # Retrieve from ctxt
        segments.write_arg(ids.block_header_rlp, context.saved_block_header_rlp.values)
        ids.block_header_rlp_len = context.saved_block_header_rlp_len
        ids.block_header_rlp_bytes_len = context.saved_block_header_rlp_bytes_len
    %}
    local l1_headers_store;
    %{ ids.l1_headers_store = context.l1_headers_store_addr %}
    local facts_registry;
    %{ ids.facts_registry = context.facts_registry %}
    local options_set;
    local block_number;
    local proof_sizes_bytes_len;
    let (proof_sizes_bytes: felt*) = alloc();
    local proof_sizes_words_len;
    let (proof_sizes_words: felt*) = alloc();
    local proofs_concat_len;
    let (proofs_concat: felt*) = alloc();
    local account_word_1;
    local account_word_2;
    local account_word_3;
    %{
        from mocks.trie_proofs import trie_proofs
        ids.options_set = 15 # saves everything in state
        ids.block_number = mocked_blocks[7]['number']

        proof = list(map(lambda element: Data.from_hex(element).to_ints(), trie_proofs[1]['accountProof']))
        flat_proof = []
        flat_proof_sizes_bytes = []
        flat_proof_sizes_words = []
        for proof_element in proof:
            flat_proof += proof_element.values
            flat_proof_sizes_bytes += [proof_element.length]
            flat_proof_sizes_words += [len(proof_element.values)]

        l1_account_address = Data.from_hex(trie_proofs[1]['address'])
        account_words64 = l1_account_address.to_ints()

        ids.account_word_1 = account_words64.values[0]
        ids.account_word_2 = account_words64.values[1]
        ids.account_word_3 = account_words64.values[2]
        ids.proof_sizes_bytes_len = len(flat_proof_sizes_bytes)
        segments.write_arg(ids.proof_sizes_bytes, flat_proof_sizes_bytes)
        ids.proof_sizes_words_len = len(flat_proof_sizes_words)
        segments.write_arg(ids.proof_sizes_words, flat_proof_sizes_words)
        ids.proofs_concat_len = len(flat_proof)
        segments.write_arg(ids.proofs_concat, flat_proof)
    %}
    local account: Address = Address(account_word_1, account_word_2, account_word_3);
    let (mmr_last_pos) = L1HeadersStore.get_mmr_last_pos(contract_address=l1_headers_store);
    FactsRegistry.prove_account(
        contract_address=facts_registry,
        options_set=options_set,
        block_number=block_number,
        account=account,
        proof_sizes_bytes_len=proof_sizes_bytes_len,
        proof_sizes_bytes=proof_sizes_bytes,
        proof_sizes_words_len=proof_sizes_words_len,
        proof_sizes_words=proof_sizes_words,
        proofs_concat_len=proofs_concat_len,
        proofs_concat=proofs_concat,
        block_proof_leaf_index=1,
        block_proof_leaf_value=pedersen_hash,
        block_proof_len=0,
        block_proof=block_proof,
        mmr_peaks_len=1,
        mmr_peaks=mmr_peaks,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        mmr_pos=mmr_last_pos,
    );
    local slot_word1;
    local slot_word2;
    local slot_word3;
    local slot_word4;
    local account_160;
    local block;
    local proof_sizes_bytes_len_2;
    let (proof_sizes_bytes_2: felt*) = alloc();
    local proof_sizes_words_len_2;
    let (proof_sizes_words_2: felt*) = alloc();
    local proofs_concat_len_2;
    let (proofs_concat_2: felt*) = alloc();
    %{
        slot = Data.from_hex(trie_proofs[2]['storageProof'][0]['key']).to_ints()
        ids.slot_word1 = slot.values[0]
        ids.slot_word2 = slot.values[1]
        ids.slot_word3 = slot.values[2]
        ids.slot_word4 = slot.values[3]

        storage_proof = list(map(lambda element: Data.from_hex(element).to_ints(), trie_proofs[2]['storageProof'][0]['proof']))
        flat_storage_proof = []
        flat_storage_proof_sizes_bytes = []
        flat_storage_proof_sizes_words = []
        for proof_element in storage_proof:
            flat_storage_proof += proof_element.values
            flat_storage_proof_sizes_bytes += [proof_element.length]
            flat_storage_proof_sizes_words += [len(proof_element.values)]

        ids.proof_sizes_bytes_len_2 = len(flat_storage_proof_sizes_bytes)
        segments.write_arg(ids.proof_sizes_bytes_2, flat_storage_proof_sizes_bytes)
        ids.proof_sizes_words_len_2 = len(flat_storage_proof_sizes_words)
        segments.write_arg(ids.proof_sizes_words_2, flat_storage_proof_sizes_words)
        ids.proofs_concat_len_2 = len(flat_storage_proof)
        segments.write_arg(ids.proofs_concat_2, flat_storage_proof)

        ids.account_160 = int(trie_proofs[2]['address'][2:], 16)
        ids.block = mocked_blocks[7]['number']
    %}
    local slot: StorageSlot = StorageSlot(slot_word1, slot_word2, slot_word3, slot_word4);
    let (res_bytes_len: felt, res_len: felt, res: felt*) = FactsRegistry.get_storage(
        contract_address=facts_registry,
        block=block,
        account_160=account_160,
        slot=slot,
        proof_sizes_bytes_len=proof_sizes_bytes_len_2,
        proof_sizes_bytes=proof_sizes_bytes_2,
        proof_sizes_words_len=proof_sizes_words_len_2,
        proof_sizes_words=proof_sizes_words_2,
        proofs_concat_len=proofs_concat_len_2,
        proofs_concat=proofs_concat_2,
    );
    %{
        expected = trie_proofs[2]['storageProof'][0]['value']
        got = memory.get_range(ids.res, ids.res_len)
        assert Data.from_ints(IntsSequence(got, ids.res_bytes_len)).to_hex() == trie_proofs[2]['storageProof'][0]['value']
    %}
    return ();
}

@external
func test_get_storage_uint{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;
    let (local mmr_peaks: felt*) = alloc();
    let (pedersen_hash) = registry_initialized();
    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, pedersen_hash);
    assert mmr_peaks[0] = node1;
    let (local block_proof: felt*) = alloc();

    let (block_header_rlp: felt*) = alloc();
    local block_header_rlp_len;
    local block_header_rlp_bytes_len;
    %{
        # Retrieve from ctxt
        segments.write_arg(ids.block_header_rlp, context.saved_block_header_rlp.values)
        ids.block_header_rlp_len = context.saved_block_header_rlp_len
        ids.block_header_rlp_bytes_len = context.saved_block_header_rlp_bytes_len
    %}
    local l1_headers_store;
    %{ ids.l1_headers_store = context.l1_headers_store_addr %}
    local facts_registry;
    %{ ids.facts_registry = context.facts_registry %}
    local options_set;
    local block_number;
    local proof_sizes_bytes_len;
    let (proof_sizes_bytes: felt*) = alloc();
    local proof_sizes_words_len;
    let (proof_sizes_words: felt*) = alloc();
    local proofs_concat_len;
    let (proofs_concat: felt*) = alloc();
    local account_word_1;
    local account_word_2;
    local account_word_3;
    %{
        from mocks.trie_proofs import trie_proofs
        ids.options_set = 15 # saves everything in state
        ids.block_number = mocked_blocks[7]['number']

        proof = list(map(lambda element: Data.from_hex(element).to_ints(), trie_proofs[1]['accountProof']))
        flat_proof = []
        flat_proof_sizes_bytes = []
        flat_proof_sizes_words = []
        for proof_element in proof:
            flat_proof += proof_element.values
            flat_proof_sizes_bytes += [proof_element.length]
            flat_proof_sizes_words += [len(proof_element.values)]

        l1_account_address = Data.from_hex(trie_proofs[1]['address'])
        account_words64 = l1_account_address.to_ints()

        ids.account_word_1 = account_words64.values[0]
        ids.account_word_2 = account_words64.values[1]
        ids.account_word_3 = account_words64.values[2]
        ids.proof_sizes_bytes_len = len(flat_proof_sizes_bytes)
        segments.write_arg(ids.proof_sizes_bytes, flat_proof_sizes_bytes)
        ids.proof_sizes_words_len = len(flat_proof_sizes_words)
        segments.write_arg(ids.proof_sizes_words, flat_proof_sizes_words)
        ids.proofs_concat_len = len(flat_proof)
        segments.write_arg(ids.proofs_concat, flat_proof)
    %}
    local account: Address = Address(account_word_1, account_word_2, account_word_3);
    let (mmr_last_pos) = L1HeadersStore.get_mmr_last_pos(contract_address=l1_headers_store);
    FactsRegistry.prove_account(
        contract_address=facts_registry,
        options_set=options_set,
        block_number=block_number,
        account=account,
        proof_sizes_bytes_len=proof_sizes_bytes_len,
        proof_sizes_bytes=proof_sizes_bytes,
        proof_sizes_words_len=proof_sizes_words_len,
        proof_sizes_words=proof_sizes_words,
        proofs_concat_len=proofs_concat_len,
        proofs_concat=proofs_concat,
        block_proof_leaf_index=1,
        block_proof_leaf_value=pedersen_hash,
        block_proof_len=0,
        block_proof=block_proof,
        mmr_peaks_len=1,
        mmr_peaks=mmr_peaks,
        block_header_rlp_len=block_header_rlp_len,
        block_header_rlp=block_header_rlp,
        block_header_rlp_bytes_len=block_header_rlp_bytes_len,
        mmr_pos=mmr_last_pos,
    );
    local slot_word1;
    local slot_word2;
    local slot_word3;
    local slot_word4;
    local account_160;
    local block;
    local proof_sizes_bytes_len_2;
    let (proof_sizes_bytes_2: felt*) = alloc();
    local proof_sizes_words_len_2;
    let (proof_sizes_words_2: felt*) = alloc();
    local proofs_concat_len_2;
    let (proofs_concat_2: felt*) = alloc();
    %{
        slot = Data.from_hex(trie_proofs[2]['storageProof'][0]['key']).to_ints()
        ids.slot_word1 = slot.values[0]
        ids.slot_word2 = slot.values[1]
        ids.slot_word3 = slot.values[2]
        ids.slot_word4 = slot.values[3]

        storage_proof = list(map(lambda element: Data.from_hex(element).to_ints(), trie_proofs[2]['storageProof'][0]['proof']))
        flat_storage_proof = []
        flat_storage_proof_sizes_bytes = []
        flat_storage_proof_sizes_words = []
        for proof_element in storage_proof:
            flat_storage_proof += proof_element.values
            flat_storage_proof_sizes_bytes += [proof_element.length]
            flat_storage_proof_sizes_words += [len(proof_element.values)]

        ids.proof_sizes_bytes_len_2 = len(flat_storage_proof_sizes_bytes)
        segments.write_arg(ids.proof_sizes_bytes_2, flat_storage_proof_sizes_bytes)
        ids.proof_sizes_words_len_2 = len(flat_storage_proof_sizes_words)
        segments.write_arg(ids.proof_sizes_words_2, flat_storage_proof_sizes_words)
        ids.proofs_concat_len_2 = len(flat_storage_proof)
        segments.write_arg(ids.proofs_concat_2, flat_storage_proof)

        ids.account_160 = int(trie_proofs[2]['address'][2:], 16)
        ids.block = mocked_blocks[7]['number']
    %}
    local slot: StorageSlot = StorageSlot(slot_word1, slot_word2, slot_word3, slot_word4);
    let (res) = FactsRegistry.get_storage_uint(
        contract_address=facts_registry,
        block=block,
        account_160=account_160,
        slot=slot,
        proof_sizes_bytes_len=proof_sizes_bytes_len_2,
        proof_sizes_bytes=proof_sizes_bytes_2,
        proof_sizes_words_len=proof_sizes_words_len_2,
        proof_sizes_words=proof_sizes_words_2,
        proofs_concat_len=proofs_concat_len_2,
        proofs_concat=proofs_concat_2,
    );
    return ();
}
