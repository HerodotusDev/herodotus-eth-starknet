%lang starknet
%builtins pedersen range_check bitwise

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.hash_state import hash_felts
from starkware.cairo.common.hash import hash2

from lib.types import BedrockOutputRootPreimage, Bytes32, Keccak256Hash, Address

@contract_interface
namespace EthereumHeadersStore {
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
namespace IStateBatchCommitmentsRecipient {
    func verify_l2_output_root_bedrock(
        l1_inclusion_header_leaf_index: felt,
        l1_inclusion_header_leaf_value: felt,
        l1_inclusion_header_proof_len: felt,
        l1_inclusion_header_proof: felt*,
        l1_inclusion_header_peaks_len: felt,
        l1_inclusion_header_peaks: felt*,
        l1_inclusion_header_mmr_pos: felt,
        l1_inclusion_header_rlp_len: felt,
        l1_inclusion_header_rlp: felt*,
        l1_inclusion_header_rlp_bytes_len: felt,
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
    }

    func initialize(
        ethereum_headers_store_addr: felt,
        optimism_headers_store_addr: felt,
        l2output_oracle_addr: Address,
    ) {
    }
}

@external
func __setup__{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    local state_batch_commitment_recipient_addr;
    local optimism_headers_store_addr;
    local ethereum_headers_store_addr;

    local l2output_oracle_addr: Address;
    %{
        from starkware.crypto.signature.signature import (
            private_to_stark_key,
        )
        from utils.types import Data 
        priv_key = 12345678
        pub_key = private_to_stark_key(priv_key)
        context.relayer_pub_key = pub_key
        context.ethereum_headers_store_addr = deploy_contract("src/connections/ethereum/HeadersStore.cairo", [pub_key]).contract_address

        l2output_oracle_addr = Data.from_hex("0xe6dfba0953616bacab0c9a8ecb3a9bba77fc15c0").to_ints()
        context.state_batch_commitment_recipient_addr = deploy_contract("src/connections/optimism/StateBatchCommitmentRecipient.cairo", []).contract_address
        context.optimism_headers_store_addr = deploy_contract("src/connections/ethereum/HeadersStore.cairo", [context.state_batch_commitment_recipient_addr]).contract_address

        ids.state_batch_commitment_recipient_addr = context.state_batch_commitment_recipient_addr
        ids.optimism_headers_store_addr = context.optimism_headers_store_addr
        ids.ethereum_headers_store_addr = context.ethereum_headers_store_addr

        ids.l2output_oracle_addr.word_1 = l2output_oracle_addr.values[0]
        ids.l2output_oracle_addr.word_2 = l2output_oracle_addr.values[1]
        ids.l2output_oracle_addr.word_3 = l2output_oracle_addr.values[2]
    %}
    IStateBatchCommitmentsRecipient.initialize(
        contract_address=state_batch_commitment_recipient_addr,
        ethereum_headers_store_addr=ethereum_headers_store_addr,
        optimism_headers_store_addr=optimism_headers_store_addr,
        l2output_oracle_addr=l2output_oracle_addr,
    );
    return ();
}

func init_headers_store{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    alloc_locals;

    local ethereum_headers_store_addr;
    let (parent_hash: felt*) = alloc();
    local block_number;

    %{
        from utils.helpers import chunk_bytes_input, bytes_to_int_big, IntsSequence
        from mocks.blocks import mocked_goerli_blocks_optimism_bedrock_commitments
        from utils.types import Data, Encoding, BlockHeaderIndexes
        from utils.block_header import build_block_header

        ids.ethereum_headers_store_addr = context.ethereum_headers_store_addr

        block_header = mocked_goerli_blocks_optimism_bedrock_commitments[0]
        header_serialized = build_block_header(block_header)
        header_rlp_ints = Data.from_bytes(header_serialized.raw_rlp()).to_ints()

        trusted_parent_hash = Data.from_hex("0x566f87ab288e13f6e70d17388bfae98ff048a87be07ae4e8d514471d380306be")
        assert trusted_parent_hash.to_hex() == header_serialized.hash().hex()

        parent_hash = trusted_parent_hash.to_ints(Encoding.BIG).values
        segments.write_arg(ids.parent_hash, parent_hash)
        ids.block_number = mocked_goerli_blocks_optimism_bedrock_commitments[0]['number'] + 1

        stop_prank_callable = start_prank(context.relayer_pub_key, target_contract_address=context.ethereum_headers_store_addr)
    %}

    EthereumHeadersStore.receive_from_l1(
        contract_address=ethereum_headers_store_addr,
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
        from mocks.blocks import mocked_goerli_blocks_optimism_bedrock_commitments

        block_header = mocked_goerli_blocks_optimism_bedrock_commitments[0]
        header_serialized = build_block_header(block_header)
        header_rlp_ints = Data.from_bytes(header_serialized.raw_rlp()).to_ints()

        ids.block_header_rlp_bytes_len = header_rlp_ints.length
        segments.write_arg(ids.block_header_rlp, header_rlp_ints.values)
        ids.block_header_rlp_len = len(header_rlp_ints.values)

        # +1 below is to use child block number (reference block).
        ids.block_number_process_block = block_header['number'] + 1

        # Save in ctxt for later retrieval
        context.saved_block_header_rlp = header_rlp_ints.values
        context.saved_block_header_rlp_len = ids.block_header_rlp_len
        context.saved_block_header_rlp_bytes_len = ids.block_header_rlp_bytes_len
    %}

    let (local mmr_peaks: felt*) = alloc();
    // Add first node to MMR (reference block is in contract storage).
    EthereumHeadersStore.process_block_from_message(
        contract_address=ethereum_headers_store_addr,
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

@view
func test_verify_l2_output_root_bedrock{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
}() {
    alloc_locals;

    local ethereum_headers_store_addr;
    local state_batch_commitment_recipient_addr;
    %{
        ids.state_batch_commitment_recipient_addr = context.state_batch_commitment_recipient_addr
        ids.ethereum_headers_store_addr = context.ethereum_headers_store_addr
    %}

    let (local pedersen_hash: felt) = init_headers_store();
    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, pedersen_hash);
    let (local mmr_peaks: felt*) = alloc();
    assert mmr_peaks[0] = node1;
    let (mmr_pos) = EthereumHeadersStore.get_mmr_last_pos(
        contract_address=ethereum_headers_store_addr
    );

    let (block_header_rlp: felt*) = alloc();
    local block_header_rlp_len;
    local block_header_rlp_bytes_len;
    %{
        # Retrieve from ctxt
        segments.write_arg(ids.block_header_rlp, context.saved_block_header_rlp)
        ids.block_header_rlp_len = context.saved_block_header_rlp_len
        ids.block_header_rlp_bytes_len = context.saved_block_header_rlp_bytes_len
    %}

    local path_size_bytes;
    local path_len;
    let (path: felt*) = alloc();

    local receipt_proof_sizes_bytes_len;
    let (receipt_proof_sizes_bytes: felt*) = alloc();

    local receipt_proof_sizes_words_len;
    let (receipt_proof_sizes_words: felt*) = alloc();

    local receipt_proof_concat_len;
    let (receipt_proof_concat: felt*) = alloc();

    %{
        from mocks.trie_proofs import trie_proofs, receipts_proofs
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

        proof_path = proof_path = Data.from_hex("0x" + encode(Data.from_hex(receipts_proofs[2]['receipt']['transactionIndex']).to_bytes()).hex())

        path_values = proof_path.to_ints().values
        segments.write_arg(ids.path, path_values)
        ids.path_len = len(path_values)
        ids.path_size_bytes = proof_path.to_ints().length

        # Handle receipt proof
        receipt_proof = list(map(lambda element: Data.from_hex(element).to_ints(), receipts_proofs[2]['receiptProof']))
        flat_receipt_proof = []
        flat_receipt_proof_sizes_bytes = []
        flat_receipt_proof_sizes_words = []
        for proof_element in receipt_proof:
            flat_receipt_proof += proof_element.values
            flat_receipt_proof_sizes_bytes += [proof_element.length]
            flat_receipt_proof_sizes_words += [len(proof_element.values)]

        ids.receipt_proof_sizes_bytes_len = len(flat_receipt_proof_sizes_bytes)
        segments.write_arg(ids.receipt_proof_sizes_bytes, flat_receipt_proof_sizes_bytes)

        ids.receipt_proof_sizes_words_len = len(flat_receipt_proof_sizes_words)
        segments.write_arg(ids.receipt_proof_sizes_words, flat_receipt_proof_sizes_words)

        ids.receipt_proof_concat_len = len(flat_receipt_proof)
        segments.write_arg(ids.receipt_proof_concat, flat_receipt_proof)
    %}

    local preimage_version: Bytes32 = Bytes32(0x0, 0x0, 0x0, 0x0);
    local preimage_l2_block_state_root: Keccak256Hash = Keccak256Hash(
        0x0ba2190732990103, 0xe5750c0ff0490a47, 0xc519186ee437927a, 0x8bf9f45f595ef129
    );
    local preimage_l2_withdrawals_storage_root: Keccak256Hash = Keccak256Hash(
        0xf3e48738f5ebd8d8, 0x19d77bfda1c5d59a, 0x1816cda540ee217f, 0xfc842fdf9198dbc3
    );
    local preimage_l2_block_hash: Keccak256Hash = Keccak256Hash(
        0x5802a3b8720151a3, 0xb3a32bd318b04c2f, 0x47e65a0bf922b8a3, 0x638fd59f13f8a42a
    );

    local preimage: BedrockOutputRootPreimage = BedrockOutputRootPreimage(
        version=preimage_version,
        l2_block_state_root=preimage_l2_block_state_root,
        l2_withdrawals_storage_root=preimage_l2_withdrawals_storage_root,
        l2_block_hash=preimage_l2_block_hash,
    );

    let (local block_proof: felt*) = alloc();
    IStateBatchCommitmentsRecipient.verify_l2_output_root_bedrock(
        contract_address=state_batch_commitment_recipient_addr,
        l1_inclusion_header_leaf_index=1,
        l1_inclusion_header_leaf_value=pedersen_hash,
        l1_inclusion_header_proof_len=0,
        l1_inclusion_header_proof=block_proof,
        l1_inclusion_header_peaks_len=1,
        l1_inclusion_header_peaks=mmr_peaks,
        l1_inclusion_header_mmr_pos=mmr_pos,
        l1_inclusion_header_rlp_len=block_header_rlp_len,
        l1_inclusion_header_rlp=block_header_rlp,
        l1_inclusion_header_rlp_bytes_len=block_header_rlp_bytes_len,
        path_size_bytes=path_size_bytes,
        path_len=path_len,
        path=path,
        receipt_inclusion_proof_sizes_bytes_len=receipt_proof_sizes_bytes_len,
        receipt_inclusion_proof_sizes_bytes=receipt_proof_sizes_bytes,
        receipt_inclusion_proof_sizes_words_len=receipt_proof_sizes_words_len,
        receipt_inclusion_proof_sizes_words=receipt_proof_sizes_words,
        receipt_inclusion_proof_concat_len=receipt_proof_concat_len,
        receipt_inclusion_proof_concat=receipt_proof_concat,
        output_root_preimage=preimage,
    );

    return ();
}
