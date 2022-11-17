%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from lib.blockheader_rlp_extractor import (
    decode_parent_hash,
    decode_uncles_hash,
    decode_beneficiary,
    decode_state_root,
    decode_transactions_root,
    decode_receipts_root,
    decode_difficulty,
    decode_block_number,
    decode_gas_limit,
    decode_gas_used,
    decode_timestamp,
    decode_base_fee,
    Keccak256Hash,
    Address,
)
from lib.types import IntsSequence
from starkware.cairo.common.alloc import alloc

@view
func test_decode_parent_hash{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len_bytes;
    local block_rlp_len;
    let (block_rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from web3 import Web3

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        assert block_header.hash() == block["hash"]
        block_rlp_formatted = Data.from_bytes(block_rlp).to_ints()

        ids.block_rlp_len_bytes = block_rlp_formatted.length
        ids.block_rlp_len = len(block_rlp_formatted.values)
        segments.write_arg(ids.block_rlp, block_rlp_formatted.values)
    %}
    let (parent_hash) = helper_test_decode_parent_hash(
        block_rlp_len_bytes, block_rlp_len, block_rlp
    );
    %{
        extracted = [ids.parent_hash.word_1, ids.parent_hash.word_2, ids.parent_hash.word_3, ids.parent_hash.word_4]
        l = list(map(lambda x: str(hex(x)[2:]), extracted))
        formatted_hash = '0x' + ''.join(l)
        assert Web3.toBytes(hexstr=formatted_hash) == block["parentHash"]
    %}
    return ();
}

func helper_test_decode_parent_hash{range_check_ptr}(
    block_rlp_len_bytes: felt, block_rlp_len: felt, block_rlp: felt*
) -> (res: Keccak256Hash) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(block_rlp, block_rlp_len, block_rlp_len_bytes);
    let (local parent_hash: Keccak256Hash) = decode_parent_hash(input);
    return (parent_hash,);
}

@view
func test_decode_uncles_hash{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len_bytes;
    local block_rlp_len;
    let (block_rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from web3 import Web3

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        assert block_header.hash() == block["hash"]
        block_rlp_formatted = Data.from_bytes(block_rlp).to_ints()

        ids.block_rlp_len_bytes = block_rlp_formatted.length
        ids.block_rlp_len = len(block_rlp_formatted.values)
        segments.write_arg(ids.block_rlp, block_rlp_formatted.values)
    %}
    let (uncles_hash) = helper_test_decode_uncles_hash(
        block_rlp_len_bytes, block_rlp_len, block_rlp
    );
    %{
        extracted = [ids.uncles_hash.word_1, ids.uncles_hash.word_2, ids.uncles_hash.word_3, ids.uncles_hash.word_4]
        l = list(map(lambda x: str(hex(x)[2:]), extracted))
        formatted_hash = '0x' + ''.join(l)
        assert Web3.toBytes(hexstr=formatted_hash) == block["sha3Uncles"]
    %}
    return ();
}

func helper_test_decode_uncles_hash{range_check_ptr}(
    block_rlp_len_bytes: felt, block_rlp_len: felt, block_rlp: felt*
) -> (res: Keccak256Hash) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(block_rlp, block_rlp_len, block_rlp_len_bytes);
    let (local uncles_hash: Keccak256Hash) = decode_uncles_hash(input);
    return (uncles_hash,);
}

@view
func test_decode_beneficiary{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len_bytes;
    local block_rlp_len;
    let (block_rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from web3 import Web3

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        assert block_header.hash() == block["hash"]
        block_rlp_formatted = Data.from_bytes(block_rlp).to_ints()

        ids.block_rlp_len_bytes = block_rlp_formatted.length
        ids.block_rlp_len = len(block_rlp_formatted.values)
        segments.write_arg(ids.block_rlp, block_rlp_formatted.values)
    %}
    let (beneficiary) = helper_test_decode_beneficiary(
        block_rlp_len_bytes, block_rlp_len, block_rlp
    );
    %{
        extracted = [ids.beneficiary.word_1, ids.beneficiary.word_2, ids.beneficiary.word_3]
        l = list(map(lambda x: str(hex(x)[2:]), extracted))
        formatted_hash = '0x' + ''.join(l)
        assert Web3.toBytes(hexstr=formatted_hash) == bytes.fromhex(block["miner"][2:])
    %}
    return ();
}

func helper_test_decode_beneficiary{range_check_ptr}(
    block_rlp_len_bytes: felt, block_rlp_len: felt, block_rlp: felt*
) -> (res: Address) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(block_rlp, block_rlp_len, block_rlp_len_bytes);
    let (local beneficiary: Address) = decode_beneficiary(input);
    return (beneficiary,);
}

@view
func test_decode_state_root{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len_bytes;
    local block_rlp_len;
    let (block_rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from web3 import Web3

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        assert block_header.hash() == block["hash"]
        block_rlp_formatted = Data.from_bytes(block_rlp).to_ints()

        ids.block_rlp_len_bytes = block_rlp_formatted.length
        ids.block_rlp_len = len(block_rlp_formatted.values)
        segments.write_arg(ids.block_rlp, block_rlp_formatted.values)
    %}
    let (state_root) = helper_test_decode_state_root(block_rlp_len_bytes, block_rlp_len, block_rlp);
    %{
        extracted = [ids.state_root.word_1, ids.state_root.word_2, ids.state_root.word_3, ids.state_root.word_4]
        l = list(map(lambda x: str(hex(x)[2:]), extracted))
        formatted_hash = '0x' + ''.join(l)
        assert Web3.toBytes(hexstr=formatted_hash) == block["stateRoot"]
    %}
    return ();
}

func helper_test_decode_state_root{range_check_ptr}(
    block_rlp_len_bytes: felt, block_rlp_len: felt, block_rlp: felt*
) -> (res: Keccak256Hash) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(block_rlp, block_rlp_len, block_rlp_len_bytes);
    let (local state_root: Keccak256Hash) = decode_state_root(input);
    return (state_root,);
}

@view
func test_decode_transactions_root{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len_bytes;
    local block_rlp_len;
    let (block_rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from web3 import Web3

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        assert block_header.hash() == block["hash"]
        block_rlp_formatted = Data.from_bytes(block_rlp).to_ints()

        ids.block_rlp_len_bytes = block_rlp_formatted.length
        ids.block_rlp_len = len(block_rlp_formatted.values)
        segments.write_arg(ids.block_rlp, block_rlp_formatted.values)
    %}
    let (transactions_root) = helper_test_decode_transactions_root(
        block_rlp_len_bytes, block_rlp_len, block_rlp
    );
    %{
        extracted = [ids.transactions_root.word_1, ids.transactions_root.word_2, ids.transactions_root.word_3, ids.transactions_root.word_4]
        l = list(map(lambda x: str(hex(x)[2:]), extracted))
        formatted_hash = '0x' + ''.join(l)
        assert Web3.toBytes(hexstr=formatted_hash) == block["transactionsRoot"]
    %}
    return ();
}

func helper_test_decode_transactions_root{range_check_ptr}(
    block_rlp_len_bytes: felt, block_rlp_len: felt, block_rlp: felt*
) -> (res: Keccak256Hash) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(block_rlp, block_rlp_len, block_rlp_len_bytes);
    let (local transactions_root: Keccak256Hash) = decode_transactions_root(input);
    return (transactions_root,);
}

@view
func test_decode_receipts_root{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len_bytes;
    local block_rlp_len;
    let (block_rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from web3 import Web3

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        assert block_header.hash() == block["hash"]
        block_rlp_formatted = Data.from_bytes(block_rlp).to_ints()

        ids.block_rlp_len_bytes = block_rlp_formatted.length
        ids.block_rlp_len = len(block_rlp_formatted.values)
        segments.write_arg(ids.block_rlp, block_rlp_formatted.values)
    %}
    let (receipts_root) = helper_test_decode_receipts_root(
        block_rlp_len_bytes, block_rlp_len, block_rlp
    );
    %{
        extracted = [ids.receipts_root.word_1, ids.receipts_root.word_2, ids.receipts_root.word_3, ids.receipts_root.word_4]
        l = list(map(lambda x: str(hex(x)[2:]), extracted))
        formatted_hash = '0x' + ''.join(l)
        assert Web3.toBytes(hexstr=formatted_hash) == block["receiptsRoot"]
    %}
    return ();
}

func helper_test_decode_receipts_root{range_check_ptr}(
    block_rlp_len_bytes: felt, block_rlp_len: felt, block_rlp: felt*
) -> (res: Keccak256Hash) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(block_rlp, block_rlp_len, block_rlp_len_bytes);
    let (local receipts_root: Keccak256Hash) = decode_receipts_root(input);
    return (receipts_root,);
}

@view
func test_decode_difficulty{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len_bytes;
    local block_rlp_len;
    let (block_rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from web3 import Web3

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        assert block_header.hash() == block["hash"]
        block_rlp_formatted = Data.from_bytes(block_rlp).to_ints()

        ids.block_rlp_len_bytes = block_rlp_formatted.length
        ids.block_rlp_len = len(block_rlp_formatted.values)
        segments.write_arg(ids.block_rlp, block_rlp_formatted.values)
    %}
    let (difficulty) = helper_test_decode_difficulty(block_rlp_len_bytes, block_rlp_len, block_rlp);
    %{ assert ids.difficulty == block["difficulty"] %}
    return ();
}

func helper_test_decode_difficulty{range_check_ptr}(
    block_rlp_len_bytes: felt, block_rlp_len: felt, block_rlp: felt*
) -> (res: felt) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(block_rlp, block_rlp_len, block_rlp_len_bytes);
    return decode_difficulty(input);
}

@view
func test_decode_block_number{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len_bytes;
    local block_rlp_len;
    let (block_rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from web3 import Web3

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        assert block_header.hash() == block["hash"]
        block_rlp_formatted = Data.from_bytes(block_rlp).to_ints()

        ids.block_rlp_len_bytes = block_rlp_formatted.length
        ids.block_rlp_len = len(block_rlp_formatted.values)
        segments.write_arg(ids.block_rlp, block_rlp_formatted.values)
    %}
    let (block_number) = helper_test_decode_block_number(
        block_rlp_len_bytes, block_rlp_len, block_rlp
    );
    %{ assert ids.block_number == block["number"] %}
    return ();
}

func helper_test_decode_block_number{range_check_ptr}(
    block_rlp_len_bytes: felt, block_rlp_len: felt, block_rlp: felt*
) -> (res: felt) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(block_rlp, block_rlp_len, block_rlp_len_bytes);
    return decode_block_number(input);
}

@view
func test_decode_gas_limit{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len_bytes;
    local block_rlp_len;
    let (block_rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from web3 import Web3

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        assert block_header.hash() == block["hash"]
        block_rlp_formatted = Data.from_bytes(block_rlp).to_ints()

        ids.block_rlp_len_bytes = block_rlp_formatted.length
        ids.block_rlp_len = len(block_rlp_formatted.values)
        segments.write_arg(ids.block_rlp, block_rlp_formatted.values)
    %}
    let (gas_limit) = helper_test_decode_gas_limit(block_rlp_len_bytes, block_rlp_len, block_rlp);
    %{ assert ids.gas_limit == block["gasLimit"] %}
    return ();
}

func helper_test_decode_gas_limit{range_check_ptr}(
    block_rlp_len_bytes: felt, block_rlp_len: felt, block_rlp: felt*
) -> (res: felt) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(block_rlp, block_rlp_len, block_rlp_len_bytes);
    return decode_gas_limit(input);
}

@view
func test_decode_gas_used{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len_bytes;
    local block_rlp_len;
    let (block_rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from web3 import Web3

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        assert block_header.hash() == block["hash"]
        block_rlp_formatted = Data.from_bytes(block_rlp).to_ints()

        ids.block_rlp_len_bytes = block_rlp_formatted.length
        ids.block_rlp_len = len(block_rlp_formatted.values)
        segments.write_arg(ids.block_rlp, block_rlp_formatted.values)
    %}
    let (gas_used) = helper_test_decode_gas_used(block_rlp_len_bytes, block_rlp_len, block_rlp);
    %{ assert ids.gas_used == block["gasUsed"] %}
    return ();
}

func helper_test_decode_gas_used{range_check_ptr}(
    block_rlp_len_bytes: felt, block_rlp_len: felt, block_rlp: felt*
) -> (res: felt) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(block_rlp, block_rlp_len, block_rlp_len_bytes);
    return decode_gas_used(input);
}

@view
func test_decode_timestamp{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len_bytes;
    local block_rlp_len;
    let (block_rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from web3 import Web3

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        assert block_header.hash() == block["hash"]
        block_rlp_formatted = Data.from_bytes(block_rlp).to_ints()

        ids.block_rlp_len_bytes = block_rlp_formatted.length
        ids.block_rlp_len = len(block_rlp_formatted.values)
        segments.write_arg(ids.block_rlp, block_rlp_formatted.values)
    %}
    let (timestamp) = helper_test_decode_timestamp(block_rlp_len_bytes, block_rlp_len, block_rlp);
    %{ assert ids.timestamp == block["timestamp"] %}
    return ();
}

func helper_test_decode_timestamp{range_check_ptr}(
    block_rlp_len_bytes: felt, block_rlp_len: felt, block_rlp: felt*
) -> (res: felt) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(block_rlp, block_rlp_len, block_rlp_len_bytes);
    return decode_timestamp(input);
}

@view
func test_decode_base_fee{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len_bytes;
    local block_rlp_len;
    let (block_rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from web3 import Web3

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        assert block_header.hash() == block["hash"]
        block_rlp_formatted = Data.from_bytes(block_rlp).to_ints()

        ids.block_rlp_len_bytes = block_rlp_formatted.length
        ids.block_rlp_len = len(block_rlp_formatted.values)
        segments.write_arg(ids.block_rlp, block_rlp_formatted.values)
    %}
    let (base_fee) = helper_test_decode_base_fee(block_rlp_len_bytes, block_rlp_len, block_rlp);
    %{ assert ids.base_fee == block["baseFeePerGas"] %}
    return ();
}

func helper_test_decode_base_fee{range_check_ptr}(
    block_rlp_len_bytes: felt, block_rlp_len: felt, block_rlp: felt*
) -> (res: felt) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(block_rlp, block_rlp_len, block_rlp_len_bytes);
    return decode_base_fee(input);
}
