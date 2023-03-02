%lang starknet
%builtins pedersen range_check

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash_state import hash_felts
from starkware.cairo.common.hash import hash2
from cairo_mmr.src.mmr import append, verify_proof

@view
func test_compute_block_header_pedersen_hash{
    range_check_ptr, pedersen_ptr: HashBuiltin*, syscall_ptr: felt*
}() -> () {
    alloc_locals;

    local reference_block_number;
    local block_header_rlp_bytes_len;
    local block_header_rlp_len;
    let (block_header_rlp: felt*) = alloc();

    %{
        from utils.types import Data
        from utils.block_header import build_block_header
        from mocks.blocks import mocked_blocks

        # 0x8407da492b7df20d2fe034a942a7c480c34eef978fe8b91ae98fcea4f3767125
        block = mocked_blocks[0]
        block_header = build_block_header(block)

        block_rlp = Data.from_bytes(block_header.raw_rlp()).to_ints()

        ids.reference_block_number = block['number']
        ids.block_header_rlp_bytes_len = block_rlp.length
        segments.write_arg(ids.block_header_rlp, block_rlp.values)
        print(block_rlp.values)
        ids.block_header_rlp_len = len(block_rlp.values)
    %}

    let (pedersen_hash) = hash_felts{hash_ptr=pedersen_ptr}(
        data=block_header_rlp, length=block_header_rlp_len
    );
    let (local peaks: felt*) = alloc();
    assert pedersen_hash = 64500923809563958742308028500326302135879678726424812917573848972147944060;

    append(elem=pedersen_hash, peaks_len=0, peaks=peaks);

    let (node1) = hash2{hash_ptr=pedersen_ptr}(1, pedersen_hash);
    assert peaks[0] = node1;
    let (local proof: felt*) = alloc();
    verify_proof(1, pedersen_hash, 0, proof, 1, peaks);

    return ();
}
