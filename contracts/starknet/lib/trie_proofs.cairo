from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.math import assert_not_equal

from starkware.cairo.common.alloc import alloc

from starknet.lib.extract_from_rlp import extract_data, to_list, is_rlp_list, is_rlp_list_rlp_item
from starknet.lib.words64 import extract_nibble, extract_nibble_from_words

from starknet.lib.unsafe_keccak import keccak256
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak

from starknet.lib.comp_arr import arr_eq
from starknet.lib.swap_endianness import swap_endianness_four_words

from starknet.types import Keccak256Hash, IntsSequence, RLPItem



# TODO check for safety
func is_empty_keccak(input: IntsSequence) -> (res: felt):
    let not_empty = (input.element[0] - 6262289465969759654) * (input.element[1] - 18411636558227634286) * (input.element[2] - 6577753664917384640) * (input.element[3] - 99694600006120481)
    if not_empty == 0:
        return (1)
    else:
        return (0)
    end
end


func count_shared_prefix_len{ range_check_ptr }(
    path_offset: felt,
    path: IntsSequence,
    element_rlp: IntsSequence,
    node_path_item: RLPItem) -> (new_path_offset: felt):
    alloc_locals

    let (local node_path_decoded: IntsSequence) = extract_data(
        node_path_item.dataPosition,
        node_path_item.length,
        element_rlp)
    assert_not_equal(node_path_decoded.element_size_bytes, 0)

    # Extract node_path
    # Assumption that the first word of the proof element will be always a full word(8 bytes)
    let (first_nibble) = extract_nibble(node_path_decoded.element[0], 8, 0)

    local skip_nibbles

    if first_nibble == 0:
        skip_nibbles = 2
    else:
        if first_nibble == 1:
            skip_nibbles = 1
        else:
            if first_nibble == 2:
                skip_nibbles = 2
            else:
                if first_nibble == 3:
                    skip_nibbles = 1
                else:
                    assert 1 = 0
                end
            end
        end
    end

    let (local skipped_nibbles_above_size) = is_le(element_rlp.element_size_bytes, skip_nibbles)
    if skipped_nibbles_above_size == 1:
        return (path_offset)
    end

    let (shared_prefix) = count_shared_prefix_len_rec(path_offset, path, node_path_decoded, skip_nibbles, 0)
    return (shared_prefix + path_offset)
end

func count_shared_prefix_len_rec{ range_check_ptr }(
    path_offset: felt,
    path: IntsSequence,
    node_path_decoded: IntsSequence,
    skip_nibbles: felt,
    current_index: felt) -> (res: felt):
    alloc_locals
    let node_path_nibbles_len = node_path_decoded.element_size_bytes * 2 - skip_nibbles
    let path_nibbles_len = path.element_size_bytes * 2

    # current_index + path_offset >= len(path)
    let (local path_completed) = is_le(path_nibbles_len, current_index + path_offset)
    # current_index >= len(node_path)
    let (local node_path_completed) = is_le(node_path_nibbles_len, current_index)

    if path_completed + node_path_completed == 2:
        return (current_index)
    end

    let (current_path_nibble) = extract_nibble_from_words(path, current_index + path_offset)
    let (current_node_path_nibble) = extract_nibble_from_words(node_path_decoded, current_index + skip_nibbles)

    if current_path_nibble == current_node_path_nibble:
        return count_shared_prefix_len_rec(path_offset, path, node_path_decoded, skip_nibbles, current_index + 1)
    else:
        return (current_index)
    end
end

func get_next_hash{ range_check_ptr }(rlp_input: IntsSequence, rlp_node: RLPItem) -> (res: IntsSequence):
    alloc_locals
    assert rlp_node.length = 32
    let (local res: IntsSequence) = extract_data(rlp_node.dataPosition, rlp_node.length, rlp_input)
    assert res.element_size_words = 4
    return (res)
end

func verify_proof{ range_check_ptr, bitwise_ptr : BitwiseBuiltin* }(
    path: IntsSequence,
    root_hash: IntsSequence,
    proof: IntsSequence*,
    proof_len: felt) -> (res: IntsSequence):
    alloc_locals

    let (local keccak_ptr : felt*) = alloc()
    let keccak_ptr_start = keccak_ptr

    if proof_len == 0:
        let (is_root_zero) = is_empty_keccak(root_hash)
        assert is_root_zero = 1
        let (empty_arr) = alloc()
        local res: IntsSequence = IntsSequence(empty_arr, 0 , 0)
        return (res)
    end

    let (empty_arr) = alloc()
    local empty_hash: IntsSequence = IntsSequence(empty_arr, 0 , 0)

    let (local res: IntsSequence) = verify_proof_rec{keccak_ptr=keccak_ptr}(
        path,
        root_hash,
        proof,
        proof_len,
        empty_hash,
        0,
        0)
    
    # finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)
    return (res)
end


func verify_proof_rec{ keccak_ptr: felt*, range_check_ptr, bitwise_ptr : BitwiseBuiltin* }(
    path: IntsSequence,
    root_hash: IntsSequence,
    proof: IntsSequence*,
    proof_len: felt,
    next_hash: IntsSequence,
    path_offset: felt,
    current_index: felt) -> (res: IntsSequence):
    alloc_locals

    # let (local keccak_ptr : felt*) = alloc()

    if current_index == proof_len + 1:
        assert 1 = 0
    end

    local current_element: IntsSequence = proof[current_index]
    let (keccak_output) = keccak256{keccak_ptr=keccak_ptr}(current_element)
    local current_element_keccak: IntsSequence = IntsSequence(keccak_output, 4, 32)

    if current_index == 0:
        let (local hashes_match: felt) = arr_eq(current_element_keccak.element, current_element_keccak.element_size_words, root_hash.element, root_hash.element_size_words)
        assert hashes_match = 1
    else:
        let (local hashes_match: felt) = arr_eq(current_element_keccak.element, current_element_keccak.element_size_words, next_hash.element, next_hash.element_size_words)
        assert hashes_match = 1
    end

    let (node, node_len) = to_list(current_element)

    # Handle leaf node otherwise branch node
    if node_len == 2:
        # Leaf node logic goes here
        let (current_path_offset) = count_shared_prefix_len(path_offset, path, current_element, node[0])
        if current_index == proof_len - 1:
            assert current_path_offset = path.element_size_bytes * 2
            let (local res: IntsSequence) = extract_data(node[1].dataPosition, node[1].length, current_element)
            return (res)
        else:
            local children: RLPItem = node[1]
            let (local is_list) = is_rlp_list_rlp_item(children, current_element)
            if is_list == 0:
                let (local next_hash: IntsSequence) = get_next_hash(current_element, children)
                return verify_proof_rec{keccak_ptr=keccak_ptr}(
                    path=path,
                    root_hash=root_hash,
                    proof=proof,
                    proof_len=proof_len,
                    next_hash=next_hash,
                    path_offset=current_path_offset,
                    current_index=current_index + 1)
            else:
                let (local element_data_extracted: IntsSequence) = extract_data(children.dataPosition, children.length, current_element)
                let (local next_hash_words_le: felt*) = keccak256{keccak_ptr=keccak_ptr}(element_data_extracted)
                local next_hash_le: IntsSequence = IntsSequence(next_hash_words_le, 4, 32)
                let (local next_hash: IntsSequence) = swap_endianness_four_words(next_hash_le)

                return verify_proof_rec{keccak_ptr=keccak_ptr}(
                    path=path,
                    root_hash=root_hash,
                    proof=proof,
                    proof_len=proof_len,
                    next_hash=next_hash,
                    path_offset=current_path_offset,
                    current_index=current_index + 1)
            end
        end
    else:
        # Branch node logic goes here
        assert node_len = 17

        if current_index == proof_len - 1:
            if path_offset + 1 == path.element_size_bytes * 2:
                let (local res: IntsSequence) = extract_data(node[16].dataPosition, node[16].length, current_element)
                return (res)
            else:
                let (local node_children: felt) = extract_nibble_from_words(path, path_offset)
                local children: RLPItem = node[node_children]
                assert children.length = 0
                let (empty_arr) = alloc()
                local res: IntsSequence = IntsSequence(empty_arr, 0 , 0)
                return (res) 
            end
        else:
            let (not_reached_end) = is_le(path_offset, path.element_size_bytes * 2 - 1)
            assert not_reached_end = 1
            let (local node_children: felt) = extract_nibble_from_words(path, path_offset)
            local children: RLPItem = node[node_children]
            let current_path_offset = path_offset + 1

            let (local is_list) = is_rlp_list_rlp_item(children, current_element)

            if is_list == 0:
                let (local next_hash: IntsSequence) = get_next_hash(current_element, children)
                return verify_proof_rec(
                    path=path,
                    root_hash=root_hash,
                    proof=proof,
                    proof_len=proof_len,
                    next_hash=next_hash,
                    path_offset=current_path_offset,
                    current_index=current_index + 1)
            else:
                let (local element_data_extracted: IntsSequence) = extract_data(children.dataPosition, children.length, current_element)

                let (local next_hash_words_le: felt*) = keccak256{keccak_ptr=keccak_ptr}(element_data_extracted)

                local next_hash_le: IntsSequence = IntsSequence(next_hash_words_le, 4, 32)
                let (local next_hash: IntsSequence) = swap_endianness_four_words(next_hash_le)

                return verify_proof_rec{keccak_ptr=keccak_ptr}(
                    path=path,
                    root_hash=root_hash,
                    proof=proof,
                    proof_len=proof_len,
                    next_hash=next_hash,
                    path_offset=current_path_offset,
                    current_index=current_index + 1)
            end
        end
    end
    assert 1 = 0
    ret
end