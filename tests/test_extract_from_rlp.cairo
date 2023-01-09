%lang starknet
%builtins pedersen range_check ecdsa

from lib.extract_from_rlp import (
    extract_data,
    is_rlp_list,
    to_list,
    getElement,
    extract_list_values,
    extractElement,
)
from lib.concat_arr import concat_arr
from lib.types import IntsSequence, RLPItem

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy

@view
func test_is_rlp_list_valid_input{range_check_ptr}() -> () {
    alloc_locals;
    local rlp_len_bytes;
    local rlp_len;
    let (rlp: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()

        list_input = Data.from_bytes(block_rlp).to_ints()

        ids.rlp_len_bytes = list_input.length
        segments.write_arg(ids.rlp, list_input.values)
        ids.rlp_len = len(list_input.values)
    %}
    let (is_list) = test_is_rlp_list(0, rlp_len_bytes, rlp_len, rlp);
    assert is_list = 1;
    return ();
}

func test_is_rlp_list{range_check_ptr}(
    pos: felt, rlp_len_bytes: felt, rlp_len: felt, rlp: felt*
) -> (res: felt) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(rlp, rlp_len, rlp_len_bytes);
    return is_rlp_list(pos, input);
}

@view
func test_is_rlp_list_invalid_input{range_check_ptr}() -> () {
    alloc_locals;
    let (rlp: felt*) = alloc();
    local rlp_len;
    %{
        ids.rlp_len = len([0xdeadbeef])
        segments.write_arg(ids.rlp, [0xdeadbeef])
    %}
    let (is_list) = test_is_rlp_list(0, 3, rlp_len, rlp);
    assert is_list = 0;
    return ();
}

@view
func test_get_element{range_check_ptr}() -> () {
    alloc_locals;
    local block_rlp_len;
    let (values: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()
        list_input = Data.from_bytes(block_rlp).to_ints()
        ids.block_rlp_len = len(block_rlp)
        segments.write_arg(ids.values, list_input.values)
    %}
    local input: IntsSequence = IntsSequence(values, block_rlp_len, block_rlp_len);

    let (output) = getElement(input, 0);
    %{
        from utils.rlp import getElement
        from utils.types import Data

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()

        input = Data.from_bytes(block_rlp)  
        expected_output = getElement(input.to_ints(), 0)
        assert ids.output.dataPosition == expected_output.dataPosition
        assert ids.output.length == expected_output.length
    %}
    return ();
}

@view
func test_to_list{range_check_ptr}() -> () {
    alloc_locals;

    local block_rlp_len;
    let (values: felt*) = alloc();

    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp())

        ids.block_rlp_len = block_rlp.to_ints().length
        segments.write_arg(ids.values, block_rlp.to_ints().values)
    %}
    let (data_positions_len, data_positions, lengths_len, lengths) = helper_test_to_list(
        block_rlp_len, block_rlp_len, values
    );
    %{
        from utils.rlp import to_list
        from utils.types import Data

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()

        expected = to_list(Data.from_bytes(block_rlp).to_ints())
        expected_data_positions = list(map(lambda item: item.dataPosition, expected))
        expected_lengths = list(map(lambda item: item.length, expected))

        assert expected_data_positions == memory.get_range(ids.data_positions, ids.data_positions_len)
        assert expected_lengths == memory.get_range(ids.lengths, ids.lengths_len)
    %}
    return ();
}

func helper_test_to_list{range_check_ptr}(rlp_len_bytes: felt, rlp_len: felt, rlp: felt*) -> (
    data_positions_len: felt, data_positions: felt*, lengths_len: felt, lengths: felt*
) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(rlp, rlp_len, rlp_len_bytes);
    let (local list: RLPItem*, list_len) = to_list(input);

    let (local data_positions: felt*) = alloc();
    let (local lengths: felt*) = alloc();

    deconstruct_rlp_items_arr(list, list_len, data_positions, 0, lengths, 0, 0);
    return (list_len, data_positions, list_len, lengths);
}

func deconstruct_rlp_items_arr{range_check_ptr}(
    list: RLPItem*,
    list_len: felt,
    data_positions_acc: felt*,
    data_positions_acc_len: felt,
    lengths_acc: felt*,
    lengths_acc_len: felt,
    current_index: felt,
) {
    if (current_index == list_len) {
        return ();
    }

    assert data_positions_acc[current_index] = list[current_index].dataPosition;
    assert lengths_acc[current_index] = list[current_index].length;

    return deconstruct_rlp_items_arr(
        list=list,
        list_len=list_len,
        data_positions_acc=data_positions_acc,
        data_positions_acc_len=data_positions_acc_len,
        lengths_acc=lengths_acc,
        lengths_acc_len=lengths_acc_len,
        current_index=current_index + 1,
    );
}

@view
func test_extract_list_values{range_check_ptr}() -> () {
    alloc_locals;
    local rlp_len_bytes;
    local rlp_len;
    let (rlp: felt*) = alloc();

    local rlp_items_first_bytes_len;
    let (rlp_items_first_bytes: felt*) = alloc();
    local rlp_items_data_positions_len;
    let (rlp_items_data_positions: felt*) = alloc();
    local rlp_items_lenghts_len;
    let (rlp_items_lenghts: felt*) = alloc();
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from utils.rlp import to_list, IntsSequence, extract_list_values
        from typing import List

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp())

        ids.rlp_len_bytes = block_rlp.to_ints().length
        ids.rlp_len = len(block_rlp.to_ints().values)
        segments.write_arg(ids.rlp, block_rlp.to_ints().values)
    %}
    let (data_positions_len, data_positions, lengths_len, lengths) = helper_test_to_list(
        rlp_len_bytes, rlp_len, rlp
    );
    %{
        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = block_header.raw_rlp()

        expected = to_list(Data.from_bytes(block_rlp).to_ints())
        expected_data_positions = list(map(lambda item: item.dataPosition, expected))
        expected_lengths = list(map(lambda item: item.length, expected))

        assert expected_data_positions == memory.get_range(ids.data_positions, ids.data_positions_len)
        assert expected_lengths == memory.get_range(ids.lengths, ids.lengths_len)

        expected_first_bytes = list(map(lambda item: item.firstByte, expected))

        ids.rlp_items_first_bytes_len = len(expected_first_bytes)
        segments.write_arg(ids.rlp_items_first_bytes, expected_first_bytes)

        ids.rlp_items_data_positions_len = len(expected_data_positions)
        segments.write_arg(ids.rlp_items_data_positions, expected_data_positions)

        ids.rlp_items_lenghts_len = len(expected_lengths)
        segments.write_arg(ids.rlp_items_lenghts, expected_lengths)
    %}
    let (
        flattened_list_elements_len,
        flattened_list_elements,
        flattened_list_sizes_words_len,
        flattened_list_sizes_words,
        flattened_list_sizes_bytes_len,
        flattened_list_sizes_bytes,
    ) = helper_test_extract_list_values(
        rlp_len_bytes,
        rlp_len,
        rlp,
        rlp_items_first_bytes_len,
        rlp_items_first_bytes,
        rlp_items_data_positions_len,
        rlp_items_data_positions,
        rlp_items_lenghts_len,
        rlp_items_lenghts,
    );
    %{
        block_rlp = Data.from_bytes(block_header.raw_rlp())
        rlp_items = to_list(block_rlp.to_ints())
        rlp_values = extract_list_values(block_rlp.to_ints(), rlp_items)

        output_list_elements_flat = memory.get_range(ids.flattened_list_elements, ids.flattened_list_elements_len)
        output_list_elements_sizes_words = memory.get_range(ids.flattened_list_sizes_words, ids.flattened_list_sizes_words_len)
        output_list_elements_sizes_bytes = memory.get_range(ids.flattened_list_sizes_bytes, ids.flattened_list_sizes_bytes_len)

        offset = 0
        output_list_elements: List[IntsSequence] = []
        for i in range(0, len(output_list_elements_sizes_words)):
            size_words = output_list_elements_sizes_words[i]
            size_bytes = output_list_elements_sizes_bytes[i]
            output_list_elements.append(IntsSequence(output_list_elements_flat[offset:offset+size_words], size_bytes))
            offset += size_words
            assert output_list_elements[i] == rlp_values[i], f"Failed at iteration: {i}"
    %}
    return ();
}

@view
func test_extract_list_from_account_rlp_entry{range_check_ptr}() -> () {
    alloc_locals;
    local rlp_len_bytes;
    local rlp_len;
    let (rlp: felt*) = alloc();

    local rlp_items_first_bytes_len;
    let (rlp_items_first_bytes: felt*) = alloc();
    local rlp_items_data_positions_len;
    let (rlp_items_data_positions: felt*) = alloc();
    local rlp_items_lenghts_len;
    let (rlp_items_lenghts: felt*) = alloc();
    %{
        from utils.types import Data
        from utils.rlp import to_list, IntsSequence, extract_list_values
        from typing import List

        input_hex = '0xf8440180a0199c2e6b850bcc9beaea25bf1bacc5741a7aad954d28af9b23f4b53f5404937ba04e36f96ee1667a663dfaac57c4d185a0e369a3a217e0079d49620f34f85d1ac7' 
        input = Data.from_hex(input_hex)

        ids.rlp_len_bytes = input.to_ints().length
        ids.rlp_len = len(input.to_ints().values)
        segments.write_arg(ids.rlp, input.to_ints().values)
    %}
    let (data_positions_len, data_positions, lengths_len, lengths) = helper_test_to_list(
        rlp_len_bytes, rlp_len, rlp
    );
    %{
        expected = to_list(input.to_ints())
        expected_data_positions = list(map(lambda item: item.dataPosition, expected))
        expected_lengths = list(map(lambda item: item.length, expected))
        expected_first_bytes = list(map(lambda item: item.firstByte, expected))

        assert expected_data_positions == memory.get_range(ids.data_positions, ids.data_positions_len)
        assert expected_lengths == memory.get_range(ids.lengths, ids.lengths_len)

        expected_first_bytes = list(map(lambda item: item.firstByte, expected))

        ids.rlp_items_first_bytes_len = len(expected_first_bytes)
        segments.write_arg(ids.rlp_items_first_bytes, expected_first_bytes)

        ids.rlp_items_data_positions_len = len(expected_data_positions)
        segments.write_arg(ids.rlp_items_data_positions, expected_data_positions)

        ids.rlp_items_lenghts_len = len(expected_lengths)
        segments.write_arg(ids.rlp_items_lenghts, expected_lengths)
    %}
    let (
        flattened_list_elements_len,
        flattened_list_elements,
        flattened_list_sizes_words_len,
        flattened_list_sizes_words,
        flattened_list_sizes_bytes_len,
        flattened_list_sizes_bytes,
    ) = helper_test_extract_list_values(
        rlp_len_bytes,
        rlp_len,
        rlp,
        rlp_items_first_bytes_len,
        rlp_items_first_bytes,
        rlp_items_data_positions_len,
        rlp_items_data_positions,
        rlp_items_lenghts_len,
        rlp_items_lenghts,
    );
    %{
        rlp_items = to_list(input.to_ints())
        rlp_values = extract_list_values(input.to_ints(), rlp_items)

        output_list_elements_flat = memory.get_range(ids.flattened_list_elements, ids.flattened_list_elements_len)
        output_list_elements_sizes_words = memory.get_range(ids.flattened_list_sizes_words, ids.flattened_list_sizes_words_len)
        output_list_elements_sizes_bytes = memory.get_range(ids.flattened_list_sizes_bytes, ids.flattened_list_sizes_bytes_len)

        offset = 0
        output_list_elements: List[IntsSequence] = []
        for i in range(0, len(output_list_elements_sizes_words)):
            size_words = output_list_elements_sizes_words[i]
            size_bytes = output_list_elements_sizes_bytes[i]
            output_list_elements.append(IntsSequence(output_list_elements_flat[offset:offset+size_words], size_bytes))
            offset += size_words
            assert output_list_elements[i] == rlp_values[i], f"Failed at iteration: {i}"
    %}
    return ();
}

func helper_test_extract_list_values{range_check_ptr}(
    rlp_len_bytes: felt,
    rlp_len: felt,
    rlp: felt*,
    rlp_items_first_bytes_len: felt,
    rlp_items_first_bytes: felt*,
    rlp_items_data_positions_len: felt,
    rlp_items_data_positions: felt*,
    rlp_items_lenghts_len: felt,
    rlp_items_lenghts: felt*,
) -> (
    flattened_list_elements_len: felt,
    flattened_list_elements: felt*,
    flattened_list_sizes_words_len: felt,
    flattened_list_sizes_words: felt*,
    flattened_list_sizes_bytes_len: felt,
    flattened_list_sizes_bytes: felt*,
) {
    alloc_locals;

    // flattened_list_elements: felt*
    // flattened_list_sizes: felt*

    let (local rlp_items: RLPItem*) = alloc();

    construct_rlp_items_arr(
        rlp_items_first_bytes,
        rlp_items_first_bytes_len,
        rlp_items_data_positions,
        rlp_items_data_positions_len,
        rlp_items_lenghts,
        rlp_items_lenghts_len,
        acc=rlp_items,
        acc_len=0,
        current_index=0,
    );

    local rlp_input: IntsSequence = IntsSequence(rlp, rlp_len, rlp_len_bytes);
    let (res, res_len) = extract_list_values(rlp_input, rlp_items, rlp_items_lenghts_len);

    let (local flattened_list_elements: felt*) = alloc();
    let (local flattened_list_sizes_words: felt*) = alloc();
    let (local flattened_list_sizes_bytes: felt*) = alloc();

    let (elements_acc_len, sizes_words_acc_len, sizes_bytes_acc_len) = flatten_ints_sequence_array(
        arr=res,
        arr_len=res_len,
        elements_acc=flattened_list_elements,
        elements_acc_len=0,
        sizes_words_acc=flattened_list_sizes_words,
        sizes_words_acc_len=0,
        sizes_bytes_acc=flattened_list_sizes_bytes,
        sizes_bytes_acc_len=0,
        current_index=0,
    );
    return (
        elements_acc_len,
        flattened_list_elements,
        sizes_words_acc_len,
        flattened_list_sizes_words,
        sizes_bytes_acc_len,
        flattened_list_sizes_bytes,
    );
}

func flatten_ints_sequence_array{range_check_ptr}(
    arr: IntsSequence*,
    arr_len: felt,
    elements_acc: felt*,
    elements_acc_len: felt,
    sizes_words_acc: felt*,
    sizes_words_acc_len: felt,
    sizes_bytes_acc: felt*,
    sizes_bytes_acc_len: felt,
    current_index: felt,
) -> (elements_acc_length: felt, sizes_words_acc_len: felt, sizes_bytes_acc_len: felt) {
    alloc_locals;
    if (current_index == arr_len) {
        return (elements_acc_len, sizes_words_acc_len, sizes_bytes_acc_len);
    }

    // Handle elements
    memcpy(
        elements_acc + elements_acc_len,
        arr[current_index].element,
        arr[current_index].element_size_words,
    );

    // Handle sizes
    assert sizes_words_acc[current_index] = arr[current_index].element_size_words;
    assert sizes_bytes_acc[current_index] = arr[current_index].element_size_bytes;

    return flatten_ints_sequence_array(
        arr=arr,
        arr_len=arr_len,
        elements_acc=elements_acc,
        elements_acc_len=elements_acc_len + arr[current_index].element_size_words,
        sizes_words_acc=sizes_words_acc,
        sizes_words_acc_len=sizes_words_acc_len + 1,
        sizes_bytes_acc=sizes_bytes_acc,
        sizes_bytes_acc_len=sizes_bytes_acc_len + 1,
        current_index=current_index + 1,
    );
}

func construct_rlp_items_arr{range_check_ptr}(
    rlp_items_first_bytes: felt*,
    rlp_items_first_bytes_len: felt,
    rlp_items_data_positions: felt*,
    rlp_items_data_positions_len: felt,
    rlp_items_lenghts: felt*,
    rlp_items_lenghts_len: felt,
    acc: RLPItem*,
    acc_len: felt,
    current_index: felt,
) {
    if (current_index == rlp_items_data_positions_len) {
        return ();
    }

    assert acc[current_index] = RLPItem(
        rlp_items_first_bytes[current_index],
        rlp_items_data_positions[current_index],
        rlp_items_lenghts[current_index],
    );

    return construct_rlp_items_arr(
        rlp_items_first_bytes=rlp_items_first_bytes,
        rlp_items_first_bytes_len=rlp_items_first_bytes_len,
        rlp_items_data_positions=rlp_items_data_positions,
        rlp_items_data_positions_len=rlp_items_data_positions_len,
        rlp_items_lenghts=rlp_items_lenghts,
        rlp_items_lenghts_len=rlp_items_lenghts_len,
        acc=acc,
        acc_len=acc_len,
        current_index=current_index + 1,
    );
}

@view
func test_extract_words{range_check_ptr}() -> () {
    alloc_locals;
    local rlp_len_bytes;
    local rlp_len;
    let (rlp: felt*) = alloc();

    local start_pos;
    local size;
    %{
        from mocks.blocks import mocked_blocks
        from utils.block_header import build_block_header
        from utils.types import Data
        from utils.rlp import to_list

        block = mocked_blocks[0]
        block_header = build_block_header(block)
        block_rlp = Data.from_bytes(block_header.raw_rlp())

        ids.rlp_len_bytes = block_rlp.to_ints().length
        ids.rlp_len = len(block_rlp.to_ints().values)
        segments.write_arg(ids.rlp, block_rlp.to_ints().values)
    %}
    let (data_positions_len, data_positions, lengths_len, lengths) = helper_test_to_list(
        rlp_len_bytes, rlp_len, rlp
    );
    %{
        expected = to_list(block_rlp.to_ints())
        expected_data_positions = list(map(lambda item: item.dataPosition, expected))
        expected_lengths = list(map(lambda item: item.length, expected))

        assert expected_data_positions == memory.get_range(ids.data_positions, ids.data_positions_len)
        assert expected_lengths == memory.get_range(ids.lengths, ids.lengths_len)
        rlp_items = to_list(block_rlp.to_ints())
        ids.start_pos = rlp_items[0].dataPosition
        ids.size = rlp_items[0].length
    %}
    let (res_len_bytes: felt, res_len: felt, res: felt*) = helper_test_extractData(
        start_pos, size, rlp_len_bytes, rlp_len, rlp
    );
    return ();
}

func helper_test_extractData{range_check_ptr}(
    start_pos: felt, size: felt, rlp_len_bytes: felt, rlp_len: felt, rlp: felt*
) -> (res_len_bytes: felt, res_len: felt, res: felt*) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(rlp, rlp_len, rlp_len_bytes);
    let (local data: IntsSequence) = extract_data(start_pos=start_pos, size=size, rlp=input);
    return (data.element_size_bytes, data.element_size_words, data.element);
}

@view
func test_extract_element{range_check_ptr}() -> () {
    alloc_locals;
    local rlp_len_bytes;
    local rlp_len;
    let (rlp: felt*) = alloc();
    %{
        from utils.types import Data
        input = Data.from_hex('0x2A').to_ints()

        ids.rlp_len_bytes = input.length
        ids.rlp_len = len(input.values)
        segments.write_arg(ids.rlp, input.values)
    %}
    let (res_len_bytes, res_len, res) = test_extractElement(0, rlp_len_bytes, rlp_len, rlp);
    %{ assert memory.get_range(ids.res, ids.res_len) == [42] %}
    return ();
}

func test_extractElement{range_check_ptr}(
    pos: felt, rlp_len_bytes: felt, rlp_len: felt, rlp: felt*
) -> (res_len_bytes: felt, res_len: felt, res: felt*) {
    alloc_locals;
    local input: IntsSequence = IntsSequence(rlp, rlp_len, rlp_len_bytes);
    let (local result: IntsSequence) = extractElement(input, pos);
    return (result.element_size_bytes, result.element_size_words, result.element);
}

// TODO: find an elegant way to write test_random (having 3 nested loops)

// @view
// func test_random{range_check_ptr}() -> () {
//     helper_test_random(34);
//     return ();
// }

// func helper_test_random{range_check_ptr}(length: felt) -> () {
//     if (length == 0) {
//         return ();
//     }
//     helper_2_test_random(length - 1, length - 1);
//     return helper_test_random(length - 1);
// }

// func helper_2_test_random{range_check_ptr}(length: felt, start_byte: felt) -> () {
//     if (start_byte == 0) {
//         return ();
//     }
//     helper_3_test_random(length, start_byte, length - start_byte + 1);
//     return helper_2_test_random(length, start_byte - 1);
// }

// func helper_3_test_random{range_check_ptr}(length: felt, start_byte: felt, size: felt) -> () {
//     alloc_locals;
//     local rlp_len_bytes;
//     local rlp_len;
//     let (rlp : felt*) = alloc();
//     if (size == 0) {
//         return ();
//     }
//     %{
//         from utils.types import Data
//         from utils.helpers import random_bytes

// input = Data.from_bytes(random_bytes(ids.length))
//         ids.rlp_len_bytes = input.to_ints().length
//         segments.write_arg(ids.rlp, input.to_ints().values)
//         ids.rlp_len = len(input.to_ints().values)
//     %}
//     %{
//         print("helper_test_extractData", ids.length, ids.start_byte, ids.size)
//     %}
//     let (res_len_bytes: felt, res_len: felt, res: felt*) = helper_test_extractData(
//         start_byte, size, rlp_len_bytes, rlp_len, rlp
//     );
//     %{
//         print("output", memory.get_range(ids.res, ids.res_len))
//     %}
//     return helper_3_test_random(length, start_byte, size - 1);
// }
