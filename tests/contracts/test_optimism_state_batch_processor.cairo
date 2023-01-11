%lang starknet
%builtins pedersen range_check bitwise

@contract_interface
namespace L2StateRootsProcessor {
    func receive_batch_root(
        from_address: felt,
        batch_index: felt,
        batch_start: felt,
        batch_root_word_1: felt,
        batch_root_word_2: felt,
        batch_root_word_3: felt,
        batch_root_word_4: felt
    ) {
    }
}

@external
func __setup__{syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    return ();
}