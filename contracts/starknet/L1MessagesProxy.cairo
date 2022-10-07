%lang starknet
%builtins pedersen range_check ecdsa

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.starknet.common.syscalls import get_caller_address, get_contract_address
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.hash_state import hash_felts
from starkware.cairo.common.math_cmp import is_not_zero, is_le

from starknet.types import Keccak256Hash
from starknet.lib.keccak_compare import keccak_compare
from starkware.cairo.common.uint256 import Uint256

// L1HeadersStore simplified interface
@contract_interface
namespace IL1HeadersStore {
    func receive_from_l1(parent_hash_len: felt, parent_hash: felt*, block_number: felt) {
    }

    func get_parent_hash(block_number: felt) -> (res: Keccak256Hash) {
    }
}

// ERC20 token interface
@contract_interface
namespace IERC20 {
    func name() -> (name: felt) {
    }

    func symbol() -> (symbol: felt) {
    }

    func decimals() -> (decimals: felt) {
    }

    func totalSupply() -> (totalSupply: Uint256) {
    }

    func balanceOf(account: felt) -> (balance: Uint256) {
    }

    func allowance(owner: felt, spender: felt) -> (remaining: Uint256) {
    }

    func transfer(recipient: felt, amount: Uint256) -> (success: felt) {
    }

    func transferFrom(sender: felt, recipient: felt, amount: Uint256) -> (success: felt) {
    }

    func approve(spender: felt, amount: Uint256) -> (success: felt) {
    }
}

// L1 address allowed to send messages to this contract
@storage_var
func _l1_messages_sender() -> (res: felt) {
}

// Starknet address of the he
@storage_var
func _l1_headers_store_addr() -> (res: felt) {
}

// Contract owner
@storage_var
func _owner() -> (res: felt) {
}

// Optimistic message relayer pubkey
@storage_var
func _relayer_pubkey() -> (res: felt) {
}

// Message relayer stake amount
@storage_var
func _relayer_stake() -> (res: felt) {
}

// Relayer address
@storage_var
func _relayer_addr() -> (res: felt) {
}

// Required stake amount in stake asset to relay
@storage_var
func _relayer_required_stake_amount() -> (res: felt) {
}

// Contract address of relayer's staked asset
@storage_var
func _relayer_stake_asset_addr() -> (res: felt) {
}

// Indicates if contract has already been initialized
@storage_var
func _initialized() -> (res: felt) {
}

//###################################################
//                   VIEW FUNCTIONS
//###################################################

@view
func get_initialized{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    return _initialized.read();
}

@view
func get_l1_messages_sender{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    return _l1_messages_sender.read();
}

@view
func get_l1_headers_store_addr{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ) -> (res: felt) {
    return _l1_headers_store_addr.read();
}

@view
func get_owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res: felt) {
    return _owner.read();
}

@view
func get_relayer_pubkey{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    return _relayer_pubkey.read();
}

@view
func get_relayer_stake{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    return _relayer_stake.read();
}

@view
func get_relayer_addr{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    return _relayer_addr.read();
}

@view
func get_relayer_required_stake_amount{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
}() -> (res: felt) {
    return _relayer_required_stake_amount.read();
}

@view
func get_relayer_stake_asset_addr{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ) -> (res: felt) {
    return _relayer_stake_asset_addr.read();
}

// Initializes the contract
@external
func initialize{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    l1_messages_sender: felt,
    l1_headers_store_addr: felt,
    owner: felt,
    relay_asset_addr: felt,
    minimum_required_in_asset_to_relay: felt,
) {
    let (initialized) = _initialized.read();
    assert initialized = 0;
    _initialized.write(1);
    _l1_messages_sender.write(l1_messages_sender);
    _l1_headers_store_addr.write(l1_headers_store_addr);
    _owner.write(owner);

    // Relayer default settings
    let (relayer_required_stake_amount) = _relayer_required_stake_amount.read();
    assert relayer_required_stake_amount = 0;
    _relayer_required_stake_amount.write(minimum_required_in_asset_to_relay);

    let (relayer_stake_asset_addr) = _relayer_stake_asset_addr.read();
    assert relayer_stake_asset_addr = 0;
    _relayer_stake_asset_addr.write(relay_asset_addr);
    return ();
}

@external
func increase_required_stake_amount{
    pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr
}(new_required_stake_amount: felt) {
    alloc_locals;

    let (caller) = get_caller_address();
    let (current_owner) = _owner.read();

    assert caller = current_owner;

    let (relayer_required_stake_amount) = _relayer_required_stake_amount.read();

    local should_not_update = is_le(new_required_stake_amount, relayer_required_stake_amount);

    assert should_not_update = 0;

    _relayer_required_stake_amount.write(new_required_stake_amount);
    return ();
}

@external
func change_owner{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    new_owner: felt
) {
    let (caller) = get_caller_address();
    let (current_owner) = _owner.read();

    assert caller = current_owner;
    _owner.write(new_owner);
    return ();
}

@external
func change_contract_addresses{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    new_sender_addr: felt, new_headers_store_addr: felt
) {
    let (caller) = get_caller_address();
    let (current_owner) = _owner.read();

    assert caller = current_owner;

    _l1_messages_sender.write(new_sender_addr);
    _l1_headers_store_addr.write(new_headers_store_addr);
    return ();
}

@external
func change_relayer_pubkey{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    relayer_pubkey: felt
) {
    let (caller) = get_caller_address();
    let (current_owner) = _owner.read();

    assert caller = current_owner;

    _relayer_pubkey.write(relayer_pubkey);
    return ();
}

@external
func relay_optimistic{
    pedersen_ptr: HashBuiltin*, ecdsa_ptr: SignatureBuiltin*, syscall_ptr: felt*, range_check_ptr
}(
    parent_hash_word_1: felt,
    parent_hash_word_2: felt,
    parent_hash_word_3: felt,
    parent_hash_word_4: felt,
    block_number: felt,
    signature_len: felt,
    signature: felt*,
) {
    alloc_locals;
    let (relayer_pubkey) = _relayer_pubkey.read();

    // Check that the relayer has enough staked to relay
    let (relayer_stake) = _relayer_stake.read();
    let (relayer_required_stake_amount) = _relayer_required_stake_amount.read();

    assert relayer_required_stake_amount = relayer_stake;

    let (local msg) = alloc();

    assert msg[0] = parent_hash_word_1;
    assert msg[1] = parent_hash_word_2;
    assert msg[2] = parent_hash_word_3;
    assert msg[3] = parent_hash_word_4;
    assert msg[4] = block_number;

    local sig_r = signature[0];
    local sig_s = signature[1];

    let (local msg_hash) = hash_felts{hash_ptr=pedersen_ptr}(msg, 5);
    verify_ecdsa_signature(
        message=msg_hash, public_key=relayer_pubkey, signature_r=sig_r, signature_s=sig_s
    );

    let (contract_addr) = _l1_headers_store_addr.read();

    let (local parent_hash: felt*) = alloc();
    assert parent_hash[0] = parent_hash_word_1;
    assert parent_hash[1] = parent_hash_word_2;
    assert parent_hash[2] = parent_hash_word_3;
    assert parent_hash[3] = parent_hash_word_4;

    IL1HeadersStore.receive_from_l1(
        contract_address=contract_addr,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    return ();
}

@l1_handler
func receive_from_l1{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    from_address: felt,
    parent_hash_word_1: felt,
    parent_hash_word_2: felt,
    parent_hash_word_3: felt,
    parent_hash_word_4: felt,
    block_number: felt,
    caller_origin_addr: felt,
) {
    alloc_locals;
    let (l1_sender) = _l1_messages_sender.read();
    assert from_address = l1_sender;

    let (contract_addr) = _l1_headers_store_addr.read();

    // Check if message was relayed optimistically
    let (local optimistic_message) = IL1HeadersStore.get_parent_hash(
        contract_address=contract_addr, block_number=block_number
    );
    local exising_blockhash = optimistic_message.word_1 + optimistic_message.word_2 + optimistic_message.word_3 + optimistic_message.word_4;
    local overrides_optimistic = is_not_zero(exising_blockhash);

    local parent_hash_as_keccak: Keccak256Hash = Keccak256Hash(
        word_1=parent_hash_word_1,
        word_2=parent_hash_word_2,
        word_3=parent_hash_word_3,
        word_4=parent_hash_word_4,
        );

    if (overrides_optimistic == 1) {
        let (local was_message_correct) = keccak_compare(parent_hash_as_keccak, optimistic_message);

        if (was_message_correct == 0) {
            let (relayer_stake_asset_addr) = _relayer_stake_asset_addr.read();
            let (relayer_required_stake_amount) = _relayer_required_stake_amount.read();

            slash(relayer_stake_asset_addr, relayer_required_stake_amount, caller_origin_addr);
            return send_message(
                contract_addr,
                block_number,
                parent_hash_word_1,
                parent_hash_word_2,
                parent_hash_word_3,
                parent_hash_word_4,
            );
        } else {
            // Relay L1 message
            return send_message(
                contract_addr,
                block_number,
                parent_hash_word_1,
                parent_hash_word_2,
                parent_hash_word_3,
                parent_hash_word_4,
            );
        }
    } else {
        return send_message(
            contract_addr,
            block_number,
            parent_hash_word_1,
            parent_hash_word_2,
            parent_hash_word_3,
            parent_hash_word_4,
        );
    }
}

// Requires an external upfront approval of relayer_required_stake_amount
@external
func stake{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    relayer_public_key: felt
) {
    alloc_locals;

    let (relayer_stake) = _relayer_stake.read();

    assert relayer_stake = 0;

    let (initialized) = _initialized.read();
    assert initialized = 1;

    let (caller_addr) = get_caller_address();
    let (contract_address) = get_contract_address();
    let (relayer_stake_asset_addr) = _relayer_stake_asset_addr.read();
    let (local relayer_required_stake_amount) = _relayer_required_stake_amount.read();

    let amount: Uint256 = Uint256(relayer_required_stake_amount, 0);

    IERC20.transferFrom(
        contract_address=relayer_stake_asset_addr,
        sender=caller_addr,
        recipient=contract_address,
        amount=amount,
    );

    _relayer_stake.write(relayer_required_stake_amount);
    let (relayer_pubkey) = _relayer_pubkey.read();

    _relayer_pubkey.write(relayer_public_key);
    let (relayer_addr) = _relayer_addr.read();
    _relayer_addr.write(caller_addr);
    return ();
}

@external
func unstake{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}() {
    alloc_locals;
    let (relayer_pubkey) = _relayer_pubkey.read();
    assert relayer_pubkey = 1;

    let (caller_addr) = get_caller_address();
    let (relayer_addr) = _relayer_addr.read();

    assert relayer_addr = caller_addr;

    _relayer_addr.write(0);
    _relayer_pubkey.write(0);

    let (contract_address) = get_contract_address();
    let (relayer_stake_asset_addr) = _relayer_stake_asset_addr.read();
    let (relayer_stake) = _relayer_stake.read();

    let amount: Uint256 = Uint256(relayer_stake, 0);
    IERC20.transfer(
        contract_address=relayer_stake_asset_addr, recipient=caller_addr, amount=amount
    );

    _relayer_stake.write(0);
    return ();
}

func slash{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    asset_address: felt, slash_amount: felt, caller_origin_addr: felt
) {
    alloc_locals;
    let (relayer_stake_asset_addr) = _relayer_stake_asset_addr.read();
    let (contract_address) = get_contract_address();

    let amount: Uint256 = Uint256(slash_amount, 0);
    local should_reward = is_not_zero(caller_origin_addr);

    let (relayer_stake) = _relayer_stake.read();
    _relayer_stake.write(0);

    if (should_reward == 1) {
        IERC20.transfer(
            contract_address=relayer_stake_asset_addr, recipient=caller_origin_addr, amount=amount
        );
        return ();
    }

    return ();
}

func send_message{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    contract_addr: felt,
    block_number: felt,
    parent_hash_word_1: felt,
    parent_hash_word_2: felt,
    parent_hash_word_3: felt,
    parent_hash_word_4: felt,
) {
    alloc_locals;

    let (local parent_hash: felt*) = alloc();
    assert parent_hash[0] = parent_hash_word_1;
    assert parent_hash[1] = parent_hash_word_2;
    assert parent_hash[2] = parent_hash_word_3;
    assert parent_hash[3] = parent_hash_word_4;

    IL1HeadersStore.receive_from_l1(
        contract_address=contract_addr,
        parent_hash_len=4,
        parent_hash=parent_hash,
        block_number=block_number,
    );
    return ();
}
