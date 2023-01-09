%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.starknet.common.syscalls import get_caller_address, get_contract_address
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.hash_state import hash_felts
from starkware.cairo.common.math_cmp import is_not_zero, is_le

from lib.types import Keccak256Hash
from lib.keccak_compare import keccak_compare
from starkware.cairo.common.uint256 import Uint256

// L1HeadersStore simplified interface
@contract_interface
namespace IL1HeadersStore {
    func receive_from_l1(parent_hash_len: felt, parent_hash: felt*, block_number: felt) {
    }

    func get_commitments_parent_hash(block_number: felt) -> (res: Keccak256Hash) {
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

// Starknet address of the L1 headers store contract
@storage_var
func _l1_headers_store_addr() -> (res: felt) {
}

// Contract owner
@storage_var
func _owner() -> (res: felt) {
}

// Optimistic message relayer public key
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

//
// @dev Gets the initialized state of the contract.
// @return The initialized state of the contract (1 for initialized, 0 for uninitialized).
//
@view
func get_initialized{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    return _initialized.read();
}

//
// @dev Gets the address of the L1 messages sender contract.
// @return The address of the L1 messages sender contract.
//
@view
func get_l1_messages_sender{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    return _l1_messages_sender.read();
}

//
// @dev Gets the address of the L1 headers store contract.
// @return The address of the L1 headers store contract.
//
@view
func get_l1_headers_store_addr{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ) -> (res: felt) {
    return _l1_headers_store_addr.read();
}

//
// @dev Gets the owner address of the contract.
// @return The owner address of the contract.
//
@view
func get_owner{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res: felt) {
    return _owner.read();
}

//
// @dev Gets the public key of the message relayer.
// @return The public key of the message relayer.
//
@view
func get_relayer_pubkey{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    return _relayer_pubkey.read();
}

//
// @dev Gets the amount of stake held by the message relayer.
// @return The amount of stake held by the message relayer.
//
@view
func get_relayer_stake{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    return _relayer_stake.read();
}

//
// @dev Gets the address of the message relayer.
// @return The address of the message relayer.
//
@view
func get_relayer_addr{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    return _relayer_addr.read();
}

//
// @dev Gets the required stake amount to relay.
// @return The required stake amount to relay.
//
@view
func get_relayer_required_stake_amount{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
}() -> (res: felt) {
    return _relayer_required_stake_amount.read();
}

//
// @dev Gets the contract address of the relayer's staked asset.
// @return The contract address of the relayer's staked asset.
//
@view
func get_relayer_stake_asset_addr{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ) -> (res: felt) {
    return _relayer_stake_asset_addr.read();
}

//
// @dev Initializes this contract with the specified values.
// @param l1_messages_sender The address of the L1 messages sender contract.
// @param l1_headers_store_addr The address of the L1 headers store contract.
// @param owner The address of the owner of the contract.
// @param relay_asset_addr The address of the relay asset contract (e.g. USDC ERC20).
// @param required_in_asset_to_relay The exact amount of asset required to be staked by relayers.
//
@external
func initialize{pedersen_ptr: HashBuiltin*, syscall_ptr: felt*, range_check_ptr}(
    l1_messages_sender: felt,
    l1_headers_store_addr: felt,
    owner: felt,
    relay_asset_addr: felt,
    required_in_asset_to_relay: felt,
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
    _relayer_required_stake_amount.write(required_in_asset_to_relay);

    let (relayer_stake_asset_addr) = _relayer_stake_asset_addr.read();
    assert relayer_stake_asset_addr = 0;
    _relayer_stake_asset_addr.write(relay_asset_addr);
    return ();
}

//
// @dev Increases the required stake amount to relay.
// @param new_required_stake_amount The new required stake amount to relay.
//
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

//
// @dev Changes the owner of the contract.
// @param new_owner The new owner of the contract.
//
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

//
// @dev Changes the contract addresses of the L1 messages sender and L1 headers store.
// @param new_sender_addr The new address of the L1 messages sender contract.
// @param new_headers_store_addr The new address of the L1 headers store contract.
//
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

//
// @dev Changes the public key of the message relayer.
// @param relayer_pubkey The new public key of the message relayer.
//
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

//
// This function allows a relayer to optimistically relay an L1 message to the L1 headers store.
// @param parent_hash_word_1: the first word of the parent block's hash
// @param parent_hash_word_2: the second word of the parent block's hash
// @param parent_hash_word_3: the third word of the parent block's hash
// @param parent_hash_word_4: the fourth word of the parent block's hash
// @param block_number: the number of the block being relayed (from the source chain)
// @param signature_len: the length of the signature parameter
// @param signature: a pointer to an array of felt values representing the signature to verify
// Preconditions
// The parent hash must have 4 words.
// The relayer must have the required amount of tokens staked.
// The ECDSA signature must be valid for the message.
// Postconditions
// The message will be optimistically relayed to the L1 headers store.
//
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

//
// This function receives a message from the L1 layer and processes it.
// The message is validated and L1 headers store.
// @param from_address: the sender's address from L1.
// @param parent_hash_word_1: the first word of the parent hash of the message.
// @param parent_hash_word_2: the second word of the parent hash of the message.
// @param parent_hash_word_3: the third word of the parent hash of the message.
// @param parent_hash_word_4: the fourth word of the parent hash of the message.
// @param block_number: the block number of the message.
// @param caller_origin_addr: the origin address of the caller.
// Preconditions
// The from_address must match the address of the L1 message sender.
// Postconditions
// If the optimsitic message is valid, it will be relayed to the L1 headers store without slashing the relayer.
// Else, the relayer's stake will be slashed and the correct message will be relayed to the L1 headers store.
// In the case where the message had not been previously optimistically relayed, it will also be forwarded to the L1 headers store.
//
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
    let (local optimistic_message) = IL1HeadersStore.get_commitments_parent_hash(
        contract_address=contract_addr, block_number=block_number
    );
    local exising_blockhash = optimistic_message.word_1 + optimistic_message.word_2 +
        optimistic_message.word_3 + optimistic_message.word_4;
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
            // Relay L1 message
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
}

//
// This function allows a relayer to stake the required amount of tokens to become eligible to relay L1 messages.
// @notice Requires an external upfront approval of relayer_required_stake_amount
// @param relayer_public_key: a felt representing the relayer's public key.
// Preconditions
// The contract must be initialized.
// The relayer must not have already staked tokens (unless it had unstaked or had been slashed).
// Postconditions
// The relayer will have staked the required amount of tokens to become eligible to relay L1 messages.
// The relayer's public key and address will be recorded in the contract.
//
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

//
// This function allows a relayer to unstake their tokens and withdraw them from the contract.
// Preconditions
// The relayer must have staked tokens and be the caller of this function.
// Postconditions
// The relayer's staked tokens will be transferred to their address.
// The relayer's public key and address will be cleared from the contract.
//
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

//
// This function slashes the stake of a relayer and rewards the caller if specified.
// @param asset_address: the address of the asset to be slashed.
// @param slash_amount: the amount of the asset to be slashed.
// @param caller_origin_addr: the address of the caller.
// If this is not zero, the caller will be rewarded with the slashed tokens.
// Preconditions
// The relayer must have staked tokens.
// Postconditions
// The relayer's staked tokens will be transferred to either the caller's address (if caller_origin_addr is not zero) or nowhere.
// The relayer's stake in the contract will be set to zero.
//
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

//
// This function sends a message with a given parent hash and block number to the next L1 headers store.
// @param contract_addr: the address of the L1 headers store contract.
// @param block_number: the block number of the message.
// @param parent_hash_word_1: the first word of the parent hash of the message.
// @param parent_hash_word_2: the second word of the parent hash of the message.
// @param parent_hash_word_3: the third word of the parent hash of the message.
// @param parent_hash_word_4: the fourth word of the parent hash of the message.
// Preconditions
// The parent hash must have 4 words.
// Postconditions
// The message will be sent to the L1 headers store.
//
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
