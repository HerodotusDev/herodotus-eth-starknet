#[contract]
mod CommitmentsInbox {
    use starknet::{ContractAddress, get_caller_address};
    use zeroable::Zeroable;

    struct Storage {
        headers_store: ContractAddress,
        l1_message_sender: felt252,
        owner: ContractAddress
    }

    #[constructor]
    fn constructor(_headers_store: ContractAddress, _l1_message_sender: felt252, _owner: ContractAddress) {
        headers_store::write(_headers_store);
        l1_message_sender::write(_l1_message_sender);
        owner::write(_owner);
    }

    #[view]
    fn get_headers_store() -> ContractAddress {
        headers_store::read()
    }

    #[view]
    fn get_l1_message_sender() -> felt252 {
        l1_message_sender::read()
    }

    #[view]
    fn get_owner() -> ContractAddress {
        owner::read()
    }

    #[external]
    fn transfer_ownership(_new_owner: ContractAddress) {
        let caller = get_caller_address();
        assert(owner::read() == caller, 'Only owner');
        owner::write(_new_owner);
    }

    #[external]
    fn rennounce_ownership() {
        let caller = get_caller_address();
        assert(owner::read() == caller, 'Only owner');
        owner::write(Zeroable::zero());
    }

    #[l1_handler]
    fn receive_commitment(_from_address: felt252, _blockhash: u256, _block_number: u256) {
        // TODO return Result with custom error
        assert(_from_address == l1_message_sender::read(), 'Invalid sender');
        
        // Send to HeadersStore
    }

    #[external]
    fn receive_commitment_owner(_blockhash: u256, _block_number: u256) {
        let caller = get_caller_address();
        assert(owner::read() == caller, 'Only owner');

        // Send to HeadersStore
    }
}
