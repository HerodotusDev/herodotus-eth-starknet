#[contract]
mod CommitmentsInbox {
    use starknet::ContractAddress;

    struct Storage {
        headers_store: ContractAddress,
        l1_message_sender: felt252
    }

    #[constructor]
    fn constructor(_headers_store: ContractAddress, _l1_message_sender: felt252) {
        headers_store::write(_headers_store);
        l1_message_sender::write(_l1_message_sender);
    }

    #[view]
    fn get_headers_store() -> ContractAddress {
        headers_store::read()
    }

    #[view]
    fn get_l1_message_sender() -> felt252 {
        l1_message_sender::read()
    }

    #[l1_handler]
    fn receive_commitment(_from_address: felt252, _blockhash: u256, _block_number: u256) {
        // TODO return Result with custom error
        assert(_from_address == l1_message_sender::read(), 'Invalid sender');
        
        // Send to HeadersStore
    }
}
