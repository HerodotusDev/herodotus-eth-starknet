#[contract]
mod CommitmentsInbox {
    use starknet::ContractAddress;

    struct Storage {
        headers_store: ContractAddress,
    }

    #[constructor]
    fn constructor(_headers_store: ContractAddress) {
        headers_store::write(_headers_store);
    }

    #[view]
    fn get_headers_store() -> ContractAddress {
        headers_store::read()
    }

    #[l1_handler]
    fn receive_commitment(_blockhash: u256, _block_number: u256) {
        // TODO verify origin caller address
        
        // Send to HeadersStore
    }
}
