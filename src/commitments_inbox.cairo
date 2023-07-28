use starknet::ContractAddress;
use option::OptionTrait;

#[starknet::interface]
trait ICommitmentsInbox<TContractState> {
    fn get_headers_store(self: @TContractState) -> ContractAddress;
    fn get_l1_message_sender(self: @TContractState) -> felt252;
    fn get_owner(self: @TContractState) -> ContractAddress;

    fn transfer_ownership(ref self: TContractState, new_owner: ContractAddress);
    fn rennounce_ownership(ref self: TContractState);

    fn receive_commitment(self: @TContractState, from_address: felt252, blockhash: u256, block_number: u256);
    fn receive_commitment_owner(self: @TContractState, blockhash: u256, block_number: u256);
}

#[starknet::contract]
mod CommitmentsInbox {
    use starknet::{ContractAddress, get_caller_address};
    use zeroable::Zeroable;

    #[storage]
    struct Storage {
        headers_store: ContractAddress,
        l1_message_sender: felt252,
        owner: ContractAddress
    }

    #[constructor]
    fn constructor(ref self: ContractState, headers_store: ContractAddress, l1_message_sender: felt252, owner: Option<ContractAddress>) {
        self.headers_store.write(headers_store);
        self.l1_message_sender.write(l1_message_sender);

        match owner {
            Option::Some(o) => self.owner.write(o),
            Option::None(_) => self.owner.write(get_caller_address())
        };
    }

    #[external(v0)]
    impl CommitmentsInbox of super::ICommitmentsInbox<ContractState> {
        fn get_headers_store(self: @ContractState) -> ContractAddress {
            self.headers_store.read()
        }

        fn get_l1_message_sender(self: @ContractState) -> felt252 {
            self.l1_message_sender.read()
        }

        fn get_owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }

        fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
            let caller = get_caller_address();
            assert(self.owner.read() == caller, 'Only owner');
            self.owner.write(new_owner);
        }

        fn rennounce_ownership(ref self: ContractState) {
            let caller = get_caller_address();
            assert(self.owner.read() == caller, 'Only owner');
            self.owner.write(Zeroable::zero());
        }

        // TODO add [l1_handler]
        fn receive_commitment(self: @ContractState, from_address: felt252, blockhash: u256, block_number: u256) {
            // TODO return Result with custom error
            assert(from_address == self.l1_message_sender.read(), 'Invalid sender');
            
            // Send to HeadersStore
        }

        fn receive_commitment_owner(self: @ContractState, blockhash: u256, block_number: u256) {
            let caller = get_caller_address();
            assert(self.owner.read() == caller, 'Only owner');

            // Send to HeadersStore
        }
    }
}
