use starknet::ContractAddress;
use cairo_lib::data_structures::mmr::proof::Proof;
use cairo_lib::utils::types::bytes::Bytes;

#[derive(Drop, Serde)]
enum AccountField {
    StorageHash: (),
    CodeHash: (),
    Balance: (),
    Nonce: ()
}

#[starknet::interface]
trait IEVMFactsRegistry<TContractState> {
    fn get_headers_store(self: @TContractState) -> ContractAddress;

    fn get_account_field(self: @TContractState, account: felt252, block: u256, field: AccountField) -> u256;

    fn prove_account(
        ref self: TContractState, 
        fields: Span<AccountField>, 
        block: u256, 
        account: felt252, 
        mpt_proof: Span<Bytes>, 
        mmr_proof: Proof, 
        block_header: Bytes
    );
    fn get_storage(
        self: @TContractState, 
        block: u256, 
        account: felt252, 
        slot: Bytes, 
        mpt_proof: Span<Bytes>
    ) -> u256;
}

#[starknet::contract]
mod EVMFactsRegistry {
    use starknet::ContractAddress;
    use zeroable::Zeroable;
    use super::AccountField;
    use cairo_lib::data_structures::mmr::proof::Proof;
    use cairo_lib::utils::types::bytes::{Bytes, BytesTryIntoU256};
    use cairo_lib::data_structures::eth_mpt::MPTTrait;
    use result::ResultTrait;
    use option::OptionTrait;
    use traits::TryInto;

    #[storage]
    struct Storage {
        headers_store: ContractAddress,
        
        // (account_address, block_number) => value
        storage_hash: LegacyMap::<(felt252, u256), u256>,
        code_hash: LegacyMap::<(felt252, u256), u256>,
        balance: LegacyMap::<(felt252, u256), u256>,
        nonce: LegacyMap::<(felt252, u256), u256>
    }

    #[constructor]
    fn constructor(ref self: ContractState, headers_store: ContractAddress) {
        self.headers_store.write(headers_store);
    }

    #[external(v0)]
    impl EVMFactsRegistry of super::IEVMFactsRegistry<ContractState> {
        fn get_headers_store(self: @ContractState) -> ContractAddress {
            self.headers_store.read()
        }

        fn get_account_field(self: @ContractState, account: felt252, block: u256, field: AccountField) -> u256 {
            match field {
                AccountField::StorageHash(_) => self.storage_hash.read((account, block)),
                AccountField::CodeHash(_) => self.code_hash.read((account, block)),
                AccountField::Balance(_) => self.balance.read((account, block)),
                AccountField::Nonce(_) => self.nonce.read((account, block))
            }
        }

        fn prove_account(
            ref self: ContractState, 
            fields: Span<AccountField>, 
            block: u256, 
            account: felt252, 
            mpt_proof: Span<Bytes>, 
            mmr_proof: Proof, 
            block_header: Bytes
        ) {
            // TODO
            // 1. Verify MMR proof for block_header
            // 2. Decode block state root from block_header
            // 3. Verify MPT proof for account
            // 4. Decode account fields
        }

        fn get_storage(
            self: @ContractState, 
            block: u256, 
            account: felt252, 
            slot: Bytes,
            mpt_proof: Span<Bytes>
        ) -> u256 {
            let storage_hash = self.storage_hash.read((account, block));
            assert(storage_hash != Zeroable::zero(), 'Storage hash not proven');

            let mpt = MPTTrait::new(storage_hash);
            // TODO error handling
            let value = mpt.verify(slot, mpt_proof).unwrap();
            let value_u256: Option<u256> = value.try_into();

            // TODO error handling
            value_u256.unwrap()
        }
    }
}
