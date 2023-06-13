// TODO replace account: felt252 with starknet::EthAddress (not supported yet)
#[contract]
mod EVMFactsRegisty {
    use starknet::ContractAddress;
    use herodotus_eth_starknet::utils::{mpt::MPTProof, mmr::MMRProof};

    #[derive(Drop, Serde)]
    enum AccountField {
        StorageHash: (),
        CodeHash: (),
        Balance: (),
        Nonce: ()
    }

    struct Storage {
        headers_store: ContractAddress,
        
        // (account_address, block_number) => value
        storage_hash: LegacyMap::<(felt252, u128), u256>,
        code_hash: LegacyMap::<(felt252, u128), u256>,
        balance: LegacyMap::<(felt252, u128), u256>,
        nonce: LegacyMap::<(felt252, u128), u256>
    }

    #[constructor]
    fn constructor(_headers_store: ContractAddress) {
        headers_store::write(_headers_store);
    }

    #[view]
    fn get_headers_store() -> ContractAddress {
        headers_store::read()
    }

    #[view]
    fn get_account_field(_account: felt252, _block: u128, _field: AccountField) -> u256 {
        match _field {
            AccountField::StorageHash(_) => storage_hash::read((_account, _block)),
            AccountField::CodeHash(_) => code_hash::read((_account, _block)),
            AccountField::Balance(_) => balance::read((_account, _block)),
            AccountField::Nonce(_) => nonce::read((_account, _block))
        }
    }

    #[external]
    fn prove_account(
        _fields: Array<AccountField>,
        _block: u128,
        _account: felt252,
        _mpt_proof: MPTProof,
        _mmr_proof: MMRProof,
        // TODO define type
        _block_header: felt252
    ) {
        // 1. Verify MMR proof for block_header
        // 2. Decode block state root from block_header
        // 3. Verify MPT proof for account
        // 4. Decode account fields
    }

    #[external]
    fn get_storage(
        _block: u128,
        _account: felt252,
        _slot: u256,
        _mpt_proof: MPTProof
        // TODO define type
    ) -> u256 {
        // 1. Assert account storage hash has been proven
        // 2. Verify the MPT proof
        // 3. Verify MPT proof for account
        // 4. Decode account storage
        // 5. Verify storage value
        0
    }
}
