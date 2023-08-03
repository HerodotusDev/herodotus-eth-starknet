use starknet::ContractAddress;
use cairo_lib::data_structures::mmr::proof::Proof;
use cairo_lib::data_structures::mmr::peaks::Peaks;
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
    fn get_slot_value(self: @TContractState, account: felt252, block: u256, slot: u256) -> u256;

    fn prove_account(
        ref self: TContractState, 
        fields: Span<AccountField>, 
        block_header_rlp: Bytes,
        account: Bytes, 
        mpt_proof: Span<Bytes>, 
        mmr_index: usize,
        mmr_peaks: Peaks,
        mmr_proof: Proof, 
    );
    fn prove_storage(
        ref self: TContractState, 
        block: u256, 
        account: felt252, 
        slot: Bytes, 
        mpt_proof: Span<Bytes>
    );
}

#[starknet::contract]
mod EVMFactsRegistry {
    use starknet::ContractAddress;
    use zeroable::Zeroable;
    use super::AccountField;
    use cairo_lib::data_structures::mmr::proof::Proof;
    use cairo_lib::data_structures::mmr::peaks::Peaks;
    use cairo_lib::hashing::poseidon::PoseidonHasher;
    use cairo_lib::utils::types::bytes::{Bytes, BytesTryIntoU256, BytesTryIntoFelt252};
    use cairo_lib::data_structures::eth_mpt::{MPTTrait, MPTNode};
    use cairo_lib::encoding::rlp::{RLPItem, rlp_decode};
    use result::ResultTrait;
    use option::OptionTrait;
    use traits::{Into, TryInto};
    use array::{ArrayTrait, SpanTrait};
    use herodotus_eth_starknet::headers_store::{IHeadersStoreDispatcherTrait, IHeadersStoreDispatcher};

    #[storage]
    struct Storage {
        headers_store: ContractAddress,
        
        // (account_address, block_number) => value
        storage_hash: LegacyMap::<(felt252, u256), u256>,
        code_hash: LegacyMap::<(felt252, u256), u256>,
        balance: LegacyMap::<(felt252, u256), u256>,
        nonce: LegacyMap::<(felt252, u256), u256>,

        // (account_address, block_number, slot) => value
        slot_values: LegacyMap::<(felt252, u256, u256), u256>
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        AccountProven: AccountProven,
        StorageProven: StorageProven
    }

    #[derive(Drop, starknet::Event)]
    struct AccountProven {
        account: felt252,
        block: u256,
        fields: Span<AccountField>
    }

    #[derive(Drop, starknet::Event)]
    struct StorageProven {
        account: felt252,
        block: u256,
        slot: u256,
        value: u256
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

        fn get_slot_value(self: @ContractState, account: felt252, block: u256, slot: u256) -> u256 {
            self.slot_values.read((account, block, slot))
        }

        fn prove_account(
            ref self: ContractState, 
            fields: Span<AccountField>, 
            block_header_rlp: Bytes,
            account: Bytes, 
            mpt_proof: Span<Bytes>, 
            mmr_index: usize,
            mmr_peaks: Peaks,
            mmr_proof: Proof, 
        ) {
            let blockhash = InternalFunctions::poseidon_hash_rlp(block_header_rlp);

            let contract_address = self.headers_store.read();
            let mmr_inclusion = IHeadersStoreDispatcher { contract_address }.verify_mmr_inclusion(mmr_index, blockhash, mmr_peaks, mmr_proof);
            assert(mmr_inclusion, 'MMR inclusion not proven');

            let (decoded_rlp, _) = rlp_decode(block_header_rlp).unwrap();
            let mut state_root: u256 = 0;
            let mut block_number: u256 = 0;
            match decoded_rlp {
                RLPItem::Bytes(_) => panic_with_felt252('Invalid header rlp'),
                RLPItem::List(l) => {
                    // State root is the fourth element in the list
                    // Block number is the ninth element in the list
                    // TODO error handling
                    state_root = (*l.at(3)).try_into().unwrap();
                    block_number = (*l.at(8)).try_into().unwrap();
                },
            };

            //let mpt = MPTTrait::new(state_root);
            // TODO error handling
            //let rlp_account = mpt.verify(account, mpt_proof).unwrap();

            // TODO mocked verification, keccak not available
            let leaf_node = MPTTrait::decode_rlp_node(*mpt_proof.at(mpt_proof.len() - 1)).unwrap();
            let mut rlp_account = ArrayTrait::new().span();
            match leaf_node {
                MPTNode::Branch((_, _)) => panic_with_felt252('Invalid leaf node'),
                MPTNode::Extension((_, _)) => panic_with_felt252('Invalid leaf node'),
                MPTNode::Leaf((_, v)) => {
                    rlp_account = v;
                },
            }

            let (decoded_account, _) = rlp_decode(rlp_account).unwrap();
            let mut account_felt252 = 0;
            match decoded_account {
                RLPItem::Bytes(_) => panic_with_felt252('Invalid account rlp'),
                RLPItem::List(l) => {
                    let mut i: usize = 0;
                    account_felt252 = account.try_into().unwrap();
                    loop {
                        if i == fields.len() {
                            break ();
                        }

                        let field = fields.at(i);
                        match field {
                            AccountField::StorageHash(_) => {
                                let storage_hash: u256 = (*l.at(2)).try_into().unwrap();
                                self.storage_hash.write((account_felt252, block_number), storage_hash);
                            },
                            AccountField::CodeHash(_) => {
                                let code_hash: u256 = (*l.at(3)).try_into().unwrap();
                                self.code_hash.write((account_felt252, block_number), code_hash);
                            },
                            AccountField::Balance(_) => {
                                let balance: u256 = (*l.at(0)).try_into().unwrap();
                                self.balance.write((account_felt252, block_number), balance);
                            },
                            AccountField::Nonce(_) => {
                                let nonce: u256 = (*l.at(1)).try_into().unwrap();
                                self.nonce.write((account_felt252, block_number), nonce);
                            },
                        };

                        i += 1;
                    };
                },
            };

            self.emit(Event::AccountProven(AccountProven {
                account: account_felt252,
                block: block_number,
                fields
            }));
        }

        fn prove_storage(
            ref self: ContractState, 
            block: u256, 
            account: felt252, 
            slot: Bytes,
            mpt_proof: Span<Bytes>
        ) {
            let storage_hash = self.storage_hash.read((account, block));
            assert(storage_hash != Zeroable::zero(), 'Storage hash not proven');

            //let mpt = MPTTrait::new(storage_hash);
            // TODO error handling
            //let value = mpt.verify(slot, mpt_proof).unwrap();

            // TODO mocked verification, keccak not available
            let leaf_node = MPTTrait::decode_rlp_node(*mpt_proof.at(mpt_proof.len() - 1)).unwrap();
            let mut value = ArrayTrait::new().span();
            match leaf_node {
                MPTNode::Branch((_, _)) => panic_with_felt252('Invalid leaf node'),
                MPTNode::Extension((_, _)) => panic_with_felt252('Invalid leaf node'),
                MPTNode::Leaf((_, v)) => {
                    value = v;
                },
            }

            // TODO error handling
            let slot_u256 = slot.try_into().unwrap();
            let value_u256 = value.try_into().unwrap();

            self.slot_values.write((account, block, slot_u256), value_u256);

            self.emit(Event::StorageProven(StorageProven {
                account,
                block,
                slot: slot_u256,
                value: value_u256
            }));
        }
    }

    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        fn poseidon_hash_rlp(rlp: Bytes) -> felt252 {
            // TODO refactor hashing logic
            let mut rlp_felt_arr: Array<felt252> = ArrayTrait::new();
            let mut i: usize = 0;
            loop {
                if i >= rlp.len() {
                    break ();
                }

                rlp_felt_arr.append((*rlp.at(i)).into());
                i += 1;
            };
            
            PoseidonHasher::hash_many(rlp_felt_arr.span())
        }
    }
}
