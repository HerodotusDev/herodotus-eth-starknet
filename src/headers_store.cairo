

//#[contract]
//mod HeadersStore {
    //use starknet::get_caller_address;
    //use starknet::ContractAddress;

    //struct Storage {
        //commitments_inbox: ContractAddress,
        //mmr_root: u256,
        //mmr_size: u256,
        //// block_number => blockhash
        //received_blocks: LegacyMap::<u256, u256>
    //}

    //#[view]
    //fn get_mmr_root() -> u256 {
        //mmr_root::read()
    //}

    //#[view]
    //fn get_mmr_size() -> u256 {
        //mmr_size::read()
    //}

    //#[view]
    //fn get_received_block(_block_number: u256) -> u256 {
        //received_blocks::read(_block_number)
    //}

    //#[external]
    //fn receive_hash(_blockhash: u256, _block_number: u256) {
        //let caller = get_caller_address();
        //assert(caller == commitments_inbox::read(), 'Only CommitmentsInbox');

        //received_blocks::write(_block_number, _blockhash);
    //}

    //#[external]
    //fn process_received_block(
        //_block_number: u256, 
        //_header_rlp: Array<u256>,
        //_mmr_peaks: Array<u256>,
    //) {
        //let blockhash = received_blocks::read(_block_number);
        //// 1. Validate the header rlp against the blockhash
        //// 2. Update the MMR
    //}
//}
