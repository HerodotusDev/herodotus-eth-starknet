#!/bin/bash

# Note: PROTOSTAR_ACCOUNT_PRIVATE_KEY env variable has to be set.
# Example for __DEVNET__: PROTOSTAR_ACCOUNT_PRIVATE_KEY=150029774816543015997477495460890485588

usage="Usage: ./deploy_and_init_contracts.sh [--skip-build] [--skip-stake-approval] --profile XXX --evm_messages_sender ADDR --owner ADDR --relayer_public_key PUB_KEY --relay_asset_contract_address ADDR --relay_amount AMOUNT"

# Example to be ran from root of this repo:
# ./scripts/deploy_and_init_contracts.sh --profile devnet --owner 0x7f7f6980fd051997e518f118ef602e56af072a09301327aa2a3cdef898f3b29  \
# --evm_messages_sender 0x289ba4b1ea70e059d28d721f20adad4e6d0f58ec --relayer_public_key 0x68d47cf3a26d53f5c449b19d08ade1ea71ac9d1dbdd2d37b25048102b5cfa5c \
# --relay_asset_contract_address 0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7 --relay_amount 1

if [ $# -lt $(expr 6 \* 2) ]; then
    echo $usage && exit 1
fi

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
    --skip-build)
        skip_build="true"
        shift
        ;;
    --skip-stake-approval)
        skip_stake_approval="true"
        shift
        ;;
    --profile)
        profile="$2"
        shift
        ;;
    --owner)
        owner="$2"
        shift
        ;;
    --evm_messages_sender)
        evm_messages_sender="$2"
        shift
        ;;
    --relayer_public_key)
        relayer_public_key="$2"
        shift
        ;;
    --relay_asset_contract_address)
        relay_asset_contract_address="$2"
        shift
        ;;
    --relay_amount)
        relay_amount="$2"
        shift
        ;;
    *)
        printf "Unknown option: %s.\n%s\n" "$key" "$usage" >&2
        exit 1
        ;;
    esac
    shift
done

if [ "$profile" != "testnet" ] && [ "$profile" != "devnet" ]; then
    echo "The profile value is neither 'testnet' or 'devnet'"
else
    printf "Using profile: %s\n" $profile
fi

if [ "$skip_build" == "true" ]; then
    echo "Skipping protostar build"
else
    echo "Building contracts..."
    protostar build
    if [ $? -eq 0 ]; then
        echo "Build succeeded"
    else
        echo "Build failed" && exit
    fi
fi

echo "Declaring contracts..."

class_hash_blockhashes_recipient=$(protostar -p $profile declare ./build/EthereumBlockhashesRecipient.json --max-fee auto --json --wait-for-acceptance | jq -r '.class_hash')

class_hash_headers_store=$(protostar -p $profile declare ./build/EthereumHeadersStore.json --max-fee auto --json --wait-for-acceptance | jq -r '.class_hash')

class_hash_evm_facts_registry=$(protostar -p $profile declare ./build/EvmFactsRegistry.json --max-fee auto --json --wait-for-acceptance | jq -r '.class_hash')

printf "BlockhashesRecipient class hash: %s\nHeadersStore class hash: %s\nEvmFactsRegistry class hash: %s\n" "$class_hash_blockhashes_recipient" "$class_hash_headers_store" "$class_hash_evm_facts_registry"

echo "Deploying contracts..."

blockhashes_recipient_addr=$(protostar -p $profile deploy $class_hash_blockhashes_recipient --max-fee auto --json --wait-for-acceptance | jq -r '.contract_address')

headers_store_addr=$(protostar -p $profile deploy $class_hash_headers_store --inputs $blockhashes_recipient_addr --max-fee auto --json --wait-for-acceptance | jq -r '.contract_address')

evm_facts_registry_addr=$(protostar -p $profile deploy $class_hash_evm_facts_registry --inputs $headers_store_addr --max-fee auto --json --wait-for-acceptance | jq -r '.contract_address')

printf "BlockhashesRecipient contract address: %s\nHeadersStore contract address: %s\nEvmFactsRegistry contract address: %s\n" "$blockhashes_recipient_addr" "$headers_store_addr" "$evm_facts_registry_addr"

# Inbox init

inputs="$evm_messages_sender $headers_store_addr $owner $relay_asset_contract_address $relay_amount"
invokation=$(protostar -p $profile invoke --function "initialize" --contract-address $blockhashes_recipient_addr --inputs $inputs --max-fee auto --wait-for-acceptance --json)

echo $invokation

# Stake approval
if [ "$skip_stake_approval" == "true" ]; then
    echo "Skipping relay asset approval. Make sure the allowance is enough to stake."
else
    inputs="$blockhashes_recipient_addr $relay_amount 0"
    approval=$(protostar -p $profile invoke --function "approve" --contract-address $relay_asset_contract_address --inputs $inputs --max-fee auto --wait-for-acceptance --json)
    if [ $? -eq 0 ]; then
        echo $approval
    else
        echo "Approval failed" && exit 1
    fi
fi

# Stake
invokation=$(protostar -p $profile invoke --function "stake" --contract-address $blockhashes_recipient_addr --inputs $relayer_public_key --max-fee auto --wait-for-acceptance --json)

echo $invokation

exit 0
