#!/bin/bash

if [[ $* == *"--skip-build"* ]]; then
    echo "Skipping protostar build"
else
    protostar build
    if [ $? -eq 0 ]; then
        echo "Build succeeded"
    else
        echo "Build failed" && exit
    fi
fi

echo "Declaring contracts..."

# Note: PROTOSTAR_ACCOUNT_PRIVATE_KEY env variable has to be set.

class_hash_l1_messages_proxy=$(protostar -p testnet declare ./build/L1MessagesProxy.json --max-fee auto --json --wait-for-acceptance | jq -r '.class_hash')
class_hash_l1_headers_store=$(protostar -p testnet declare ./build/L1HeadersStore.json --max-fee auto --json --wait-for-acceptance | jq -r '.class_hash')
class_hash_l1_facts_registry=$(protostar -p testnet declare ./build/FactsRegistry.json --max-fee auto --json --wait-for-acceptance | jq -r '.class_hash')

printf "L1MessagesProxy class hash: %s\nL1HeadersStore class hash: %s\nL1FactsRegistry class hash: %s\n" "$class_hash_l1_messages_proxy" "$class_hash_l1_headers_store" "$class_hash_l1_facts_registry"

echo "Deploying contracts..."

l1_messages_proxy_addr=$(protostar -p testnet deploy $class_hash_l1_messages_proxy --max-fee auto --json --wait-for-acceptance | jq -r '.contract_address')
l1_headers_store_addr=$(protostar -p testnet deploy $class_hash_l1_headers_store --inputs $l1_messages_proxy_addr --max-fee auto --json --wait-for-acceptance | jq -r '.contract_address')
l1_facts_registry_addr=$(protostar -p testnet deploy $class_hash_l1_facts_registry --inputs $l1_headers_store_addr --max-fee auto --json --wait-for-acceptance | jq -r '.contract_address')

printf "L1MessagesProxy contract address: %s\nL1HeadersStore contract address: %s\nL1FactsRegistry contract address: %s\n" "$l1_messages_proxy_addr" "$l1_headers_store_addr" "$l1_facts_registry_addr"

echo "Note: do not forget to initialize the L1MessagesProxy contract at "$l1_messages_proxy_addr" manually"

exit 0