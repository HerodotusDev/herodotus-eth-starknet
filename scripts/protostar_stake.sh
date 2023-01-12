#!/bin/bash

# Note: PROTOSTAR_ACCOUNT_PRIVATE_KEY env variable has to be set.

usage="Usage: ./protostar_stake.sh --contract_address ADDR --relayer_public_key PUB_KEY --relay_asset_contract_address ADDR --relay_amount AMOUNT"

if [[ $* == *"--skip-approval"* ]]; then
    if [ $# -ne $(expr 2 \* 2) ]; then
        printf "Error: invalid number of options provided. Expected 2 options.\n%s\n" "$usage" >&2
        exit 1
    fi
else
    if [ $# -ne $(expr 4 \* 2) ]; then
        printf "Error: invalid number of options provided. Expected 4 options.\n%s\n" "$usage" >&2
        exit 1
    fi
fi

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --contract_address)
            contract_address="$2"
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

echo "###Parameters###"
echo "contract_address: $contract_address"
echo "relayer_public_key: $relayer_public_key"

if [[ $* == *"--skip-approval"* ]]; then
    echo "Skipping relay asset approval. Make sure one hass been set with the right value before staking."
else
    echo "relay_asset_contract_address: $relay_asset_contract_address"
    echo "amount: $relay_amount"
    inputs="$contract_address $relay_amount 0"
    approval=$(protostar -p testnet invoke --function "approve" --contract-address $relay_asset_contract_address --inputs $inputs --max-fee auto --wait-for-acceptance --json)
    if [ $? -eq 0 ]; then
        echo $approval
    else
        echo "Approval KO" && exit 1
    fi
fi

inputs="relayer_public_key=$relayer_public_key"
invokation=$(protostar -p testnet invoke --function "stake" --contract-address $contract_address --inputs $inputs --max-fee auto --wait-for-acceptance --json)

echo $invokation

exit 0