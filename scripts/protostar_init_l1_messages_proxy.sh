#!/bin/bash

# Note: PROTOSTAR_ACCOUNT_PRIVATE_KEY env variable has to be set.

usage="Usage: ./protostar_init_l1_messages_proxy.sh --contract-address ADDR --l1_messages_sender ADDR --l1_headers_store_addr ADDR --owner ADDR --relay_asset_addr ADDR --required_in_asset_to_relay XXX"

if [ $# -ne $(expr 6 \* 2) ]; then
    printf "Error: invalid number of options provided. Expected 6 options.\n%s\n" "$usage" >&2
    exit 1
fi

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --contract_address)
            contract_address="$2"
            shift
        ;;
        --l1_messages_sender)
            l1_messages_sender="$2"
            shift
        ;;
        --l1_headers_store_addr)
            l1_headers_store_addr="$2"
            shift
        ;;
        --owner)
            owner="$2"
            shift
        ;;
        --relay_asset_addr)
            relay_asset_addr="$2"
            shift
        ;;
        --required_in_asset_to_relay)
            required_in_asset_to_relay="$2"
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
echo "l1_messages_sender: $l1_messages_sender"
echo "l1_headers_store_addr: $l1_headers_store_addr"
echo "owner: $owner"
echo "relay_asset_addr: $relay_asset_addr"
echo "required_in_asset_to_relay: $required_in_asset_to_relay"

inputs="l1_messages_sender=$l1_messages_sender l1_headers_store_addr=$l1_headers_store_addr owner=$owner relay_asset_addr=$relay_asset_addr required_in_asset_to_relay=$required_in_asset_to_relay"

invokation=$(protostar -p testnet invoke --function "initialize" --contract-address "0x042e530b1f6717e3f90359881b58232954732b0b5b25793f64a06a94d8e24de2" --inputs $inputs --max-fee auto --wait-for-acceptance --json)

echo $invokation

exit 0