#!/bin/bash

# Array of class hashes
class_hashes=(
"0x6ecf5b5e584b6fdefa8ef072192a002b5f202500a32c622e9bc4616a27eaa20"
"0x36fc1c737e2e1027ecbb956edbcee3c3de62ae3e17ddabd62b7c6c6ca61dda9"
"0xca2888788ebd514df0c7a4d1587e2277349feb3d1bfa7cbe87631b1865cd74"
)

# First deployment
output=$(sncast --profile dev deploy --class-hash "${class_hashes[0]}" --constructor-calldata "0x1 0x1 0x1")
contract_addresses[0]=$(echo "$output" | grep -Eo 'contract_address: 0x[a-fA-F0-9]+' | awk -F " " '{print $2}')

# Second deployment
output=$(sncast --profile dev deploy --class-hash "${class_hashes[1]}" --constructor-calldata "${contract_addresses[0]}")
contract_addresses[1]=$(echo "$output" | grep -Eo 'contract_address: 0x[a-fA-F0-9]+' | awk -F " " '{print $2}')

# Third deployment
output=$(sncast --profile dev deploy --class-hash "${class_hashes[2]}" --constructor-calldata "${contract_addresses[1]}")
contract_addresses[2]=$(echo "$output" | grep -Eo 'contract_address: 0x[a-fA-F0-9]+' | awk -F " " '{print $2}')

for address in "${contract_addresses[@]}"; do
    echo $address
done
