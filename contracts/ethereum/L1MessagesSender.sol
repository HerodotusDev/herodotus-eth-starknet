// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.9;

import {FormatWords64} from "./lib/FormatWords64.sol";
import {IStarknetCore} from "./interfaces/IStarknetCore.sol";

contract L1MessagesSender {
    IStarknetCore public immutable starknetCore;
    uint256 public immutable l2RecipientAddr;

    /// @dev starknetSelector(receive_from_l1)
    uint256 constant SUBMIT_L1_BLOCKHASH_SELECTOR =
        598342674068027518481179578557554850038206119856216505601406522348670006916;

    /// @param starknetCore_ a StarknetCore address to send and consume messages on/from L2
    /// @param l2RecipientAddr_ a L2 recipient address that is the recipient contract on L2.
    constructor(IStarknetCore starknetCore_, uint256 l2RecipientAddr_) {
        starknetCore = starknetCore_;
        l2RecipientAddr = l2RecipientAddr_;
    }

    /// @notice Send an exact L1 parent hash to L2
    /// @param blockNumber_ the child block of the requested parent hash
    function sendExactParentHashToL2(uint256 blockNumber_) external {
        bytes32 parentHash = blockhash(blockNumber_ - 1);
        require(parentHash != bytes32(0), "ERR_INVALID_BLOCK_NUMBER");
        _sendBlockHashToL2(parentHash, blockNumber_, 0);
    }

    /// @notice Send the L1 latest parent hash to L2
    function sendLatestParentHashToL2() external {
        bytes32 parentHash = blockhash(block.number - 1);
        _sendBlockHashToL2(parentHash, block.number, 0);
    }

    /// @notice Send an exact L1 parent hash to L2
    /// @param blockNumber_ the child block of the requested parent hash
    /// @param slashingRewardL2Recipient_ L2 address of the reward recipient if slashing occurs
    function proveFraudalentRelay(
        uint256 blockNumber_,
        uint256 slashingRewardL2Recipient_
    ) external {
        bytes32 parentHash = blockhash(blockNumber_ - 1);
        require(parentHash != bytes32(0), "ERR_INVALID_BLOCK_NUMBER");
        _sendBlockHashToL2(
            parentHash,
            blockNumber_,
            slashingRewardL2Recipient_
        );
    }

    function _sendBlockHashToL2(
        bytes32 parentHash_,
        uint256 blockNumber_,
        uint256 slashRewarderL2Addr_
    ) internal {
        uint256[] memory message = new uint256[](6);
        (
            bytes8 hashWord1,
            bytes8 hashWord2,
            bytes8 hashWord3,
            bytes8 hashWord4
        ) = FormatWords64.fromBytes32(parentHash_);

        message[0] = uint256(uint64(hashWord1));
        message[1] = uint256(uint64(hashWord2));
        message[2] = uint256(uint64(hashWord3));
        message[3] = uint256(uint64(hashWord4));
        message[4] = blockNumber_;
        message[5] = slashRewarderL2Addr_;

        starknetCore.sendMessageToL2(
            l2RecipientAddr,
            SUBMIT_L1_BLOCKHASH_SELECTOR,
            message
        );
    }
}
