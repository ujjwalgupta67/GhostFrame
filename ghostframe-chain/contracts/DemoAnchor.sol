// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @notice Tiny stand-in for GhostFrameAnchor, used only to prove the 4-node
/// network works before the real GhostFrame code is connected.
/// Stores a file's SHA-256 once; nobody can overwrite or delete it.
contract DemoAnchor {
    struct Record {
        uint256 blockNumber;
        address submitter;
    }

    mapping(bytes32 => Record) public records;

    event Anchored(bytes32 indexed fileHash, uint256 blockNumber, address indexed submitter);

    function anchor(bytes32 fileHash) external {
        require(fileHash != bytes32(0), "zero hash");
        require(records[fileHash].blockNumber == 0, "already anchored");
        records[fileHash] = Record(block.number, msg.sender);
        emit Anchored(fileHash, block.number, msg.sender);
    }
}
