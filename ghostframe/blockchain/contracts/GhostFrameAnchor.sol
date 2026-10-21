// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @notice Registers privacy-safe GhostFrame commitments. It stores no files,
/// metadata, evidence blobs, keys, or passphrases and makes no external calls.
contract GhostFrameAnchor {
    string public constant CONTRACT_VERSION = "ghostframe-anchor/1.0";

    error ZeroCommitment();
    error InspectionAlreadyExists();
    error InspectionMissing();
    error VerificationAlreadyExists();
    error UnauthorizedVerifier();

    struct Record {
        address inspectionSubmitter;
        uint64 inspectionTimestamp;
        bytes32 sourceFileHash;
        bytes32 inspectionCommitment;
        bytes32 schemaCommitment;
        uint64 verificationTimestamp;
        bytes32 sanitizedFileHash;
        bytes32 verificationCommitment;
        bytes32 finalLifecycleCommitment;
    }

    mapping(bytes32 operationCommitment => Record) private records;

    event InspectionAnchored(
        bytes32 indexed operationCommitment,
        address indexed submitter,
        bytes32 sourceFileHash,
        bytes32 inspectionCommitment,
        bytes32 schemaCommitment,
        uint64 timestamp
    );

    event VerificationAnchored(
        bytes32 indexed operationCommitment,
        address indexed submitter,
        bytes32 sanitizedFileHash,
        bytes32 verificationCommitment,
        bytes32 finalLifecycleCommitment,
        uint64 timestamp
    );

    function anchorInspection(
        bytes32 operationCommitment,
        bytes32 sourceFileHash,
        bytes32 inspectionCommitment,
        bytes32 schemaCommitment
    ) external {
        if (
            operationCommitment == bytes32(0) ||
            sourceFileHash == bytes32(0) ||
            inspectionCommitment == bytes32(0) ||
            schemaCommitment == bytes32(0)
        ) revert ZeroCommitment();

        Record storage record = records[operationCommitment];
        if (record.inspectionTimestamp != 0) revert InspectionAlreadyExists();

        uint64 timestamp = uint64(block.timestamp);
        record.inspectionSubmitter = msg.sender;
        record.inspectionTimestamp = timestamp;
        record.sourceFileHash = sourceFileHash;
        record.inspectionCommitment = inspectionCommitment;
        record.schemaCommitment = schemaCommitment;

        emit InspectionAnchored(
            operationCommitment,
            msg.sender,
            sourceFileHash,
            inspectionCommitment,
            schemaCommitment,
            timestamp
        );
    }

    function anchorVerification(
        bytes32 operationCommitment,
        bytes32 sanitizedFileHash,
        bytes32 verificationCommitment,
        bytes32 finalLifecycleCommitment
    ) external {
        if (
            operationCommitment == bytes32(0) ||
            sanitizedFileHash == bytes32(0) ||
            verificationCommitment == bytes32(0) ||
            finalLifecycleCommitment == bytes32(0)
        ) revert ZeroCommitment();

        Record storage record = records[operationCommitment];
        if (record.inspectionTimestamp == 0) revert InspectionMissing();
        if (record.verificationTimestamp != 0) revert VerificationAlreadyExists();
        if (record.inspectionSubmitter != msg.sender) revert UnauthorizedVerifier();

        uint64 timestamp = uint64(block.timestamp);
        record.verificationTimestamp = timestamp;
        record.sanitizedFileHash = sanitizedFileHash;
        record.verificationCommitment = verificationCommitment;
        record.finalLifecycleCommitment = finalLifecycleCommitment;

        emit VerificationAnchored(
            operationCommitment,
            msg.sender,
            sanitizedFileHash,
            verificationCommitment,
            finalLifecycleCommitment,
            timestamp
        );
    }

    function getRecord(bytes32 operationCommitment) external view returns (Record memory) {
        return records[operationCommitment];
    }
}
