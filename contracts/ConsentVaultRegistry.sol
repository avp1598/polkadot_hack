// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ConsentVaultRegistry
/// @notice Minimal public registry for notarizing local file hashes.
/// @dev Stores immutable audit records keyed by content hash.
contract ConsentVaultRegistry {
    struct NotarizationRecord {
        address submitter;
        uint64 timestamp;
        string label;
    }

    mapping(bytes32 => NotarizationRecord[]) private notarizations;

    event HashNotarized(
        bytes32 indexed hash,
        address indexed submitter,
        uint64 timestamp,
        string label
    );

    /// @notice Stores a new notarization record for a hash.
    /// @param hash The SHA-256 hash of the file bytes.
    /// @param label Human-readable label supplied by the user.
    function notarize(bytes32 hash, string calldata label) external {
        require(hash != bytes32(0), "hash is required");

        NotarizationRecord memory record = NotarizationRecord({
            submitter: msg.sender,
            timestamp: uint64(block.timestamp),
            label: label
        });

        notarizations[hash].push(record);
        emit HashNotarized(hash, msg.sender, record.timestamp, label);
    }

    /// @notice Returns true if any record exists for the hash.
    function isNotarized(bytes32 hash) external view returns (bool) {
        return notarizations[hash].length > 0;
    }

    /// @notice Returns all records for a hash.
    function getRecords(
        bytes32 hash
    ) external view returns (NotarizationRecord[] memory) {
        return notarizations[hash];
    }
}
