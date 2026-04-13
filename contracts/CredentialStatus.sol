// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CredentialStatus
 * @author Group 15 - CSE 540 (Revat Saharan, Abhilakshay Sreehari, Satwik Mazumdar, Sreehari Krishna Sadesh, Shashank Valayaputtur)
 * @notice Manages the on-chain revocation and status registry for Verifiable Credentials (VCs).
 *         Uses a gas-efficient bitmap approach: each credential is assigned an index in a
 *         bitmap, and its revocation status is stored as a single bit flip.
 *
 * @dev Design Rationale:
 *      - Storing full VCs on-chain is gas-prohibitive and risks PII exposure.
 *      - Instead, only a cryptographic hash (commitment) of each VC is anchored here.
 *      - Verifiers fetch the full VC from IPFS, recompute the hash, and compare it to
 *        the on-chain commitment to verify data integrity.
 *      - The bitmap revocation list allows O(1) status checks with minimal gas overhead.
 *      - Complies with the W3C StatusList2021 specification concept.
 */
contract CredentialStatus {

    // -------------------------------------------------------------------------
    // Data Structures
    // -------------------------------------------------------------------------

    /**
     * @dev On-chain anchor record for an issued Verifiable Credential.
     *      issuer:          The Ethereum address (DID controller) that issued the credential.
     *      subjectDID:      The DID of the credential subject (holder).
     *      credentialHash:  Keccak256 hash of the off-chain VC JSON payload (integrity anchor).
     *      ipfsCID:         The IPFS Content Identifier where the encrypted VC is stored.
     *      issuedAt:        Block timestamp when the credential anchor was written on-chain.
     *      statusIndex:     The index of this credential in the issuer's revocation bitmap.
     */
    struct CredentialAnchor {
        address issuer;
        string subjectDID;
        bytes32 credentialHash;
        string ipfsCID;
        uint256 issuedAt;
        uint256 statusIndex;
    }

    // -------------------------------------------------------------------------
    // State Variables
    // -------------------------------------------------------------------------

    /// @dev Maps a credential ID (bytes32 hash of issuer+subject+nonce) to its on-chain anchor.
    mapping(bytes32 => CredentialAnchor) private credentialAnchors;

    /// @dev Tracks which credential IDs have been registered.
    mapping(bytes32 => bool) private registeredCredentials;

    /**
     * @dev Bitmap-based revocation list.
     *      revocationBitmaps[issuer][bitmapChunk] is a uint256 where each bit
     *      represents the revocation status of one credential (1 = revoked, 0 = valid).
     *      This allows 256 credentials per storage slot, minimizing gas costs.
     */
    mapping(address => mapping(uint256 => uint256)) private revocationBitmaps;

    /// @dev Tracks the next available status index per issuer for bitmap allocation.
    mapping(address => uint256) private nextStatusIndex;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a new credential anchor is written on-chain by an issuer.
    event CredentialIssued(
        bytes32 indexed credentialId,
        address indexed issuer,
        string indexed subjectDID,
        bytes32 credentialHash,
        string ipfsCID,
        uint256 statusIndex,
        uint256 timestamp
    );

    /// @notice Emitted when an issuer revokes a previously issued credential.
    event CredentialRevoked(
        bytes32 indexed credentialId,
        address indexed issuer,
        uint256 statusIndex,
        uint256 timestamp
    );

    /// @notice Emitted when a verifier triggers an on-chain verification event (for auditability).
    event VerificationLogged(
        bytes32 indexed credentialId,
        address indexed verifier,
        bool result,
        uint256 timestamp
    );

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    /// @dev Restricts revocation to the original issuer of a credential.
    modifier onlyIssuer(bytes32 credentialId) {
        require(registeredCredentials[credentialId], "CredentialStatus: Credential not found");
        require(
            credentialAnchors[credentialId].issuer == msg.sender,
            "CredentialStatus: Caller is not the issuer"
        );
        _;
    }

    // -------------------------------------------------------------------------
    // Core Functions
    // -------------------------------------------------------------------------

    /**
     * @notice Anchors a new Verifiable Credential on-chain after off-chain signing.
     * @dev    Called by the Issuer after signing the VC off-chain with EIP-712.
     *         Only the IPFS CID and credential hash are stored — no raw credential data.
     *         Automatically allocates a status bitmap index for future revocation.
     * @param subjectDID      The DID of the credential subject (holder).
     * @param credentialHash  Keccak256 hash of the full VC JSON payload.
     * @param ipfsCID         The IPFS CID pointing to the encrypted VC off-chain.
     * @return credentialId   A unique bytes32 identifier for this credential anchor.
     */
    function issueCredential(
        string memory subjectDID,
        bytes32 credentialHash,
        string memory ipfsCID
    ) external returns (bytes32 credentialId) {
        credentialId = keccak256(
            abi.encodePacked(msg.sender, subjectDID, credentialHash, block.timestamp)
        );
        require(!registeredCredentials[credentialId], "CredentialStatus: duplicate credentialId");

        uint256 statusIndex = nextStatusIndex[msg.sender];
        unchecked {
            nextStatusIndex[msg.sender] = statusIndex + 1;
        }

        credentialAnchors[credentialId] = CredentialAnchor({
            issuer: msg.sender,
            subjectDID: subjectDID,
            credentialHash: credentialHash,
            ipfsCID: ipfsCID,
            issuedAt: block.timestamp,
            statusIndex: statusIndex
        });
        registeredCredentials[credentialId] = true;

        emit CredentialIssued(
            credentialId,
            msg.sender,
            subjectDID,
            credentialHash,
            ipfsCID,
            statusIndex,
            block.timestamp
        );
    }

    /**
     * @notice Revokes an existing credential by flipping its bit in the revocation bitmap.
     * @dev    Only the original issuer may revoke. Sets the bit at statusIndex to 1.
     *         This is a gas-efficient O(1) operation using bitwise OR.
     * @param credentialId  The unique identifier of the credential anchor to revoke.
     */
    function revokeCredential(bytes32 credentialId) external onlyIssuer(credentialId) {
        // TODO: Implement revocation logic
        // - Retrieve the credential's statusIndex from credentialAnchors[credentialId]
        // - Compute bitmapChunk = statusIndex / 256 and bitPosition = statusIndex % 256
        // - Set the bit: revocationBitmaps[msg.sender][bitmapChunk] |= (1 << bitPosition)
        // - Emit CredentialRevoked event
    }

    /**
     * @notice Logs a verification attempt on-chain for auditability.
     * @dev    Does not enforce access; purely an event-emission for transparency.
     *         Verifiers call this to leave an immutable audit trail without PII.
     * @param credentialId  The credential being verified.
     * @param result        The result of the off-chain cryptographic verification.
     */
    function logVerification(bytes32 credentialId, bool result) external {
        require(registeredCredentials[credentialId], "CredentialStatus: Credential not found");
        emit VerificationLogged(credentialId, msg.sender, result, block.timestamp);
    }

    // -------------------------------------------------------------------------
    // View / Read Functions
    // -------------------------------------------------------------------------

    /**
     * @notice Checks whether a credential has been revoked.
     * @dev    Reads the bitmap bit at the credential's statusIndex.
     * @param credentialId  The unique identifier of the credential to check.
     * @return              True if the credential has been revoked, false if still valid.
     */
    function isRevoked(bytes32 credentialId) external view returns (bool) {
        require(registeredCredentials[credentialId], "CredentialStatus: Credential not found");
        CredentialAnchor storage anchor = credentialAnchors[credentialId];
        uint256 statusIndex = anchor.statusIndex;
        address issuer = anchor.issuer;
        uint256 bitmapChunk = statusIndex / 256;
        uint256 bitPosition = statusIndex % 256;
        uint256 chunk = revocationBitmaps[issuer][bitmapChunk];
        return ((chunk >> bitPosition) & 1) == 1;
    }

    /**
     * @notice Returns the on-chain anchor data for a given credential ID.
     * @param credentialId  The unique identifier of the credential to retrieve.
     * @return              The CredentialAnchor struct with IPFS CID, hash, and metadata.
     */
    function getCredentialAnchor(bytes32 credentialId) external view returns (CredentialAnchor memory) {
        require(registeredCredentials[credentialId], "CredentialStatus: Credential not found");
        return credentialAnchors[credentialId];
    }

    /**
     * @notice Verifies the integrity of a fetched VC by comparing its hash to the on-chain commitment.
     * @dev    Verifiers fetch the encrypted VC from IPFS, decrypt it, then call this to confirm
     *         the data has not been tampered with.
     * @param credentialId    The credential anchor ID to verify against.
     * @param computedHash    The keccak256 hash of the locally fetched and decrypted VC payload.
     * @return                True if the hash matches the on-chain commitment (data integrity confirmed).
     */
    function verifyCredentialIntegrity(bytes32 credentialId, bytes32 computedHash) external view returns (bool) {
        require(registeredCredentials[credentialId], "CredentialStatus: Credential not found");
        return credentialAnchors[credentialId].credentialHash == computedHash;
    }
}
