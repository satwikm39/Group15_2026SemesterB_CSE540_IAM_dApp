// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DIDRegistry
 * @author Group 15 - CSE 540 (Revat Saharan, Abhilakshay Sreehari, Satwik Mazumdar, Sreehari Krishna Sadesh, Shashank Valayaputtur)
 * @notice Implements a W3C-compliant Decentralized Identifier (DID) registry on-chain.
 *         This contract anchors minimal DID metadata (public keys, service endpoints,
 *         and controller addresses) without ever storing raw PII on the ledger.
 *
 * @dev Architecture Overview:
 *      - Each DID maps to a DIDDocument struct holding key references and service endpoints.
 *      - All mutations emit events for transparent, immutable auditability.
 *      - Only the DID controller (owner) may update or deactivate their DID document.
 *      - Follows the W3C DID Core spec: https://www.w3.org/TR/did-core/
 */
contract DIDRegistry {

    // -------------------------------------------------------------------------
    // Data Structures
    // -------------------------------------------------------------------------

    /**
     * @dev Represents a public key associated with a DID.
     *      keyId:       A short identifier for this key (e.g., "key-1").
     *      keyType:     The cryptographic key type (e.g., "EcdsaSecp256k1VerificationKey2019").
     *      controller:  The DID that controls this key.
     *      publicKeyHex: The hex-encoded public key material.
     */
    struct PublicKey {
        string keyId;
        string keyType;
        address controller;
        string publicKeyHex;
    }

    /**
     * @dev Represents a service endpoint in the DID document.
     *      serviceId:   A short identifier for this service (e.g., "LinkedDomains").
     *      serviceType: The type of service (e.g., "VerifiableCredentialService").
     *      endpoint:    The URL or URI of the service.
     */
    struct ServiceEndpoint {
        string serviceId;
        string serviceType;
        string endpoint;
    }

    /**
     * @dev The on-chain DID Document. Stores only metadata anchors, never raw PII.
     *      controller:        The Ethereum address that owns and controls this DID.
     *      created:           Block timestamp of DID registration.
     *      updated:           Block timestamp of the last update.
     *      active:            Whether the DID is currently active (not deactivated).
     *      publicKeys:        Array of cryptographic keys associated with this DID.
     *      serviceEndpoints:  Array of service endpoints declared in the DID document.
     */
    struct DIDDocument {
        address controller;
        uint256 created;
        uint256 updated;
        bool active;
        PublicKey[] publicKeys;
        ServiceEndpoint[] serviceEndpoints;
    }

    // -------------------------------------------------------------------------
    // State Variables
    // -------------------------------------------------------------------------

    /// @dev Maps a DID string (e.g., "did:ethr:0x...") to its on-chain DID document.
    mapping(string => DIDDocument) private didDocuments;

    /// @dev Tracks which DIDs have been registered to prevent duplicates.
    mapping(string => bool) private registeredDIDs;

    /// @dev Maps an Ethereum address to the DIDs it controls (for lookup convenience).
    mapping(address => string[]) private controllerToDIDs;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a new DID is registered on-chain.
    event DIDRegistered(string indexed did, address indexed controller, uint256 timestamp);

    /// @notice Emitted when a DID document is updated (key or service change).
    event DIDUpdated(string indexed did, address indexed controller, uint256 timestamp);

    /// @notice Emitted when a DID is deactivated by its controller.
    event DIDDeactivated(string indexed did, address indexed controller, uint256 timestamp);

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    /// @dev Restricts a function to the controller of a given DID.
    modifier onlyController(string memory did) {
        require(registeredDIDs[did], "DIDRegistry: DID not registered");
        require(didDocuments[did].controller == msg.sender, "DIDRegistry: Caller is not controller");
        require(didDocuments[did].active, "DIDRegistry: DID has been deactivated");
        _;
    }

    // -------------------------------------------------------------------------
    // Core Functions
    // -------------------------------------------------------------------------

    /**
     * @notice Registers a new Decentralized Identifier (DID) on-chain.
     * @dev    Anchors the DID to the caller's address as the controller.
     *         The full DID document (credentials, extended metadata) is stored
     *         off-chain (IPFS); only the minimal anchor is stored here.
     * @param did              The DID string to register (e.g., "did:ethr:0x...").
     * @param initialPublicKey The primary verification key to associate with this DID.
     * @param initialService   An optional initial service endpoint (pass empty strings to skip).
     */
    function registerDID(
        string memory did,
        PublicKey memory initialPublicKey,
        ServiceEndpoint memory initialService
    ) external {
        require(bytes(did).length > 0, "DIDRegistry: empty DID");
        require(!registeredDIDs[did], "DIDRegistry: DID already registered");

        DIDDocument storage doc = didDocuments[did];
        doc.controller = msg.sender;
        doc.created = block.timestamp;
        doc.updated = block.timestamp;
        doc.active = true;
        doc.publicKeys.push(initialPublicKey);
        if (bytes(initialService.serviceId).length > 0) {
            doc.serviceEndpoints.push(initialService);
        }

        registeredDIDs[did] = true;
        controllerToDIDs[msg.sender].push(did);

        emit DIDRegistered(did, msg.sender, block.timestamp);
    }

    /**
     * @notice Adds a new public key to an existing DID document.
     * @dev    Only the DID controller may call this. Emits DIDUpdated.
     * @param did       The DID to update.
     * @param newKey    The new PublicKey struct to append to the DID document.
     */
    function addPublicKey(string memory did, PublicKey memory newKey) external onlyController(did) {
        require(bytes(newKey.keyId).length > 0, "DIDRegistry: empty keyId");
        require(bytes(newKey.keyType).length > 0, "DIDRegistry: empty keyType");
        require(newKey.controller == msg.sender, "DIDRegistry: key controller mismatch");

        DIDDocument storage doc = didDocuments[did];
        doc.publicKeys.push(newKey);
        doc.updated = block.timestamp;

        emit DIDUpdated(did, msg.sender, block.timestamp);
    }

    /**
     * @notice Adds a new service endpoint to an existing DID document.
     * @dev    Only the DID controller may call this. Emits DIDUpdated.
     * @param did      The DID to update.
     * @param service  The new ServiceEndpoint struct to append.
     */
    function addServiceEndpoint(string memory did, ServiceEndpoint memory service) external onlyController(did) {
        require(bytes(service.serviceId).length > 0, "DIDRegistry: empty serviceId");
        require(bytes(service.serviceType).length > 0, "DIDRegistry: empty serviceType");
        require(bytes(service.endpoint).length > 0, "DIDRegistry: empty endpoint");

        DIDDocument storage doc = didDocuments[did];
        doc.serviceEndpoints.push(service);
        doc.updated = block.timestamp;

        emit DIDUpdated(did, msg.sender, block.timestamp);
    }

    /**
     * @notice Permanently deactivates a DID. This action is irreversible.
     * @dev    Sets active = false. The DID document remains readable for historical audit.
     *         Only the DID controller may call this. Emits DIDDeactivated.
     * @param did  The DID to deactivate.
     */
    function deactivateDID(string memory did) external onlyController(did) {
        DIDDocument storage doc = didDocuments[did];
        doc.active = false;
        doc.updated = block.timestamp;

        emit DIDDeactivated(did, msg.sender, block.timestamp);
    }

    // -------------------------------------------------------------------------
    // View / Read Functions
    // -------------------------------------------------------------------------

    /**
     * @notice Resolves a DID to its on-chain document metadata.
     * @param did  The DID string to resolve.
     * @return     The DIDDocument struct associated with the given DID.
     */
    function resolveDID(string memory did) external view returns (DIDDocument memory) {
        require(registeredDIDs[did], "DIDRegistry: DID not registered");
        return didDocuments[did];
    }

    /**
     * @notice Returns all DIDs controlled by a given Ethereum address.
     * @param controller  The controller address to query.
     * @return            An array of DID strings controlled by the address.
     */
    function getDIDsByController(address controller) external view returns (string[] memory) {
        return controllerToDIDs[controller];
    }

    /**
     * @notice Checks whether a given DID is currently active.
     * @param did  The DID string to check.
     * @return     True if the DID is registered and active, false otherwise.
     */
    function isDIDActive(string memory did) external view returns (bool) {
        if (!registeredDIDs[did]) return false;
        return didDocuments[did].active;
    }
}
