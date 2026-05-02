// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DIDRegistry.sol";
import "./CredentialStatus.sol";

/**
 * @title AccessControl
 * @author Group 15 - CSE 540 (Revat Saharan, Abhilakshay Sreehari, Satwik Mazumdar, Sreehari Krishna Sadesh, Shashank Valayaputtur)
 * @notice Governs role-based access management within the IAM dApp.
 *         Defines and enforces the three core stakeholder roles:
 *         Issuer, Verifier, and Holder (User/Subject).
 *
 * @dev Design Rationale:
 *      - Role assignments are anchored to DIDs (not raw Ethereum addresses) to ensure
 *        that identity context is preserved even if a user rotates their keys.
 *      - The contract integrates with DIDRegistry to validate that a DID is active
 *        before granting or checking permissions.
 *      - Admins (trusted entities, e.g., universities, hospitals) can authorize Issuers.
 *      - Verifiers are self-registered but subject to Holder consent for data access.
 */
contract AccessControl {

    // -------------------------------------------------------------------------
    // Enums & Data Structures
    // -------------------------------------------------------------------------

    /// @dev The three roles in the SSI identity lifecycle.
    enum Role { NONE, HOLDER, ISSUER, VERIFIER }

    /**
     * @dev Represents a registered stakeholder in the system.
     *      did:          The DID string of this stakeholder.
     *      role:         Their assigned role (HOLDER, ISSUER, or VERIFIER).
     *      authorizedBy: The admin address that granted ISSUER role (zero for others).
     *      registeredAt: Block timestamp of role registration.
     *      active:       Whether this stakeholder is currently active.
     */
    struct Stakeholder {
        string did;
        Role role;
        address authorizedBy;
        uint256 registeredAt;
        bool active;
    }

    /**
     * @dev Represents a Holder's consent grant to a specific Verifier.
     *      holderDID:    The DID of the consenting Holder.
     *      verifierDID:  The DID of the Verifier being granted access.
     *      credentialId: The specific credential the Verifier may access.
     *      expiresAt:    Timestamp after which the consent is no longer valid (0 = no expiry).
     *      granted:      Whether the consent is currently active.
     */
    struct ConsentGrant {
        string holderDID;
        string verifierDID;
        bytes32 credentialId;
        uint256 expiresAt;
        bool granted;
    }

    // -------------------------------------------------------------------------
    // State Variables
    // -------------------------------------------------------------------------

    /// @dev Reference to the DIDRegistry contract for DID resolution and validation.
    DIDRegistry public immutable didRegistry;

    /// @dev Reference to the CredentialStatus contract for revocation checks.
    CredentialStatus public immutable credentialStatus;

    /// @dev The deployer address is the initial super-admin of this access control system.
    address public immutable superAdmin;

    /// @dev Maps Ethereum address => Stakeholder record.
    mapping(address => Stakeholder) private stakeholders;

    /// @dev Maps an admin address to whether they have admin privileges.
    mapping(address => bool) private admins;
    mapping(bytes32 => address) private didToAccount;

    /**
     * @dev Consent registry. Key is keccak256(holderDID, verifierDID, credentialId).
     *      Allows holders to grant/revoke per-credential access to specific verifiers.
     */
    mapping(bytes32 => ConsentGrant) private consentGrants;

    /// @dev Internal helper to normalize a DID string as mapping key.
    function _didKey(string memory did) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(did));
    }

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a new stakeholder is registered with a role.
    event StakeholderRegistered(address indexed account, string did, Role role, uint256 timestamp);

    /// @notice Emitted when an admin authorizes a new Issuer.
    event IssuerAuthorized(address indexed issuer, string did, address indexed admin, uint256 timestamp);

    /// @notice Emitted when a Holder grants consent to a Verifier for a specific credential.
    event ConsentGranted(string holderDID, string verifierDID, bytes32 credentialId, uint256 expiresAt);

    /// @notice Emitted when a Holder revokes a previously granted consent.
    event ConsentRevoked(string holderDID, string verifierDID, bytes32 credentialId, uint256 timestamp);

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /**
     * @param _didRegistry        Address of the deployed DIDRegistry contract.
     * @param _credentialStatus   Address of the deployed CredentialStatus contract.
     */
    constructor(address _didRegistry, address _credentialStatus) {
        didRegistry = DIDRegistry(_didRegistry);
        credentialStatus = CredentialStatus(_credentialStatus);
        superAdmin = msg.sender;
        admins[msg.sender] = true;
    }

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    /// @dev Restricts access to admins only.
    modifier onlyAdmin() {
        require(admins[msg.sender], "AccessControl: Caller is not an admin");
        _;
    }

    /// @dev Ensures the caller is a registered active stakeholder.
    modifier onlyRegistered() {
        require(stakeholders[msg.sender].active, "AccessControl: Caller is not registered");
        _;
    }

    // -------------------------------------------------------------------------
    // Role Management Functions
    // -------------------------------------------------------------------------

    /**
     * @notice Registers the caller as a Holder in the system.
     * @dev    Requires that the caller has an active DID in the DIDRegistry.
     *         Holders self-register; no admin approval is needed.
     * @param did  The caller's DID string (must be active in DIDRegistry).
     */
    function registerAsHolder(string memory did) external {
        require(didRegistry.isDIDActive(did), "AccessControl: DID is not active");
        require(!stakeholders[msg.sender].active, "AccessControl: already registered");

        bytes32 didKey = _didKey(did);
        require(didToAccount[didKey] == address(0), "AccessControl: DID already in use");

        stakeholders[msg.sender] = Stakeholder({
            did: did,
            role: Role.HOLDER,
            authorizedBy: address(0),
            registeredAt: block.timestamp,
            active: true
        });
        didToAccount[didKey] = msg.sender;

        emit StakeholderRegistered(msg.sender, did, Role.HOLDER, block.timestamp);
    }

    /**
     * @notice Registers the caller as a Verifier in the system.
     * @dev    Verifiers self-register but require an active DID.
     *         They can only access credentials with explicit Holder consent.
     * @param did  The caller's DID string (must be active in DIDRegistry).
     */
    function registerAsVerifier(string memory did) external {
        require(didRegistry.isDIDActive(did), "AccessControl: DID is not active");
        require(!stakeholders[msg.sender].active, "AccessControl: already registered");

        bytes32 didKey = _didKey(did);
        require(didToAccount[didKey] == address(0), "AccessControl: DID already in use");

        stakeholders[msg.sender] = Stakeholder({
            did: did,
            role: Role.VERIFIER,
            authorizedBy: address(0),
            registeredAt: block.timestamp,
            active: true
        });
        didToAccount[didKey] = msg.sender;

        emit StakeholderRegistered(msg.sender, did, Role.VERIFIER, block.timestamp);
    }

    /**
     * @notice Authorizes a specific address as an Issuer. Admin-only.
     * @dev    Issuers are trusted entities (e.g., universities, hospitals) granted by admins.
     * @param issuerAddress  The Ethereum address of the entity to authorize as Issuer.
     * @param did            The Issuer's active DID.
     */
    function authorizeIssuer(address issuerAddress, string memory did) external onlyAdmin {
        require(issuerAddress != address(0), "AccessControl: invalid issuer address");
        require(didRegistry.isDIDActive(did), "AccessControl: DID is not active");

        bytes32 didKey = _didKey(did);
        address existingAccount = didToAccount[didKey];
        require(
            existingAccount == address(0) || existingAccount == issuerAddress,
            "AccessControl: DID already in use"
        );
        require(
            !stakeholders[issuerAddress].active || keccak256(bytes(stakeholders[issuerAddress].did)) == keccak256(bytes(did)),
            "AccessControl: issuer address already bound to another DID"
        );

        stakeholders[issuerAddress] = Stakeholder({
            did: did,
            role: Role.ISSUER,
            authorizedBy: msg.sender,
            registeredAt: block.timestamp,
            active: true
        });
        didToAccount[didKey] = issuerAddress;

        emit IssuerAuthorized(issuerAddress, did, msg.sender, block.timestamp);
    }

    // -------------------------------------------------------------------------
    // Consent Management Functions
    // -------------------------------------------------------------------------

    /**
     * @notice Grants a specific Verifier access to a specific credential.
     * @dev    Called by a Holder to authorize a Verifier to view a credential.
     *         Consent is scoped to a single credentialId to enforce data minimization.
     * @param verifierDID   The DID of the Verifier being granted access.
     * @param credentialId  The specific credential being consented to.
     * @param expiresAt     Unix timestamp for consent expiry (0 for no expiry).
     */
    function grantConsent(
        string memory verifierDID,
        bytes32 credentialId,
        uint256 expiresAt
    ) external onlyRegistered {
        Stakeholder storage caller = stakeholders[msg.sender];
        require(caller.role == Role.HOLDER, "AccessControl: caller is not a holder");
        require(didRegistry.isDIDActive(verifierDID), "AccessControl: verifier DID is not active");

        address verifierAccount = didToAccount[_didKey(verifierDID)];
        require(verifierAccount != address(0), "AccessControl: verifier not registered");
        require(
            stakeholders[verifierAccount].active && stakeholders[verifierAccount].role == Role.VERIFIER,
            "AccessControl: invalid verifier role"
        );

        CredentialStatus.CredentialAnchor memory anchor = credentialStatus.getCredentialAnchor(credentialId);
        require(
            keccak256(bytes(anchor.subjectDID)) == keccak256(bytes(caller.did)),
            "AccessControl: holder not credential subject"
        );
        require(!credentialStatus.isRevoked(credentialId), "AccessControl: credential revoked");
        require(expiresAt == 0 || expiresAt > block.timestamp, "AccessControl: invalid expiry");

        bytes32 consentKey = keccak256(abi.encodePacked(caller.did, verifierDID, credentialId));
        consentGrants[consentKey] = ConsentGrant({
            holderDID: caller.did,
            verifierDID: verifierDID,
            credentialId: credentialId,
            expiresAt: expiresAt,
            granted: true
        });

        emit ConsentGranted(caller.did, verifierDID, credentialId, expiresAt);
    }

    /**
     * @notice Revokes a previously granted consent.
     * @dev    Called by a Holder to withdraw a Verifier's access to a credential.
     * @param verifierDID   The DID of the Verifier whose access is being revoked.
     * @param credentialId  The credential for which consent is revoked.
     */
    function revokeConsent(string memory verifierDID, bytes32 credentialId) external onlyRegistered {
        Stakeholder storage caller = stakeholders[msg.sender];
        require(caller.role == Role.HOLDER, "AccessControl: caller is not a holder");

        bytes32 consentKey = keccak256(abi.encodePacked(caller.did, verifierDID, credentialId));
        ConsentGrant storage grant = consentGrants[consentKey];
        require(grant.granted, "AccessControl: consent not active");
        require(
            keccak256(bytes(grant.holderDID)) == keccak256(bytes(caller.did)),
            "AccessControl: unauthorized revocation"
        );

        grant.granted = false;
        emit ConsentRevoked(caller.did, verifierDID, credentialId, block.timestamp);
    }

    // -------------------------------------------------------------------------
    // View / Read Functions
    // -------------------------------------------------------------------------

    /**
     * @notice Returns the role of a given Ethereum address.
     * @param account  The address to query.
     * @return         The Role enum value (NONE, HOLDER, ISSUER, or VERIFIER).
     */
    function getRole(address account) external view returns (Role) {
        return stakeholders[account].role;
    }

    /**
     * @notice Checks whether a Verifier has valid consent to access a specific credential.
     * @param holderDID     The DID of the Holder who issued the consent.
     * @param verifierDID   The DID of the Verifier requesting access.
     * @param credentialId  The credential being accessed.
     * @return              True if consent is granted and not expired.
     */
    function hasConsent(
        string memory holderDID,
        string memory verifierDID,
        bytes32 credentialId
    ) external view returns (bool) {
        bytes32 consentKey = keccak256(abi.encodePacked(holderDID, verifierDID, credentialId));
        ConsentGrant storage grant = consentGrants[consentKey];

        if (!grant.granted) {
            return false;
        }
        if (grant.expiresAt != 0 && block.timestamp > grant.expiresAt) {
            return false;
        }
        if (credentialStatus.isRevoked(credentialId)) {
            return false;
        }
        return true;
    }

    /**
     * @notice Returns the full Stakeholder record for a given address.
     * @param account  The Ethereum address to query.
     * @return         The Stakeholder struct with DID, role, and registration details.
     */
    function getStakeholder(address account) external view returns (Stakeholder memory) {
        return stakeholders[account];
    }
}
