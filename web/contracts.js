window.IAM_ABIS = {
  DIDRegistry: [
    "function registerDID(string did,(string keyId,string keyType,address controller,string publicKeyHex) initialPublicKey,(string serviceId,string serviceType,string endpoint) initialService) external",
    "function addPublicKey(string did,(string keyId,string keyType,address controller,string publicKeyHex) newKey) external",
    "function addServiceEndpoint(string did,(string serviceId,string serviceType,string endpoint) service) external",
    "function deactivateDID(string did) external",
    "function isDIDActive(string did) external view returns (bool)",
    "function resolveDID(string did) external view returns ((address controller,uint256 created,uint256 updated,bool active,(string keyId,string keyType,address controller,string publicKeyHex)[] publicKeys,(string serviceId,string serviceType,string endpoint)[] serviceEndpoints))"
  ],
  CredentialStatus: [
    "function issueCredential(string subjectDID,bytes32 credentialHash,string ipfsCID) external returns (bytes32 credentialId)",
    "function revokeCredential(bytes32 credentialId) external",
    "function isRevoked(bytes32 credentialId) external view returns (bool)",
    "function verifyCredentialIntegrity(bytes32 credentialId,bytes32 computedHash) external view returns (bool)",
    "function logVerification(bytes32 credentialId,bool result) external",
    "function getCredentialAnchor(bytes32 credentialId) external view returns ((address issuer,string subjectDID,bytes32 credentialHash,string ipfsCID,uint256 issuedAt,uint256 statusIndex))",
    "event CredentialIssued(bytes32 indexed credentialId,address indexed issuer,string indexed subjectDID,bytes32 credentialHash,string ipfsCID,uint256 statusIndex,uint256 timestamp)"
  ],
  AccessControl: [
    "function registerAsHolder(string did) external",
    "function registerAsVerifier(string did) external",
    "function authorizeIssuer(address issuerAddress,string did) external",
    "function grantConsent(string verifierDID,bytes32 credentialId,uint256 expiresAt) external",
    "function revokeConsent(string verifierDID,bytes32 credentialId) external",
    "function hasConsent(string holderDID,string verifierDID,bytes32 credentialId) external view returns (bool)",
    "function getRole(address account) external view returns (uint8)",
    "function getStakeholder(address account) external view returns ((string did,uint8 role,address authorizedBy,uint256 registeredAt,bool active))"
  ]
};
