/**
 * WalletTrustContract ABI - Human-Readable format for ethers.js v6
 * 仅包含 SGX 端需要调用的 view 函数
 */
export const CONTRACT_ABI = [
  // ===== 配置查询 =====
  'function getRuntimeParams() view returns (string)',
  'function getCodeRepository() view returns (string)',
  'function getPublicInfo() view returns (string, string, tuple(bytes32 mrenclave, bytes32 mrsigner, uint16 isvprodid, uint16 isvsvn, string description)[])',

  // ===== Enclave 白名单（RA-TLS 验证用） =====
  'function getEnclaveWhitelist() view returns (tuple(bytes32 mrenclave, bytes32 mrsigner, uint16 isvprodid, uint16 isvsvn, string description)[])',
  'function isEnclaveWhitelisted(bytes32) view returns (bool)',

  // ===== 平台白名单 =====
  'function getPlatformWhitelist() view returns (address[])',
  'function isPlatformWhitelisted(address) view returns (bool)',

  // ===== 授权撤销 =====
  'function isAuthorizationRevoked(string, string) view returns (bool)',
  'function getRevokedAuthorizations(string) view returns (tuple(string authorizationId, address grantee, bytes32 passkeyPubKeyX, bytes32 passkeyPubKeyY, uint256 revokedAt)[])',

  // ===== Passkey 恢复 =====
  'function passkeyRecoveryExists(string, bytes32) view returns (bool)',
  'function getPasskeyRecovery(string, bytes32) view returns (bytes32 oldPubKeyHash, string uuid, string memo, uint256 createdAt)',

  // ===== 合约迁移目标（无需鉴权，所有人可读） =====
  'function getMigrationTarget() view returns (string rpcUrl, string contractAddress, uint256 chainId)',
];
