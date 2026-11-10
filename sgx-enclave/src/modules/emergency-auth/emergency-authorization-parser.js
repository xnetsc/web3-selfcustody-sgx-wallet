/**
 * 应急授权 JSON 结构解析与验证
 *
 * 应急授权与普通用户授权的区别（结构性）：
 *  - 签发者是运营方治理 Passkey（普通账户的 Passkey，身份由合约指定），
 *    不是钱包归属用户；授权对象永远是“别人的钱包”。
 *  - grantee 只能是单个确定的平台地址，禁止数组与 "*" 通配。
 *  - 一份授权覆盖一个或多个钱包（wallets[]），每个钱包条目携带自己独立的
 *    policy，不存在顶层共享 policy；同一 userId 在一份授权内只能出现一次。
 *  - policy 按操作列项（operations），每项的操作特有约束就是该项里的参数
 *    字段本身（数据，不是代码分支）：如 passkey_bind 的 newPubKeyHash、
 *    tx_sign 的 scope 字段。任何操作都不为此新造一套授权逻辑。
 *  - 每项可带 maxUses（正整数），缺省 1。
 */

export const EMERGENCY_OPERATIONS = [
  'tx_sign',           // 交易签名（转账/合约调用/部署/7702 等，范围由 scope 字段约束）
  'wallet_create',     // 创建钱包
  'wallet_delete',     // 删除钱包
  'wallet_entry_delete', // 删除钱包条目（单地址）
  'passkey_bind',      // 绑定新 Passkey（注册流程的应急路径）
  'passkey_delete',    // 删除 Passkey
  'key_import',        // 密钥导入（单个/批量）
  'key_export',        // 密钥导出（init + complete 两步共用一个操作名）
  'auth_revoke',       // 撤销目标用户的某份普通授权
  'evidence_query',    // 授权记录证据查询
];

const ETH_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const BYTES32_RE = /^0x[0-9a-fA-F]{64}$/;

/**
 * 规范化一个操作条目：true → 无参数、maxUses=1；对象 → 分离 maxUses 与参数
 * @param {*} raw - operations[op] 的原始值
 * @returns {{ maxUses: number, params: Object } | null} 非法时返回 null
 */
export function normalizeOperationEntry(raw) {
  if (raw === true) return { maxUses: 1, params: {} };
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const { maxUses, ...params } = raw;
  if (maxUses !== undefined && (!Number.isInteger(maxUses) || maxUses < 1)) return null;
  return { maxUses: maxUses === undefined ? 1 : maxUses, params };
}

/**
 * 解析并验证应急授权 JSON 结构
 * @param {Object} auth - 已 JSON.parse 的授权对象
 * @returns {{ valid: boolean, reason: string }}
 */
export function parseEmergencyAuthorization(auth) {
  if (!auth || typeof auth !== 'object' || Array.isArray(auth)) {
    return { valid: false, reason: 'Emergency authorization is null or not an object' };
  }

  if (auth.type !== 'emergency') {
    return { valid: false, reason: 'authorization type must be "emergency"' };
  }
  for (const field of ['authorizationId', 'operatorUserId', 'operatorCredentialId', 'createdAt']) {
    if (typeof auth[field] !== 'string' || auth[field].trim() === '') {
      return { valid: false, reason: `Missing required field: ${field}` };
    }
  }

  // grantee：单个平台地址字符串，禁止数组、禁止 "*" 通配
  if (typeof auth.grantee !== 'string' || !ETH_ADDRESS_RE.test(auth.grantee)) {
    return { valid: false, reason: 'grantee must be a single Ethereum address string (no wildcard, no array)' };
  }

  // timePolicy.deadline 必填且须为合法时间
  if (!auth.timePolicy || typeof auth.timePolicy !== 'object' || Array.isArray(auth.timePolicy)) {
    return { valid: false, reason: 'timePolicy is required and must be an object' };
  }
  if (!auth.timePolicy.deadline || Number.isNaN(Date.parse(auth.timePolicy.deadline))) {
    return { valid: false, reason: 'timePolicy.deadline is required and must be a valid date' };
  }
  if (auth.timePolicy.cronWindows !== undefined && !Array.isArray(auth.timePolicy.cronWindows)) {
    return { valid: false, reason: 'timePolicy.cronWindows must be an array' };
  }

  // wallets：非空数组，每个 userId 至多一条（精确匹配的前提）
  if (!Array.isArray(auth.wallets) || auth.wallets.length === 0) {
    return { valid: false, reason: 'wallets must be a non-empty array' };
  }
  const seenUserIds = new Set();
  for (const entry of auth.wallets) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      return { valid: false, reason: 'each wallets entry must be an object' };
    }
    if (typeof entry.userId !== 'string' || entry.userId.trim() === '') {
      return { valid: false, reason: 'each wallets entry requires a userId' };
    }
    if (seenUserIds.has(entry.userId)) {
      return { valid: false, reason: `duplicate wallets entry for userId: ${entry.userId}` };
    }
    seenUserIds.add(entry.userId);

    const ops = entry.policy?.operations;
    if (!ops || typeof ops !== 'object' || Array.isArray(ops) || Object.keys(ops).length === 0) {
      return { valid: false, reason: `wallets entry for userId ${entry.userId} requires a non-empty policy.operations` };
    }
    for (const [op, rawEntry] of Object.entries(ops)) {
      if (!EMERGENCY_OPERATIONS.includes(op)) {
        return { valid: false, reason: `unknown operation in policy for userId ${entry.userId}: ${op}` };
      }
      const normalized = normalizeOperationEntry(rawEntry);
      if (!normalized) {
        return { valid: false, reason: `invalid policy entry for operation ${op} (userId ${entry.userId}): must be true or an object with optional positive-integer maxUses` };
      }
      const params = normalized.params;

      // 操作特有参数的结构校验（只是字段形状，语义比对在校验器统一做）
      if (op === 'passkey_bind') {
        if (typeof params.newPubKeyHash !== 'string' || !BYTES32_RE.test(params.newPubKeyHash)) {
          return { valid: false, reason: 'passkey_bind policy requires newPubKeyHash (bytes32 hex): the key to bind must be pinned in the policy' };
        }
      }
      if (op === 'tx_sign') {
        for (const listField of ['targetAddresses', 'signingWallets']) {
          if (!Array.isArray(params[listField]) || params[listField].length === 0) {
            return { valid: false, reason: `tx_sign policy requires non-empty ${listField}` };
          }
          for (const item of params[listField]) {
            if (!item || item.chainId === undefined || typeof item.address !== 'string' || item.address === '') {
              return { valid: false, reason: `tx_sign policy ${listField} items require chainId and address` };
            }
          }
        }
        if (params.tokenRestrictions !== undefined) {
          if (!Array.isArray(params.tokenRestrictions)) {
            return { valid: false, reason: 'tx_sign policy tokenRestrictions must be an array' };
          }
          for (const item of params.tokenRestrictions) {
            if (!item || item.chainId === undefined || typeof item.tokenAddress !== 'string' || item.tokenAddress === '') {
              return { valid: false, reason: 'tx_sign policy tokenRestrictions items require chainId and tokenAddress' };
            }
          }
        }
      }
      if (op === 'passkey_delete' && params.credentialIdsToDelete !== undefined) {
        if (!Array.isArray(params.credentialIdsToDelete) || params.credentialIdsToDelete.length === 0) {
          return { valid: false, reason: 'passkey_delete policy credentialIdsToDelete must be a non-empty array when declared' };
        }
      }
      if ((op === 'wallet_create' || op === 'key_import') && params.chains !== undefined) {
        if (!Array.isArray(params.chains) || params.chains.length === 0) {
          return { valid: false, reason: `${op} policy chains must be a non-empty array when declared` };
        }
      }
    }
  }

  return { valid: true, reason: 'OK' };
}

/**
 * 查找某目标用户的授权条目
 * @param {Object} auth
 * @param {string} userId
 * @returns {Object|null}
 */
export function findWalletEntry(auth, userId) {
  return auth.wallets.find((w) => w.userId === userId) || null;
}

/**
 * 取某条目下某操作的规范化 policy（未授权返回 null）
 * @param {Object} walletEntry
 * @param {string} operation
 * @returns {{ maxUses: number, params: Object } | null}
 */
export function getOperationPolicy(walletEntry, operation) {
  const raw = walletEntry?.policy?.operations?.[operation];
  if (raw === undefined) return null;
  return normalizeOperationEntry(raw);
}
