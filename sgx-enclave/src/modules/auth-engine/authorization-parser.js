/**
 * 授权 JSON 结构解析与验证
 * 检查必填字段完整性，返回解析结果
 */

import crypto from 'crypto';

/**
 * 必填字段路径定义
 */
const REQUIRED_FIELDS = [
  'authorizationId',
  'userId',
  'grantee',
  'credentialId',
  'webauthnSignature',
  // webauthnSignature 内部字段由 verifier.js 验证，支持两种格式：
  //   格式1（Browser WebAuthn API response）：{ response: { authenticatorData, clientDataJSON, signature } }
  //   格式2（直接格式）：{ authenticatorData, clientDataJSON, signature }
  'scope',
  'scope.targetAddresses',
  'scope.signingWallets',
  'timePolicy',
  'createdAt',
];

/**
 * 已知的以太坊交易类型
 */
export const KNOWN_TX_TYPES = {
  LEGACY: 0,          // type 0 — Legacy
  EIP_2930: 1,        // type 1 — Access List
  EIP_1559: 2,        // type 2 — EIP-1559
  EIP_7702: 4,        // type 4 — SET_CODE_TX_TYPE (EIP-7702)
};

const ALL_KNOWN_TX_TYPE_VALUES = Object.values(KNOWN_TX_TYPES);

/**
 * 已知的操作类型（由签名模块自动识别）
 */
export const KNOWN_OPERATIONS = [
  'transfer',        // 基本转账（type 0/1/2，to 有值，data 为空/0x）
  'contractCall',    // 合约调用（type 0/1/2，to 有值，data 非空）
  'contractDeploy',  // 合约部署（type 0/1/2，to 为 null，data 非空）
  'eip7702Auth',     // EIP-7702 授权签名（用户 EOA 签名的委托授权数据）
  'eip7702Tx',       // EIP-7702 交易（type=4，含 authorizationList）
  'arbitraryData',   // 任意二进制（无法识别为以上任何类型）
];

/**
 * 按路径获取嵌套对象的值
 * @param {Object} obj
 * @param {string} path - 点分隔路径
 * @returns {*}
 */
function getNestedValue(obj, path) {
  const keys = path.split('.');
  let current = obj;
  for (const key of keys) {
    if (current === null || current === undefined) {
      return undefined;
    }
    current = current[key];
  }
  return current;
}

/**
 * 解析并验证授权 JSON 结构
 *
 * @param {Object} auth - 授权 JSON 对象
 * @returns {{ valid: boolean, reason: string }}
 */
export function parseAuthorization(auth) {
  console.log(`[AuthorizationParser] parseAuthorization: authorizationId=${auth?.authorizationId || 'N/A'}, userId=${auth?.userId || 'N/A'}`);

  if (!auth || typeof auth !== 'object') {
    console.log(`[AuthorizationParser] parseAuthorization: INVALID - null or not an object`);
    return { valid: false, reason: 'Authorization is null or not an object' };
  }

  // 检查所有必填字段
  for (const field of REQUIRED_FIELDS) {
    const value = getNestedValue(auth, field);
    if (value === undefined || value === null || value === '') {
      return { valid: false, reason: `Missing required field: ${field}` };
    }
  }

  // 检查 grantee 是非空数组，每个元素是地址字符串或 "*"
  if (!Array.isArray(auth.grantee) || auth.grantee.length === 0) {
    return { valid: false, reason: 'grantee must be a non-empty array' };
  }
  for (const g of auth.grantee) {
    if (typeof g !== 'string' || g.trim() === '') {
      return { valid: false, reason: 'Each grantee must be a non-empty string (address or "*")' };
    }
  }

  // 检查 targetAddresses 是非空数组
  if (!Array.isArray(auth.scope.targetAddresses) || auth.scope.targetAddresses.length === 0) {
    return { valid: false, reason: 'scope.targetAddresses must be a non-empty array' };
  }

  // 检查 signingWallets 是非空数组
  if (!Array.isArray(auth.scope.signingWallets) || auth.scope.signingWallets.length === 0) {
    return { valid: false, reason: 'scope.signingWallets must be a non-empty array' };
  }

  // 检查 targetAddresses 结构
  for (const item of auth.scope.targetAddresses) {
    if (item.chainId === undefined || !item.address) {
      return { valid: false, reason: 'Invalid targetAddresses item: requires chainId and address' };
    }
  }

  // 检查 signingWallets 结构
  for (const item of auth.scope.signingWallets) {
    if (item.chainId === undefined || !item.address) {
      return { valid: false, reason: 'Invalid signingWallets item: requires chainId and address' };
    }
  }

  // 验证 dataPolicy（数据策略，控制允许的交易类型和是否允许任意二进制签名）
  if (auth.scope.dataPolicy) {
    const dp = auth.scope.dataPolicy;

    // allowedTxTypes 如果存在，必须是数组且值都是已知类型
    if (dp.allowedTxTypes !== undefined) {
      if (!Array.isArray(dp.allowedTxTypes)) {
        return { valid: false, reason: 'scope.dataPolicy.allowedTxTypes must be an array' };
      }
      for (const t of dp.allowedTxTypes) {
        if (!ALL_KNOWN_TX_TYPE_VALUES.includes(t)) {
          return { valid: false, reason: `Unknown tx type in allowedTxTypes: ${t}` };
        }
      }
    }

    // allowedOperations 如果存在，必须是数组且值都是已知操作类型
    if (dp.allowedOperations !== undefined) {
      if (!Array.isArray(dp.allowedOperations)) {
        return { valid: false, reason: 'scope.dataPolicy.allowedOperations must be an array' };
      }
      for (const op of dp.allowedOperations) {
        if (!KNOWN_OPERATIONS.includes(op)) {
          return { valid: false, reason: `Unknown operation in allowedOperations: ${op}` };
        }
      }
    }

    // allowArbitraryData 如果存在，必须是布尔值
    if (dp.allowArbitraryData !== undefined && typeof dp.allowArbitraryData !== 'boolean') {
      return { valid: false, reason: 'scope.dataPolicy.allowArbitraryData must be a boolean' };
    }
  }

  // 验证 revocationPolicy（撤销检查策略，必填）
  if (!auth.revocationPolicy || typeof auth.revocationPolicy !== 'object' || Array.isArray(auth.revocationPolicy)) {
    return { valid: false, reason: 'revocationPolicy is required and must be an object' };
  }
  if (typeof auth.revocationPolicy.allowContractUnavailable !== 'boolean') {
    return { valid: false, reason: 'revocationPolicy.allowContractUnavailable is required and must be a boolean' };
  }

  // 验证 eip7702Policy（EIP-7702 策略）
  if (auth.scope.eip7702Policy) {
    const ep = auth.scope.eip7702Policy;

    // allowedDelegateContracts 如果存在，必须是数组，每个元素含 chainId 和 address
    if (ep.allowedDelegateContracts !== undefined) {
      if (!Array.isArray(ep.allowedDelegateContracts)) {
        return { valid: false, reason: 'scope.eip7702Policy.allowedDelegateContracts must be an array' };
      }
      for (const item of ep.allowedDelegateContracts) {
        if (item.chainId === undefined || !item.address) {
          return { valid: false, reason: 'Invalid allowedDelegateContracts item: requires chainId and address' };
        }
      }
    }

    // allowedFunctionSelectors 如果存在，必须是数组，每个元素是 4 字节 hex 字符串
    if (ep.allowedFunctionSelectors !== undefined) {
      if (!Array.isArray(ep.allowedFunctionSelectors)) {
        return { valid: false, reason: 'scope.eip7702Policy.allowedFunctionSelectors must be an array' };
      }
      for (const sel of ep.allowedFunctionSelectors) {
        if (typeof sel !== 'string' || !/^0x[0-9a-fA-F]{8}$/.test(sel)) {
          return { valid: false, reason: `Invalid function selector: ${sel} (must be 0x + 8 hex chars)` };
        }
      }
    }
  }

  // 验证 tokenRestrictions 中的 tokenAddress
  if (auth.scope.tokenRestrictions) {
    if (!Array.isArray(auth.scope.tokenRestrictions)) {
      return { valid: false, reason: 'scope.tokenRestrictions must be an array' };
    }
    
    for (const item of auth.scope.tokenRestrictions) {
      if (item.chainId === undefined || !item.tokenAddress) {
        return { valid: false, reason: 'Invalid tokenRestrictions item: requires chainId and tokenAddress' };
      }
      
      // 验证tokenAddress格式：合法以太坊地址、"*" 通配符、或带 chainId 前缀的特殊标识符
      if (!isValidTokenAddress(item.tokenAddress, item.chainId)) {
        return {
          valid: false,
          reason: `Invalid tokenAddress: ${item.tokenAddress}. Must be a valid Ethereum address, "*" wildcard, or special identifier "${item.chainId}_native" / "${item.chainId}_unknown"`
        };
      }
    }
  }

  // 验证 cumulativeLimits.tokenLimits 中的键格式
  if (auth.scope.cumulativeLimits && auth.scope.cumulativeLimits.tokenLimits) {
    const tokenLimits = auth.scope.cumulativeLimits.tokenLimits;
    
    for (const key in tokenLimits) {
      // 键格式应为 "chainId_tokenAddress"，其中 tokenAddress 部分可以是：
      //   - 合法以太坊地址（0x + 40 hex）
      //   - "native"（原生代币）
      //   - "unknown"（未知 token）
      // 注意：tokenAddress 部分本身不含 chainId 前缀
      const underscoreIdx = key.indexOf('_');
      if (underscoreIdx === -1) {
        return {
          valid: false,
          reason: `Invalid tokenLimits key: ${key}. Must be in format 'chainId_tokenAddress'`
        };
      }
      
      const chainId = key.slice(0, underscoreIdx);
      const tokenAddress = key.slice(underscoreIdx + 1);
      
      // 验证chainId是否为数字
      if (isNaN(parseInt(chainId))) {
        return {
          valid: false,
          reason: `Invalid chainId in tokenLimits key: ${key}. ChainId must be a number`
        };
      }
      
      // 验证tokenAddress部分是否有效（合法以太坊地址、"native" 或 "unknown"）
      if (!/^0x[0-9a-fA-F]{40}$/.test(tokenAddress) &&
          tokenAddress !== 'native' &&
          tokenAddress !== 'unknown') {
        return {
          valid: false,
          reason: `Invalid tokenAddress in tokenLimits key: ${key}. Must be a valid Ethereum address, "native", or "unknown"`
        };
      }
    }
  }

  console.log(`[AuthorizationParser] parseAuthorization: VALID - granteeCount=${auth.grantee.length}, targetCount=${auth.scope.targetAddresses.length}, walletCount=${auth.scope.signingWallets.length}, hasDataPolicy=${!!auth.scope.dataPolicy}, hasEip7702Policy=${!!auth.scope.eip7702Policy}, hasRevocationPolicy=${!!auth.revocationPolicy}`);
  return { valid: true, reason: 'OK' };
}

/**
 * 验证 tokenRestrictions 中的 tokenAddress 是否有效
 *
 * 合法值：
 *   1. 合法以太坊地址：0x + 40 位十六进制
 *   2. 通配符 "*"：匹配任意 token
 *   3. 带 chainId 前缀的特殊标识符："{chainId}_native" 或 "{chainId}_unknown"
 *      必须带 chainId 前缀，以明确标识是哪条链的原生币
 *
 * 注意：不允许裸 "native" 或 "unknown"，因为无法确定是哪条链的原生币
 *
 * @param {string} tokenAddress - 待验证的 token 地址
 * @param {number} chainId - 链 ID
 * @returns {boolean} 是否有效
 */
function isValidTokenAddress(tokenAddress, chainId) {
  // 通配符 "*"：匹配任意 token
  if (tokenAddress === '*') {
    return true;
  }

  // 合法以太坊地址：0x + 40 位十六进制
  if (/^0x[0-9a-fA-F]{40}$/.test(tokenAddress)) {
    return true;
  }

  // 带 chainId 前缀的特殊标识符："{chainId}_native" 或 "{chainId}_unknown"
  // 必须带前缀，不允许裸 "native" 或 "unknown"
  if (tokenAddress === `${chainId}_native` || tokenAddress === `${chainId}_unknown`) {
    return true;
  }

  // 不满足以上任何条件，则无效
  return false;
}

/**
 * 计算授权信息的 SHA256 哈希（base64url 编码）
 * 用于作为 WebAuthn challenge 值
 *
 * 重要：接受原始 JSON 字符串（不是对象），直接对字符串计算哈希。
 * 这样才能保证客户端和服务端对同一字符串计算哈希，WebAuthn 验证才能通过。
 *
 * 客户端流程：
 *   1. 构造授权 JSON 字符串（不含 webauthnSignature）
 *   2. 调用此函数计算哈希，作为 WebAuthn challenge
 *   3. 用 Passkey 对 challenge 签名
 *   4. 将授权 JSON 字符串（不是对象）放在 payload.authorization 中传给服务端
 *
 * 服务端流程：
 *   1. 从 payload 中取出 authorization 字符串
 *   2. 调用此函数计算哈希
 *   3. 与 WebAuthn clientDataJSON.challenge 比对
 *
 * @param {string} authorizationJson - 授权 JSON 字符串（不含 webauthnSignature）
 * @returns {string} base64url 编码的 SHA256 哈希
 */
export function computeAuthorizationHash(authorizationJson) {
  if (typeof authorizationJson !== 'string') {
    throw new Error('computeAuthorizationHash: authorizationJson must be a string, not an object');
  }

  // 解析以获取 authorizationId 和 userId 用于日志
  let authId = 'N/A', userId = 'N/A';
  try {
    const parsed = JSON.parse(authorizationJson);
    authId = parsed.authorizationId || 'N/A';
    userId = parsed.userId || 'N/A';
  } catch {}

  console.log(`[AuthorizationParser] computeAuthorizationHash: authorizationId=${authId}, userId=${userId}`);

  // 直接对原始 JSON 字符串计算哈希（不做任何 parse/stringify 转换）
  const hash = crypto.createHash('sha256').update(authorizationJson).digest();

  // base64url 编码（符合 WebAuthn 标准）
  const result = hash.toString('base64url');
  console.log(`[AuthorizationParser] computeAuthorizationHash: hash computed (base64url length=${result.length})`);
  return result;
}
