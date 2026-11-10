/**
 * 应急授权通用校验器
 *
 * 全系统只有一个应急授权校验器，所有操作共用同一条流水线，不为任何单个
 * 业务新造授权逻辑；操作之间的差异全部来自授权原文里逐钱包 policy 的
 * 参数字段（数据），由本校验器统一解释：
 *
 *   1. 结构解析（emergency-authorization-parser）
 *   2. grantee 与本次请求的平台信封地址严格相等（单一平台、无通配）
 *   3. 目标用户不是治理方本人（应急授权只操作别人的钱包）
 *   4. 合约实时核查：按 authorizationId 精确查记录——不存在/已撤销/链上
 *      已过期一律拒绝；递进的授权全文与合约存储全文逐字一致；记录内的
 *      治理方、grantee、到期时间与授权原文互相一致。合约不可用直接拒绝
 *      （fail-closed），本校验器不读任何本地缓存的有效性状态。
 *   5. 治理身份：治理 Passkey 是治理方普通账户的 Passkey（本地 passkeys
 *      表查归属与公钥），其公钥哈希须与合约记录一致，且合约当场仍指定
 *      它为治理 Passkey（指定被移除即刻失效）。
 *   6. 治理签名：WebAuthn 签名对授权原文哈希（challenge = SHA256(原文)，
 *      与普通用户授权同一构造）验签通过。
 *   7. 时效：未过 deadline；声明了 cronWindows 时当前时间须在窗口内。
 *   8. 逐钱包 policy：目标用户条目存在、操作被该条目授权、本次请求的
 *      实际参数与该操作在 policy 中声明的参数相符（声明了才约束）。
 *   9. 次数：该 (授权, 目标用户, 操作) 已用次数小于 policy 的 maxUses。
 *
 * 使用计数在操作成功后由调用方经 recordUse 落库（tx_sign 在签名状态
 * 事务内用 StateManager 的事务内方法递增，保证原子性）。
 */

import { parseEmergencyAuthorization, findWalletEntry, getOperationPolicy } from './emergency-authorization-parser.js';
import { computeAuthorizationHash } from '../auth-engine/authorization-parser.js';
import { matchCron } from '../auth-engine/cron-matcher.js';
import { verifyWebAuthnSignature } from '../webauthn/verifier.js';
import { PasskeyManager } from '../webauthn/passkey-manager.js';
import { getMonotonicDate } from '../../utils/monotonic-clock.js';

function addressMatch(ruleAddress, actualAddress) {
  if (ruleAddress === '*') return true;
  return typeof actualAddress === 'string' && ruleAddress.toLowerCase() === actualAddress.toLowerCase();
}

function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
}

function deepEqual(a, b) {
  return stableStringify(a) === stableStringify(b);
}

/** 归一化导出地址项：字符串或 {address, chainId} → 小写地址字符串 */
function normalizeExportAddress(addr) {
  if (typeof addr === 'string') return addr.toLowerCase();
  if (addr && typeof addr === 'object' && typeof addr.address === 'string') return addr.address.toLowerCase();
  return null;
}

/**
 * 通用参数比对：policy 中声明了的参数才构成约束，未声明的参数不限制。
 * 特殊语义的键在此统一解释（集合包含类），其余键一律深等值比对。
 * @returns {{ ok: boolean, reason?: string }}
 */
function matchDeclaredParams(operation, declared, actual) {
  for (const [key, declaredValue] of Object.entries(declared)) {
    // tx_sign 的范围类字段由 checkTxScope 解释，不走等值比对
    if (operation === 'tx_sign') continue;

    const actualValue = actual ? actual[key] : undefined;

    if (key === 'chains') {
      // 链集合：实际使用的每条链都必须在声明集合内。
      // 实际值条目可能是裸 chainId，也可能是 { chainId, coinType } 对象
      // （wallet_create 的请求形状），统一取 chainId 比对；声明值同理。
      const chainIdOf = (c) => String(c && typeof c === 'object' ? c.chainId : c);
      if (!Array.isArray(actualValue) || actualValue.length === 0) {
        return { ok: false, reason: `parameter chains is required for ${operation}` };
      }
      const allowed = new Set(declaredValue.map(chainIdOf));
      for (const c of actualValue) {
        if (!allowed.has(chainIdOf(c))) {
          return { ok: false, reason: `chain ${chainIdOf(c)} not in policy-declared chains for ${operation}` };
        }
      }
      continue;
    }

    if (key === 'credentialIdsToDelete') {
      // 删除集合：实际删除的每个 credentialId 都必须在声明集合内
      if (!Array.isArray(actualValue) || actualValue.length === 0) {
        return { ok: false, reason: 'parameter credentialIdsToDelete is required for passkey_delete' };
      }
      const allowed = new Set(declaredValue);
      for (const id of actualValue) {
        if (!allowed.has(id)) {
          return { ok: false, reason: `credentialId ${id} not in policy-declared credentialIdsToDelete` };
        }
      }
      continue;
    }

    if (key === 'exportInfo') {
      // 导出清单：实际导出的每个钱包必须在声明清单内；声明项 addresses
      // 非空时实际地址必须是其子集，声明为空数组表示该钱包全部地址可导出
      if (!Array.isArray(actualValue) || actualValue.length === 0) {
        return { ok: false, reason: 'parameter exportInfo is required for key_export' };
      }
      const declaredByWallet = new Map(declaredValue.map((item) => [item.walletId, item]));
      for (const item of actualValue) {
        const declaredItem = declaredByWallet.get(item.walletId);
        if (!declaredItem) {
          return { ok: false, reason: `walletId ${item.walletId} not in policy-declared exportInfo` };
        }
        const declaredAddrs = (declaredItem.addresses || []).map(normalizeExportAddress);
        if (declaredAddrs.length > 0) {
          for (const addr of item.addresses || []) {
            if (!declaredAddrs.includes(normalizeExportAddress(addr))) {
              return { ok: false, reason: `address ${normalizeExportAddress(addr)} not in policy-declared exportInfo for walletId ${item.walletId}` };
            }
          }
        }
      }
      continue;
    }

    // 其余声明参数：深等值（实际值必须与声明值完全一致）
    if (!deepEqual(declaredValue, actualValue)) {
      return { ok: false, reason: `parameter ${key} mismatch for ${operation}: policy declares ${stableStringify(declaredValue)}, actual is ${stableStringify(actualValue)}` };
    }
  }
  return { ok: true };
}

/**
 * tx_sign 的范围检查：与普通用户授权 AuthEngine 第 9–12 项同一语义，
 * policy 的 tx_sign 参数即普通授权的 scope 形状。
 * @returns {{ ok: boolean, reason?: string }}
 */
function checkTxScope(scope, tx) {
  const targetAllowed = scope.targetAddresses.some(
    (t) => Number(t.chainId) === Number(tx.chainId) && addressMatch(t.address, tx.toAddress)
  );
  if (!targetAllowed) return { ok: false, reason: 'Target address not in emergency-authorized list' };

  const walletAllowed = scope.signingWallets.some(
    (w) => Number(w.chainId) === Number(tx.chainId) && addressMatch(w.address, tx.fromAddress)
  );
  if (!walletAllowed) return { ok: false, reason: 'Signing wallet not in emergency-authorized scope' };

  if (scope.amountLimits) {
    const txAmount = BigInt(tx.amount);
    if (scope.amountLimits.min && txAmount < BigInt(scope.amountLimits.min)) {
      return { ok: false, reason: 'Transaction amount below minimum' };
    }
    if (scope.amountLimits.max && txAmount > BigInt(scope.amountLimits.max)) {
      return { ok: false, reason: 'Transaction amount above maximum' };
    }
  }

  if (scope.tokenRestrictions && scope.tokenRestrictions.length > 0) {
    const tokenAllowed = scope.tokenRestrictions.some(
      (t) => Number(t.chainId) === Number(tx.chainId) && addressMatch(t.tokenAddress, tx.tokenAddress)
    );
    if (!tokenAllowed) return { ok: false, reason: 'Token/chain not in emergency-authorized restrictions' };
  }

  return { ok: true };
}

export class EmergencyAuthorizer {
  /**
   * @param {Object} deps
   * @param {import('../contract-client/index.js').ContractClient} deps.contractClient
   * @param {import('../webauthn/passkey-manager.js').PasskeyManager} deps.passkeyManager
   * @param {import('../state-management/state-manager.js').StateManager} deps.stateManager
   * @param {Function} [deps.verifyWebAuthnSignatureFn] - 测试注入用，缺省为真实 WebAuthn 验签
   */
  constructor(deps) {
    if (!deps.contractClient) throw new Error('EmergencyAuthorizer requires contractClient');
    if (!deps.passkeyManager) throw new Error('EmergencyAuthorizer requires passkeyManager');
    if (!deps.stateManager) throw new Error('EmergencyAuthorizer requires stateManager');
    this._contract = deps.contractClient;
    this._passkey = deps.passkeyManager;
    this._state = deps.stateManager;
    this._verifySignature = deps.verifyWebAuthnSignatureFn || verifyWebAuthnSignature;
  }

  /**
   * 执行完整的应急授权校验（每次执行都重新实时查合约，不缓存有效性）
   *
   * @param {Object} args
   * @param {string} args.authorizationJson - 授权 JSON 原始字符串（与上链全文逐字比对）
   * @param {Object} args.signature - 治理 Passkey 的 WebAuthn 签名对象
   * @param {string} args.platformAddress - 本次请求平台信封签名恢复出的地址
   * @param {string} args.operation - 操作名（见 EMERGENCY_OPERATIONS）
   * @param {string} args.userId - 目标用户（被操作的钱包归属用户）
   * @param {Object} [args.actualParams] - 本次操作实际参数（与 policy 声明比对）
   * @param {Object} [args.tx] - operation=tx_sign 时的交易字段 { chainId, toAddress, fromAddress, amount, tokenAddress }
   * @returns {Promise<{ approved: boolean, reason?: string, auth?: Object, walletEntry?: Object, opPolicy?: Object, operatorPubKeyHash?: string }>}
   */
  async verify({ authorizationJson, signature, platformAddress, operation, userId, actualParams = {}, tx = null }) {
    const reject = (reason) => {
      console.log(`[EmergencyAuthorizer] REJECTED operation=${operation}, userId=${userId}: ${reason}`);
      return { approved: false, reason };
    };

    if (typeof authorizationJson !== 'string' || authorizationJson.length === 0) {
      return reject('emergencyAuthorizationJson is required and must be the raw JSON string');
    }
    if (!signature) return reject('emergencySignature is required');
    if (!platformAddress) return reject('platform address is required');

    // 1. 结构解析
    let auth;
    try {
      auth = JSON.parse(authorizationJson);
    } catch {
      return reject('emergencyAuthorizationJson is not valid JSON');
    }
    const parseResult = parseEmergencyAuthorization(auth);
    if (!parseResult.valid) return reject(parseResult.reason);

    // 2. grantee 与平台信封地址严格相等
    if (auth.grantee.toLowerCase() !== platformAddress.toLowerCase()) {
      return reject('grantee does not match the requesting platform address');
    }

    // 3. 只操作别人的钱包：目标用户不得是治理方本人
    if (userId === auth.operatorUserId) {
      return reject('emergency authorization cannot operate on the operator account itself');
    }

    // 4. 合约实时核查（fail-closed：查不到、不可用、已撤销、已过期、文本不一致都拒绝）
    let record;
    try {
      record = await this._contract.getEmergencyAuthorization(auth.authorizationId);
    } catch (err) {
      return reject(`Contract unavailable: cannot verify emergency authorization (${err.message})`);
    }
    if (!record) return reject('no emergency authorization record on contract for this authorizationId');
    if (record.revoked) return reject('emergency authorization has been revoked on contract');
    if (record.authorizationJson !== authorizationJson) {
      return reject('authorization text does not match the contract record');
    }
    if (record.operatorUserId !== auth.operatorUserId) {
      return reject('operator in authorization does not match the contract record');
    }
    if (record.grantee.toLowerCase() !== auth.grantee.toLowerCase()) {
      return reject('grantee does not match the contract record');
    }
    const deadlineMs = Date.parse(auth.timePolicy.deadline);
    if (Math.floor(deadlineMs / 1000) !== record.expiresAt) {
      return reject('timePolicy.deadline does not match the contract record expiresAt');
    }
    const now = getMonotonicDate();
    if (record.expiresAt * 1000 <= now.getTime()) {
      return reject('emergency authorization has expired on contract');
    }

    // 5. 治理身份：本地归属 + 公钥哈希与记录一致 + 合约当场仍指定为治理 Passkey
    const passkey = await this._passkey.getPasskey(auth.operatorUserId, auth.operatorCredentialId);
    if (!passkey) return reject('governance passkey not bound to the operator account');
    const operatorPubKeyHash = PasskeyManager.computePubKeyHash(passkey.publicKeyCose);
    if (operatorPubKeyHash.toLowerCase() !== record.operatorPubKeyHash.toLowerCase()) {
      return reject('governance passkey public key does not match the contract record');
    }
    let designated;
    try {
      designated = await this._contract.isGovernancePasskey(auth.operatorUserId, operatorPubKeyHash);
    } catch (err) {
      return reject(`Contract unavailable: cannot verify governance designation (${err.message})`);
    }
    if (!designated) return reject('passkey is not currently designated as a governance passkey on contract');

    // 6. 治理签名：challenge = SHA256(授权原文)，与普通用户授权同一构造
    const expectedChallenge = computeAuthorizationHash(authorizationJson);
    const sigResult = await this._verifySignature({
      userId: auth.operatorUserId,
      credentialId: auth.operatorCredentialId,
      webauthnSignature: signature,
      expectedChallenge,
      publicKeyCose: passkey.publicKeyCose,
    });
    if (!sigResult.verified) return reject(`governance passkey signature invalid: ${sigResult.reason || 'verification failed'}`);

    // 7. 时效
    if (deadlineMs <= now.getTime()) return reject('emergency authorization has expired');
    const cronWindows = auth.timePolicy.cronWindows || [];
    if (cronWindows.length > 0 && !cronWindows.some((cron) => matchCron(cron, now))) {
      return reject('current time not in allowed cron window');
    }

    // 8. 逐钱包 policy：条目、操作授权、参数相符
    const walletEntry = findWalletEntry(auth, userId);
    if (!walletEntry) return reject(`no policy entry for target userId ${userId} in this authorization`);
    const opPolicy = getOperationPolicy(walletEntry, operation);
    if (!opPolicy) return reject(`operation ${operation} is not authorized for userId ${userId} in this authorization`);

    if (operation === 'tx_sign') {
      if (!tx) return reject('tx context is required for tx_sign verification');
      const scopeResult = checkTxScope(opPolicy.params, tx);
      if (!scopeResult.ok) return reject(scopeResult.reason);
    } else {
      const matchResult = matchDeclaredParams(operation, opPolicy.params, actualParams);
      if (!matchResult.ok) return reject(matchResult.reason);
    }

    // 9. 次数上限（只读本地消费计数；有效性判定不依赖本地状态）
    const used = await this._state.getEmergencyUseCount(auth.authorizationId, userId, operation);
    if (used >= opPolicy.maxUses) {
      return reject(`operation ${operation} use limit reached for userId ${userId}: used=${used}, maxUses=${opPolicy.maxUses}`);
    }

    console.log(`[EmergencyAuthorizer] APPROVED operation=${operation}, userId=${userId}, authorizationId=${auth.authorizationId}, used=${used}/${opPolicy.maxUses}`);
    // 本次授权中同样被授权了该操作的所有目标用户（批量类操作逐条目约束时用）
    const authorizedUserIds = auth.wallets
      .filter((w) => getOperationPolicy(w, operation) !== null)
      .map((w) => w.userId);
    return { approved: true, auth, walletEntry, opPolicy, operatorPubKeyHash, authorizedUserIds };
  }

  /**
   * 操作成功后记录一次使用（tx_sign 由 handler 在其状态事务内递增，不走此方法）
   * @param {Object} auth - 已验签的授权对象
   * @param {string} userId - 目标用户
   * @param {string} operation
   */
  async recordUse(auth, userId, operation) {
    return this._state.recordEmergencyUse(auth.authorizationId, userId, operation);
  }
}
