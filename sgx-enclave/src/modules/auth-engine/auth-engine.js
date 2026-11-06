/**
 * 授权验证引擎
 * 完整实现 14 项检查清单，按顺序执行，任一失败即拒绝签名
 *
 * 依赖模块：
 * - whitelist (TODO-06): verifyRequest() — 第 1 项
 * - webauthn (TODO-07): verifyPasskeyOwnership(), verifyWebAuthnSignature() — 第 3-5 项
 * - ContractClient (TODO-05): getAuthorizationRevocation() — 第 6 项（本地撤销记录未命中时的兜底查询）
 * - state-management (TODO-10): checkLimits() — 第 13 项
 * - wallet-management (TODO-08): getWalletByAddress() — 第 14 项
 */

import { parseAuthorization, computeAuthorizationHash } from './authorization-parser.js';
import { matchCron } from './cron-matcher.js';
import { verifyWebAuthnSignature } from '../webauthn/verifier.js';
import { getMonotonicDate } from '../../utils/monotonic-clock.js';

/**
 * 统一的地址匹配函数，支持 "*" 通配符
 * @param {string} ruleAddress - 规则中的地址（或 "*"）
 * @param {string} actualAddress - 实际地址
 * @returns {boolean}
 */
function addressMatch(ruleAddress, actualAddress) {
  if (ruleAddress === '*') return true;
  return ruleAddress.toLowerCase() === actualAddress.toLowerCase();
}

export class AuthEngine {
  /**
   * @param {Object} deps - 依赖注入
   * @param {import('../whitelist/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../contract-client/index.js').ContractClient} deps.contractClient
   * @param {import('../webauthn/passkey-manager.js').PasskeyManager} deps.passkeyManager
   * @param {import('../state-management/state-manager.js').StateManager} deps.stateManager
   * @param {import('../wallet-management/wallet-manager.js').WalletManager} deps.walletManager
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('AuthEngine requires whitelistVerifier');
    if (!deps.contractClient) throw new Error('AuthEngine requires contractClient');
    if (!deps.passkeyManager) throw new Error('AuthEngine requires passkeyManager');
    if (!deps.stateManager) throw new Error('AuthEngine requires stateManager');
    if (!deps.walletManager) throw new Error('AuthEngine requires walletManager');

    this._whitelist = deps.whitelistVerifier;
    this._contract = deps.contractClient;
    this._passkey = deps.passkeyManager;
    this._state = deps.stateManager;
    this._wallet = deps.walletManager;
  }

  /**
   * 执行完整的 14 项授权验证
   *
   * @param {Object} request - 签名请求
   * @param {string} request.platformSignature - 平台 secp256k1 签名（十六进制，含 0x 前缀）
   * @param {string} request.payload - 请求体（被平台签名的原始数据）
   * @param {Object} request.authorization - 授权 JSON
   * @param {Object} request.transaction - 交易信息
   * @param {number} request.transaction.chainId - 链 ID
   * @param {string} request.transaction.toAddress - 目标地址
   * @param {string} request.transaction.fromAddress - 签名钱包地址
   * @param {string} request.transaction.amount - 交易金额（Wei 字符串）
   * @param {string} request.transaction.tokenAddress - Token 地址（原生代币使用 "{chainId}_native" 格式，如 "1_native"）
   * @returns {Promise<{ approved: boolean, step: number, reason: string }>}
   */
  async verify(request) {
    const auth = request.authorization;
    const tx = request.transaction;

    console.log(`[AuthEngine] verify: userId=${auth.userId}, authorizationId=${auth.authorizationId}, chainId=${tx.chainId}, toAddress=${tx.toAddress}`);

    // ===== 第 1 项：验证平台请求签名（公钥在合约白名单中） =====
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[AuthEngine] verify: REJECTED at step 1 - ${whitelistResult.reason}`);
      return { approved: false, step: 1, reason: whitelistResult.reason };
    }
    console.log(`[AuthEngine] verify: step 1 passed, platformAddress=${whitelistResult.address}`);
    const platformAddress = whitelistResult.address;

    // ===== 第 2 项：解析授权信息，验证结构完整性 + grantee 匹配 =====
    const parseResult = parseAuthorization(auth);
    if (!parseResult.valid) {
      return { approved: false, step: 2, reason: parseResult.reason };
    }
    // 检查 grantee 数组与平台地址匹配（支持 "*" 通配符）
    const granteeList = Array.isArray(auth.grantee) ? auth.grantee : [auth.grantee];
    const granteeMatch = granteeList.some((g) => addressMatch(g, platformAddress));
    if (!granteeMatch) {
      console.log(`[AuthEngine] verify: REJECTED at step 2 - grantee mismatch`);
      return { approved: false, step: 2, reason: 'Grantee does not match platform address' };
    }

    // ===== 第 3 项：校验 Passkey 绑定在该 userId 下 =====
    const ownershipValid = await this._passkey.verifyPasskeyOwnership(auth.userId, auth.credentialId);
    if (!ownershipValid) {
      console.log(`[AuthEngine] verify: REJECTED at step 3 - passkey not bound`);
      return { approved: false, step: 3, reason: 'Passkey not bound to user' };
    }

    // ===== 第 4 项：计算授权信息 SHA256 哈希并比对 =====
    // 重要：必须使用原始 JSON 字符串（authorizationJson）计算哈希，而不是对象序列化
    // 这样才能保证客户端和服务端对同一字符串计算哈希，WebAuthn 验证才能通过
    // authorizationJson 由 tx-signing.js 从 payload 中提取的原始字符串
    const authorizationJson = request.authorizationJson;
    if (!authorizationJson) {
      return { approved: false, step: 4, reason: 'authorizationJson is required (authorization must be passed as JSON string)' };
    }
    const authHash = computeAuthorizationHash(authorizationJson);

    // ===== 第 5 项：使用 Passkey 公钥验证 WebAuthn 签名（同时验证 challenge = authHash） =====
    const passkey = await this._passkey.getPasskey(auth.userId, auth.credentialId);
    if (!passkey) {
      return { approved: false, step: 5, reason: 'Passkey not found' };
    }
    const sigResult = await verifyWebAuthnSignature({
      userId: auth.userId,
      credentialId: auth.credentialId,
      webauthnSignature: auth.webauthnSignature,
      expectedChallenge: authHash,
      publicKeyCose: passkey.publicKeyCose,
    });
    if (!sigResult.verified) {
      console.log(`[AuthEngine] verify: REJECTED at step 5 - WebAuthn signature invalid`);
      return { approved: false, step: 5, reason: sigResult.reason };
    }

    // ===== 第 6 项：查询撤销记录，确认授权未被撤销（本地优先，合约兜底） =====
    // 顺序与来源语义：
    //   1. 先查本地 authorization_revocations 表。命中即以本地为准，不查合约：
    //      - source=platform：平台转发的用户撤销，SGX 直接记录，与合约无关；
    //      - source=contract：此前合约查询结果的缓存。缓存若与链上不一致（链上
    //        已无此记录），由 StateManager.reconcileContractRevocations 在清理
    //        周期内对账删除，本项不为单笔交易重复对账。
    //   2. 本地未命中才查合约（兜底：平台不配合转发时，用户直接在合约上撤销，
    //      合约不受平台控制，平台无法拒绝）。查到撤销 → 以 source=contract
    //      写入本地缓存，后续交易走第 1 步；未查到 → 放行。
    //   3. 本地记录已随授权到期失效（authorizationExpiresAt <= now）→ 删除并
    //      打日志（deleteRevocation 内含），按未命中处理；授权本身是否过期由
    //      第 7 项判定。
    // revocationPolicy.allowContractUnavailable（必填布尔值）只决定第 2 步合约
    // 不可用时的行为：true → 无本地记录时放行；false → 拒绝。
    const allowContractUnavailable = auth.revocationPolicy.allowContractUnavailable;
    const authorizationExpiresAt = auth.timePolicy?.deadline
      ? new Date(auth.timePolicy.deadline).toISOString()
      : null;

    let localRevocation = await this._state.getRevocation(auth.userId, auth.authorizationId);
    if (localRevocation?.authorizationExpiresAt
        && new Date(localRevocation.authorizationExpiresAt) <= getMonotonicDate()) {
      await this._state.deleteRevocation(auth.userId, auth.authorizationId, { reason: 'authorization expired' })
        .catch(() => {});
      localRevocation = null;
    }

    if (localRevocation) {
      // 用本次已验签的授权原文补齐本地记录缺失的到期时间/哈希（不改变来源）
      if ((!localRevocation.authorizationExpiresAt && authorizationExpiresAt)
          || (!localRevocation.authorizationHash && authHash)) {
        localRevocation = await this._state.recordRevocation({
          userId: auth.userId,
          authorizationId: auth.authorizationId,
          grantee: localRevocation.grantee,
          source: localRevocation.source,
          revokedAt: localRevocation.revokedAt,
          authorizationExpiresAt: authorizationExpiresAt || localRevocation.authorizationExpiresAt,
          authorizationHash: authHash || localRevocation.authorizationHash,
        }).catch(() => localRevocation);
      }
      console.log(`[AuthEngine] verify: REJECTED at step 6 - authorization revoked (local record, source=${localRevocation.source})`);
      return { approved: false, step: 6, reason: `Authorization has been revoked (source: ${localRevocation.source})` };
    }

    // 本地未命中 → 合约兜底查询
    try {
      const contractRevocation = await this._contract.getAuthorizationRevocation(auth.userId, auth.authorizationId);
      if (contractRevocation) {
        // 合约确认已撤销 → 缓存到本地（source=contract），后续交易本地命中
        await this._state.recordRevocation({
          userId: auth.userId,
          authorizationId: auth.authorizationId,
          grantee: contractRevocation.grantee,
          source: 'contract',
          revokedAt: contractRevocation.revokedAt,
          authorizationExpiresAt,
          authorizationHash: authHash,
        }).catch(() => {});
        console.log(`[AuthEngine] verify: REJECTED at step 6 - authorization revoked (contract)`);
        return { approved: false, step: 6, reason: 'Authorization has been revoked' };
      }
      // 合约明确无此撤销记录：若本地在此期间同步来一条 contract 来源记录，
      // 它与链上状态矛盾，按来源规则删除该缓存（platform 来源不受此影响，
      // 上面的本地命中分支已先行处理，不会走到这里）。
      const concurrentRevocation = await this._state.getRevocation(auth.userId, auth.authorizationId);
      if (concurrentRevocation?.source === 'contract') {
        await this._state.deleteRevocation(auth.userId, auth.authorizationId, {
          expectedSource: 'contract',
          reason: 'contract query returned no revocation record',
          restoreState: true,
        }).catch(() => {});
      }
      // 确保本地有 active 状态缓存，供后续回退查询
      await this._state.getOrCreateState(auth.authorizationId, auth.userId, auth.grantee).catch(() => {});
    } catch (err) {
      // 合约不可用（未配置或不可达），且本地无撤销记录
      if (allowContractUnavailable) {
        console.warn(`[AuthEngine] verify: step 6 - contract unavailable, allowContractUnavailable=true, no local revocation record, skipping revocation check`);
      } else {
        console.log(`[AuthEngine] verify: REJECTED at step 6 - contract unavailable, cannot verify revocation: ${err.message}`);
        return { approved: false, step: 6, reason: 'Contract unavailable: cannot verify revocation status' };
      }
    }

    // ===== 第 7 项：检查授权截止日期 =====
    const now = getMonotonicDate();
    if (auth.timePolicy.deadline && new Date(auth.timePolicy.deadline) < now) {
      console.log(`[AuthEngine] verify: REJECTED at step 7 - expired, deadline=${auth.timePolicy.deadline}`);
      return { approved: false, step: 7, reason: 'Authorization has expired' };
    }

    // ===== 第 8 项：检查 cron 时间窗口 =====
    const cronWindows = auth.timePolicy.cronWindows || [];
    if (cronWindows.length > 0) {
      const inWindow = cronWindows.some((cron) => matchCron(cron, now));
      if (!inWindow) {
        console.log(`[AuthEngine] verify: REJECTED at step 8 - outside cron window`);
        return { approved: false, step: 8, reason: 'Current time not in allowed cron window' };
      }
    }

    // ===== 第 9 项：检查交易目标地址（支持 "*" 通配符） =====
    // 注意：chainId 可能是字符串或数字，统一转换为数字比较
    const targetAllowed = auth.scope.targetAddresses.some(
      (t) => Number(t.chainId) === Number(tx.chainId) && addressMatch(t.address, tx.toAddress)
    );
    if (!targetAllowed) {
      console.log(`[AuthEngine] verify: REJECTED at step 9 - target address ${tx.toAddress} not authorized`);
      return { approved: false, step: 9, reason: 'Target address not in authorized list' };
    }

    // ===== 第 10 项：检查签名钱包地址（支持 "*" 通配符） =====
    // 注意：chainId 可能是字符串或数字，统一转换为数字比较
    const walletAllowed = auth.scope.signingWallets.some(
      (w) => Number(w.chainId) === Number(tx.chainId) && addressMatch(w.address, tx.fromAddress)
    );
    if (!walletAllowed) {
      console.log(`[AuthEngine] verify: REJECTED at step 10 - wallet ${tx.fromAddress} not authorized`);
      return { approved: false, step: 10, reason: 'Signing wallet not in authorized scope' };
    }

    // ===== 第 11 项：检查交易金额范围 =====
    const txAmount = BigInt(tx.amount);
    if (auth.scope.amountLimits) {
      if (auth.scope.amountLimits.min && txAmount < BigInt(auth.scope.amountLimits.min)) {
        console.log(`[AuthEngine] verify: REJECTED at step 11 - amount below minimum`);
        return { approved: false, step: 11, reason: 'Transaction amount below minimum' };
      }
      if (auth.scope.amountLimits.max && txAmount > BigInt(auth.scope.amountLimits.max)) {
        console.log(`[AuthEngine] verify: REJECTED at step 11 - amount above maximum`);
        return { approved: false, step: 11, reason: 'Transaction amount above maximum' };
      }
    }

    // ===== 第 12 项：检查 token 和 chain 限制（支持 "*" 通配符） =====
    // 注意：chainId 可能是字符串或数字，统一转换为数字比较
    if (auth.scope.tokenRestrictions && auth.scope.tokenRestrictions.length > 0) {
      const tokenAllowed = auth.scope.tokenRestrictions.some(
        (t) => Number(t.chainId) === Number(tx.chainId) && addressMatch(t.tokenAddress, tx.tokenAddress)
      );
      if (!tokenAllowed) {
        console.log(`[AuthEngine] verify: REJECTED at step 12 - token/chain not authorized`);
        return { approved: false, step: 12, reason: 'Token/chain not in authorized restrictions' };
      }
    }

    // ===== 第 13 项：检查累计金额和签名次数 =====
    if (auth.scope.cumulativeLimits) {
      const limitsResult = await this._state.checkLimits(
        auth.authorizationId,
        auth.scope.cumulativeLimits,
        { amount: tx.amount, chainId: tx.chainId, tokenAddress: tx.tokenAddress }
      );
      if (!limitsResult.allowed) {
        console.log(`[AuthEngine] verify: REJECTED at step 13 - ${limitsResult.reason}`);
        return { approved: false, step: 13, reason: limitsResult.reason };
      }
    }

    // ===== 第 14 项：确认私钥存在于密封存储中 =====
    const wallet = await this._wallet.getWalletByAddress(auth.userId, tx.chainId, tx.fromAddress);
    if (!wallet) {
      console.log(`[AuthEngine] verify: REJECTED at step 14 - private key not found for ${tx.fromAddress}`);
      return { approved: false, step: 14, reason: 'Private key not found in sealed storage' };
    }

    console.log(`[AuthEngine] verify: APPROVED - all 14 checks passed for userId=${auth.userId}, authorizationId=${auth.authorizationId}`);
    return { approved: true, step: 14, reason: 'All 14 checks passed' };
  }
}
