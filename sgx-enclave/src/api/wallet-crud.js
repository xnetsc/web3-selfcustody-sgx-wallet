/**
 * TODO-19: 钱包写操作流程 API
 * 四个操作：wallet.create, wallet.delete, wallet.list, passkey.delete
 *
 * 写操作（create, delete, passkey.delete）需要：
 *   1. 平台白名单签名验证
 *   2. Passkey 归属验证
 *   3. WebAuthn 签名验证（基于 intentHash = SHA256(rawChallenge + userIntentJson)）
 *   4. userIntentJson 业务参数比对
 *
 * 读操作（list）仅需：
 *   1. 平台白名单签名验证
 *
 * HTTP body 仅包含 { payload, platformSignature }，
 * 所有业务参数从验证后的 payload 解析获取。
 *
 * 写操作 payload 中需要携带：
 *   - rawChallenge：从 /api/challenge 获取的原始挑战值
 *   - userIntentJson：用户意图的原始 JSON 字符串
 *   - webauthnSignature：用 intentHash = SHA256(rawChallenge + userIntentJson) 做的 WebAuthn 签名
 *
 * 事务性：所有写操作在数据库事务中完成，确保原子性。
 */

import { verifyWebAuthnSignature } from '../modules/webauthn/verifier.js';

export class WalletCrudHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/whitelist/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../modules/webauthn/passkey-manager.js').PasskeyManager} deps.passkeyManager
   * @param {import('../modules/webauthn/challenge-manager.js').WebAuthnChallengeManager} deps.challengeManager
   * @param {import('../modules/wallet-management/wallet-manager.js').WalletManager} deps.walletManager
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('WalletCrudHandler requires whitelistVerifier');
    if (!deps.passkeyManager) throw new Error('WalletCrudHandler requires passkeyManager');
    if (!deps.challengeManager) throw new Error('WalletCrudHandler requires challengeManager');
    if (!deps.walletManager) throw new Error('WalletCrudHandler requires walletManager');
    this._whitelist = deps.whitelistVerifier;
    this._passkey = deps.passkeyManager;
    this._challenge = deps.challengeManager;
    this._wallet = deps.walletManager;
    // 应急授权校验器（可选注入）：payload 携带 emergencyAuthorizationJson 时
    // 以治理授权替代目标用户的 Passkey 意图签名，未注入时应急请求直接拒绝
    this._emergency = deps.emergencyAuthorizer || null;
  }

  /**
   * 创建钱包
   *
   * payload JSON: {
   *   userId, credentialId, webauthnSignature,
   *   rawChallenge,    // 从 /api/challenge 获取的原始挑战值
   *   userIntentJson,  // 用户意图 JSON 字符串：{ purpose: "wallet_create", userId, chains, mnemonicStrength? }
   *   walletId?, chains, mnemonicStrength?
   * }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<{ success: boolean, walletId: string, addresses: Object[] }>}
   */
  async handleCreate(request) {
    // 1. 验证平台白名单签名 + 解析 payload
    const parsed = this._verifyAndParseEx(request, 'handleCreate');
    request = parsed.body;

    if (!request.userId) throw new Error('userId is required');
    if (!request.chains || request.chains.length === 0) throw new Error('chains is required');

    // 2. 验证授权：应急授权（治理）或用户 WebAuthn 签名 + userIntent 业务参数比对
    let emergencyCtx = null;
    if (request.emergencyAuthorizationJson) {
      emergencyCtx = await this._verifyEmergency(request, parsed.platformAddress, 'handleCreate', 'wallet_create', {
        chains: request.chains,
        mnemonicStrength: request.mnemonicStrength ?? null,
      });
    } else {
      // intentFields：用户签名时承诺的语义参数，必须与实际请求参数一致
      await this._verifyPasskeyAndWebAuthn(request, 'handleCreate', 'wallet_create', {
        purpose: 'wallet_create',
        userId: request.userId,
        chains: request.chains,
        ...(request.mnemonicStrength !== undefined ? { mnemonicStrength: request.mnemonicStrength } : {}),
      });
    }

    // 3. 在事务中创建钱包（确保原子性）
    const result = await this._wallet.createNativeWallet(
      request.userId,
      request.walletId,
      request.chains,
      request.mnemonicStrength || 128
    );

    console.log(`[WalletCrud] handleCreate: success, walletId=${result.walletId}`);

    // 将 wallets 数组转换为 addresses 格式（只暴露 chainId 和 address，不暴露私钥）
    const addresses = (result.wallets || []).map(w => ({
      chainId: w.chainId,
      address: w.address,
    }));

    let executionLog = null;
    if (emergencyCtx) {
      const usedCount = await this._emergency.recordUse(emergencyCtx.auth, request.userId, 'wallet_create');
      executionLog = await this._emergency.recordExecution(emergencyCtx, {
        platformAddress: parsed.platformAddress,
        userId: request.userId,
        operation: 'wallet_create',
        executionIndex: usedCount,
        detail: { chains: request.chains.map((c) => c.chainId), walletId: result.walletId },
        outcome: { walletId: result.walletId, addresses },
      });
    }

    return {
      success: true,
      walletId: result.walletId,
      addresses,
      ...(emergencyCtx ? { emergencyAuthorizationId: emergencyCtx.auth.authorizationId, executionLog } : {}),
    };
  }

  /**
   * 删除钱包
   *
   * payload JSON: {
   *   userId, credentialId, webauthnSignature,
   *   rawChallenge,    // 从 /api/challenge 获取的原始挑战值
   *   userIntentJson,  // 用户意图 JSON 字符串：{ purpose: "wallet_delete", userId, walletId }
   *   walletId
   * }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<{ success: boolean, walletId: string }>}
   */
  async handleDelete(request) {
    // 1. 验证平台白名单签名 + 解析 payload
    const parsed = this._verifyAndParseEx(request, 'handleDelete');
    request = parsed.body;

    if (!request.userId) throw new Error('userId is required');
    if (!request.walletId) throw new Error('walletId is required');

    // 2. 验证授权：应急授权（治理）或用户 WebAuthn 签名 + userIntent 业务参数比对
    let emergencyCtx = null;
    if (request.emergencyAuthorizationJson) {
      emergencyCtx = await this._verifyEmergency(request, parsed.platformAddress, 'handleDelete', 'wallet_delete', {
        walletId: request.walletId,
      });
    } else {
      await this._verifyPasskeyAndWebAuthn(request, 'handleDelete', 'wallet_delete', {
        purpose: 'wallet_delete',
        userId: request.userId,
        walletId: request.walletId,
      });
    }

    // 3. 在事务中删除钱包（确保原子性）
    await this._wallet.deleteWallet(request.userId, request.walletId);

    console.log(`[WalletCrud] handleDelete: success, walletId=${request.walletId}`);

    let executionLog = null;
    if (emergencyCtx) {
      const usedCount = await this._emergency.recordUse(emergencyCtx.auth, request.userId, 'wallet_delete');
      executionLog = await this._emergency.recordExecution(emergencyCtx, {
        platformAddress: parsed.platformAddress,
        userId: request.userId,
        operation: 'wallet_delete',
        executionIndex: usedCount,
        detail: { walletId: request.walletId },
        outcome: { walletId: request.walletId, deleted: true },
      });
    }

    return {
      success: true,
      walletId: request.walletId,
      ...(emergencyCtx ? { emergencyAuthorizationId: emergencyCtx.auth.authorizationId, executionLog } : {}),
    };
  }

  /**
   * 列出钱包（只需平台签名）
   *
   * payload JSON: { userId }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<{ success: boolean, wallets: Object[] }>}
   */
  async handleList(request) {
    // 1. 验证平台白名单签名 + 解析 payload（读操作不需要 Passkey）
    request = this._verifyAndParse(request, 'handleList');

    if (!request.userId) throw new Error('userId is required');

    // 2. 列出钱包
    const wallets = await this._wallet.listWallets(request.userId);

    console.log(`[WalletCrud] handleList: success, count=${wallets.length}`);

    return {
      success: true,
      wallets,
    };
  }

  /**
   * 删除 Passkey（支持批量）
   * 如果删除后该 userId 下没有剩余 Passkey，则级联删除整个用户数据
   *
   * payload JSON: {
   *   userId, credentialId, webauthnSignature,
   *   rawChallenge,    // 从 /api/challenge 获取的原始挑战值
   *   userIntentJson,  // 用户意图 JSON 字符串：{ purpose: "passkey_delete", userId, credentialIdsToDelete }
   *   credentialIdsToDelete
   * }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<{ success: boolean, deletedCount: number, accountDeleted: boolean }>}
   */
  async handleDeletePasskey(request) {
    // 1. 验证平台白名单签名 + 解析 payload
    const parsed = this._verifyAndParseEx(request, 'handleDeletePasskey');
    request = parsed.body;

    if (!request.userId) throw new Error('userId is required');
    if (!request.credentialIdsToDelete || request.credentialIdsToDelete.length === 0) {
      throw new Error('credentialIdsToDelete is required and must not be empty');
    }

    console.log(`[WalletCrud] handleDeletePasskey: userId=${request.userId}, toDelete=${request.credentialIdsToDelete?.length || 0}`);

    // 2. 验证授权：应急授权（治理）或用户 WebAuthn 签名 + userIntent 业务参数比对
    let emergencyCtx = null;
    if (request.emergencyAuthorizationJson) {
      emergencyCtx = await this._verifyEmergency(request, parsed.platformAddress, 'handleDeletePasskey', 'passkey_delete', {
        credentialIdsToDelete: request.credentialIdsToDelete,
      });
    } else {
      await this._verifyPasskeyAndWebAuthn(request, 'handleDeletePasskey', 'passkey_delete', {
        purpose: 'passkey_delete',
        userId: request.userId,
        credentialIdsToDelete: request.credentialIdsToDelete,
      });
    }

    // 3. 删除 Passkey（passkey-manager.deletePasskeys 内部已在事务中处理级联删除：
    //    若删完后该 userId 无剩余 Passkey → 事务内级联删除 wallets/accounts/authorization_states 等）
    const result = await this._passkey.deletePasskeys(request.userId, request.credentialIdsToDelete);

    console.log(`[WalletCrud] handleDeletePasskey: success, deletedCount=${result.deletedCount}, accountDeleted=${result.accountDeleted}`);

    let executionLog = null;
    if (emergencyCtx) {
      const usedCount = await this._emergency.recordUse(emergencyCtx.auth, request.userId, 'passkey_delete');
      executionLog = await this._emergency.recordExecution(emergencyCtx, {
        platformAddress: parsed.platformAddress,
        userId: request.userId,
        operation: 'passkey_delete',
        executionIndex: usedCount,
        detail: { credentialIdsToDelete: request.credentialIdsToDelete },
        outcome: { deletedCount: result.deletedCount, accountDeleted: result.accountDeleted },
      });
    }

    return {
      success: true,
      deletedCount: result.deletedCount,
      accountDeleted: result.accountDeleted,
      ...(emergencyCtx ? { emergencyAuthorizationId: emergencyCtx.auth.authorizationId, executionLog } : {}),
    };
  }

  // ===== 内部通用验证方法 =====

  /**
   * 验证平台白名单签名 + 解析 payload，返回解析后的业务对象
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @param {string} callerName - 调用方名称（日志用）
   * @returns {Object} 解析后的业务参数对象
   */
  _verifyAndParse(request, callerName) {
    return this._verifyAndParseEx(request, callerName).body;
  }

  /**
   * 同 _verifyAndParse，但同时返回平台信封签名恢复出的地址
   * （应急授权校验需要拿它与授权的 grantee 比对）
   * @returns {{ body: Object, platformAddress: string }}
   */
  _verifyAndParseEx(request, callerName) {
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[WalletCrud] ${callerName}: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }
    try {
      return { body: JSON.parse(request.payload), platformAddress: whitelistResult.address };
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }
  }

  /**
   * 应急授权校验（payload 携带 emergencyAuthorizationJson 时替代用户意图签名）
   * @param {Object} request - 解析后的 payload
   * @param {string} platformAddress - 平台信封地址
   * @param {string} callerName
   * @param {string} operation - 操作名
   * @param {Object} actualParams - 本次实际参数（与 policy 声明比对）
   * @returns {Promise<Object>} EmergencyAuthorizer.verify 的批准结果
   */
  async _verifyEmergency(request, platformAddress, callerName, operation, actualParams) {
    if (!this._emergency) {
      throw new Error('Emergency authorization is not enabled on this enclave');
    }
    const result = await this._emergency.verify({
      authorizationJson: request.emergencyAuthorizationJson,
      signature: request.emergencySignature,
      platformAddress,
      operation,
      userId: request.userId,
      actualParams,
    });
    if (!result.approved) {
      throw new Error(`Emergency authorization verification failed: ${result.reason}`);
    }
    console.log(`[WalletCrud] ${callerName}: emergency authorization approved, authorizationId=${result.auth.authorizationId}`);
    return result;
  }

  /**
   * 验证 WebAuthn 签名 + userIntent 业务参数比对
   *
   * 验证流程：
   *   1. 验证凭证归属（credentialId 必须属于 userId）
   *   2. 验证 rawChallenge 存在性（通过 challengeManager）
   *   3. 计算 intentHash = SHA256(rawChallenge + userIntentJson)
   *   4. 验证 WebAuthn 签名（expectedChallenge = intentHash）
   *   5. 解析 userIntentJson 并与 intentFields 比对
   *
   * @param {Object} request - 包含 credentialId, webauthnSignature, rawChallenge, userIntentJson
   * @param {string} callerName - 调用方名称（日志用）
   * @param {string} purpose - 挑战值用途
   * @param {Object} intentFields - 需要与 userIntentJson 比对的业务参数字段（key-value 对）
   */
  async _verifyPasskeyAndWebAuthn(request, callerName, purpose, intentFields = {}) {
    if (!request.credentialId) throw new Error('credentialId is required');
    if (!request.webauthnSignature) throw new Error('webauthnSignature is required');
    if (!request.rawChallenge) throw new Error('rawChallenge is required');
    if (!request.userIntentJson) throw new Error('userIntentJson is required');

    // Passkey 归属验证
    const ownershipValid = await this._passkey.verifyPasskeyOwnership(request.userId, request.credentialId);
    if (!ownershipValid) {
      console.log(`[WalletCrud] ${callerName}: REJECTED - passkey not bound to userId=${request.userId}`);
      throw new Error('Passkey not bound to this user');
    }

    const passkey = await this._passkey.getPasskey(request.userId, request.credentialId);
    if (!passkey) {
      throw new Error('Passkey not found');
    }

    // 验证 userIntentJson 是合法 JSON（提前验证，避免后续解析失败）
    let intent;
    try {
      intent = JSON.parse(request.userIntentJson);
    } catch {
      throw new Error('userIntentJson must be a valid JSON string');
    }

    // WebAuthn 签名验证：
    // - rawChallenge：服务端生成的原始随机挑战值（用于查询 DB 记录）
    // - userIntentJson：用户意图 JSON 字符串（用于计算 intentHash）
    // - verifier 内部计算 intentHash = SHA256(rawChallenge + userIntentJson) 作为 expectedChallenge
    const sigResult = await verifyWebAuthnSignature({
      userId: request.userId,
      credentialId: request.credentialId,
      webauthnSignature: request.webauthnSignature,
      challengeManager: this._challenge,
      purpose,
      rawChallenge: request.rawChallenge,
      userIntentJson: request.userIntentJson,
      publicKeyCose: passkey.publicKeyCose,
    });

    if (!sigResult.verified) {
      console.log(`[WalletCrud] ${callerName}: REJECTED - WebAuthn signature invalid: ${sigResult.reason}`);
      throw new Error(`WebAuthn verification failed: ${sigResult.reason}`);
    }

    // 验证 userIntentJson 中的业务参数与实际请求参数一致
    for (const [key, actualValue] of Object.entries(intentFields)) {
      const intentValue = intent[key];
      // 对数组类型做深度比较（JSON 序列化比较）
      const intentStr = JSON.stringify(intentValue);
      const actualStr = JSON.stringify(actualValue);
      if (intentStr !== actualStr) {
        console.log(`[WalletCrud] ${callerName}: REJECTED - userIntent.${key} mismatch: signed="${intentStr}", actual="${actualStr}"`);
        throw new Error(`userIntent parameter mismatch: ${key} was signed as ${intentStr} but actual value is ${actualStr}`);
      }
    }
    console.log(`[WalletCrud] ${callerName}: userIntent verification passed`);
  }
}
