/**
 * 私钥导入流程 API
 * 两步导入：初始化（密钥交换）→ 完成导入（解密并存储）
 *
 * 支持两种密钥交换方式：
 * - ECDH（默认）：不传 rsaPublicKey，返回 SGX ECDH 公钥（prime256v1）
 * - RSA：传入 rsaPublicKey，返回 RSA 加密后的 AES-256 密钥
 * 加密使用 AES-256-GCM
 *
 * 两步操作均强制要求用户 WebAuthn Passkey 签名，平台无法绕过用户授权静默导入私钥。
 *
 * HTTP body 仅包含 { payload, platformSignature }，
 * 所有业务参数从验证后的 payload 解析获取。
 *
 * userIntentJson 规范：
 *   handleInit:     { purpose: "key_import_init", userId, importType }
 *   handleComplete: { purpose: "key_import_complete", userId, sessionId, walletId, chains }
 */

import { verifyWebAuthnSignature } from '../modules/webauthn/verifier.js';

export class KeyImportHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/whitelist/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../modules/key-management/key-import.js').KeyImporter} deps.keyImporter
   * @param {import('../modules/webauthn/passkey-manager.js').PasskeyManager} [deps.passkeyManager]
   * @param {import('../modules/webauthn/challenge-manager.js').WebAuthnChallengeManager} [deps.challengeManager]
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('KeyImportHandler requires whitelistVerifier');
    if (!deps.keyImporter) throw new Error('KeyImportHandler requires keyImporter');
    this._whitelist = deps.whitelistVerifier;
    this._keyImporter = deps.keyImporter;
    this._passkey = deps.passkeyManager || null;
    this._challenge = deps.challengeManager || null;
  }

  /**
   * 第一步：初始化导入会话（密钥交换）
   *
   * 强制要求用户 WebAuthn Passkey 签名。
   *
   * payload JSON: { userId, credentialId, importType, webauthnSignature, rawChallenge, userIntentJson, rsaPublicKey? }
   * - 不传 rsaPublicKey：ECDH 模式，返回 enclavePublicKey
   * - 传入 rsaPublicKey：RSA 模式，返回 encryptedAESKey
   * - TTL 由服务端 runtimeParams.session.importTtlSeconds 控制（默认 300 秒），调用方不可指定
   *
   * userIntentJson: { purpose: "key_import_init", userId, importType }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<Object>} 响应含 keyType 字段标明密钥交换类型
   */
  async handleInit(request) {
    // 1. 验证平台白名单签名
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[KeyImport] handleInit: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 2. 解析验证过的 payload，替换 request
    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    console.log(`[KeyImport] handleInit: userId=${request.userId}, importType=${request.importType}`);

    if (!request.userId) {
      throw new Error('userId is required');
    }
    if (!request.importType) {
      throw new Error('importType is required');
    }

    // 3. 强制验证用户 WebAuthn 签名，平台不得绕过
    if (!request.webauthnSignature) {
      throw new Error('webauthnSignature is required: key import must be authorized by the user');
    }
    await this._verifyUserWebAuthn(request, 'handleInit', 'key_import_init', {
      purpose: 'key_import_init',
      userId: request.userId,
      importType: request.importType,
    });
    console.log(`[KeyImport] handleInit: WebAuthn verification passed`);

    // 4. 创建导入会话（根据是否传入 rsaPublicKey 决定密钥交换方式）
    const session = await this._keyImporter.initImport(
      request.userId,
      request.importType,
      this._keyImporter._importTtlSeconds,
      request.rsaPublicKey || null
    );

    console.log(`[KeyImport] handleInit: session created, sessionId=${session.sessionId}, keyType=${session.keyType}`);

    // 5. 构建响应（根据 keyType 返回不同字段）
    const response = {
      sessionId: session.sessionId,
      keyType: session.keyType,
    };

    if (session.keyType === 'ecdh') {
      response.enclavePublicKey = session.enclavePublicKey;
    } else {
      response.encryptedAESKey = session.encryptedAESKey;
    }

    return response;
  }

  /**
   * 第二步：完成导入（客户端加密后的数据 → SGX 解密并存储）
   *
   * 强制要求用户 WebAuthn Passkey 签名。
   *
   * payload JSON: { sessionId, userId, credentialId, webauthnSignature, rawChallenge, userIntentJson, encryptedData, peerPublicKey?, walletId?, chains? }
   * - ECDH 模式：peerPublicKey 必填
   * - RSA 模式：peerPublicKey 无需（当前会话已存储 AES 密钥）
   *
   * userIntentJson 绑定 userId、sessionId、walletId、chains，防止平台篡改关键参数：
   * - userId：防止平台替换成另一个用户（与 Passkey 归属绑定）
   * - sessionId：防止平台替换成另一个用户的会话
   * - walletId：防止平台替换 walletId 覆盖已有钱包（null 表示不指定）
   * - chains：防止平台替换链列表导致派生不同地址（null 表示不指定）
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<{ success: boolean, walletId?: string, addresses?: Object[], results?: Object[], sharedWalletIds?: Object<string,string> }>}
   */
  async handleComplete(request) {
    // 1. 验证平台白名单签名
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[KeyImport] handleComplete: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 2. 解析验证过的 payload，替换 request
    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    console.log(`[KeyImport] handleComplete: sessionId=${request.sessionId}`);

    if (!request.sessionId) {
      throw new Error('sessionId is required');
    }
    if (!request.encryptedData) {
      throw new Error('encryptedData is required');
    }

    // 3. 强制验证用户 WebAuthn 签名，平台不得绕过
    //    userIntentJson 绑定关键参数，防止平台篡改
    if (!request.webauthnSignature) {
      throw new Error('webauthnSignature is required: key import must be authorized by the user');
    }
    await this._verifyUserWebAuthn(request, 'handleComplete', 'key_import_complete', {
      purpose: 'key_import_complete',
      userId: request.userId,
      sessionId: request.sessionId,
      walletId: request.walletId || null,
      chains: request.chains || null,
    });
    console.log(`[KeyImport] handleComplete: WebAuthn verification passed`);

    // 4. 完成导入（根据会话 keyType 自动选择解密方式）
    const result = await this._keyImporter.completeImport(
      request.sessionId,
      request.peerPublicKey || null,
      request.encryptedData,
      request.walletId,
      request.chains
    );

    // 5. 返回结果（区分单个/批量）
    if (result.results) {
      // 批量导入（支持多 userId，sharedWalletIds 按 userId 分组）
      console.log(`[KeyImport] handleComplete: batch success, count=${result.results.length}, sharedWalletIds=${JSON.stringify(result.sharedWalletIds)}`);
      return {
        success: true,
        results: result.results,
        sharedWalletIds: result.sharedWalletIds,
      };
    } else {
      // 单个导入
      console.log(`[KeyImport] handleComplete: success, walletId=${result.walletId}`);
      return {
        success: true,
        walletId: result.walletId,
        addresses: result.addresses || [],
      };
    }
  }

  /**
   * 验证用户端 WebAuthn 签名 + userIntent 业务参数比对
   *
   * 验证流程：
   *   1. 检查 passkeyManager 和 challengeManager 是否已注入
   *   2. 验证凭证归属（credentialId 必须属于 userId）
   *   3. 验证 rawChallenge 存在性（通过 challengeManager）
   *   4. 计算 intentHash = SHA256(rawChallenge + userIntentJson)
   *   5. 验证 WebAuthn 签名（expectedChallenge = intentHash）
   *   6. 解析 userIntentJson 并与 intentFields 比对
   *
   * @param {Object} request - 包含 credentialId, webauthnSignature, rawChallenge, userIntentJson
   * @param {string} callerName - 调用方名称（日志用）
   * @param {string} purpose - 挑战值用途
   * @param {Object} intentFields - 需要与 userIntentJson 比对的业务参数字段（key-value 对）
   * @private
   */
  async _verifyUserWebAuthn(request, callerName, purpose, intentFields = {}) {
    if (!this._passkey || !this._challenge) {
      throw new Error('User-side WebAuthn import requires passkeyManager and challengeManager');
    }
    if (!request.userId) throw new Error('Both userId and credentialId are required');
    if (!request.credentialId) throw new Error('Both userId and credentialId are required');
    if (!request.rawChallenge) throw new Error('rawChallenge is required for user-side import');
    if (!request.userIntentJson) throw new Error('userIntentJson is required for user-side import');

    // Passkey 归属验证
    const ownershipValid = await this._passkey.verifyPasskeyOwnership(request.userId, request.credentialId);
    if (!ownershipValid) {
      console.log(`[KeyImport] ${callerName}: REJECTED - passkey not bound to userId=${request.userId}`);
      throw new Error('Passkey not bound to this user');
    }

    const passkey = await this._passkey.getPasskey(request.userId, request.credentialId);
    if (!passkey) {
      throw new Error('Passkey not found');
    }

    // 验证 userIntentJson 是合法 JSON
    let intent;
    try {
      intent = JSON.parse(request.userIntentJson);
    } catch {
      throw new Error('userIntentJson must be a valid JSON string');
    }

    // WebAuthn 签名验证（intentHash = SHA256(rawChallenge + userIntentJson)）
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
      console.log(`[KeyImport] ${callerName}: REJECTED - WebAuthn signature invalid: ${sigResult.reason}`);
      throw new Error(`WebAuthn verification failed: ${sigResult.reason}`);
    }

    // 验证 userIntentJson 中的业务参数与实际请求参数一致
    for (const [key, actualValue] of Object.entries(intentFields)) {
      const intentValue = intent[key];
      const intentStr = JSON.stringify(intentValue);
      const actualStr = JSON.stringify(actualValue);
      if (intentStr !== actualStr) {
        console.log(`[KeyImport] ${callerName}: REJECTED - userIntent.${key} mismatch: signed="${intentStr}", actual="${actualStr}"`);
        throw new Error(`userIntent parameter mismatch: ${key} was signed as ${intentStr} but actual value is ${actualStr}`);
      }
    }
    console.log(`[KeyImport] ${callerName}: userIntent verification passed`);
  }
}
