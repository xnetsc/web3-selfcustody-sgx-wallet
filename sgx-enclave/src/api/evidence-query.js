/**
 * 取证查询 API
 * 提供授权原文记录的查询接口，用于争议取证。
 *
 * 两个接口：
 *   1. 按 (userId, authorizationId) 查询单条授权原文记录
 *   2. 按 userId 列出所有授权记录摘要
 *
 * 统一鉴权：所有请求均通过平台转发，HTTP body 为 { payload, platformSignature }
 *
 * payload 解析后区分发起方：
 *   - 平台发起：payload 不含 credentialId/webauthnSignature（单条查询时验证平台地址在 grantee 列表中）
 *   - 用户发起（平台转发）：payload 含 credentialId + webauthnSignature + rawChallenge + userIntentJson，
 *     额外验证 WebAuthn 签名（intentHash = SHA256(rawChallenge + userIntentJson)）
 */

import { verifyWebAuthnSignature } from '../modules/webauthn/verifier.js';

export class EvidenceQueryHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/whitelist/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../modules/state-management/state-manager.js').StateManager} deps.stateManager
   * @param {import('../modules/webauthn/passkey-manager.js').PasskeyManager} deps.passkeyManager
   * @param {import('../modules/webauthn/challenge-manager.js').WebAuthnChallengeManager} [deps.challengeManager]
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('EvidenceQueryHandler requires whitelistVerifier');
    if (!deps.stateManager) throw new Error('EvidenceQueryHandler requires stateManager');
    if (!deps.passkeyManager) throw new Error('EvidenceQueryHandler requires passkeyManager');
    this._whitelist = deps.whitelistVerifier;
    this._state = deps.stateManager;
    this._passkey = deps.passkeyManager;
    this._challenge = deps.challengeManager || null;
  }

  /**
   * 查询单条授权原文记录
   *
   * payload JSON 两种形态：
   *   A. 平台发起：{ userId, authorizationId }
   *   B. 用户发起（平台转发）：{ userId, authorizationId, credentialId, webauthnSignature }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<Object>}
   */
  async handleGetRecord(request) {
    // 统一平台签名验证
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[EvidenceQuery] handleGetRecord: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 解析 payload
    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    console.log(`[EvidenceQuery] handleGetRecord: userId=${request.userId}, authorizationId=${request.authorizationId}`);
    if (!request.userId) throw new Error('userId is required');
    if (!request.authorizationId) throw new Error('authorizationId is required');

    const isUserInitiated = !!(request.credentialId && request.webauthnSignature);

    if (isUserInitiated) {
      // 用户发起（平台转发）：验证 WebAuthn 签名
      await this._verifyUserAuth(request, 'handleGetRecord');
    } else {
      // 平台发起：验证平台地址在 grantee 列表中
      const record = await this._getRecordOrThrow(request.userId, request.authorizationId);
      const granteeList = Array.isArray(record.grantee) ? record.grantee : [record.grantee];
      const recoveredAddress = whitelistResult.address;
      const normalizedGrantee = granteeList.map(g => g.toLowerCase());
      if (!normalizedGrantee.includes(recoveredAddress.toLowerCase())) {
        console.log(`[EvidenceQuery] handleGetRecord: REJECTED - platform ${recoveredAddress} not in grantee list`);
        throw new Error('Platform verification failed: requester not in grantee list');
      }
      console.log(`[EvidenceQuery] handleGetRecord: success (platform)`);
      return this._formatRecord(record);
    }

    const record = await this._getRecordOrThrow(request.userId, request.authorizationId);
    console.log(`[EvidenceQuery] handleGetRecord: success (user via platform)`);
    return this._formatRecord(record);
  }

  /**
   * 列出用户的所有授权记录摘要
   *
   * payload JSON 两种形态：
   *   A. 平台发起：{ userId }
   *   B. 用户发起（平台转发）：{ userId, credentialId, webauthnSignature }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<Object>}
   */
  async handleListRecords(request) {
    // 统一平台签名验证
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[EvidenceQuery] handleListRecords: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 解析 payload
    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    const isUserInitiated = !!(request.credentialId && request.webauthnSignature);

    if (isUserInitiated) {
      await this._verifyUserAuth(request, 'handleListRecords');
    }

    console.log(`[EvidenceQuery] handleListRecords: userId=${request.userId}`);
    if (!request.userId) throw new Error('userId is required');

    const records = await this._state.listAuthorizationRecords(request.userId);

    const mode = isUserInitiated ? 'user via platform' : 'platform';
    console.log(`[EvidenceQuery] handleListRecords: success (${mode}), count=${records.length}`);

    return {
      userId: request.userId,
      records: records.map(r => ({
        authorizationId: r.authorization_id,
        grantee: Array.isArray(r.grantee) ? r.grantee : [r.grantee],
        authorizationHash: r.authorization_hash,
        createdAt: r.created_at,
      })),
    };
  }

  // ===== 内部方法 =====

  /**
   * 用户鉴权：WebAuthn 签名验证 + userIntent 业务参数比对
   *
   * 验证流程：
   *   - rawChallenge：服务端生成的原始随机挑战值
   *   - userIntentJson：用户意图 JSON 字符串
   *   - webauthnSignature：用 intentHash = SHA256(rawChallenge + userIntentJson) 做的签名
   *
   * @param {Object} request - 已解析的 payload 对象
   * @param {string} callerName
   */
  async _verifyUserAuth(request, callerName) {
    if (!request.credentialId) throw new Error('credentialId is required');
    if (!request.webauthnSignature) throw new Error('webauthnSignature is required');
    if (!request.rawChallenge) throw new Error('rawChallenge is required');
    if (!request.userIntentJson) throw new Error('userIntentJson is required');

    // Passkey 归属验证
    const ownershipValid = await this._passkey.verifyPasskeyOwnership(request.userId, request.credentialId);
    if (!ownershipValid) {
      console.log(`[EvidenceQuery] ${callerName}: REJECTED - passkey not bound to userId=${request.userId}`);
      throw new Error('Passkey not bound to this user');
    }

    // WebAuthn 签名验证
    const passkey = await this._passkey.getPasskey(request.userId, request.credentialId);
    if (!passkey) {
      throw new Error('Passkey not found');
    }

    // 验证 userIntentJson 是合法 JSON（提前验证）
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
      ...(this._challenge
        ? { challengeManager: this._challenge, purpose: 'evidence_query', rawChallenge: request.rawChallenge, userIntentJson: request.userIntentJson }
        : { expectedChallenge: request.webauthnSignature?.challenge }),
      publicKeyCose: passkey.publicKeyCose,
    });
    if (!sigResult.verified) {
      console.log(`[EvidenceQuery] ${callerName}: REJECTED - WebAuthn signature invalid`);
      throw new Error(`WebAuthn verification failed: ${sigResult.reason}`);
    }

    // 验证 userIntentJson 中的业务参数与实际请求参数一致
    // evidence_query 的 userIntent 字段：{ purpose, userId, authorizationId? }
    const intentFields = {
      purpose: 'evidence_query',
      userId: request.userId,
      ...(request.authorizationId !== undefined ? { authorizationId: request.authorizationId } : {}),
    };
    for (const [key, actualValue] of Object.entries(intentFields)) {
      if (JSON.stringify(intent[key]) !== JSON.stringify(actualValue)) {
        console.log(`[EvidenceQuery] ${callerName}: REJECTED - userIntent.${key} mismatch`);
        throw new Error(`userIntent parameter mismatch: ${key} was signed as ${JSON.stringify(intent[key])} but actual value is ${JSON.stringify(actualValue)}`);
      }
    }
    console.log(`[EvidenceQuery] ${callerName}: userIntent verification passed`);

    console.log(`[EvidenceQuery] ${callerName}: user auth success for userId=${request.userId}`);
  }

  /**
   * 查询授权记录，不存在则抛错
   */
  async _getRecordOrThrow(userId, authorizationId) {
    const record = await this._state.getAuthorizationRecord(userId, authorizationId);
    if (!record) {
      console.log(`[EvidenceQuery] record NOT FOUND: userId=${userId}, authorizationId=${authorizationId}`);
      throw new Error(`Authorization record not found: userId=${userId}, authorizationId=${authorizationId}`);
    }
    return record;
  }

  /**
   * 格式化授权记录为响应对象
   */
  _formatRecord(record) {
    return {
      authorizationId: record.authorization_id,
      userId: record.user_id,
      grantee: Array.isArray(record.grantee) ? record.grantee : [record.grantee],
      authorizationJson: record.authorization_json,
      authorizationHash: record.authorization_hash,
      createdAt: record.created_at,
    };
  }
}
