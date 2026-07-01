/**
 * 统一挑战值生成 API
 *
 * 将原来分散的挑战值接口合并为一个：
 *   - /api/passkey/register/challenge  (purpose=register)
 *   - /api/wallet/challenge            (purpose=wallet_create/wallet_delete/passkey_delete/wallet_entry_delete/key_export/key_export_confirm)
 *
 * 注意：authorize（授权JSON签名）不需要调用此接口。
 * 授权JSON的WebAuthn challenge由客户端自行计算：SHA256(authJson)，不依赖服务端挑战值。
 *
 * 路由：POST /api/challenge
 *
 * 鉴权规则：
 *   - purpose=register：userId 可选（不存在则生成），不需要 Passkey 归属验证
 *   - 其他 purpose：userId + credentialId 必填，验证 Passkey 归属后生成纯随机挑战值
 *
 * 新的挑战值使用流程（非 register/authenticate purpose）：
 *   1. 客户端调用此接口获取 rawChallenge（纯随机数）
 *   2. 客户端构造 userIntentJson 字符串
 *   3. 客户端计算 intentHash = SHA256(rawChallenge + userIntentJson)
 *   4. 客户端用 Passkey 对 intentHash 签名（WebAuthn challenge = intentHash）
 *   5. 业务请求中携带：webauthnSignature、userIntentJson、rawChallenge 及其他业务参数
 *
 * HTTP body 仅包含 { payload, platformSignature }，
 * 所有业务参数从验证后的 payload 解析获取。
 *
 * purpose=register 的 payload 结构：
 *   { purpose, userId? }
 *
 * 其他 purpose 的 payload 结构：
 *   { purpose, userId, credentialId }
 */

import { v4 as uuidv4 } from 'uuid';

/**
 * 所有支持的 purpose 枚举
 * 注意：authorize 已移除，授权JSON签名不需要服务端挑战值
 */
const VALID_PURPOSES = [
  'register',           // 新用户 Passkey 注册（无需 Passkey 归属验证）
  'register_passkey',   // 已有用户添加新 Passkey（需要现有 Passkey 归属验证）
  'wallet_create',      // 创建钱包
  'wallet_delete',      // 删除钱包容器
  'passkey_delete',     // 删除 Passkey
  'wallet_entry_delete',// 删除单个逻辑钱包
  'key_export',         // 密钥导出（初始化）
  'key_export_confirm', // 密钥导出确认（确认已收到数据，授权删除钱包）
  'key_import_init',    // 用户端密钥导入（初始化密钥交换）
  'key_import_complete',// 用户端密钥导入（完成导入）
];

/**
 * 不需要 Passkey 归属验证的 purpose
 */
const NO_PASSKEY_VERIFY_PURPOSES = new Set(['register']);

export class ChallengeHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/whitelist/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../modules/webauthn/passkey-manager.js').PasskeyManager} deps.passkeyManager
   * @param {import('../modules/webauthn/challenge-manager.js').WebAuthnChallengeManager} deps.challengeManager
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('ChallengeHandler requires whitelistVerifier');
    if (!deps.passkeyManager) throw new Error('ChallengeHandler requires passkeyManager');
    if (!deps.challengeManager) throw new Error('ChallengeHandler requires challengeManager');
    this._whitelist = deps.whitelistVerifier;
    this._passkey = deps.passkeyManager;
    this._challenge = deps.challengeManager;
  }

  /**
   * 统一挑战值生成
   *
   * payload JSON:
   *   - purpose=register:  { purpose, userId? }
   *   - 其他 purpose:      { purpose, userId, credentialId }
   *
   * 返回的 challenge 是纯随机数（rawChallenge）。
   * 客户端收到后，需要：
   *   1. 构造 userIntentJson 字符串
   *   2. 计算 intentHash = SHA256(rawChallenge + userIntentJson)
   *   3. 用 Passkey 对 intentHash 签名
   *   4. 业务请求中携带 webauthnSignature、userIntentJson、rawChallenge
   *
   * 各 purpose 的 userIntentJson 字段规范（业务请求时使用）：
   *   wallet_create:        { purpose, userId, chains, mnemonicStrength? }
   *   wallet_delete:        { purpose, userId, walletId }
   *   passkey_delete:       { purpose, userId, credentialIdsToDelete }
   *   wallet_entry_delete:  { purpose, userId, walletId, address }
   *   key_export（ECDH）:   { purpose, userId, exportInfo, peerPublicKey }
   *   key_export（RSA）:    { purpose, userId, exportInfo, rsaPublicKey }
   *   （exportInfo 为数组：[{ walletId, addresses }]，addresses 为空时导出该 walletId 下所有私钥）
   *   key_export_confirm:   { purpose, userId, sessionId }
   *   register_passkey:     { purpose, userId }
   *   key_import_init:      { purpose, userId, importType }
   *   key_import_complete:  { purpose, userId, sessionId, walletId, chains }
   *
   * 注意：authorize（授权JSON签名）不在此接口支持范围内。
   * 授权JSON的WebAuthn challenge由客户端自行计算：SHA256(authJson)，不依赖服务端挑战值。
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<{ challenge: string, userId: string, expiresAt?: string }>}
   */
  async handleChallenge(request) {
    // 1. 验证平台白名单签名
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[Challenge] handleChallenge: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 2. 解析验证过的 payload
    let req;
    try {
      req = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    // 3. 验证 purpose
    if (!req.purpose) {
      throw new Error('purpose is required');
    }
    if (!VALID_PURPOSES.includes(req.purpose)) {
      throw new Error(`Invalid purpose. Must be one of: ${VALID_PURPOSES.join(', ')}`);
    }

    const purpose = req.purpose;

    // 4. 根据 purpose 决定验证逻辑
    if (NO_PASSKEY_VERIFY_PURPOSES.has(purpose)) {
      // register：userId 可选，不需要 Passkey 归属验证
      const userId = req.userId || `user-${uuidv4()}`;

      const { challenge, expiresAt } = this._challenge.createChallenge(userId, purpose);

      console.log(`[Challenge] handleChallenge: success, purpose=${purpose}, userId=${userId}`);

      return {
        challenge,
        userId,
        expiresAt,
      };
    } else {
      // 其他 purpose：userId + credentialId 必填
      if (!req.userId) throw new Error('userId is required');
      if (!req.credentialId) throw new Error('credentialId is required');

      // 5. 验证 Passkey 归属
      const passkeyData = await this._passkey.getPasskey(req.userId, req.credentialId);
      if (!passkeyData) {
        console.log(`[Challenge] handleChallenge: REJECTED - passkey not bound to userId=${req.userId}`);
        throw new Error('Passkey not bound to this user');
      }

      // 6. 生成纯随机挑战值（不绑定业务意图）
      const { challenge, expiresAt } = this._challenge.createChallenge(
        req.userId,
        purpose,
        req.credentialId
      );

      console.log(`[Challenge] handleChallenge: success, purpose=${purpose}, userId=${req.userId}`);

      return {
        challenge,
        userId: req.userId,
        expiresAt,
      };
    }
  }
}
