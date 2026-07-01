/**
 * WebAuthn 挑战值管理器
 * 负责挑战值的生成、存储、验证和清理
 *
 * 挑战值生成策略：
 *   所有 purpose 的 challenge 均为随机 32 字节（base64url），不绑定业务参数。
 *   服务端只负责生成并记录随机数，不存储用户意图。
 *
 * 客户端使用流程（非 register/authenticate purpose）：
 *   1. 调用 /api/challenge 获取 rawChallenge（随机数）
 *   2. 构造 userIntentJson 字符串
 *   3. 计算 intentHash = SHA256(rawChallenge + userIntentJson)
 *   4. 用 Passkey 对 intentHash 签名（WebAuthn challenge = intentHash）
 *   5. 业务请求中携带：webauthnSignature、userIntentJson、rawChallenge
 *
 * 服务端验证流程：
 *   1. 根据 rawChallenge 查询挑战值记录，不存在则拒绝
 *   2. 计算 intentHash = SHA256(rawChallenge + userIntentJson)
 *   3. 验证 WebAuthn 签名（expectedChallenge = intentHash）
 *   4. 解析 userIntentJson 并与业务参数比对
 *   5. 消费（删除）挑战值记录
 *
 * 注意：authorize（授权JSON签名）不使用此管理器。
 * 授权JSON的WebAuthn challenge由客户端自行计算：SHA256(authJson)，
 * auth-engine 使用 expectedChallenge 模式直接比对，不经过 challengeManager。
 */

import crypto from 'crypto';

/**
 * 默认 TTL：5 分钟
 */
const DEFAULT_CHALLENGE_TTL_SECONDS = 300;

/**
 * 计算 intentHash：SHA256(rawChallenge + userIntentJson)
 * @param {string} rawChallenge - base64url 编码的原始挑战值（随机数）
 * @param {string} userIntentJson - 用户意图的原始 JSON 字符串
 * @returns {string} base64url 编码的 SHA256 哈希
 */
export function computeIntentHash(rawChallenge, userIntentJson) {
  return crypto.createHash('sha256')
    .update(rawChallenge + userIntentJson)
    .digest('base64url');
}

export class WebAuthnChallengeManager {
  /**
   * @param {import('../../database/connection-manager.js').default} connectionManager
   * @param {Object} options
   * @param {number} options.challengeTtlSeconds - 挑战值 TTL，默认 300 秒
   */
  constructor(connectionManager, options = {}) {
    if (!connectionManager) {
      throw new Error('WebAuthnChallengeManager requires a ConnectionManager instance');
    }
    this._db = connectionManager;
    this._ttlSeconds = options.challengeTtlSeconds || DEFAULT_CHALLENGE_TTL_SECONDS;
  }

  /**
   * 生成并存储 WebAuthn 挑战值
   *
   * 所有 purpose 的 challenge 均为随机 32 字节（base64url），不绑定业务参数。
   *
   * @param {string} userId - 用户 ID
   * @param {string} purpose - 用途（'register' | 'authenticate' | 'register_passkey' | 'wallet_create' | 'wallet_delete' | 'passkey_delete' | 'wallet_entry_delete' | 'key_export' | 'key_export_confirm' | 'evidence_query'）
   * @param {string} [credentialId] - 可选，关联的凭证 ID
   * @returns {{ challenge: string, expiresAt: string }} 生成成功后的挑战值和过期时间
   */
  createChallenge(userId, purpose, credentialId = null) {
    if (!userId) {
      throw new Error('userId is required');
    }
    if (!purpose) {
      throw new Error('purpose is required');
    }

    const expiresAt = this._computeExpiresAt();

    // 所有 purpose：challenge = 随机 32 字节
    const challenge = crypto.randomBytes(32).toString('base64url');

    this._db.writeQuery(
      `INSERT INTO webauthn_challenges (challenge, user_id, purpose, credential_id, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
      [challenge, userId, purpose, credentialId, expiresAt]
    );

    console.log(`[WebAuthnChallengeManager] Created challenge for userId=${userId}, purpose=${purpose}, expiresAt=${expiresAt}`);

    return { challenge, expiresAt };
  }

  /**
   * 查找挑战值（不消费）
   * 用于需要先查找再手动消费的场景（如 register_passkey 流程）
   *
   * @param {string} challenge - 挑战值（base64url 编码）
   * @param {string} [userId] - 可选，期望的用户 ID
   * @param {string} [purpose] - 可选，期望的用途
   * @returns {{ found: boolean, reason: string, id?: number, userId?: string, purpose?: string, credentialId?: string }}
   */
  findChallenge(challenge, userId = null, purpose = null) {
    if (!challenge) {
      return { found: false, reason: 'challenge is required' };
    }

    const rows = this._db.readQuery(
      `SELECT id, user_id, purpose, credential_id, expires_at
       FROM webauthn_challenges
       WHERE challenge = ? AND expires_at > datetime('now')`,
      [challenge]
    );

    if (rows.length === 0) {
      return { found: false, reason: 'challenge not found or expired' };
    }

    const row = rows[0];

    if (userId && row.user_id !== userId) {
      return { found: false, reason: 'challenge userId mismatch' };
    }

    if (purpose && row.purpose !== purpose) {
      return { found: false, reason: 'challenge purpose mismatch' };
    }

    return {
      found: true,
      reason: 'OK',
      id: row.id,
      userId: row.user_id,
      purpose: row.purpose,
      credentialId: row.credential_id,
    };
  }

  /**
   * 按 ID 消费（删除）挑战值
   * 与 findChallenge 配合使用
   * @param {number} id - 挑战值记录 ID
   */
  consumeChallengeById(id) {
    this._db.writeQuery(`DELETE FROM webauthn_challenges WHERE id = ?`, [id]);
    console.log(`[WebAuthnChallengeManager] Challenge consumed by id=${id}`);
  }

  /**
   * 验证挑战值是否存在且未过期
   * 验证成功后自动删除挑战值（一次性使用）
   *
   * 注意：此方法仅验证 rawChallenge 的存在性，不验证 userIntentJson。
   * 调用方需要自行计算 intentHash = SHA256(rawChallenge + userIntentJson)，
   * 并将 intentHash 作为 WebAuthn 签名的 expectedChallenge。
   *
   * @param {string} rawChallenge - 原始挑战值（base64url 编码，即服务端生成的随机数）
   * @param {string} [userId] - 可选，期望的用户 ID（用于增强安全性）
   * @param {string} [purpose] - 可选，期望的用途
   * @returns {{ valid: boolean, reason: string, userId?: string, purpose?: string, credentialId?: string }}
   */
  verifyAndConsumeChallenge(rawChallenge, userId = null, purpose = null) {
    if (!rawChallenge) {
      return { valid: false, reason: 'challenge is required' };
    }

    // 查询挑战值（未过期的）
    const rows = this._db.readQuery(
      `SELECT id, user_id, purpose, credential_id, expires_at
       FROM webauthn_challenges
       WHERE challenge = ? AND expires_at > datetime('now')`,
      [rawChallenge]
    );

    if (rows.length === 0) {
      // 挑战值不存在或已过期
      return { valid: false, reason: 'challenge not found or expired' };
    }

    const row = rows[0];

    // 验证 userId（如果提供了）
    if (userId && row.user_id !== userId) {
      return { valid: false, reason: 'challenge userId mismatch' };
    }

    // 验证 purpose（如果提供了）
    if (purpose && row.purpose !== purpose) {
      return { valid: false, reason: 'challenge purpose mismatch' };
    }

    // 删除挑战值（一次性使用）
    this._db.writeQuery(
      `DELETE FROM webauthn_challenges WHERE id = ?`,
      [row.id]
    );

    console.log(`[WebAuthnChallengeManager] Challenge verified and consumed: userId=${row.user_id}, purpose=${row.purpose}`);

    return {
      valid: true,
      reason: 'OK',
      userId: row.user_id,
      purpose: row.purpose,
      credentialId: row.credential_id,
    };
  }

  /**
   * 清理过期的挑战值
   * @returns {number} 删除的记录数
   */
  cleanExpiredChallenges() {
    const result = this._db.writeQuery(
      `DELETE FROM webauthn_challenges WHERE expires_at < datetime('now')`
    );
    if (result.changes > 0) {
      console.log(`[WebAuthnChallengeManager] Cleaned ${result.changes} expired challenges`);
    }
    return result.changes;
  }

  /**
   * 计算过期时间
   * @returns {string} ISO 8601 格式的时间字符串
   * @private
   */
  _computeExpiresAt() {
    const now = new Date();
    now.setSeconds(now.getSeconds() + this._ttlSeconds);
    return now.toISOString().slice(0, 19).replace('T', ' ');
  }
}
