/**
 * Passkey 管理模块
 * 负责 Passkey 公钥的 CRUD 操作 + 归属验证
 * 全局规则：所有 Passkey 鉴权接口必须同时提供 userId 和 credentialId
 *
 * 公钥格式：COSE（CBOR Object Signing and Encryption）格式，由 @simplewebauthn/server 解析
 */

import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { createConnProxy } from '../../sync/sync-adapter.js';

export class PasskeyManager {
  /**
   * @param {import('../../database/connection-manager.js').default} connectionManager
   * @param {import('@xnetx/raft-hlc-sync').SyncEngine} engine
   */
  constructor(connectionManager, engine) {
    if (!connectionManager) {
      throw new Error('PasskeyManager requires a ConnectionManager instance');
    }
    this._db = connectionManager;
    this._engine = engine;
  }

  /**
   * 注册/导入 Passkey（绑定到 userId）
   * 若 userId 不存在则先创建账户，再绑定 Passkey
   *
   * @param {string} userId - 用户 ID（导入时必传，创建时可传或随机生成）
   * @param {string} credentialId - Passkey 凭证 ID（base64url 编码）
   * @param {Uint8Array|Buffer} publicKeyCose - COSE 格式公钥（由 @simplewebauthn/server 提供）
   * @returns {Promise<{ userId: string, credentialId: string, created: boolean }>}
   */
  async registerPasskey(userId, credentialId, publicKeyCose) {
    if (!credentialId) {
      throw new Error('credentialId is required');
    }
    if (!publicKeyCose) {
      throw new Error('publicKeyCose is required');
    }

    // 如果未传 userId，随机生成
    const finalUserId = userId || uuidv4();
    // 确保 publicKeyCose 是 Buffer
    const publicKeyCoseBuf = Buffer.isBuffer(publicKeyCose) ? publicKeyCose : Buffer.from(publicKeyCose);

    return this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      const ts = this._engine.hlc.tick();

      // 1. 确保账户存在（INSERT OR IGNORE 幂等）
      conn.query(
        'INSERT OR IGNORE INTO accounts (user_id, _hlc) VALUES (?, ?)',
        [finalUserId, ts]
      );

      // 2. 绑定 Passkey（唯一约束 user_id + credential_id）
      const result = conn.query(
        'INSERT INTO passkeys (user_id, credential_id, public_key_cose, _hlc) VALUES (?, ?, ?, ?)',
        [finalUserId, credentialId, publicKeyCoseBuf, ts]
      );

      return {
        userId: finalUserId,
        credentialId,
        created: result.changes > 0,
      };
    }, finalUserId);
  }

  /**
   * 查询 Passkey 公钥（必须同时指定 userId + credentialId）
   *
   * @param {string} userId - 用户 ID
   * @param {string} credentialId - Passkey 凭证 ID
   * @returns {Promise<{ publicKeyCose: Buffer, signCount: number } | null>}
   */
  async getPasskey(userId, credentialId) {
    if (!userId || !credentialId) {
      throw new Error('Both userId and credentialId are required');
    }

    const rows = await this._db.readQuery(
      'SELECT public_key_cose, sign_count FROM passkeys WHERE user_id = ? AND credential_id = ?',
      [userId, credentialId]
    );

    if (rows.length === 0) {
      return null;
    }

    return {
      publicKeyCose: rows[0].public_key_cose,
      signCount: rows[0].sign_count,
    };
  }

  /**
   * 验证 Passkey 归属（检查 userId + credentialId 组合是否存在）
   *
   * @param {string} userId - 用户 ID
   * @param {string} credentialId - Passkey 凭证 ID
   * @returns {Promise<boolean>}
   */
  async verifyPasskeyOwnership(userId, credentialId) {
    if (!userId || !credentialId) {
      throw new Error('Both userId and credentialId are required');
    }

    const rows = await this._db.readQuery(
      'SELECT 1 FROM passkeys WHERE user_id = ? AND credential_id = ? LIMIT 1',
      [userId, credentialId]
    );

    return rows.length > 0;
  }

  /**
   * 根据 credentialId 查询所有绑定的 userId 列表
   * （同一 Passkey 允许绑定多个 userId）
   *
   * @param {string} credentialId - Passkey 凭证 ID
   * @returns {Promise<string[]>} userId 数组
   */
  async getUserIdsByPasskey(credentialId) {
    if (!credentialId) {
      throw new Error('credentialId is required');
    }

    const rows = await this._db.readQuery(
      'SELECT user_id FROM passkeys WHERE credential_id = ?',
      [credentialId]
    );

    return rows.map((row) => row.user_id);
  }

  /**
   * 删除 Passkey（支持批量，传 credentialId 列表）
   * 删除后若该 userId 下无剩余 Passkey，级联删除整个账户及所有下属数据
   *
   * @param {string} userId - 用户 ID
   * @param {string[]} credentialIds - 要删除的 credentialId 列表
   * @returns {Promise<{ deletedCount: number, accountDeleted: boolean }>}
   */
  async deletePasskeys(userId, credentialIds) {
    if (!userId) {
      throw new Error('userId is required');
    }
    if (!credentialIds || credentialIds.length === 0) {
      throw new Error('credentialIds array is required and must not be empty');
    }

    return this._engine.write(async (db) => {
      const conn = createConnProxy(db);

      // 1. 删除指定的 Passkey
      const placeholders = credentialIds.map(() => '?').join(',');
      const deleteResult = conn.query(
        `DELETE FROM passkeys WHERE user_id = ? AND credential_id IN (${placeholders})`,
        [userId, ...credentialIds]
      );

      // 2. 检查该用户下是否还有剩余 Passkey
      const remaining = conn.query(
        'SELECT COUNT(*) as cnt FROM passkeys WHERE user_id = ?',
        [userId]
      );

      let accountDeleted = false;

      if (remaining[0].cnt === 0) {
        // 3. 无剩余 Passkey → 删除账户记录及授权数据，级联删除整个账户及所有下属数据
        conn.query('DELETE FROM tx_sign_nonces WHERE authorization_id IN (SELECT authorization_id FROM authorization_states WHERE user_id = ?)', [userId]);
        conn.query('DELETE FROM authorization_token_states WHERE authorization_id IN (SELECT authorization_id FROM authorization_states WHERE user_id = ?)', [userId]);
        conn.query('DELETE FROM authorization_states WHERE user_id = ?', [userId]);
        conn.query('DELETE FROM import_sessions WHERE user_id = ?', [userId]);
        conn.query('DELETE FROM wallets WHERE user_id = ?', [userId]);
        conn.query('DELETE FROM accounts WHERE user_id = ?', [userId]);
        accountDeleted = true;
      }

      return {
        deletedCount: deleteResult.changes,
        accountDeleted,
      };
    }, userId);
  }

  /**
   * 获取用户所有 Passkey 列表
   *
   * @param {string} userId - 用户 ID
   * @returns {Promise<Array<{ credentialId: string, publicKeyCose: Buffer, signCount: number, createdAt: Date }>>}
   */
  async listPasskeys(userId) {
    if (!userId) {
      throw new Error('userId is required');
    }

    const rows = await this._db.readQuery(
      'SELECT credential_id, public_key_cose, sign_count, created_at FROM passkeys WHERE user_id = ? ORDER BY created_at ASC',
      [userId]
    );

    return rows.map((row) => ({
      credentialId: row.credential_id,
      publicKeyCose: row.public_key_cose,
      signCount: row.sign_count,
      createdAt: row.created_at,
    }));
  }

  /**
   * 更新签名计数器（防重放）
   *
   * @param {string} userId - 用户 ID
   * @param {string} credentialId - Passkey 凭证 ID
   * @param {number} newSignCount - 新的签名计数值
   * @returns {Promise<boolean>} 是否更新成功
   */
  async updateSignCount(userId, credentialId, newSignCount) {
    if (!userId || !credentialId) {
      throw new Error('Both userId and credentialId are required');
    }

    const result = await this._engine.write(async (db) => {
      const ts = this._engine.hlc.tick();
      return db.run(
        'UPDATE passkeys SET sign_count = ?, _hlc = ? WHERE user_id = ? AND credential_id = ?',
        [newSignCount, ts, userId, credentialId]
      );
    }, userId);

    return result.changes > 0;
  }

  /**
   * 计算 Passkey 公钥的 SHA256 哈希（用于与合约恢复条目中的哈希值比对）
   * @param {Buffer|Uint8Array} publicKeyCose - COSE 格式公钥
   * @returns {string} 0x 前缀的 bytes32 hex 字符串
   */
  static computePubKeyHash(publicKeyCose) {
    const hash = crypto.createHash('sha256').update(publicKeyCose).digest();
    return '0x' + hash.toString('hex');
  }

  /**
   * 恢复替换（Owner 授权的 Passkey 找回流程）
   * 1. 在 userId 下查找公钥哈希匹配 oldPubKeyHash 的 Passkey 记录
   * 2. 删除该 userId 下所有其他 Passkey（仅保留匹配的那条，防止级联删除账户）
   * 3. 用新 Passkey 信息原地替换保留的那条记录
   *
   * @param {string} userId - 用户 ID
   * @param {string} oldPubKeyHash - 旧 Passkey 公钥的 SHA256 哈希（0x bytes32 hex）
   * @param {string} newCredentialId - 新 Passkey 凭证 ID
   * @param {Uint8Array|Buffer} newPublicKeyCose - 新 Passkey 的 COSE 格式公钥
   * @returns {Promise<{ success: boolean, replacedCredentialId: string|null, deletedCount: number }>}
   */
  async recoveryReplace(userId, oldPubKeyHash, newCredentialId, newPublicKeyCose) {
    if (!userId || !oldPubKeyHash || !newCredentialId || !newPublicKeyCose) {
      throw new Error('userId, oldPubKeyHash, newCredentialId and newPublicKeyCose are all required');
    }

    const newPublicKeyCoseBuf = Buffer.isBuffer(newPublicKeyCose) ? newPublicKeyCose : Buffer.from(newPublicKeyCose);

    // 1. 读取该用户所有 Passkey，找到匹配 oldPubKeyHash 的那条
    const allPasskeys = await this._db.readQuery(
      'SELECT credential_id, public_key_cose FROM passkeys WHERE user_id = ?',
      [userId]
    );

    let matchedCredentialId = null;
    for (const row of allPasskeys) {
      const hash = PasskeyManager.computePubKeyHash(row.public_key_cose);
      if (hash === oldPubKeyHash) {
        matchedCredentialId = row.credential_id;
        break;
      }
    }

    if (!matchedCredentialId) {
      return { success: false, replacedCredentialId: null, deletedCount: 0 };
    }

    // 2. 在写事务中：删除其他所有 Passkey + 替换匹配的那条
    const result = await this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      const ts = this._engine.hlc.tick();

      // 删除 userId 下除 matchedCredentialId 以外的所有 Passkey
      const deleteResult = conn.query(
        'DELETE FROM passkeys WHERE user_id = ? AND credential_id != ?',
        [userId, matchedCredentialId]
      );

      // 替换保留的那条 Passkey
      conn.query(
        'UPDATE passkeys SET credential_id = ?, public_key_cose = ?, sign_count = 0, _hlc = ? WHERE user_id = ? AND credential_id = ?',
        [newCredentialId, newPublicKeyCoseBuf, ts, userId, matchedCredentialId]
      );

      return { deletedCount: deleteResult.changes };
    }, userId);

    return {
      success: true,
      replacedCredentialId: matchedCredentialId,
      deletedCount: result.deletedCount,
    };
  }

  /**
   * 替换 Passkey（用于冻结账户的 Passkey 替换场景）
   * 原地更新 credential_id 和 public_key_cose，不删除记录，保留 wallets 等关联数据
   *
   * @param {string} userId - 用户 ID
   * @param {string} oldCredentialId - 旧的 Passkey 凭证 ID（被替换的）
   * @param {string} newCredentialId - 新的 Passkey 凭证 ID
   * @param {Uint8Array|Buffer} newPublicKeyCose - 新的 COSE 格式公钥
   * @returns {Promise<boolean>} 是否替换成功
   */
  async replacePasskey(userId, oldCredentialId, newCredentialId, newPublicKeyCose) {
    if (!userId || !oldCredentialId || !newCredentialId || !newPublicKeyCose) {
      throw new Error('userId, oldCredentialId, newCredentialId and newPublicKeyCose are all required');
    }

    const newPublicKeyCoseBuf = Buffer.isBuffer(newPublicKeyCose) ? newPublicKeyCose : Buffer.from(newPublicKeyCose);

    const result = await this._engine.write(async (db) => {
      const ts = this._engine.hlc.tick();
      return db.run(
        'UPDATE passkeys SET credential_id = ?, public_key_cose = ?, sign_count = 0, _hlc = ? WHERE user_id = ? AND credential_id = ?',
        [newCredentialId, newPublicKeyCoseBuf, ts, userId, oldCredentialId]
      );
    }, userId);

    return result.changes > 0;
  }
}
