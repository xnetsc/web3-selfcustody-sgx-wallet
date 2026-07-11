/**
 * 导入会话管理器
 * 管理密钥交换的临时会话（创建/查找）
 *
 * 会话删除由 completeImport 事务内执行（保证原子性），
 * 过期清理由 schema.js 的 cleanExpiredSessions 定时执行。
 *
 * 支持两种密钥交换方式：
 * - ECDH（默认）：SGX 生成 ECDH 密钥对，返回公钥；客户端用共享密钥加密数据
 * - RSA：客户端提供 RSA 公钥，SGX 生成 AES-256 密钥并用 RSA 加密返回；客户端用 AES 密钥加密数据
 */

import { v4 as uuidv4 } from 'uuid';
import { generateECDHKeyPair } from './ecdh.js';
import { generateAESKey, encryptAESKeyWithRSA, validateAndDetectRSAPublicKey } from './rsa.js';
import { getMonotonicSqliteNow, getMonotonicSqliteAfter } from '../../utils/monotonic-clock.js';

export class SessionManager {
  /**
   * @param {import('../../database/connection-manager.js').default} connectionManager
   * @param {import('@xnetx/raft-hlc-sync').SyncEngine} engine
   */
  constructor(connectionManager, engine) {
    if (!connectionManager) {
      throw new Error('SessionManager requires a ConnectionManager instance');
    }
    this._db = connectionManager;
    this._engine = engine;
  }

  /**
   * 创建导入会话（ECDH 模式）
   * SGX 生成 ECDH 密钥对，私钥存入数据库，返回公钥给客户端
   *
   * @param {string} userId - 用户 ID
   * @param {string} importType - 'private_key' | 'mnemonic'
   * @param {number} expireSeconds - 过期时间（秒）
   * @returns {Promise<{ sessionId: string, enclavePublicKey: string, keyType: string }>}
   */
  async createECDHSession(userId, importType, expireSeconds) {
    this._validateCommonParams(userId, importType, expireSeconds);

    const sessionId = uuidv4();
    const keyPair = generateECDHKeyPair();

    console.log(`[SessionManager] createECDHSession: userId=${userId}, importType=${importType}, expireSeconds=${expireSeconds}, sessionId=${sessionId}`);

    await this._engine.write(async (db) => {
      const ts = this._engine.hlc.tick();
      db.run(
        `INSERT INTO import_sessions (session_id, user_id, key_type, secret_key, import_type, created_at, expires_at, _hlc)
         VALUES (?, ?, 'ecdh', ?, ?, ?, ?, ?)`,
        [sessionId, userId, keyPair.privateKey, importType, getMonotonicSqliteNow(), getMonotonicSqliteAfter(expireSeconds), ts]
      );
    }, userId);

    console.log(`[SessionManager] createECDHSession: session persisted`);

    return {
      sessionId,
      enclavePublicKey: keyPair.publicKey,
      keyType: 'ecdh',
    };
  }

  /**
   * 创建导入会话（RSA 模式）
   * 客户端提供 RSA 公钥，SGX 生成 AES-256 密钥并用 RSA 公钥加密返回
   * AES 密钥明文存入数据库，供后续解密使用
   *
   * @param {string} userId - 用户 ID
   * @param {string} importType - 'private_key' | 'mnemonic'
   * @param {number} expireSeconds - 过期时间（秒）
   * @param {string} rsaPublicKey - 客户端 RSA 公钥（PEM 或 Base64 DER）
   * @returns {Promise<{ sessionId: string, encryptedAESKey: string, keyType: string }>}
   */
  async createRSASession(userId, importType, expireSeconds, rsaPublicKey) {
    this._validateCommonParams(userId, importType, expireSeconds);

    if (!rsaPublicKey) {
      throw new Error('rsaPublicKey is required for RSA mode');
    }

    // 验证并检测 RSA 公钥类型
    const rsaResult = validateAndDetectRSAPublicKey(rsaPublicKey);
    if (!rsaResult.valid) {
      throw new Error(`Invalid RSA public key: ${rsaResult.error}`);
    }

    const sessionId = uuidv4();
    const aesKey = generateAESKey();
    const encryptedAESKey = encryptAESKeyWithRSA(rsaPublicKey, aesKey);

    console.log(`[SessionManager] createRSASession: userId=${userId}, importType=${importType}, keyType=${rsaResult.keyType}, expireSeconds=${expireSeconds}, sessionId=${sessionId}`);

    await this._engine.write(async (db) => {
      const ts = this._engine.hlc.tick();
      db.run(
        `INSERT INTO import_sessions (session_id, user_id, key_type, secret_key, import_type, created_at, expires_at, _hlc)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [sessionId, userId, rsaResult.keyType, aesKey.toString('hex'), importType, getMonotonicSqliteNow(), getMonotonicSqliteAfter(expireSeconds), ts]
      );
    }, userId);

    console.log(`[SessionManager] createRSASession: session persisted, keyType=${rsaResult.keyType}`);

    return {
      sessionId,
      encryptedAESKey,
      keyType: rsaResult.keyType,
    };
  }

  /**
   * 查找有效会话（校验过期时间）
   *
   * @param {string} sessionId - 会话 ID
   * @returns {Promise<{ sessionId: string, userId: string, secretKey: string, keyType: string, importType: string } | null>}
   */
  async findSession(sessionId) {
    if (!sessionId) {
      throw new Error('sessionId is required');
    }

    console.log(`[SessionManager] findSession: sessionId=${sessionId}`);

    const rows = await this._db.readQuery(
      `SELECT session_id, user_id, key_type, secret_key, import_type FROM import_sessions WHERE session_id = ? AND expires_at > ?`,
      [sessionId, getMonotonicSqliteNow()]
    );

    if (rows.length === 0) {
      console.log(`[SessionManager] findSession: not found or expired`);
      return null;
    }

    console.log(`[SessionManager] findSession: found, userId=${rows[0].user_id}, keyType=${rows[0].key_type}, importType=${rows[0].import_type}`);

    return {
      sessionId: rows[0].session_id,
      userId: rows[0].user_id,
      secretKey: rows[0].secret_key,
      keyType: rows[0].key_type,
      importType: rows[0].import_type,
    };
  }

  /**
   * 校验公共参数
   * @private
   */
  _validateCommonParams(userId, importType, expireSeconds) {
    if (!userId) {
      throw new Error('userId is required');
    }
    if (!importType || !['private_key', 'mnemonic', 'batch'].includes(importType)) {
      throw new Error('importType must be "private_key", "mnemonic", or "batch"');
    }
    if (!expireSeconds || expireSeconds <= 0) {
      throw new Error('expireSeconds must be a positive number');
    }
  }
}
