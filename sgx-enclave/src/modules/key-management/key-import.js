/**
 * 钱包导入模块
 * 两步导入流程：初始化密钥交换 → 接收加密数据并解密存储
 *
 * 支持两种密钥交换方式：
 * - ECDH（默认）：SGX 生成 ECDH 密钥对，返回公钥；客户端用共享密钥加密数据
 * - RSA：客户端提供 RSA 公钥，SGX 生成 AES 密钥并用 RSA 加密返回；客户端用 AES 密钥加密数据
 *
 * 支持批量导入：一次可导入多个钱包（私钥 + 助记词混合，可跨 userId）
 * walletId 规则（按 userId 分组）：
 * - 每个钱包项可单独指定 walletId
 * - 同一 userId 下未指定 walletId 的钱包共用一个随机生成的 walletId
 * - 不同 userId 各自独立生成 sharedWalletId
 */

import crypto from 'crypto';
import { deriveSharedSecret, decrypt } from './ecdh.js';
import { validateMnemonic, deriveWallet, privateKeyToAddress } from '../wallet-management/hd-wallet.js';
import { createConnProxy } from '../../sync/sync-adapter.js';
const DEFAULT_IMPORT_TTL_SECONDS = 300 // 5 分钟

export class KeyImporter {
  /**
   * @param {import('./session-manager.js').SessionManager} sessionManager
   * @param {import('../wallet-management/wallet-manager.js').WalletManager} walletManager
   * @param {Object} [options]
   * @param {import('@xnetx/raft-hlc-sync').SyncEngine} [options.engine]
   */
  constructor(sessionManager, walletManager, options = {}) {
    if (!sessionManager) {
      throw new Error('KeyImporter requires a SessionManager instance');
    }
    if (!walletManager) {
      throw new Error('KeyImporter requires a WalletManager instance');
    }
    this._sessionManager = sessionManager;
    this._walletManager = walletManager;
    this._engine = options.engine;
    this._importTtlSeconds = options.importTtlSeconds || DEFAULT_IMPORT_TTL_SECONDS;
  }

  /**
   * 第一步：创建导入会话
   * - ECDH 模式（默认）：不传 rsaPublicKey，返回 SGX ECDH 公钥
   * - RSA 模式：传入 rsaPublicKey，返回 RSA 加密后的 AES 密钥
   *
   * @param {string} userId - 用户 ID
   * @param {string} importType - 'private_key' | 'mnemonic' | 'batch'
   * @param {number} expireSeconds - 会话过期时间（秒）
   * @param {string} [rsaPublicKey] - 客户端 RSA 公钥（传入则走 RSA 流程）
   * @returns {Promise<Object>} ECDH: { sessionId, enclavePublicKey, keyType } | RSA: { sessionId, encryptedAESKey, keyType }
   */
  async initImport(userId, importType, expireSeconds, rsaPublicKey) {
    console.log(`[KeyImporter] initImport: userId=${userId}, importType=${importType}, expireSeconds=${expireSeconds}, mode=${rsaPublicKey ? 'rsa' : 'ecdh'}`);

    let result;
    if (rsaPublicKey) {
      result = await this._sessionManager.createRSASession(userId, importType, expireSeconds, rsaPublicKey);
    } else {
      result = await this._sessionManager.createECDHSession(userId, importType, expireSeconds);
    }

    console.log(`[KeyImporter] initImport: session created, sessionId=${result.sessionId}, keyType=${result.keyType}`);
    return result;
  }

  /**
   * 第二步：接收加密数据，解密后批量存入钱包
   *
   * 解密方式根据会话的 keyType 自动选择：
   * - ECDH：需要 peerPublicKey，通过共享密钥解密
   * - RSA：无需 peerPublicKey，直接用存储的 AES 密钥解密
   *
   * @param {string} sessionId - 会话 ID
   * @param {string|null} peerPublicKey - 对方 ECDH 公钥（hex），ECDH 模式必填，RSA 模式无需
   * @param {Object} encryptedData - 加密数据 { ciphertext, iv, authTag }（均为 hex）
   * @param {string|null} [walletId] - 钱包 ID（单个导入时使用，可选）
   * @param {Array<{chainId: number, coinType: number}>} [chains] - 链列表（单个导入时使用）
   * @returns {Promise<Object>} 导入结果
   */
  async completeImport(sessionId, peerPublicKey, encryptedData, walletId, chains) {
    console.log(`[KeyImporter] completeImport: sessionId=${sessionId}`);

    // 1. 查找会话（校验过期）
    const session = await this._sessionManager.findSession(sessionId);
    if (!session) {
      console.log(`[KeyImporter] completeImport: FAILED - session not found or expired`);
      throw new Error('Session not found or expired');
    }
    console.log(`[KeyImporter] completeImport: session found, userId=${session.userId}, keyType=${session.keyType}, importType=${session.importType}`);

    // 2. 根据 keyType 获取解密密钥
    let decryptionKey;
    if (session.keyType === 'ecdh') {
      if (!peerPublicKey) {
        throw new Error('peerPublicKey is required for ECDH mode');
      }
      decryptionKey = deriveSharedSecret(session.secretKey, peerPublicKey);
    } else {
      // RSA 模式：直接使用存储的 AES 密钥
      decryptionKey = Buffer.from(session.secretKey, 'hex');
    }

    // 3. AES-256-GCM 解密
    const decrypted = decrypt(
      decryptionKey,
      encryptedData.ciphertext,
      encryptedData.iv,
      encryptedData.authTag
    );
    const plaintext = decrypted.toString('utf8');

    // 4. 所有 DB 写操作在 engine.write() 内完成：导入钱包 + 删除会话（原子性 + 2PC）
    return this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      const ts = this._engine.hlc.tick();

      let result;
      if (session.importType === 'batch') {
        result = this._batchImportInTransaction(conn, session.userId, plaintext, ts);
      } else {
        result = this._singleImportInTransaction(conn, session.userId, session.importType, plaintext, walletId, chains, ts);
      }

      // 在同一事务中删除会话（确保导入和会话删除的原子性）
      conn.query('DELETE FROM import_sessions WHERE session_id = ?', [sessionId]);
      console.log(`[KeyImporter] completeImport: session ${sessionId} deleted in transaction`);

      return result;
    }, session.userId);
  }

  /**
   * 单个导入（事务内执行，接受事务连接）
   * 注意：better-sqlite3 事务回调必须是同步函数
   * @private
   */
  _singleImportInTransaction(conn, userId, importType, plaintext, walletId, chains, ts) {
    const finalWalletId = walletId || crypto.randomUUID();
    let result;

    if (importType === 'private_key') {
      const address = privateKeyToAddress(plaintext);
      conn.query(
        `INSERT INTO wallets (user_id, wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, _hlc)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, finalWalletId, 'imported_key', null, chains[0].chainId, chains[0].coinType, address, plaintext, ts]
      );
      result = { walletId: finalWalletId, address };
    } else if (importType === 'mnemonic') {
      if (!validateMnemonic(plaintext)) {
        throw new Error('Invalid mnemonic');
      }
      // 查询已有的链（避免重复生成）
      const existingRows = conn.query(
        'SELECT chain_id FROM wallets WHERE user_id = ? AND wallet_id = ?',
        [userId, finalWalletId]
      );
      const existingChainIds = new Set(existingRows.map((r) => r.chain_id));

      const wallets = [];
      for (const chain of chains) {
        if (existingChainIds.has(chain.chainId)) continue;
        const derived = deriveWallet(plaintext, chain.coinType);
        conn.query(
          `INSERT INTO wallets (user_id, wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, derivation_path, _hlc)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [userId, finalWalletId, 'imported_mnemonic', plaintext, chain.chainId, chain.coinType, derived.address, derived.privateKey, derived.derivationPath, ts]
        );
        wallets.push({
          chainId: chain.chainId,
          coinType: chain.coinType,
          address: derived.address,
          privateKey: derived.privateKey,
          derivationPath: derived.derivationPath,
        });
      }
      result = { walletId: finalWalletId, wallets };
    }

    console.log(`[KeyImporter] _singleImportInTransaction: success, importType=${importType}`);
    return result;
  }

  /**
   * 批量导入：解密后得到 JSON 数组，逐个导入（支持多 userId）
   *
   * 输入格式（解密后的 JSON 数组）：
   * [
   *   { userId?: 'user-A', type: 'private_key', data: '0xabc...', walletId?: 'my-wallet', chains: [{chainId: 1, coinType: 60}] },
   *   { userId?: 'user-B', type: 'mnemonic', data: 'word1 word2 ...', chains: [{chainId: 1, coinType: 60}, {chainId: 56, coinType: 60}] },
   * ]
   *
   * userId 规则：
   * - 每个 item 可单独指定 userId
   * - 未指定 userId 的使用 defaultUserId（会话级别的 userId）
   *
   * walletId 规则（按 userId 分组）：
   * - 指定了 walletId 的用指定的
   * - 同一 userId 下未指定 walletId 的共用一个随机生成的 walletId
   * - 不同 userId 各自独立生成 sharedWalletId
   *
   * @param {string} defaultUserId - 会话级别的默认 userId
   * @param {string} jsonText - 解密后的 JSON 字符串
   * @returns {Promise<{ results: Array, sharedWalletIds: Object<string, string> }>}
   * @private
   */
  _batchImportInTransaction(conn, defaultUserId, jsonText, ts) { // ts = hlc.tick() from caller
    let items;
    try {
      items = JSON.parse(jsonText);
    } catch (err) {
      throw new Error('Invalid batch import data: not valid JSON');
    }

    if (!Array.isArray(items) || items.length === 0) {
      throw new Error('Batch import requires a non-empty array of wallet items');
    }

    // 预校验所有 item
    for (const item of items) {
      if (!item.type || !item.data) {
        throw new Error('Each wallet item must have type and data');
      }
      if (!item.chains || item.chains.length === 0) {
        throw new Error('Each wallet item must have a non-empty chains array');
      }
      if (!item.userId && !defaultUserId) {
        throw new Error('Each wallet item must have userId (or session must have a default userId)');
      }
    }

    const sharedWalletIdMap = {}; // userId -> sharedWalletId
    const results = [];

    for (const item of items) {
      const itemUserId = item.userId || defaultUserId;

      // 确定 walletId：指定的 > 按 userId 分组的 sharedWalletId
      let itemWalletId = item.walletId;
      if (!itemWalletId) {
        if (!sharedWalletIdMap[itemUserId]) {
          sharedWalletIdMap[itemUserId] = crypto.randomUUID();
        }
        itemWalletId = sharedWalletIdMap[itemUserId];
      }

      if (item.type === 'private_key') {
        const address = privateKeyToAddress(item.data);
        conn.query(
          `INSERT INTO wallets (user_id, wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, _hlc)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [itemUserId, itemWalletId, 'imported_key', null, item.chains[0].chainId, item.chains[0].coinType, address, item.data, ts]
        );
        results.push({ walletId: itemWalletId, address });
      } else if (item.type === 'mnemonic') {
        if (!validateMnemonic(item.data)) {
          throw new Error('Invalid mnemonic in batch item');
        }
        const wallets = [];
        for (const chain of item.chains) {
          const derived = deriveWallet(item.data, chain.coinType);
          conn.query(
            `INSERT INTO wallets (user_id, wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, derivation_path, _hlc)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [itemUserId, itemWalletId, 'imported_mnemonic', item.data, chain.chainId, chain.coinType, derived.address, derived.privateKey, derived.derivationPath, ts]
          );
          wallets.push({
            chainId: chain.chainId,
            coinType: chain.coinType,
            address: derived.address,
            privateKey: derived.privateKey,
            derivationPath: derived.derivationPath,
          });
        }
        results.push({ walletId: itemWalletId, wallets });
      } else {
        throw new Error(`Unknown import type: ${item.type}`);
      }

      console.log(`[KeyImporter] _batchImportInTransaction: imported ${item.type}, userId=${itemUserId}, walletId=${itemWalletId}`);
    }

    console.log(`[KeyImporter] _batchImportInTransaction: success, count=${results.length}, sharedWalletIds=${JSON.stringify(sharedWalletIdMap)}`);
    return { results, sharedWalletIds: sharedWalletIdMap };
  }
}
