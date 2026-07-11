/**
 * 私钥导出模块（两步导出流程）
 *
 * 支持两种密钥交换方式，流程相似：
 *
 * ECDH（默认）：
 *   第一步 initiateExport：客户端传 peerPublicKey → SGX 生成 ECDH 密钥对，用共享密钥加密钱包数据 →
 *     返回 enclavePublicKey + encryptedData + sessionId（客户端用自己的私钥+SGX公钥算出同样的共享密钥解密）
 *   第二步 confirmExport：客户端确认收到数据 → SGX 删除钱包+会话
 *
 * RSA：
 *   第一步 initiateExport：客户端传 RSA 公钥 → SGX 生成 AES 密钥，加密钱包数据，用 RSA 公钥加密 AES 密钥 →
 *     返回 encryptedAESKey + encryptedData + sessionId
 *   第二步 confirmExport：客户端确认收到数据 → SGX 删除钱包+会话
 *
 * 两种模式的 complete 都只是通知 SGX 删除已导出的钱包数据，不返回任何加密数据。
 *
 * TTL 到期：仅自动删除过期会话记录（由 cleanExpiredExportSessions 执行），不删除钱包。
 * 钱包删除只在 confirmExport（客户端主动确认已收到加密数据）时执行，避免因网络中断导致私钥/助记词丢失。
 * TTL 值从合约 runtimeParams 读取，默认 24 小时（86400 秒）
 *
 * 批量导出：
 *   exportInfo 是一个数组，每个元素为 { walletId, addresses }
 *   - addresses 为空数组时，导出该 walletId 下的所有私钥
 *   - addresses 有值时，每个元素为 { address, chainId }，精确匹配指定链上的指定地址
 *     （同一地址在不同链上的私钥可以分别导出）
 *
 * 导出数据结构（与 wallet/get 接口返回结构一致）：
 *   {
 *     userId,
 *     wallets: [
 *       {
 *         walletId,
 *         wallets: [
 *           {
 *             walletType,
 *             mnemonic,   // 助记词（纯私钥钱包为 null）
 *             keys: [     // 该助记词下的私钥列表（或纯私钥钱包的单个私钥）
 *               { chainId, coinType, address, privateKey, derivationPath }
 *             ]
 *           }
 *         ]
 *       }
 *     ]
 *   }
 */

import crypto from 'crypto';
import { generateECDHKeyPair, deriveSharedSecret, encrypt } from './ecdh.js';
import { generateAESKey, encryptAESKeyWithRSA, validateAndDetectRSAPublicKey } from './rsa.js';
import { createConnProxy } from '../../sync/sync-adapter.js';
import { getMonotonicSqliteNow, getMonotonicSqliteAfter } from '../../utils/monotonic-clock.js';

const DEFAULT_EXPORT_TTL_SECONDS = 86400; // 24 小时

export class KeyExporter {
  /**
   * @param {import('../wallet-management/wallet-manager.js').WalletManager} walletManager
   * @param {import('../../database/connection-manager.js').default} connectionManager
   * @param {Object} [options]
   * @param {number} [options.exportTtlSeconds] - 导出会话 TTL（秒），默认从合约读取，fallback 86400
   * @param {import('@xnetx/raft-hlc-sync').SyncEngine} [options.engine]
   */
  constructor(walletManager, connectionManager, options = {}) {
    if (!walletManager) {
      throw new Error('KeyExporter requires a WalletManager instance');
    }
    if (!connectionManager) {
      throw new Error('KeyExporter requires a ConnectionManager instance');
    }
    this._walletManager = walletManager;
    this._db = connectionManager;
    this._engine = options.engine;
    this._exportTtlSeconds = options.exportTtlSeconds || DEFAULT_EXPORT_TTL_SECONDS;
  }

  /**
   * 第一步：发起批量导出（加密数据并返回）
   *
   * ECDH 模式：客户端传 peerPublicKey → SGX 生成 ECDH 密钥对 → 算出共享密钥 → 加密钱包数据
   *   返回 enclavePublicKey + encryptedWalletData + sessionId
   * RSA 模式：客户端传 rsaPublicKey → SGX 生成 AES 密钥 → 加密钱包数据 → RSA 加密 AES 密钥
   *   返回 encryptedAESKey + encryptedWalletData + sessionId
   *
   * 导出粒度：
   *   - exportInfo 数组中每个元素指定一个 walletId 及其要导出的 addresses
   *   - addresses 为空数组时，导出该 walletId 下的所有私钥
   *   - addresses 有值时，每个元素为 { address, chainId }，精确匹配指定链上的指定地址
   *
   * @param {string} userId - 用户 ID
   * @param {Array<{walletId: string, addresses: Array<{address: string, chainId: number}|string>}>} exportInfo - 导出信息数组
   * @param {Object} keyExchangeParams - 密钥交换参数
   * @param {string} [keyExchangeParams.peerPublicKey] - 客户端 ECDH 公钥（hex），ECDH 模式必填
   * @param {string} [keyExchangeParams.rsaPublicKey] - 客户端 RSA 公钥（PEM 或 Base64 DER），RSA 模式必填
   * @returns {Promise<Object>} ECDH: { sessionId, enclavePublicKey, encryptedWalletData, keyType } | RSA: { sessionId, encryptedAESKey, encryptedWalletData, keyType }
   */
  async initiateExport(userId, exportInfo, keyExchangeParams) {
    console.log(`[KeyExporter] initiateExport: userId=${userId}, exportInfo=${JSON.stringify(exportInfo)}`);

    if (!userId) {
      throw new Error('userId is required');
    }
    if (!Array.isArray(exportInfo) || exportInfo.length === 0) {
      throw new Error('exportInfo must be a non-empty array');
    }
    for (const item of exportInfo) {
      if (!item.walletId) {
        throw new Error('Each exportInfo item must have a walletId');
      }
      if (!Array.isArray(item.addresses)) {
        throw new Error('Each exportInfo item must have an addresses array (can be empty to export all)');
      }
      // 验证 addresses 元素格式：可以是字符串（纯地址）或 {address, chainId} 对象
      for (const addr of item.addresses) {
        if (typeof addr === 'string') {
          // 兼容旧格式：纯地址字符串
        } else if (addr && typeof addr === 'object' && addr.address) {
          // 新格式：{address, chainId}
        } else {
          throw new Error('Each address in addresses must be a string or {address, chainId} object');
        }
      }
    }

    if (!keyExchangeParams) {
      throw new Error('keyExchangeParams is required');
    }

    const isRSAMode = !!keyExchangeParams.rsaPublicKey;
    if (!isRSAMode && !keyExchangeParams.peerPublicKey) {
      throw new Error('Either peerPublicKey (ECDH) or rsaPublicKey (RSA) is required');
    }

    // 预先做纯内存校验（不涉及 DB）
    let rsaResult, keyType;
    if (isRSAMode) {
      rsaResult = validateAndDetectRSAPublicKey(keyExchangeParams.rsaPublicKey);
      if (!rsaResult.valid) {
        throw new Error(`Invalid RSA public key: ${rsaResult.error}`);
      }
      keyType = rsaResult.keyType;
    } else {
      keyType = 'ecdh';
    }

    const sessionId = crypto.randomUUID();
    const ttl = this._exportTtlSeconds;

    // 所有 DB 操作在 engine.write() 内完成：读钱包 → 写 session（原子性 + 2PC）
    return this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      const ts = this._engine.hlc.tick();

      // 收集所有要导出的钱包容器数据（按 walletId 分组）
      const allExportedContainers = [];
      let totalKeyCount = 0;

      for (const item of exportInfo) {
        const { walletId, addresses } = item;

        // 查询该 walletId 下的所有行
        const walletRows = conn.query(
          'SELECT user_id, wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, derivation_path FROM wallets WHERE user_id = ? AND wallet_id = ?',
          [userId, walletId]
        );
        if (walletRows.length === 0) {
          console.log(`[KeyExporter] initiateExport: FAILED - wallet container not found: walletId=${walletId}`);
          throw new Error(`Wallet not found: userId=${userId}, walletId=${walletId}`);
        }

        // 根据 addresses 过滤要导出的行
        let filteredRows;
        if (!addresses || addresses.length === 0) {
          // 导出该 walletId 下的所有行
          filteredRows = walletRows;
        } else {
          // 精确匹配：支持 {address, chainId} 或纯地址字符串
          filteredRows = walletRows.filter((row) => {
            return addresses.some((addr) => {
              if (typeof addr === 'string') {
                // 纯地址字符串：只匹配地址，不限链
                return row.address === addr;
              } else {
                // {address, chainId} 对象：精确匹配地址+链
                const chainIdMatch = addr.chainId !== undefined
                  ? Number(row.chain_id) === Number(addr.chainId)
                  : true;
                return row.address === addr.address && chainIdMatch;
              }
            });
          });
          if (filteredRows.length === 0) {
            console.log(`[KeyExporter] initiateExport: FAILED - none of the specified addresses found in walletId=${walletId}`);
            throw new Error(`None of the specified addresses found in wallet: walletId=${walletId}, addresses=${JSON.stringify(addresses)}`);
          }
        }

        // 将过滤后的行重组为容器结构（按助记词分组逻辑钱包）
        const container = this._buildContainerFromRows(walletId, filteredRows);
        allExportedContainers.push(this._buildContainerExportData(userId, container));
        totalKeyCount += filteredRows.length;
      }

      // 构建批量导出数据 JSON（与 wallet/get 接口返回结构一致）
      const walletDataJson = JSON.stringify({ userId, wallets: allExportedContainers });

      // 序列化 exportInfo 存入 session（用于 confirmExport 时定位要删除的数据）
      const exportInfoJson = JSON.stringify(exportInfo);

      if (isRSAMode) {
        // RSA 加密
        const aesKey = generateAESKey();
        const encryptedWalletData = encrypt(aesKey, walletDataJson);
        const encryptedAESKey = encryptAESKeyWithRSA(keyExchangeParams.rsaPublicKey, aesKey);

        // 写入导出会话（同一事务内）
        conn.query(
          `INSERT INTO export_sessions (session_id, user_id, export_info, key_type, created_at, expires_at, _hlc)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [sessionId, userId, exportInfoJson, keyType, getMonotonicSqliteNow(), getMonotonicSqliteAfter(ttl), ts]
        );

        console.log(`[KeyExporter] initiateExport: success (RSA), sessionId=${sessionId}, keyType=${keyType}, ttl=${ttl}s, totalKeyCount=${totalKeyCount}`);
        return { sessionId, keyType, encryptedWalletData, encryptedAESKey };
      } else {
        // ECDH 加密
        const keyPair = generateECDHKeyPair();
        const sharedKey = deriveSharedSecret(keyPair.privateKey, keyExchangeParams.peerPublicKey);
        const encryptedWalletData = encrypt(sharedKey, walletDataJson);

        // 写入导出会话（同一事务内）
        conn.query(
          `INSERT INTO export_sessions (session_id, user_id, export_info, key_type, created_at, expires_at, _hlc)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [sessionId, userId, exportInfoJson, keyType, getMonotonicSqliteNow(), getMonotonicSqliteAfter(ttl), ts]
        );

        console.log(`[KeyExporter] initiateExport: success (ECDH), sessionId=${sessionId}, keyType=${keyType}, ttl=${ttl}s, totalKeyCount=${totalKeyCount}`);
        return { sessionId, keyType, enclavePublicKey: keyPair.publicKey, encryptedWalletData };
      }
    }, userId);
  }

  /**
   * 第二步：确认导出（删除钱包）
   *
   * 两种模式都一样：客户端确认已收到并解密数据后，通知 SGX 删除导出过的钱包数据。
   * 不返回任何加密数据。
   *
   * 根据 session 中存储的 exportInfo 批量删除对应的钱包数据：
   * - addresses 为空时，删除该 walletId 下所有行
   * - addresses 有值时（{address, chainId} 或纯地址字符串），精确删除匹配的行
   *   注意：对于助记词钱包，删除指定行后，同一助记词下的其他链地址仍然保留
   *   （与导出粒度一致：导出了哪些行，就删除哪些行）
   *
   * @param {string} sessionId - 导出会话 ID
   * @returns {Promise<{ deletedCount: number, walletIds: string[] }>}
   */
  async confirmExport(sessionId) {
    console.log(`[KeyExporter] confirmExport: sessionId=${sessionId}`);

    if (!sessionId) {
      throw new Error('sessionId is required');
    }

    // 1. 查找有效的导出会话（未过期）
    const rows = await this._db.readQuery(
      `SELECT session_id, user_id, export_info FROM export_sessions WHERE session_id = ? AND expires_at > ?`,
      [sessionId, getMonotonicSqliteNow()]
    );

    if (rows.length === 0) {
      console.log(`[KeyExporter] confirmExport: FAILED - session not found or expired`);
      throw new Error('Export session not found or expired');
    }

    const session = rows[0];
    let exportInfo;
    try {
      exportInfo = JSON.parse(session.export_info);
    } catch {
      throw new Error('Invalid export_info in session: not valid JSON');
    }

    console.log(`[KeyExporter] confirmExport: session found, userId=${session.user_id}, exportInfo=${session.export_info}`);

    // 2. 事务内：批量删除钱包 + 删除会话
    return this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      let totalDeletedCount = 0;
      const walletIds = [];

      for (const item of exportInfo) {
        const { walletId, addresses } = item;

        if (!addresses || addresses.length === 0) {
          // 导出了该 walletId 下的所有行，全部删除
          const result = conn.query(
            'DELETE FROM wallets WHERE user_id = ? AND wallet_id = ?',
            [session.user_id, walletId]
          );
          totalDeletedCount += result.changes;
        } else {
          // 精确删除匹配的行（与导出时的过滤逻辑一致）
          for (const addr of addresses) {
            let result;
            if (typeof addr === 'string') {
              // 纯地址字符串：删除该 walletId 下所有匹配该地址的行（不限链）
              result = conn.query(
                'DELETE FROM wallets WHERE user_id = ? AND wallet_id = ? AND address = ?',
                [session.user_id, walletId, addr]
              );
            } else {
              // {address, chainId} 对象：精确删除指定链上的指定地址
              if (addr.chainId !== undefined) {
                result = conn.query(
                  'DELETE FROM wallets WHERE user_id = ? AND wallet_id = ? AND address = ? AND chain_id = ?',
                  [session.user_id, walletId, addr.address, Number(addr.chainId)]
                );
              } else {
                result = conn.query(
                  'DELETE FROM wallets WHERE user_id = ? AND wallet_id = ? AND address = ?',
                  [session.user_id, walletId, addr.address]
                );
              }
            }
            totalDeletedCount += result.changes;
          }
        }

        walletIds.push(walletId);
      }

      conn.query('DELETE FROM export_sessions WHERE session_id = ?', [sessionId]);

      console.log(`[KeyExporter] confirmExport: success, totalDeletedCount=${totalDeletedCount}, walletIds=${JSON.stringify(walletIds)}`);
      return { deletedCount: totalDeletedCount, walletIds };
    }, session.user_id);
  }

  /**
   * 从数据库行重组钱包容器结构（用于事务内查询）
   * 按助记词分组逻辑钱包，纯私钥钱包每行独立
   * @private
   */
  _buildContainerFromRows(walletId, rows) {
    const walletMap = new Map(); // mnemonic|'key:'+address+chainId -> { walletType, mnemonic, keys[] }
    for (const row of rows) {
      // 纯私钥钱包：每行独立（用 address+chainId 作为 key 避免碰撞）
      const key = row.mnemonic ? `mnemonic:${row.mnemonic}` : `key:${row.address}:${row.chain_id}`;
      if (!walletMap.has(key)) {
        walletMap.set(key, {
          walletType: row.wallet_type,
          mnemonic: row.mnemonic || null,
          keys: [],
        });
      }
      walletMap.get(key).keys.push({
        chainId: row.chain_id,
        coinType: row.coin_type,
        address: row.address,
        privateKey: row.private_key,
        derivationPath: row.derivation_path || null,
      });
    }
    return {
      walletId,
      wallets: Array.from(walletMap.values()),
    };
  }

  /**
   * 构建钱包容器导出数据（与 wallet/get 接口返回结构一致）
   * 结构：{ walletId, wallets: [{ walletType, mnemonic, keys: [...] }] }
   * @private
   */
  _buildContainerExportData(userId, container) {
    return {
      userId,
      walletId: container.walletId,
      wallets: container.wallets.map((w) => ({
        walletType: w.walletType,
        mnemonic: w.mnemonic || null,
        keys: w.keys.map((k) => ({
          chainId: k.chainId,
          coinType: k.coinType,
          address: k.address,
          privateKey: k.privateKey,
          derivationPath: k.derivationPath || null,
        })),
      })),
    };
  }

  /**
   * 查找导出会话（用于检查状态）
   * @param {string} sessionId
   * @returns {Promise<Object|null>}
   */
  async findExportSession(sessionId) {
    const rows = await this._db.readQuery(
      `SELECT session_id, user_id, export_info, key_type, created_at, expires_at FROM export_sessions WHERE session_id = ? AND expires_at > ?`,
      [sessionId, getMonotonicSqliteNow()]
    );
    if (rows.length === 0) return null;
    const row = rows[0];
    // 解析 export_info JSON，方便调用方使用
    try {
      row.exportInfo = JSON.parse(row.export_info);
    } catch {
      row.exportInfo = [];
    }
    return row;
  }
}
