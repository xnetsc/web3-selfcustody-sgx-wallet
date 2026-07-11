/**
 * 钱包管理器
 * 负责钱包的 CRUD 操作：创建原生钱包、导入私钥/助记词钱包、查询、删除
 *
 * 层级结构：userId → walletId(容器) → 多个钱包(native + imported_key + imported_mnemonic)
 * walletId 是钱包容器，在用户范围内唯一，可传入或随机生成
 * 一个 walletId 下可以有多个钱包（助记词生成的 + 导入的私钥及地址）
 * 所有钱包类型均允许删除和导出
 */

import { v4 as uuidv4 } from 'uuid';
import { generateMnemonic, validateMnemonic, deriveWallet, privateKeyToAddress } from './hd-wallet.js';
import { createConnProxy } from '../../sync/sync-adapter.js';
import { getMonotonicSqliteNow } from '../../utils/monotonic-clock.js';

export class WalletManager {
  /**
   * @param {import('../../database/connection-manager.js').default} connectionManager
   * @param {import('@xnetx/raft-hlc-sync').SyncEngine} engine
   */
  constructor(connectionManager, engine) {
    if (!connectionManager) {
      throw new Error('WalletManager requires a ConnectionManager instance');
    }
    this._db = connectionManager;
    this._engine = engine;
  }

  /**
   * 创建原生钱包（用户主动请求）
   * 生成助记词，按指定链列表派生多链地址
   *
   * @param {string} userId - 用户 ID
   * @param {string|null} walletId - 钱包 ID（可选，不传则随机生成）
   * @param {Array<{chainId: number, coinType: number}>} chains - 需要派生的链列表
   * @param {number} mnemonicStrength - 助记词强度，默认 128（12 词）
   * @returns {Promise<{ walletId: string, mnemonic: string, wallets: Array }>}
   */
  async createNativeWallet(userId, walletId, chains, mnemonicStrength = 128) {
    if (!userId) {
      throw new Error('userId is required');
    }
    if (!chains || chains.length === 0) {
      throw new Error('chains array is required and must not be empty');
    }

    const finalWalletId = walletId || uuidv4();
    const requestedChainIds = chains.map((c) => c.chainId);

    const mnemonic = generateMnemonic(mnemonicStrength);

    const wallets = [];
    for (const chain of chains) {
      const derived = deriveWallet(mnemonic, chain.coinType);
      wallets.push({
        chainId: chain.chainId,
        coinType: chain.coinType,
        address: derived.address,
        privateKey: derived.privateKey,
        derivationPath: derived.derivationPath,
      });
    }

    return this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      const ts = this._engine.hlc.tick();

      // 在事务内检查是否已存在同 walletId + 同 chainId 的 native 钱包（防止并发重复创建）
      const existingRows = conn.query(
        'SELECT chain_id FROM wallets WHERE user_id = ? AND wallet_id = ? AND wallet_type = ?',
        [userId, finalWalletId, 'native']
      );
      const existingChainIds = new Set(existingRows.map((r) => r.chain_id));
      for (const chainId of requestedChainIds) {
        if (existingChainIds.has(chainId)) {
          throw new Error(`Duplicate native wallet: walletId=${finalWalletId}, chainId=${chainId} already exists`);
        }
      }

      for (const w of wallets) {
        conn.query(
          `INSERT INTO wallets (user_id, wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, derivation_path, created_at, _hlc)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [userId, finalWalletId, 'native', mnemonic, w.chainId, w.coinType, w.address, w.privateKey, w.derivationPath, getMonotonicSqliteNow(), ts]
        );
      }

      return {
        walletId: finalWalletId,
        mnemonic,
        wallets,
      };
    }, userId);
  }

  /**
   * 导入纯私钥钱包
   *
   * @param {string} userId - 用户 ID
   * @param {string|null} walletId - 钱包 ID（可选）
   * @param {string} privateKey - 私钥（十六进制）
   * @param {number} chainId - 链 ID
   * @param {number} coinType - BIP-44 coin type
   * @returns {Promise<{ walletId: string, address: string }>}
   */
  async importPrivateKey(userId, walletId, privateKey, chainId, coinType) {
    if (!userId) {
      throw new Error('userId is required');
    }
    if (!privateKey) {
      throw new Error('privateKey is required');
    }

    let address;
    try {
      address = privateKeyToAddress(privateKey);
    } catch (err) {
      throw new Error('Invalid private key: ' + err.message);
    }

    const finalWalletId = walletId || uuidv4();

    await this._engine.write(async (db) => {
      const ts = this._engine.hlc.tick();
      db.run(
        `INSERT INTO wallets (user_id, wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, created_at, _hlc)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, finalWalletId, 'imported_key', null, chainId, coinType, address, privateKey, getMonotonicSqliteNow(), ts]
      );
    }, userId);

    return { walletId: finalWalletId, address };
  }

  /**
   * 导入助记词钱包
   * 按指定链列表派生多链地址，已有链不重复生成
   *
   * @param {string} userId - 用户 ID
   * @param {string|null} walletId - 钱包 ID（可选）
   * @param {string} mnemonic - 助记词
   * @param {Array<{chainId: number, coinType: number}>} chains - 需要派生的链列表
   * @returns {Promise<{ walletId: string, wallets: Array }>}
   */
  async importMnemonic(userId, walletId, mnemonic, chains) {
    if (!userId) {
      throw new Error('userId is required');
    }
    if (!mnemonic || !validateMnemonic(mnemonic)) {
      throw new Error('Invalid mnemonic');
    }
    if (!chains || chains.length === 0) {
      throw new Error('chains array is required and must not be empty');
    }

    const finalWalletId = walletId || uuidv4();

    return this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      const ts = this._engine.hlc.tick();

      // 查询已有的链（避免重复生成）
      const existingRows = conn.query(
        'SELECT chain_id FROM wallets WHERE user_id = ? AND wallet_id = ?',
        [userId, finalWalletId]
      );
      const existingChainIds = new Set(existingRows.map((r) => r.chain_id));

      const wallets = [];
      for (const chain of chains) {
        if (existingChainIds.has(chain.chainId)) {
          continue; // 已有链不重复生成
        }

        const derived = deriveWallet(mnemonic, chain.coinType);
        conn.query(
          `INSERT INTO wallets (user_id, wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, derivation_path, created_at, _hlc)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [userId, finalWalletId, 'imported_mnemonic', mnemonic, chain.chainId, chain.coinType, derived.address, derived.privateKey, derived.derivationPath, getMonotonicSqliteNow(), ts]
        );

        wallets.push({
          chainId: chain.chainId,
          coinType: chain.coinType,
          address: derived.address,
          privateKey: derived.privateKey,
          derivationPath: derived.derivationPath,
        });
      }

      return { walletId: finalWalletId, wallets };
    }, userId);
  }

  /**
   * 查询用户所有钱包（按 walletId 分组，内部按逻辑钱包再分组）
   *
   * walletId 是容器，内含多个逻辑钱包：
   * - 助记词钱包（native/imported_mnemonic）：同一助记词的所有链地址 = 一个钱包
   * - 纯私钥钱包（imported_key）：每行 = 一个独立钱包
   *
   * @param {string} userId - 用户 ID
   * @returns {Promise<Array<{ walletId: string, wallets: Array<{ walletType: string, mnemonic: string|null, addresses: Array<{ chainId: number, coinType: number, address: string, privateKey: string, derivationPath: string|null, createdAt: string }> }> }>>}
   */
  async listWallets(userId) {
    if (!userId) {
      throw new Error('userId is required');
    }

    const rows = await this._db.readQuery(
      `SELECT wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, derivation_path, created_at
       FROM wallets WHERE user_id = ? ORDER BY wallet_id, wallet_type, chain_id`,
      [userId]
    );

    return this._groupRowsIntoContainers(rows);
  }

  /**
   * 查询指定钱包容器
   *
   * walletId 是容器，内含多个逻辑钱包：
   * - 助记词钱包：同一助记词的所有链地址 = 一个钱包
   * - 纯私钥钱包：每行 = 一个独立钱包
   *
   * @param {string} userId - 用户 ID
   * @param {string} walletId - 钱包容器 ID
   * @returns {Promise<{ walletId: string, wallets: Array<{ walletType: string, mnemonic: string|null, addresses: Array<{ chainId: number, coinType: number, address: string, privateKey: string, derivationPath: string|null, createdAt: string }> }> } | null>}
   */
  async getWallet(userId, walletId) {
    if (!userId || !walletId) {
      throw new Error('Both userId and walletId are required');
    }

    const rows = await this._db.readQuery(
      `SELECT wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, derivation_path, created_at
       FROM wallets WHERE user_id = ? AND wallet_id = ? ORDER BY wallet_type, chain_id`,
      [userId, walletId]
    );

    if (rows.length === 0) {
      return null;
    }

    const containers = this._groupRowsIntoContainers(rows);
    return containers[0]; // 只有一个 walletId，取第一个
  }

  /**
   * 删除整个钱包容器（walletId 下的所有钱包和地址）
   * 用于 passkey 全部删除时的级联清理
   *
   * @param {string} userId - 用户 ID
   * @param {string} walletId - 钱包容器 ID
   * @returns {Promise<{ deletedCount: number }>}
   */
  async deleteWallet(userId, walletId) {
    if (!userId || !walletId) {
      throw new Error('Both userId and walletId are required');
    }

    return this._engine.write(async (db) => {
      const result = db.run(
        'DELETE FROM wallets WHERE user_id = ? AND wallet_id = ?',
        [userId, walletId]
      );

      if (result.changes === 0) {
        throw new Error(`Wallet not found: userId=${userId}, walletId=${walletId}`);
      }

      return { deletedCount: result.changes };
    }, userId);
  }

  /**
   * 删除容器内的单个逻辑钱包
   * - 助记词钱包：通过 address 定位到 mnemonic，删除该 mnemonic 下的所有链地址
   * - 纯私钥钱包：通过 address 定位，删除该单行
   *
   * @param {string} userId - 用户 ID
   * @param {string} walletId - 钱包容器 ID
   * @param {string} address - 该逻辑钱包中的任一地址（用于定位）
   * @returns {Promise<{ deletedCount: number }>}
   */
  async deleteWalletEntry(userId, walletId, address) {
    if (!userId || !walletId || !address) {
      throw new Error('userId, walletId and address are required');
    }

    return this._engine.write(async (db) => {
      const conn = createConnProxy(db);

      // 1. 查找该地址对应的行，获取 wallet_type 和 mnemonic
      const rows = conn.query(
        'SELECT wallet_type, mnemonic FROM wallets WHERE user_id = ? AND wallet_id = ? AND address = ?',
        [userId, walletId, address]
      );

      if (rows.length === 0) {
        throw new Error(`Wallet entry not found: walletId=${walletId}, address=${address}`);
      }

      const { wallet_type: walletType, mnemonic } = rows[0];

      // 2. 根据类型决定删除范围
      let deletedCount;
      if (walletType === 'imported_key') {
        // 纯私钥钱包：删单行
        const result = conn.query(
          'DELETE FROM wallets WHERE user_id = ? AND wallet_id = ? AND address = ?',
          [userId, walletId, address]
        );
        deletedCount = result.changes;
      } else {
        // 助记词钱包（native / imported_mnemonic）：删同一助记词下的所有行
        const result = conn.query(
          'DELETE FROM wallets WHERE user_id = ? AND wallet_id = ? AND mnemonic = ?',
          [userId, walletId, mnemonic]
        );
        deletedCount = result.changes;
      }

      return { deletedCount };
    }, userId);
  }

  /**
   * 按地址查询钱包信息
   *
   * @param {string} userId - 用户 ID
   * @param {number} chainId - 链 ID
   * @param {string} address - 钱包地址
   * @returns {Promise<{ walletId: string, walletType: string, privateKey: string, derivationPath: string|null } | null>}
   */
  async getWalletByAddress(userId, chainId, address) {
    if (!userId || !address) {
      throw new Error('userId and address are required');
    }

    const rows = await this._db.readQuery(
      'SELECT wallet_id, wallet_type, private_key, derivation_path FROM wallets WHERE user_id = ? AND chain_id = ? AND address = ?',
      [userId, chainId, address]
    );

    if (rows.length === 0) {
      return null;
    }

    return {
      walletId: rows[0].wallet_id,
      walletType: rows[0].wallet_type,
      privateKey: rows[0].private_key,
      derivationPath: rows[0].derivation_path,
    };
  }

  /**
   * 查询所有用户的授权ID列表（用于管理员统计）
   *
   * 主查用户表（accounts），以用户表分页，
   * 每个用户附加其所有授权ID列表（从authorization_states表查询）
   * 不包含任何敏感信息
   *
   * @param {number} page - 页码（从1开始）
   * @param {number} pageSize - 每页用户数
   * @returns {Promise<{ totalUsers: number, page: number, pageSize: number, totalPages: number, users: Array<{ userId: string, authorizationIds: Array<string> }> }>}
   */
  async listAllWalletsForPlatform(page = 1, pageSize = 50) {
    page = Math.max(1, page);
    pageSize = Math.min(100, Math.max(1, pageSize));

    // 获取总用户数（从accounts表）
    const countResult = await this._db.readQuery(
      `SELECT COUNT(*) as total FROM accounts`,
      []
    );
    const totalUsers = countResult[0].total;
    const totalPages = Math.ceil(totalUsers / pageSize);

    // 分页获取用户列表（从accounts表）
    const offset = (page - 1) * pageSize;
    const userRows = await this._db.readQuery(
      `SELECT user_id FROM accounts ORDER BY user_id LIMIT ? OFFSET ?`,
      [pageSize, offset]
    );

    // 为每个用户查询其授权ID列表
    const users = [];
    for (const userRow of userRows) {
      const userId = userRow.user_id;

      // 查询该用户的所有授权ID
      const authRows = await this._db.readQuery(
        `SELECT authorization_id FROM authorization_states WHERE user_id = ? ORDER BY authorization_id`,
        [userId]
      );

      users.push({
        userId,
        authorizationIds: authRows.map(r => r.authorization_id),
      });
    }

    return {
      totalUsers,
      page,
      pageSize,
      totalPages,
      users,
    };
  }

  /**
   * 将同一个 walletId 下的行分组为逻辑钱包（平台查询用，排除敏感字段）
   * @param {Array} rows
   * @returns {Array<{ walletType: string, addresses: Array }>}
   * @private
   */
  _groupRowsIntoWalletsForPlatform(rows) {
    const wallets = [];
    const mnemonicGroups = new Map();

    for (const row of rows) {
      const addressEntry = {
        chainId: row.chain_id,
        coinType: row.coin_type,
        address: row.address,
        derivationPath: row.derivation_path,
        createdAt: row.created_at,
      };

      if (row.wallet_type === 'imported_key') {
        wallets.push({
          walletType: 'imported_key',
          addresses: [addressEntry],
        });
      } else {
        const key = `${row.wallet_type}::${row.wallet_id}`;
        if (!mnemonicGroups.has(key)) {
          mnemonicGroups.set(key, {
            walletType: row.wallet_type,
            addresses: [],
          });
        }
        mnemonicGroups.get(key).addresses.push(addressEntry);
      }
    }

    return [...mnemonicGroups.values(), ...wallets];
  }

  // ===== 内部方法 =====

  /**
   * 将 DB 行分组为 walletId 容器 → 逻辑钱包 → 地址列表
   *
   * 分组规则：
   * - 第一层：按 wallet_id 分组（容器）
   * - 第二层：按逻辑钱包分组
   *   - native/imported_mnemonic：同一 mnemonic 的行归为一个钱包
   *   - imported_key：每行是一个独立钱包
   *
   * @param {Array} rows - DB 查询结果行
   * @returns {Array<{ walletId: string, wallets: Array }>}
   * @private
   */
  _groupRowsIntoContainers(rows) {
    // 第一层：按 walletId 分组
    const containerMap = new Map();
    for (const row of rows) {
      const wid = row.wallet_id;
      if (!containerMap.has(wid)) {
        containerMap.set(wid, []);
      }
      containerMap.get(wid).push(row);
    }

    const result = [];
    for (const [walletId, containerRows] of containerMap) {
      const wallets = this._groupRowsIntoWallets(containerRows);
      result.push({ walletId, wallets });
    }
    return result;
  }

  /**
   * 将同一个 walletId 下的行分组为逻辑钱包
   * @param {Array} rows
   * @returns {Array<{ walletType: string, mnemonic: string|null, addresses: Array }>}
   * @private
   */
  _groupRowsIntoWallets(rows) {
    const wallets = [];
    // 助记词钱包按 mnemonic 聚合
    const mnemonicGroups = new Map();

    for (const row of rows) {
      const addressEntry = {
        chainId: row.chain_id,
        coinType: row.coin_type,
        address: row.address,
        privateKey: row.private_key,
        derivationPath: row.derivation_path,
        createdAt: row.created_at,
      };

      if (row.wallet_type === 'imported_key') {
        // 纯私钥：每行一个独立钱包
        wallets.push({
          walletType: 'imported_key',
          mnemonic: null,
          addresses: [addressEntry],
        });
      } else {
        // native / imported_mnemonic：同一 mnemonic 归为一个钱包
        const key = `${row.wallet_type}::${row.mnemonic}`;
        if (!mnemonicGroups.has(key)) {
          mnemonicGroups.set(key, {
            walletType: row.wallet_type,
            mnemonic: row.mnemonic,
            addresses: [],
          });
        }
        mnemonicGroups.get(key).addresses.push(addressEntry);
      }
    }

    // 助记词钱包排在前面，私钥钱包排在后面
    return [...mnemonicGroups.values(), ...wallets];
  }
}
