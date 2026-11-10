/**
 * 授权状态管理器
 * 管理授权累计状态：已用金额/次数（总计+分 token），状态机转换
 *
 * 状态机：active → revoked / expired / exceeded
 * 大数处理：使用 JavaScript 原生 BigInt（Wei 精度）
 */

import { createConnProxy, shouldExecuteInternalWrite, withLocalFallback } from '../../sync/sync-adapter.js';
import { getMonotonicDate, getMonotonicSqliteNow } from '../../utils/monotonic-clock.js';

/**
 * 将时间值规范化为 ISO 字符串（便于统一比较与存储），无法解析时返回 null
 * @param {string|null|undefined} value
 * @returns {string|null}
 */
function _normalizeIsoTime(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * 将 authorization_revocations 表行转换为对外对象
 * @param {Object} row
 * @returns {Object|null}
 */
function _revocationFromRow(row) {
  if (!row) return null;
  return {
    userId: row.user_id,
    authorizationId: row.authorization_id,
    grantee: row.grantee || null,
    source: row.source,
    revokedAt: row.revoked_at,
    authorizationExpiresAt: row.authorization_expires_at || null,
    authorizationHash: row.authorization_hash || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * 构造 tokenLimits 的 key
 *
 * tokenAddress 格式约定：
 *   - 原生币："{chainId}_native"（如 "1_native"）
 *   - 未知 token："{chainId}_unknown"（如 "1_unknown"）
 *   - ERC20：以太坊地址（如 "0xA0b8..."，不含 chainId 前缀）
 *
 * tokenLimits key 格式："{chainId}_{tokenAddress_without_prefix}"
 *   - 原生币：tokenAddress="1_native" → key="1_native"（tokenAddress 本身已含 chainId）
 *   - ERC20：tokenAddress="0xA0b8..." → key="1_0xA0b8..."（需要拼接 chainId）
 *
 * @param {number} chainId
 * @param {string} tokenAddress
 * @returns {string}
 */
function _buildTokenKey(chainId, tokenAddress) {
  // 如果 tokenAddress 已经以 "{chainId}_" 开头（原生币/未知 token），直接返回
  if (tokenAddress.startsWith(`${chainId}_`)) {
    return tokenAddress;
  }
  // ERC20 地址：拼接 chainId 前缀
  return `${chainId}_${tokenAddress}`;
}

export class StateManager {
  /**
   * @param {import('../../database/connection-manager.js').default} connectionManager
   * @param {import('@xnetx/raft-hlc-sync').SyncEngine} engine
   */
  constructor(connectionManager, engine) {
    if (!connectionManager) {
      throw new Error('StateManager requires a ConnectionManager instance');
    }
    this._db = connectionManager;
    this._engine = engine;
  }

  /**
   * 获取或创建授权状态（首次签名请求时自动创建）
   * @param {string} authorizationId - 授权 ID
   * @param {string} userId - 用户 ID
   * @param {string} [grantee] - 被授权平台地址（首次创建时必须提供）
   * @returns {Promise<Object>} 授权状态记录
   */
  async getOrCreateState(authorizationId, userId, grantee) {
    if (!authorizationId || !userId) {
      throw new Error('authorizationId and userId are required');
    }

    console.log(`[StateManager] getOrCreateState: userId=${userId}, authorizationId=${authorizationId}`);

    // 使用 engine.write() 解决竞态条件：检查-创建在同一事务中执行（+ 2PC）
    return this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      const ts = this._engine.hlc.tick();

      // 先尝试获取（组合键查询）
      const rows = conn.query(
        'SELECT authorization_id, user_id, status, total_amount_used, total_count_used, created_at, updated_at FROM authorization_states WHERE user_id = ? AND authorization_id = ?',
        [userId, authorizationId]
      );

      if (rows.length > 0) {
        console.log(`[StateManager] getOrCreateState: existing state found, status=${rows[0].status}`);
        return rows[0];
      }

      // 不存在则创建
      console.log(`[StateManager] getOrCreateState: creating new state, grantee=${grantee || 'unknown'}`);
      conn.query(
        `INSERT INTO authorization_states (authorization_id, user_id, grantee, status, total_amount_used, total_count_used, created_at, updated_at, _hlc)
         VALUES (?, ?, ?, 'active', '0', 0, ?, ?, ?)`,
        [authorizationId, userId, grantee || '*', getMonotonicSqliteNow(), getMonotonicSqliteNow(), ts]
      );

      // 返回刚创建的记录
      const newRows = conn.query(
        'SELECT authorization_id, user_id, status, total_amount_used, total_count_used, created_at, updated_at FROM authorization_states WHERE user_id = ? AND authorization_id = ?',
        [userId, authorizationId]
      );
      return newRows[0];
    }, userId);
  }

  /**
   * 获取授权状态（按 authorizationId 查询，兼容旧调用方）
   * 注意：authorizationId 不保证全局唯一，多条记录时返回第一条
   * @param {string} authorizationId
   * @returns {Promise<Object|null>}
   */
  async getState(authorizationId) {
    if (!authorizationId) {
      throw new Error('authorizationId is required');
    }

    const rows = await this._db.readQuery(
      'SELECT authorization_id, user_id, status, total_amount_used, total_count_used, created_at, updated_at FROM authorization_states WHERE authorization_id = ?',
      [authorizationId]
    );

    if (rows.length === 0) {
      return null;
    }

    return rows[0];
  }

  /**
   * 获取授权状态（按组合键查询，精确定位）
   * @param {string} userId
   * @param {string} authorizationId
   * @returns {Promise<Object|null>}
   */
  async getStateByCompositeKey(userId, authorizationId) {
    if (!userId || !authorizationId) {
      throw new Error('userId and authorizationId are required');
    }

    const rows = await this._db.readQuery(
      'SELECT authorization_id, user_id, status, total_amount_used, total_count_used, created_at, updated_at FROM authorization_states WHERE user_id = ? AND authorization_id = ?',
      [userId, authorizationId]
    );

    if (rows.length === 0) {
      return null;
    }

    return rows[0];
  }

  /**
   * 检查累计限制是否超限
   * @param {string} authorizationId - 授权 ID
   * @param {Object} limits - 授权限制条件
   * @param {string} [limits.totalAmountLimit] - 总累计金额上限（Wei 字符串）
   * @param {number} [limits.totalCountLimit] - 总累计次数上限
   * @param {Object} [limits.tokenLimits] - 分 token 限制 { [chainId_tokenAddress]: { amountLimit, countLimit } }
   * @param {Object} transaction - 当前交易信息
   * @param {string} transaction.amount - 本次交易金额（Wei 字符串）
   * @param {number} transaction.chainId - 链 ID
   * @param {string} transaction.tokenAddress - Token 地址，格式为 "{chainId}_native" / "{chainId}_unknown" / "0x..." ERC20 地址
   * @returns {Promise<{ allowed: boolean, reason: string }>}
   */
  async checkLimits(authorizationId, limits, transaction) {
    console.log(`[StateManager] checkLimits: authorizationId=${authorizationId}, txAmount=${transaction.amount}, chainId=${transaction.chainId}, token=${transaction.tokenAddress}`);

    // 1. 获取当前授权状态
    const state = await this.getState(authorizationId);
    // 如果状态记录尚不存在（首次签名），视为全新授权（0 用量），状态记录将在签名事务中创建
    if (state && state.status !== 'active') {
      console.log(`[StateManager] checkLimits: REJECTED - status=${state.status}`);
      return { allowed: false, reason: `Authorization status: ${state.status}` };
    }

    const currentTotalAmountUsed = state ? state.total_amount_used : '0';
    const currentTotalCountUsed = state ? state.total_count_used : 0;

    // 2. 检查总累计金额
    const newTotalAmount = BigInt(currentTotalAmountUsed) + BigInt(transaction.amount);
    if (limits.totalAmountLimit && newTotalAmount > BigInt(limits.totalAmountLimit)) {
      console.log(`[StateManager] checkLimits: REJECTED - total amount limit exceeded`);
      return { allowed: false, reason: 'Total cumulative amount limit exceeded' };
    }

    // 3. 检查总累计次数
    const newTotalCount = currentTotalCountUsed + 1;
    if (limits.totalCountLimit && newTotalCount > limits.totalCountLimit) {
      console.log(`[StateManager] checkLimits: REJECTED - total count limit exceeded`);
      return { allowed: false, reason: 'Total cumulative count limit exceeded' };
    }

    // 4. 获取分 token 状态
    // tokenAddress 格式为 "{chainId}_native" / "{chainId}_unknown" / "0x..." ERC20 地址
    // tokenLimits 的 key 格式为 "{chainId}_{tokenAddress_without_prefix}"，即：
    //   - 原生币：tokenAddress="1_native" → tokenKey="1_native"（直接用 tokenAddress）
    //   - ERC20：tokenAddress="0xA0b8..." → tokenKey="1_0xA0b8..."（需要拼接 chainId）
    const tokenKey = _buildTokenKey(transaction.chainId, transaction.tokenAddress);
    const tokenState = await this.getTokenState(authorizationId, transaction.chainId, transaction.tokenAddress);
    const tokenLimit = limits.tokenLimits?.[tokenKey];

    if (tokenLimit) {
      // 5. 检查分 token 累计金额
      const currentTokenAmount = BigInt(tokenState?.amount_used || '0');
      const newTokenAmount = currentTokenAmount + BigInt(transaction.amount);
      if (tokenLimit.amountLimit && newTokenAmount > BigInt(tokenLimit.amountLimit)) {
        console.log(`[StateManager] checkLimits: REJECTED - token ${tokenKey} amount limit exceeded`);
        return { allowed: false, reason: `Token ${tokenKey} cumulative amount limit exceeded` };
      }

      // 6. 检查分 token 累计次数
      const currentTokenCount = tokenState?.count_used || 0;
      const newTokenCount = currentTokenCount + 1;
      if (tokenLimit.countLimit && newTokenCount > tokenLimit.countLimit) {
        console.log(`[StateManager] checkLimits: REJECTED - token ${tokenKey} count limit exceeded`);
        return { allowed: false, reason: `Token ${tokenKey} cumulative count limit exceeded` };
      }
    }

    console.log(`[StateManager] checkLimits: ALLOWED`);
    return { allowed: true, reason: 'OK' };
  }

  /**
   * 签名成功后递增累计值（在同一事务中更新总计和分 token）
   * @param {string} authorizationId
   * @param {string} amount - 本次交易金额（Wei 字符串）
   * @param {number} chainId
   * @param {string} tokenAddress
   */
  async incrementUsage(authorizationId, amount, chainId, tokenAddress, userId = null) {
    if (!authorizationId || amount === undefined || amount === null) {
      throw new Error('authorizationId and amount are required');
    }

    console.log(`[StateManager] incrementUsage: authorizationId=${authorizationId}, amount=${amount}, chainId=${chainId}, token=${tokenAddress}`);

    // 分片键必须用 userId（与请求路由分片一致），此前误用 authorizationId，
    // 2PC 的 term 守卫落在错误的分片上；缺省时回退旧行为仅为兼容未知调用方
    await this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      const ts = this._engine.hlc.tick();

      // 更新总计 — SQLite 没有 DECIMAL，用应用层 BigInt 计算后存回字符串
      const stateRows = conn.query(
        'SELECT total_amount_used FROM authorization_states WHERE authorization_id = ?',
        [authorizationId]
      );
      if (stateRows.length > 0) {
        const newTotal = (BigInt(stateRows[0].total_amount_used || '0') + BigInt(amount)).toString();
        conn.query(
          `UPDATE authorization_states
           SET total_amount_used = ?,
               total_count_used = total_count_used + 1,
               updated_at = ?,
               _hlc = ?
           WHERE authorization_id = ?`,
          [newTotal, getMonotonicSqliteNow(), ts, authorizationId]
        );
      }

      // 更新分 token（INSERT OR IGNORE + UPDATE）
      conn.query(
        `INSERT OR IGNORE INTO authorization_token_states (authorization_id, chain_id, token_address, amount_used, count_used, _hlc)
         VALUES (?, ?, ?, '0', 0, ?)`,
        [authorizationId, chainId, tokenAddress, ts]
      );
      const tokenRows = conn.query(
        'SELECT amount_used FROM authorization_token_states WHERE authorization_id = ? AND chain_id = ? AND token_address = ?',
        [authorizationId, chainId, tokenAddress]
      );
      const newTokenTotal = (BigInt(tokenRows[0].amount_used || '0') + BigInt(amount)).toString();
      conn.query(
        `UPDATE authorization_token_states
         SET amount_used = ?, count_used = count_used + 1, _hlc = ?
         WHERE authorization_id = ? AND chain_id = ? AND token_address = ?`,
        [newTokenTotal, ts, authorizationId, chainId, tokenAddress]
      );
    }, userId ?? authorizationId);
  }

  /**
   * 更新授权状态（活跃→已撤销/已过期/已超限）
   * @param {string} authorizationId
   * @param {string} newStatus - 'revoked' | 'expired' | 'exceeded'
   */
  async updateStatus(authorizationId, newStatus) {
    if (!authorizationId || !newStatus) {
      throw new Error('authorizationId and newStatus are required');
    }
    const validStatuses = ['revoked', 'expired', 'exceeded'];
    if (!validStatuses.includes(newStatus)) {
      throw new Error(`Invalid status: ${newStatus}. Must be one of: ${validStatuses.join(', ')}`);
    }

    console.log(`[StateManager] updateStatus: authorizationId=${authorizationId}, newStatus=${newStatus}`);

    // 分片键必须用该授权所属 userId（与请求路由分片一致）：先读出归属再写，
    // 此前误用 authorizationId，2PC 的 term 守卫落在错误的分片上
    const ownerRows = await this._db.readQuery(
      'SELECT user_id FROM authorization_states WHERE authorization_id = ?',
      [authorizationId]
    );
    const ownerUserId = ownerRows && ownerRows.length > 0 ? ownerRows[0].user_id : null;

    const result = await this._engine.write(async (db) => {
      const ts = this._engine.hlc.tick();
      return db.run(
        `UPDATE authorization_states SET status = ?, updated_at = ?, _hlc = ? WHERE authorization_id = ? AND status = ?`,
        [newStatus, getMonotonicSqliteNow(), ts, authorizationId, 'active']
      );
    }, ownerUserId ?? authorizationId);

    console.log(`[StateManager] updateStatus: affectedRows=${result.changes}`);
    return result.changes > 0;
  }

  /**
   * 获取分 token 状态
   * @param {string} authorizationId
   * @param {number} chainId
   * @param {string} tokenAddress
   * @returns {Promise<Object|null>}
   */
  async getTokenState(authorizationId, chainId, tokenAddress) {
    const rows = await this._db.readQuery(
      'SELECT authorization_id, chain_id, token_address, amount_used, count_used FROM authorization_token_states WHERE authorization_id = ? AND chain_id = ? AND token_address = ?',
      [authorizationId, chainId, tokenAddress]
    );

    if (rows.length === 0) {
      return null;
    }

    return rows[0];
  }

  /**
   * 获取授权的所有分 token 状态列表
   * @param {string} authorizationId
   * @returns {Promise<Array>}
   */
  async listTokenStates(authorizationId) {
    const rows = await this._db.readQuery(
      'SELECT authorization_id, chain_id, token_address, amount_used, count_used FROM authorization_token_states WHERE authorization_id = ?',
      [authorizationId]
    );
    return rows;
  }

  // ========== 授权原文记录（争议取证） ==========

  /**
   * 保存授权原文记录（幂等，重复保存同一 (userId, authorizationId) 不报错）
   * @param {string} userId - 用户 ID
   * @param {string} authorizationId - 授权 ID
   * @param {string[]} grantee - 被授权平台地址数组
   * @param {Object} authorizationJson - 完整授权 JSON 对象
   * @param {string} authorizationHash - 授权 JSON 的 SHA256 哈希（base64url）
   */
  async saveAuthorizationRecord(userId, authorizationId, grantee, authorizationJson, authorizationHash) {
    if (!userId || !authorizationId || !grantee || !authorizationJson || !authorizationHash) {
      throw new Error('All parameters are required for saveAuthorizationRecord');
    }

    console.log(`[StateManager] saveAuthorizationRecord: userId=${userId}, authorizationId=${authorizationId}, granteeCount=${Array.isArray(grantee) ? grantee.length : 1}`);

    await this._engine.write(async (db) => {
      const ts = this._engine.hlc.tick();
      db.run(
        `INSERT OR IGNORE INTO authorization_records (user_id, authorization_id, grantee, authorization_json, authorization_hash, created_at, _hlc)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [userId, authorizationId, JSON.stringify(grantee), JSON.stringify(authorizationJson), authorizationHash, getMonotonicSqliteNow(), ts]
      );
    }, userId);
  }

  /**
   * 在事务中保存授权原文记录（供 handleSigningRequest 调用）
   * @param {Object} conn - 数据库连接
   * @param {string} userId
   * @param {string} authorizationId
   * @param {string[]} grantee
   * @param {Object} authorizationJson
   * @param {string} authorizationHash
   */
  _saveAuthorizationRecordInTransaction(conn, userId, authorizationId, grantee, authorizationJson, authorizationHash) {
    const ts = this._engine.hlc.tick();
    conn.query(
      `INSERT OR IGNORE INTO authorization_records (user_id, authorization_id, grantee, authorization_json, authorization_hash, created_at, _hlc)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [userId, authorizationId, JSON.stringify(grantee), JSON.stringify(authorizationJson), authorizationHash, getMonotonicSqliteNow(), ts]
    );
  }

  /**
   * 在事务中确保授权状态存在（供 handleSigningRequest 调用）
   * @param {Object} conn - 数据库连接
   * @param {string} authorizationId
   * @param {string} userId
   * @param {string[]} grantee
   */
  _ensureStateExists(conn, authorizationId, userId, grantee) {
    // 先尝试获取
    const rows = conn.query(
      'SELECT 1 FROM authorization_states WHERE user_id = ? AND authorization_id = ?',
      [userId, authorizationId]
    );

    if (rows.length === 0) {
      // 不存在则创建
      const ts = this._engine.hlc.tick();
      conn.query(
        `INSERT INTO authorization_states (authorization_id, user_id, grantee, status, total_amount_used, total_count_used, created_at, updated_at, _hlc)
         VALUES (?, ?, ?, 'active', '0', 0, ?, ?, ?)`,
        [authorizationId, userId, JSON.stringify(grantee), getMonotonicSqliteNow(), getMonotonicSqliteNow(), ts]
      );
    }
  }

  /**
   * 在事务中检查累计限制是否超限（供 handleSigningRequest 调用，与 _incrementUsageInTransaction 在同一事务中执行）
   * 解决 checkLimits（读）与 incrementUsage（写）之间的 TOCTOU 竞态问题。
   * @param {Object} conn - 数据库连接（事务内）
   * @param {string} authorizationId
   * @param {Object} limits - 授权限制条件（同 checkLimits 参数）
   * @param {Object} transaction - 当前交易信息（同 checkLimits 参数）
   * @throws {Error} 超限时抛出错误，触发事务回滚
   */
  _checkLimitsInTransaction(conn, authorizationId, limits, transaction) {
    const stateRows = conn.query(
      'SELECT status, total_amount_used, total_count_used FROM authorization_states WHERE authorization_id = ?',
      [authorizationId]
    );

    const state = stateRows.length > 0 ? stateRows[0] : null;
    if (state && state.status !== 'active') {
      throw new Error(`Authorization status: ${state.status}`);
    }

    const currentTotalAmountUsed = state ? state.total_amount_used : '0';
    const currentTotalCountUsed = state ? state.total_count_used : 0;

    // 检查总累计金额
    const newTotalAmount = BigInt(currentTotalAmountUsed) + BigInt(transaction.amount);
    if (limits.totalAmountLimit && newTotalAmount > BigInt(limits.totalAmountLimit)) {
      throw new Error('Total cumulative amount limit exceeded');
    }

    // 检查总累计次数
    const newTotalCount = currentTotalCountUsed + 1;
    if (limits.totalCountLimit && newTotalCount > limits.totalCountLimit) {
      throw new Error('Total cumulative count limit exceeded');
    }

    // 检查分 token 限制
    const tokenKey = _buildTokenKey(transaction.chainId, transaction.tokenAddress);
    const tokenLimit = limits.tokenLimits?.[tokenKey];
    if (tokenLimit) {
      const tokenRows = conn.query(
        'SELECT amount_used, count_used FROM authorization_token_states WHERE authorization_id = ? AND chain_id = ? AND token_address = ?',
        [authorizationId, transaction.chainId, transaction.tokenAddress]
      );
      const tokenState = tokenRows.length > 0 ? tokenRows[0] : null;

      const currentTokenAmount = BigInt(tokenState?.amount_used || '0');
      const newTokenAmount = currentTokenAmount + BigInt(transaction.amount);
      if (tokenLimit.amountLimit && newTokenAmount > BigInt(tokenLimit.amountLimit)) {
        throw new Error(`Token ${tokenKey} cumulative amount limit exceeded`);
      }

      const currentTokenCount = tokenState?.count_used || 0;
      const newTokenCount = currentTokenCount + 1;
      if (tokenLimit.countLimit && newTokenCount > limits.totalCountLimit) {
        throw new Error(`Token ${tokenKey} cumulative count limit exceeded`);
      }
    }
  }

  /**
   * 在事务中递增累计值（供 handleSigningRequest 调用）
   * @param {Object} conn - 数据库连接
   * @param {string} authorizationId
   * @param {string} amount
   * @param {number} chainId
   * @param {string} tokenAddress
   */
  _incrementUsageInTransaction(conn, authorizationId, amount, chainId, tokenAddress) {
    // 更新总计 — SQLite 没有 DECIMAL，用应用层 BigInt 计算后存回字符串
    const stateRows = conn.query(
      'SELECT total_amount_used FROM authorization_states WHERE authorization_id = ?',
      [authorizationId]
    );
    if (stateRows.length > 0) {
      const newTotal = (BigInt(stateRows[0].total_amount_used || '0') + BigInt(amount)).toString();
      conn.query(
        `UPDATE authorization_states
         SET total_amount_used = ?,
             total_count_used = total_count_used + 1,
             updated_at = ?,
             _hlc = ?
         WHERE authorization_id = ?`,
        [newTotal, getMonotonicSqliteNow(), this._engine.hlc.tick(), authorizationId]
      );
    }

    // 更新分 token（INSERT OR IGNORE + UPDATE）
    conn.query(
      `INSERT OR IGNORE INTO authorization_token_states (authorization_id, chain_id, token_address, amount_used, count_used, _hlc)
       VALUES (?, ?, ?, '0', 0, ?)`,
      [authorizationId, chainId, tokenAddress, this._engine.hlc.tick()]
    );
    const tokenRows = conn.query(
      'SELECT amount_used FROM authorization_token_states WHERE authorization_id = ? AND chain_id = ? AND token_address = ?',
      [authorizationId, chainId, tokenAddress]
    );
    const newTokenTotal = (BigInt(tokenRows[0].amount_used || '0') + BigInt(amount)).toString();
    conn.query(
      `UPDATE authorization_token_states
       SET amount_used = ?, count_used = count_used + 1, _hlc = ?
       WHERE authorization_id = ? AND chain_id = ? AND token_address = ?`,
      [newTokenTotal, this._engine.hlc.tick(), authorizationId, chainId, tokenAddress]
    );
  }

  /**
   * 获取授权原文记录（按组合键查询）
   * @param {string} userId - 用户 ID
   * @param {string} authorizationId - 授权 ID
   * @returns {Promise<Object|null>} { authorization_id, user_id, grantee, authorization_json, authorization_hash, created_at }
   */
  async getAuthorizationRecord(userId, authorizationId) {
    if (!userId || !authorizationId) {
      throw new Error('userId and authorizationId are required');
    }

    console.log(`[StateManager] getAuthorizationRecord: userId=${userId}, authorizationId=${authorizationId}`);

    const rows = await this._db.readQuery(
      'SELECT authorization_id, user_id, grantee, authorization_json, authorization_hash, created_at FROM authorization_records WHERE user_id = ? AND authorization_id = ?',
      [userId, authorizationId]
    );

    if (rows.length === 0) {
      return null;
    }

    const row = rows[0];
    // grantee 存储为 JSON 字符串，需解析
    if (typeof row.grantee === 'string') {
      row.grantee = JSON.parse(row.grantee);
    }
    // authorization_json 存储为 JSON 字符串，需解析
    if (typeof row.authorization_json === 'string') {
      row.authorization_json = JSON.parse(row.authorization_json);
    }
    return row;
  }

  // ========== 授权撤销记录（本地优先，合约兜底） ==========

  /**
   * 查询本地撤销记录（按组合键）
   * @param {string} userId
   * @param {string} authorizationId
   * @returns {Promise<Object|null>} 撤销记录（见 _revocationFromRow）或 null
   */
  async getRevocation(userId, authorizationId) {
    if (!userId || !authorizationId) {
      throw new Error('userId and authorizationId are required');
    }
    const rows = await this._db.readQuery(
      'SELECT * FROM authorization_revocations WHERE user_id = ? AND authorization_id = ?',
      [userId, authorizationId]
    );
    return _revocationFromRow(rows[0]);
  }

  /**
   * 构造撤销记录查询条件（listRevocations / countRevocations 共用）
   * 支持按记录的 key 字段任意组合精确匹配：userId、authorizationId（主键）、
   * grantee、source；至少提供一个。
   * @param {{ userId?: string, authorizationId?: string, grantee?: string, source?: string }} filter
   * @returns {{ where: string, params: string[] }}
   */
  _revocationWhere(filter = {}) {
    const { userId, authorizationId, grantee, source } = filter;
    if (!userId && !authorizationId && !grantee && !source) {
      throw new Error('at least one query key is required (userId, authorizationId, grantee or source)');
    }
    if (source && !['platform', 'contract', 'emergency'].includes(source)) {
      throw new Error(`Invalid revocation source: ${source}`);
    }
    const conditions = [];
    const params = [];
    if (userId) { conditions.push('user_id = ?'); params.push(userId); }
    if (authorizationId) { conditions.push('authorization_id = ?'); params.push(authorizationId); }
    if (grantee) { conditions.push('grantee = ?'); params.push(grantee); }
    if (source) { conditions.push('source = ?'); params.push(source); }
    return { where: conditions.join(' AND '), params };
  }

  /**
   * 列出本地撤销记录（供无鉴权查询接口使用，只读本地表，不查合约）
   * userId / authorizationId 至少提供一个；两者都给时精确匹配一条。
   * @param {{ userId?: string, authorizationId?: string }} filter
   * @param {{ limit: number, offset: number }} [pagination] - 分页（由调用方校验范围）
   * @returns {Promise<Object[]>} 撤销记录列表（按 revoked_at 升序）
   */
  async listRevocations(filter = {}, pagination = null) {
    const { where, params } = this._revocationWhere(filter);
    let sql = `SELECT * FROM authorization_revocations WHERE ${where} ORDER BY revoked_at ASC`;
    if (pagination) {
      sql += ' LIMIT ? OFFSET ?';
      params.push(pagination.limit, pagination.offset);
    }
    const rows = await this._db.readQuery(sql, params);
    return rows.map(_revocationFromRow);
  }

  /**
   * 统计本地撤销记录总数（分页用）
   * @param {{ userId?: string, authorizationId?: string }} filter
   * @returns {Promise<number>}
   */
  async countRevocations(filter = {}) {
    const { where, params } = this._revocationWhere(filter);
    const rows = await this._db.readQuery(
      `SELECT COUNT(*) AS cnt FROM authorization_revocations WHERE ${where}`,
      params
    );
    return rows[0]?.cnt || 0;
  }

  /**
   * 记录/更新一条撤销记录，并同步将授权状态置为 revoked。
   *
   * 来源优先级：platform（平台转发的用户撤销，本地直接记录）高于 contract
   * （合约查询结果的缓存）：已存在 platform 记录时，合约缓存不得覆盖它，
   * 只允许补齐缺失的到期时间/授权哈希；contract 记录可被 platform 记录升级。
   *
   * @param {Object} record
   * @param {string} record.userId
   * @param {string} record.authorizationId
   * @param {string} [record.grantee] - 被授权平台地址（单个）
   * @param {'platform'|'contract'} record.source - 记录来源
   * @param {string} [record.revokedAt] - 撤销发生时间（ISO），缺省为当前单调时间
   * @param {string} [record.authorizationExpiresAt] - 被撤销授权的到期时间（ISO）
   * @param {string} [record.authorizationHash] - 授权原文哈希
   * @param {Function} [beforeRecordInTx] - 可选的同事务前置写入回调 (conn) => void：
   *   在同一个 engine.write 事务内、写撤销记录之前执行，任一步失败整体回滚。
   *   用于把授权原文落库与撤销落库放进一个事务，避免只成功一半。
   * @returns {Promise<Object>} 落库后的撤销记录
   */
  async recordRevocation(record, beforeRecordInTx = null) {
    const { userId, authorizationId, source } = record || {};
    if (!userId || !authorizationId) {
      throw new Error('userId and authorizationId are required');
    }
    if (!['platform', 'contract', 'emergency'].includes(source)) {
      throw new Error(`Invalid revocation source: ${source}`);
    }
    const revokedAt = _normalizeIsoTime(record.revokedAt) || getMonotonicDate().toISOString();
    const expiresAt = _normalizeIsoTime(record.authorizationExpiresAt);
    const authorizationHash = record.authorizationHash || null;
    const grantee = record.grantee || null;

    await this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      if (beforeRecordInTx) beforeRecordInTx(conn);
      const ts = this._engine.hlc.tick();
      const now = getMonotonicSqliteNow();

      const existing = conn.query(
        'SELECT * FROM authorization_revocations WHERE user_id = ? AND authorization_id = ?',
        [userId, authorizationId]
      );

      if (existing.length > 0) {
        const ex = existing[0];
        if ((ex.source === 'platform' || ex.source === 'emergency') && source === 'contract') {
          // platform / emergency 记录优先（均为本地权威来源）：合约缓存只补元数据，不覆盖来源与撤销时间
          conn.query(
            `UPDATE authorization_revocations
             SET authorization_expires_at = COALESCE(authorization_expires_at, ?),
                 authorization_hash = COALESCE(authorization_hash, ?),
                 updated_at = ?, _hlc = ?
             WHERE user_id = ? AND authorization_id = ?`,
            [expiresAt, authorizationHash, now, ts, userId, authorizationId]
          );
        } else {
          const earliestRevokedAt = [ex.revoked_at, revokedAt].sort()[0];
          conn.query(
            `UPDATE authorization_revocations
             SET grantee = COALESCE(?, grantee), source = ?, revoked_at = ?,
                 authorization_expires_at = COALESCE(?, authorization_expires_at),
                 authorization_hash = COALESCE(?, authorization_hash),
                 updated_at = ?, _hlc = ?
             WHERE user_id = ? AND authorization_id = ?`,
            [grantee, source, earliestRevokedAt, expiresAt, authorizationHash, now, ts, userId, authorizationId]
          );
        }
      } else {
        conn.query(
          `INSERT INTO authorization_revocations
             (user_id, authorization_id, grantee, source, revoked_at, authorization_expires_at, authorization_hash, created_at, updated_at, _hlc)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [userId, authorizationId, grantee, source, revokedAt, expiresAt, authorizationHash, now, now, ts]
        );
      }

      // 同步授权状态为 revoked（状态行不存在则创建），供 /api/auth/status 等读取方看到一致结果
      const stateRows = conn.query(
        'SELECT status FROM authorization_states WHERE user_id = ? AND authorization_id = ?',
        [userId, authorizationId]
      );
      if (stateRows.length > 0) {
        if (stateRows[0].status !== 'revoked') {
          conn.query(
            `UPDATE authorization_states SET status = 'revoked', updated_at = ?, _hlc = ? WHERE user_id = ? AND authorization_id = ?`,
            [now, ts, userId, authorizationId]
          );
        }
      } else {
        conn.query(
          `INSERT INTO authorization_states (authorization_id, user_id, grantee, status, total_amount_used, total_count_used, created_at, updated_at, _hlc)
           VALUES (?, ?, ?, 'revoked', '0', 0, ?, ?, ?)`,
          [authorizationId, userId, grantee || '*', now, now, ts]
        );
      }
    }, userId);

    console.log(`[AuthorizationRevocation] recorded: userId=${userId}, authorizationId=${authorizationId}, source=${source}, revokedAt=${revokedAt}, authorizationExpiresAt=${expiresAt || 'none'}`);
    return this.getRevocation(userId, authorizationId);
  }

  /**
   * 删除本地撤销记录（删除必打日志，供运维监控跟踪每一次撤销记录消失的原因）
   * @param {string} userId
   * @param {string} authorizationId
   * @param {Object} [options]
   * @param {string} [options.expectedSource] - 仅当现有记录来源与此一致时才删除
   * @param {string} [options.reason] - 删除原因（写入日志）
   * @param {boolean} [options.restoreState] - 删除后若授权状态为 revoked 则恢复为 active
   *   （用于合约对账删除错误缓存：该状态的 revoked 仅来自这条缓存记录）
   * @returns {Promise<boolean>} 是否实际删除
   */
  async deleteRevocation(userId, authorizationId, options = {}) {
    let deletedRow = null;

    await this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      const rows = conn.query(
        'SELECT * FROM authorization_revocations WHERE user_id = ? AND authorization_id = ?',
        [userId, authorizationId]
      );
      if (rows.length === 0) return;
      const existing = rows[0];
      // 来源校验必须在事务内做：事务外预读与删除之间，记录可能刚被升级
      // （contract → platform），按旧来源误删会把平台撤销记录删掉
      if (options.expectedSource && existing.source !== options.expectedSource) return;

      conn.query(
        'DELETE FROM authorization_revocations WHERE user_id = ? AND authorization_id = ?',
        [userId, authorizationId]
      );
      if (options.restoreState) {
        const ts = this._engine.hlc.tick();
        conn.query(
          `UPDATE authorization_states SET status = 'active', updated_at = ?, _hlc = ?
           WHERE user_id = ? AND authorization_id = ? AND status = 'revoked'`,
          [getMonotonicSqliteNow(), ts, userId, authorizationId]
        );
      }
      deletedRow = existing;
    }, userId);

    if (!deletedRow) return false;
    console.log(`[AuthorizationRevocation] local revocation record deleted: userId=${userId}, authorizationId=${authorizationId}, source=${deletedRow.source}, revokedAt=${deletedRow.revoked_at}, reason=${options.reason || 'unspecified'}`);
    return true;
  }

  // ========== 应急授权使用计数（只记消费进度，不参与有效性判定） ==========

  /**
   * 查询应急授权在 (目标用户, 操作) 维度上已成功执行的次数
   * @param {string} authorizationId - 应急授权 ID（全局唯一）
   * @param {string} userId - 目标用户（被操作的钱包归属用户）
   * @param {string} operation - 操作名
   * @returns {Promise<number>}
   */
  async getEmergencyUseCount(authorizationId, userId, operation) {
    const rows = await this._db.readQuery(
      'SELECT used_count FROM emergency_authorization_uses WHERE authorization_id = ? AND user_id = ? AND operation = ?',
      [authorizationId, userId, operation]
    );
    return rows.length > 0 ? rows[0].used_count : 0;
  }

  /**
   * 事务内检查应急授权使用次数未超限（超限抛错，与业务写同事务回滚）
   * @param {Object} conn - createConnProxy 代理
   * @param {string} authorizationId
   * @param {string} userId
   * @param {string} operation
   * @param {number} maxUses
   */
  _checkEmergencyUseInTransaction(conn, authorizationId, userId, operation, maxUses) {
    const rows = conn.query(
      'SELECT used_count FROM emergency_authorization_uses WHERE authorization_id = ? AND user_id = ? AND operation = ?',
      [authorizationId, userId, operation]
    );
    const used = rows.length > 0 ? rows[0].used_count : 0;
    if (used >= maxUses) {
      throw new Error(`Emergency authorization use limit exceeded: operation=${operation}, used=${used}, maxUses=${maxUses}`);
    }
  }

  /**
   * 事务内递增应急授权使用计数（行不存在则创建）
   * @param {Object} conn - createConnProxy 代理
   * @param {string} authorizationId
   * @param {string} userId
   * @param {string} operation
   */
  _incrementEmergencyUseInTransaction(conn, authorizationId, userId, operation) {
    const ts = this._engine.hlc.tick();
    const now = getMonotonicSqliteNow();
    const rows = conn.query(
      'SELECT used_count FROM emergency_authorization_uses WHERE authorization_id = ? AND user_id = ? AND operation = ?',
      [authorizationId, userId, operation]
    );
    if (rows.length > 0) {
      conn.query(
        'UPDATE emergency_authorization_uses SET used_count = used_count + 1, updated_at = ?, _hlc = ? WHERE authorization_id = ? AND user_id = ? AND operation = ?',
        [now, ts, authorizationId, userId, operation]
      );
    } else {
      conn.query(
        `INSERT INTO emergency_authorization_uses (authorization_id, user_id, operation, used_count, updated_at, _hlc)
         VALUES (?, ?, ?, 1, ?, ?)`,
        [authorizationId, userId, operation, now, ts]
      );
    }
  }

  /**
   * 记录一次应急授权的成功执行（独立事务，按目标用户分片键写入）
   * @param {string} authorizationId
   * @param {string} userId - 目标用户
   * @param {string} operation
   * @returns {Promise<number>} 递增后的已用次数
   */
  async recordEmergencyUse(authorizationId, userId, operation) {
    await this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      this._incrementEmergencyUseInTransaction(conn, authorizationId, userId, operation);
    }, userId);
    const count = await this.getEmergencyUseCount(authorizationId, userId, operation);
    console.log(`[EmergencyAuth] use recorded: authorizationId=${authorizationId}, userId=${userId}, operation=${operation}, usedCount=${count}`);
    return count;
  }

  /**
   * 清理已过期的撤销记录：被撤销的授权一旦到期，撤销记录失去意义，删除并打日志。
   * 无到期时间的记录不清理（无法判定授权何时过期，保守保留）。
   * @returns {Promise<{ cleaned: number }>}
   */
  async cleanExpiredRevocations() {
    const nowIso = getMonotonicDate().toISOString();
    const rows = await this._db.readQuery(
      `SELECT user_id, authorization_id FROM authorization_revocations
       WHERE authorization_expires_at IS NOT NULL AND authorization_expires_at <= ?`,
      [nowIso]
    );
    let cleaned = 0;
    for (const row of rows) {
      if (await this.deleteRevocation(row.user_id, row.authorization_id, { reason: 'authorization expired' })) {
        cleaned++;
      }
    }
    if (cleaned > 0) {
      console.log(`[AuthorizationRevocation] cleanup: deleted ${cleaned} expired revocation record(s)`);
    }
    return { cleaned };
  }

  /**
   * 合约对账：contract 来源的本地记录只是链上状态的缓存，链上已不存在对应
   * 撤销记录时，该缓存必须删除（并把仅由它置 revoked 的授权状态恢复 active）。
   * platform 来源的记录不参与对账删除——它不依赖合约存在。
   * 合约不可达的用户跳过，不删除任何记录。
   * @param {import('../../modules/contract-client/index.js').ContractClient} contractClient
   * @returns {Promise<{ checked: number, deleted: number }>}
   */
  async reconcileContractRevocations(contractClient) {
    const rows = await this._db.readQuery(
      `SELECT * FROM authorization_revocations WHERE source = 'contract'`
    );
    if (rows.length === 0) return { checked: 0, deleted: 0 };

    const nowIso = getMonotonicDate().toISOString();
    const byUser = new Map();
    for (const row of rows) {
      // 已到期的记录由 cleanExpiredRevocations 负责删除并说明原因，对账不重复处理
      if (row.authorization_expires_at && row.authorization_expires_at <= nowIso) continue;
      if (!byUser.has(row.user_id)) byUser.set(row.user_id, []);
      byUser.get(row.user_id).push(row);
    }

    let checked = 0;
    let deleted = 0;
    for (const [userId, userRows] of byUser) {
      let chainRecords;
      try {
        chainRecords = await contractClient.getRevokedAuthorizations(userId);
      } catch (err) {
        console.warn(`[AuthorizationRevocation] reconcile skipped for userId=${userId}: contract unavailable (${err.message})`);
        continue;
      }
      const chainIds = new Set(chainRecords.map((r) => r.authorizationId));
      for (const row of userRows) {
        checked++;
        if (!chainIds.has(row.authorization_id)) {
          const removed = await this.deleteRevocation(userId, row.authorization_id, {
            expectedSource: 'contract',
            reason: 'contract reconciliation: no revocation record on contract',
            restoreState: true,
          });
          if (removed) deleted++;
        }
      }
    }
    if (deleted > 0) {
      console.log(`[AuthorizationRevocation] reconcile: checked=${checked}, deleted=${deleted} stale contract-sourced cache record(s)`);
    }
    return { checked, deleted };
  }

  /**
   * 定时全量同步：把合约上的撤销记录同步进本地数据库（source='contract'）。
   * 枚举本地全部用户（accounts 表），逐用户拉取链上撤销列表：
   *   - 链上有、本地无 → 以 source='contract' 落库；到期时间与授权哈希从本地
   *     已存的授权原文记录补全（链上撤销记录本身不含这两项），供过期清理使用；
   *     本地已有 platform 记录时，来源优先级保证其不会被降级覆盖；
   *   - 本地有 contract 记录、链上已无 → 在同一次同步中删除并恢复授权状态
   *    （与 reconcileContractRevocations 相同的删除规则）；platform 来源的
   *     记录不参与删除。
   * 合约不可达的用户整户跳过：不落库、不删除。
   * 由 enclave 定时清理任务周期调用（见 sgx-enclave/index.js）。
   * @param {import('../../modules/contract-client/index.js').ContractClient} contractClient
   * @returns {Promise<{ users: number, synced: number, deleted: number, skippedUsers: number }>}
   */
  async syncRevocationsFromContract(contractClient) {
    const userRows = await this._db.readQuery('SELECT user_id FROM accounts');
    let synced = 0;
    let deleted = 0;
    let skippedUsers = 0;
    let failed = 0;
    let leaderSkipped = 0;

    for (const { user_id: userId } of userRows) {
      // leader 纪律与 HTTP 写请求一致（见 sync-adapter shouldExecuteInternalWrite）：
      // 该用户分片 leader 是其它节点时本节点不执行，由 leader 节点上的同一轮
      // 同步完成；无 leader 时本地兜底落地，后续靠同步传播，不会写坏。
      if (!shouldExecuteInternalWrite(this._engine, userId)) {
        leaderSkipped++;
        continue;
      }
      let chainRecords;
      try {
        chainRecords = await contractClient.getRevokedAuthorizations(userId);
      } catch (err) {
        skippedUsers++;
        console.warn(`[AuthorizationRevocation] contract sync skipped for userId=${userId}: contract unavailable (${err.message})`);
        continue;
      }

      const chainIds = new Set();
      for (const rec of chainRecords) {
        chainIds.add(rec.authorizationId);
        // 到期时间/哈希从本地授权原文记录补全（没有存量记录时留空，不影响撤销效力）
        let authorizationExpiresAt;
        let authorizationHash;
        const stored = await this.getAuthorizationRecord(userId, rec.authorizationId).catch(() => null);
        if (stored) {
          // getAuthorizationRecord 返回原始行字段（snake_case）
          authorizationHash = stored.authorizationHash ?? stored.authorization_hash;
          try {
            const deadline = JSON.parse(stored.authorizationJson ?? stored.authorization_json)?.data?.deadline;
            if (deadline) authorizationExpiresAt = new Date(deadline).toISOString();
          } catch { /* 授权原文不可解析时不补全 */ }
        }
        const before = await this.getRevocation(userId, rec.authorizationId);
        // 逐条隔离：单条写失败只跳过本条，不中断整轮同步；未落地的记录
        // 下一轮全量对账会重新补齐。协调未完成（如写到一半网络断开）时
        // withLocalFallback 按无 leader 的同一规则回落本地提交，先落地再传播
        try {
          await withLocalFallback(this._engine, () => this.recordRevocation({
            userId,
            authorizationId: rec.authorizationId,
            grantee: rec.grantee,
            source: 'contract',
            revokedAt: rec.revokedAt,
            authorizationExpiresAt,
            authorizationHash,
          }));
          if (!before) synced++;
        } catch (err) {
          failed++;
          console.warn(`[AuthorizationRevocation] contract sync record failed for userId=${userId}, authorizationId=${rec.authorizationId}: ${err.message}`);
        }
      }

      // 同一次同步内做删除对账：本地 contract 缓存中链上已不存在的记录删除
      const localContractRows = await this._db.readQuery(
        `SELECT authorization_id FROM authorization_revocations WHERE user_id = ? AND source = 'contract'`,
        [userId]
      );
      for (const row of localContractRows) {
        if (!chainIds.has(row.authorization_id)) {
          // 与写入同一口径逐条隔离 + 协调未完成回落本地提交（见上）
          try {
            const removed = await withLocalFallback(this._engine, () => this.deleteRevocation(userId, row.authorization_id, {
              expectedSource: 'contract',
              reason: 'contract sync: no revocation record on contract',
              restoreState: true,
            }));
            if (removed) deleted++;
          } catch (err) {
            failed++;
            console.warn(`[AuthorizationRevocation] contract sync delete failed for userId=${userId}, authorizationId=${row.authorization_id}: ${err.message}`);
          }
        }
      }
    }

    if (synced > 0 || deleted > 0 || skippedUsers > 0 || failed > 0 || leaderSkipped > 0) {
      console.log(`[AuthorizationRevocation] contract sync: users=${userRows.length}, synced=${synced}, deleted=${deleted}, skippedUsers=${skippedUsers}, failed=${failed}, leaderSkipped=${leaderSkipped}`);
    }
    return { users: userRows.length, synced, deleted, skippedUsers, failed, leaderSkipped };
  }

  // ========== 签名防重放（GUID nonce） ==========

  /**
   * 在事务中检查并记录 GUID（供 handleSigningRequest 调用）
   * 不管后续签名成功与否，只要见过这个 GUID 就记录，后续拒绝相同 GUID
   * @param {Object} conn - 数据库连接（事务内）
   * @param {string} authorizationId
   * @param {string} guid
   * @throws {Error} 如果 GUID 已存在则抛出错误
   */
  _checkAndRecordNonceInTransaction(conn, authorizationId, guid) {
    const existing = conn.query(
      'SELECT 1 FROM tx_sign_nonces WHERE authorization_id = ? AND guid = ?',
      [authorizationId, guid]
    );
    if (existing.length > 0) {
      throw new Error(`Duplicate signing request: guid=${guid} has already been used for authorization=${authorizationId}`);
    }
    const ts = this._engine.hlc.tick();
    conn.query(
      'INSERT INTO tx_sign_nonces (authorization_id, guid, created_at, _hlc) VALUES (?, ?, ?, ?)',
      [authorizationId, guid, getMonotonicSqliteNow(), ts]
    );
  }


  /**
   * 清理已失效的授权缓存（status 为 revoked / expired / exceeded 的记录）
   * 同时清除关联的 token 状态和 nonce 记录
   * 由定时器周期调用，防止无效缓存无限堆积
   * @returns {Promise<{ cleaned: number }>}
   */
  async cleanInvalidatedStates() {
    console.log(`[StateManager] cleanInvalidatedStates: scanning for invalidated authorization states`);

    // 1. 查出所有非 active 的 authorization_id 及其 user_id
    const invalidRows = await this._db.readQuery(
      `SELECT authorization_id, user_id FROM authorization_states WHERE status != 'active'`
    );

    if (invalidRows.length === 0) {
      console.log(`[StateManager] cleanInvalidatedStates: no invalidated states found`);
      return { cleaned: 0 };
    }

    console.log(`[StateManager] cleanInvalidatedStates: found ${invalidRows.length} invalidated state(s), cleaning...`);

    // 2. 按 userId 分组，每组用独立的 engine.write()（2PC + 正确的分片路由）
    const byUser = new Map();
    for (const row of invalidRows) {
      if (!byUser.has(row.user_id)) {
        byUser.set(row.user_id, []);
      }
      byUser.get(row.user_id).push(row.authorization_id);
    }

    for (const [userId, ids] of byUser) {
      const placeholders = ids.map(() => '?').join(',');
      await this._engine.write(async (db) => {
        const conn = createConnProxy(db);
        conn.query(`DELETE FROM authorization_token_states WHERE authorization_id IN (${placeholders})`, ids);
        conn.query(`DELETE FROM tx_sign_nonces WHERE authorization_id IN (${placeholders})`, ids);
        conn.query(`DELETE FROM authorization_states WHERE authorization_id IN (${placeholders})`, ids);
      }, userId);
    }

    console.log(`[StateManager] cleanInvalidatedStates: cleaned ${invalidRows.length} invalidated state(s) and associated data`);
    return { cleaned: invalidRows.length };
  }

  /**
   * 按用户 ID 列出所有授权记录
   * @param {string} userId
   * @returns {Promise<Array>}
   */
  async listAuthorizationRecords(userId) {
    if (!userId) {
      throw new Error('userId is required');
    }

    const rows = await this._db.readQuery(
      'SELECT authorization_id, user_id, grantee, authorization_hash, created_at FROM authorization_records WHERE user_id = ?',
      [userId]
    );

    return rows.map((row) => {
      if (typeof row.grantee === 'string') {
        row.grantee = JSON.parse(row.grantee);
      }
      return row;
    });
  }
}
