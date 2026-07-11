/**
 * 授权状态管理器
 * 管理授权累计状态：已用金额/次数（总计+分 token），状态机转换
 *
 * 状态机：active → revoked / expired / exceeded
 * 大数处理：使用 JavaScript 原生 BigInt（Wei 精度）
 */

import { createConnProxy } from '../../sync/sync-adapter.js';
import { getMonotonicSqliteNow } from '../../utils/monotonic-clock.js';

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
  async incrementUsage(authorizationId, amount, chainId, tokenAddress) {
    if (!authorizationId || amount === undefined || amount === null) {
      throw new Error('authorizationId and amount are required');
    }

    console.log(`[StateManager] incrementUsage: authorizationId=${authorizationId}, amount=${amount}, chainId=${chainId}, token=${tokenAddress}`);

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
    }, authorizationId);
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

    const result = await this._engine.write(async (db) => {
      const ts = this._engine.hlc.tick();
      return db.run(
        `UPDATE authorization_states SET status = ?, updated_at = ?, _hlc = ? WHERE authorization_id = ? AND status = ?`,
        [newStatus, getMonotonicSqliteNow(), ts, authorizationId, 'active']
      );
    }, authorizationId);

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
