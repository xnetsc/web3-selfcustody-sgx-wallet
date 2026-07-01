/**
 * SQLite 连接管理器
 * 使用 better-sqlite3（同步 API）
 *
 * 接口契约：
 *   readQuery(sql, params)        → rows[]
 *   writeQuery(sql, params)       → { changes, lastInsertRowid }
 *   writeTransaction(callback)    → callback 返回值
 *
 * 注意：better-sqlite3 是同步库，但为了保持上层调用代码不变，
 * 本模块的公共方法仍然保留同步签名（不再是 async）。
 * 上层代码原本 await readQuery(...) 对同步返回值 await 也不会出错。
 */

import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { DB_PATH } from './constants.js';
import { initializeSchema } from './schema.js';

class ConnectionManager {
    constructor() {
        this.db = null;
        this._readDb = null; // 独立只读连接（WAL 模式下不受写事务影响）
        this.initialized = false;
        // 写操作后的通知回调（用于同步模块 push-on-write）
        this._onWriteCallbacks = [];
        // 2PC 手动事务状态
        this._activeManualTxn = null;
        // 外部注入的手动事务检查函数（SyncEngine 管理事务时使用）
        this._externalHasActiveManualTxn = null;
    }

    /**
     * 初始化 SQLite 连接
     * @param {object} config - { dbPath?: string }（可选，默认使用 constants.DB_PATH）
     */
    initialize(config = {}) {
        if (this.initialized) {
            throw new Error('ConnectionManager already initialized');
        }

        const dbPath = config.dbPath || DB_PATH;

        // 确保目录存在
        const dir = path.dirname(dbPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        this.db = new Database(dbPath);

        // 性能优化
        this.db.pragma('journal_mode = WAL');
        this.db.pragma('synchronous = NORMAL');
        this.db.pragma('foreign_keys = ON');
        this.db.pragma('busy_timeout = 5000');

        // 独立只读连接：WAL 模式下读取已提交的快照，不受写事务影响
        // 解决 2PC 事务期间读请求看到未提交数据的问题
        this._readDb = new Database(dbPath, { readonly: true });
        this._readDb.pragma('busy_timeout = 5000');

        this.initialized = true;
    }

    /**
     * 注册写操作后的回调（用于 sync 模块的 push-on-write）
     * @param {Function} callback
     */
    onWrite(callback) {
        this._onWriteCallbacks.push(callback);
    }

    /**
     * 注入外部手动事务检测函数
     * 当 SyncEngine 管理 2PC 事务时，connectionManager 需要知道是否有活跃事务
     * 以决定是否跳过 _notifyWrite
     * @param {function(): boolean} fn
     */
    setExternalManualTxnCheck(fn) {
        this._externalHasActiveManualTxn = fn;
    }

    /**
     * 触发写操作通知
     */
    _notifyWrite(tableName, operation, rowKey, rowData) {
        for (const cb of this._onWriteCallbacks) {
            try {
                cb(tableName, operation, rowKey, rowData);
            } catch (err) {
                console.error('[ConnectionManager] onWrite callback error:', err);
            }
        }
    }

    /**
     * 执行写操作（INSERT / UPDATE / DELETE）
     * @param {string} sql
     * @param {Array} params
     * @returns {{ changes: number, lastInsertRowid: number }}
     */
    writeQuery(sql, params = []) {
        this._ensureInitialized();
        const stmt = this.db.prepare(sql);
        const result = stmt.run(...params);
        if (result.changes > 0 && !this._isInManualTxn()) {
            this._notifyWrite();
        }
        return result;
    }

    /**
     * 执行读操作（SELECT）
     * @param {string} sql
     * @param {Array} params
     * @returns {Array<object>} 行数组
     */
    readQuery(sql, params = []) {
        this._ensureInitialized();
        // 使用独立只读连接：WAL 模式下读取已提交快照，不受 2PC 事务影响
        const db = this._readDb || this.db;
        const stmt = db.prepare(sql);
        return stmt.all(...params);
    }

    /**
     * 执行写事务
     * @param {Function} callback - (connProxy) => result
     *   connProxy 提供 .query(sql, params) 方法，兼容原有事务回调
     * @returns {*} callback 的返回值
     */
    writeTransaction(callback) {
        this._ensureInitialized();
        const self = this;
        const txn = this.db.transaction(() => {
            // 构造事务内的查询代理对象
            const connProxy = {
                query(sql, params = []) {
                    const trimmed = sql.trimStart().toUpperCase();
                    if (trimmed.startsWith('SELECT') || trimmed.startsWith('WITH')) {
                        const stmt = self.db.prepare(sql);
                        return stmt.all(...params);
                    } else {
                        const stmt = self.db.prepare(sql);
                        return stmt.run(...params);
                    }
                },
            };
            return callback(connProxy);
        });
        const result = txn();
        if (!this._isInManualTxn()) {
            this._notifyWrite();
        }
        return result;
    }

    /**
     * 检查是否有活跃的手动事务（本地 or SyncEngine 管理的）
     * @returns {boolean}
     */
    _isInManualTxn() {
        if (this._activeManualTxn) return true;
        if (this._externalHasActiveManualTxn) return this._externalHasActiveManualTxn();
        return false;
    }

    /**
     * 获取底层 better-sqlite3 Database 实例（供 sync 模块等高级用途）
     */
    getDatabase() {
        this._ensureInitialized();
        return this.db;
    }

    /**
     * 2PC：开启手动事务（BEGIN IMMEDIATE）
     * 记录当前 _sync_log 的 maxSeq，用于后续读取本次事务新增的条目
     *
     * @param {string} writeId - 本次写操作的唯一 ID
     * @throws {Error} 如果已有活跃的手动事务
     */
    beginManualTransaction(writeId) {
        this._ensureInitialized();
        if (this._activeManualTxn) {
            throw new Error('ConnectionManager: already has an active manual transaction (writeId=' + this._activeManualTxn.writeId + ')');
        }
        // 记录事务开始前的 maxSeq
        const prevMaxSeqRow = this.db.prepare('SELECT MAX(id) AS max_seq FROM _sync_log').get();
        const prevMaxSeq = prevMaxSeqRow?.max_seq || 0;
        // 开启手动事务（IMMEDIATE 模式：立即获取写锁，防止死锁）
        this.db.exec('BEGIN IMMEDIATE');
        this._activeManualTxn = { writeId, prevMaxSeq };
    }

    /**
     * 2PC：读取本次手动事务新增的 _sync_log 条目
     * 必须在 beginManualTransaction 之后、commitManualTransaction 之前调用
     *
     * @param {string} writeId - 必须与 beginManualTransaction 的 writeId 一致
     * @returns {Array<object>} 新增的 _sync_log 条目
     */
    getManualTransactionEntries(writeId) {
        this._ensureInitialized();
        if (!this._activeManualTxn || this._activeManualTxn.writeId !== writeId) {
            throw new Error('ConnectionManager: no active manual transaction for writeId=' + writeId);
        }
        const { prevMaxSeq } = this._activeManualTxn;
        return this.db.prepare(
            'SELECT id AS seq, table_name, operation, row_key, row_data, _hlc, created_at FROM _sync_log WHERE id > ? ORDER BY id ASC'
        ).all(prevMaxSeq);
    }

    /**
     * 2PC：提交手动事务（COMMIT）
     * 提交后触发 onWrite 回调（用于异步 push-on-write）
     *
     * @param {string} writeId - 必须与 beginManualTransaction 的 writeId 一致
     */
    commitManualTransaction(writeId) {
        this._ensureInitialized();
        if (!this._activeManualTxn || this._activeManualTxn.writeId !== writeId) {
            throw new Error('ConnectionManager: no active manual transaction for writeId=' + writeId);
        }
        this.db.exec('COMMIT');
        this._activeManualTxn = null;
        this._notifyWrite();
    }

    /**
     * 2PC：回滚手动事务（ROLLBACK）
     *
     * @param {string} writeId - 必须与 beginManualTransaction 的 writeId 一致（或 null 强制回滚）
     */
    rollbackManualTransaction(writeId) {
        this._ensureInitialized();
        if (!this._activeManualTxn) return; // 没有活跃事务，忽略
        if (writeId && this._activeManualTxn.writeId !== writeId) {
            throw new Error('ConnectionManager: writeId mismatch in rollback: expected=' + this._activeManualTxn.writeId + ', got=' + writeId);
        }
        try {
            this.db.exec('ROLLBACK');
        } catch (err) {
            // 事务可能已经自动回滚（如 SQLite 错误），忽略
            console.warn('[ConnectionManager] ROLLBACK error (may be already rolled back):', err.message);
        }
        this._activeManualTxn = null;
    }

    /**
     * 2PC：是否有活跃的手动事务
     * @returns {boolean}
     */
    hasActiveManualTransaction() {
        return this._activeManualTxn !== null;
    }

    /**
     * 关闭数据库连接
     */
    close() {
        if (this._activeManualTxn) {
            try { this.db.exec('ROLLBACK'); } catch {}
            this._activeManualTxn = null;
        }
        if (this._readDb) {
            try { this._readDb.close(); } catch {}
            this._readDb = null;
        }
        if (this.db) {
            this.db.close();
            this.db = null;
            this.initialized = false;
        }
    }

    _ensureInitialized() {
        if (!this.initialized) {
            throw new Error('ConnectionManager not initialized. Call initialize() first.');
        }
    }
}

/**
 * 懒初始化连接管理器包装器
 */
class LazyConnectionManager {
    constructor(config) {
        this._config = config;
        this._inner = null;
        this._initialized = false;
    }

    _ensureReady() {
        if (this._initialized) return;
        this._doInitialize();
    }

    _doInitialize() {
        // initializeSchema 在模块顶层导入（见文件底部的 import）
        const cm = new ConnectionManager();
        cm.initialize(this._config);
        initializeSchema(cm.getDatabase());
        this._inner = cm;
        this._initialized = true;
        console.log('[LazyConnectionManager] Database initialized successfully');
    }

    get initialized() { return this._initialized; }

    onWrite(callback) {
        this._ensureReady();
        this._inner.onWrite(callback);
    }

    setExternalManualTxnCheck(fn) {
        this._ensureReady();
        this._inner.setExternalManualTxnCheck(fn);
    }

    writeQuery(sql, params = []) {
        this._ensureReady();
        return this._inner.writeQuery(sql, params);
    }

    readQuery(sql, params = []) {
        this._ensureReady();
        return this._inner.readQuery(sql, params);
    }

    writeTransaction(callback) {
        this._ensureReady();
        return this._inner.writeTransaction(callback);
    }

    getDatabase() {
        this._ensureReady();
        return this._inner.getDatabase();
    }

    // ===== 2PC 手动事务方法代理 =====

    beginManualTransaction(writeId) {
        this._ensureReady();
        return this._inner.beginManualTransaction(writeId);
    }

    getManualTransactionEntries(writeId) {
        this._ensureReady();
        return this._inner.getManualTransactionEntries(writeId);
    }

    commitManualTransaction(writeId) {
        this._ensureReady();
        return this._inner.commitManualTransaction(writeId);
    }

    rollbackManualTransaction(writeId) {
        this._ensureReady();
        return this._inner.rollbackManualTransaction(writeId);
    }

    hasActiveManualTransaction() {
        if (!this._initialized) return false;
        return this._inner.hasActiveManualTransaction();
    }

    close() {
        if (this._inner) {
            this._inner.close();
            this._inner = null;
            this._initialized = false;
        }
    }
}

export default ConnectionManager;
export { LazyConnectionManager };
