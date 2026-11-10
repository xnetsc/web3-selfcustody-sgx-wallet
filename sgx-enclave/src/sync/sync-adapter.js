/**
 * sync-lib 适配层
 *
 * 将 sgx-wallet 的业务表定义、验证器、反序列化器、DatabaseAdapter
 * 桥接到 sync-lib 的通用接口。
 *
 * 本文件是 sync-lib 与 sgx-wallet 项目之间的唯一桥接点。
 */

import { randomUUID } from 'node:crypto';
import { HLC } from '@xnetx/raft-hlc-sync';

// ═══════════════════════════════════════════════════
//  DatabaseAdapter（better-sqlite3 → sync-lib 接口）
// ═══════════════════════════════════════════════════

/**
 * 将 better-sqlite3 Database 实例包装为 sync-lib 的 DatabaseAdapter。
 *
 * 只需提供基础查询方法（run / get / all / exec），
 * 方言相关方法（事务、upsert、schema、触发器）由 SyncEngine 的
 * dialect: 'sqlite' 参数自动填充。
 *
 * @param {import('better-sqlite3').Database} sqliteDb
 * @returns {object} DatabaseAdapter（基础查询部分）
 */
export function createSQLiteAdapter(sqliteDb) {
    // 初始化时单独取出原始函数自持：原始 Database 实例随后会被装上探针
    // （见 ConnectionManager.trapRawDatabases），此后任何人再经实例调用
    // prepare/exec 都只会走到探针报错；适配器凭此处提取的引用继续工作，
    // 且永不再经实例取用原始函数。
    const rawPrepare = sqliteDb.prepare.bind(sqliteDb);
    const rawExec = sqliteDb.exec.bind(sqliteDb);
    return {
        run(sql, params = []) { return rawPrepare(sql).run(...params); },
        get(sql, params = []) { return rawPrepare(sql).get(...params) || null; },
        all(sql, params = []) { return rawPrepare(sql).all(...params); },
        exec(sql)             { rawExec(sql); },
    };
}

// ═══════════════════════════════════════════════════
//  Engine facade（业务层注入用）
// ═══════════════════════════════════════════════════

/**
 * 给业务模块注入的 SyncEngine 门面：只改写 write()，其余成员原样透传。
 *
 * sync-lib 的两种写模式各自语义完整、互不组合：手动事务模式
 * （beginManualTransaction → 直接写库 → 收集触发器条目 → prepare/commit，
 * server 请求框架在用）与 engine.write 独立 2PC 模式（各业务 manager 在用）。
 * 请求处理链上两者会嵌套：外层请求框架已开启手动事务时，manager 再调
 * engine.write 会被库拒绝（Already has active manual transaction）。
 *
 * 本门面是钱包侧的组合约定，不改变库的任何行为：存在活动手动事务时，
 * write(fn) 直接在该事务内执行 fn —— 变更由触发器记入 _sync_log，
 * 由外层事务持有者统一收集条目并完成 prepare/commit，与手动模式的
 * 设计一致；不存在时原样委托 engine.write 走独立 2PC。
 *
 * 门面另提供 withLocalFallback(fn) 给进程内部写专用（HTTP 路径不用）：
 * 在其作用域内，engine.write 协调失败时是否回落本地有严格前提——
 * 只有「联系不上」才回落：prepare 超时无人应答、或根本没有已连接的
 * peer。这类失败里没有任何节点表过态，本地兜底提交、变更经触发器
 * 留在 _sync_log，待后续靠提交广播与 HLC 拉/推传播到其它节点。
 * 「主动拒绝」绝不回落：任一 follower 明确拒绝 prepare（引擎以
 * '2PC prepare rejected:' 报错并广播 abort），或 prepare 期间 term
 * 变更（新 leader 已产生，同为该前缀）——系统已经表态，本地再写就是
 * 绕过裁决。fn 自身的业务错误同样不回落，原样上抛。
 *
 * @param {object} engine SyncEngine 实例
 * @returns {object} 与 engine 同接口的门面（write 行为见上，另加 withLocalFallback）
 */
/**
 * 把协调层错误分类为结构化原因，供调用者准确处理（重试、等待、放弃、
 * 是否回落），不必解析消息文本。
 *
 * refusal=true 表示系统已主动表态拒绝：
 *   - prepare_rejected：某 follower 明确拒绝 prepare，reason 为其原话
 *     （'busy' 事务槽被占 / 'stale term' 任期落后 / 'invalid message' /
 *     应用条目时的错误信息）；
 *   - term_changed：prepare 期间发生新选举，任期已变。
 * refusal=false 为未表态的失败（联系不上类）：
 *   - prepare_timeout / no_connected_peers / no_leader /
 *     leader_unavailable / proxy_timeout。
 * 非协调错误（业务错误等）返回 null。
 *
 * @param {Error} err
 * @returns {{ code: string, reason: string, refusal: boolean } | null}
 */
export function classifyCoordinationError(err) {
    const msg = (err && err.message) || '';
    if (msg.startsWith('2PC prepare rejected: term changed during prepare')) {
        return { code: 'term_changed', reason: msg.slice('2PC prepare rejected: '.length), refusal: true };
    }
    if (msg.startsWith('2PC prepare rejected: ')) {
        return { code: 'prepare_rejected', reason: msg.slice('2PC prepare rejected: '.length), refusal: true };
    }
    if (msg.startsWith('2PC prepare timeout')) {
        return { code: 'prepare_timeout', reason: msg, refusal: false };
    }
    if (msg.startsWith('2PC: no connected peers')) {
        return { code: 'no_connected_peers', reason: msg, refusal: false };
    }
    if (/^shard \d+: no leader/.test(msg)) {
        return { code: 'no_leader', reason: msg, refusal: false };
    }
    if (/^shard \d+: leader peer not available/.test(msg)) {
        return { code: 'leader_unavailable', reason: msg, refusal: false };
    }
    if (msg === 'proxy request timed out') {
        return { code: 'proxy_timeout', reason: msg, refusal: false };
    }
    return null;
}

/**
 * 判定一笔协调写的失败是否允许回落本地（见 createEngineFacade）。
 * 允许的只有「联系不上」：prepare 超时（窗口内无人明确拒绝、只是没等到
 * quorum 应答）与无已连接 peer。引擎的报错形态保证两者可区分：任一
 * follower 明确拒绝时，waitForPrepareAck 立即以 '2PC prepare rejected:'
 * 拒绝并清掉超时，永远不会退化成超时错误；term 变更同为该前缀。
 * @param {Error} err engine.write 抛出的错误
 * @returns {boolean}
 */
export function isLocalFallbackAllowedError(err) {
    const info = classifyCoordinationError(err);
    return !!info && !info.refusal &&
        (info.code === 'prepare_timeout' || info.code === 'no_connected_peers');
}

export function createEngineFacade(engine) {
    let fallbackDepth = 0;
    return new Proxy(engine, {
        get(target, prop) {
            if (prop === 'write') {
                return async (fn, shardKey) => {
                    if (target.hasActiveManualTransaction()) {
                        return await fn(target.db);
                    }
                    try {
                        return await target.write(fn, shardKey);
                    } catch (err) {
                        // 协调错误附结构化原因（code / reason / refusal），
                        // 调用者据此准确处理，不必解析消息文本
                        const info = classifyCoordinationError(err);
                        if (info) {
                            err.code = info.code;
                            err.reason = info.reason;
                            err.refusal = info.refusal;
                        }
                        if (fallbackDepth === 0) throw err;
                        // 回落前提：只有协调对象「联系不上」才回落本地；
                        // 主动拒绝（prepare 被明确拒绝 / term 已变更）与
                        // 业务错误一律原样上抛，不绕过系统的裁决。
                        if (!isLocalFallbackAllowedError(err)) throw err;
                        // 回落本地兜底：手动事务本地提交，
                        // 条目留在 _sync_log，后续 leader 出现后靠同步传播
                        const writeId = 'local-fallback-' + randomUUID();
                        try {
                            target.beginManualTransaction(writeId);
                            const result = await fn(target.db);
                            target.commitManualTransaction(writeId);
                            try { target.broadcastCommit(writeId); } catch (_) {}
                            console.warn(`[SyncEngineFacade] coordinated write incomplete (${err.message}); fell back to local commit`);
                            return result;
                        } catch (_) {
                            try { target.rollbackManualTransaction(writeId); } catch (_) {}
                            throw err;
                        }
                    }
                };
            }
            if (prop === 'withLocalFallback') {
                return async (fn) => {
                    fallbackDepth++;
                    try {
                        return await fn();
                    } finally {
                        fallbackDepth--;
                    }
                };
            }
            const value = Reflect.get(target, prop);
            return typeof value === 'function' ? value.bind(target) : value;
        },
    });
}

/**
 * 在内部写作用域内启用 facade 的本地回落（见 createEngineFacade）。
 * engine 不是 facade（如单元测试桩）时原样执行 fn，不改变行为。
 *
 * @param {object} engine SyncEngine 实例或其 facade
 * @param {function} fn 内部写逻辑
 */
export async function withLocalFallback(engine, fn) {
    if (engine && typeof engine.withLocalFallback === 'function') {
        return engine.withLocalFallback(fn);
    }
    return fn();
}

// ═══════════════════════════════════════════════════
//  内部写的 leader 路由判定
// ═══════════════════════════════════════════════════

/**
 * 进程内部发起的写（定时同步、定时清理、钉住落库等不经 HTTP 写框架的写）
 * 与 HTTP 写请求共用同一条 leader 纪律，不另设内部通道：
 *
 *   - 该分片 leader 是本节点 → 本地执行，与 HTTP 写请求落到 leader 上
 *     执行完全一致；
 *   - 该分片暂无 leader → 本地兜底执行。变更由触发器记入 _sync_log：
 *     有 peer 连接时 engine.write 照常走 2PC 广播，无 peer 时本地提交，
 *     待 leader 出现后靠提交广播与 HLC 拉/推传播到其它节点。这类写入
 *     内容均为幂等、可对账的数据（链上导出 / 状态过期判定），不会写坏；
 *   - 该分片 leader 是其它节点 → 不在本地执行。周期性内部逻辑每个节点
 *     都在跑，该分片的工作由 leader 节点上的同一份逻辑完成，分工结果
 *     与 HTTP 转发到 leader 执行等效。
 *
 * @param {object} engine SyncEngine 实例（或其 facade）
 * @param {string|null} shardKey 分片键（如 userId）；null 表示 shard 0
 * @returns {boolean} 本节点是否应执行这笔内部写
 */
export function shouldExecuteInternalWrite(engine, shardKey) {
    const leader = shardKey ? engine.getLeaderForKey(shardKey) : engine.getLeaderForShard(0);
    return leader == null || leader === engine.nodeId;
}

// ═══════════════════════════════════════════════════
//  业务表定义 + validators + deserializers
// ═══════════════════════════════════════════════════

/**
 * 各业务表的验证器（同步数据写入前校验，防注入）
 */
const TABLE_VALIDATORS = {
    accounts(rowData) {
        if (!rowData.user_id || typeof rowData.user_id !== 'string' || rowData.user_id.length === 0) {
            throw new Error('accounts: user_id is required and must be a non-empty string');
        }
    },
    passkeys(rowData) {
        if (!rowData.user_id || typeof rowData.user_id !== 'string') {
            throw new Error('passkeys: user_id is required');
        }
        if (!rowData.credential_id || typeof rowData.credential_id !== 'string') {
            throw new Error('passkeys: credential_id is required');
        }
        if (!rowData.public_key_cose) {
            throw new Error('passkeys: public_key_cose is required');
        }
    },
    wallets(rowData) {
        if (!rowData.user_id || typeof rowData.user_id !== 'string') {
            throw new Error('wallets: user_id is required');
        }
        if (!rowData.wallet_id || typeof rowData.wallet_id !== 'string') {
            throw new Error('wallets: wallet_id is required');
        }
        if (!rowData.address || typeof rowData.address !== 'string') {
            throw new Error('wallets: address is required');
        }
        if (!/^0x[0-9a-fA-F]{40}$/.test(rowData.address)) {
            throw new Error('wallets: address format invalid: ' + rowData.address);
        }
        if (!rowData.private_key || typeof rowData.private_key !== 'string') {
            throw new Error('wallets: private_key is required');
        }
        const pk = rowData.private_key.startsWith('0x') ? rowData.private_key.slice(2) : rowData.private_key;
        if (!/^[0-9a-fA-F]{64}$/.test(pk)) {
            throw new Error('wallets: private_key format invalid');
        }
    },
    authorization_states(rowData) {
        if (!rowData.user_id || !rowData.authorization_id) {
            throw new Error('authorization_states: user_id and authorization_id are required');
        }
        if (!['active', 'revoked', 'expired', 'exceeded'].includes(rowData.status)) {
            throw new Error('authorization_states: invalid status: ' + rowData.status);
        }
    },
    authorization_revocations(rowData) {
        if (!rowData.user_id || !rowData.authorization_id) {
            throw new Error('authorization_revocations: user_id and authorization_id are required');
        }
        if (!['platform', 'contract', 'emergency'].includes(rowData.source)) {
            throw new Error('authorization_revocations: invalid source: ' + rowData.source);
        }
    },
};

/**
 * passkeys 表的 BLOB 反序列化：hex string → Buffer
 */
function passkeysDeserializer(rowData) {
    if (rowData.public_key_cose && typeof rowData.public_key_cose === 'string') {
        rowData.public_key_cose = Buffer.from(rowData.public_key_cose, 'hex');
    }
    return rowData;
}

/**
 * 所有需要同步的业务表定义
 * 格式与 sync-lib 的 registerTable() 兼容
 */
export const BUSINESS_TABLES = {
    accounts: {
        keyColumns: ['user_id'],
        dataColumns: ['user_id', 'created_at', '_hlc'],
        validator: TABLE_VALIDATORS.accounts,
    },
    passkeys: {
        keyColumns: ['user_id', 'credential_id'],
        dataColumns: ['user_id', 'credential_id', 'public_key_cose', 'sign_count', 'created_at', '_hlc'],
        blobColumns: ['public_key_cose'],
        validator: TABLE_VALIDATORS.passkeys,
        deserializer: passkeysDeserializer,
    },
    wallets: {
        keyColumns: ['user_id', 'chain_id', 'address'],
        dataColumns: ['user_id', 'wallet_id', 'wallet_type', 'mnemonic', 'chain_id', 'coin_type', 'address', 'private_key', 'derivation_path', 'created_at', '_hlc'],
        validator: TABLE_VALIDATORS.wallets,
    },
    authorization_states: {
        keyColumns: ['user_id', 'authorization_id'],
        dataColumns: ['user_id', 'authorization_id', 'grantee', 'total_amount_used', 'total_count_used', 'status', 'created_at', 'updated_at', '_hlc'],
        validator: TABLE_VALIDATORS.authorization_states,
    },
    authorization_token_states: {
        keyColumns: ['authorization_id', 'chain_id', 'token_address'],
        dataColumns: ['authorization_id', 'chain_id', 'token_address', 'amount_used', 'count_used', '_hlc'],
    },
    authorization_records: {
        keyColumns: ['user_id', 'authorization_id'],
        dataColumns: ['user_id', 'authorization_id', 'grantee', 'authorization_json', 'authorization_hash', 'created_at', '_hlc'],
    },
    authorization_revocations: {
        keyColumns: ['user_id', 'authorization_id'],
        dataColumns: ['user_id', 'authorization_id', 'grantee', 'source', 'revoked_at', 'authorization_expires_at', 'authorization_hash', 'created_at', 'updated_at', '_hlc'],
        validator: TABLE_VALIDATORS.authorization_revocations,
    },
    import_sessions: {
        keyColumns: ['session_id'],
        dataColumns: ['session_id', 'user_id', 'key_type', 'secret_key', 'import_type', 'created_at', 'expires_at', '_hlc'],
    },
    export_sessions: {
        keyColumns: ['session_id'],
        dataColumns: ['session_id', 'user_id', 'export_info', 'key_type', 'created_at', 'expires_at', '_hlc'],
    },
    tx_sign_nonces: {
        keyColumns: ['authorization_id', 'guid'],
        dataColumns: ['authorization_id', 'guid', 'created_at', '_hlc'],
    },
    pinned_contract: {
        keyColumns: ['id'],
        dataColumns: ['id', 'rpc_url', 'chain_id', 'contract_address', 'allow_non_ra_tls', 'rpc_tls_ca_cert', 'snapshot_json', 'pinned_at', 'updated_at', '_hlc'],
    },
    account_freezes: {
        keyColumns: ['user_id'],
        dataColumns: ['user_id', 'credential_id', 'frozen_at', 'freeze_until', 'status', 'lifted_at', '_hlc'],
    },
    emergency_authorization_uses: {
        keyColumns: ['authorization_id', 'user_id', 'operation'],
        dataColumns: ['authorization_id', 'user_id', 'operation', 'used_count', 'updated_at', '_hlc'],
    },
    webauthn_challenges: {
        // id 是节点本地自增主键，不参与同步；以全局唯一的 challenge 字符串为同步键
        keyColumns: ['challenge'],
        dataColumns: ['challenge', 'user_id', 'purpose', 'credential_id', 'created_at', 'expires_at', '_hlc'],
    },
};

/**
 * 将所有业务表注册到 SyncEngine
 * @param {import('@xnetx/raft-hlc-sync').SyncEngine} engine
 */
export function registerBusinessTables(engine) {
    for (const [name, def] of Object.entries(BUSINESS_TABLES)) {
        engine.registerTable(name, def);
    }
}

/**
 * 创建兼容 writeTransaction conn.query() 模式的代理对象
 * 将 conn.query(sql, params) 映射到 db adapter 的 run / all 方法，
 * 使现有事务回调代码可在 engine.write() 内复用。
 *
 * @param {object} db - engine.write() 回调中的 db adapter
 * @returns {{ query: (sql: string, params?: any[]) => any }}
 */
export function createConnProxy(db) {
    return {
        query(sql, params = []) {
            const t = sql.trimStart().toUpperCase();
            if (t.startsWith('SELECT') || t.startsWith('WITH')) {
                return db.all(sql, params);
            } else {
                return db.run(sql, params);
            }
        },
    };
}

// ═══════════════════════════════════════════════════
//  代理写的读己之写（接收节点本机补齐）
// ═══════════════════════════════════════════════════

/**
 * 只读校验：一批 sync log 条目的效果是否已在本机业务表可读。
 * INSERT/UPDATE：对应行存在且 _hlc 不旧于条目（相等=已应用，更大=已被更新的写覆盖）；
 * DELETE：对应行已不存在，或已被更新的写重新创建。
 * @param {object} db - engine 的 DatabaseAdapter（只用 get）
 * @param {Array<object>} entries - _sync_log 条目（readSyncLog 形状）
 * @returns {boolean}
 */
export function entriesVisibleLocally(db, entries) {
    for (const entry of entries) {
        const def = BUSINESS_TABLES[entry.table_name];
        if (!def) continue;
        let key;
        try { key = JSON.parse(entry.row_key); } catch { return false; }
        const where = def.keyColumns.map(c => `"${c}" = ?`).join(' AND ');
        const params = def.keyColumns.map(c => key[c]);
        const row = db.get(`SELECT _hlc FROM "${entry.table_name}" WHERE ${where}`, params);
        if (!row) {
            if (entry.operation !== 'DELETE') return false;
            continue;
        }
        const cmp = HLC.compare(row._hlc, entry._hlc);
        if (entry.operation === 'DELETE') {
            if (cmp === 0) return false;
        } else if (cmp < 0) {
            return false;
        }
    }
    return true;
}

/**
 * 把 leader 随代理响应捎回的 sync log 条目补齐到本机，直到可读为止。
 *
 * 入库只走引擎既有接口：以既有 'sync' 消息经 receiveMessage 注入，
 * 由引擎内部 applyEntries 在单个事务内整批应用（全有或全无）；
 * 本函数只负责注入与只读校验，不直接写任何业务表。
 * 注入可能暂时失败（如本机正暂存着该写的 prepare 事务、连接被占用），
 * 轮询重试直到条目可读；超过 deadlineMs 仍不可读则抛错——写已在
 * leader 提交成功，此时报错好过把"返回即可读"的保证静默打破。
 *
 * @param {{ engine: object, peerId: string, entries: Array<object>,
 *           verifyDb?: object, deadlineMs?: number, pollMs?: number }} opts
 *   engine 为本机 SyncEngine（用 receiveMessage 注入）；
 *   peerId 为 leader 在本机引擎中的对端标识（水位/ack 记账用）；
 *   verifyDb 为校验用 DatabaseAdapter——必须是独立只读连接（只见已提交
 *   快照）：引擎写连接在 follower 暂存事务打开时能看到未提交的暂存数据，
 *   拿它校验会把"暂存可见"误判为"已可读"，而暂存可能被回滚。
 *   未传时退回 engine.db（仅单机/测试场景）。
 */
export async function ensureEntriesAppliedLocally({ engine, peerId, entries, verifyDb, deadlineMs = 10000, pollMs = 25 }) {
    if (!entries || entries.length === 0) return;
    const vdb = verifyDb || engine.db;
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));
    const deadline = Date.now() + deadlineMs;
    for (;;) {
        if (entriesVisibleLocally(vdb, entries)) return;
        try { engine.receiveMessage(peerId, JSON.stringify({ type: 'sync', entries })); } catch (_) {}
        if (entriesVisibleLocally(vdb, entries)) return;
        if (Date.now() >= deadline) {
            const err = new Error('proxied write committed on leader but its sync entries are not readable locally within ' + deadlineMs + 'ms');
            err.code = 'local_apply_timeout';
            err.refusal = false;
            throw err;
        }
        await sleep(pollMs);
    }
}
