/**
 * sync-lib 适配层
 *
 * 将 sgx-wallet 的业务表定义、验证器、反序列化器、DatabaseAdapter
 * 桥接到 sync-lib 的通用接口。
 *
 * 本文件是 sync-lib 与 sgx-wallet 项目之间的唯一桥接点。
 */

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
 * @param {object} engine SyncEngine 实例
 * @returns {object} 与 engine 同接口的门面（write 行为见上）
 */
export function createEngineFacade(engine) {
    return new Proxy(engine, {
        get(target, prop) {
            if (prop === 'write') {
                return async (fn, shardKey) => {
                    if (target.hasActiveManualTransaction()) {
                        return await fn(target.db);
                    }
                    return target.write(fn, shardKey);
                };
            }
            const value = Reflect.get(target, prop);
            return typeof value === 'function' ? value.bind(target) : value;
        },
    });
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
        if (!['platform', 'contract'].includes(rowData.source)) {
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
