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
    return {
        run(sql, params = []) { return sqliteDb.prepare(sql).run(...params); },
        get(sql, params = []) { return sqliteDb.prepare(sql).get(...params) || null; },
        all(sql, params = []) { return sqliteDb.prepare(sql).all(...params); },
        exec(sql)             { sqliteDb.exec(sql); },
    };
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
