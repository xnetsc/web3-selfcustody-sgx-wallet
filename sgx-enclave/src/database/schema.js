/**
 * 数据库 Schema 定义和初始化（SQLite 版本）
 * 8 张业务表 + 2 张同步表
 * accounts, passkeys, wallets, authorization_states, authorization_token_states,
 * authorization_records, import_sessions, export_sessions,
 * _sync_log, _sync_peers
 */

import { DB_PATH } from './constants.js';

// ========== 表创建 SQL（SQLite 语法） ==========

export const CREATE_ACCOUNTS_SQL = `
CREATE TABLE IF NOT EXISTS accounts (
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    _hlc TEXT NOT NULL DEFAULT '0',
    PRIMARY KEY (user_id)
)`;

export const CREATE_PASSKEYS_SQL = `
CREATE TABLE IF NOT EXISTS passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    public_key_cose BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    _hlc TEXT NOT NULL DEFAULT '0',
    UNIQUE (user_id, credential_id)
)`;

export const CREATE_PASSKEYS_INDEXES_SQL = [
    `CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys (user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_passkeys_credential_id ON passkeys (credential_id)`,
];

export const CREATE_WALLETS_SQL = `
CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    wallet_id TEXT NOT NULL,
    wallet_type TEXT NOT NULL CHECK (wallet_type IN ('native', 'imported_mnemonic', 'imported_key')),
    mnemonic TEXT,
    chain_id INTEGER NOT NULL,
    coin_type INTEGER NOT NULL,
    address TEXT NOT NULL,
    private_key TEXT NOT NULL,
    derivation_path TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    _hlc TEXT NOT NULL DEFAULT '0',
    UNIQUE (user_id, chain_id, address)
)`;

export const CREATE_WALLETS_INDEXES_SQL = [
    `CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON wallets (user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_wallets_user_wallet ON wallets (user_id, wallet_id)`,
];

export const CREATE_AUTHORIZATION_STATES_SQL = `
CREATE TABLE IF NOT EXISTS authorization_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    authorization_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    grantee TEXT NOT NULL,
    total_amount_used TEXT NOT NULL DEFAULT '0',
    total_count_used INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired', 'exceeded')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    _hlc TEXT NOT NULL DEFAULT '0',
    UNIQUE (user_id, authorization_id)
)`;

export const CREATE_AUTHORIZATION_STATES_INDEXES_SQL = [
    `CREATE INDEX IF NOT EXISTS idx_auth_states_user_id ON authorization_states (user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_auth_states_auth_id ON authorization_states (authorization_id)`,
    `CREATE INDEX IF NOT EXISTS idx_auth_states_grantee ON authorization_states (grantee)`,
];

export const CREATE_AUTHORIZATION_TOKEN_STATES_SQL = `
CREATE TABLE IF NOT EXISTS authorization_token_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    authorization_id TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    token_address TEXT NOT NULL DEFAULT 'native',
    amount_used TEXT NOT NULL DEFAULT '0',
    count_used INTEGER NOT NULL DEFAULT 0,
    _hlc TEXT NOT NULL DEFAULT '0',
    UNIQUE (authorization_id, chain_id, token_address)
)`;

export const CREATE_AUTHORIZATION_TOKEN_STATES_INDEXES_SQL = [
    `CREATE INDEX IF NOT EXISTS idx_auth_token_states_auth_id ON authorization_token_states (authorization_id)`,
];

export const CREATE_IMPORT_SESSIONS_SQL = `
CREATE TABLE IF NOT EXISTS import_sessions (
    session_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    key_type TEXT NOT NULL DEFAULT 'ecdh',
    secret_key TEXT NOT NULL,
    import_type TEXT NOT NULL CHECK (import_type IN ('private_key', 'mnemonic', 'batch')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    _hlc TEXT NOT NULL DEFAULT '0',
    PRIMARY KEY (session_id)
)`;

export const CREATE_IMPORT_SESSIONS_INDEXES_SQL = [
    `CREATE INDEX IF NOT EXISTS idx_import_sessions_user_id ON import_sessions (user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_import_sessions_expires ON import_sessions (expires_at)`,
];

export const CREATE_EXPORT_SESSIONS_SQL = `
CREATE TABLE IF NOT EXISTS export_sessions (
    session_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    export_info TEXT NOT NULL,
    key_type TEXT NOT NULL DEFAULT 'ecdh',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    _hlc TEXT NOT NULL DEFAULT '0',
    PRIMARY KEY (session_id)
)`;

export const CREATE_EXPORT_SESSIONS_INDEXES_SQL = [
    `CREATE INDEX IF NOT EXISTS idx_export_sessions_user_id ON export_sessions (user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_export_sessions_expires ON export_sessions (expires_at)`,
];

export const CREATE_AUTHORIZATION_RECORDS_SQL = `
CREATE TABLE IF NOT EXISTS authorization_records (
    authorization_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    grantee TEXT NOT NULL,
    authorization_json TEXT NOT NULL,
    authorization_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    _hlc TEXT NOT NULL DEFAULT '0',
    PRIMARY KEY (user_id, authorization_id)
)`;

export const CREATE_AUTHORIZATION_RECORDS_INDEXES_SQL = [
    `CREATE INDEX IF NOT EXISTS idx_auth_records_auth_id ON authorization_records (authorization_id)`,
    `CREATE INDEX IF NOT EXISTS idx_auth_records_user_id ON authorization_records (user_id)`,
];

// ========== 签名防重放表 ==========

export const CREATE_TX_SIGN_NONCES_SQL = `
CREATE TABLE IF NOT EXISTS tx_sign_nonces (
    authorization_id TEXT NOT NULL,
    guid TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    _hlc TEXT NOT NULL DEFAULT '0',
    PRIMARY KEY (authorization_id, guid)
)`;

export const CREATE_TX_SIGN_NONCES_INDEXES_SQL = [
    `CREATE INDEX IF NOT EXISTS idx_tx_sign_nonces_auth_id ON tx_sign_nonces (authorization_id)`,
];

// ========== WebAuthn 挑战值存储表 ==========

export const CREATE_WEBAUTHN_CHALLENGES_SQL = `
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('register', 'register_passkey', 'authenticate', 'wallet_create', 'wallet_delete', 'passkey_delete', 'wallet_entry_delete', 'key_export', 'key_export_confirm', 'evidence_query', 'key_import_init', 'key_import_complete')),
    credential_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    _hlc TEXT NOT NULL DEFAULT '0'
)`;

export const CREATE_WEBAUTHN_CHALLENGES_INDEXES_SQL = [
    `CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_id ON webauthn_challenges (user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires ON webauthn_challenges (expires_at)`,
];

// ========== 账户冻结表 ==========

export const CREATE_ACCOUNT_FREEZES_SQL = `
CREATE TABLE IF NOT EXISTS account_freezes (
    user_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    frozen_at TEXT NOT NULL DEFAULT (datetime('now')),
    freeze_until TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'frozen' CHECK (status IN ('frozen', 'lifted')),
    lifted_at TEXT,
    _hlc TEXT NOT NULL DEFAULT '0',
    PRIMARY KEY (user_id)
)`;

export const CREATE_ACCOUNT_FREEZES_INDEXES_SQL = [
    `CREATE INDEX IF NOT EXISTS idx_account_freezes_credential_id ON account_freezes (credential_id)`,
    `CREATE INDEX IF NOT EXISTS idx_account_freezes_status ON account_freezes (status)`,
];

// ========== 合约身份钉住表（安全：防止 env 注入替换合约） ==========

// 单行表（id 恒为 1）。首次成功读到合约数据时写入合约身份 + 最近一次已知的
// 安全相关合约配置快照（runtimeParams / 白名单 / codeRepository）。
// 一旦钉住，enclave 永久使用该合约身份，忽略环境变量里的合约连接参数；
// 钉住的合约不可达时使用该快照作为最后已知配置，绝不回退到环境变量。
// 参与跨节点同步（HLC LWW），确保所有节点用同一份钉住数据。
export const CREATE_PINNED_CONTRACT_SQL = `
CREATE TABLE IF NOT EXISTS pinned_contract (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    rpc_url TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    contract_address TEXT NOT NULL,
    allow_non_ra_tls INTEGER NOT NULL DEFAULT 0,
    snapshot_json TEXT,
    pinned_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    _hlc TEXT NOT NULL DEFAULT '0'
)`;

// ========== 同步表 ==========

export const CREATE_SYNC_LOG_SQL = `
CREATE TABLE IF NOT EXISTS _sync_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
    row_key TEXT NOT NULL,
    row_data TEXT,
    _hlc TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
)`;

export const CREATE_SYNC_LOG_INDEXES_SQL = [
    `CREATE INDEX IF NOT EXISTS idx_sync_log_id ON _sync_log (id)`,
];

export const CREATE_SYNC_PEERS_SQL = `
CREATE TABLE IF NOT EXISTS _sync_peers (
    peer_url TEXT NOT NULL,
    last_sync_id INTEGER NOT NULL DEFAULT 0,
    last_sync_at TEXT,
    PRIMARY KEY (peer_url)
)`;

export const CREATE_TOMBSTONES_SQL = `
CREATE TABLE IF NOT EXISTS _tombstones (
    table_name TEXT NOT NULL,
    row_key TEXT NOT NULL,
    _hlc TEXT NOT NULL,
    PRIMARY KEY (table_name, row_key)
)`;

// 所有建表 SQL 按创建顺序排列
export const ALL_TABLE_SQLS = [
    { name: 'accounts', sql: CREATE_ACCOUNTS_SQL, indexes: [] },
    { name: 'passkeys', sql: CREATE_PASSKEYS_SQL, indexes: CREATE_PASSKEYS_INDEXES_SQL },
    { name: 'wallets', sql: CREATE_WALLETS_SQL, indexes: CREATE_WALLETS_INDEXES_SQL },
    { name: 'authorization_states', sql: CREATE_AUTHORIZATION_STATES_SQL, indexes: CREATE_AUTHORIZATION_STATES_INDEXES_SQL },
    { name: 'authorization_token_states', sql: CREATE_AUTHORIZATION_TOKEN_STATES_SQL, indexes: CREATE_AUTHORIZATION_TOKEN_STATES_INDEXES_SQL },
    { name: 'authorization_records', sql: CREATE_AUTHORIZATION_RECORDS_SQL, indexes: CREATE_AUTHORIZATION_RECORDS_INDEXES_SQL },
    { name: 'import_sessions', sql: CREATE_IMPORT_SESSIONS_SQL, indexes: CREATE_IMPORT_SESSIONS_INDEXES_SQL },
    { name: 'export_sessions', sql: CREATE_EXPORT_SESSIONS_SQL, indexes: CREATE_EXPORT_SESSIONS_INDEXES_SQL },
    { name: 'tx_sign_nonces', sql: CREATE_TX_SIGN_NONCES_SQL, indexes: CREATE_TX_SIGN_NONCES_INDEXES_SQL },
    { name: 'webauthn_challenges', sql: CREATE_WEBAUTHN_CHALLENGES_SQL, indexes: CREATE_WEBAUTHN_CHALLENGES_INDEXES_SQL },
    { name: 'account_freezes', sql: CREATE_ACCOUNT_FREEZES_SQL, indexes: CREATE_ACCOUNT_FREEZES_INDEXES_SQL },
    { name: 'pinned_contract', sql: CREATE_PINNED_CONTRACT_SQL, indexes: [] },
    { name: '_sync_log', sql: CREATE_SYNC_LOG_SQL, indexes: CREATE_SYNC_LOG_INDEXES_SQL },
    { name: '_sync_peers', sql: CREATE_SYNC_PEERS_SQL, indexes: [] },
    { name: '_tombstones', sql: CREATE_TOMBSTONES_SQL, indexes: [] },
];

/**
 * 初始化数据库 Schema（SQLite 版本）
 * 直接在已打开的数据库上创建所有表和索引
 * @param {import('better-sqlite3').Database} db - better-sqlite3 数据库实例
 */
export function initializeSchema(db) {
    // 启用 WAL 模式（性能更好，允许并发读）
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');

    for (const { name, sql, indexes } of ALL_TABLE_SQLS) {
        db.exec(sql);
        for (const indexSql of indexes) {
            db.exec(indexSql);
        }
        console.log(`Table '${name}' ensured.`);
    }

    console.log('Database schema initialized successfully.');
}

/**
 * 删除所有表（测试用）
 * @param {import('better-sqlite3').Database} db - better-sqlite3 数据库实例
 */
export function dropAllTables(db) {
    const reversedTables = [...ALL_TABLE_SQLS].reverse();
    for (const { name } of reversedTables) {
        db.exec(`DROP TABLE IF EXISTS ${name}`);
    }
    console.log('All tables dropped.');
}

/**
 * 清理过期的导入会话
 * @param {import('./connection-manager.js').default} connectionManager
 * @returns {number} 删除的记录数
 */
export function cleanExpiredSessions(connectionManager) {
    const result = connectionManager.writeQuery(
        "DELETE FROM import_sessions WHERE expires_at < datetime('now')"
    );
    if (result.changes > 0) {
        console.log(`Cleaned ${result.changes} expired import sessions.`);
    }
    return result.changes;
}

/**
 * 清理过期的导出会话（仅删除会话记录，不删除钱包）
 *
 * 钱包删除只在 confirmExport（客户端主动确认已收到加密数据）时执行。
 * TTL 过期只清理会话记录，避免因 HTTP 响应未到达客户端而导致私钥/助记词丢失。
 *
 * @param {import('./connection-manager.js').default} connectionManager
 * @returns {number} 删除的会话数
 */
export function cleanExpiredExportSessions(connectionManager) {
    const result = connectionManager.writeQuery(
        "DELETE FROM export_sessions WHERE expires_at < datetime('now')"
    );
    if (result.changes > 0) {
        console.log(`Cleaned ${result.changes} expired export sessions (wallets preserved).`);
    }
    return result.changes;
}

/**
 * 清理过期的 WebAuthn 挑战值
 * @param {import('./connection-manager.js').default} connectionManager
 * @returns {number} 删除的记录数
 */
export function cleanExpiredWebAuthnChallenges(connectionManager) {
    const result = connectionManager.writeQuery(
        "DELETE FROM webauthn_challenges WHERE expires_at < datetime('now')"
    );
    if (result.changes > 0) {
        console.log(`[Schema] Cleaned ${result.changes} expired webauthn challenges.`);
    }
    return result.changes;
}
