/**
 * 数据库模块统一导出（SQLite 版本）
 */

export { default as ConnectionManager, LazyConnectionManager } from './connection-manager.js';
export {
    DB_NAME,
    DB_PATH,
} from './constants.js';
export {
    initializeSchema,
    dropAllTables,
    cleanExpiredSessions,
    cleanExpiredExportSessions,
    cleanExpiredWebAuthnChallenges,
    CREATE_ACCOUNTS_SQL,
    CREATE_PASSKEYS_SQL,
    CREATE_WALLETS_SQL,
    CREATE_AUTHORIZATION_STATES_SQL,
    CREATE_AUTHORIZATION_TOKEN_STATES_SQL,
    CREATE_AUTHORIZATION_RECORDS_SQL,
    CREATE_IMPORT_SESSIONS_SQL,
    CREATE_EXPORT_SESSIONS_SQL,
    CREATE_TX_SIGN_NONCES_SQL,
    CREATE_WEBAUTHN_CHALLENGES_SQL,
    ALL_TABLE_SQLS,
} from './schema.js';
