/**
 * 数据库常量定义
 * SQLite 数据库路径硬编码在加密分区内，不可配置
 */

// 数据库名（保留，用于日志等）
export const DB_NAME = 'sgx_wallet';

// SQLite 数据库文件路径 — 硬编码，位于加密分区（encrypted mount, key = MRENCLAVE）
export const DB_PATH = '/app/sgx-enclave/wallet/sgx_wallet.db';
