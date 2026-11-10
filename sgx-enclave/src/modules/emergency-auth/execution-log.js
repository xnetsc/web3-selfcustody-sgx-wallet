/**
 * 应急授权执行日志的哈希链工具
 *
 * 每条执行日志是一个链节点：
 *   entry_hash = SHA256(规范序列化(全部业务字段 + prev_hash))
 *   prev_hash  = 上一条的 entry_hash（第一条为 GENESIS_PREV_HASH）
 *
 * 规范序列化是固定字段顺序的 JSON 数组，任何人拿到日志条目都可以按同一
 * 规则重算 entry_hash 并逐条核对 prev_hash 衔接，从而检出改、删、插。
 * 条目随操作响应返回后，响应整体被 server 的 wrap 以 SHA256 注入
 * attestation quote 的 user_report_data —— entry_hash 因此成为度量材料，
 * 日志的真实性由度量值背书，而不仅是数据库自说自话。
 *
 * detail / outcome 只放非敏感摘要（地址、金额、txHash、walletId、计数等
 * 链上或业务公开信息），严禁写入私钥、助记词、加密载荷、签名原文。
 */

import crypto from 'crypto';

export const GENESIS_PREV_HASH = '0x' + '0'.repeat(64);

/** 参与哈希的字段顺序（规范序列化的唯一定义，验算方按此顺序重算） */
export const EXECUTION_LOG_HASH_FIELDS = [
  'createdAt',
  'authorizationId',
  'authHash',
  'operatorUserId',
  'operatorPubKeyHash',
  'platformAddress',
  'targetUserId',
  'operation',
  'executionIndex',
  'detail',
  'result',
  'outcome',
  'prevHash',
];

/**
 * 计算一条执行日志的 entry_hash
 * detail/outcome 接受字符串（存储形态）或对象（对外形态）：对象先按
 * JSON.stringify 归一化为存储形态再参与哈希，两种形态重算结果一致。
 * @param {Object} entry - 字段齐全的日志条目
 * @returns {string} 0x 前缀的 SHA256 hex
 */
export function computeExecutionLogHash(entry) {
  const normalize = (field, value) => {
    if ((field === 'detail' || field === 'outcome') && value !== null && typeof value === 'object') {
      return JSON.stringify(value);
    }
    return value;
  };
  const values = EXECUTION_LOG_HASH_FIELDS.map((field) => normalize(field, entry[field]));
  const canonical = JSON.stringify(values);
  return '0x' + crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * 校验一组日志条目的哈希链完整性（与条目排列/到达顺序无关）
 * 沿 prev_hash → entry_hash 的衔接从创世条目一路走到底：每条 entry_hash
 * 必须可重算；每个 prev_hash 必须恰有一条后继（零条 = 链断裂/有删除，
 * 多条 = 链分叉）；全部条目必须都被链覆盖（有游离条目 = 有插入）。
 * @param {Object[]} entries
 * @returns {{ valid: boolean, reason?: string, brokenAtEntryHash?: string }}
 */
export function verifyExecutionLogChain(entries) {
  for (const entry of entries) {
    if (computeExecutionLogHash(entry) !== entry.entryHash) {
      return { valid: false, reason: 'entry_hash mismatch (entry content was modified)', brokenAtEntryHash: entry.entryHash };
    }
  }
  const byPrevHash = new Map();
  for (const entry of entries) {
    const siblings = byPrevHash.get(entry.prevHash) || [];
    siblings.push(entry);
    byPrevHash.set(entry.prevHash, siblings);
  }
  let cursor = GENESIS_PREV_HASH;
  let visited = 0;
  for (;;) {
    const next = byPrevHash.get(cursor) || [];
    if (next.length === 0) break;
    if (next.length > 1) {
      return { valid: false, reason: 'hash chain forked (multiple entries share the same prev_hash)', brokenAtEntryHash: next[1].entryHash };
    }
    cursor = next[0].entryHash;
    visited++;
  }
  if (entries.length > 0 && visited === 0) {
    return { valid: false, reason: 'no entry chains from the genesis prev_hash (head segment missing)', brokenAtEntryHash: entries[0].entryHash };
  }
  if (visited !== entries.length) {
    return { valid: false, reason: 'entries exist that are not reachable from the genesis chain (insertion or missing middle segment)', brokenAtEntryHash: cursor };
  }
  return { valid: true };
}
