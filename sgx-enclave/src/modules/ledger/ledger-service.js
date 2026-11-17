/**
 * 账本服务（编排层）
 *
 * 写纪律：全部账本表写操作经 engine.write 发起，分片键 = 账本所有权人的
 * userId——同一账本的全部记账（跨用户划转、入账、冻结、提现占用）在同一
 * 写域内单事务完成。账本在 SGX 内的存在以 ledgers 表为准：合约指定只是
 * 第一步，账本由所有权人持指定 Passkey 提交创建授权后才存在；未创建的
 * 账本一切操作被拒。所有权与启用状态在每次敏感操作时实时以合约为准，
 * ledgers 表的创建快照不作授权依据。
 */

import { createConnProxy } from '../../sync/sync-adapter.js';
import { getMonotonicSqliteNow } from '../../utils/monotonic-clock.js';
import { LedgerCore, normalizeAssetId } from './ledger-core.js';

export class LedgerService {
  /**
   * @param {Object} deps
   * @param {import('../../database/connection-manager.js').default} deps.connectionManager
   * @param {import('@xnetx/raft-hlc-sync').SyncEngine} deps.engine
   * @param {import('./ledger-auth.js').LedgerAuthorizer} deps.authorizer
   */
  constructor(deps) {
    this._db = deps.connectionManager;
    this._engine = deps.engine;
    this._authorizer = deps.authorizer;
    this.core = new LedgerCore({
      hlc: () => this._engine.hlc.tick(),
      now: () => getMonotonicSqliteNow(),
    });
  }

  // ---------- 基础读写 ----------

  getLedgerRow(ledgerId) {
    const rows = this._db.readQuery('SELECT * FROM ledgers WHERE ledger_id = ?', [ledgerId]);
    return rows[0] || null;
  }

  listLedgers(ownerUserId = null) {
    if (ownerUserId) {
      return this._db.readQuery('SELECT * FROM ledgers WHERE owner_user_id = ? ORDER BY created_at ASC', [ownerUserId]);
    }
    return this._db.readQuery('SELECT * FROM ledgers ORDER BY created_at ASC', []);
  }

  /** 在账本写域（所有权人分片）内执行事务回调；账本不存在即拒绝 */
  async withLedgerWrite(ledgerId, fn) {
    const row = this.getLedgerRow(ledgerId);
    if (!row) throw new Error(`ledger ${ledgerId} does not exist (not created in SGX)`);
    return this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      return fn(conn, row);
    }, row.owner_user_id);
  }

  // ---------- 账本创建（所有权人敏感操作） ----------

  /**
   * 创建账本：授权校验（合约指定 + 指定 Passkey 签名）通过后落 ledgers 表。
   * 一次性：已创建的账本重复创建被拒；他人不可代创（签名者必须正是被指定人）。
   */
  async createLedger({ ledgerId, payloadJson, signature }) {
    const verdict = await this._authorizer.verify({
      payloadJson, signature, actorRole: 'owner',
      ledgerId, operation: 'create_ledger', params: { ledgerId },
    });
    if (!verdict.approved) throw new Error(`ledger creation rejected: ${verdict.reason}`);
    if (this.getLedgerRow(ledgerId)) throw new Error(`ledger ${ledgerId} already created`);

    await this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      const inside = conn.query('SELECT ledger_id FROM ledgers WHERE ledger_id = ?', [ledgerId]);
      if (inside.length > 0) throw new Error(`ledger ${ledgerId} already created`);
      conn.query(
        `INSERT INTO ledgers (ledger_id, owner_user_id, owner_pub_key_hash, created_by_credential_id, created_at, _hlc)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [ledgerId, verdict.actorUserId, verdict.designation.ownerPubKeyHash, verdict.credentialId,
         getMonotonicSqliteNow(), this._engine.hlc.tick()]
      );
    }, verdict.actorUserId);
    return this.getLedgerRow(ledgerId);
  }

  // ---------- 用户操作：内部转账 ----------

  async transfer({ ledgerId, payloadJson, signature, toUserId, chainId, assetId, amount }) {
    const asset = normalizeAssetId(assetId);
    const verdict = await this._authorizer.verify({
      payloadJson, signature, actorRole: 'user',
      ledgerId, operation: 'transfer',
      params: { toUserId, chainId: Number(chainId), assetId: asset, amount: String(amount) },
    });
    if (!verdict.approved) throw new Error(`transfer rejected: ${verdict.reason}`);
    return this.withLedgerWrite(ledgerId, (conn) => this.core.transfer(conn, {
      ledgerId, fromUserId: verdict.actorUserId, toUserId,
      chainId: Number(chainId), assetId: asset, amount: String(amount),
      idempotencyKey: verdict.opId,
    }));
  }

  // ---------- 所有权人操作：冻结 / 解冻 ----------

  async freeze({ ledgerId, payloadJson, signature, targetUserId, chainId = null, assetId = null, targetAmount = null, reason = null }) {
    const asset = assetId === null ? null : normalizeAssetId(assetId);
    const verdict = await this._authorizer.verify({
      payloadJson, signature, actorRole: 'owner',
      ledgerId, operation: 'freeze',
      params: {
        targetUserId,
        chainId: chainId === null ? null : Number(chainId),
        assetId: asset,
        targetAmount: targetAmount === null ? null : String(targetAmount),
      },
    });
    if (!verdict.approved) throw new Error(`freeze rejected: ${verdict.reason}`);
    return this.withLedgerWrite(ledgerId, (conn) => this.core.freeze(conn, {
      ledgerId, userId: targetUserId,
      chainId: chainId === null ? null : Number(chainId),
      assetId: asset, targetAmount: targetAmount === null ? null : String(targetAmount),
      reason,
    }));
  }

  async unfreeze({ ledgerId, payloadJson, signature, freezeId, amount = null, liftAll = false }) {
    const verdict = await this._authorizer.verify({
      payloadJson, signature, actorRole: 'owner',
      ledgerId, operation: 'unfreeze',
      params: { freezeId, amount: amount === null ? null : String(amount), liftAll: !!liftAll },
    });
    if (!verdict.approved) throw new Error(`unfreeze rejected: ${verdict.reason}`);
    return this.withLedgerWrite(ledgerId, (conn) => this.core.unfreeze(conn, {
      ledgerId, freezeId, amount: amount === null ? null : String(amount), liftAll: !!liftAll,
    }));
  }

  // ---------- 查询（只读，账本侧数据） ----------

  getBalance(ledgerId, userId, chainId, assetId) {
    const rows = this._db.readQuery(
      'SELECT available, frozen, withheld FROM ledger_balances WHERE ledger_id = ? AND user_id = ? AND chain_id = ? AND asset_id = ?',
      [ledgerId, userId, Number(chainId), normalizeAssetId(assetId)]
    );
    const row = rows[0];
    return {
      available: row ? row.available : '0',
      frozen: row ? row.frozen : '0',
      withheld: row ? row.withheld : '0',
    };
  }

  listUserBalances(ledgerId, userId) {
    return this._db.readQuery(
      'SELECT chain_id, asset_id, available, frozen, withheld FROM ledger_balances WHERE ledger_id = ? AND user_id = ? ORDER BY chain_id, asset_id',
      [ledgerId, userId]
    );
  }

  listLedgerBalances(ledgerId, { limit = 100, offset = 0 } = {}) {
    return this._db.readQuery(
      'SELECT user_id, chain_id, asset_id, available, frozen, withheld FROM ledger_balances WHERE ledger_id = ? ORDER BY user_id, chain_id, asset_id LIMIT ? OFFSET ?',
      [ledgerId, limit, offset]
    );
  }

  listEntries(ledgerId, { userId = null, kind = null, limit = 100, offset = 0 } = {}) {
    let sql = 'SELECT * FROM ledger_entries WHERE ledger_id = ?';
    const params = [ledgerId];
    if (userId) { sql += ' AND user_id = ?'; params.push(userId); }
    if (kind) { sql += ' AND kind = ?'; params.push(kind); }
    sql += ' ORDER BY created_at DESC, entry_id DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);
    return this._db.readQuery(sql, params);
  }

  totalLiabilities(ledgerId, chainId, assetId) {
    // 金额可超出 int64，汇总在应用层以 BigInt 完成
    const all = this._db.readQuery(
      'SELECT available, frozen, withheld FROM ledger_balances WHERE ledger_id = ? AND chain_id = ? AND asset_id = ?',
      [ledgerId, Number(chainId), normalizeAssetId(assetId)]
    );
    let available = 0n, frozen = 0n, withheld = 0n;
    for (const r of all) {
      available += BigInt(r.available);
      frozen += BigInt(r.frozen);
      withheld += BigInt(r.withheld);
    }
    return {
      available: available.toString(),
      frozen: frozen.toString(),
      withheld: withheld.toString(),
      total: (available + frozen + withheld).toString(),
    };
  }

  listActiveFreezes(ledgerId, userId = null) {
    if (userId) {
      return this._db.readQuery(
        `SELECT * FROM ledger_freezes WHERE ledger_id = ? AND user_id = ? AND status = 'active' ORDER BY created_at ASC`,
        [ledgerId, userId]
      );
    }
    return this._db.readQuery(
      `SELECT * FROM ledger_freezes WHERE ledger_id = ? AND status = 'active' ORDER BY created_at ASC`,
      [ledgerId]
    );
  }
}
