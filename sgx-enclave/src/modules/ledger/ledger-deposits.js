/**
 * 专属充值地址开通 + 充值观察入账 + 待认领认领
 *
 * 开通：外部只给 (ledgerId, userId, chainId)，SGX 在所有权人账户下生成普通
 * 钱包并在同一次写入中登记归属映射、给钱包打永久禁止导出标记；接口幂等，
 * 已有映射直接返回原地址，调用方不能指定地址、映射只写一次不可改绑。
 *
 * 入账走观察提交式：外部报 txHash，SGX 经资产读链通道自读收据并交叉核对，
 * 按收款地址反查归属映射定归属；金额、方向只认链上证据，外部只能影响时效。
 * 到账地址不在该账本合约公布集内、或账本被停用、或地址无归属映射的，
 * 一律记待认领，不自动入账。
 */

import { v4 as uuidv4 } from 'uuid';
import { createConnProxy } from '../../sync/sync-adapter.js';
import { getMonotonicSqliteNow } from '../../utils/monotonic-clock.js';
import { generateMnemonic, deriveWallet } from '../wallet-management/hd-wallet.js';

const EVM_COIN_TYPE = 60;

export class LedgerDepositService {
  /**
   * @param {Object} deps
   * @param {import('../../database/connection-manager.js').default} deps.connectionManager
   * @param {import('@xnetx/raft-hlc-sync').SyncEngine} deps.engine
   * @param {import('./ledger-service.js').LedgerService} deps.ledgerService
   * @param {import('./ledger-auth.js').LedgerAuthorizer} deps.authorizer
   * @param {import('../contract-client/index.js').ContractClient} deps.contractClient
   * @param {import('./chain-reader.js').ChainReader} deps.chainReader
   */
  constructor(deps) {
    this._db = deps.connectionManager;
    this._engine = deps.engine;
    this._ledger = deps.ledgerService;
    this._authorizer = deps.authorizer;
    this._contract = deps.contractClient;
    this._chainReader = deps.chainReader;
  }

  getAssignment(ledgerId, userId, chainId) {
    const rows = this._db.readQuery(
      'SELECT * FROM ledger_deposit_addresses WHERE ledger_id = ? AND user_id = ? AND chain_id = ?',
      [ledgerId, userId, Number(chainId)]
    );
    return rows[0] || null;
  }

  /** 开通专属充值地址（幂等：已有则返回原址） */
  async getOrCreateDepositAddress({ ledgerId, userId, chainId }) {
    const existing = this.getAssignment(ledgerId, userId, chainId);
    if (existing) return { address: existing.address, created: false };

    const ledgerRow = this._ledger.getLedgerRow(ledgerId);
    if (!ledgerRow) throw new Error(`ledger ${ledgerId} does not exist (not created in SGX)`);
    const ownerUserId = ledgerRow.owner_user_id;

    return this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      const inside = conn.query(
        'SELECT address FROM ledger_deposit_addresses WHERE ledger_id = ? AND user_id = ? AND chain_id = ?',
        [ledgerId, userId, Number(chainId)]
      );
      if (inside.length > 0) return { address: inside[0].address, created: false };

      const mnemonic = generateMnemonic(128);
      const derived = deriveWallet(mnemonic, EVM_COIN_TYPE);
      const walletId = uuidv4();
      const ts = getMonotonicSqliteNow();
      // 普通钱包行 + 永久禁止导出标记，与归属映射同一次写入
      conn.query(
        `INSERT INTO wallets (user_id, wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, derivation_path, export_locked, created_at, _hlc)
         VALUES (?, ?, 'native', ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
        [ownerUserId, walletId, mnemonic, Number(chainId), EVM_COIN_TYPE, derived.address,
         derived.privateKey, derived.derivationPath, ts, this._engine.hlc.tick()]
      );
      conn.query(
        `INSERT INTO ledger_deposit_addresses (ledger_id, user_id, chain_id, address, owner_user_id, wallet_id, created_at, _hlc)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [ledgerId, userId, Number(chainId), derived.address, ownerUserId, walletId, ts, this._engine.hlc.tick()]
      );
      return { address: derived.address, created: true };
    }, ownerUserId);
  }

  /**
   * 观察一笔链上交易并处理其中与本账本相关的转账（充值入账入口）
   * @returns {Promise<Array<{logIndex: number, assetId: string, to: string, amount: string, status: string}>>}
   */
  async observeDeposit({ ledgerId, chainId, txHash }) {
    const ledgerRow = this._ledger.getLedgerRow(ledgerId);
    if (!ledgerRow) throw new Error(`ledger ${ledgerId} does not exist (not created in SGX)`);

    // 实时指定：公布集与启用状态以合约当场为准（合约不可用则按未启用处理，本次只记待认领/待确认）
    let designation = null;
    try {
      designation = await this._contract.getLedger(ledgerId);
    } catch {
      designation = null;
    }
    const poolSet = new Set((designation?.poolAddresses || []).map((a) => a.toLowerCase()));
    const ledgerEnabled = !!(designation && designation.enabled);

    const evidence = await this._chainReader.fetchTransferEvidence(Number(chainId), txHash);
    const results = [];

    for (const transfer of evidence.transfers) {
      const to = String(transfer.to).toLowerCase();
      const assignmentRows = this._db.readQuery(
        'SELECT * FROM ledger_deposit_addresses WHERE ledger_id = ? AND chain_id = ? AND LOWER(address) = ?',
        [ledgerId, Number(chainId), to]
      );
      const assignment = assignmentRows[0] || null;
      const inPool = poolSet.has(to);
      if (!assignment && !inPool) continue; // 与本账本无关

      const outcome = await this._ledger.withLedgerWrite(ledgerId, (conn) => {
        const existingRows = conn.query(
          'SELECT * FROM ledger_deposits WHERE chain_id = ? AND tx_hash = ? AND log_index = ?',
          [Number(chainId), txHash.toLowerCase(), transfer.logIndex]
        );
        const existing = existingRows[0] || null;
        if (existing && existing.ledger_id !== ledgerId) {
          return { status: 'foreign' }; // 该笔转账已归属另一账本（地址被多账本公布时以先记者为准）
        }
        if (existing && existing.status === 'credited') {
          return { status: 'credited' };
        }

        const enoughConfirmations = evidence.confirmations >= evidence.requiredConfirmations;
        const creditable = enoughConfirmations && !!assignment && inPool && ledgerEnabled;
        const status = !enoughConfirmations ? 'pending' : (creditable ? 'credited' : 'unclaimed');
        const ts = getMonotonicSqliteNow();
        let depositId = existing?.deposit_id;

        if (!existing) {
          depositId = uuidv4();
          conn.query(
            `INSERT INTO ledger_deposits (deposit_id, ledger_id, user_id, chain_id, asset_id, tx_hash, log_index, from_address, to_address, amount, status, confirmations_seen, created_at, updated_at, _hlc)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [depositId, ledgerId, assignment ? assignment.user_id : null, Number(chainId), transfer.assetId,
             txHash.toLowerCase(), transfer.logIndex, transfer.from, to, transfer.amount,
             status, evidence.confirmations, ts, ts, this._engine.hlc.tick()]
          );
        } else {
          conn.query(
            `UPDATE ledger_deposits SET status = ?, confirmations_seen = ?, updated_at = ?, _hlc = ? WHERE deposit_id = ?`,
            [status, evidence.confirmations, ts, this._engine.hlc.tick(), depositId]
          );
        }

        if (status === 'credited') {
          this._ledger.core.credit(conn, {
            ledgerId, userId: assignment.user_id, chainId: Number(chainId), assetId: transfer.assetId,
            amount: transfer.amount, kind: 'deposit', refType: 'deposit', refId: depositId,
            idempotencyKey: `deposit:${chainId}:${txHash.toLowerCase()}:${transfer.logIndex}`,
          });
        }
        return { status };
      });

      results.push({
        logIndex: transfer.logIndex, assetId: transfer.assetId,
        to, amount: transfer.amount, status: outcome.status,
      });
    }
    return results;
  }

  /** 待认领认领：所有权人授权，把一笔待认领充值记入指定用户 */
  async claimDeposit({ ledgerId, payloadJson, signature, depositId, targetUserId }) {
    const verdict = await this._authorizer.verify({
      payloadJson, signature, actorRole: 'owner',
      ledgerId, operation: 'claim_deposit', params: { depositId, targetUserId },
    });
    if (!verdict.approved) throw new Error(`claim rejected: ${verdict.reason}`);

    return this._ledger.withLedgerWrite(ledgerId, (conn) => {
      const rows = conn.query('SELECT * FROM ledger_deposits WHERE ledger_id = ? AND deposit_id = ?', [ledgerId, depositId]);
      const deposit = rows[0];
      if (!deposit) throw new Error('deposit not found');
      if (deposit.status !== 'unclaimed') throw new Error(`deposit is not unclaimed (status=${deposit.status})`);
      this._ledger.core.credit(conn, {
        ledgerId, userId: targetUserId, chainId: Number(deposit.chain_id), assetId: deposit.asset_id,
        amount: deposit.amount, kind: 'deposit', refType: 'deposit', refId: depositId,
        idempotencyKey: `deposit-claim:${depositId}`,
      });
      conn.query(
        `UPDATE ledger_deposits SET status = 'credited', user_id = ?, updated_at = ?, _hlc = ? WHERE deposit_id = ?`,
        [targetUserId, getMonotonicSqliteNow(), this._engine.hlc.tick(), depositId]
      );
      return { depositId, status: 'credited', userId: targetUserId };
    });
  }

  // ---------- 查询 ----------

  listDeposits(ledgerId, { userId = null, status = null, limit = 100, offset = 0 } = {}) {
    let sql = 'SELECT * FROM ledger_deposits WHERE ledger_id = ?';
    const params = [ledgerId];
    if (userId) { sql += ' AND user_id = ?'; params.push(userId); }
    if (status) { sql += ' AND status = ?'; params.push(status); }
    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);
    return this._db.readQuery(sql, params);
  }

  getDepositsByTxHash(chainId, txHash) {
    return this._db.readQuery(
      'SELECT * FROM ledger_deposits WHERE chain_id = ? AND tx_hash = ? ORDER BY log_index ASC',
      [Number(chainId), String(txHash).toLowerCase()]
    );
  }

  listDepositAddresses(ledgerId) {
    return this._db.readQuery(
      'SELECT ledger_id, user_id, chain_id, address, created_at FROM ledger_deposit_addresses WHERE ledger_id = ? ORDER BY user_id, chain_id',
      [ledgerId]
    );
  }

  /** 逐地址累计入账额（归集决策数据之一；链上余额由外部自查） */
  creditedTotalsByAddress(ledgerId, chainId) {
    const rows = this._db.readQuery(
      `SELECT to_address, asset_id, amount FROM ledger_deposits
       WHERE ledger_id = ? AND chain_id = ? AND status = 'credited'`,
      [ledgerId, Number(chainId)]
    );
    const totals = new Map();
    for (const r of rows) {
      const key = `${r.to_address}|${r.asset_id}`;
      totals.set(key, (totals.get(key) || 0n) + BigInt(r.amount));
    }
    return [...totals.entries()].map(([key, total]) => {
      const [address, assetId] = key.split('|');
      return { address, assetId, creditedTotal: total.toString() };
    });
  }
}
