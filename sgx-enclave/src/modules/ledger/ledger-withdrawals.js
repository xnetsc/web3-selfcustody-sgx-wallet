/**
 * 提现状态机：申请 → 冻结占用 → 出款签名广播 → 链上确认核销；失败解冻回滚
 *
 * 申请：用户 Passkey 授权，SGX 实时读合约风控规则（单笔/日累计限额）强制
 * 校验；出款地址由外部在申请时指定，SGX 只校验它属于该账本的合格归集
 * 地址（合约公布集内、属所有权人账户、原生钱包）。冻结先行（available →
 * withheld），账本层面不可能超提或双花；提现单以授权 opId 幂等。
 *
 * 出款：先签好交易并把原文与哈希落库，再广播——崩溃后可凭原文重播。
 * 出款签名之前复查合规冻结：该（用户、链、资产）存在生效冻结时不出款，
 * 提现单保持冻结占用待冻结解除。确认走读链通道交叉核对，确认数达标才核销。
 */

import { v4 as uuidv4 } from 'uuid';
import { ethers } from 'ethers';
import { getMonotonicSqliteNow } from '../../utils/monotonic-clock.js';
import { normalizeAssetId } from './ledger-core.js';

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const ERC20_IFACE = new ethers.Interface(['function transfer(address to, uint256 amount) returns (bool)']);

async function defaultSign({ provider, privateKey, chainId, assetId, amount, toAddress }) {
  const wallet = new ethers.Wallet(privateKey, provider);
  const base = assetId === 'native'
    ? { to: toAddress, value: BigInt(amount) }
    : { to: assetId, value: 0n, data: ERC20_IFACE.encodeFunctionData('transfer', [toAddress, BigInt(amount)]) };
  const populated = await wallet.populateTransaction({ ...base, chainId: Number(chainId) });
  const rawTx = await wallet.signTransaction(populated);
  return { rawTx, txHash: ethers.Transaction.from(rawTx).hash };
}

async function defaultBroadcast({ provider, rawTx }) {
  await provider.broadcastTransaction(rawTx);
}

export class LedgerWithdrawalService {
  /**
   * @param {Object} deps
   * @param {import('../../database/connection-manager.js').default} deps.connectionManager
   * @param {import('@xnetx/raft-hlc-sync').SyncEngine} deps.engine
   * @param {import('./ledger-service.js').LedgerService} deps.ledgerService
   * @param {import('./ledger-auth.js').LedgerAuthorizer} deps.authorizer
   * @param {import('../contract-client/index.js').ContractClient} deps.contractClient
   * @param {import('./chain-reader.js').ChainReader} deps.chainReader
   * @param {Function} [deps.signFn] - 测试注入用
   * @param {Function} [deps.broadcastFn] - 测试注入用
   */
  constructor(deps) {
    this._db = deps.connectionManager;
    this._engine = deps.engine;
    this._ledger = deps.ledgerService;
    this._authorizer = deps.authorizer;
    this._contract = deps.contractClient;
    this._chainReader = deps.chainReader;
    this._sign = deps.signFn || defaultSign;
    this._broadcast = deps.broadcastFn || defaultBroadcast;
  }

  getWithdrawal(withdrawalId) {
    const rows = this._db.readQuery('SELECT * FROM ledger_withdrawals WHERE withdrawal_id = ?', [withdrawalId]);
    return rows[0] || null;
  }

  listWithdrawals(ledgerId, { userId = null, status = null, limit = 100, offset = 0 } = {}) {
    let sql = 'SELECT * FROM ledger_withdrawals WHERE ledger_id = ?';
    const params = [ledgerId];
    if (userId) { sql += ' AND user_id = ?'; params.push(userId); }
    if (status) { sql += ' AND status = ?'; params.push(status); }
    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);
    return this._db.readQuery(sql, params);
  }

  /** 出款地址资格：合约公布集内 ∧ 所有权人账户的原生钱包 */
  async _assertQualifiedSource(ledgerId, ownerUserId, sourceAddress) {
    const source = String(sourceAddress).toLowerCase();
    let designation;
    try {
      designation = await this._contract.getLedger(ledgerId);
    } catch (err) {
      throw new Error(`Contract unavailable: cannot verify collection address (${err.message})`);
    }
    if (!designation) throw new Error(`ledger ${ledgerId} is not designated on contract`);
    if (!designation.enabled) throw new Error(`ledger ${ledgerId} is disabled`);
    if (designation.ownerUserId !== ownerUserId) throw new Error('ledger owner mismatch with contract designation');
    if (!designation.poolAddresses.some((a) => a.toLowerCase() === source)) {
      throw new Error('source address is not in the ledger collection set published on contract');
    }
    const rows = this._db.readQuery(
      'SELECT wallet_type FROM wallets WHERE user_id = ? AND LOWER(address) = ?',
      [ownerUserId, source]
    );
    if (rows.length === 0) throw new Error('source address is not a wallet of the ledger owner account');
    if (rows[0].wallet_type !== 'native') {
      throw new Error('source wallet is not key-qualified (only native wallets may pay out collection funds)');
    }
  }

  async requestWithdrawal({ ledgerId, payloadJson, signature, chainId, assetId, amount, toAddress, sourceAddress }) {
    const asset = normalizeAssetId(assetId);
    const amountStr = String(amount);
    const verdict = await this._authorizer.verify({
      payloadJson, signature, actorRole: 'user',
      ledgerId, operation: 'withdraw',
      params: {
        chainId: Number(chainId), assetId: asset, amount: amountStr,
        toAddress: String(toAddress).toLowerCase(), sourceAddress: String(sourceAddress).toLowerCase(),
      },
    });
    if (!verdict.approved) throw new Error(`withdrawal rejected: ${verdict.reason}`);
    const userId = verdict.actorUserId;

    const ledgerRow = this._ledger.getLedgerRow(ledgerId);
    if (!ledgerRow) throw new Error(`ledger ${ledgerId} does not exist (not created in SGX)`);

    // 风控规则实时读合约强制校验（未设规则 = 不限；合约不可用 = 拒绝）
    let policy = null;
    try {
      policy = await this._contract.getLedgerWithdrawalPolicy(ledgerId, asset === 'native' ? ZERO_ADDRESS : asset);
    } catch (err) {
      throw new Error(`Contract unavailable: cannot verify withdrawal policy (${err.message})`);
    }
    if (policy) {
      const value = BigInt(amountStr);
      if (BigInt(policy.maxSingleAmount) > 0n && value > BigInt(policy.maxSingleAmount)) {
        throw new Error(`withdrawal exceeds the single-transaction limit (${policy.maxSingleAmount})`);
      }
      if (BigInt(policy.maxDailyAmount) > 0n) {
        const dayStart = new Date(); dayStart.setUTCHours(0, 0, 0, 0);
        const todays = this._db.readQuery(
          `SELECT amount, created_at FROM ledger_withdrawals
           WHERE ledger_id = ? AND user_id = ? AND chain_id = ? AND asset_id = ? AND status IN ('frozen', 'broadcast', 'confirmed')`,
          [ledgerId, userId, Number(chainId), asset]
        );
        let spent = 0n;
        for (const r of todays) {
          if (Date.parse(r.created_at) >= dayStart.getTime()) spent += BigInt(r.amount);
        }
        if (spent + value > BigInt(policy.maxDailyAmount)) {
          throw new Error(`withdrawal exceeds the daily limit (${policy.maxDailyAmount})`);
        }
      }
    }

    await this._assertQualifiedSource(ledgerId, ledgerRow.owner_user_id, sourceAddress);

    return this._ledger.withLedgerWrite(ledgerId, (conn) => {
      const dup = conn.query(
        'SELECT * FROM ledger_withdrawals WHERE ledger_id = ? AND idempotency_key = ?',
        [ledgerId, verdict.opId]
      );
      if (dup.length > 0) return dup[0];

      const withdrawalId = uuidv4();
      this._ledger.core.withhold(conn, {
        ledgerId, userId, chainId: Number(chainId), assetId: asset, amount: amountStr,
        refId: withdrawalId, idempotencyKey: `withdraw-hold:${verdict.opId}`,
      });
      const ts = getMonotonicSqliteNow();
      conn.query(
        `INSERT INTO ledger_withdrawals (withdrawal_id, ledger_id, user_id, chain_id, asset_id, amount, to_address, source_address, status, tx_hash, raw_tx, idempotency_key, created_at, updated_at, _hlc)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'frozen', NULL, NULL, ?, ?, ?, ?)`,
        [withdrawalId, ledgerId, userId, Number(chainId), asset, amountStr,
         String(toAddress).toLowerCase(), String(sourceAddress).toLowerCase(),
         verdict.opId, ts, ts, this._engine.hlc.tick()]
      );
      const rows = conn.query('SELECT * FROM ledger_withdrawals WHERE withdrawal_id = ?', [withdrawalId]);
      return rows[0];
    });
  }

  /** 出款：冻结闸门复查 → 签名落库 → 广播 */
  async executePayout({ ledgerId, withdrawalId }) {
    const row = this.getWithdrawal(withdrawalId);
    if (!row || row.ledger_id !== ledgerId) throw new Error('withdrawal not found');
    if (row.status !== 'frozen' && row.status !== 'broadcast') {
      throw new Error(`withdrawal is not payable (status=${row.status})`);
    }
    const ledgerRow = this._ledger.getLedgerRow(ledgerId);
    await this._assertQualifiedSource(ledgerId, ledgerRow.owner_user_id, row.source_address);

    // 合规冻结闸门：冻结生效期间不出款，提现单保持冻结占用
    const freezeRows = this._db.readQuery(
      `SELECT freeze_id FROM ledger_freezes WHERE ledger_id = ? AND user_id = ? AND status = 'active'
         AND (chain_id IS NULL OR chain_id = ?) AND (asset_id IS NULL OR asset_id = ?)`,
      [ledgerId, row.user_id, Number(row.chain_id), row.asset_id]
    );
    if (freezeRows.length > 0) {
      throw new Error('payout blocked: an active freeze covers this user and asset');
    }

    const channel = await this._chainReader.getBroadcastChannel(Number(row.chain_id));

    let rawTx = row.raw_tx;
    let txHash = row.tx_hash;
    if (!rawTx) {
      const wallets = this._db.readQuery(
        'SELECT private_key FROM wallets WHERE user_id = ? AND LOWER(address) = ? AND chain_id = ?',
        [ledgerRow.owner_user_id, row.source_address, Number(row.chain_id)]
      );
      if (wallets.length === 0) throw new Error('source wallet not found for payout');
      const signed = await this._sign({
        provider: channel.provider, privateKey: wallets[0].private_key,
        chainId: Number(row.chain_id), assetId: row.asset_id, amount: row.amount, toAddress: row.to_address,
      });
      rawTx = signed.rawTx;
      txHash = signed.txHash;
      await this._ledger.withLedgerWrite(ledgerId, (conn) => {
        conn.query(
          `UPDATE ledger_withdrawals SET raw_tx = ?, tx_hash = ?, status = 'broadcast', updated_at = ?, _hlc = ? WHERE withdrawal_id = ? AND status = 'frozen'`,
          [rawTx, txHash, getMonotonicSqliteNow(), this._engine.hlc.tick(), withdrawalId]
        );
      });
    }

    try {
      await this._broadcast({ provider: channel.provider, rawTx });
    } catch (err) {
      // 广播报错不等于未广播：查链上证据定论，避免误回滚造成双付
      const evidence = await this._chainReader.fetchTransferEvidence(Number(row.chain_id), txHash).catch(() => null);
      if (evidence && evidence.found) return { withdrawalId, status: 'broadcast', txHash };
      if (evidence && !evidence.found) {
        await this._failAndRelease(ledgerId, row, 'broadcast failed and transaction not found on chain');
        return { withdrawalId, status: 'failed', txHash };
      }
      throw new Error(`broadcast failed and chain state is uncertain: ${err.message}`);
    }
    return { withdrawalId, status: 'broadcast', txHash };
  }

  /** 刷新提现状态：链上确认 → 核销；链上失败 → 回滚解冻；未上链 → 保持 */
  async refreshWithdrawal({ ledgerId, withdrawalId }) {
    const row = this.getWithdrawal(withdrawalId);
    if (!row || row.ledger_id !== ledgerId) throw new Error('withdrawal not found');
    if (row.status !== 'broadcast') return { withdrawalId, status: row.status };

    const evidence = await this._chainReader.fetchTransferEvidence(Number(row.chain_id), row.tx_hash);
    if (!evidence.found) return { withdrawalId, status: 'broadcast', pending: true };
    if (evidence.status === 0) {
      await this._failAndRelease(ledgerId, row, 'transaction failed on chain');
      return { withdrawalId, status: 'failed' };
    }
    if (evidence.confirmations >= evidence.requiredConfirmations) {
      await this._ledger.withLedgerWrite(ledgerId, (conn) => {
        this._ledger.core.settleWithdrawal(conn, {
          ledgerId, userId: row.user_id, chainId: Number(row.chain_id), assetId: row.asset_id,
          amount: row.amount, refId: withdrawalId,
        });
        conn.query(
          `UPDATE ledger_withdrawals SET status = 'confirmed', updated_at = ?, _hlc = ? WHERE withdrawal_id = ?`,
          [getMonotonicSqliteNow(), this._engine.hlc.tick(), withdrawalId]
        );
      });
      return { withdrawalId, status: 'confirmed' };
    }
    return { withdrawalId, status: 'broadcast', pending: true, confirmations: evidence.confirmations };
  }

  /** 取消尚未出款的提现（用户本人授权）：解冻回滚 */
  async cancelWithdrawal({ ledgerId, payloadJson, signature, withdrawalId }) {
    const verdict = await this._authorizer.verify({
      payloadJson, signature, actorRole: 'user',
      ledgerId, operation: 'withdraw_cancel', params: { withdrawalId },
    });
    if (!verdict.approved) throw new Error(`cancel rejected: ${verdict.reason}`);
    const row = this.getWithdrawal(withdrawalId);
    if (!row || row.ledger_id !== ledgerId) throw new Error('withdrawal not found');
    if (row.user_id !== verdict.actorUserId) throw new Error('only the withdrawing user may cancel');
    if (row.status !== 'frozen') throw new Error(`withdrawal cannot be cancelled (status=${row.status})`);

    await this._ledger.withLedgerWrite(ledgerId, (conn) => {
      this._ledger.core.releaseWithheld(conn, {
        ledgerId, userId: row.user_id, chainId: Number(row.chain_id), assetId: row.asset_id,
        amount: row.amount, refId: withdrawalId,
      });
      conn.query(
        `UPDATE ledger_withdrawals SET status = 'cancelled', updated_at = ?, _hlc = ? WHERE withdrawal_id = ?`,
        [getMonotonicSqliteNow(), this._engine.hlc.tick(), withdrawalId]
      );
    });
    return { withdrawalId, status: 'cancelled' };
  }

  async _failAndRelease(ledgerId, row, _reason) {
    await this._ledger.withLedgerWrite(ledgerId, (conn) => {
      this._ledger.core.releaseWithheld(conn, {
        ledgerId, userId: row.user_id, chainId: Number(row.chain_id), assetId: row.asset_id,
        amount: row.amount, refId: row.withdrawal_id,
      });
      conn.query(
        `UPDATE ledger_withdrawals SET status = 'failed', updated_at = ?, _hlc = ? WHERE withdrawal_id = ?`,
        [getMonotonicSqliteNow(), this._engine.hlc.tick(), row.withdrawal_id]
      );
    });
  }
}
