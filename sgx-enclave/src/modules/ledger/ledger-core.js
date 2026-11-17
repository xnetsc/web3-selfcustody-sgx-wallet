/**
 * 账本记账核心（纯记账逻辑，只在调用方提供的事务连接上工作）
 *
 * 余额三桶：available（可用）/ frozen（合规冻结）/ withheld（提现在途占用）。
 * 金额一律最小单位整数、十进制字符串存储，BigInt 运算。
 *
 * 不变量（全部在同一事务内校验）：
 *  - 任何桶不得为负；
 *  - 内部转账借贷等额；
 *  - 入账先过冻结路由：命中生效冻结指令的入账先补冻、余下才进可用；
 *  - 出账只动 available；frozen 只经解冻释放，withheld 只经提现核销/回滚释放；
 *  - 同一（账本、用户、链、资产）至多一条生效冻结指令（新建与既有生效指令范围重叠即拒绝）。
 */

import { v4 as uuidv4 } from 'uuid';

export const NATIVE_ASSET = 'native';

/** 校验并归一资产标识：'native' 或小写合约地址 */
export function normalizeAssetId(assetId) {
  if (assetId === NATIVE_ASSET) return NATIVE_ASSET;
  if (typeof assetId === 'string' && /^0x[0-9a-fA-F]{40}$/.test(assetId)) return assetId.toLowerCase();
  throw new Error(`invalid assetId: ${assetId}`);
}

/** 解析金额字符串为 BigInt（必须为非负整数；requirePositive 时必须 > 0） */
export function parseAmount(value, { requirePositive = true } = {}) {
  if (typeof value !== 'string' || !/^\d+$/.test(value)) {
    throw new Error(`invalid amount: ${value}`);
  }
  const amount = BigInt(value);
  if (requirePositive && amount <= 0n) throw new Error('amount must be positive');
  return amount;
}

function rowToBalance(row) {
  if (!row) return { available: 0n, frozen: 0n, withheld: 0n };
  return {
    available: BigInt(row.available),
    frozen: BigInt(row.frozen),
    withheld: BigInt(row.withheld),
  };
}

export class LedgerCore {
  /**
   * @param {{ hlc: () => string, now: () => string }} clock - HLC 滴答与单调时间提供者
   */
  constructor(clock) {
    this._clock = clock;
  }

  getBalance(conn, ledgerId, userId, chainId, assetId) {
    const rows = conn.query(
      'SELECT available, frozen, withheld FROM ledger_balances WHERE ledger_id = ? AND user_id = ? AND chain_id = ? AND asset_id = ?',
      [ledgerId, userId, chainId, assetId]
    );
    return rowToBalance(rows[0]);
  }

  _upsertBalance(conn, ledgerId, userId, chainId, assetId, balance) {
    const ts = this._clock.now();
    const hlc = this._clock.hlc();
    conn.query(
      `INSERT INTO ledger_balances (ledger_id, user_id, chain_id, asset_id, available, frozen, withheld, updated_at, _hlc)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (ledger_id, user_id, chain_id, asset_id)
       DO UPDATE SET available = excluded.available, frozen = excluded.frozen, withheld = excluded.withheld, updated_at = excluded.updated_at, _hlc = excluded._hlc`,
      [ledgerId, userId, chainId, assetId, balance.available.toString(), balance.frozen.toString(), balance.withheld.toString(), ts, hlc]
    );
  }

  _appendEntry(conn, fields) {
    const entryId = uuidv4();
    conn.query(
      `INSERT INTO ledger_entries (entry_id, ledger_id, user_id, chain_id, asset_id, kind, amount,
         available_delta, frozen_delta, withheld_delta, balance_after_available, balance_after_frozen, balance_after_withheld,
         ref_type, ref_id, counterparty_user_id, idempotency_key, created_at, _hlc)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        entryId, fields.ledgerId, fields.userId, fields.chainId, fields.assetId, fields.kind,
        fields.amount.toString(),
        fields.availableDelta.toString(), fields.frozenDelta.toString(), fields.withheldDelta.toString(),
        fields.after.available.toString(), fields.after.frozen.toString(), fields.after.withheld.toString(),
        fields.refType || null, fields.refId || null, fields.counterpartyUserId || null,
        fields.idempotencyKey || null, this._clock.now(), this._clock.hlc(),
      ]
    );
    return entryId;
  }

  _findByIdempotencyKey(conn, ledgerId, idempotencyKey) {
    if (!idempotencyKey) return null;
    const rows = conn.query(
      'SELECT entry_id FROM ledger_entries WHERE ledger_id = ? AND idempotency_key = ?',
      [ledgerId, idempotencyKey]
    );
    return rows[0] || null;
  }

  /** 生效中且覆盖（链、资产）的冻结指令，按创建时间升序 */
  _activeFreezesFor(conn, ledgerId, userId, chainId, assetId) {
    return conn.query(
      `SELECT * FROM ledger_freezes WHERE ledger_id = ? AND user_id = ? AND status = 'active'
         AND (chain_id IS NULL OR chain_id = ?) AND (asset_id IS NULL OR asset_id = ?)
       ORDER BY created_at ASC, freeze_id ASC`,
      [ledgerId, userId, chainId, assetId]
    );
  }

  /**
   * 入账：金额先进冻结路由（补生效定额冻结的待冻额 / 全额冻结全额落冻），余下进可用。
   * @returns {{ entryId: string, frozenPart: bigint, availablePart: bigint, duplicate?: boolean }}
   */
  credit(conn, { ledgerId, userId, chainId, assetId, amount, kind, refType, refId, idempotencyKey, counterpartyUserId }) {
    const value = parseAmount(amount);
    const dup = this._findByIdempotencyKey(conn, ledgerId, idempotencyKey);
    if (dup) return { entryId: dup.entry_id, frozenPart: 0n, availablePart: 0n, duplicate: true };

    let remaining = value;
    let frozenPart = 0n;
    const freezes = this._activeFreezesFor(conn, ledgerId, userId, chainId, assetId);
    for (const freeze of freezes) {
      if (remaining <= 0n) break;
      let take;
      if (freeze.target_amount === null || freeze.target_amount === undefined) {
        take = remaining; // 全额冻结：全部落冻
      } else {
        const capacity = BigInt(freeze.target_amount) - BigInt(freeze.held_amount);
        take = capacity > 0n ? (remaining < capacity ? remaining : capacity) : 0n;
      }
      if (take > 0n) {
        frozenPart += take;
        remaining -= take;
        if (freeze.chain_id !== null && freeze.asset_id !== null && freeze.target_amount !== null && freeze.target_amount !== undefined) {
          conn.query(
            'UPDATE ledger_freezes SET held_amount = ?, updated_at = ?, _hlc = ? WHERE freeze_id = ?',
            [(BigInt(freeze.held_amount) + take).toString(), this._clock.now(), this._clock.hlc(), freeze.freeze_id]
          );
        }
      }
    }

    const balance = this.getBalance(conn, ledgerId, userId, chainId, assetId);
    balance.available += remaining;
    balance.frozen += frozenPart;
    this._upsertBalance(conn, ledgerId, userId, chainId, assetId, balance);

    const entryId = this._appendEntry(conn, {
      ledgerId, userId, chainId, assetId, kind, amount: value,
      availableDelta: remaining, frozenDelta: frozenPart, withheldDelta: 0n,
      after: balance, refType, refId, idempotencyKey, counterpartyUserId,
    });
    return { entryId, frozenPart, availablePart: remaining };
  }

  /**
   * 出账：只扣可用余额（冻结与在途占用不可动）。
   * @returns {{ entryId: string, duplicate?: boolean }}
   */
  debit(conn, { ledgerId, userId, chainId, assetId, amount, kind, refType, refId, idempotencyKey, counterpartyUserId }) {
    const value = parseAmount(amount);
    const dup = this._findByIdempotencyKey(conn, ledgerId, idempotencyKey);
    if (dup) return { entryId: dup.entry_id, duplicate: true };

    const balance = this.getBalance(conn, ledgerId, userId, chainId, assetId);
    if (balance.available < value) {
      throw new Error(`insufficient available balance: have ${balance.available}, need ${value}`);
    }
    balance.available -= value;
    this._upsertBalance(conn, ledgerId, userId, chainId, assetId, balance);

    const entryId = this._appendEntry(conn, {
      ledgerId, userId, chainId, assetId, kind, amount: value,
      availableDelta: -value, frozenDelta: 0n, withheldDelta: 0n,
      after: balance, refType, refId, idempotencyKey, counterpartyUserId,
    });
    return { entryId };
  }

  /** 内部转账：同账本同资产，借贷等额、同一事务。收款方入账同样过冻结路由。 */
  transfer(conn, { ledgerId, fromUserId, toUserId, chainId, assetId, amount, idempotencyKey }) {
    if (fromUserId === toUserId) throw new Error('cannot transfer to self');
    const value = parseAmount(amount);
    const dup = this._findByIdempotencyKey(conn, ledgerId, idempotencyKey);
    if (dup) return { entryId: dup.entry_id, duplicate: true };

    const refId = uuidv4();
    const out = this.debit(conn, {
      ledgerId, userId: fromUserId, chainId, assetId, amount, kind: 'transfer_out',
      refType: 'transfer', refId, idempotencyKey, counterpartyUserId: toUserId,
    });
    this.credit(conn, {
      ledgerId, userId: toUserId, chainId, assetId, amount, kind: 'transfer_in',
      refType: 'transfer', refId, idempotencyKey: idempotencyKey ? `${idempotencyKey}:in` : null,
      counterpartyUserId: fromUserId,
    });
    return { entryId: out.entryId, refId };
  }

  /**
   * 新建冻结指令。targetAmount 为 null 表示全额冻结（含后续入账）；
   * 定额冻结必须指定（chainId, assetId）。创建即把当前可用余额转入冻结（定额至多到目标）。
   * @returns {{ freezeId: string, moved: bigint }}
   */
  freeze(conn, { ledgerId, userId, chainId = null, assetId = null, targetAmount = null, reason = null }) {
    if (targetAmount !== null && targetAmount !== undefined) {
      if (chainId === null || assetId === null) {
        throw new Error('amount freeze requires chainId and assetId');
      }
      parseAmount(targetAmount);
    }
    // 范围重叠检查：同一（账本、用户）下生效指令的（链、资产）范围不得重叠
    const existing = conn.query(
      `SELECT freeze_id, chain_id, asset_id FROM ledger_freezes WHERE ledger_id = ? AND user_id = ? AND status = 'active'`,
      [ledgerId, userId]
    );
    for (const f of existing) {
      const chainOverlap = f.chain_id === null || chainId === null || Number(f.chain_id) === Number(chainId);
      const assetOverlap = f.asset_id === null || assetId === null || f.asset_id === assetId;
      if (chainOverlap && assetOverlap) {
        throw new Error(`an active freeze already covers this scope (freezeId=${f.freeze_id})`);
      }
    }

    const freezeId = uuidv4();
    const ts = this._clock.now();
    conn.query(
      `INSERT INTO ledger_freezes (freeze_id, ledger_id, user_id, chain_id, asset_id, target_amount, held_amount, status, reason, created_at, updated_at, _hlc)
       VALUES (?, ?, ?, ?, ?, ?, '0', 'active', ?, ?, ?, ?)`,
      [freezeId, ledgerId, userId, chainId, assetId, targetAmount ?? null, reason, ts, ts, this._clock.hlc()]
    );

    // 创建即冻结存量：资产特定范围直接处理该资产；全范围逐资产处理
    let moved = 0n;
    const targets = (chainId !== null && assetId !== null)
      ? [{ chainId, assetId }]
      : conn.query(
          'SELECT chain_id, asset_id FROM ledger_balances WHERE ledger_id = ? AND user_id = ?',
          [ledgerId, userId]
        ).map((r) => ({ chainId: Number(r.chain_id), assetId: r.asset_id }));

    for (const t of targets) {
      const balance = this.getBalance(conn, ledgerId, userId, t.chainId, t.assetId);
      if (balance.available <= 0n) continue;
      let take = balance.available;
      if (targetAmount !== null && targetAmount !== undefined) {
        const capacity = BigInt(targetAmount) - moved;
        if (capacity <= 0n) break;
        take = take < capacity ? take : capacity;
      }
      balance.available -= take;
      balance.frozen += take;
      moved += take;
      this._upsertBalance(conn, ledgerId, userId, t.chainId, t.assetId, balance);
      this._appendEntry(conn, {
        ledgerId, userId, chainId: t.chainId, assetId: t.assetId, kind: 'freeze', amount: take,
        availableDelta: -take, frozenDelta: take, withheldDelta: 0n,
        after: balance, refType: 'freeze', refId: freezeId,
      });
    }
    if (targetAmount !== null && targetAmount !== undefined) {
      conn.query(
        'UPDATE ledger_freezes SET held_amount = ?, updated_at = ?, _hlc = ? WHERE freeze_id = ?',
        [moved.toString(), this._clock.now(), this._clock.hlc(), freezeId]
      );
    }
    return { freezeId, moved };
  }

  /**
   * 解冻：amount 省略 = 释放该指令下全部可释放额；定额冻结部分解冻等额下调目标，
   * 目标降至已冻额以下时指令自动失效（status=lifted）；liftAll=true 直接解除指令并全额释放。
   * @returns {{ released: bigint, lifted: boolean }}
   */
  unfreeze(conn, { ledgerId, freezeId, amount = null, liftAll = false }) {
    const rows = conn.query('SELECT * FROM ledger_freezes WHERE ledger_id = ? AND freeze_id = ?', [ledgerId, freezeId]);
    const freeze = rows[0];
    if (!freeze) throw new Error('freeze not found');
    if (freeze.status !== 'active') throw new Error('freeze is not active');

    const assetScoped = freeze.chain_id !== null && freeze.asset_id !== null;
    const targets = assetScoped
      ? [{ chainId: Number(freeze.chain_id), assetId: freeze.asset_id }]
      : conn.query(
          'SELECT chain_id, asset_id FROM ledger_balances WHERE ledger_id = ? AND user_id = ?',
          [ledgerId, freeze.user_id]
        ).map((r) => ({ chainId: Number(r.chain_id), assetId: r.asset_id }));

    let want = (amount === null || amount === undefined) ? null : parseAmount(amount);
    let released = 0n;
    for (const t of targets) {
      if (want !== null && released >= want) break;
      const balance = this.getBalance(conn, ledgerId, freeze.user_id, t.chainId, t.assetId);
      if (balance.frozen <= 0n) continue;
      let take = balance.frozen;
      if (want !== null) {
        const remain = want - released;
        take = take < remain ? take : remain;
      }
      balance.frozen -= take;
      balance.available += take;
      released += take;
      this._upsertBalance(conn, ledgerId, freeze.user_id, t.chainId, t.assetId, balance);
      this._appendEntry(conn, {
        ledgerId, userId: freeze.user_id, chainId: t.chainId, assetId: t.assetId, kind: 'unfreeze', amount: take,
        availableDelta: take, frozenDelta: -take, withheldDelta: 0n,
        after: balance, refType: 'freeze', refId: freezeId,
      });
    }

    let lifted = false;
    let newTarget = freeze.target_amount;
    let newHeld = BigInt(freeze.held_amount);
    if (freeze.target_amount !== null && freeze.target_amount !== undefined) {
      // 定额冻结：解冻等额下调目标与已冻额
      newTarget = (BigInt(freeze.target_amount) - released).toString();
      newHeld = newHeld - released;
      if (newHeld < 0n) newHeld = 0n;
      if (BigInt(newTarget) <= 0n) lifted = true;
    }
    if (liftAll) lifted = true;
    conn.query(
      'UPDATE ledger_freezes SET target_amount = ?, held_amount = ?, status = ?, updated_at = ?, _hlc = ? WHERE freeze_id = ?',
      [lifted ? freeze.target_amount : newTarget, newHeld.toString(), lifted ? 'lifted' : 'active', this._clock.now(), this._clock.hlc(), freezeId]
    );
    return { released, lifted };
  }

  /** 提现占用：available → withheld（冻结先行） */
  withhold(conn, { ledgerId, userId, chainId, assetId, amount, refId, idempotencyKey }) {
    const value = parseAmount(amount);
    const dup = this._findByIdempotencyKey(conn, ledgerId, idempotencyKey);
    if (dup) return { entryId: dup.entry_id, duplicate: true };
    const balance = this.getBalance(conn, ledgerId, userId, chainId, assetId);
    if (balance.available < value) {
      throw new Error(`insufficient available balance: have ${balance.available}, need ${value}`);
    }
    balance.available -= value;
    balance.withheld += value;
    this._upsertBalance(conn, ledgerId, userId, chainId, assetId, balance);
    const entryId = this._appendEntry(conn, {
      ledgerId, userId, chainId, assetId, kind: 'withdraw_hold', amount: value,
      availableDelta: -value, frozenDelta: 0n, withheldDelta: value,
      after: balance, refType: 'withdrawal', refId, idempotencyKey,
    });
    return { entryId };
  }

  /** 提现核销：withheld 直接扣减（资金已出账本） */
  settleWithdrawal(conn, { ledgerId, userId, chainId, assetId, amount, refId }) {
    const value = parseAmount(amount);
    const balance = this.getBalance(conn, ledgerId, userId, chainId, assetId);
    if (balance.withheld < value) {
      throw new Error(`insufficient withheld balance for settlement: have ${balance.withheld}, need ${value}`);
    }
    balance.withheld -= value;
    this._upsertBalance(conn, ledgerId, userId, chainId, assetId, balance);
    return this._appendEntry(conn, {
      ledgerId, userId, chainId, assetId, kind: 'withdraw_settle', amount: value,
      availableDelta: 0n, frozenDelta: 0n, withheldDelta: -value,
      after: balance, refType: 'withdrawal', refId,
    });
  }

  /** 提现回滚：withheld → available */
  releaseWithheld(conn, { ledgerId, userId, chainId, assetId, amount, refId }) {
    const value = parseAmount(amount);
    const balance = this.getBalance(conn, ledgerId, userId, chainId, assetId);
    if (balance.withheld < value) {
      throw new Error(`insufficient withheld balance for release: have ${balance.withheld}, need ${value}`);
    }
    balance.withheld -= value;
    balance.available += value;
    this._upsertBalance(conn, ledgerId, userId, chainId, assetId, balance);
    return this._appendEntry(conn, {
      ledgerId, userId, chainId, assetId, kind: 'withdraw_release', amount: value,
      availableDelta: value, frozenDelta: 0n, withheldDelta: -value,
      after: balance, refType: 'withdrawal', refId,
    });
  }

  /** 是否存在覆盖（用户、链、资产）的生效冻结——提现出款前的合规闸门 */
  hasActiveFreeze(conn, ledgerId, userId, chainId, assetId) {
    return this._activeFreezesFor(conn, ledgerId, userId, chainId, assetId).length > 0;
  }
}
