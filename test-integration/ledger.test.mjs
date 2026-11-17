/**
 * 平台账本（站内资产）业务逻辑测试
 *
 * 运行：node --test test-integration/ledger.test.mjs
 *
 * 覆盖：
 *   - 账本创建：合约指定 + 指定 Passkey 签名才可创建；未指定/停用/合约不可用/
 *     非指定人/重复创建全部拒绝
 *   - 记账核心：入账冻结路由（定额待冻额、全额、全范围）、出账只扣可用、
 *     内部转账借贷等额与幂等、冻结范围重叠拒绝、解冻（部分/全额/解除）、
 *     提现占用-核销-回滚三桶流转
 *   - 服务层授权：用户转账与所有权人冻结的签名/参数一致性校验
 *
 * 合约客户端与 WebAuthn 验签以桩注入（合约指定语义由 contracts 的 Hardhat
 * 测试覆盖）；账本核心、服务、Passkey 管理为真实模块 + 内存 SQLite。
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';

import { ALL_TABLE_SQLS } from '../sgx-enclave/src/database/schema.js';
import { PasskeyManager } from '../sgx-enclave/src/modules/webauthn/passkey-manager.js';
import { LedgerAuthorizer } from '../sgx-enclave/src/modules/ledger/ledger-auth.js';
import { LedgerService } from '../sgx-enclave/src/modules/ledger/ledger-service.js';
import { createConnProxy } from '../sgx-enclave/src/sync/sync-adapter.js';

const OWNER = 'ledger-owner';
const OWNER_CRED = 'owner-cred-1';
const OWNER_COSE = Buffer.from('owner-passkey-cose-material');
const OWNER_HASH = PasskeyManager.computePubKeyHash(OWNER_COSE);

const ALICE = 'user-alice';
const ALICE_CRED = 'alice-cred-1';
const ALICE_COSE = Buffer.from('alice-passkey-cose-material');
const BOB = 'user-bob';

const LEDGER = 'ledger-main';
const CHAIN = 1;
const USDT = '0xdac17f958d2ee523a2206206994597c13d831ec7';

const GOOD_SIG = { __valid: true };
const BAD_SIG = { __valid: false };

function makeDb() {
  const db = new Database(':memory:');
  for (const t of ALL_TABLE_SQLS) {
    db.exec(t.sql);
    for (const idx of t.indexes || []) db.exec(idx);
  }
  return db;
}

function makeConnMgr(db) {
  return {
    readQuery(sql, params = []) { return db.prepare(sql).all(...params); },
    writeQuery(sql, params = []) { return db.prepare(sql).run(...params); },
  };
}

function makeFakeEngine(db) {
  let counter = 0;
  const adapter = {
    all: (sql, params = []) => db.prepare(sql).all(...params),
    run: (sql, params = []) => db.prepare(sql).run(...params),
    get: (sql, params = []) => db.prepare(sql).get(...params),
  };
  return {
    nodeId: 'test-node',
    hlc: { tick: () => String(++counter).padStart(16, '0') },
    getLeaderForKey: () => null,
    getLeaderForShard: () => null,
    async write(fn) {
      db.exec('BEGIN');
      try {
        const result = await fn(adapter);
        db.exec('COMMIT');
        return result;
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }
    },
  };
}

/** 合约桩：账本指定可动态调整 */
function makeMockContract() {
  return {
    designations: new Map(),
    unavailable: false,
    async getLedger(ledgerId) {
      if (this.unavailable) throw new Error('RPC unreachable');
      return this.designations.get(ledgerId) || null;
    },
  };
}

let opCounter = 0;
function payload({ ledgerId = LEDGER, actorUserId, credentialId, operation, params = {} }) {
  return JSON.stringify({
    type: 'ledger_op', version: 1,
    ledgerId, actorUserId, credentialId, operation, params,
    opId: `op-${++opCounter}`,
    expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
  });
}

function setup() {
  const db = makeDb();
  const connMgr = makeConnMgr(db);
  const engine = makeFakeEngine(db);
  const contract = makeMockContract();
  const passkeyManager = new PasskeyManager(connMgr, engine);
  const authorizer = new LedgerAuthorizer({
    passkeyManager,
    contractClient: contract,
    verifyWebAuthnSignatureFn: async ({ webauthnSignature }) => ({
      verified: webauthnSignature && webauthnSignature.__valid === true,
      reason: 'stub rejection',
    }),
  });
  const service = new LedgerService({ connectionManager: connMgr, engine, authorizer });

  const seedPasskey = (userId, credentialId, cose) => {
    db.prepare('INSERT INTO passkeys (user_id, credential_id, public_key_cose, sign_count, created_at, _hlc) VALUES (?, ?, ?, 0, ?, ?)')
      .run(userId, credentialId, cose, '2026-01-01T00:00:00.000Z', '0000000000000001');
  };
  seedPasskey(OWNER, OWNER_CRED, OWNER_COSE);
  seedPasskey(ALICE, ALICE_CRED, ALICE_COSE);

  contract.designations.set(LEDGER, {
    ownerUserId: OWNER, ownerPubKeyHash: OWNER_HASH,
    enabled: true, exists: true,
  });

  return { db, engine, contract, service };
}

async function createLedger(service, sig = GOOD_SIG) {
  return service.createLedger({
    ledgerId: LEDGER, signature: sig,
    payloadJson: payload({ actorUserId: OWNER, credentialId: OWNER_CRED, operation: 'create_ledger', params: { ledgerId: LEDGER } }),
  });
}

/** 直接经记账核心入账（充值入账的记账段，链上核验在后续阶段） */
async function credit(service, { userId, amount, assetId = USDT, idempotencyKey = null }) {
  return service.withLedgerWrite(LEDGER, (conn) => service.core.credit(conn, {
    ledgerId: LEDGER, userId, chainId: CHAIN, assetId, amount,
    kind: 'deposit', refType: 'deposit', refId: 'dep-1', idempotencyKey,
  }));
}

function balance(service, userId, assetId = USDT) {
  const b = service.getBalance(LEDGER, userId, CHAIN, assetId);
  return { available: b.available, frozen: b.frozen, withheld: b.withheld };
}

// ============ 账本创建 ============

test('createLedger: designated owner creates the ledger', async () => {
  const { service } = setup();
  const row = await createLedger(service);
  assert.equal(row.owner_user_id, OWNER);
  assert.equal(row.owner_pub_key_hash, OWNER_HASH);
});

test('createLedger: rejected when signer is not the designated owner', async () => {
  const { service } = setup();
  await assert.rejects(
    service.createLedger({
      ledgerId: LEDGER, signature: GOOD_SIG,
      payloadJson: payload({ actorUserId: ALICE, credentialId: ALICE_CRED, operation: 'create_ledger', params: { ledgerId: LEDGER } }),
    }),
    /not the designated owner/
  );
});

test('createLedger: fail-closed when the contract is unavailable or ledger disabled/undesignated', async () => {
  const { service, contract } = setup();
  contract.unavailable = true;
  await assert.rejects(createLedger(service), /Contract unavailable/);
  contract.unavailable = false;
  contract.designations.get(LEDGER).enabled = false;
  await assert.rejects(createLedger(service), /disabled/);
  contract.designations.delete(LEDGER);
  await assert.rejects(createLedger(service), /not designated/);
});

test('createLedger: duplicate creation and bad signature rejected', async () => {
  const { service } = setup();
  await createLedger(service);
  await assert.rejects(createLedger(service), /already created/);
  const { service: s2 } = setup();
  await assert.rejects(createLedger(s2, BAD_SIG), /signature invalid/);
});

// ============ 记账核心：入账与冻结路由 ============

test('credit: plain credit lands in available; duplicate idempotency key does not double-credit', async () => {
  const { service } = setup();
  await createLedger(service);
  await credit(service, { userId: ALICE, amount: '100', idempotencyKey: 'dep-key-1' });
  const dup = await credit(service, { userId: ALICE, amount: '100', idempotencyKey: 'dep-key-1' });
  assert.equal(dup.duplicate, true);
  assert.deepEqual(balance(service, ALICE), { available: '100', frozen: '0', withheld: '0' });
});

test('freeze: amount freeze moves stock, pending shortfall is filled by later credits first', async () => {
  const { service } = setup();
  await createLedger(service);
  await credit(service, { userId: ALICE, amount: '25' });
  const frozen = await service.withLedgerWrite(LEDGER, (conn) => service.core.freeze(conn, {
    ledgerId: LEDGER, userId: ALICE, chainId: CHAIN, assetId: USDT, targetAmount: '60', reason: 'tainted deposit',
  }));
  assert.equal(frozen.moved, 25n);
  assert.deepEqual(balance(service, ALICE), { available: '0', frozen: '25', withheld: '0' });

  // 后续入账 50：先补冻 35 到满 60，余 15 进可用
  const c = await credit(service, { userId: ALICE, amount: '50' });
  assert.equal(c.frozenPart, 35n);
  assert.equal(c.availablePart, 15n);
  assert.deepEqual(balance(service, ALICE), { available: '15', frozen: '60', withheld: '0' });

  // 目标已满：再入账全进可用
  await credit(service, { userId: ALICE, amount: '10' });
  assert.deepEqual(balance(service, ALICE), { available: '25', frozen: '60', withheld: '0' });
});

test('freeze: full freeze routes all later credits to frozen; unfreeze liftAll releases everything', async () => {
  const { service } = setup();
  await createLedger(service);
  await credit(service, { userId: ALICE, amount: '100' });
  const { freezeId } = await service.withLedgerWrite(LEDGER, (conn) => service.core.freeze(conn, {
    ledgerId: LEDGER, userId: ALICE, chainId: CHAIN, assetId: USDT, targetAmount: null,
  }));
  assert.deepEqual(balance(service, ALICE), { available: '0', frozen: '100', withheld: '0' });
  await credit(service, { userId: ALICE, amount: '50' });
  assert.deepEqual(balance(service, ALICE), { available: '0', frozen: '150', withheld: '0' });

  const un = await service.withLedgerWrite(LEDGER, (conn) => service.core.unfreeze(conn, {
    ledgerId: LEDGER, freezeId, liftAll: true,
  }));
  assert.equal(un.released, 150n);
  assert.equal(un.lifted, true);
  assert.deepEqual(balance(service, ALICE), { available: '150', frozen: '0', withheld: '0' });
});

test('freeze: all-scope freeze covers every asset; overlapping scope rejected, disjoint asset allowed', async () => {
  const { service } = setup();
  await createLedger(service);
  await credit(service, { userId: ALICE, amount: '70' });
  await assert.rejects(
    service.withLedgerWrite(LEDGER, (conn) => service.core.freeze(conn, {
      ledgerId: LEDGER, userId: ALICE, chainId: CHAIN, assetId: USDT, targetAmount: '10',
    })).then(() => service.withLedgerWrite(LEDGER, (conn) => service.core.freeze(conn, {
      ledgerId: LEDGER, userId: ALICE, chainId: CHAIN, assetId: USDT, targetAmount: '5',
    }))),
    /already covers this scope/
  );

  const { service: s2 } = setup();
  await createLedger(s2);
  await credit(s2, { userId: ALICE, amount: '70' });
  await s2.withLedgerWrite(LEDGER, (conn) => s2.core.freeze(conn, {
    ledgerId: LEDGER, userId: ALICE, chainId: null, assetId: null, targetAmount: null,
  }));
  assert.deepEqual(balance(s2, ALICE), { available: '0', frozen: '70', withheld: '0' });
  await credit(s2, { userId: ALICE, amount: '5', assetId: 'native' });
  assert.deepEqual(balance(s2, ALICE, 'native'), { available: '0', frozen: '5', withheld: '0' });
});

test('unfreeze: partial unfreeze of an amount freeze lowers the target equally', async () => {
  const { service } = setup();
  await createLedger(service);
  await credit(service, { userId: ALICE, amount: '100' });
  const { freezeId } = await service.withLedgerWrite(LEDGER, (conn) => service.core.freeze(conn, {
    ledgerId: LEDGER, userId: ALICE, chainId: CHAIN, assetId: USDT, targetAmount: '60',
  }));
  const un = await service.withLedgerWrite(LEDGER, (conn) => service.core.unfreeze(conn, {
    ledgerId: LEDGER, freezeId, amount: '20',
  }));
  assert.equal(un.released, 20n);
  assert.equal(un.lifted, false);
  assert.deepEqual(balance(service, ALICE), { available: '60', frozen: '40', withheld: '0' });
  // 目标已降至 40 且已冻满：新入账全进可用
  await credit(service, { userId: ALICE, amount: '10' });
  assert.deepEqual(balance(service, ALICE), { available: '70', frozen: '40', withheld: '0' });
});

// ============ 内部转账 ============

test('transfer: moves between users, recipient credit passes freeze routing, replay is a no-op', async () => {
  const { service } = setup();
  await createLedger(service);
  await credit(service, { userId: ALICE, amount: '100' });
  await service.withLedgerWrite(LEDGER, (conn) => service.core.freeze(conn, {
    ledgerId: LEDGER, userId: BOB, chainId: CHAIN, assetId: USDT, targetAmount: '50',
  }));

  const move = (key) => service.withLedgerWrite(LEDGER, (conn) => service.core.transfer(conn, {
    ledgerId: LEDGER, fromUserId: ALICE, toUserId: BOB, chainId: CHAIN, assetId: USDT,
    amount: '30', idempotencyKey: key,
  }));
  await move('tx-key-1');
  assert.deepEqual(balance(service, ALICE), { available: '70', frozen: '0', withheld: '0' });
  assert.deepEqual(balance(service, BOB), { available: '0', frozen: '30', withheld: '0' });

  const replay = await move('tx-key-1');
  assert.equal(replay.duplicate, true);
  assert.deepEqual(balance(service, ALICE), { available: '70', frozen: '0', withheld: '0' });
});

test('transfer: insufficient balance aborts atomically', async () => {
  const { service } = setup();
  await createLedger(service);
  await credit(service, { userId: ALICE, amount: '10' });
  await assert.rejects(
    service.withLedgerWrite(LEDGER, (conn) => service.core.transfer(conn, {
      ledgerId: LEDGER, fromUserId: ALICE, toUserId: BOB, chainId: CHAIN, assetId: USDT,
      amount: '30', idempotencyKey: 'tx-key-x',
    })),
    /insufficient available/
  );
  assert.deepEqual(balance(service, ALICE), { available: '10', frozen: '0', withheld: '0' });
  assert.deepEqual(balance(service, BOB), { available: '0', frozen: '0', withheld: '0' });
});

// ============ 提现三桶流转 ============

test('withdraw buckets: withhold -> settle, and withhold -> release', async () => {
  const { service } = setup();
  await createLedger(service);
  await credit(service, { userId: ALICE, amount: '100' });
  await service.withLedgerWrite(LEDGER, (conn) => service.core.withhold(conn, {
    ledgerId: LEDGER, userId: ALICE, chainId: CHAIN, assetId: USDT, amount: '40', refId: 'w-1',
  }));
  assert.deepEqual(balance(service, ALICE), { available: '60', frozen: '0', withheld: '40' });
  await service.withLedgerWrite(LEDGER, (conn) => service.core.settleWithdrawal(conn, {
    ledgerId: LEDGER, userId: ALICE, chainId: CHAIN, assetId: USDT, amount: '40', refId: 'w-1',
  }));
  assert.deepEqual(balance(service, ALICE), { available: '60', frozen: '0', withheld: '0' });

  await service.withLedgerWrite(LEDGER, (conn) => service.core.withhold(conn, {
    ledgerId: LEDGER, userId: ALICE, chainId: CHAIN, assetId: USDT, amount: '10', refId: 'w-2',
  }));
  await service.withLedgerWrite(LEDGER, (conn) => service.core.releaseWithheld(conn, {
    ledgerId: LEDGER, userId: ALICE, chainId: CHAIN, assetId: USDT, amount: '10', refId: 'w-2',
  }));
  assert.deepEqual(balance(service, ALICE), { available: '60', frozen: '0', withheld: '0' });
  const totals = service.totalLiabilities(LEDGER, CHAIN, USDT);
  assert.equal(totals.total, '60');
});

// ============ 服务层授权 ============

test('service transfer: user authorization enforced, params must match the request', async () => {
  const { service } = setup();
  await createLedger(service);
  await credit(service, { userId: ALICE, amount: '100' });

  const ok = await service.transfer({
    ledgerId: LEDGER, signature: GOOD_SIG, toUserId: BOB, chainId: CHAIN, assetId: USDT, amount: '25',
    payloadJson: payload({
      actorUserId: ALICE, credentialId: ALICE_CRED, operation: 'transfer',
      params: { toUserId: BOB, chainId: CHAIN, assetId: USDT, amount: '25' },
    }),
  });
  assert.ok(ok.entryId);
  assert.deepEqual(balance(service, BOB), { available: '25', frozen: '0', withheld: '0' });

  await assert.rejects(
    service.transfer({
      ledgerId: LEDGER, signature: GOOD_SIG, toUserId: BOB, chainId: CHAIN, assetId: USDT, amount: '99',
      payloadJson: payload({
        actorUserId: ALICE, credentialId: ALICE_CRED, operation: 'transfer',
        params: { toUserId: BOB, chainId: CHAIN, assetId: USDT, amount: '25' },
      }),
    }),
    /params do not match/
  );
});

test('service freeze: only the designated owner may freeze, checked live against the contract', async () => {
  const { service, contract } = setup();
  await createLedger(service);
  await credit(service, { userId: ALICE, amount: '80' });

  const res = await service.freeze({
    ledgerId: LEDGER, signature: GOOD_SIG, targetUserId: ALICE,
    chainId: CHAIN, assetId: USDT, targetAmount: '30',
    payloadJson: payload({
      actorUserId: OWNER, credentialId: OWNER_CRED, operation: 'freeze',
      params: { targetUserId: ALICE, chainId: CHAIN, assetId: USDT, targetAmount: '30' },
    }),
  });
  assert.equal(res.moved, 30n);
  assert.deepEqual(balance(service, ALICE), { available: '50', frozen: '30', withheld: '0' });

  // 合约改指定他人后，原所有权人的授权立即失效
  contract.designations.get(LEDGER).ownerUserId = 'someone-else';
  await assert.rejects(
    service.freeze({
      ledgerId: LEDGER, signature: GOOD_SIG, targetUserId: ALICE,
      chainId: CHAIN, assetId: USDT, targetAmount: '1',
      payloadJson: payload({
        actorUserId: OWNER, credentialId: OWNER_CRED, operation: 'freeze',
        params: { targetUserId: ALICE, chainId: CHAIN, assetId: USDT, targetAmount: '1' },
      }),
    }),
    /not the designated owner/
  );
});
