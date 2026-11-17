/**
 * 平台账本 HTTP 层测试：经 createApp 真实路由 + 平台信封 + LedgerHandler 全链路
 *
 * 运行：node --test test-integration/ledger-api.test.mjs
 *
 * 平台白名单验签以桩注入（真实验签由既有套件覆盖）；合约指定、WebAuthn
 * 验签、链上证据以桩脚本化；账本服务全为真实模块 + 内存 SQLite。
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';

import { ALL_TABLE_SQLS } from '../sgx-enclave/src/database/schema.js';
import { PasskeyManager } from '../sgx-enclave/src/modules/webauthn/passkey-manager.js';
import { LedgerAuthorizer } from '../sgx-enclave/src/modules/ledger/ledger-auth.js';
import { LedgerService } from '../sgx-enclave/src/modules/ledger/ledger-service.js';
import { LedgerDepositService } from '../sgx-enclave/src/modules/ledger/ledger-deposits.js';
import { LedgerWithdrawalService } from '../sgx-enclave/src/modules/ledger/ledger-withdrawals.js';
import { LedgerHandler } from '../sgx-enclave/src/api/ledger.js';
import { createApp } from '../sgx-enclave/src/server.js';

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
const COLLECTION = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const EXTERNAL = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const TX = '0x' + 'ab'.repeat(32);
const GOOD_SIG = { __valid: true };

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
    db,
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
    getLeaderForKey: () => null, getLeaderForShard: () => null,
    async write(fn) {
      db.exec('BEGIN');
      try { const r = await fn(adapter); db.exec('COMMIT'); return r; }
      catch (e) { db.exec('ROLLBACK'); throw e; }
    },
  };
}

let opCounter = 0;
function authz({ actorUserId, credentialId, operation, params = {} }) {
  return JSON.stringify({
    type: 'ledger_op', version: 1, ledgerId: LEDGER, actorUserId, credentialId,
    operation, params, opId: `op-${++opCounter}`,
    expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
  });
}

function setup() {
  const db = makeDb();
  const connMgr = makeConnMgr(db);
  const engine = makeFakeEngine(db);
  const contract = {
    designation: {
      ownerUserId: OWNER, ownerPubKeyHash: OWNER_HASH,
      poolAddresses: [COLLECTION], enabled: true, exists: true,
    },
    async getLedger() { return this.designation; },
    async getCollectionPayoutTargets() { return [EXTERNAL]; },
    async getLedgerWithdrawalPolicy() { return null; },
  };
  const passkeyManager = new PasskeyManager(connMgr, engine);
  const authorizer = new LedgerAuthorizer({
    passkeyManager, contractClient: contract,
    verifyWebAuthnSignatureFn: async ({ webauthnSignature }) => ({
      verified: webauthnSignature?.__valid === true, reason: 'stub rejection',
    }),
  });
  const ledgerService = new LedgerService({ connectionManager: connMgr, engine, authorizer });
  const evidence = { confirmations: 20, requiredConfirmations: 12, transfers: [] };
  const chainReader = {
    async fetchTransferEvidence() {
      return { found: true, status: 1, blockNumber: 100, ...evidence };
    },
    async getBroadcastChannel() { return { provider: { __stub: true }, requiredConfirmations: 12 }; },
  };
  const deposits = new LedgerDepositService({
    connectionManager: connMgr, engine, ledgerService, authorizer, contractClient: contract, chainReader,
  });
  const withdrawals = new LedgerWithdrawalService({
    connectionManager: connMgr, engine, ledgerService, authorizer, contractClient: contract, chainReader,
    signFn: async () => ({ rawTx: '0xsigned', txHash: '0x' + 'cd'.repeat(32) }),
    broadcastFn: async () => {},
  });
  const ledgerHandler = new LedgerHandler({
    whitelistVerifier: {
      verifyRequest: (payload, signature) => signature === 'platform-ok'
        ? { valid: true, address: '0x1111111111111111111111111111111111111111' }
        : { valid: false, reason: 'bad platform signature' },
    },
    ledgerService, ledgerDepositService: deposits, ledgerWithdrawalService: withdrawals, contractClient: contract,
  });
  const app = createApp({ ledgerHandler }, null, null);

  const seed = (userId, credentialId, cose) => {
    db.prepare('INSERT INTO passkeys (user_id, credential_id, public_key_cose, sign_count, created_at, _hlc) VALUES (?, ?, ?, 0, ?, ?)')
      .run(userId, credentialId, cose, '2026-01-01T00:00:00.000Z', '0000000000000001');
  };
  seed(OWNER, OWNER_CRED, OWNER_COSE);
  seed(ALICE, ALICE_CRED, ALICE_COSE);
  db.prepare(`INSERT INTO wallets (user_id, wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, derivation_path, export_locked, created_at, _hlc)
              VALUES (?, 'w-collection', 'native', 'm', ?, 60, ?, '0xkey', 'path', 0, '2026-01-01T00:00:00.000Z', '1')`)
    .run(OWNER, CHAIN, COLLECTION);

  return { app, contract, evidence };
}

async function post(app, path, payloadObj, signature = 'platform-ok') {
  const server = app.listen(0);
  try {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ payload: JSON.stringify(payloadObj), platformSignature: signature }),
    });
    const raw = await res.json().catch(() => null);
    // 服务端统一把业务响应包在证明信封里：{ attestationQuote, data: "<json>" }
    const body = raw && typeof raw.data === 'string' ? JSON.parse(raw.data) : raw;
    return { status: res.status, body };
  } finally {
    server.close();
  }
}

test('ledger API end-to-end: create -> deposit address -> observe credit -> transfer -> withdraw', async () => {
  const { app, contract, evidence } = setup();

  // 平台签名错误：整请求被拒
  const bad = await post(app, '/api/ledger/list', { userId: OWNER }, 'wrong');
  assert.notEqual(bad.status, 200);

  // 创建账本（信封 userId = 所有权人 = 分片路由键）
  const created = await post(app, '/api/ledger/create', {
    userId: OWNER, ledgerId: LEDGER,
    ledgerAuthorizationJson: authz({ actorUserId: OWNER, credentialId: OWNER_CRED, operation: 'create_ledger', params: { ledgerId: LEDGER } }),
    ledgerSignature: GOOD_SIG,
  });
  assert.equal(created.body.success, true);

  // 开通专属充值地址
  const opened = await post(app, '/api/ledger/deposit-address/get-or-create', {
    userId: OWNER, ledgerId: LEDGER, targetUserId: ALICE, chainId: CHAIN,
  });
  assert.equal(opened.body.success, true);
  const depositAddress = opened.body.address;
  contract.designation.poolAddresses = [COLLECTION, depositAddress];

  // 充值观察入账
  evidence.transfers = [{ assetId: USDT, from: EXTERNAL, to: depositAddress, amount: '500', logIndex: 0 }];
  const observed = await post(app, '/api/ledger/deposit/observe', {
    userId: OWNER, ledgerId: LEDGER, chainId: CHAIN, txHash: TX,
  });
  assert.equal(observed.body.success, true);
  assert.equal(observed.body.results[0].status, 'credited');

  // 余额查询（只读）
  const bal = await post(app, '/api/ledger/balance', { userId: ALICE, ledgerId: LEDGER });
  assert.equal(bal.body.success, true);
  assert.equal(bal.body.balances[0].available, '500');

  // 内部转账
  const moved = await post(app, '/api/ledger/transfer', {
    userId: OWNER, ledgerId: LEDGER, toUserId: BOB, chainId: CHAIN, assetId: USDT, amount: '120',
    ledgerAuthorizationJson: authz({
      actorUserId: ALICE, credentialId: ALICE_CRED, operation: 'transfer',
      params: { toUserId: BOB, chainId: CHAIN, assetId: USDT, amount: '120' },
    }),
    ledgerSignature: GOOD_SIG,
  });
  assert.equal(moved.body.success, true);

  // 提现：申请 → 出款 → 刷新确认
  const wreq = await post(app, '/api/ledger/withdraw/request', {
    userId: OWNER, ledgerId: LEDGER, chainId: CHAIN, assetId: USDT, amount: '80',
    toAddress: EXTERNAL, sourceAddress: COLLECTION,
    ledgerAuthorizationJson: authz({
      actorUserId: ALICE, credentialId: ALICE_CRED, operation: 'withdraw',
      params: { chainId: CHAIN, assetId: USDT, amount: '80', toAddress: EXTERNAL, sourceAddress: COLLECTION },
    }),
    ledgerSignature: GOOD_SIG,
  });
  assert.equal(wreq.body.success, true);
  const withdrawalId = wreq.body.withdrawal.withdrawal_id;

  const paid = await post(app, '/api/ledger/withdraw/payout', { userId: OWNER, ledgerId: LEDGER, withdrawalId });
  assert.equal(paid.body.status, 'broadcast');
  const refreshed = await post(app, '/api/ledger/withdraw/refresh', { userId: OWNER, ledgerId: LEDGER, withdrawalId });
  assert.equal(refreshed.body.status, 'confirmed');

  const balAfter = await post(app, '/api/ledger/balance', { userId: ALICE, ledgerId: LEDGER });
  assert.equal(balAfter.body.balances[0].available, '300'); // 500 - 120 - 80
  const liabilities = await post(app, '/api/ledger/liabilities', { userId: OWNER, ledgerId: LEDGER, chainId: CHAIN, assetId: USDT });
  assert.equal(liabilities.body.liabilities.total, '420'); // alice 300 + bob 120
});
