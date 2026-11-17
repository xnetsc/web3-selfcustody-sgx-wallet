/**
 * 平台账本阶段三测试：转账护栏（归集出金目标检查）、导出护栏、提现状态机
 *
 * 运行：node --test test-integration/ledger-withdrawals.test.mjs
 *
 * 合约指定/出金目标/风控规则以桩注入（合约语义由 Hardhat 测试覆盖）；
 * 链上广播与证据以桩脚本化；账本核心、护栏、提现服务为真实模块。
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
import { LedgerGuard, decodeEffectiveTarget } from '../sgx-enclave/src/modules/ledger/ledger-guard.js';

const OWNER = 'ledger-owner';
const OWNER_CRED = 'owner-cred-1';
const OWNER_COSE = Buffer.from('owner-passkey-cose-material');
const OWNER_HASH = PasskeyManager.computePubKeyHash(OWNER_COSE);
const ALICE = 'user-alice';
const ALICE_CRED = 'alice-cred-1';
const ALICE_COSE = Buffer.from('alice-passkey-cose-material');

const LEDGER = 'ledger-main';
const CHAIN = 1;
const USDT = '0xdac17f958d2ee523a2206206994597c13d831ec7';
const COLLECTION = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; // 归集地址（所有权人原生钱包）
const EXTERNAL = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';   // 外部目标地址
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
function payload({ actorUserId, credentialId, operation, params = {} }) {
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
    payoutTargets: new Map(), // `${ledger}|${source}` -> [targets]
    policy: null,
    unavailable: false,
    async getLedger() { if (this.unavailable) throw new Error('RPC unreachable'); return this.designation; },
    async getCollectionPayoutTargets(ledgerId, source) {
      if (this.unavailable) throw new Error('RPC unreachable');
      return this.payoutTargets.get(`${ledgerId}|${source.toLowerCase()}`) || [];
    },
    async getLedgerWithdrawalPolicy() { if (this.unavailable) throw new Error('RPC unreachable'); return this.policy; },
  };
  const passkeyManager = new PasskeyManager(connMgr, engine);
  const authorizer = new LedgerAuthorizer({
    passkeyManager, contractClient: contract,
    verifyWebAuthnSignatureFn: async ({ webauthnSignature }) => ({
      verified: webauthnSignature?.__valid === true, reason: 'stub rejection',
    }),
  });
  const ledgerService = new LedgerService({ connectionManager: connMgr, engine, authorizer });
  const guard = new LedgerGuard({ connectionManager: connMgr, contractClient: contract, passkeyManager });

  const seedPasskey = (userId, credentialId, cose) => {
    db.prepare('INSERT INTO passkeys (user_id, credential_id, public_key_cose, sign_count, created_at, _hlc) VALUES (?, ?, ?, 0, ?, ?)')
      .run(userId, credentialId, cose, '2026-01-01T00:00:00.000Z', '0000000000000001');
  };
  seedPasskey(OWNER, OWNER_CRED, OWNER_COSE);
  seedPasskey(ALICE, ALICE_CRED, ALICE_COSE);

  // 所有权人的归集钱包（原生）与一个普通外部持有的导入钱包
  db.prepare(`INSERT INTO wallets (user_id, wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, derivation_path, export_locked, created_at, _hlc)
              VALUES (?, 'w-collection', 'native', 'm', ?, 60, ?, '0xkey', 'path', 0, '2026-01-01T00:00:00.000Z', '1')`)
    .run(OWNER, CHAIN, COLLECTION);
  db.prepare(`INSERT INTO wallets (user_id, wallet_id, wallet_type, mnemonic, chain_id, coin_type, address, private_key, derivation_path, export_locked, created_at, _hlc)
              VALUES (?, 'w-imported', 'imported_key', NULL, ?, 60, ?, '0xkey2', NULL, 0, '2026-01-01T00:00:00.000Z', '1')`)
    .run(ALICE, CHAIN, '0xcccccccccccccccccccccccccccccccccccccccc');

  const evidence = { found: true, status: 1, confirmations: 20, requiredConfirmations: 12, transfers: [], blockNumber: 100 };
  const chainReader = {
    async fetchTransferEvidence() { return evidence; },
    async getBroadcastChannel() { return { provider: { __stub: true }, requiredConfirmations: 12 }; },
  };
  const broadcasts = [];
  const withdrawals = new LedgerWithdrawalService({
    connectionManager: connMgr, engine, ledgerService, authorizer,
    contractClient: contract, chainReader,
    signFn: async () => ({ rawTx: '0xsignedraw', txHash: '0x' + 'cd'.repeat(32) }),
    broadcastFn: async ({ rawTx }) => { broadcasts.push(rawTx); },
  });
  const deposits = new LedgerDepositService({
    connectionManager: connMgr, engine, ledgerService, authorizer,
    contractClient: contract, chainReader,
  });

  return { db, contract, ledgerService, guard, withdrawals, deposits, evidence, broadcasts, seedPasskey };
}

async function createLedger(service) {
  return service.createLedger({
    ledgerId: LEDGER, signature: GOOD_SIG,
    payloadJson: payload({ actorUserId: OWNER, credentialId: OWNER_CRED, operation: 'create_ledger', params: { ledgerId: LEDGER } }),
  });
}

async function creditAlice(service, amount) {
  return service.withLedgerWrite(LEDGER, (conn) => service.core.credit(conn, {
    ledgerId: LEDGER, userId: ALICE, chainId: CHAIN, assetId: USDT, amount: String(amount),
    kind: 'deposit', refType: 'deposit', refId: 'dep-x',
  }));
}

function withdrawPayload(amount, toAddress = EXTERNAL, sourceAddress = COLLECTION) {
  return payload({
    actorUserId: ALICE, credentialId: ALICE_CRED, operation: 'withdraw',
    params: { chainId: CHAIN, assetId: USDT, amount: String(amount), toAddress, sourceAddress },
  });
}

// ============ 转账护栏 ============

test('guard: unbound source passes freely; bound source enforces owner + configured targets', async () => {
  const { ledgerService, guard, contract } = setup();
  await createLedger(ledgerService);

  // 普通地址：不受护栏约束
  const free = await guard.assertTransferAllowed({ signerUserId: ALICE, fromAddress: EXTERNAL, toAddress: COLLECTION });
  assert.equal(free.bound, false);

  // 归集地址出金，签名者不是所有权人 → 拒
  await assert.rejects(
    guard.assertTransferAllowed({ signerUserId: ALICE, fromAddress: COLLECTION, toAddress: EXTERNAL }),
    /not the ledger owner/
  );
  // 所有权人出金但目标未配置 → 拒
  await assert.rejects(
    guard.assertTransferAllowed({ signerUserId: OWNER, signerCredentialId: OWNER_CRED, fromAddress: COLLECTION, toAddress: EXTERNAL }),
    /not a configured payout target/
  );
  // 配置目标后放行
  contract.payoutTargets.set(`${LEDGER}|${COLLECTION}`, [EXTERNAL]);
  const ok = await guard.assertTransferAllowed({ signerUserId: OWNER, signerCredentialId: OWNER_CRED, fromAddress: COLLECTION, toAddress: EXTERNAL });
  assert.equal(ok.bound, true);
  assert.equal(ok.ledgerId, LEDGER);
});

test('guard: only the contract-designated passkey can move bound addresses', async () => {
  const { ledgerService, guard, contract, seedPasskey } = setup();
  await createLedger(ledgerService);
  contract.payoutTargets.set(`${LEDGER}|${COLLECTION}`, [EXTERNAL]);

  // 所有权人账号的第二把 Passkey（未被合约指定）→ 拒
  seedPasskey(OWNER, 'owner-cred-2', Buffer.from('owner-second-passkey-cose'));
  await assert.rejects(
    guard.assertTransferAllowed({ signerUserId: OWNER, signerCredentialId: 'owner-cred-2', fromAddress: COLLECTION, toAddress: EXTERNAL }),
    /contract-designated owner passkey/
  );
  // 授权里没有 credentialId → 无法证明是指定 Passkey，拒
  await assert.rejects(
    guard.assertTransferAllowed({ signerUserId: OWNER, fromAddress: COLLECTION, toAddress: EXTERNAL }),
    /contract-designated owner passkey/
  );
  // 指定 Passkey → 放行（对照）
  const ok = await guard.assertTransferAllowed({ signerUserId: OWNER, signerCredentialId: OWNER_CRED, fromAddress: COLLECTION, toAddress: EXTERNAL });
  assert.equal(ok.bound, true);
});

test('guard: ERC20 calldata recipient is the effective target; imported target wallet rejected', async () => {
  const { ledgerService, guard, contract } = setup();
  await createLedger(ledgerService);
  const data = '0xa9059cbb' + '0'.repeat(24) + EXTERNAL.slice(2) + '0'.repeat(64);
  const decoded = decodeEffectiveTarget(USDT, data);
  assert.equal(decoded.target, EXTERNAL);
  assert.equal(decoded.isPlainTransfer, true);

  contract.payoutTargets.set(`${LEDGER}|${COLLECTION}`, [EXTERNAL]);
  const ok = await guard.assertTransferAllowed({
    signerUserId: OWNER, signerCredentialId: OWNER_CRED, fromAddress: COLLECTION, toAddress: USDT, data,
  });
  assert.equal(ok.bound, true);

  // 目标是 SGX 内的导入钱包：即使配进目标集也不合格
  const imported = '0xcccccccccccccccccccccccccccccccccccccccc';
  contract.payoutTargets.set(`${LEDGER}|${COLLECTION}`, [imported]);
  const data2 = '0xa9059cbb' + '0'.repeat(24) + imported.slice(2) + '0'.repeat(64);
  await assert.rejects(
    guard.assertTransferAllowed({ signerUserId: OWNER, signerCredentialId: OWNER_CRED, fromAddress: COLLECTION, toAddress: USDT, data: data2 }),
    /not key-qualified/
  );
});

test('guard: deposit addresses are bound even before pool publication; export guard locks them', async () => {
  const { ledgerService, guard, deposits } = setup();
  await createLedger(ledgerService);
  const { address } = await deposits.getOrCreateDepositAddress({ ledgerId: LEDGER, userId: ALICE, chainId: CHAIN });

  const binding = await guard.findBinding(address);
  assert.equal(binding.kind, 'deposit_address');

  // 导出护栏：专属充值地址（export_locked=1）直接拒绝
  await assert.rejects(
    guard.assertExportAllowed([{ address, export_locked: 1 }]),
    /permanently export-locked|dedicated deposit address/
  );
  // 导出护栏：公布集内的归集地址动态锁定
  await assert.rejects(
    guard.assertExportAllowed([{ address: COLLECTION, export_locked: 0 }]),
    /published as a collection address/
  );
  // 普通地址放行
  await guard.assertExportAllowed([{ address: EXTERNAL, export_locked: 0 }]);
});

// ============ 提现状态机 ============

test('withdrawal: request withholds, payout broadcasts, refresh settles on confirmation', async () => {
  const { ledgerService, withdrawals, broadcasts } = setup();
  await createLedger(ledgerService);
  await creditAlice(ledgerService, 100);

  const row = await withdrawals.requestWithdrawal({
    ledgerId: LEDGER, signature: GOOD_SIG, chainId: CHAIN, assetId: USDT,
    amount: '40', toAddress: EXTERNAL, sourceAddress: COLLECTION,
    payloadJson: withdrawPayload(40),
  });
  assert.equal(row.status, 'frozen');
  let bal = ledgerService.getBalance(LEDGER, ALICE, CHAIN, USDT);
  assert.deepEqual([bal.available, bal.withheld], ['60', '40']);

  const paid = await withdrawals.executePayout({ ledgerId: LEDGER, withdrawalId: row.withdrawal_id });
  assert.equal(paid.status, 'broadcast');
  assert.equal(broadcasts.length, 1);

  const done = await withdrawals.refreshWithdrawal({ ledgerId: LEDGER, withdrawalId: row.withdrawal_id });
  assert.equal(done.status, 'confirmed');
  bal = ledgerService.getBalance(LEDGER, ALICE, CHAIN, USDT);
  assert.deepEqual([bal.available, bal.withheld], ['60', '0']);
  assert.equal(ledgerService.totalLiabilities(LEDGER, CHAIN, USDT).total, '60');
});

test('withdrawal: policy limits (single + daily) are enforced from the contract config', async () => {
  const { ledgerService, withdrawals, contract } = setup();
  await createLedger(ledgerService);
  await creditAlice(ledgerService, 1000);
  contract.policy = { maxSingleAmount: '40', maxDailyAmount: '100', exists: true };

  await assert.rejects(
    withdrawals.requestWithdrawal({
      ledgerId: LEDGER, signature: GOOD_SIG, chainId: CHAIN, assetId: USDT,
      amount: '41', toAddress: EXTERNAL, sourceAddress: COLLECTION, payloadJson: withdrawPayload(41),
    }),
    /single-transaction limit/
  );
  await withdrawals.requestWithdrawal({
    ledgerId: LEDGER, signature: GOOD_SIG, chainId: CHAIN, assetId: USDT,
    amount: '40', toAddress: EXTERNAL, sourceAddress: COLLECTION, payloadJson: withdrawPayload(40),
  });
  contract.policy = { maxSingleAmount: '0', maxDailyAmount: '50', exists: true };
  await assert.rejects(
    withdrawals.requestWithdrawal({
      ledgerId: LEDGER, signature: GOOD_SIG, chainId: CHAIN, assetId: USDT,
      amount: '11', toAddress: EXTERNAL, sourceAddress: COLLECTION, payloadJson: withdrawPayload(11),
    }),
    /daily limit/
  );
});

test('withdrawal: unqualified source rejected; active freeze blocks payout until lifted', async () => {
  const { ledgerService, withdrawals } = setup();
  await createLedger(ledgerService);
  await creditAlice(ledgerService, 100);

  await assert.rejects(
    withdrawals.requestWithdrawal({
      ledgerId: LEDGER, signature: GOOD_SIG, chainId: CHAIN, assetId: USDT,
      amount: '10', toAddress: EXTERNAL, sourceAddress: EXTERNAL,
      payloadJson: withdrawPayload(10, EXTERNAL, EXTERNAL),
    }),
    /not in the ledger collection set/
  );

  const row = await withdrawals.requestWithdrawal({
    ledgerId: LEDGER, signature: GOOD_SIG, chainId: CHAIN, assetId: USDT,
    amount: '30', toAddress: EXTERNAL, sourceAddress: COLLECTION, payloadJson: withdrawPayload(30),
  });
  const { freezeId } = await ledgerService.withLedgerWrite(LEDGER, (conn) => ledgerService.core.freeze(conn, {
    ledgerId: LEDGER, userId: ALICE, chainId: CHAIN, assetId: USDT, targetAmount: null,
  }));
  await assert.rejects(
    withdrawals.executePayout({ ledgerId: LEDGER, withdrawalId: row.withdrawal_id }),
    /blocked: an active freeze/
  );
  await ledgerService.withLedgerWrite(LEDGER, (conn) => ledgerService.core.unfreeze(conn, {
    ledgerId: LEDGER, freezeId, liftAll: true,
  }));
  const paid = await withdrawals.executePayout({ ledgerId: LEDGER, withdrawalId: row.withdrawal_id });
  assert.equal(paid.status, 'broadcast');
});

test('withdrawal: on-chain failure rolls back the hold; user can cancel a frozen withdrawal', async () => {
  const { ledgerService, withdrawals, evidence } = setup();
  await createLedger(ledgerService);
  await creditAlice(ledgerService, 100);

  const row = await withdrawals.requestWithdrawal({
    ledgerId: LEDGER, signature: GOOD_SIG, chainId: CHAIN, assetId: USDT,
    amount: '25', toAddress: EXTERNAL, sourceAddress: COLLECTION, payloadJson: withdrawPayload(25),
  });
  await withdrawals.executePayout({ ledgerId: LEDGER, withdrawalId: row.withdrawal_id });
  evidence.status = 0;
  const failed = await withdrawals.refreshWithdrawal({ ledgerId: LEDGER, withdrawalId: row.withdrawal_id });
  assert.equal(failed.status, 'failed');
  let bal = ledgerService.getBalance(LEDGER, ALICE, CHAIN, USDT);
  assert.deepEqual([bal.available, bal.withheld], ['100', '0']);

  evidence.status = 1;
  const row2 = await withdrawals.requestWithdrawal({
    ledgerId: LEDGER, signature: GOOD_SIG, chainId: CHAIN, assetId: USDT,
    amount: '10', toAddress: EXTERNAL, sourceAddress: COLLECTION, payloadJson: withdrawPayload(10),
  });
  const cancelled = await withdrawals.cancelWithdrawal({
    ledgerId: LEDGER, signature: GOOD_SIG, withdrawalId: row2.withdrawal_id,
    payloadJson: payload({ actorUserId: ALICE, credentialId: ALICE_CRED, operation: 'withdraw_cancel', params: { withdrawalId: row2.withdrawal_id } }),
  });
  assert.equal(cancelled.status, 'cancelled');
  bal = ledgerService.getBalance(LEDGER, ALICE, CHAIN, USDT);
  assert.deepEqual([bal.available, bal.withheld], ['100', '0']);
});
