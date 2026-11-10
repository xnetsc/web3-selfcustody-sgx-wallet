/**
 * 应急授权（运营方治理）业务逻辑测试
 *
 * 运行：node --test test-integration/emergency-auth.test.mjs
 *
 * 覆盖：
 *   - 解析器结构矩阵（grantee 通配/数组、重复 userId、未知操作、passkey_bind 缺哈希钉子等）
 *   - 通用校验器接受/拒绝矩阵（无链上记录、合约不可用、文本不一致、已撤销、
 *     链上过期、deadline 与 expiresAt 不一致、治理指定被移除、公钥哈希不符、
 *     签名无效、grantee 不符、目标=运营方本人、操作未授权、参数不符、
 *     newPubKeyHash 钉子、tx scope 越界、次数耗尽）
 *   - Handler 级：WalletCrud 应急创建/删除钱包成功路径与次数限制
 *   - Handler 级：AuthRevocation 应急撤销落库 source=emergency
 *
 * 合约客户端与 WebAuthn 验签以桩注入（真实 WebAuthn 验签由既有集成测试覆盖，
 * 合约记录的写入/撤销语义由 contracts 的 Hardhat 测试覆盖）；状态层、Passkey
 * 管理、钱包管理均为真实模块 + 内存 SQLite。
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import Database from 'better-sqlite3';

import { ALL_TABLE_SQLS } from '../sgx-enclave/src/database/schema.js';
import { StateManager } from '../sgx-enclave/src/modules/state-management/state-manager.js';
import { PasskeyManager } from '../sgx-enclave/src/modules/webauthn/passkey-manager.js';
import { WalletManager } from '../sgx-enclave/src/modules/wallet-management/wallet-manager.js';
import { EmergencyAuthorizer } from '../sgx-enclave/src/modules/emergency-auth/emergency-authorizer.js';
import { parseEmergencyAuthorization } from '../sgx-enclave/src/modules/emergency-auth/emergency-authorization-parser.js';
import { computeAuthorizationHash } from '../sgx-enclave/src/modules/auth-engine/authorization-parser.js';
import { WalletCrudHandler } from '../sgx-enclave/src/api/wallet-crud.js';
import { AuthRevocationHandler } from '../sgx-enclave/src/api/auth-revocation.js';
import { EmergencyLogQueryHandler } from '../sgx-enclave/src/api/emergency-log-query.js';
import { verifyExecutionLogChain, computeExecutionLogHash, GENESIS_PREV_HASH } from '../sgx-enclave/src/modules/emergency-auth/execution-log.js';
import { createConnProxy, BUSINESS_TABLES, createSQLiteAdapter, entriesVisibleLocally } from '../sgx-enclave/src/sync/sync-adapter.js';
import { createApp } from '../sgx-enclave/src/server.js';

// ============ 常量 ============

const OPERATOR = 'operator-user';
const OPERATOR_CRED = 'operator-cred-1';
const OPERATOR_COSE = Buffer.from('operator-governance-cose-key-material');
const OPERATOR_PUBKEY_HASH = PasskeyManager.computePubKeyHash(OPERATOR_COSE);

const ALICE = 'user-alice';
const BOB = 'user-bob';
const PLATFORM = '0x1111111111111111111111111111111111111111';
const OTHER_PLATFORM = '0x2222222222222222222222222222222222222222';
const NEW_KEY_HASH = '0x' + 'ef'.repeat(32);
const TARGET_ADDR = '0x3333333333333333333333333333333333333333';

const GOOD_SIG = { __valid: true };
const BAD_SIG = { __valid: false };

// ============ 测试基础设施 ============

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
    readQuery(sql, params = []) {
      return db.prepare(sql).all(...params);
    },
    writeQuery(sql, params = []) {
      return db.prepare(sql).run(...params);
    },
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

/** 合约桩：记录与治理指定均可动态调整，模拟链上状态变化 */
function makeMockContract() {
  return {
    record: null,
    designated: new Map(), // `${userId}|${hash}` -> bool
    unavailable: false,
    async getEmergencyAuthorization(id) {
      if (this.unavailable) throw new Error('RPC unreachable');
      if (!this.record || this.record.__id !== id) return null;
      const { __id, ...rest } = this.record;
      return { ...rest, exists: true };
    },
    async isGovernancePasskey(userId, hash) {
      if (this.unavailable) throw new Error('RPC unreachable');
      return this.designated.get(`${userId}|${hash.toLowerCase()}`) === true;
    },
  };
}

function futureDeadline(offsetMs = 3600_000) {
  const ms = Math.floor((Date.now() + offsetMs) / 1000) * 1000;
  return new Date(ms).toISOString();
}

function buildAuth(overrides = {}) {
  const auth = {
    authorizationId: 'emg-test-0001',
    type: 'emergency',
    operatorUserId: OPERATOR,
    operatorCredentialId: OPERATOR_CRED,
    grantee: PLATFORM,
    wallets: [
      {
        userId: ALICE,
        policy: {
          operations: {
            wallet_create: { chains: [1] },
            wallet_delete: { walletId: 'wallet-fixed-1' },
            passkey_bind: { newPubKeyHash: NEW_KEY_HASH },
            tx_sign: {
              maxUses: 5,
              targetAddresses: [{ chainId: 1, address: TARGET_ADDR }],
              signingWallets: [{ chainId: 1, address: '*' }],
              amountLimits: { max: '1000' },
            },
          },
        },
      },
      {
        userId: BOB,
        policy: { operations: { wallet_create: true } },
      },
    ],
    timePolicy: { deadline: futureDeadline() },
    createdAt: '2026-11-10T00:00:00.000Z',
    ...overrides,
  };
  return auth;
}

/** 把授权对象登记为合约记录（与真实合约语义一致：哈希由记录方自算） */
function registerOnContract(mock, auth, authJson, overrides = {}) {
  mock.record = {
    __id: auth.authorizationId,
    authorizationJson: authJson,
    signatureJson: JSON.stringify(GOOD_SIG),
    authHash: '0x' + crypto.createHash('sha256').update(authJson, 'utf8').digest('hex'),
    operatorUserId: auth.operatorUserId,
    operatorPubKeyHash: OPERATOR_PUBKEY_HASH,
    grantee: auth.grantee,
    createdAt: Math.floor(Date.now() / 1000) - 60,
    expiresAt: Math.floor(Date.parse(auth.timePolicy.deadline) / 1000),
    revoked: false,
    ...overrides,
  };
  mock.designated.set(`${auth.operatorUserId}|${OPERATOR_PUBKEY_HASH.toLowerCase()}`, true);
}

async function makeWorld() {
  const db = makeDb();
  const connMgr = makeConnMgr(db);
  const engine = makeFakeEngine(db);
  const stateManager = new StateManager(connMgr, engine);
  const passkeyManager = new PasskeyManager(connMgr, engine);
  await passkeyManager.registerPasskey(OPERATOR, OPERATOR_CRED, OPERATOR_COSE);
  const mockContract = makeMockContract();
  const authorizer = new EmergencyAuthorizer({
    contractClient: mockContract,
    passkeyManager,
    stateManager,
    verifyWebAuthnSignatureFn: async ({ webauthnSignature }) => ({
      verified: !!(webauthnSignature && webauthnSignature.__valid),
      reason: 'stub signature check',
    }),
  });
  return { db, connMgr, engine, stateManager, passkeyManager, mockContract, authorizer };
}

function verifyArgs(authJson, overrides = {}) {
  return {
    authorizationJson: authJson,
    signature: GOOD_SIG,
    platformAddress: PLATFORM,
    operation: 'wallet_create',
    userId: ALICE,
    actualParams: { chains: [1] },
    ...overrides,
  };
}

// ============ 解析器矩阵 ============

test('parser: 合法授权通过', () => {
  assert.equal(parseEmergencyAuthorization(buildAuth()).valid, true);
});

test('parser: grantee 为通配符或数组时拒绝', () => {
  assert.equal(parseEmergencyAuthorization(buildAuth({ grantee: '*' })).valid, false);
  assert.equal(parseEmergencyAuthorization(buildAuth({ grantee: [PLATFORM] })).valid, false);
});

test('parser: 同一 userId 重复条目拒绝（精确匹配前提）', () => {
  const auth = buildAuth();
  auth.wallets.push({ userId: ALICE, policy: { operations: { wallet_create: true } } });
  const r = parseEmergencyAuthorization(auth);
  assert.equal(r.valid, false);
  assert.match(r.reason, /duplicate/);
});

test('parser: 未知操作拒绝', () => {
  const auth = buildAuth();
  auth.wallets[0].policy.operations.fly_to_moon = true;
  assert.equal(parseEmergencyAuthorization(auth).valid, false);
});

test('parser: passkey_bind 缺 newPubKeyHash 钉子拒绝', () => {
  const auth = buildAuth();
  auth.wallets[0].policy.operations.passkey_bind = true;
  const r = parseEmergencyAuthorization(auth);
  assert.equal(r.valid, false);
  assert.match(r.reason, /newPubKeyHash/);
});

test('parser: tx_sign 缺 targetAddresses 拒绝；maxUses 非正整数拒绝', () => {
  const auth = buildAuth();
  delete auth.wallets[0].policy.operations.tx_sign.targetAddresses;
  assert.equal(parseEmergencyAuthorization(auth).valid, false);

  const auth2 = buildAuth();
  auth2.wallets[1].policy.operations.wallet_create = { maxUses: 0 };
  assert.equal(parseEmergencyAuthorization(auth2).valid, false);
});

// ============ 校验器矩阵 ============

test('verify: 全链路通过（wallet_create）', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);
  const r = await w.authorizer.verify(verifyArgs(json));
  assert.equal(r.approved, true, r.reason);
  assert.equal(r.opPolicy.maxUses, 1);
});

test('verify: 链上无记录拒绝', async () => {
  const w = await makeWorld();
  const json = JSON.stringify(buildAuth());
  const r = await w.authorizer.verify(verifyArgs(json));
  assert.equal(r.approved, false);
  assert.match(r.reason, /no emergency authorization record/);
});

test('verify: 合约不可用时 fail-closed 拒绝', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);
  w.mockContract.unavailable = true;
  const r = await w.authorizer.verify(verifyArgs(json));
  assert.equal(r.approved, false);
  assert.match(r.reason, /Contract unavailable/);
});

test('verify: 递进文本与合约全文不一致拒绝（防链下另签更宽授权）', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);
  // 平台递进一份改过的文本（把链 1 改成链 137），签名仍是“有效”桩签名
  const tampered = json.replace('"chains":[1]', '"chains":[137]');
  assert.notEqual(tampered, json);
  const r = await w.authorizer.verify(verifyArgs(tampered, { actualParams: { chains: [137] } }));
  assert.equal(r.approved, false);
  assert.match(r.reason, /does not match the contract record/);
});

test('verify: 已撤销拒绝；治理指定被移除拒绝（下一次执行即刻生效）', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);

  w.mockContract.record.revoked = true;
  let r = await w.authorizer.verify(verifyArgs(json));
  assert.equal(r.approved, false);
  assert.match(r.reason, /revoked/);

  w.mockContract.record.revoked = false;
  w.mockContract.designated.set(`${OPERATOR}|${OPERATOR_PUBKEY_HASH.toLowerCase()}`, false);
  r = await w.authorizer.verify(verifyArgs(json));
  assert.equal(r.approved, false);
  assert.match(r.reason, /not currently designated/);
});

test('verify: 链上已过期 / deadline 与 expiresAt 不一致拒绝', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json, { expiresAt: Math.floor(Date.now() / 1000) - 10 });
  let r = await w.authorizer.verify(verifyArgs(json));
  assert.equal(r.approved, false);

  registerOnContract(w.mockContract, auth, json, { expiresAt: Math.floor(Date.parse(auth.timePolicy.deadline) / 1000) + 999 });
  r = await w.authorizer.verify(verifyArgs(json));
  assert.equal(r.approved, false);
  assert.match(r.reason, /expiresAt/);
});

test('verify: 记录中的治理公钥哈希与实际 Passkey 不符拒绝', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json, { operatorPubKeyHash: '0x' + '00'.repeat(32) });
  const r = await w.authorizer.verify(verifyArgs(json));
  assert.equal(r.approved, false);
  assert.match(r.reason, /does not match the contract record/);
});

test('verify: 治理签名无效拒绝', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);
  const r = await w.authorizer.verify(verifyArgs(json, { signature: BAD_SIG }));
  assert.equal(r.approved, false);
  assert.match(r.reason, /signature invalid/);
});

test('verify: grantee 与请求平台不符拒绝', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);
  const r = await w.authorizer.verify(verifyArgs(json, { platformAddress: OTHER_PLATFORM }));
  assert.equal(r.approved, false);
  assert.match(r.reason, /grantee does not match/);
});

test('verify: 目标是运营方本人拒绝（只操作别人的钱包）', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  auth.wallets.push({ userId: OPERATOR, policy: { operations: { wallet_create: true } } });
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);
  const r = await w.authorizer.verify(verifyArgs(json, { userId: OPERATOR, actualParams: {} }));
  assert.equal(r.approved, false);
  assert.match(r.reason, /operator account itself/);
});

test('verify: 目标用户无条目 / 操作未授权拒绝', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);

  let r = await w.authorizer.verify(verifyArgs(json, { userId: 'user-nobody' }));
  assert.equal(r.approved, false);
  assert.match(r.reason, /no policy entry/);

  r = await w.authorizer.verify(verifyArgs(json, { operation: 'key_export', actualParams: {} }));
  assert.equal(r.approved, false);
  assert.match(r.reason, /not authorized/);
});

test('verify: 参数与 policy 声明不符拒绝（walletId 钉子 / chains 越界）', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);

  let r = await w.authorizer.verify(verifyArgs(json, {
    operation: 'wallet_delete',
    actualParams: { walletId: 'wallet-other' },
  }));
  assert.equal(r.approved, false);
  assert.match(r.reason, /walletId/);

  r = await w.authorizer.verify(verifyArgs(json, { actualParams: { chains: [137] } }));
  assert.equal(r.approved, false);
  assert.match(r.reason, /chain 137/);
});

test('verify: passkey_bind 的 newPubKeyHash 钉子', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);

  let r = await w.authorizer.verify(verifyArgs(json, {
    operation: 'passkey_bind',
    actualParams: { newPubKeyHash: '0x' + 'aa'.repeat(32) },
  }));
  assert.equal(r.approved, false);
  assert.match(r.reason, /newPubKeyHash/);

  r = await w.authorizer.verify(verifyArgs(json, {
    operation: 'passkey_bind',
    actualParams: { newPubKeyHash: NEW_KEY_HASH },
  }));
  assert.equal(r.approved, true, r.reason);
});

test('verify: tx_sign scope（目标越界 / 金额超限 / 合规通过）', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);

  const baseTx = { chainId: 1, toAddress: TARGET_ADDR, fromAddress: '0x4444444444444444444444444444444444444444', amount: '500', tokenAddress: '1_native' };
  let r = await w.authorizer.verify(verifyArgs(json, { operation: 'tx_sign', actualParams: {}, tx: baseTx }));
  assert.equal(r.approved, true, r.reason);

  r = await w.authorizer.verify(verifyArgs(json, {
    operation: 'tx_sign', actualParams: {},
    tx: { ...baseTx, toAddress: '0x9999999999999999999999999999999999999999' },
  }));
  assert.equal(r.approved, false);
  assert.match(r.reason, /Target address/);

  r = await w.authorizer.verify(verifyArgs(json, {
    operation: 'tx_sign', actualParams: {},
    tx: { ...baseTx, amount: '1001' },
  }));
  assert.equal(r.approved, false);
  assert.match(r.reason, /above maximum/);
});

test('verify: 次数耗尽拒绝（maxUses 缺省 1）', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);

  let r = await w.authorizer.verify(verifyArgs(json, { userId: BOB, actualParams: {} }));
  assert.equal(r.approved, true, r.reason);
  await w.authorizer.recordUse(r.auth, BOB, 'wallet_create');
  assert.equal(await w.stateManager.getEmergencyUseCount(auth.authorizationId, BOB, 'wallet_create'), 1);

  r = await w.authorizer.verify(verifyArgs(json, { userId: BOB, actualParams: {} }));
  assert.equal(r.approved, false);
  assert.match(r.reason, /use limit reached/);
});

// ============ Handler 级 ============

function makeWhitelistStub() {
  return {
    verifyRequest: () => ({ valid: true, address: PLATFORM, reason: 'OK' }),
  };
}

function envelope(payloadObj) {
  return { payload: JSON.stringify(payloadObj), platformSignature: 'stub' };
}

test('handler: WalletCrud 应急创建钱包成功且计次，第二次超限拒绝', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);

  const walletManager = new WalletManager(w.connMgr, w.engine);
  const crud = new WalletCrudHandler({
    whitelistVerifier: makeWhitelistStub(),
    passkeyManager: w.passkeyManager,
    challengeManager: {},
    walletManager,
    emergencyAuthorizer: w.authorizer,
  });

  const payload = {
    userId: ALICE,
    chains: [{ chainId: 1, coinType: 60 }],
    emergencyAuthorizationJson: json,
    emergencySignature: GOOD_SIG,
  };
  const res = await crud.handleCreate(envelope(payload));
  assert.equal(res.success, true);
  assert.ok(res.walletId);
  assert.equal(res.emergencyAuthorizationId, auth.authorizationId);
  assert.equal(res.addresses.length, 1);
  assert.equal(await w.stateManager.getEmergencyUseCount(auth.authorizationId, ALICE, 'wallet_create'), 1);

  // maxUses 缺省 1：同一授权再创建应被拒绝
  await assert.rejects(() => crud.handleCreate(envelope(payload)), /use limit reached/);
});

test('handler: WalletCrud 应急删除钱包（walletId 钉子）', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);

  const walletManager = new WalletManager(w.connMgr, w.engine);
  // 预置一个钱包（直接走 WalletManager，walletId 与 policy 钉子一致）
  await walletManager.createNativeWallet(ALICE, 'wallet-fixed-1', [{ chainId: 1, coinType: 60 }]);

  const crud = new WalletCrudHandler({
    whitelistVerifier: makeWhitelistStub(),
    passkeyManager: w.passkeyManager,
    challengeManager: {},
    walletManager,
    emergencyAuthorizer: w.authorizer,
  });

  // 钉子不符的 walletId 先被拒绝
  await assert.rejects(
    () => crud.handleDelete(envelope({
      userId: ALICE, walletId: 'wallet-other',
      emergencyAuthorizationJson: json, emergencySignature: GOOD_SIG,
    })),
    /Emergency authorization verification failed/
  );

  const res = await crud.handleDelete(envelope({
    userId: ALICE, walletId: 'wallet-fixed-1',
    emergencyAuthorizationJson: json, emergencySignature: GOOD_SIG,
  }));
  assert.equal(res.success, true);
  const wallets = await walletManager.listWallets(ALICE);
  assert.equal(wallets.length, 0);
});

test('handler: AuthRevocation 应急撤销落库 source=emergency', async () => {
  const w = await makeWorld();
  const targetAuthId = 'auth-user-normal-1';
  const targetAuth = {
    authorizationId: targetAuthId,
    userId: ALICE,
    credentialId: 'alice-cred',
    grantee: PLATFORM,
    scope: { targetAddresses: [{ chainId: 1, address: '*' }], signingWallets: [{ chainId: 1, address: '*' }] },
    timePolicy: { deadline: futureDeadline(86400_000) },
    createdAt: '2026-11-10T00:00:00.000Z',
  };
  const targetAuthJson = JSON.stringify(targetAuth);
  // 预置目标授权原文记录（模拟该授权此前被使用过）
  await w.engine.write(async (db) => {
    const conn = createConnProxy(db);
    w.stateManager._saveAuthorizationRecordInTransaction(
      conn, ALICE, targetAuthId, [PLATFORM], targetAuth, computeAuthorizationHash(targetAuthJson)
    );
  }, ALICE);

  const emgAuth = buildAuth();
  emgAuth.wallets[0].policy.operations.auth_revoke = { authorizationId: targetAuthId, grantee: PLATFORM };
  const emgJson = JSON.stringify(emgAuth);
  registerOnContract(w.mockContract, emgAuth, emgJson);

  const handler = new AuthRevocationHandler({
    whitelistVerifier: makeWhitelistStub(),
    passkeyManager: w.passkeyManager,
    stateManager: w.stateManager,
    emergencyAuthorizer: w.authorizer,
  });

  const res = await handler.handleRevoke(envelope({
    userId: ALICE,
    authorizationId: targetAuthId,
    grantee: PLATFORM,
    emergencyAuthorizationJson: emgJson,
    emergencySignature: GOOD_SIG,
  }));
  assert.equal(res.revoked, true);
  assert.equal(res.source, 'emergency');
  assert.equal(res.emergencyAuthorizationId, emgAuth.authorizationId);

  const records = await w.stateManager.listRevocations({ userId: ALICE, source: 'emergency' });
  assert.equal(records.length, 1);
  assert.equal(records[0].authorizationId, targetAuthId);
  assert.equal(await w.stateManager.getEmergencyUseCount(emgAuth.authorizationId, ALICE, 'auth_revoke'), 1);
});

// ============ 应急执行日志 ============

async function createViaEmergency(w) {
  const auth = buildAuth();
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);
  const walletManager = new WalletManager(w.connMgr, w.engine);
  const crud = new WalletCrudHandler({
    whitelistVerifier: makeWhitelistStub(),
    passkeyManager: w.passkeyManager,
    challengeManager: {},
    walletManager,
    emergencyAuthorizer: w.authorizer,
  });
  const res = await crud.handleCreate(envelope({
    userId: ALICE,
    chains: [{ chainId: 1, coinType: 60 }],
    emergencyAuthorizationJson: json,
    emergencySignature: GOOD_SIG,
  }));
  return { auth, json, res, crud, walletManager };
}

test('execution-log: 应急操作返回当前日志条目，字段可对着授权 JSON 验证', async () => {
  const w = await makeWorld();
  const { auth, json, res } = await createViaEmergency(w);

  const log = res.executionLog;
  assert.ok(log, 'response must carry executionLog');
  assert.equal(log.logId, undefined, 'no node-local autoincrement id: identity is the entry hash');
  assert.match(log.entryHash, /^0x[0-9a-f]{64}$/);
  assert.equal(log.authorizationId, auth.authorizationId);
  // authHash 必须等于对授权 JSON 原文重算的哈希——用户拿着授权 JSON 即可验证
  assert.equal(log.authHash, computeAuthorizationHash(json));
  assert.equal(log.operatorUserId, OPERATOR);
  assert.equal(log.operatorPubKeyHash, OPERATOR_PUBKEY_HASH);
  assert.equal(log.platformAddress, PLATFORM);
  assert.equal(log.targetUserId, ALICE);
  assert.equal(log.operation, 'wallet_create');
  assert.equal(log.executionIndex, 1);
  assert.equal(log.result, 'success');
  assert.equal(log.prevHash, GENESIS_PREV_HASH);
  // createdAt 为 UTC ISO 时间
  assert.ok(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(log.createdAt) && log.createdAt.endsWith('Z'));
  // entryHash 可由任何人按公开规则重算
  assert.equal(computeExecutionLogHash(log), log.entryHash);
  // 日志不得泄漏敏感信息：钱包创建 detail/outcome 只有链与公开地址
  const serialized = JSON.stringify([log.detail, log.outcome]);
  for (const banned of ['privateKey', 'mnemonic', 'seed', 'encrypted', 'signature']) {
    assert.ok(!serialized.includes(banned), `log must not contain ${banned}`);
  }
});

test('execution-log: 哈希链递增衔接，篡改与删行可检出', async () => {
  const w = await makeWorld();
  const { auth, json, res: firstRes, crud, walletManager } = await createViaEmergency(w);

  // 第二个操作（删除另一个预置钱包）产生第二条日志
  await walletManager.createNativeWallet(ALICE, 'wallet-fixed-1', [{ chainId: 1, coinType: 60 }]);
  const delRes = await crud.handleDelete(envelope({
    userId: ALICE,
    walletId: 'wallet-fixed-1',
    emergencyAuthorizationJson: json,
    emergencySignature: GOOD_SIG,
  }));
  assert.equal(delRes.executionLog.operation, 'wallet_delete');
  assert.equal(delRes.executionLog.prevHash, firstRes.executionLog.entryHash);

  const page = await w.stateManager.listExecutionLogs({}, 1, 10, 'asc');
  assert.equal(page.count, 2);
  assert.deepEqual(verifyExecutionLogChain(page.logs), { valid: true });
  // 校验与条目排列顺序无关：副本节点以任意到达顺序收到条目也能验链
  assert.deepEqual(verifyExecutionLogChain([...page.logs].reverse()), { valid: true });
  assert.equal(page.logs[1].prevHash, page.logs[0].entryHash);

  // 篡改第二条的 detail：重算哈希不符，链校验失败
  w.db.prepare("UPDATE emergency_execution_logs SET detail = ? WHERE entry_hash = ?").run('{"walletId":"forged"}', delRes.executionLog.entryHash);
  const tampered = await w.stateManager.listExecutionLogs({}, 1, 10, 'asc');
  const check = verifyExecutionLogChain(tampered.logs);
  assert.equal(check.valid, false);
  assert.equal(check.brokenAtEntryHash, delRes.executionLog.entryHash);
});

test('execution-log: 公开查询接口分页、过滤、顺序与链头', async () => {
  const w = await makeWorld();
  const { auth, res } = await createViaEmergency(w);
  const handler = new EmergencyLogQueryHandler({ stateManager: w.stateManager });

  // 无鉴权直查（不带任何签名）
  const all = await handler.handleQuery({});
  assert.equal(all.count, 1);
  assert.equal(all.logs[0].entryHash, res.executionLog.entryHash);
  assert.equal(all.latestEntryHash, res.executionLog.entryHash);

  // 过滤命中与未命中
  const byOp = await handler.handleQuery({ operation: 'wallet_create' });
  assert.equal(byOp.count, 1);
  const byAuth = await handler.handleQuery({ authorizationId: auth.authorizationId });
  assert.equal(byAuth.count, 1);
  const byUser = await handler.handleQuery({ userId: ALICE });
  assert.equal(byUser.count, 1);
  const byHash = await handler.handleQuery({ entryHash: res.executionLog.entryHash });
  assert.equal(byHash.count, 1);
  const miss = await handler.handleQuery({ operation: 'wallet_delete' });
  assert.equal(miss.count, 0);

  // 分页参数校验：越界直接报错
  await assert.rejects(() => handler.handleQuery({ pageSize: 0 }), /pageSize/);
  await assert.rejects(() => handler.handleQuery({ pageSize: 101 }), /pageSize/);
  await assert.rejects(() => handler.handleQuery({ page: 0 }), /page/);
  await assert.rejects(() => handler.handleQuery({ order: 'sideways' }), /order/);
  await assert.rejects(() => handler.handleQuery({ operation: 'nonsense' }), /unknown operation/);
  await assert.rejects(() => handler.handleQuery({ entryHash: 42 }), /entryHash/);
});

test('execution-log: SQL 注入字符串只当普通过滤值，查不到也不影响表', async () => {
  const w = await makeWorld();
  await createViaEmergency(w);
  const handler = new EmergencyLogQueryHandler({ stateManager: w.stateManager });

  const r1 = await handler.handleQuery({ authorizationId: "' OR '1'='1" });
  assert.equal(r1.count, 0);
  const r2 = await handler.handleQuery({ userId: "x'; DROP TABLE emergency_execution_logs; --" });
  assert.equal(r2.count, 0);
  const r3 = await handler.handleQuery({ platformAddress: "0x' UNION SELECT * FROM passkeys --" });
  assert.equal(r3.count, 0);

  // 表完好，原有日志仍可查
  const all = await handler.handleQuery({});
  assert.equal(all.count, 1);
  assert.deepEqual(verifyExecutionLogChain(all.logs), { valid: true });
});

test('execution-log: executionIndex 随同授权同操作递增，跨操作独立', async () => {
  const w = await makeWorld();
  const auth = buildAuth();
  auth.wallets[0].policy.operations.wallet_create = { maxUses: 3 };
  const json = JSON.stringify(auth);
  registerOnContract(w.mockContract, auth, json);
  const walletManager = new WalletManager(w.connMgr, w.engine);
  const crud = new WalletCrudHandler({
    whitelistVerifier: makeWhitelistStub(),
    passkeyManager: w.passkeyManager,
    challengeManager: {},
    walletManager,
    emergencyAuthorizer: w.authorizer,
  });
  for (let i = 1; i <= 3; i++) {
    const res = await crud.handleCreate(envelope({
      userId: ALICE,
      chains: [{ chainId: 1, coinType: 60 }],
      emergencyAuthorizationJson: json,
      emergencySignature: GOOD_SIG,
    }));
    assert.equal(res.executionLog.executionIndex, i);
  }
  const page = await w.stateManager.listExecutionLogs({ authorizationId: auth.authorizationId }, 1, 2, 'desc');
  assert.equal(page.count, 3);
  assert.equal(page.totalPages, 2);
  assert.equal(page.logs[0].executionIndex, 3);
});

test('execution-log: 同步注册以 entry_hash 为键，无自增 id 列', () => {
  const def = BUSINESS_TABLES.emergency_execution_logs;
  assert.ok(def, 'table must be registered as a sync business table');
  assert.deepEqual(def.keyColumns, ['entry_hash']);
  assert.ok(def.dataColumns.includes('entry_hash'));
  assert.ok(def.dataColumns.includes('_hlc'));
  assert.ok(!def.dataColumns.includes('log_id'));
});

// ============ 写纪律：应急取证按写请求路由到 leader ============

function makeRoutingApp({ isLeader }) {
  const calls = { handler: 0, proxied: [], manualTx: 0 };
  const evidenceQueryHandler = {
    handleGetRecord: async () => { calls.handler++; return { marker: 'local-exec' }; },
    handleListRecords: async () => { calls.handler++; return { marker: 'local-exec' }; },
  };
  const accountFreezeManager = {
    getFreezeStatus: () => null,
    checkRequest: async () => ({ allowed: true }),
    liftFreeze: async () => {},
  };
  const syncManager = {
    isMultiNodeDeployment: () => true,
    isLeaderForUser: () => isLeader,
    getShardForUser: () => 0,
    isShardWarming: () => false,
    proxyWriteRequest: async (userId, req) => {
      calls.proxied.push({ userId, path: req.path });
      return { status: 200, body: { proxiedMarker: true } };
    },
    beginManualTransaction: () => { calls.manualTx++; },
    getManualTransactionEntries: () => [],
    _shardElections: new Map(),
    waitForPrepareAck: async () => {},
    commitManualTransaction: () => {},
    broadcastCommit: () => {},
    rollbackManualTransaction: () => {},
    broadcastAbort: () => {},
  };
  const app = createApp({ evidenceQueryHandler }, accountFreezeManager, syncManager);
  return { app, calls };
}

async function postJson(app, path, body) {
  const server = app.listen(0);
  try {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  } finally {
    server.close();
  }
}

test('write-discipline: 普通取证在 follower 本地执行，不代理', async () => {
  const { app, calls } = makeRoutingApp({ isLeader: false });
  const res = await postJson(app, '/api/evidence/get', {
    payload: JSON.stringify({ userId: ALICE, authorizationId: 'a1' }),
    platformSignature: 'stub',
  });
  assert.equal(calls.proxied.length, 0);
  assert.equal(calls.handler, 1);
  assert.equal(res.status, 200);
});

test('write-discipline: 应急取证在 follower 被代理到 leader，本地不执行', async () => {
  const { app, calls } = makeRoutingApp({ isLeader: false });
  const res = await postJson(app, '/api/evidence/get', {
    payload: JSON.stringify({ userId: ALICE, authorizationId: 'a1', emergencyAuthorizationJson: '{}' }),
    platformSignature: 'stub',
  });
  assert.equal(calls.handler, 0, 'follower must not execute emergency evidence locally');
  assert.equal(calls.proxied.length, 1);
  assert.equal(calls.proxied[0].userId, ALICE);
  assert.equal(calls.proxied[0].path, '/api/evidence/get');
  assert.equal(res.body.proxiedMarker, true);
});

test('write-discipline: 应急取证在 leader 本地执行且开启手动事务（计数与日志并入同一事务）', async () => {
  const { app, calls } = makeRoutingApp({ isLeader: true });
  const res = await postJson(app, '/api/evidence/list', {
    payload: JSON.stringify({ userId: ALICE, emergencyAuthorizationJson: '{}' }),
    platformSignature: 'stub',
  });
  assert.equal(calls.proxied.length, 0);
  assert.equal(calls.handler, 1);
  assert.equal(calls.manualTx, 1, 'leader must execute emergency evidence inside a manual transaction');
  assert.equal(res.status, 200);
});

test('execution-log: 读己之写可见性检查覆盖日志表（捎带条目未落库时不可见、落库后可见）', async () => {
  const w = await makeWorld();
  const { res } = await createViaEmergency(w);
  const entryHash = res.executionLog.entryHash;
  const row = w.db.prepare('SELECT * FROM emergency_execution_logs WHERE entry_hash = ?').get(entryHash);
  assert.ok(row);
  const entry = {
    table_name: 'emergency_execution_logs',
    operation: 'INSERT',
    row_key: JSON.stringify({ entry_hash: entryHash }),
    row_data: JSON.stringify(row),
    _hlc: row._hlc,
  };
  // 另一个空库（模拟刚代理完写、尚未应用捎带条目的 follower）：不可见
  const db2 = makeDb();
  const adapter2 = createSQLiteAdapter(db2);
  assert.equal(entriesVisibleLocally(adapter2, [entry]), false);
  // 条目落库后（同 _hlc）：可见——ensureEntriesAppliedLocally 的放行条件成立
  const cols = Object.keys(row);
  db2.prepare(`INSERT INTO emergency_execution_logs (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`)
    .run(...cols.map((c) => row[c]));
  assert.equal(entriesVisibleLocally(adapter2, [entry]), true);
});
