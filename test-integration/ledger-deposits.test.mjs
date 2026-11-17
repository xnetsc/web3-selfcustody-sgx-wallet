/**
 * 平台账本阶段二测试：读链通道交叉核对、专属充值地址开通、充值观察入账、待认领认领
 *
 * 运行：node --test test-integration/ledger-deposits.test.mjs
 *
 * 链上证据以脚本化端点桩提供（端点分歧/身份锚/确认数等读链语义真实走
 * ChainReader 逻辑）；合约指定以桩注入；账本核心与充值服务为真实模块。
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { ethers } from 'ethers';

import { ALL_TABLE_SQLS } from '../sgx-enclave/src/database/schema.js';
import { PasskeyManager } from '../sgx-enclave/src/modules/webauthn/passkey-manager.js';
import { LedgerAuthorizer } from '../sgx-enclave/src/modules/ledger/ledger-auth.js';
import { LedgerService } from '../sgx-enclave/src/modules/ledger/ledger-service.js';
import { LedgerDepositService } from '../sgx-enclave/src/modules/ledger/ledger-deposits.js';
import { ChainReader, TRANSFER_TOPIC } from '../sgx-enclave/src/modules/ledger/chain-reader.js';

const OWNER = 'ledger-owner';
const OWNER_CRED = 'owner-cred-1';
const OWNER_COSE = Buffer.from('owner-passkey-cose-material');
const OWNER_HASH = PasskeyManager.computePubKeyHash(OWNER_COSE);
const ALICE = 'user-alice';
const LEDGER = 'ledger-main';
const CHAIN = 1;
const USDT = '0xdac17f958d2ee523a2206206994597c13d831ec7';
const TX = '0x' + 'ab'.repeat(32);
const SENDER = '0x9999999999999999999999999999999999999999';
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
  const designation = {
    ownerUserId: OWNER, ownerPubKeyHash: OWNER_HASH,
    poolAddresses: [], enabled: true, exists: true,
  };
  const contract = {
    designation,
    async getLedger() { return this.designation; },
  };
  const passkeyManager = new PasskeyManager(connMgr, engine);
  const authorizer = new LedgerAuthorizer({
    passkeyManager, contractClient: contract,
    verifyWebAuthnSignatureFn: async ({ webauthnSignature }) => ({
      verified: webauthnSignature?.__valid === true, reason: 'stub rejection',
    }),
  });
  const ledgerService = new LedgerService({ connectionManager: connMgr, engine, authorizer });

  db.prepare('INSERT INTO passkeys (user_id, credential_id, public_key_cose, sign_count, created_at, _hlc) VALUES (?, ?, ?, 0, ?, ?)')
    .run(OWNER, OWNER_CRED, OWNER_COSE, '2026-01-01T00:00:00.000Z', '0000000000000001');

  // 链上证据脚本（测试内改写）
  const evidence = { confirmations: 20, requiredConfirmations: 12, transfers: [] };
  const chainReader = {
    async fetchTransferEvidence(chainId, txHash) {
      return { blockNumber: 100, confirmations: evidence.confirmations, requiredConfirmations: evidence.requiredConfirmations, transfers: evidence.transfers };
    },
  };
  const deposits = new LedgerDepositService({
    connectionManager: connMgr, engine, ledgerService, authorizer,
    contractClient: contract, chainReader,
  });
  return { db, contract, ledgerService, deposits, evidence };
}

async function createLedger(service) {
  return service.createLedger({
    ledgerId: LEDGER, signature: GOOD_SIG,
    payloadJson: payload({ actorUserId: OWNER, credentialId: OWNER_CRED, operation: 'create_ledger', params: { ledgerId: LEDGER } }),
  });
}

function erc20Transfer(to, amount, logIndex = 0, asset = USDT) {
  return { assetId: asset, from: SENDER, to, amount: String(amount), logIndex };
}

// ============ 专属充值地址开通 ============

test('deposit address: created once under the owner account, permanently export-locked, idempotent', async () => {
  const { db, ledgerService, deposits } = setup();
  await createLedger(ledgerService);
  const first = await deposits.getOrCreateDepositAddress({ ledgerId: LEDGER, userId: ALICE, chainId: CHAIN });
  assert.equal(first.created, true);
  assert.match(first.address, /^0x[0-9a-fA-F]{40}$/);

  const second = await deposits.getOrCreateDepositAddress({ ledgerId: LEDGER, userId: ALICE, chainId: CHAIN });
  assert.equal(second.created, false);
  assert.equal(second.address, first.address);

  const wallet = db.prepare('SELECT * FROM wallets WHERE address = ?').get(first.address);
  assert.equal(wallet.user_id, OWNER);
  assert.equal(wallet.wallet_type, 'native');
  assert.equal(wallet.export_locked, 1);
});

// ============ 充值观察入账 ============

test('observe: creditable deposit credits the assigned user exactly once', async () => {
  const { contract, ledgerService, deposits, evidence } = setup();
  await createLedger(ledgerService);
  const { address } = await deposits.getOrCreateDepositAddress({ ledgerId: LEDGER, userId: ALICE, chainId: CHAIN });
  contract.designation.poolAddresses = [address];
  evidence.transfers = [erc20Transfer(address, '500')];

  const r1 = await deposits.observeDeposit({ ledgerId: LEDGER, chainId: CHAIN, txHash: TX });
  assert.equal(r1[0].status, 'credited');
  assert.equal(ledgerService.getBalance(LEDGER, ALICE, CHAIN, USDT).available, '500');

  const r2 = await deposits.observeDeposit({ ledgerId: LEDGER, chainId: CHAIN, txHash: TX });
  assert.equal(r2[0].status, 'credited');
  assert.equal(ledgerService.getBalance(LEDGER, ALICE, CHAIN, USDT).available, '500');
});

test('observe: insufficient confirmations stays pending, later observation completes it', async () => {
  const { contract, ledgerService, deposits, evidence } = setup();
  await createLedger(ledgerService);
  const { address } = await deposits.getOrCreateDepositAddress({ ledgerId: LEDGER, userId: ALICE, chainId: CHAIN });
  contract.designation.poolAddresses = [address];
  evidence.transfers = [erc20Transfer(address, '70')];
  evidence.confirmations = 3;

  const r1 = await deposits.observeDeposit({ ledgerId: LEDGER, chainId: CHAIN, txHash: TX });
  assert.equal(r1[0].status, 'pending');
  assert.equal(ledgerService.getBalance(LEDGER, ALICE, CHAIN, USDT).available, '0');

  evidence.confirmations = 12;
  const r2 = await deposits.observeDeposit({ ledgerId: LEDGER, chainId: CHAIN, txHash: TX });
  assert.equal(r2[0].status, 'credited');
  assert.equal(ledgerService.getBalance(LEDGER, ALICE, CHAIN, USDT).available, '70');
});

test('observe: address not in the published pool set goes unclaimed; owner claim credits it', async () => {
  const { ledgerService, deposits, evidence } = setup();
  await createLedger(ledgerService);
  const { address } = await deposits.getOrCreateDepositAddress({ ledgerId: LEDGER, userId: ALICE, chainId: CHAIN });
  // 公布集为空：地址未生效
  evidence.transfers = [erc20Transfer(address, '88')];
  const r = await deposits.observeDeposit({ ledgerId: LEDGER, chainId: CHAIN, txHash: TX });
  assert.equal(r[0].status, 'unclaimed');
  assert.equal(ledgerService.getBalance(LEDGER, ALICE, CHAIN, USDT).available, '0');

  const rows = deposits.listDeposits(LEDGER, { status: 'unclaimed' });
  assert.equal(rows.length, 1);
  const claimed = await deposits.claimDeposit({
    ledgerId: LEDGER, signature: GOOD_SIG, depositId: rows[0].deposit_id, targetUserId: ALICE,
    payloadJson: payload({ actorUserId: OWNER, credentialId: OWNER_CRED, operation: 'claim_deposit', params: { depositId: rows[0].deposit_id, targetUserId: ALICE } }),
  });
  assert.equal(claimed.status, 'credited');
  assert.equal(ledgerService.getBalance(LEDGER, ALICE, CHAIN, USDT).available, '88');
});

test('observe: transfers to unrelated addresses are ignored', async () => {
  const { ledgerService, deposits, evidence } = setup();
  await createLedger(ledgerService);
  evidence.transfers = [erc20Transfer('0x5555555555555555555555555555555555555555', '10')];
  const r = await deposits.observeDeposit({ ledgerId: LEDGER, chainId: CHAIN, txHash: TX });
  assert.deepEqual(r, []);
});

// ============ 读链通道 ============

function stubProvider({ genesis = '0xgenesis', head = 200, receipt = null, tx = null, chainId = 1n }) {
  return {
    async getNetwork() { return { chainId }; },
    async getBlock(n) { return { hash: genesis, number: n }; },
    async getBlockNumber() { return head; },
    async getTransactionReceipt() { return receipt; },
    async getTransaction() { return tx; },
  };
}

function erc20Receipt(to, amount, blockNumber = 100) {
  const topic = (addr) => '0x' + '0'.repeat(24) + addr.slice(2).toLowerCase();
  return {
    blockNumber, status: 1, from: SENDER, to: USDT,
    logs: [{
      address: USDT, index: 0,
      topics: [TRANSFER_TOPIC, topic(SENDER), topic(to)],
      data: '0x' + BigInt(amount).toString(16).padStart(64, '0'),
    }],
  };
}

function chainSetup(providersByUrl, configOverrides = {}) {
  const contract = {
    async getChainRpcConfig() {
      return {
        chainName: 'test', rpcUrls: Object.keys(providersByUrl),
        caCerts: Object.keys(providersByUrl).map(() => ''),
        confirmations: 12, exists: true, ...configOverrides,
      };
    },
  };
  return new ChainReader({
    contractClient: contract, connectionManager: null,
    providerFactory: (url) => providersByUrl[url],
  });
}

test('chain reader: two agreeing endpoints produce parsed transfers and confirmations', async () => {
  const to = '0x7777777777777777777777777777777777777777';
  const receipt = erc20Receipt(to, '123');
  const tx = { from: SENDER, to: USDT, value: 0n };
  const reader = chainSetup({
    'https://a.example': stubProvider({ receipt, tx }),
    'https://b.example': stubProvider({ receipt, tx }),
  });
  const ev = await reader.fetchTransferEvidence(1, TX);
  assert.equal(ev.confirmations, 101); // head 200 - block 100 + 1
  assert.equal(ev.transfers.length, 1);
  assert.equal(ev.transfers[0].to, to);
  assert.equal(ev.transfers[0].amount, '123');
  assert.equal(ev.transfers[0].assetId, USDT);
});

test('chain reader: http endpoint in config rejects the whole chain', async () => {
  const reader = chainSetup({
    'http://a.example': stubProvider({}),
    'https://b.example': stubProvider({}),
  });
  await assert.rejects(reader.fetchTransferEvidence(1, TX), /non-https/);
});

test('chain reader: disagreeing endpoints and genesis impostors are refused', async () => {
  const to = '0x7777777777777777777777777777777777777777';
  const tx = { from: SENDER, to: USDT, value: 0n };
  const disagree = chainSetup({
    'https://a.example': stubProvider({ receipt: erc20Receipt(to, '1'), tx }),
    'https://b.example': stubProvider({ receipt: erc20Receipt(to, '2'), tx }),
  });
  await assert.rejects(disagree.fetchTransferEvidence(1, TX), /disagree/);

  const receipt = erc20Receipt(to, '1');
  const impostor = chainSetup({
    'https://a.example': stubProvider({ receipt, tx }),
    'https://b.example': stubProvider({ receipt, tx, genesis: '0xotherchain' }),
  });
  await assert.rejects(impostor.fetchTransferEvidence(1, TX), /genesis consensus|fewer than two/);
});
