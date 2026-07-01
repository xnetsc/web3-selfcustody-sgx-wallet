/**
 * 合约身份钉住（TOFU）回归测试
 *
 * 运行：node --test src/modules/contract-client/contract-pin.test.mjs
 *
 * 覆盖：
 *   1. 首次成功读到合约 → 钉住身份 + 快照
 *   2. 已钉住后 env 指向不同合约 → 忽略 env，永久使用钉住身份
 *   3. 钉住合约不可达 → 使用最后已知快照（而非 env、而非空/默认）
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';

import { ContractClient } from './index.js';
import { ContractPinStore } from './contract-pin-store.js';
import { CREATE_PINNED_CONTRACT_SQL } from '../../database/schema.js';

const IDENTITY_A = {
  rpcUrl: 'http://good-rpc.example:8545',
  chainId: 1,
  contractAddress: '0x' + 'a'.repeat(40),
};
const IDENTITY_B = {
  rpcUrl: 'http://attacker-rpc.evil:8545',
  chainId: 999,
  contractAddress: '0x' + 'b'.repeat(40),
};

function makeContractData(tag) {
  return {
    runtimeParams: { session: { importTtlSeconds: 111 }, __tag: tag, attestation: { allowNonRaTls: false } },
    codeRepository: `repo-${tag}`,
    platformWhitelist: ['0x' + '1'.repeat(40)],
    enclaveWhitelist: [
      { mrenclave: `mre-${tag}`, mrsigner: 'sgn', isvprodid: 0, isvsvn: 0, description: 'd' },
    ],
    migration: null,
  };
}

/**
 * 最小 ConnectionManager mock，包装内存 better-sqlite3 实例。
 * 只实现 readQuery / writeQuery，满足 ContractPinStore 接口。
 */
function makeMockConnMgr() {
  const db = new Database(':memory:');
  db.exec(CREATE_PINNED_CONTRACT_SQL);
  return {
    _db: db,
    readQuery(sql, params = []) {
      return db.prepare(sql).all(...params);
    },
    writeQuery(sql, params = []) {
      return db.prepare(sql).run(...params);
    },
  };
}

/**
 * 构造一个 ContractClient，并把网络读取替换成受控 stub。
 * @param {Object} identity - env 侧身份
 * @param {ContractPinStore} pinStore
 * @param {Object|Error} readResult - stub 返回的数据；若为 Error 则抛出（模拟不可达）
 */
function makeClient(identity, pinStore, readResult) {
  const client = new ContractClient({ ...identity, pinStore });
  // 覆盖真实网络读取，避免依赖真实 RPC
  client._readContractData = async () => {
    if (readResult instanceof Error) throw readResult;
    return readResult;
  };
  return client;
}

test('1. 首次成功读到合约 → 钉住身份 + 快照', async () => {
  const connMgr = makeMockConnMgr();
  const pinStore = new ContractPinStore(connMgr);
  assert.equal(pinStore.load(), null, 'initially no pin');

  const dataA = makeContractData('A');
  const client = makeClient(IDENTITY_A, pinStore, dataA);
  await client.initialize();
  client.close();

  assert.equal(client.isContractAvailable(), true);
  const pinned = pinStore.load();
  assert.ok(pinned, 'pin persisted after first success');
  assert.equal(pinned.rpcUrl, IDENTITY_A.rpcUrl);
  assert.equal(pinned.chainId, IDENTITY_A.chainId);
  assert.equal(pinned.contractAddress, IDENTITY_A.contractAddress);
  assert.equal(pinned.snapshot.codeRepository, 'repo-A');
});

test('2. 已钉住后 env 指向不同合约 → 忽略 env，使用钉住身份', async () => {
  const connMgr = makeMockConnMgr();
  const pinStore = new ContractPinStore(connMgr);
  // 先用 A 钉住
  await (async () => {
    const c = makeClient(IDENTITY_A, pinStore, makeContractData('A'));
    await c.initialize();
    c.close();
  })();

  // 攻击者把 env 改成 B，但合约（B）可读并返回攻击者数据
  const attackerData = makeContractData('ATTACKER');
  const client = makeClient(IDENTITY_B, pinStore, attackerData);
  await client.initialize();
  client.close();

  // 身份被钉住为 A，env 的 B 被忽略
  assert.equal(client._rpcUrl, IDENTITY_A.rpcUrl);
  assert.equal(client._chainId, IDENTITY_A.chainId);
  assert.equal(client._contractAddress, IDENTITY_A.contractAddress);

  // 身份不会被覆盖（pinStore 仍是 A）
  const pinned = pinStore.load();
  assert.equal(pinned.rpcUrl, IDENTITY_A.rpcUrl);
  assert.equal(pinned.contractAddress, IDENTITY_A.contractAddress);
});

test('3. 钉住合约不可达 → 使用最后已知快照，不回退 env/默认', async () => {
  const connMgr = makeMockConnMgr();
  const pinStore = new ContractPinStore(connMgr);
  await (async () => {
    const c = makeClient(IDENTITY_A, pinStore, makeContractData('A'));
    await c.initialize();
    c.close();
  })();

  // 现在合约不可达；env 被攻击者改为 B
  const client = makeClient(IDENTITY_B, pinStore, new Error('RPC unreachable'));
  await client.initialize();

  assert.equal(client.isContractAvailable(), false, 'contract unavailable');
  // 身份仍锁定为 A
  assert.equal(client._contractAddress, IDENTITY_A.contractAddress);
  // 使用最后已知快照（A），而不是空 / env
  assert.equal(client.getCodeRepository(), 'repo-A');
  assert.deepEqual(client.getPlatformWhitelist(), ['0x' + '1'.repeat(40)]);
  assert.equal(client.getRuntimeParams().__tag, 'A');
  assert.equal(client.isPlatformWhitelisted('0x' + '1'.repeat(40)), true);
  client.close();
});

test('4. 无 pinStore（未启用钉住）时不影响基本行为', async () => {
  const client = makeClient(IDENTITY_A, null, makeContractData('A'));
  await client.initialize();
  assert.equal(client.isContractAvailable(), true);
  assert.equal(client.getCodeRepository(), 'repo-A');
  client.close();
});

test('5. getPinnedIdentity 返回钉住的身份', async () => {
  const connMgr = makeMockConnMgr();
  const pinStore = new ContractPinStore(connMgr);
  const client = makeClient(IDENTITY_A, pinStore, makeContractData('A'));
  await client.initialize();
  client.close();

  const identity = client.getPinnedIdentity();
  assert.ok(identity, 'getPinnedIdentity returns non-null after pinning');
  assert.equal(identity.rpcUrl, IDENTITY_A.rpcUrl);
  assert.equal(identity.chainId, IDENTITY_A.chainId);
  assert.equal(identity.contractAddress, IDENTITY_A.contractAddress);
  assert.equal(identity.allowNonRaTls, false, 'allowNonRaTls pinned as false');
});

test('5b. allowNonRaTls=true 被 pin 住', async () => {
  const connMgr = makeMockConnMgr();
  const pinStore = new ContractPinStore(connMgr);
  const dataWithNonRaTls = { ...makeContractData('A'), runtimeParams: { ...makeContractData('A').runtimeParams, attestation: { allowNonRaTls: true } } };
  const client = makeClient(IDENTITY_A, pinStore, dataWithNonRaTls);
  await client.initialize();
  client.close();

  const identity = client.getPinnedIdentity();
  assert.equal(identity.allowNonRaTls, true, 'allowNonRaTls pinned as true');

  const pinned = pinStore.load();
  assert.equal(pinned.allowNonRaTls, true, 'pinStore has allowNonRaTls=true');
});

test('6. 合约迁移：migration target 验证成功后切换身份', async () => {
  const connMgr = makeMockConnMgr();
  const pinStore = new ContractPinStore(connMgr);

  // 先用 A 钉住
  await (async () => {
    const c = makeClient(IDENTITY_A, pinStore, makeContractData('A'));
    await c.initialize();
    c.close();
  })();

  // 合约返回迁移目标 B，且新合约可读
  const MIGRATION_B = {
    rpcUrl: IDENTITY_B.rpcUrl,
    contractAddress: IDENTITY_B.contractAddress,
    chainId: IDENTITY_B.chainId,
  };
  const dataWithMigration = { ...makeContractData('A'), migration: MIGRATION_B };
  const newDataB = makeContractData('B');

  const client = makeClient(IDENTITY_A, pinStore, dataWithMigration);
  // stub _readContractDataFrom 以模拟新合约读取
  client._readContractDataFrom = async () => newDataB;
  await client.initialize();
  // 等待异步迁移完成
  await new Promise((r) => setTimeout(r, 100));

  // 身份应切换为 B
  assert.equal(client._rpcUrl, IDENTITY_B.rpcUrl);
  assert.equal(client._chainId, IDENTITY_B.chainId);
  assert.equal(client._contractAddress, IDENTITY_B.contractAddress);

  // pin 也应更新为 B
  const pinned = pinStore.load();
  assert.equal(pinned.rpcUrl, IDENTITY_B.rpcUrl);
  assert.equal(pinned.contractAddress, IDENTITY_B.contractAddress);
  assert.equal(pinned.chainId, IDENTITY_B.chainId);
  assert.equal(pinned.snapshot.codeRepository, 'repo-B');
  client.close();
});

test('7. 合约迁移：新合约不可用时保持旧身份', async () => {
  const connMgr = makeMockConnMgr();
  const pinStore = new ContractPinStore(connMgr);

  // 先用 A 钉住
  await (async () => {
    const c = makeClient(IDENTITY_A, pinStore, makeContractData('A'));
    await c.initialize();
    c.close();
  })();

  const MIGRATION_B = {
    rpcUrl: IDENTITY_B.rpcUrl,
    contractAddress: IDENTITY_B.contractAddress,
    chainId: IDENTITY_B.chainId,
  };
  const dataWithMigration = { ...makeContractData('A'), migration: MIGRATION_B };

  const client = makeClient(IDENTITY_A, pinStore, dataWithMigration);
  // 新合约读取失败
  client._readContractDataFrom = async () => { throw new Error('new contract unreachable'); };
  await client.initialize();
  await new Promise((r) => setTimeout(r, 100));

  // 身份仍为 A
  assert.equal(client._rpcUrl, IDENTITY_A.rpcUrl);
  assert.equal(client._contractAddress, IDENTITY_A.contractAddress);
  const pinned = pinStore.load();
  assert.equal(pinned.rpcUrl, IDENTITY_A.rpcUrl);
  client.close();
});

test('8. 合约迁移：新合约 runtimeParams 为空时中止迁移', async () => {
  const connMgr = makeMockConnMgr();
  const pinStore = new ContractPinStore(connMgr);

  await (async () => {
    const c = makeClient(IDENTITY_A, pinStore, makeContractData('A'));
    await c.initialize();
    c.close();
  })();

  const MIGRATION_B = {
    rpcUrl: IDENTITY_B.rpcUrl,
    contractAddress: IDENTITY_B.contractAddress,
    chainId: IDENTITY_B.chainId,
  };
  const dataWithMigration = { ...makeContractData('A'), migration: MIGRATION_B };

  const client = makeClient(IDENTITY_A, pinStore, dataWithMigration);
  // 新合约返回空 runtimeParams
  client._readContractDataFrom = async () => ({ ...makeContractData('B'), runtimeParams: null });
  await client.initialize();
  await new Promise((r) => setTimeout(r, 100));

  // 身份仍为 A
  assert.equal(client._rpcUrl, IDENTITY_A.rpcUrl);
  const pinned = pinStore.load();
  assert.equal(pinned.rpcUrl, IDENTITY_A.rpcUrl);
  client.close();
});
