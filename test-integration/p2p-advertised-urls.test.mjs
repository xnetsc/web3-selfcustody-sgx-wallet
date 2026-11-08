/**
 * 配置通告集分发端到端测试 —— 使用真实 SyncManager
 *
 * 场景：B 用 JSON 数组配置了两个通告地址（一个外部名字 + 实际可达的
 * 127.0.0.1)，A 按其中可达的一个拨入 B。
 * 验证：地址只从配置来，配置了几个就有几个——A 的地址簿里 B 的候选集
 * 与 B 的配置集完全一致（顺序、规范化形态均一致），不多不少。
 *
 * 运行: node p2p-advertised-urls.test.mjs
 */

import assert from 'node:assert';
import { createRequire } from 'module';
import { SyncManager } from '../sgx-enclave/src/sync/sync-manager.js';
import { HLC } from '../sgx-enclave/node_modules/@xnetx/raft-hlc-sync/index.js';
import { ALL_TABLE_SQLS } from '../sgx-enclave/src/database/schema.js';

const require_fn = createRequire(import.meta.url);
const Database = require_fn('../sgx-enclave/node_modules/better-sqlite3');

const identity = {
    rpcUrl: 'http://127.0.0.1:8545',
    rpcTlsCaCert: 'test-ca-cert',
    contractAddress: '0x' + 'a'.repeat(40),
    chainId: 31337,
    allowNonRaTls: true,
};

function createMockContractClient() {
    return {
        getPinnedIdentity: () => identity,
        refreshCache: async () => {},
    };
}

function createDb() {
    const db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    for (const { sql, indexes } of ALL_TABLE_SQLS) {
        db.exec(sql);
        for (const idx of indexes) db.exec(idx);
    }
    return db;
}

function createNode(name, port, peerUrls, advertisedUrl) {
    const db = createDb();
    const hlc = new HLC(name, () => ({ value: Date.now(), unit: 'ms' }));
    const mgr = new SyncManager({
        db,
        hlc,
        peerUrls,
        listenPort: port,
        advertisedUrl,
        contractClient: createMockContractClient(),
        getMinQuorum: () => 1,
    });
    return { name, mgr, db };
}

async function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function main() {
    console.log('=== 配置通告集分发端到端测试（真实 SyncManager）===\n');

    // B 配置两个通告地址（JSON 数组字符串，与环境变量形态一致）；
    // A 只按其中可达的一个拨入
    const configuredSet = ['ws://b.internal:3322', 'ws://127.0.0.1:3322'];
    const nodeB = createNode('nodeB', 3322, [], JSON.stringify(configuredSet));
    const nodeA = createNode('nodeA', 3321, ['ws://127.0.0.1:3322'], 'ws://127.0.0.1:3321');

    await nodeB.mgr.start();
    await nodeA.mgr.start();

    // 等待连接 + pin-check 完成
    await sleep(1500);

    // 验证 1：B 的通告集就是配置集，不多不少
    const bUrls = nodeB.mgr._getAdvertisedUrls();
    console.log('[验证1] B advertised urls:', bUrls);
    assert.deepEqual(bUrls, configuredSet);
    console.log('✓ 验证 1 通过：通告集恒等于配置集\n');

    // 验证 2：A 的地址簿里 B 的候选集与 B 的配置集完全一致
    const aBookForB = nodeA.mgr._knownPeers.get('nodeB');
    console.log('[验证2] A 的地址簿中 nodeB 的候选:', aBookForB);
    assert.deepEqual(aBookForB, configuredSet);
    console.log('✓ 验证 2 通过：配置集经 pin-check 自报原样分发\n');

    nodeA.mgr.stop();
    nodeB.mgr.stop();
    nodeA.db.close();
    nodeB.db.close();

    console.log('=== 全部通过 ===');
    process.exit(0);
}

main().catch((err) => {
    console.error('Test failed:', err);
    process.exit(1);
});
