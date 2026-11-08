/**
 * Host 学习端到端测试 —— 使用真实 SyncManager
 *
 * 场景：B 的配置自报地址是一个外部不可达的名字（b.internal:3322），
 * A 用 ws://127.0.0.1:3322 拨入 B。
 * 验证：
 *   1. B 从入站连接的 Host 头学到自己的实测可达地址
 *      （127.0.0.1:3322），作为配置自报的补充
 *   2. 学到的地址随 pin-check 重发扩散：A 的地址簿里 B 的候选集
 *      同时包含配置自报与实测地址，自报在前
 *
 * 运行: node p2p-host-learning.test.mjs
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
    console.log('=== Host 学习端到端测试（真实 SyncManager）===\n');

    // B 配置自报一个拨不通的名字；A 按 IP 拨入 B
    const nodeB = createNode('nodeB', 3322, [], 'ws://b.internal:3322');
    const nodeA = createNode('nodeA', 3321, ['ws://127.0.0.1:3322'], 'ws://127.0.0.1:3321');

    await nodeB.mgr.start();
    await nodeA.mgr.start();

    // 等待连接 + pin-check 完成（Host 学习在 pin-check 通过时触发）
    await sleep(1500);

    // 验证 1：B 学到实测可达地址，排在配置自报之后
    const bUrls = nodeB.mgr._getAdvertisedUrls();
    console.log('[验证1] B advertised urls:', bUrls);
    assert.deepEqual(bUrls, ['ws://b.internal:3322', 'ws://127.0.0.1:3322']);
    console.log('✓ 验证 1 通过：B 从入站 Host 学到实测可达地址作为补充\n');

    // 验证 2：学到的地址随 pin-check 重发扩散到 A 的地址簿（自报在前）
    const aBookForB = nodeA.mgr._knownPeers.get('nodeB');
    console.log('[验证2] A 的地址簿中 nodeB 的候选:', aBookForB);
    assert.deepEqual(aBookForB, ['ws://b.internal:3322', 'ws://127.0.0.1:3322']);
    console.log('✓ 验证 2 通过：新地址随自报扩散，对端候选集合并去重\n');

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
