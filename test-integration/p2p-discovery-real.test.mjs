/**
 * P2P 节点发现端到端测试 —— 使用真实 SyncManager
 *
 * 场景：3 个节点，A 只配置连接 B，C 只配置连接 B，B 不配置任何节点。
 * 验证：
 *   1. 节点连接 + pin-check 握手（真实代码路径）
 *   2. pin-check 自报 nodeId + listenUrl（入站方也能学到可连接地址）
 *   3. peers-list 定期广播 + 病毒式发现
 *   4. A 与 C 互相发现并建立连接（去重、跳过自己）
 *
 * 运行: node p2p-discovery-real.test.mjs
 */

import assert from 'node:assert';
import { createRequire } from 'module';
import { SyncManager } from '../sgx-enclave/src/sync/sync-manager.js';
import { HLC } from '../sgx-enclave/node_modules/@xnetx/raft-hlc-sync/index.js';
import { ALL_TABLE_SQLS } from '../sgx-enclave/src/database/schema.js';

const require_fn = createRequire(import.meta.url);
const Database = require_fn('../sgx-enclave/node_modules/better-sqlite3');

// 缩短广播间隔以加速测试（覆盖模块常量不可行，直接手动触发广播）

function createDb() {
    const db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    for (const { sql, indexes } of ALL_TABLE_SQLS) {
        db.exec(sql);
        for (const idx of indexes) db.exec(idx);
    }
    return db;
}

// 共同的 pinned 身份（所有节点一致，pin-check 才能通过）
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

function createNode(name, port, peerUrls) {
    const db = createDb();
    const hlc = new HLC(name, () => ({ value: Date.now(), unit: 'ms' }));
    const mgr = new SyncManager({
        db,
        hlc,
        peerUrls,
        listenPort: port,
        advertisedUrl: 'ws://127.0.0.1:' + port, // 显式自报地址
        contractClient: createMockContractClient(),
        getMinQuorum: () => 1,
    });
    return { name, mgr, db };
}

async function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function main() {
    console.log('=== P2P 发现端到端测试（真实 SyncManager）===\n');

    // 拓扑：A → B ← C（B 无任何配置）
    const nodeA = createNode('nodeA', 3311, ['ws://127.0.0.1:3312']);
    const nodeB = createNode('nodeB', 3312, []);
    const nodeC = createNode('nodeC', 3313, ['ws://127.0.0.1:3312']);

    await nodeA.mgr.start();
    await nodeB.mgr.start();
    await nodeC.mgr.start();

    // 等待连接 + pin-check 完成
    await sleep(1500);

    // 验证 1：pin-check 自报地址 —— B 是纯入站方，也应学到 A 和 C 的可连接地址
    const bKnown = nodeB.mgr._knownPeers;
    console.log('[验证1] B known peers:', [...bKnown.entries()]);
    assert(bKnown.has('nodeA'), 'B should learn nodeA via pin-check self-advertisement');
    assert(bKnown.has('nodeC'), 'B should learn nodeC via pin-check self-advertisement');
    assert.equal(bKnown.get('nodeA'), 'ws://127.0.0.1:3311');
    assert.equal(bKnown.get('nodeC'), 'ws://127.0.0.1:3313');
    console.log('✓ 验证 1 通过：入站方通过 pin-check 自报学到可连接地址\n');

    // 验证 2：手动触发 B 广播 peers-list，A 和 C 应互相发现并连接
    nodeB.mgr._broadcastPeers();
    await sleep(1500);

    const aKnown = nodeA.mgr._knownPeers;
    const cKnown = nodeC.mgr._knownPeers;
    console.log('[验证2] A known peers:', [...aKnown.entries()]);
    console.log('[验证2] C known peers:', [...cKnown.entries()]);
    assert(aKnown.has('nodeC'), 'A should discover nodeC via peers-list');
    assert(cKnown.has('nodeA'), 'C should discover nodeA via peers-list');
    console.log('✓ 验证 2 通过：peers-list 广播实现病毒式发现\n');

    // 验证 3：A 与 C 之间建立了连接并通过 pin-check
    const aConnectedNodeIds = new Set(nodeA.mgr._peerIdToNodeId.values());
    const cConnectedNodeIds = new Set(nodeC.mgr._peerIdToNodeId.values());
    console.log('[验证3] A connected nodeIds:', [...aConnectedNodeIds]);
    console.log('[验证3] C connected nodeIds:', [...cConnectedNodeIds]);
    assert(aConnectedNodeIds.has('nodeC') || cConnectedNodeIds.has('nodeA'),
        'A and C should be connected to each other');
    console.log('✓ 验证 3 通过：新发现的节点自动建立连接\n');

    // 验证 4：去重 —— 没有节点把自己加入 _knownPeers
    assert(!aKnown.has('nodeA'), 'A should not contain itself');
    assert(!bKnown.has('nodeB'), 'B should not contain itself');
    assert(!cKnown.has('nodeC'), 'C should not contain itself');
    console.log('✓ 验证 4 通过：不会把自己加入已知节点列表\n');

    // 验证 5：再次广播 + 等待，确认没有重复连接风暴（连接数稳定）
    const aPeerCountBefore = nodeA.mgr._peerWsMap.size;
    nodeA.mgr._broadcastPeers();
    nodeB.mgr._broadcastPeers();
    nodeC.mgr._broadcastPeers();
    await sleep(1000);
    const aPeerCountAfter = nodeA.mgr._peerWsMap.size;
    console.log('[验证5] A connections before/after re-broadcast:', aPeerCountBefore, '/', aPeerCountAfter);
    assert(aPeerCountAfter <= aPeerCountBefore + 1, 'No duplicate connection storm');
    console.log('✓ 验证 5 通过：重复广播不产生重复连接\n');

    nodeA.mgr.stop();
    nodeB.mgr.stop();
    nodeC.mgr.stop();
    nodeA.db.close();
    nodeB.db.close();
    nodeC.db.close();

    console.log('=== 全部通过 ===');
    process.exit(0);
}

main().catch((err) => {
    console.error('Test failed:', err);
    process.exit(1);
});
