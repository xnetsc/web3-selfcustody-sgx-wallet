/**
 * 多地址簿单元测试 —— 真实 SyncManager + 导出的纯函数
 *
 * 覆盖：
 *   1. normalizeSyncUrl：默认端口补齐（同地址不同写法的去重基础）、显式
 *      端口保留、非法输入拒绝
 *   2. urlFromHostHeader：Host 带端口用该端口，没带补协议默认端口
 *   3. mergePeerUrls：去重、保序、自报前置、上限截断
 *   4. SyncManager 地址簿行为：自报前置、gossip 新旧格式合并、已知节点
 *      补充新地址；通告集恒等于配置集（地址只从配置来）
 *
 * 运行: node p2p-address-book.test.mjs
 */

import assert from 'node:assert';
import { createRequire } from 'module';
import {
    SyncManager,
    normalizeSyncUrl,
    parseAdvertisedUrls,
    mergePeerUrls,
} from '../sgx-enclave/src/sync/sync-manager.js';
import { HLC } from '../sgx-enclave/node_modules/@xnetx/raft-hlc-sync/index.js';
import { ALL_TABLE_SQLS } from '../sgx-enclave/src/database/schema.js';

const require_fn = createRequire(import.meta.url);
const Database = require_fn('../sgx-enclave/node_modules/better-sqlite3');

let passed = 0;
function check(name, fn) {
    fn();
    passed++;
    console.log('✓ ' + name);
}

// ---------- 1. normalizeSyncUrl ----------

check('normalizeSyncUrl 补默认端口（wss 443 / ws 80）', () => {
    assert.equal(normalizeSyncUrl('wss://a.example.com'), 'wss://a.example.com:443');
    assert.equal(normalizeSyncUrl('ws://a.example.com'), 'ws://a.example.com:80');
});

check('normalizeSyncUrl 保留显式端口、host 小写化、丢弃路径', () => {
    assert.equal(normalizeSyncUrl('wss://A.Example.com:8443'), 'wss://a.example.com:8443');
    assert.equal(normalizeSyncUrl('wss://a.example.com:8443/some/path?x=1'), 'wss://a.example.com:8443');
    assert.equal(normalizeSyncUrl('ws://127.0.0.1:3307'), 'ws://127.0.0.1:3307');
});

check('normalizeSyncUrl 等价写法归一（去重的依据）', () => {
    assert.equal(normalizeSyncUrl('wss://a.com'), normalizeSyncUrl('wss://a.com:443'));
});

check('normalizeSyncUrl 拒绝非法输入', () => {
    assert.equal(normalizeSyncUrl('http://a.com'), null);
    assert.equal(normalizeSyncUrl('not a url'), null);
    assert.equal(normalizeSyncUrl(''), null);
    assert.equal(normalizeSyncUrl(null), null);
    assert.equal(normalizeSyncUrl(123), null);
});

// ---------- 2. parseAdvertisedUrls（地址只从配置来） ----------

check('parseAdvertisedUrls：单个字符串', () => {
    assert.deepEqual(parseAdvertisedUrls('wss://a.com'), ['wss://a.com:443']);
    assert.deepEqual(parseAdvertisedUrls('wss://a.com:8443'), ['wss://a.com:8443']);
});

check('parseAdvertisedUrls：JSON 数组字符串（环境变量形态）', () => {
    assert.deepEqual(
        parseAdvertisedUrls('["wss://a.com", "wss://b.com:8443"]'),
        ['wss://a.com:443', 'wss://b.com:8443']);
});

check('parseAdvertisedUrls：字符串数组、等价写法去重、非法项丢弃', () => {
    assert.deepEqual(
        parseAdvertisedUrls(['wss://a.com', 'wss://a.com:443', 'not a url', 'wss://b.com']),
        ['wss://a.com:443', 'wss://b.com:443']);
    assert.deepEqual(parseAdvertisedUrls(''), []);
    assert.deepEqual(parseAdvertisedUrls(null), []);
    assert.deepEqual(parseAdvertisedUrls('[]'), []);
});

// ---------- 3. mergePeerUrls ----------

check('mergePeerUrls：追加合并去重保序', () => {
    const merged = mergePeerUrls(
        ['wss://a.com'],
        ['wss://a.com:443', 'wss://b.com:8443'],
    );
    assert.deepEqual(merged, ['wss://a.com:443', 'wss://b.com:8443']);
});

check('mergePeerUrls：front 自报前置', () => {
    const merged = mergePeerUrls(
        ['wss://old.com:443', 'wss://b.com:8443'],
        ['wss://new.com'],
        { front: true },
    );
    assert.deepEqual(merged, ['wss://new.com:443', 'wss://old.com:443', 'wss://b.com:8443']);
});

check('mergePeerUrls：超过上限截断尾部', () => {
    const many = Array.from({ length: 12 }, (_, i) => 'wss://h' + i + '.com');
    assert.equal(mergePeerUrls([], many).length, 8);
});

// ---------- 4. SyncManager 地址簿行为 ----------

function createManager(nodeId, extra = {}) {
    const db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    for (const { sql, indexes } of ALL_TABLE_SQLS) {
        db.exec(sql);
        for (const idx of indexes) db.exec(idx);
    }
    const hlc = new HLC(nodeId, () => ({ value: Date.now(), unit: 'ms' }));
    const mgr = new SyncManager({
        db,
        hlc,
        peerUrls: [],
        listenPort: 3399,
        contractClient: null,
        getMinQuorum: () => 1,
        ...extra,
    });
    // 记录拨号意图，避免单测真的向外连接
    mgr._dialed = [];
    mgr._connectToPeer = (url) => { mgr._dialed.push(url); };
    return mgr;
}

check('自报地址前置：listenUrls + listenUrl 合并去重排首位', () => {
    const mgr = createManager('self-1');
    mgr._recordPeerAdvertisedUrl('wss://x.com:1', {
        nodeId: 'node-b',
        listenUrl: 'wss://b.com',
        listenUrls: ['wss://b.com:443', 'wss://10.0.0.9:3307'],
    });
    assert.deepEqual(mgr._knownPeers.get('node-b'),
        ['wss://b.com:443', 'wss://10.0.0.9:3307']);
});

check('拨通的地址只作补充，不抢自报的首位', () => {
    const mgr = createManager('self-2');
    mgr._recordPeerAdvertisedUrl('p', {
        nodeId: 'node-b', listenUrl: 'wss://b.com', listenUrls: [],
    });
    mgr._extractNodeIdFromHandshake('wss://dialed.com:9443',
        JSON.stringify({ type: 'handshake', nodeId: 'node-b', lastSeq: 0 }));
    assert.deepEqual(mgr._knownPeers.get('node-b'),
        ['wss://b.com:443', 'wss://dialed.com:9443']);
});

check('gossip：旧格式 url 与新格式 urls 均合并，已知节点可补充新地址', () => {
    const mgr = createManager('self-3');
    const sender = 'wss://sender.com:443';
    mgr._pinCheckedPeers.add(sender);
    mgr._handlePeersList(sender, null, [{ nodeId: 'node-c', url: 'wss://c.com' }]);
    assert.deepEqual(mgr._knownPeers.get('node-c'), ['wss://c.com:443']);
    mgr._handlePeersList(sender, null, [{
        nodeId: 'node-c',
        urls: ['wss://c2.com:9443', 'wss://c.com:443'],
    }]);
    assert.deepEqual(mgr._knownPeers.get('node-c'),
        ['wss://c.com:443', 'wss://c2.com:9443']);
});

check('gossip：未过 pin-check 的发送方被拒绝', () => {
    const mgr = createManager('self-4');
    mgr._handlePeersList('wss://stranger.com:443', null, [{ nodeId: 'node-c', url: 'wss://c.com' }]);
    assert.equal(mgr._knownPeers.has('node-c'), false);
});

check('通告集就是配置集：JSON 数组配置原样成为通告集（规范化去重）', () => {
    const mgr = createManager('self-5', {
        advertisedUrl: '["wss://a.com", "wss://b.com:8443", "wss://a.com:443"]',
    });
    assert.deepEqual(mgr._getAdvertisedUrls(), ['wss://a.com:443', 'wss://b.com:8443']);
    assert.equal(mgr._getAdvertisedUrl(), 'wss://a.com:443');
});

check('通告集就是配置集：单个字符串配置', () => {
    const mgr = createManager('self-6', { advertisedUrl: 'wss://only.com:9443' });
    assert.deepEqual(mgr._getAdvertisedUrls(), ['wss://only.com:9443']);
});

console.log('\n=== 全部通过（' + passed + ' 项）===');
process.exit(0);
