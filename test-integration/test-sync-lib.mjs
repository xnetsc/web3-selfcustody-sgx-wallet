#!/usr/bin/env node
/**
 * sync-lib 独立模块测试
 *
 * 不依赖业务代码，直接测试 sync-lib 纯模块。
 * 使用 better-sqlite3 内存数据库作为 DatabaseAdapter。
 *
 * 运行：
 *   node test-integration/test-sync-lib.mjs
 *
 * 测试覆盖：
 *   ── HLC ──
 *   1.  tick() 单调递增
 *   2.  receive() 合并远程时钟
 *   3.  compare() 字典序
 *   4.  parse() / extractWallTime()
 *   5.  自定义 getNow 注入
 *
 *   ── Leader Election ──
 *   6.  单节点自选举
 *   7.  三节点选举
 *   8.  更高 term 降级
 *   9.  优先级改投
 *   10. quorum 计算
 *   10b. triggerElection() 单节点 Leader 主动触发重新选举
 *   10c. triggerElection() Follower 主动触发选举后集群收敛
 *   10d. SyncEngine.triggerElection() 全分片重新选举
 *
 *   ── Sync Protocol ──
 *   11. 消息编解码往返
 *   12. applyEntries HLC 幂等：远程更新写入
 *   13. applyEntries HLC 幂等：本地更新跳过
 *   14. applyDelete + 墓碑
 *   15. 墓碑阻止过期 INSERT 复活
 *   16. validator 拒绝非法数据
 *   17. deserializer 执行反序列化
 *   18. logChange 手动记录
 *   19. cleanSyncLog 清理
 *   20. cleanTombstones 过期清理
 *   21. getTriggersSQL 生成正确触发器
 *
 *   ── SyncEngine ──
 *   22. registerTable + initSchema + initTriggers
 *   23. peerConnected → 发送 handshake
 *   24. 握手后双向 nodeId 映射
 *   25. 连接去重
 *   26. notifyLocalWrite 推送数据
 *   27. tickPull 拉取
 *   28. tickHeartbeat 超时关闭
 *   29. 2PC 完整流程（Leader + Follower）
 *   30. 2PC 超时 → abort
 *   31. 2PC Follower 拒绝 → abort
 *   32. 2PC term 校验
 *   33. proxyRequest → onExecuteProxyRequest
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const Database = require('better-sqlite3');
import {
    HLC,
    LeaderElection,
    SyncEngine,
    DIALECTS,
    applyDialect,
    validateDialectMethods,
    timeValueToMs,
    SUPPORTED_TIME_UNITS,
    makeHandshake,
    makeSync,
    makeAck,
    makePullRequest,
    makePing,
    makePong,
    makeLeaderHeartbeat,
    makeVoteReq,
    makeVoteAck,
    makeProxyReq,
    makeProxyRes,
    makePrepare,
    makePrepareAck,
    makeCommit,
    makeAbort,
    parseMessage,
    applyEntries,
    readSyncLog,
    getMaxSeq,
    cleanSyncLog,
    cleanTombstones,
    logChange,
    getPeerLastSyncId,
    updatePeerSyncId,
} from '@xnetx/raft-hlc-sync';

/** 标准 getNow 注入：返回 { value, unit } 格式 */
const getNow = () => ({ value: Date.now(), unit: 'ms' });

// ─── 测试框架 ──────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

const _origLog = console.log;
const _origErr = console.error;
const _origWarn = console.warn;
// 屏蔽模块内部日志
console.log = (...args) => {
    const s = String(args[0] ?? '');
    if (s.startsWith('[LeaderElection]') || s.startsWith('[Sync')) return;
    _origLog(...args);
};
console.error = () => {};
console.warn = () => {};

function assert(cond, msg) {
    if (!cond) throw new Error('Assertion failed: ' + msg);
}

async function test(name, fn) {
    try {
        await fn();
        _origLog('  PASS ' + name);
        passed++;
    } catch (e) {
        _origLog('  FAIL ' + name + ' — ' + e.message);
        failed++;
    }
}

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

function tickPullCompat(engine) {
    if (typeof engine._tickPull === 'function') return engine._tickPull();
    if (typeof engine.tickPull === 'function') return engine.tickPull();
    if (typeof engine.onTimer === 'function') return engine.onTimer('pull');
    if (typeof engine.handleTimer === 'function') return engine.handleTimer('pull');
    throw new Error('No compatible pull timer API found on SyncEngine');
}

function tickHeartbeatCompat(engine) {
    if (typeof engine._tickHeartbeat === 'function') return engine._tickHeartbeat();
    if (typeof engine.tickHeartbeat === 'function') return engine.tickHeartbeat();
    if (typeof engine.onTimer === 'function') return engine.onTimer('heartbeat');
    if (typeof engine.handleTimer === 'function') return engine.handleTimer('heartbeat');
    throw new Error('No compatible heartbeat timer API found on SyncEngine');
}

// ─── DatabaseAdapter 工厂 ──────────────────────────────────────────────────

/**
 * 创建 DatabaseAdapter（基础查询 + 方言方法由 applyDialect 填充）。
 */
function createAdapter(sqliteDb) {
    const db = {
        run(sql, params = []) { return sqliteDb.prepare(sql).run(...params); },
        get(sql, params = []) { return sqliteDb.prepare(sql).get(...params) || null; },
        all(sql, params = []) { return sqliteDb.prepare(sql).all(...params); },
        exec(sql)             { sqliteDb.exec(sql); },
    };
    applyDialect(db, 'sqlite');
    return db;
}

/** 创建内存数据库 + adapter + 初始化业务表 */
function createTestDb() {
    const raw = new Database(':memory:');
    raw.pragma('journal_mode = WAL');
    const db = createAdapter(raw);

    // 创建 sync-lib 基础设施表（通过 dialect 获取 SQLite DDL）
    for (const sql of db.infraSchemaSQL()) {
        db.exec(sql);
    }

    // 创建测试业务表
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT NOT NULL PRIMARY KEY,
            name TEXT NOT NULL,
            _hlc TEXT NOT NULL DEFAULT '0'
        )
    `);
    db.exec(`
        CREATE TABLE IF NOT EXISTS items (
            item_id TEXT NOT NULL PRIMARY KEY,
            user_id TEXT NOT NULL,
            value INTEGER NOT NULL DEFAULT 0,
            _hlc TEXT NOT NULL DEFAULT '0'
        )
    `);

    return { raw, db };
}

/** 标准表注册 */
const TEST_TABLES = {
    users: {
        keyColumns: ['user_id'],
        dataColumns: ['user_id', 'name', '_hlc'],
    },
    items: {
        keyColumns: ['item_id'],
        dataColumns: ['item_id', 'user_id', 'value', '_hlc'],
    },
};

function registerTestTables(engine) {
    for (const [name, def] of Object.entries(TEST_TABLES)) {
        engine.registerTable(name, def);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  HLC 测试
// ═══════════════════════════════════════════════════════════════════════════

_origLog('\n── HLC ──');

await test('1. tick() 单调递增', () => {
    const hlc = new HLC('node-1', getNow);
    const t1 = hlc.tick();
    const t2 = hlc.tick();
    const t3 = hlc.tick();
    assert(HLC.compare(t1, t2) < 0, 't1 < t2');
    assert(HLC.compare(t2, t3) < 0, 't2 < t3');
});

await test('2. receive() 合并远程时钟', () => {
    const hlcA = new HLC('A', getNow);
    const hlcB = new HLC('B', getNow);
    const t1 = hlcA.tick();
    const parsed = HLC.parse(t1);
    const t2 = hlcB.receive(parsed.wallTime, parsed.counter);
    // B 收到 A 的时钟后，B 的时间戳应该 > A 的
    assert(HLC.compare(t2, t1) > 0, 'B after receive > A');
});

await test('3. compare() 字典序', () => {
    assert(HLC.compare('000000000001000.00000.A', '000000000001000.00001.A') < 0, 'counter 小');
    assert(HLC.compare('000000000001000.00001.A', '000000000001000.00000.A') > 0, 'counter 大');
    assert(HLC.compare('000000000001000.00000.A', '000000000001000.00000.A') === 0, '相等');
    assert(HLC.compare('000000000001000.00000.A', '000000000001000.00000.B') < 0, 'nodeId A < B');
});

await test('4. parse() / extractWallTime()', () => {
    const ts = '000001712345678.00042.node-x.y';
    const p = HLC.parse(ts);
    assert(p.wallTime === 1712345678, 'wallTime');
    assert(p.counter === 42, 'counter');
    assert(p.nodeId === 'node-x.y', 'nodeId with dot');
    assert(HLC.extractWallTime(ts) === 1712345678, 'extractWallTime');
});

await test('5. 自定义 getNow 注入', () => {
    let fakeNow = 1000000;
    const hlc = new HLC('test', () => ({ value: fakeNow, unit: 'ms' }));
    const t1 = hlc.tick();
    assert(t1.startsWith('000000001000000.'), 'uses fake time: ' + t1);
    fakeNow = 2000000;
    const t2 = hlc.tick();
    assert(HLC.compare(t2, t1) > 0, 't2 > t1');
    assert(t2.startsWith('000000002000000.'), 'uses updated fake time: ' + t2);
});

// ═══════════════════════════════════════════════════════════════════════════
//  Leader Election 测试
// ═══════════════════════════════════════════════════════════════════════════

_origLog('\n── Leader Election ──');

const FAST = { minElectionMs: 80, maxElectionMs: 160, heartbeatIntervalMs: 40 };

function createElectionCluster(numNodes, quorum, shardId = 0) {
    const nodes = [];
    for (let i = 0; i < numNodes; i++) {
        const nodeId = 'n' + i;
        const election = new LeaderElection({
            shardId,
            nodeId,
            getMinQuorum: async () => quorum,
            onSendHeartbeat: (_sid, term, leaderId) => {
                for (const n of nodes) {
                    if (n.nodeId !== leaderId) n.election.receiveHeartbeat(term, leaderId);
                }
            },
            onSendVoteReq: (_sid, term, candidateId, priority) => {
                for (const n of nodes) {
                    if (n.nodeId !== candidateId) n.election.receiveVoteReq(term, candidateId, priority);
                }
            },
            onSendVoteAck: (_sid, term, candidateId, granted) => {
                const target = nodes.find(n => n.nodeId === candidateId);
                if (target) target.election.receiveVoteAck(term, candidateId, granted, nodeId);
            },
            timerAPI: {
                setTimeout,
                clearTimeout,
                setInterval,
                clearInterval,
            },
            onLeaderChanged: () => {},
            _testOptions: FAST,
        });
        nodes.push({ nodeId, election });
    }
    // 互相添加
    for (const n of nodes) {
        for (const m of nodes) {
            if (n !== m) n.election.addNode(m.nodeId);
        }
    }
    return {
        nodes,
        start() { nodes.forEach(n => n.election.start()); },
        stop() { nodes.forEach(n => n.election.stop()); },
        leaders() { return nodes.filter(n => n.election.isLeader()).map(n => n.nodeId); },
        async waitForLeader(ms = 2000) {
            const deadline = Date.now() + ms;
            while (Date.now() < deadline) {
                const ls = this.leaders();
                if (ls.length === 1) return ls[0];
                await sleep(20);
            }
            throw new Error('No single leader (leaders=[' + this.leaders() + '])');
        },
    };
}

await test('6. 单节点自选举', async () => {
    const c = createElectionCluster(1, 1);
    c.start();
    const leader = await c.waitForLeader();
    assert(leader === 'n0', 'n0 is leader');
    c.stop();
});

await test('7. 三节点选举', async () => {
    const c = createElectionCluster(3, 2);
    c.start();
    const leader = await c.waitForLeader();
    assert(c.leaders().length === 1, 'exactly one leader: ' + leader);
    c.stop();
});

await test('8. 更高 term 降级', async () => {
    const c = createElectionCluster(3, 2);
    c.start();
    await c.waitForLeader();
    const leaderNode = c.nodes.find(n => n.election.isLeader());
    // 发送一个更高 term 的心跳
    leaderNode.election.receiveHeartbeat(leaderNode.election._currentTerm + 10, 'phantom');
    assert(!leaderNode.election.isLeader(), 'leader stepped down');
    c.stop();
});

await test('9. 优先级改投', () => {
    // 手动测试：节点投给低优先级候选人后，收到高优先级请求改投
    const acks = [];
    const e = new LeaderElection({
        shardId: 0, nodeId: 'voter',
        getMinQuorum: async () => 2,
        onSendHeartbeat: () => {},
        onSendVoteReq: () => {},
        onSendVoteAck: (_sid, term, candidateId, granted) => { acks.push({ term, candidateId, granted }); },
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
        onLeaderChanged: () => {},
        _testOptions: FAST,
    });
    e.start();
    // term 1, 低优先级
    e.receiveVoteReq(1, 'low', 0.1);
    assert(acks.length === 1 && acks[0].granted === true, 'first vote granted');
    // term 1, 高优先级
    e.receiveVoteReq(1, 'high', 0.9);
    assert(acks.length === 2 && acks[1].granted === true, 'higher priority gets vote');
    e.stop();
});

await test('10. quorum = max(configured, majority)', () => {
    const e = new LeaderElection({
        shardId: 0, nodeId: 'n0',
        getMinQuorum: async () => 1, // 配置 1
        onSendHeartbeat: () => {},
        onSendVoteReq: () => {},
        onSendVoteAck: () => {},
        onLeaderChanged: () => {},
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
        _testOptions: FAST,
    });
    // 3 节点：majority = 2，max(1,2) = 2
    e.addNode('n1');
    e.addNode('n2');
    assert(e._quorum() === 2, 'quorum=2 for 3 nodes even if configured=1');
    e.removeNode('n1');
    e.removeNode('n2');
    // 1 节点：majority = 1，max(1,1) = 1
    assert(e._quorum() === 1, 'quorum=1 for single node');
});

await test('10b. triggerElection() 单节点 Leader 主动触发重新选举', async () => {
    const leaderChanges = [];
    const e = new LeaderElection({
        shardId: 0, nodeId: 'solo',
        getMinQuorum: async () => 1,
        onSendHeartbeat: () => {},
        onSendVoteReq: () => {},
        onSendVoteAck: () => {},
        onLeaderChanged: (_sid, id) => { leaderChanges.push(id); },
        timerAPI: { setTimeout, clearTimeout, setInterval, clearInterval },
        _testOptions: FAST,
    });
    e.start();

    // 等待自选为 Leader
    await new Promise((resolve, reject) => {
        const deadline = Date.now() + 1000;
        const check = () => {
            if (e.isLeader()) return resolve();
            if (Date.now() > deadline) return reject(new Error('未在 1s 内成为 Leader'));
            setTimeout(check, 20);
        };
        check();
    });
    assert(e.isLeader(), '触发前应为 Leader');

    // 主动触发重新选举
    e.triggerElection();

    // 触发后立即降级
    assert(!e.isLeader(), 'triggerElection 后应立即降级');

    // 等待重新当选（quorum=1，自选）
    await new Promise((resolve, reject) => {
        const deadline = Date.now() + 1000;
        const check = () => {
            if (e.isLeader()) return resolve();
            if (Date.now() > deadline) return reject(new Error('重新选举未在 1s 内完成'));
            setTimeout(check, 20);
        };
        check();
    });
    assert(e.isLeader(), 'triggerElection 后应重新当选');

    // leaderChanges 应包含: null(降级) + 'solo'(重新当选)
    const hasStepdown = leaderChanges.includes(null);
    const hasReelect  = leaderChanges.includes('solo');
    assert(hasStepdown, '应触发降级事件(null)，实际=' + JSON.stringify(leaderChanges));
    assert(hasReelect,  '应触发重选事件(solo)，实际=' + JSON.stringify(leaderChanges));

    e.stop();
});

await test('10c. triggerElection() Follower 主动触发选举后集群收敛', async () => {
    const c = createElectionCluster(3, 2);
    c.start();
    const firstLeader = await c.waitForLeader();

    // 找一个 follower 并触发选举
    const follower = c.nodes.find(n => n.nodeId !== firstLeader);
    follower.election.triggerElection();

    // 等待集群重新收敛到一个 Leader
    await c.waitForLeader(2000);
    assert(c.leaders().length === 1, 'triggerElection 后集群应收敛到唯一 Leader，实际=' + c.leaders());

    c.stop();
});

await test('10d. SyncEngine.triggerElection() 全分片重新选举', async () => {
    const { db } = createTestDb();
    let leaderCount = 0;

    const engine = new SyncEngine({
        nodeId: 'E', db, numShards: 2, getMinQuorum: () => 1,
        onSendToPeer: () => {}, onClosePeer: () => {}, onLeaderChanged: (_sid, _id, isLocal) => {
            if (isLocal) leaderCount++;
        },
        onWriteCompleted: () => {}, onError: () => {},
        getNow,
        onExecuteProxyRequest: async () => ({ status: 200 }),
        timerAPI: { setTimeout, clearTimeout, setInterval, clearInterval },
        _testOptions: FAST,
    });
    registerTestTables(engine);
    engine.initSchema();
    engine.initTriggers();
    engine.start();

    // 等待所有分片完成首次选举（numShards=2，均为单节点自选）
    await new Promise((resolve, reject) => {
        const deadline = Date.now() + 2000;
        const check = () => {
            const status = engine.getStatus();
            const allLeader = status.shards.every(s => s.state === 'leader');
            if (allLeader) return resolve();
            if (Date.now() > deadline) return reject(new Error('首次选举未完成，状态=' + JSON.stringify(status.shards)));
            setTimeout(check, 20);
        };
        check();
    });

    const countBefore = leaderCount;
    assert(countBefore >= 2, '首次选举应产生 >=2 次 onLeaderChanged(isLocal=true)，实际=' + countBefore);

    // 主动触发全分片重新选举
    engine.triggerElection();

    // 等待重新选举完成
    await new Promise((resolve, reject) => {
        const deadline = Date.now() + 2000;
        const check = () => {
            const status = engine.getStatus();
            const allLeader = status.shards.every(s => s.state === 'leader');
            if (allLeader) return resolve();
            if (Date.now() > deadline) return reject(new Error('重新选举超时，状态=' + JSON.stringify(status.shards)));
            setTimeout(check, 20);
        };
        check();
    });

    // triggerElection 后应再次触发 onLeaderChanged(isLocal=true)
    assert(leaderCount > countBefore, 'triggerElection 后应有新的 onLeaderChanged(isLocal=true) 事件，实际总计=' + leaderCount);

    engine.stop();
});

// ═══════════════════════════════════════════════════════════════════════════
//  Sync Protocol 测试
// ═══════════════════════════════════════════════════════════════════════════

_origLog('\n── Sync Protocol ──');

await test('11. 消息编解码往返', () => {
    const cases = [
        makeHandshake('node-1', 42),
        makeSync([{ seq: 1, table_name: 't', operation: 'INSERT', row_key: '{}', row_data: '{}', _hlc: 'x' }]),
        makeAck(99),
        makePullRequest(10),
        makePing(),
        makePong(),
        makeLeaderHeartbeat(0, 5, 'leader-1'),
        makeVoteReq(0, 3, 'cand-1', 0.5),
        makeVoteAck(0, 3, 'cand-1', true, 'voter-1'),
        makeProxyReq('req-1', { method: 'POST' }),
        makeProxyRes('req-1', { status: 200 }),
        makePrepare('w1', [], 5, 0),
        makePrepareAck('w1', true, null),
        makeCommit('w1'),
        makeAbort('w1', 'timeout'),
    ];
    for (const raw of cases) {
        const parsed = parseMessage(raw);
        assert(parsed !== null, 'parse should succeed for: ' + raw.substring(0, 50));
        assert(typeof parsed.type === 'string', 'has type');
    }
    assert(parseMessage('not json') === null, 'invalid json returns null');
});

await test('12. applyEntries: 远程 HLC 更新 → 写入', () => {
    const { db } = createTestDb();
    const hlc = new HLC('local', getNow);
    const registry = new Map(Object.entries(TEST_TABLES));

    // 插入一条远程数据
    const remoteHlc = '000009999999999.00001.remote';
    const entries = [{
        seq: 1,
        table_name: 'users',
        operation: 'INSERT',
        row_key: JSON.stringify({ user_id: 'u1' }),
        row_data: JSON.stringify({ user_id: 'u1', name: 'Alice', _hlc: remoteHlc }),
        _hlc: remoteHlc,
    }];
    const result = applyEntries(db, entries, hlc, registry);
    assert(result.applied === 1, 'applied=1');
    const row = db.get('SELECT * FROM users WHERE user_id = ?', ['u1']);
    assert(row && row.name === 'Alice', 'Alice written');
});

await test('13. applyEntries: 本地 HLC 更新 → 跳过', () => {
    const { db } = createTestDb();
    const hlc = new HLC('local', getNow);
    const registry = new Map(Object.entries(TEST_TABLES));

    // 先写入一条本地数据（hlc 很大）
    const localHlc = '000009999999999.00099.local';
    db.run('INSERT INTO users (user_id, name, _hlc) VALUES (?, ?, ?)', ['u1', 'Local', localHlc]);

    // 远程数据 hlc 较小
    const remoteHlc = '000009999999999.00001.remote';
    const entries = [{
        seq: 1,
        table_name: 'users',
        operation: 'UPDATE',
        row_key: JSON.stringify({ user_id: 'u1' }),
        row_data: JSON.stringify({ user_id: 'u1', name: 'Remote', _hlc: remoteHlc }),
        _hlc: remoteHlc,
    }];
    const result = applyEntries(db, entries, hlc, registry);
    assert(result.skipped === 1, 'skipped=1');
    const row = db.get('SELECT name FROM users WHERE user_id = ?', ['u1']);
    assert(row.name === 'Local', 'Local data preserved');
});

await test('14. applyDelete + 墓碑', () => {
    const { db } = createTestDb();
    const hlc = new HLC('local', getNow);
    const registry = new Map(Object.entries(TEST_TABLES));

    // 先插入
    const insertHlc = '000009999999990.00001.remote';
    db.run('INSERT INTO users (user_id, name, _hlc) VALUES (?, ?, ?)', ['u1', 'Alice', insertHlc]);

    // 远程删除（hlc 更大）
    const deleteHlc = '000009999999999.00001.remote';
    const entries = [{
        seq: 1,
        table_name: 'users',
        operation: 'DELETE',
        row_key: JSON.stringify({ user_id: 'u1' }),
        row_data: null,
        _hlc: deleteHlc,
    }];
    const result = applyEntries(db, entries, hlc, registry);
    assert(result.applied === 1, 'delete applied');
    const row = db.get('SELECT * FROM users WHERE user_id = ?', ['u1']);
    assert(!row, 'row deleted');
    const tomb = db.get('SELECT * FROM _tombstones WHERE table_name = ? AND row_key = ?',
        ['users', JSON.stringify({ user_id: 'u1' })]);
    assert(tomb && tomb._hlc === deleteHlc, 'tombstone written');
});

await test('15. 墓碑阻止过期 INSERT 复活', () => {
    const { db } = createTestDb();
    const hlc = new HLC('local', getNow);
    const registry = new Map(Object.entries(TEST_TABLES));

    // 写入墓碑（hlc 大）
    const tombHlc = '000009999999999.00099.remote';
    db.run('INSERT INTO _tombstones (table_name, row_key, _hlc) VALUES (?, ?, ?)',
        ['users', JSON.stringify({ user_id: 'u1' }), tombHlc]);

    // 尝试用更小的 hlc 插入
    const oldHlc = '000009999999999.00001.remote';
    const entries = [{
        seq: 1,
        table_name: 'users',
        operation: 'INSERT',
        row_key: JSON.stringify({ user_id: 'u1' }),
        row_data: JSON.stringify({ user_id: 'u1', name: 'Ghost', _hlc: oldHlc }),
        _hlc: oldHlc,
    }];
    const result = applyEntries(db, entries, hlc, registry);
    assert(result.skipped === 1, 'insert blocked by tombstone');
    const row = db.get('SELECT * FROM users WHERE user_id = ?', ['u1']);
    assert(!row, 'no row resurrected');
});

await test('16. validator 拒绝非法数据', () => {
    const { db } = createTestDb();
    const hlc = new HLC('local', getNow);
    const registry = new Map();
    registry.set('users', {
        ...TEST_TABLES.users,
        validator: (row) => { if (!row.name) throw new Error('name required'); },
    });

    const remoteHlc = '000009999999999.00001.remote';
    const entries = [{
        seq: 1,
        table_name: 'users',
        operation: 'INSERT',
        row_key: JSON.stringify({ user_id: 'u1' }),
        row_data: JSON.stringify({ user_id: 'u1', _hlc: remoteHlc }), // 缺 name
        _hlc: remoteHlc,
    }];
    const result = applyEntries(db, entries, hlc, registry);
    assert(result.skipped === 1, 'validator rejected entry');
});

await test('17. deserializer 执行反序列化', () => {
    const { db } = createTestDb();
    const hlc = new HLC('local', getNow);
    const registry = new Map();
    let deserializerCalled = false;
    registry.set('users', {
        ...TEST_TABLES.users,
        deserializer: (row) => { deserializerCalled = true; row.name = row.name.toUpperCase(); return row; },
    });

    const remoteHlc = '000009999999999.00001.remote';
    const entries = [{
        seq: 1,
        table_name: 'users',
        operation: 'INSERT',
        row_key: JSON.stringify({ user_id: 'u1' }),
        row_data: JSON.stringify({ user_id: 'u1', name: 'alice', _hlc: remoteHlc }),
        _hlc: remoteHlc,
    }];
    applyEntries(db, entries, hlc, registry);
    assert(deserializerCalled, 'deserializer was called');
    const row = db.get('SELECT name FROM users WHERE user_id = ?', ['u1']);
    assert(row.name === 'ALICE', 'name uppercased by deserializer');
});

await test('18. logChange 手动记录', () => {
    const { db } = createTestDb();
    logChange(db, 'users', 'INSERT', '{"user_id":"u1"}', '{"user_id":"u1","name":"A","_hlc":"x"}', 'hlc-ts');
    const row = db.get('SELECT * FROM _sync_log WHERE id = 1', []);
    assert(row && row.table_name === 'users', 'logged to _sync_log');
    assert(row.operation === 'INSERT', 'operation correct');
    assert(row._hlc === 'hlc-ts', '_hlc correct');
});

await test('19. cleanSyncLog 清理', () => {
    const { db } = createTestDb();
    for (let i = 0; i < 20; i++) {
        logChange(db, 'users', 'INSERT', '{}', '{}', 'hlc-' + i);
    }
    assert(getMaxSeq(db) === 20, '20 entries');
    cleanSyncLog(db, 10); // 保留 10 条
    const count = db.get('SELECT COUNT(*) AS cnt FROM _sync_log', []);
    assert(count.cnt === 10, '10 entries after cleanup, got ' + count.cnt);
});

await test('20. cleanTombstones 过期清理', () => {
    const { db } = createTestDb();
    // 写入一个过期墓碑（wallTime 是 8 天前）
    const oldMs = Date.now() - 8 * 24 * 3600 * 1000;
    const oldHlc = oldMs.toString().padStart(15, '0') + '.00000.old';
    db.run('INSERT INTO _tombstones (table_name, row_key, _hlc) VALUES (?, ?, ?)',
        ['users', '{"user_id":"old"}', oldHlc]);
    // 写入一个新墓碑
    const newHlc = Date.now().toString().padStart(15, '0') + '.00000.new';
    db.run('INSERT INTO _tombstones (table_name, row_key, _hlc) VALUES (?, ?, ?)',
        ['users', '{"user_id":"new"}', newHlc]);

    const cleaned = cleanTombstones(db, getNow, 7);
    assert(cleaned === 1, 'cleaned 1 old tombstone');
    const remaining = db.all('SELECT * FROM _tombstones', []);
    assert(remaining.length === 1 && remaining[0].row_key === '{"user_id":"new"}', 'new tombstone preserved');
});

await test('21. DIALECTS.sqlite.triggersSQL 生成完整触发器（含 HLC 校验）', () => {
    const sqls = DIALECTS.sqlite.triggersSQL('users', TEST_TABLES.users);
    assert(sqls.length === 5, '5 triggers (hlc_insert/hlc_update/insert/update/delete)');
    assert(sqls[0].includes('_sync_trg_users_hlc_insert'), 'hlc insert guard trigger');
    assert(sqls[1].includes('_sync_trg_users_hlc_update'), 'hlc update guard trigger');
    assert(sqls[2].includes('_sync_trg_users_insert'), 'insert trigger');
    assert(sqls[3].includes('_sync_trg_users_update'), 'update trigger');
    assert(sqls[4].includes('_sync_trg_users_delete'), 'delete trigger');
    // 验证 key 和 data 表达式
    assert(sqls[2].includes("'user_id', NEW.user_id"), 'key expr');
    assert(sqls[2].includes("'name', NEW.name"), 'data expr');
    // HLC 校验触发器包含 RAISE
    assert(sqls[0].includes('RAISE(ABORT'), 'hlc_insert guard has RAISE');
    assert(sqls[1].includes('RAISE(ABORT'), 'hlc_update guard has RAISE');
    // dropTriggersSQL 包含全部 5 个
    const drops = DIALECTS.sqlite.dropTriggersSQL('users');
    assert(drops.length === 5, '5 drop statements');
    assert(drops.some(s => s.includes('_hlc_insert')), 'drop hlc_insert');
    assert(drops.some(s => s.includes('_hlc_update')), 'drop hlc_update');
});

await test('21f. HLC 校验触发器：INSERT 缺少 HLC 抛错', () => {
    const { db, raw } = createTestDb();
    const engine = new SyncEngine({
        nodeId: 'test', db,
        onSendToPeer: () => {}, onClosePeer: () => {}, onLeaderChanged: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        timerAPI: {
            setTimeout: (fn, ms) => setTimeout(fn, ms),
            clearTimeout: (id) => clearTimeout(id),
            setInterval: (fn, ms) => setInterval(fn, ms),
            clearInterval: (id) => clearInterval(id),
        },
    });
    registerTestTables(engine);
    engine.initSchema();
    engine.initTriggers();

    // 不带 _hlc（使用默认值 '0'）应该抛错
    let threw = false;
    try {
        raw.prepare('INSERT INTO users (user_id, name) VALUES (?, ?)').run('u1', 'NoHlc');
    } catch (e) {
        threw = true;
        assert(e.message.includes('_hlc is required'), 'error mentions _hlc: ' + e.message);
    }
    assert(threw, 'INSERT without HLC should throw');

    // 带正确 HLC 应该成功
    const hlc = new HLC('test', getNow);
    raw.prepare('INSERT INTO users (user_id, name, _hlc) VALUES (?, ?, ?)').run('u2', 'WithHlc', hlc.tick());
    const row = db.get('SELECT * FROM users WHERE user_id = ?', ['u2']);
    assert(row && row.name === 'WithHlc', 'INSERT with HLC succeeds');

    engine.dropTriggers();
    engine.stop();
});

await test('21g. HLC 校验触发器：UPDATE 时钟回退抛错', () => {
    const { db, raw } = createTestDb();
    const engine = new SyncEngine({
        nodeId: 'test', db,
        onSendToPeer: () => {}, onClosePeer: () => {}, onLeaderChanged: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        timerAPI: {
            setTimeout: (fn, ms) => setTimeout(fn, ms),
            clearTimeout: (id) => clearTimeout(id),
            setInterval: (fn, ms) => setInterval(fn, ms),
            clearInterval: (id) => clearInterval(id),
        },
    });
    registerTestTables(engine);
    engine.initSchema();
    engine.initTriggers();

    const hlc = new HLC('test', getNow);
    const t1 = hlc.tick();
    raw.prepare('INSERT INTO users (user_id, name, _hlc) VALUES (?, ?, ?)').run('u1', 'Alice', t1);

    // UPDATE 使用相同或更小的 HLC 应该抛错
    let threw = false;
    try {
        raw.prepare('UPDATE users SET name = ?, _hlc = ? WHERE user_id = ?').run('Bob', t1, 'u1');
    } catch (e) {
        threw = true;
        assert(e.message.includes('_hlc must advance'), 'error mentions advance: ' + e.message);
    }
    assert(threw, 'UPDATE with same HLC should throw');

    // UPDATE 使用更大的 HLC 应该成功
    const t2 = hlc.tick();
    raw.prepare('UPDATE users SET name = ?, _hlc = ? WHERE user_id = ?').run('Bob', t2, 'u1');
    const row = db.get('SELECT * FROM users WHERE user_id = ?', ['u1']);
    assert(row && row.name === 'Bob', 'UPDATE with advanced HLC succeeds');

    engine.dropTriggers();
    engine.stop();
});

// ═══════════════════════════════════════════════════════════════════════════
//  Dialect 测试
// ═══════════════════════════════════════════════════════════════════════════

_origLog('\n── Dialect ──');

await test('21b. dialect: sqlite 自动填充方言方法', () => {
    const raw = new Database(':memory:');
    raw.pragma('journal_mode = WAL');
    const db = {
        run(sql, params = []) { return raw.prepare(sql).run(...params); },
        get(sql, params = []) { return raw.prepare(sql).get(...params) || null; },
        all(sql, params = []) { return raw.prepare(sql).all(...params); },
        exec(sql)             { raw.exec(sql); },
    };
    // db 上没有任何方言方法
    assert(typeof db.beginTransaction !== 'function', 'no beginTransaction before');
    assert(typeof db.upsertSQL !== 'function', 'no upsertSQL before');
    assert(typeof db.triggersSQL !== 'function', 'no triggersSQL before');

    const engine = new SyncEngine({
        nodeId: 'test', db, dialect: 'sqlite',
        onSendToPeer: () => {}, onClosePeer: () => {}, onLeaderChanged: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
    });

    // dialect 应该自动填充
    assert(typeof db.beginTransaction === 'function', 'beginTransaction filled');
    assert(typeof db.upsertSQL === 'function', 'upsertSQL filled');
    assert(typeof db.infraSchemaSQL === 'function', 'infraSchemaSQL filled');
    assert(typeof db.triggersSQL === 'function', 'triggersSQL filled');
    assert(typeof db.dropTriggersSQL === 'function', 'dropTriggersSQL filled');

    // 验证功能正确
    registerTestTables(engine);
    engine.initSchema();
    raw.exec('CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, name TEXT NOT NULL, _hlc TEXT NOT NULL DEFAULT \'0\')');
    raw.exec('CREATE TABLE IF NOT EXISTS items (item_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, value INTEGER NOT NULL DEFAULT 0, _hlc TEXT NOT NULL DEFAULT \'0\')');
    engine.initTriggers();
    const hlc = new HLC('test', getNow);
    db.run('INSERT INTO users (user_id, name, _hlc) VALUES (?, ?, ?)', ['u1', 'Hi', hlc.tick()]);
    const log = db.get('SELECT * FROM _sync_log WHERE id = 1', []);
    assert(log && log.table_name === 'users', 'dialect trigger works');
    engine.dropTriggers();
    engine.stop();
});

await test('21c. 无 dialect 且缺失方法 → 报错', () => {
    const db = {
        run() {}, get() {}, all() {}, exec() {},
    };
    let threw = false;
    try {
        new SyncEngine({
            nodeId: 'test', db,
            onSendToPeer: () => {}, onClosePeer: () => {}, onLeaderChanged: () => {},
            getNow,
            onExecuteProxyRequest: async (p) => p,
            timerAPI: {
                setTimeout,
                clearTimeout,
                setInterval,
                clearInterval,
            },
        });
    } catch (e) {
        threw = true;
        assert(e.message.includes('missing required methods'), 'error mentions missing methods: ' + e.message);
        assert(e.message.includes('beginTransaction'), 'mentions beginTransaction');
        assert(e.message.includes('upsertSQL'), 'mentions upsertSQL');
        assert(e.message.includes('triggersSQL'), 'mentions triggersSQL');
    }
    assert(threw, 'should throw when dialect missing and methods not injected');
});

await test('21d. 未知 dialect → 报错', () => {
    const db = { run() {}, get() {}, all() {}, exec() {} };
    let threw = false;
    try {
        new SyncEngine({
            nodeId: 'test', db, dialect: 'oracle',
            onSendToPeer: () => {}, onClosePeer: () => {}, onLeaderChanged: () => {},
            getNow,
            onExecuteProxyRequest: async (p) => p,
            timerAPI: {
                setTimeout,
                clearTimeout,
                setInterval,
                clearInterval,
            },
        });
    } catch (e) {
        threw = true;
        assert(e.message.includes('Unknown dialect'), 'error mentions unknown dialect');
        assert(e.message.includes('oracle'), 'error mentions oracle');
    }
    assert(threw, 'should throw for unknown dialect');
});

await test('21e. dialect 不覆盖已有方法', () => {
    const raw = new Database(':memory:');
    raw.pragma('journal_mode = WAL');
    let customCalled = false;
    const db = {
        run(sql, params = []) { return raw.prepare(sql).run(...params); },
        get(sql, params = []) { return raw.prepare(sql).get(...params) || null; },
        all(sql, params = []) { return raw.prepare(sql).all(...params); },
        exec(sql)             { raw.exec(sql); },
        // 自定义 upsertSQL，应优先于 dialect
        upsertSQL(table, columns) {
            customCalled = true;
            const cols = columns.join(', ');
            const ph = columns.map(() => '?').join(', ');
            return `INSERT OR REPLACE INTO ${table} (${cols}) VALUES (${ph})`;
        },
    };
    const engine = new SyncEngine({
        nodeId: 'test', db, dialect: 'sqlite',
        onSendToPeer: () => {}, onClosePeer: () => {}, onLeaderChanged: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
    });
    registerTestTables(engine);
    engine.initSchema();
    // 调用 upsertSQL 应走自定义路径
    db.upsertSQL('users', ['user_id', 'name', '_hlc'], ['user_id']);
    assert(customCalled, 'custom upsertSQL was used, not overwritten by dialect');
    engine.stop();
});

// ═══════════════════════════════════════════════════════════════════════════
//  SyncEngine 测试
// ═══════════════════════════════════════════════════════════════════════════

_origLog('\n── SyncEngine ──');

/** 创建一对通过内存直连的 SyncEngine 实例 */
function createEnginesPair(opts = {}) {
    const { raw: rawA, db: dbA } = createTestDb();
    const { raw: rawB, db: dbB } = createTestDb();

    const sentA = []; // A 发出的消息
    const sentB = []; // B 发出的消息
    const closedA = []; // A 被关闭的 peer
    const closedB = [];
    const leaderChangesA = [];
    const leaderChangesB = [];

    const engineA = new SyncEngine({
        nodeId: 'A',
        db: dbA,
        numShards: 1,
        getMinQuorum: () => 1,
        onSendToPeer: (peerId, msg) => { sentA.push({ peerId, msg }); },
        onClosePeer: (peerId, reason) => { closedA.push({ peerId, reason }); },
        onLeaderChanged: (sid, lid, local) => { leaderChangesA.push({ sid, lid, local }); },
        onWriteCompleted: () => {},
        onError: () => {},
        getNow,
        onExecuteProxyRequest: async (payload) => ({ status: 200, body: payload }),
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },

        ...opts.a,
    });

    const engineB = new SyncEngine({
        nodeId: 'B',
        db: dbB,
        numShards: 1,
        getMinQuorum: () => 1,
        onSendToPeer: (peerId, msg) => { sentB.push({ peerId, msg }); },
        onClosePeer: (peerId, reason) => { closedB.push({ peerId, reason }); },
        onLeaderChanged: (sid, lid, local) => { leaderChangesB.push({ sid, lid, local }); },
        onWriteCompleted: () => {},
        onError: () => {},
        getNow,
        onExecuteProxyRequest: async (payload) => ({ status: 200, body: payload }),
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
        ...opts.b,
    });

    registerTestTables(engineA);
    registerTestTables(engineB);
    engineA.initSchema();
    engineB.initSchema();
    engineA.initTriggers();
    engineB.initTriggers();

    return {
        engineA, engineB,
        dbA, dbB, rawA, rawB,
        sentA, sentB, closedA, closedB,
        leaderChangesA, leaderChangesB,
        /** 将 A 的所有待发消息投递给 B，反之亦然 */
        flush() {
            const a2b = sentA.splice(0);
            const b2a = sentB.splice(0);
            for (const { msg } of a2b) engineB.receiveMessage('peer-A', msg);
            for (const { msg } of b2a) engineA.receiveMessage('peer-B', msg);
        },
        stopAll() {
            engineA.stop();
            engineB.stop();
        },
    };
}

await test('22. registerTable + initSchema + initTriggers', () => {
    const { db } = createTestDb();
    const engine = new SyncEngine({
        nodeId: 'test', db,
        onSendToPeer: () => {}, onClosePeer: () => {}, onLeaderChanged: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
    });
    registerTestTables(engine);
    engine.initSchema(); // 重复调用不报错
    engine.initTriggers();

    // 验证触发器生效：插入一行，_sync_log 应有记录
    const hlc = new HLC('test', getNow);
    db.run('INSERT INTO users (user_id, name, _hlc) VALUES (?, ?, ?)', ['u1', 'Test', hlc.tick()]);
    const log = db.get('SELECT * FROM _sync_log WHERE id = 1', []);
    assert(log && log.table_name === 'users', 'trigger wrote to _sync_log');
    assert(log.operation === 'INSERT', 'operation INSERT');

    // 清理触发器
    engine.dropTriggers();
    engine.stop();
});

await test('22b. initTriggers 支持适配器注入 triggersSQL', () => {
    const { raw, db } = createTestDb();

    // 给 db 注入自定义 triggersSQL（复用 DIALECTS.sqlite 实现，但证明走的是注入路径）
    // v1.0.26+: initTriggers 优先使用拆分版 hlc/changeLog TriggersSQL，删除它们以强制走聚合版路径
    delete db.hlcTriggersSQL;
    delete db.changeLogTriggersSQL;
    delete db.dropHlcTriggersSQL;
    delete db.dropChangeLogTriggersSQL;
    let injectedCalled = false;
    db.triggersSQL = (tableName, def) => {
        injectedCalled = true;
        return DIALECTS.sqlite.triggersSQL(tableName, def);
    };
    let dropCalled = false;
    db.dropTriggersSQL = (tableName) => {
        dropCalled = true;
        return DIALECTS.sqlite.dropTriggersSQL(tableName);
    };

    const engine = new SyncEngine({
        nodeId: 'test', db,
        onSendToPeer: () => {}, onClosePeer: () => {}, onLeaderChanged: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
    });
    registerTestTables(engine);
    engine.initSchema();
    engine.initTriggers();

    assert(injectedCalled, 'db.triggersSQL was called');

    // 验证触发器生效
    const hlc = new HLC('test', getNow);
    db.run('INSERT INTO users (user_id, name, _hlc) VALUES (?, ?, ?)', ['u1', 'Test', hlc.tick()]);
    const log = db.get('SELECT * FROM _sync_log WHERE id = 1', []);
    assert(log && log.table_name === 'users', 'injected trigger wrote to _sync_log');

    engine.dropTriggers();
    assert(dropCalled, 'db.dropTriggersSQL was called');
    engine.stop();
});

await test('23. peerConnected → 发送 handshake', () => {
    const p = createEnginesPair();
    p.engineA.start();
    p.engineA.peerConnected('peer-B', { direction: 'outbound' });

    assert(p.sentA.length === 1, 'A sent one message');
    const msg = parseMessage(p.sentA[0].msg);
    assert(msg.type === 'handshake', 'message is handshake');
    assert(msg.nodeId === 'A', 'nodeId is A');
    p.stopAll();
});

await test('24. 握手后双向 nodeId 映射', () => {
    const p = createEnginesPair();
    p.engineA.start();
    p.engineB.start();

    // A 连 B
    p.engineA.peerConnected('peer-B', { direction: 'outbound' });
    p.engineB.peerConnected('peer-A', { direction: 'inbound' });

    // 交换握手
    p.flush(); // A→B handshake, B→A handshake
    p.flush(); // 处理对方的握手

    const statusA = p.engineA.getStatus();
    const statusB = p.engineB.getStatus();
    assert(statusA.nodeIdMap.some(e => e.nodeId === 'B'), 'A knows B');
    assert(statusB.nodeIdMap.some(e => e.nodeId === 'A'), 'B knows A');
    p.stopAll();
});

await test('25. 连接去重', () => {
    // 单个 engine，同一个 nodeId 从两条连接握手
    const { db } = createTestDb();
    const closed = [];

    const engine = new SyncEngine({
        nodeId: 'A', db, numShards: 1, getMinQuorum: () => 1,
        onSendToPeer: () => {},
        onClosePeer: (pid, reason) => { closed.push({ pid, reason }); },
        onLeaderChanged: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
    });
    registerTestTables(engine);
    engine.initSchema();
    engine.initTriggers();
    engine.start();

    // 第一条出站连接，握手成功
    engine.peerConnected('conn-1', { direction: 'outbound' });
    engine.receiveMessage('conn-1', makeHandshake('B', 0));
    assert(closed.length === 0, 'no close yet');

    // 第二条入站连接，同一个 nodeId B
    engine.peerConnected('conn-2', { direction: 'inbound' });
    engine.receiveMessage('conn-2', makeHandshake('B', 0));

    // 去重应该关闭其中一条
    assert(closed.length === 1, 'one connection dedup-closed, got ' + closed.length);
    assert(closed[0].reason === 'dedup', 'reason is dedup');

    engine.stop();
});

await test('26. notifyLocalWrite 推送数据', () => {
    const p = createEnginesPair();
    p.engineA.start();
    p.engineB.start();
    p.engineA.initTriggers();

    // 建立连接
    p.engineA.peerConnected('peer-B', { direction: 'outbound' });
    p.engineB.peerConnected('peer-A', { direction: 'inbound' });
    p.flush();
    p.flush();

    // A 写数据
    const hlcTs = p.engineA.hlc.tick();
    p.dbA.run('INSERT INTO users (user_id, name, _hlc) VALUES (?, ?, ?)', ['u1', 'Alice', hlcTs]);
    p.sentA.length = 0; // 清空之前的消息

    p.engineA.notifyLocalWrite();
    assert(p.sentA.length >= 1, 'A sent sync message');
    const syncMsg = p.sentA.find(m => parseMessage(m.msg)?.type === 'sync');
    assert(syncMsg, 'has sync message');

    p.engineA.dropTriggers();
    p.stopAll();
});


await test('27. tickPull 拉取', () => {
    const p = createEnginesPair();
    p.engineA.start();
    p.engineB.start();

    p.engineA.peerConnected('peer-B', { direction: 'outbound' });
    p.engineB.peerConnected('peer-A', { direction: 'inbound' });
    p.flush();
    p.flush();
    p.sentA.length = 0;

    tickPullCompat(p.engineA);
    const pullMsg = p.sentA.find(m => parseMessage(m.msg)?.type === 'pull_req');
    assert(pullMsg, 'A sent pull_req');
    p.stopAll();
});

await test('28. tickHeartbeat 超时关闭', async () => {
    const p = createEnginesPair({
        a: { heartbeatTimeoutMs: 50, heartbeatIntervalMs: 20 },
    });
    p.engineA.start();
    p.engineA.peerConnected('peer-B', { direction: 'outbound' });

    // 模拟 B 的握手让 A 识别 nodeId
    p.engineA.receiveMessage('peer-B', makeHandshake('B', 0));

    await sleep(100); // 超过 heartbeatTimeoutMs

    tickHeartbeatCompat(p.engineA);
    assert(p.closedA.some(c => c.peerId === 'peer-B' && c.reason === 'heartbeat_timeout'),
        'peer-B closed due to timeout');
    p.stopAll();
});

// ─── 2PC 测试 ──────────────────────────────────────────────────────────────

_origLog('\n── 2PC ──');

await test('29a. engine.write() 高阶 API 自动处理 2PC', async () => {
    const { raw: rawA, db: dbA } = createTestDb();
    const { raw: rawB, db: dbB } = createTestDb();
    const queueA2B = [];
    const queueB2A = [];

    const engineA = new SyncEngine({
        nodeId: 'A', db: dbA, numShards: 1, getMinQuorum: () => 1,
        onSendToPeer: (pid, msg) => { queueA2B.push(msg); },
        onClosePeer: () => {}, onLeaderChanged: () => {},
        onWriteCompleted: () => {}, onError: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        prepareTimeoutMs: 3000,
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
    });
    const engineB = new SyncEngine({
        nodeId: 'B', db: dbB, numShards: 1, getMinQuorum: () => 1,
        onSendToPeer: (pid, msg) => { queueB2A.push(msg); },
        onClosePeer: () => {}, onLeaderChanged: () => {},
        onWriteCompleted: () => {}, onError: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        followerTxnTimeoutMs: 5000,
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
    });

    registerTestTables(engineA);
    registerTestTables(engineB);
    engineA.initSchema();
    engineB.initSchema();
    engineA.initTriggers();
    engineB.initTriggers();
    engineA.initTriggers();

    dbB.exec(`CREATE TABLE IF NOT EXISTS users (
        user_id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, _hlc TEXT NOT NULL DEFAULT '0'
    )`);

    engineA.start();
    engineB.start();

    engineA.peerConnected('peer-B', { direction: 'outbound' });
    engineB.peerConnected('peer-A', { direction: 'inbound' });
    for (const msg of queueA2B.splice(0)) engineB.receiveMessage('peer-A', msg);
    for (const msg of queueB2A.splice(0)) engineA.receiveMessage('peer-B', msg);
    for (const msg of queueA2B.splice(0)) engineB.receiveMessage('peer-A', msg);
    for (const msg of queueB2A.splice(0)) engineA.receiveMessage('peer-B', msg);

    // 使用高阶 write() API
    const writePromise = engineA.write(async (db) => {
        const ts = engineA.hlc.tick();
        db.run('INSERT INTO users (user_id, name, _hlc) VALUES (?, ?, ?)', ['u1', 'Alice', ts]);
        return { userId: 'u1', name: 'Alice' };
    }, 'u1');

    // 让 write() 内部的 async fn 执行完并到达 waitForPrepareAck 挂起点
    await sleep(0);

    // 投递 prepare 给 B
    for (const msg of queueA2B.splice(0)) engineB.receiveMessage('peer-A', msg);
    // B 发回 prepare_ack
    for (const msg of queueB2A.splice(0)) engineA.receiveMessage('peer-B', msg);
    // 投递 commit 给 B
    for (const msg of queueA2B.splice(0)) engineB.receiveMessage('peer-A', msg);

    const result = await writePromise;
    assert(result && result.userId === 'u1', 'write() returns fn result');

    const rowA = dbA.get('SELECT * FROM users WHERE user_id = ?', ['u1']);
    const rowB = dbB.get('SELECT * FROM users WHERE user_id = ?', ['u1']);
    assert(rowA && rowA.name === 'Alice', 'A has Alice');
    assert(rowB && rowB.name === 'Alice', 'B has Alice via write()');

    engineA.stop();
    engineB.stop();
});


await test('29. 2PC 完整流程（Leader + Follower）', async () => {
    const { raw: rawA, db: dbA } = createTestDb();
    const { raw: rawB, db: dbB } = createTestDb();

    // 用消息队列模拟通信
    const queueA2B = [];
    const queueB2A = [];

    const engineA = new SyncEngine({
        nodeId: 'A', db: dbA, numShards: 1, getMinQuorum: () => 1,
        onSendToPeer: (pid, msg) => { queueA2B.push(msg); },
        onClosePeer: () => {}, onLeaderChanged: () => {},
        onWriteCompleted: () => {}, onError: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        prepareTimeoutMs: 3000,
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
    });
    const engineB = new SyncEngine({
        nodeId: 'B', db: dbB, numShards: 1, getMinQuorum: () => 1,
        onSendToPeer: (pid, msg) => { queueB2A.push(msg); },
        onClosePeer: () => {}, onLeaderChanged: () => {},
        onWriteCompleted: () => {}, onError: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        followerTxnTimeoutMs: 5000,
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
    });

    registerTestTables(engineA);
    registerTestTables(engineB);
    engineA.initSchema();
    engineB.initSchema();
    engineA.initTriggers();
    engineB.initTriggers();
    engineA.initTriggers();
    // B 不需要触发器（Follower 通过 applyEntries 写入）

    // 创建 B 的 users 表
    dbB.exec(`CREATE TABLE IF NOT EXISTS users (
        user_id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, _hlc TEXT NOT NULL DEFAULT '0'
    )`);

    engineA.start();
    engineB.start();

    // 建立连接
    engineA.peerConnected('peer-B', { direction: 'outbound' });
    engineB.peerConnected('peer-A', { direction: 'inbound' });

    // 交换握手
    for (const msg of queueA2B.splice(0)) engineB.receiveMessage('peer-A', msg);
    for (const msg of queueB2A.splice(0)) engineA.receiveMessage('peer-B', msg);
    for (const msg of queueA2B.splice(0)) engineB.receiveMessage('peer-A', msg);
    for (const msg of queueB2A.splice(0)) engineA.receiveMessage('peer-B', msg);

    // Leader A: 2PC 写操作
    const writeId = 'w1';
    engineA.beginManualTransaction(writeId);
    const hlcTs = engineA.hlc.tick();
    dbA.run('INSERT INTO users (user_id, name, _hlc) VALUES (?, ?, ?)', ['u1', 'Alice', hlcTs]);
    const entries = engineA.getManualTransactionEntries(writeId);
    assert(entries.length >= 1, 'has entries');

    // 启动 prepare 等待
    const preparePromise = engineA.waitForPrepareAck(writeId, entries, 0, 0);

    // 投递 prepare 给 B
    for (const msg of queueA2B.splice(0)) engineB.receiveMessage('peer-A', msg);

    // B 应该发回 prepare_ack
    assert(queueB2A.length >= 1, 'B sent prepare_ack');
    for (const msg of queueB2A.splice(0)) engineA.receiveMessage('peer-B', msg);

    // prepare 应该 resolve
    await preparePromise;

    // Leader commit
    engineA.commitManualTransaction(writeId);
    engineA.broadcastCommit(writeId);

    // 投递 commit 给 B
    for (const msg of queueA2B.splice(0)) engineB.receiveMessage('peer-A', msg);

    // 验证双方数据
    const rowA = dbA.get('SELECT * FROM users WHERE user_id = ?', ['u1']);
    const rowB = dbB.get('SELECT * FROM users WHERE user_id = ?', ['u1']);
    assert(rowA && rowA.name === 'Alice', 'A has Alice');
    assert(rowB && rowB.name === 'Alice', 'B has Alice');

    engineA.stop();
    engineB.stop();
});

await test('30. 2PC 超时 → abort', async () => {
    const { db: dbA } = createTestDb();
    const aborted = [];

    const engine = new SyncEngine({
        nodeId: 'A', db: dbA, numShards: 1, getMinQuorum: () => 1,
        onSendToPeer: (pid, msg) => {
            const m = parseMessage(msg);
            if (m?.type === 'abort') aborted.push(m);
        },
        onClosePeer: () => {}, onLeaderChanged: () => {},
        onWriteCompleted: () => {}, onError: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        prepareTimeoutMs: 100,
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
    });
    registerTestTables(engine);
    engine.initSchema();
    engine.initTriggers();
    engine.start();

    // 添加一个假 peer（不会回应）
    engine.peerConnected('peer-B', { direction: 'outbound' });
    engine.receiveMessage('peer-B', makeHandshake('B', 0));

    let rejected = false;
    try {
        await engine.waitForPrepareAck('w1', [{ seq: 1 }], 0, 0);
    } catch (e) {
        rejected = true;
        assert(e.message.includes('timeout'), 'timeout error: ' + e.message);
    }
    assert(rejected, 'prepare was rejected');
    assert(aborted.length >= 1, 'abort was broadcast');

    engine.stop();
});

await test('31. 2PC Follower busy → reject → abort', async () => {
    // 测试 Follower 已有活跃事务时拒绝 prepare
    const { db: dbA } = createTestDb();
    const { db: dbB } = createTestDb();
    const qA2B = [];
    const qB2A = [];
    const aborted = [];

    const engineA = new SyncEngine({
        nodeId: 'A', db: dbA, numShards: 1, getMinQuorum: () => 1,
        onSendToPeer: (pid, msg) => {
            qA2B.push(msg);
            const m = parseMessage(msg);
            if (m?.type === 'abort') aborted.push(m);
        },
        onClosePeer: () => {}, onLeaderChanged: () => {},
        onWriteCompleted: () => {}, onError: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        prepareTimeoutMs: 3000,
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
    });
    const engineB = new SyncEngine({
        nodeId: 'B', db: dbB, numShards: 1, getMinQuorum: () => 1,
        onSendToPeer: (pid, msg) => { qB2A.push(msg); },
        onClosePeer: () => {}, onLeaderChanged: () => {},
        onWriteCompleted: () => {}, onError: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        followerTxnTimeoutMs: 5000,
        timerAPI: {
            setTimeout,
            clearTimeout,
            setInterval,
            clearInterval,
        },
    });

    registerTestTables(engineA);
    registerTestTables(engineB);
    engineA.initSchema();
    engineB.initSchema();
    engineA.initTriggers();
    engineB.initTriggers();

    // B 也需要 users 表
    dbB.exec(`CREATE TABLE IF NOT EXISTS users (
        user_id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, _hlc TEXT NOT NULL DEFAULT '0'
    )`);

    engineA.start();
    engineB.start();

    engineA.peerConnected('peer-B', { direction: 'outbound' });
    engineB.peerConnected('peer-A', { direction: 'inbound' });
    for (const msg of qA2B.splice(0)) engineB.receiveMessage('peer-A', msg);
    for (const msg of qB2A.splice(0)) engineA.receiveMessage('peer-B', msg);
    for (const msg of qA2B.splice(0)) engineB.receiveMessage('peer-A', msg);
    for (const msg of qB2A.splice(0)) engineA.receiveMessage('peer-B', msg);

    const entries1 = [{
        seq: 1, table_name: 'users', operation: 'INSERT',
        row_key: '{"user_id":"u1"}',
        row_data: '{"user_id":"u1","name":"X","_hlc":"000009999999999.00001.A"}',
        _hlc: '000009999999999.00001.A',
    }];

    // 第一个 prepare 让 B 进入活跃事务状态
    qA2B.length = 0;
    qB2A.length = 0;
    engineB.receiveMessage('peer-A', makePrepare('w-first', entries1, 0, 0));
    // B 应该 ack granted=true，但我们不投递给 A（模拟丢失），让 B 保持事务打开

    // 第二个 prepare 应该被 B 拒绝（busy）
    aborted.length = 0;
    qA2B.length = 0;

    const preparePromise = engineA.waitForPrepareAck('w-second', entries1, 0, 0);
    for (const msg of qA2B.splice(0)) engineB.receiveMessage('peer-A', msg);
    for (const msg of qB2A.splice(0)) engineA.receiveMessage('peer-B', msg);

    let rejected = false;
    try {
        await preparePromise;
    } catch (e) {
        rejected = true;
    }
    assert(rejected, 'prepare rejected by busy follower');
    assert(aborted.length >= 1, 'abort broadcast');

    engineA.stop();
    engineB.stop();
});

await test('32. 2PC term 校验：过期 term 被拒绝', () => {
    const { db: dbB } = createTestDb();
    const acks = [];

    const engineB = new SyncEngine({
        nodeId: 'B', db: dbB, numShards: 1, getMinQuorum: () => 1,
        onSendToPeer: (pid, msg) => { acks.push(parseMessage(msg)); },
        onClosePeer: () => {}, onLeaderChanged: () => {},
        onWriteCompleted: () => {}, onError: () => {},
        getNow,
        onExecuteProxyRequest: async (p) => p,
        timerAPI: {
                setTimeout,
                clearTimeout,
                setInterval,
                clearInterval,
        },
    });
    registerTestTables(engineB);
    engineB.initSchema();
    engineB.initTriggers();
    engineB.start();

    engineB.peerConnected('peer-A', { direction: 'inbound' });
    engineB.receiveMessage('peer-A', makeHandshake('A', 0));

    // 人为推高 B 的 term
    const election = engineB._shardElections.get(0);
    election._currentTerm = 10;

    // 发送 term=1 的 prepare（过期）
    acks.length = 0;
    engineB.receiveMessage('peer-A', makePrepare('w-stale', [{ seq: 1 }], 1, 0));

    const ack = acks.find(m => m?.type === 'prepare_ack');
    assert(ack && ack.granted === false, 'stale term rejected');

    engineB.stop();
});

await test('33. proxyRequest → onExecuteProxyRequest', async () => {
    const { db: dbA } = createTestDb();
    let executedPayload = null;

    const engineA = new SyncEngine({
        nodeId: 'A', db: dbA, numShards: 1, getMinQuorum: () => 1,
        onSendToPeer: () => {}, onClosePeer: () => {}, onLeaderChanged: () => {},
        onWriteCompleted: () => {}, onError: () => {},
        getNow,
        onExecuteProxyRequest: async (payload) => {
            executedPayload = payload;
            return { status: 200, body: 'ok' };
        },
        timerAPI: {
                setTimeout,
                clearTimeout,
                setInterval,
                clearInterval,
        },
    });
    registerTestTables(engineA);
    engineA.initSchema();
    engineA.initTriggers();
    engineA.start();

    // 让 A 成为 leader（单节点）
    await sleep(300); // 等选举完成

    const result = await engineA.proxyRequest('some-user', { method: 'POST', data: 123 });
    assert(executedPayload && executedPayload.method === 'POST', 'payload forwarded');
    assert(result.status === 200, 'response received');

    engineA.stop();
});

// ═══════════════════════════════════════════════════════════════════════════

_origLog('\n── Result ──');
_origLog('  Total: ' + (passed + failed) + '  Passed: ' + passed + '  Failed: ' + failed);

console.log = _origLog;
console.error = _origErr;
console.warn = _origWarn;

process.exit(1);
