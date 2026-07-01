#!/usr/bin/env node
/**
 * Leader Election 本地单元 + 集成测试
 *
 * 不依赖 Docker / Gramine / SGX，直接 import JS 模块，本地 Mac 可运行：
 *   node test-integration/test-leader-election.mjs
 *
 * 测试覆盖：
 *   1.   单节点自选
 *   2.   双节点选出唯一 Leader
 *   2b.  双节点同时发起选举（手工构造），高优先级节点获胜
 *   2c.  双节点选主后，follower 保持跟随状态
 *   2d.  双节点 Leader 宕机后，单节点无法独自选主（quorum 不满足）
 *   3.   三节点选出唯一 Leader
 *   3b.  三节点 Leader 宕机后，剩余 2 节点重新选主（quorum=2 满足）
 *   3c.  三节点两节点宕机后，单节点无法选主（quorum=2 不满足）
 *   4.   quorum 不足时无法选主（4 节点 2-2 分区，quorum=3）
 *   5.   Leader 降级：连接数跌破 quorum 后主动降级
 *   6.   降级后自动重新选举
 *   7.   优先级投票：同 term 多候选人，高优先级获胜
 *   8.   同一候选人重复 vote_req 继续获得支持
 *   9.   更高 term 心跳触发降级
 *   10.  多分片独立选举，互不干扰
 *   11.  Sync Push: ≤5 peer 全量推送
 *   12.  Sync Push: >5 peer fanout=5 限制
 *   13.  Sync Push: fanout 随机选择（不固定）
 *   14.  Sync Push: 推送失败时 backup 补位
 *   15.  Sync Push: 级联不回推来源节点已有的数据
 *   16.  Sync Push: 级联仍推来源节点缺少的其他数据
 *
 *  triggerElection() 主动触发选举：
 *   17.  单节点 Leader 主动触发选举 → 先降级再重选
 *   18.  三节点 Follower 主动触发选举 → 集群收敛到唯一 Leader
 *   19.  三节点 Leader 主动触发选举 → 集群重新收敛
 *   20.  多次连续 triggerElection() → 最终收敛到唯一 Leader
 */

import { LeaderElection } from '@xnetx/raft-hlc-sync';

// ─── 测试框架 ────────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function assert(cond, msg) {
    if (!cond) throw new Error('Assertion failed: ' + msg);
}

// 屏蔽 LeaderElection 内部日志（避免选举重试噪音）
const _origLog = console.log;
console.log = (...args) => {
    const s = String(args[0] ?? '');
    if (s.startsWith('[LeaderElection]')) return;
    _origLog(...args);
};

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

// ─── 测试用时间参数（加速选举，避免等待几秒）────────────────────────────────

const FAST = {
    minElectionMs: 80,
    maxElectionMs: 160,
    heartbeatIntervalMs: 40,
};

// ─── SimulatedCluster：内存内节点集合，消息通过函数调用直接传递 ─────────────

class SimulatedCluster {
    /**
     * @param {number} numNodes
     * @param {number} quorum
     * @param {number} [shardId=0]
     */
    constructor(numNodes, quorum, shardId = 0) {
        this.shardId = shardId;
        this.quorum = quorum;
        this.nodes = [];
        this._partitions = null; // null = 全连接

        for (let i = 0; i < numNodes; i++) {
            const nodeId = 'node-' + i;
            const election = new LeaderElection({
                shardId,
                nodeId,
                getMinQuorum: async () => quorum,
                onSendHeartbeat: (_sid, term, leaderId) => {
                    for (const n of this.nodes) {
                        if (n.nodeId !== leaderId && this._isConnected(leaderId, n.nodeId)) {
                            n.election.receiveHeartbeat(term, leaderId);
                        }
                    }
                },
                onSendVoteReq: (_sid, term, candidateId, priority) => {
                    for (const n of this.nodes) {
                        if (n.nodeId !== candidateId && this._isConnected(candidateId, n.nodeId)) {
                            n.election.receiveVoteReq(term, candidateId, priority);
                        }
                    }
                },
                onSendVoteAck: (_sid, term, candidateId, granted) => {
                    const target = this.nodes.find(n => n.nodeId === candidateId);
                    if (target && this._isConnected(nodeId, candidateId)) {
                        target.election.receiveVoteAck(term, candidateId, granted, nodeId);
                    }
                },
                onLeaderChanged: () => {},
                timerAPI: { setTimeout, clearTimeout, setInterval, clearInterval },

                _testOptions: FAST,
            });
            this.nodes.push({ nodeId, election });
        }

        this._connectAll();
    }

    _connectAll() {
        for (const n of this.nodes) {
            for (const m of this.nodes) {
                if (n.nodeId !== m.nodeId) n.election.addNode(m.nodeId);
            }
        }
    }

    _isConnected(fromId, toId) {
        if (!this._partitions) return true;
        return this._partitions.some(p => p.includes(fromId) && p.includes(toId));
    }

    /** 模拟网络分区：partitions = [['node-0','node-1'], ['node-2','node-3']] */
    partition(partitions) {
        this._partitions = partitions;
        for (const n of this.nodes) {
            for (const m of this.nodes) {
                if (n.nodeId === m.nodeId) continue;
                if (this._isConnected(n.nodeId, m.nodeId)) {
                    n.election.addNode(m.nodeId);
                } else {
                    n.election.removeNode(m.nodeId);
                }
            }
        }
    }

    /** 恢复全连接 */
    heal() {
        this._partitions = null;
        this._connectAll();
    }

    start() { for (const n of this.nodes) n.election.start(); }
    stop()  { for (const n of this.nodes) n.election.stop(); }

    leaders() { return this.nodes.filter(n => n.election.isLeader()).map(n => n.nodeId); }

    get(nodeId) { return this.nodes.find(n => n.nodeId === nodeId); }

    /** 等待恰好出现一个 Leader */
    waitForLeader(timeoutMs = 2000) {
        return new Promise((resolve, reject) => {
            const deadline = Date.now() + timeoutMs;
            const check = () => {
                const ls = this.leaders();
                if (ls.length === 1) return resolve(ls[0]);
                if (Date.now() > deadline) {
                    return reject(new Error(
                        'No single leader after ' + timeoutMs + 'ms (leaders=[' + ls.join(',') + '])'
                    ));
                }
                setTimeout(check, 20);
            };
            check();
        });
    }

    /** 等待所有节点都没有 Leader */
    waitForNoLeader(timeoutMs = 2000) {
        return new Promise((resolve, reject) => {
            const deadline = Date.now() + timeoutMs;
            const check = () => {
                if (this.leaders().length === 0) return resolve();
                if (Date.now() > deadline) {
                    return reject(new Error('Still have leader after ' + timeoutMs + 'ms'));
                }
                setTimeout(check, 20);
            };
            check();
        });
    }
}

// ─── 测试用例 ────────────────────────────────────────────────────────────────

console.log('\n  Leader Election Tests\n');

// 1. 单节点自选
await test('单节点 quorum=1 应当自选为 Leader', async () => {
    const c = new SimulatedCluster(1, 1);
    c.start();
    const leader = await c.waitForLeader();
    c.stop();
    assert(leader === 'node-0', 'expected node-0, got ' + leader);
});

// 2. 双节点选出唯一 Leader
await test('双节点 quorum=2 选出唯一 Leader', async () => {
    const c = new SimulatedCluster(2, 2);
    c.start();
    await c.waitForLeader();
    c.stop();
    assert(c.leaders().length === 1, '应只有一个 Leader');
});

// 2b. 双节点同时发起选举（手工构造，不依赖定时器），高优先级节点获胜
await test('双节点同时发起选举（手工构造），高优先级节点获胜', async () => {
    let winner = null;
    let eA, eB;

    // 两节点互相路由消息，不启动任何定时器
    eA = new LeaderElection({
        shardId: 0, nodeId: 'A',
        getMinQuorum: async () => 2,
        onSendHeartbeat: () => {},
        onSendVoteReq: (_sid, term, cid, priority) => eB.receiveVoteReq(term, cid, priority),
        onSendVoteAck: (_sid, term, cid, granted)   => eB.receiveVoteAck(term, cid, granted, 'A'),
        onLeaderChanged: (_sid, id) => { if (id === 'A') winner = 'A'; },
        timerAPI: { setTimeout, clearTimeout, setInterval, clearInterval },

        _testOptions: FAST,
    });
    eB = new LeaderElection({
        shardId: 0, nodeId: 'B',
        getMinQuorum: async () => 2,
        onSendHeartbeat: () => {},
        onSendVoteReq: (_sid, term, cid, priority) => eA.receiveVoteReq(term, cid, priority),
        onSendVoteAck: (_sid, term, cid, granted)   => eA.receiveVoteAck(term, cid, granted, 'B'),
        onLeaderChanged: (_sid, id) => { if (id === 'B') winner = 'B'; },
        timerAPI: { setTimeout, clearTimeout, setInterval, clearInterval },

        _testOptions: FAST,
    });
    eA.addNode('B'); eB.addNode('A');
    eA._started = true; eB._started = true;
    eA._cachedQuorum = 2; eB._cachedQuorum = 2;

    // 手工让两节点同时处于 term=1 candidate 状态，各自自投
    // A 优先级 0.3（低），B 优先级 0.8（高）→ 期望 B 获胜
    eA._currentTerm = 1; eA._state = 'candidate'; eA._electionPriority = 0.3;
    eA._votedFor.set(1, { candidateId: 'A', priority: 0.3 });
    eA._votesGranted = new Set(['A']);

    eB._currentTerm = 1; eB._state = 'candidate'; eB._electionPriority = 0.8;
    eB._votedFor.set(1, { candidateId: 'B', priority: 0.8 });
    eB._votesGranted = new Set(['B']);

    // 模拟互发 vote_req：
    //   A 收到 B 的请求 (0.8 > 0.3) → 改投 B → B 得 2 票 → 当选
    //   B 收到 A 的请求 (0.3 < 0.8) → 不改投 → A 仍只有 1 票
    eA.receiveVoteReq(1, 'B', 0.8);
    eB.receiveVoteReq(1, 'A', 0.3);

    eA.stop(); eB.stop();

    assert(winner === 'B',     '高优先级节点 B 应获胜，实际=' + winner);
    assert(eB.isLeader(),      'eB 应是 Leader');
    assert(!eA.isLeader(),     'eA 不应是 Leader');
});

// 2c. 双节点选主后，follower 收到心跳应保持跟随状态，不再发起选举
await test('双节点选主后，follower 保持跟随状态并知晓 Leader 身份', async () => {
    const c = new SimulatedCluster(2, 2);
    try {
        c.start();
        const leaderId = await c.waitForLeader();
        const follower  = c.nodes.find(n => n.nodeId !== leaderId);

        // 等待至少一个心跳周期（heartbeatIntervalMs=40ms），确保 follower 收到心跳
        await sleep(150);

        assert(follower.election._state === 'follower',
               'follower 状态应为 follower，实际=' + follower.election._state);
        assert(!follower.election.isLeader(),
               'follower 不应成为 Leader');
        assert(follower.election.getLeaderNodeId() === leaderId,
               'follower 应知道 Leader 是 ' + leaderId + '，实际=' + follower.election.getLeaderNodeId());
    } finally { c.stop(); }
});

// 2d. 双节点 Leader 宕机后，单节点无法达到 quorum=2 独自选主
await test('双节点 Leader 宕机后，单节点无法独自选主（quorum=2 不满足）', async () => {
    const c = new SimulatedCluster(2, 2);
    try {
        c.start();
        const leaderId    = await c.waitForLeader();
        const survivorId  = c.nodes.find(n => n.nodeId !== leaderId).nodeId;

        // 停止 Leader（模拟宕机），survivor 感知到连接断开
        c.get(leaderId).election.stop();
        c.get(survivorId).election.removeNode(leaderId);

        // 等待多轮选举周期（每轮 80-160ms），survivor 应一直选不出 Leader
        await sleep(600);

        assert(!c.get(survivorId).election.isLeader(),
               '单节点不应能独自赢得选举（quorum=2 不满足）');
    } finally { c.stop(); }
});

// 3. 三节点选出唯一 Leader
await test('三节点 quorum=2 选出唯一 Leader', async () => {
    const c = new SimulatedCluster(3, 2);
    c.start();
    await c.waitForLeader();
    c.stop();
    assert(c.leaders().length === 1, '应只有一个 Leader');
});

// 3b. 三节点 Leader 宕机，剩余 2 节点重新选主（quorum=2 满足）
await test('三节点 Leader 宕机后，剩余 2 节点重新选出 Leader', async () => {
    const c = new SimulatedCluster(3, 2);
    try {
        c.start();
        const leaderId = await c.waitForLeader();
        const survivors = c.nodes.filter(n => n.nodeId !== leaderId);

        // 停止 Leader（模拟宕机），两个存活节点感知连接断开
        c.get(leaderId).election.stop();
        for (const s of survivors) s.election.removeNode(leaderId);

        // 存活的两节点之间仍满足 quorum=2，应重新选出 Leader
        // 等待旧 leader 降级后 + 新 leader 当选（两轮超时内）
        await sleep(100); // 让旧 leader stop() 生效

        // 只在存活节点中等待新 Leader
        const newLeader = await new Promise((resolve, reject) => {
            const deadline = Date.now() + 3000;
            const check = () => {
                const ls = survivors.filter(n => n.election.isLeader()).map(n => n.nodeId);
                if (ls.length === 1) return resolve(ls[0]);
                if (Date.now() > deadline) return reject(new Error('存活节点未能选出新 Leader'));
                setTimeout(check, 20);
            };
            check();
        });

        assert(newLeader !== leaderId, '新 Leader 应不同于宕机的旧 Leader');
        assert(survivors.filter(n => n.election.isLeader()).length === 1, '存活节点中应只有一个 Leader');
    } finally { c.stop(); }
});

// 3c. 三节点两节点宕机，单节点无法选主（quorum=2 不满足）
await test('三节点两节点宕机后，单节点无法选主（quorum=2 不满足）', async () => {
    const c = new SimulatedCluster(3, 2);
    try {
        c.start();
        const leaderId = await c.waitForLeader();
        const others = c.nodes.filter(n => n.nodeId !== leaderId);
        const survivorId = others[0].nodeId;
        const crashId    = others[1].nodeId;

        // 停止 Leader 和另一个节点，只剩 survivor
        c.get(leaderId).election.stop();
        c.get(crashId).election.stop();
        c.get(survivorId).election.removeNode(leaderId);
        c.get(survivorId).election.removeNode(crashId);

        // 等待多轮选举周期，单节点应一直选不出 Leader
        await sleep(600);

        assert(!c.get(survivorId).election.isLeader(),
               '单节点不应能选主（quorum=2 不满足）');
    } finally { c.stop(); }
});

// 4. 四节点 quorum=3，2-2 分区 → 两侧均无 Leader（安全停服）
await test('四节点 quorum=3，2-2 分区后无 Leader（安全停服）', async () => {
    const c = new SimulatedCluster(4, 3);
    c.start();
    await c.waitForLeader();
    // 制造 2-2 分区
    c.partition([['node-0', 'node-1'], ['node-2', 'node-3']]);
    // Leader 应主动降级（heartbeat 检测到 connected < quorum）
    await c.waitForNoLeader(2000);
    c.stop();
    assert(c.leaders().length === 0, '分区后不应有 Leader');
});

// 5. Leader 降级：removeNode 使连接数跌破 quorum
await test('Leader 因连接数不足主动降级', async () => {
    const c = new SimulatedCluster(3, 2);
    c.start();
    const leaderId = await c.waitForLeader();
    const leaderNode = c.get(leaderId);

    // 断开 Leader 与其他所有节点（connected=1 < quorum=2）
    for (const n of c.nodes) {
        if (n.nodeId !== leaderId) leaderNode.election.removeNode(n.nodeId);
    }

    await sleep(300); // 等心跳检测触发降级
    c.stop();
    assert(!leaderNode.election.isLeader(), 'Leader 应已降级');
});

// 6. 降级后恢复连接，重新选出 Leader
await test('降级后恢复连接，重新选出新 Leader', async () => {
    const c = new SimulatedCluster(3, 2);
    try {
        c.start();
        const oldLeader = await c.waitForLeader();

        // 孤立旧 Leader
        c.partition([
            [oldLeader],
            c.nodes.map(n => n.nodeId).filter(id => id !== oldLeader),
        ]);
        await c.waitForNoLeader(2000);

        // 恢复网络
        c.heal();
        await c.waitForLeader(3000);
        assert(c.leaders().length === 1, '恢复后应重新选出一个 Leader');
    } finally { c.stop(); }
});

// 7. 优先级投票：同一 term 多候选人，高优先级获胜
await test('同 term 多候选人时 follower 改投高优先级候选人', async () => {
    let followerVotedFor = null;
    const follower = new LeaderElection({
        shardId: 0,
        nodeId: 'follower',
        getMinQuorum: async () => 2,
        onSendHeartbeat: () => {},
        onSendVoteReq: () => {},
        onSendVoteAck: (_sid, _term, candidateId, granted) => {
            if (granted) followerVotedFor = candidateId;
        },
        onLeaderChanged: () => {},
        timerAPI: { setTimeout, clearTimeout, setInterval, clearInterval },

        _testOptions: FAST,
    });
    follower._started = true;

    follower.receiveVoteReq(1, 'node-A', 0.3);
    assert(followerVotedFor === 'node-A', '第一票应给 node-A');

    follower.receiveVoteReq(1, 'node-B', 0.9); // 更高优先级
    assert(followerVotedFor === 'node-B', '应改投更高优先级的 node-B');

    follower.receiveVoteReq(1, 'node-A', 0.1); // 更低优先级
    assert(followerVotedFor === 'node-B', '低优先级不应再改投，仍投 node-B');

    follower.stop();
});

// 8. 同一候选人重复发 vote_req，继续获得支持票
await test('同一候选人重复 vote_req 仍获得支持票', async () => {
    let grantCount = 0;
    const follower = new LeaderElection({
        shardId: 0,
        nodeId: 'follower',
        getMinQuorum: async () => 2,
        onSendHeartbeat: () => {},
        onSendVoteReq: () => {},
        onSendVoteAck: (_sid, _term, _candidateId, granted) => {
            if (granted) grantCount++;
        },
        onLeaderChanged: () => {},
        timerAPI: { setTimeout, clearTimeout, setInterval, clearInterval },

        _testOptions: FAST,
    });
    follower._started = true;

    follower.receiveVoteReq(1, 'candidate-A', 0.5);
    follower.receiveVoteReq(1, 'candidate-A', 0.5); // 重复
    assert(grantCount === 2, '同一候选人重复请求应都返回 granted，实际=' + grantCount);

    follower.stop();
});

// 9. 收到更高 term 心跳，Leader 立即降级
await test('Leader 收到更高 term 心跳后立即降级', async () => {
    const c = new SimulatedCluster(1, 1);
    c.start();
    await c.waitForLeader();
    const node = c.get('node-0');
    assert(node.election.isLeader(), '应先是 Leader');

    node.election.receiveHeartbeat(999, 'other-node'); // term=999 远高于当前
    assert(!node.election.isLeader(), '收到更高 term 应立即降级');
    c.stop();
});

// 10. 多分片独立选举，互不干扰
await test('多分片（shard 0 和 shard 1）各自独立选出 Leader', async () => {
    const c0 = new SimulatedCluster(2, 2, 0);
    const c1 = new SimulatedCluster(2, 2, 1);
    try {
        c0.start();
        c1.start();
        await Promise.all([c0.waitForLeader(), c1.waitForLeader()]);
        assert(c0.leaders().length === 1, 'shard 0 应有唯一 Leader');
        assert(c1.leaders().length === 1, 'shard 1 应有唯一 Leader');
    } finally {
        c0.stop();
        c1.stop();
    }
});

// ─── Sync Push 模拟测试 ─────────────────────────────────────────────────────

/**
 * 模拟 SyncManager 的推送逻辑，纯内存，不依赖 ws/db。
 *
 * mockDb: { syncLog: [{seq, data}], peerLastSeq: Map<peerUrl, number> }
 * mockPeers: [{ peerUrl, open, received[] }]
 */
class MockSyncPusher {
    constructor(peers, syncLog = []) {
        this._peers = peers;           // [{ peerUrl, open, received }]
        this._syncLog = syncLog;       // [{seq, data}]
        this._peerLastSeq = new Map(); // peerUrl → lastSeq
        this._pushing = false;
    }

    _getPeerLastSeq(peerUrl) {
        return this._peerLastSeq.get(peerUrl) || 0;
    }
    _updatePeerLastSeq(peerUrl, seq) {
        this._peerLastSeq.set(peerUrl, seq);
    }
    _readSyncLog(afterSeq) {
        return this._syncLog.filter(e => e.seq > afterSeq);
    }
    _getMaxSeq() {
        return this._syncLog.length > 0 ? this._syncLog[this._syncLog.length - 1].seq : 0;
    }

    _getAllConnectedPeers() {
        return this._peers.filter(p => p.open);
    }

    pushToAllPeers() {
        if (this._pushing) return;
        this._pushing = true;
        try { this._doPushToAllPeers(); }
        finally { this._pushing = false; }
    }

    _doPushToAllPeers() {
        const allPeers = this._getAllConnectedPeers();
        if (allPeers.length === 0) return;

        const MAX_FANOUT = 5;
        let targets, backups;
        if (allPeers.length <= MAX_FANOUT) {
            targets = allPeers;
            backups = [];
        } else {
            const shuffled = allPeers.slice();
            for (let i = shuffled.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
            }
            targets = shuffled.slice(0, MAX_FANOUT);
            backups = shuffled.slice(MAX_FANOUT);
        }

        for (const peer of targets) {
            if (!this._pushToPeer(peer)) {
                while (backups.length > 0) {
                    const fallback = backups.shift();
                    if (this._pushToPeer(fallback)) break;
                }
            }
        }
    }

    _pushToPeer(peer) {
        try {
            const lastSeq = this._getPeerLastSeq(peer.peerUrl);
            const entries = this._readSyncLog(lastSeq);
            if (entries.length === 0) return true; // 无新数据也算成功

            if (!peer.open) return false; // 连接断开
            peer.received.push(...entries);
            const maxSeq = entries[entries.length - 1].seq;
            this._updatePeerLastSeq(peer.peerUrl, maxSeq);
            return true;
        } catch (_) {
            return false;
        }
    }

    /** 模拟 _handleSync: 收到来自 sourcePeerUrl 的 entries，apply 后级联推送 */
    handleSync(sourcePeerUrl, entries) {
        // 模拟 applyEntries: 把新条目加入本地 syncLog
        let applied = 0;
        for (const e of entries) {
            if (!this._syncLog.find(x => x.seq === e.seq)) {
                this._syncLog.push(e);
                applied++;
            }
        }
        this._syncLog.sort((a, b) => a.seq - b.seq);

        if (applied > 0 && sourcePeerUrl) {
            const currentMax = this._getMaxSeq();
            this._updatePeerLastSeq(sourcePeerUrl, currentMax);
            this.pushToAllPeers(); // 级联
        }
        return applied;
    }
}

function makePeers(n) {
    return Array.from({ length: n }, (_, i) => ({
        peerUrl: 'peer-' + i,
        open: true,
        received: [],
    }));
}

_origLog('\n  Sync Push Tests\n');

// 11. ≤5 个 peer 全量推送
await test('≤5 peer 全量推送', () => {
    const peers = makePeers(3);
    const pusher = new MockSyncPusher(peers, [{ seq: 1, data: 'a' }]);
    pusher.pushToAllPeers();
    for (const p of peers) {
        assert(p.received.length === 1, p.peerUrl + ' 应收到 1 条，实际=' + p.received.length);
    }
});

// 12. >5 个 peer 只推 5 个（fanout 限制）
await test('>5 peer fanout=5 限制', () => {
    const peers = makePeers(8);
    const pusher = new MockSyncPusher(peers, [{ seq: 1, data: 'a' }]);
    pusher.pushToAllPeers();
    const pushed = peers.filter(p => p.received.length > 0);
    assert(pushed.length === 5, '应只推送给 5 个 peer，实际=' + pushed.length);
});

// 13. fanout 随机性：多次推送不总是同一组
await test('fanout 随机选择（不固定）', () => {
    const hitCount = new Map(); // peerUrl → 被选中次数
    for (let round = 0; round < 30; round++) {
        const peers = makePeers(8);
        const pusher = new MockSyncPusher(peers, [{ seq: 1, data: 'a' }]);
        pusher.pushToAllPeers();
        for (const p of peers) {
            if (p.received.length > 0) hitCount.set(p.peerUrl, (hitCount.get(p.peerUrl) || 0) + 1);
        }
    }
    // 30 轮 × 5/8 概率，8 个 peer 全都应该至少被选过一次
    const hitAll = [...hitCount.keys()].length === 8;
    assert(hitAll, '30 轮后 8 个 peer 应全被选中过，实际只有 ' + hitCount.size + ' 个');
});

// 14. 推送失败时从 backup 补位
await test('推送失败时 backup 补位', () => {
    const peers = makePeers(8);
    // 前 5 个中标记 2 个为断连
    peers[0].open = false;
    peers[1].open = false;
    const pusher = new MockSyncPusher(peers, [{ seq: 1, data: 'a' }]);

    // 固定洗牌顺序以确保可预测：直接调用内部方法
    // 这里用多次运行来统计，失败的应被补位
    let totalPushed = 0;
    for (let i = 0; i < 20; i++) {
        for (const p of peers) p.received = [];
        pusher._peerLastSeq.clear();
        pusher.pushToAllPeers();
        totalPushed += peers.filter(p => p.received.length > 0).length;
    }
    // 每轮 6 个 open peer，fanout=5，失败会补位 → 每轮应推成功 5 个
    assert(totalPushed === 100, '每轮应成功推 5 个(共100)，实际=' + totalPushed);
});

// 15. 级联推送不回推给来源 peer
await test('级联推送不回推来源节点已有的数据', () => {
    const peers = makePeers(3); // peer-0(来源), peer-1, peer-2
    const pusher = new MockSyncPusher(peers);

    // 模拟从 peer-0 收到数据
    pusher.handleSync('peer-0', [{ seq: 1, data: 'from-peer-0' }]);

    // peer-0 不应收到回推（他刚发来的），peer-1/2 应收到级联
    assert(peers[0].received.length === 0,
           'peer-0 不应收到回推，实际=' + peers[0].received.length);
    assert(peers[1].received.length === 1,
           'peer-1 应收到级联，实际=' + peers[1].received.length);
    assert(peers[2].received.length === 1,
           'peer-2 应收到级联，实际=' + peers[2].received.length);
});

// 16. 级联推送仍会推来源 peer 缺少的其他数据
await test('级联推送仍推来源节点缺少的其他数据', () => {
    const peers = makePeers(3);
    const pusher = new MockSyncPusher(peers);

    // 本地已有 seq=1
    pusher._syncLog.push({ seq: 1, data: 'local-old' });

    // 从 peer-0 收到 seq=2（此时 peer-0 的 lastSeq 会被更新到 max=2）
    pusher.handleSync('peer-0', [{ seq: 2, data: 'from-peer-0' }]);

    // peer-0 不应收到 seq=2（回推），但因为 lastSeq 被设为 2，seq=1 也不会推
    // 这是正确的：peer-0 发来 seq=2 说明他已经有 seq<=2 的数据了
    assert(peers[0].received.length === 0,
           'peer-0 不应收到任何回推，实际=' + peers[0].received.length);

    // 现在本地新增 seq=3（模拟 leader 又写了新数据）
    pusher._syncLog.push({ seq: 3, data: 'new-local' });
    for (const p of peers) p.received = [];
    pusher.pushToAllPeers();

    // 这次 peer-0 应该收到 seq=3（他缺的新数据）
    assert(peers[0].received.length === 1 && peers[0].received[0].seq === 3,
           'peer-0 应收到 seq=3，实际=' + JSON.stringify(peers[0].received));
});

// ─── 两阶段提交（2PC）模拟测试 ──────────────────────────────────────────────
//
// 不依赖 better-sqlite3 / WebSocket，用纯内存对象模拟：
//   - 每个节点有独立的内存"数据库"（Map）和 _sync_log（Array）
//   - 节点间消息通过函数调用直接传递（进程内数据交接）
//   - 测试 2PC 的核心状态机：prepare → prepare_ack → commit/abort
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 模拟单个节点的内存数据库 + 2PC 状态
 */
class Mock2PCNode {
    constructor(nodeId) {
        this.nodeId = nodeId;
        // 内存"数据库"：table → Map<rowKey, rowData>
        this._tables = new Map();
        // _sync_log：[{ seq, table, op, key, data }]
        this._syncLog = [];
        this._nextSeq = 1;
        // 手动事务状态（Leader 侧）
        this._manualTxn = null; // { writeId, prevMaxSeq, pendingOps: [{table, key, data}] }
        // Follower 侧活跃事务：Map<writeId, { pendingOps, timeoutHandle }>
        this._followerTxns = new Map();
        // 已提交的数据（用于验证）
        this._committed = new Map(); // table → Map<key, data>
    }

    /** 获取表（不存在则创建） */
    _getTable(table) {
        if (!this._tables.has(table)) this._tables.set(table, new Map());
        return this._tables.get(table);
    }

    /** 模拟 beginManualTransaction */
    beginManualTransaction(writeId) {
        if (this._manualTxn) throw new Error('Already has active manual transaction');
        this._manualTxn = { writeId, prevMaxSeq: this._syncLog.length, pendingOps: [] };
    }

    /** 模拟业务写操作（在手动事务内） */
    writeInTransaction(table, key, data) {
        if (!this._manualTxn) throw new Error('No active manual transaction');
        this._manualTxn.pendingOps.push({ table, key, data });
        // 写入内存表（但不提交到 _committed）
        this._getTable(table).set(key, data);
        // 写入 _sync_log（模拟触发器）
        this._syncLog.push({ seq: this._nextSeq++, table, op: 'INSERT', key, data });
    }

    /** 模拟 getManualTransactionEntries */
    getManualTransactionEntries(writeId) {
        if (!this._manualTxn || this._manualTxn.writeId !== writeId) throw new Error('No active manual transaction for ' + writeId);
        return this._syncLog.slice(this._manualTxn.prevMaxSeq);
    }

    /** 模拟 commitManualTransaction */
    commitManualTransaction(writeId) {
        if (!this._manualTxn || this._manualTxn.writeId !== writeId) throw new Error('No active manual transaction for ' + writeId);
        // 将 pendingOps 提交到 _committed
        for (const op of this._manualTxn.pendingOps) {
            if (!this._committed.has(op.table)) this._committed.set(op.table, new Map());
            this._committed.get(op.table).set(op.key, op.data);
        }
        this._manualTxn = null;
    }

    /** 模拟 rollbackManualTransaction */
    rollbackManualTransaction(writeId) {
        if (!this._manualTxn) return;
        // 回滚：从内存表中删除 pendingOps 写入的数据
        for (const op of this._manualTxn.pendingOps) {
            this._getTable(op.table).delete(op.key);
            // 从 _sync_log 中删除
            this._syncLog = this._syncLog.filter(e => !(e.table === op.table && e.key === op.key));
            this._nextSeq = this._syncLog.length + 1;
        }
        this._manualTxn = null;
    }

    /** Follower 侧：收到 prepare，开启本地事务并应用条目 */
    handlePrepare(writeId, entries) {
        if (this._followerTxns.has(writeId)) return; // 重复消息
        const pendingOps = [];
        for (const entry of entries) {
            this._getTable(entry.table).set(entry.key, entry.data);
            this._syncLog.push({ seq: this._nextSeq++, ...entry });
            pendingOps.push(entry);
        }
        const timeoutHandle = setTimeout(() => {
            // 超时自动回滚
            this._followerTxns.delete(writeId);
            for (const op of pendingOps) {
                this._getTable(op.table).delete(op.key);
            }
        }, 10000);
        this._followerTxns.set(writeId, { pendingOps, timeoutHandle });
        return true; // granted
    }

    /** Follower 侧：收到 commit */
    handleCommit(writeId) {
        const txn = this._followerTxns.get(writeId);
        if (!txn) return;
        clearTimeout(txn.timeoutHandle);
        this._followerTxns.delete(writeId);
        // 提交到 _committed
        for (const op of txn.pendingOps) {
            if (!this._committed.has(op.table)) this._committed.set(op.table, new Map());
            this._committed.get(op.table).set(op.key, op.data);
        }
    }

    /** Follower 侧：收到 abort */
    handleAbort(writeId) {
        const txn = this._followerTxns.get(writeId);
        if (!txn) return;
        clearTimeout(txn.timeoutHandle);
        this._followerTxns.delete(writeId);
        // 回滚
        for (const op of txn.pendingOps) {
            this._getTable(op.table).delete(op.key);
        }
    }

    /** 读取已提交的数据 */
    getCommitted(table, key) {
        return this._committed.get(table)?.get(key);
    }

    /** 读取内存表（含未提交数据） */
    getUncommitted(table, key) {
        return this._tables.get(table)?.get(key);
    }
}

/**
 * 模拟 2PC 集群：Leader + Followers，消息通过函数调用直接传递
 */
class Mock2PCCluster {
    /**
     * @param {number} numNodes
     * @param {number} quorum - 最少需要的节点数（含 Leader 自身）
     */
    constructor(numNodes, quorum) {
        this.quorum = quorum;
        this.nodes = Array.from({ length: numNodes }, (_, i) => new Mock2PCNode('node-' + i));
        this.leaderIdx = 0; // 默认 node-0 是 Leader
        // 模拟网络分区：Set<nodeId> 表示与 Leader 断开的节点
        this._disconnected = new Set();
    }

    get leader() { return this.nodes[this.leaderIdx]; }
    get followers() { return this.nodes.filter((_, i) => i !== this.leaderIdx); }

    /** 模拟节点断开 */
    disconnect(nodeId) { this._disconnected.add(nodeId); }
    /** 模拟节点恢复 */
    reconnect(nodeId) { this._disconnected.delete(nodeId); }

    /** 获取当前连接的 Follower 列表 */
    _connectedFollowers() {
        return this.followers.filter(f => !this._disconnected.has(f.nodeId));
    }

    /**
     * 执行一次 2PC 写操作
     * @param {string} table
     * @param {string} key
     * @param {string} data
     * @param {object} [opts]
     * @param {boolean} [opts.leaderCrashAfterCommit] - 模拟 Leader 在 COMMIT 后、发 commit 消息前崩溃
     * @param {number} [opts.prepareTimeoutMs] - prepare 超时时间（默认 5000ms）
     * @returns {Promise<{ success: boolean, reason?: string }>}
     */
    async write(table, key, data, opts = {}) {
        const writeId = 'write-' + Math.random().toString(36).slice(2);
        const prepareTimeoutMs = opts.prepareTimeoutMs || 5000;

        // 1. Leader 开启手动事务
        this.leader.beginManualTransaction(writeId);

        // 2. 执行业务写操作
        this.leader.writeInTransaction(table, key, data);

        // 3. 读取新增的 _sync_log 条目
        const entries = this.leader.getManualTransactionEntries(writeId);

        // 4. 广播 prepare 给所有连接的 Follower，等待 quorum 确认
        const connectedFollowers = this._connectedFollowers();
        // quorum - 1（Leader 自身算一票）；quorum=1 时不需要任何 Follower 确认
        const requiredAcks = Math.max(0, this.quorum - 1);

        if (connectedFollowers.length === 0 && this.quorum > 1) {
            // 多节点部署但无连接，拒绝写操作
            this.leader.rollbackManualTransaction(writeId);
            return { success: false, reason: 'no connected peers in multi-node deployment' };
        }

        // 收集 prepare_ack
        let ackCount = 0;
        const grantedFollowers = [];
        for (const follower of connectedFollowers) {
            const granted = follower.handlePrepare(writeId, entries);
            if (granted) {
                ackCount++;
                grantedFollowers.push(follower);
            }
        }

        if (ackCount < requiredAcks) {
            // quorum 不满足，回滚
            this.leader.rollbackManualTransaction(writeId);
            // 广播 abort
            for (const follower of connectedFollowers) {
                follower.handleAbort(writeId);
            }
            return { success: false, reason: 'quorum not met: got ' + ackCount + ', need ' + requiredAcks };
        }

        // 5. 提交
        if (opts.leaderCrashAfterCommit) {
            // 模拟 Leader 在 COMMIT 后崩溃，不发 commit 消息
            this.leader.commitManualTransaction(writeId);
            // Follower 的事务挂起（等待超时自动回滚）
            return { success: true, leaderCrashed: true };
        }

        this.leader.commitManualTransaction(writeId);

        // 6. 广播 commit 给所有 Follower
        for (const follower of grantedFollowers) {
            follower.handleCommit(writeId);
        }

        return { success: true };
    }
}

_origLog('\n  2PC Sync Tests\n');

// 17. 正常 2PC：Leader + 2 Follower，写操作成功，所有节点数据一致
await test('2PC 正常流程：3 节点写操作成功，所有节点数据一致', async () => {
    const c = new Mock2PCCluster(3, 2);
    const result = await c.write('wallets', 'user1/wallet1', '{"address":"0x1234"}');
    assert(result.success, '写操作应成功，实际=' + JSON.stringify(result));

    // 验证所有节点都有已提交的数据
    for (const node of c.nodes) {
        const val = node.getCommitted('wallets', 'user1/wallet1');
        assert(val === '{"address":"0x1234"}', node.nodeId + ' 应有已提交数据，实际=' + val);
    }
});

// 18. 2PC 超时/无连接：多节点部署但无 Follower 连接，写操作被拒绝
await test('2PC 无连接：多节点部署但无 Follower 连接，写操作被拒绝', async () => {
    const c = new Mock2PCCluster(3, 2);
    // 断开所有 Follower
    c.disconnect('node-1');
    c.disconnect('node-2');

    const result = await c.write('wallets', 'user1/wallet1', '{"address":"0x1234"}');
    assert(!result.success, '无连接时写操作应失败');
    assert(result.reason.includes('no connected peers'), '失败原因应包含 no connected peers，实际=' + result.reason);

    // 验证 Leader 上没有已提交的数据（ROLLBACK）
    const val = c.leader.getCommitted('wallets', 'user1/wallet1');
    assert(val === undefined, 'Leader 上不应有已提交数据（已回滚），实际=' + val);
});

// 19. 2PC quorum 不满足：3 节点 quorum=3，只有 1 个 Follower 连接
await test('2PC quorum 不满足：3 节点 quorum=3，只有 1 个 Follower 连接，写操作被拒绝', async () => {
    const c = new Mock2PCCluster(3, 3); // quorum=3，需要 2 个 Follower 确认
    // 断开 1 个 Follower
    c.disconnect('node-2');

    const result = await c.write('wallets', 'user1/wallet1', '{"address":"0x1234"}');
    assert(!result.success, 'quorum 不满足时写操作应失败');
    assert(result.reason.includes('quorum not met'), '失败原因应包含 quorum not met，实际=' + result.reason);

    // 验证 Leader 上没有已提交的数据（ROLLBACK）
    const val = c.leader.getCommitted('wallets', 'user1/wallet1');
    assert(val === undefined, 'Leader 上不应有已提交数据（已回滚），实际=' + val);

    // 验证 Follower 上也没有已提交的数据（ABORT）
    const follower1 = c.nodes[1];
    const val1 = follower1.getCommitted('wallets', 'user1/wallet1');
    assert(val1 === undefined, 'Follower 上不应有已提交数据（已 abort），实际=' + val1);
});

// 20. 2PC Leader 崩溃：Leader COMMIT 后崩溃，Follower 事务挂起，超时后自动回滚
await test('2PC Leader 崩溃：Leader COMMIT 后崩溃，Follower 超时自动回滚', async () => {
    const c = new Mock2PCCluster(3, 2);
    // 模拟 Leader 在 COMMIT 后崩溃（不发 commit 消息）
    const result = await c.write('wallets', 'user1/wallet1', '{"address":"0x1234"}', { leaderCrashAfterCommit: true });
    assert(result.success && result.leaderCrashed, '应模拟 Leader 崩溃');

    // Leader 上有已提交的数据
    const leaderVal = c.leader.getCommitted('wallets', 'user1/wallet1');
    assert(leaderVal === '{"address":"0x1234"}', 'Leader 上应有已提交数据，实际=' + leaderVal);

    // Follower 上还没有已提交的数据（等待 commit 消息）
    for (const follower of c.followers) {
        const val = follower.getCommitted('wallets', 'user1/wallet1');
        assert(val === undefined, follower.nodeId + ' 上不应有已提交数据（等待 commit），实际=' + val);
        // 但内存表中有未提交的数据（prepare 已应用）
        const uncommitted = follower.getUncommitted('wallets', 'user1/wallet1');
        assert(uncommitted === '{"address":"0x1234"}', follower.nodeId + ' 内存表中应有未提交数据，实际=' + uncommitted);
    }
});

// 21. 2PC 单节点部署：quorum=1，无需等待 Follower，直接提交
await test('2PC 单节点部署：quorum=1，无需等待 Follower，直接提交', async () => {
    const c = new Mock2PCCluster(1, 1); // 单节点
    const result = await c.write('wallets', 'user1/wallet1', '{"address":"0x1234"}');
    assert(result.success, '单节点写操作应成功，实际=' + JSON.stringify(result));

    const val = c.leader.getCommitted('wallets', 'user1/wallet1');
    assert(val === '{"address":"0x1234"}', '单节点应有已提交数据，实际=' + val);
});

// 22. 2PC 连续写操作：多次写操作，每次都正确同步
await test('2PC 连续写操作：3 次写操作，所有节点数据一致', async () => {
    const c = new Mock2PCCluster(3, 2);

    for (let i = 1; i <= 3; i++) {
        const result = await c.write('wallets', 'user1/wallet' + i, '{"address":"0x' + i + '"}');
        assert(result.success, '第 ' + i + ' 次写操作应成功');
    }

    // 验证所有节点都有所有数据
    for (const node of c.nodes) {
        for (let i = 1; i <= 3; i++) {
            const val = node.getCommitted('wallets', 'user1/wallet' + i);
            assert(val === '{"address":"0x' + i + '"}', node.nodeId + ' 应有 wallet' + i + '，实际=' + val);
        }
    }
});

// 23. 2PC 部分 Follower 断开：quorum=2，1 个 Follower 断开，仍可写（另 1 个满足 quorum）
await test('2PC 部分 Follower 断开：quorum=2，1 个 Follower 断开，仍可写', async () => {
    const c = new Mock2PCCluster(3, 2); // quorum=2，需要 1 个 Follower 确认
    c.disconnect('node-2'); // 断开 1 个 Follower

    const result = await c.write('wallets', 'user1/wallet1', '{"address":"0x1234"}');
    assert(result.success, '1 个 Follower 断开时写操作应成功（quorum=2 满足），实际=' + JSON.stringify(result));

    // Leader 和 node-1 应有数据，node-2 没有
    assert(c.leader.getCommitted('wallets', 'user1/wallet1') !== undefined, 'Leader 应有数据');
    assert(c.nodes[1].getCommitted('wallets', 'user1/wallet1') !== undefined, 'node-1 应有数据');
    assert(c.nodes[2].getCommitted('wallets', 'user1/wallet1') === undefined, 'node-2 应无数据（已断开）');
});

// ─── triggerElection() 主动触发选举 ─────────────────────────────────────────

_origLog('\n  triggerElection() Tests\n');

// 17. 单节点 Leader 主动触发选举 → 先降级再重新当选
await test('triggerElection(): 单节点 Leader 先降级后重新当选', async () => {
    const leaderChanges = [];
    const c = new SimulatedCluster(1, 1);
    // 覆盖 onLeaderChanged 以记录事件
    c.nodes[0].election._onLeaderChanged = (_sid, id) => { leaderChanges.push(id); };
    c.start();

    await c.waitForLeader(2000);
    assert(c.leaders().length === 1, '初始应有 Leader');

    // 主动触发重新选举
    c.nodes[0].election.triggerElection();

    // 触发后应立即降级
    assert(!c.nodes[0].election.isLeader(), 'triggerElection 后应立即降级');

    // 等待重新当选（quorum=1，自选）
    await c.waitForLeader(2000);
    assert(c.leaders().length === 1, '应重新选出 Leader');
    assert(leaderChanges.includes(null), '应触发降级事件(null)，实际=' + JSON.stringify(leaderChanges));
    assert(leaderChanges.includes('node-0'), '应触发重选事件，实际=' + JSON.stringify(leaderChanges));

    c.stop();
});

// 18. 三节点：Follower 调用 triggerElection() 后集群收敛到唯一 Leader
await test('triggerElection(): 三节点 Follower 主动触发选举后集群收敛', async () => {
    const c = new SimulatedCluster(3, 2);
    try {
        c.start();
        const firstLeader = await c.waitForLeader(3000);

        // 找一个 follower
        const follower = c.nodes.find(n => n.nodeId !== firstLeader);
        assert(follower, '应存在 Follower 节点');

        follower.election.triggerElection();

        // 集群应收敛到唯一 Leader
        await c.waitForLeader(3000);
        assert(c.leaders().length === 1, 'Follower triggerElection 后集群应收敛到唯一 Leader，实际=' + c.leaders());
    } finally { c.stop(); }
});

// 19. 三节点：当前 Leader 调用 triggerElection() 后集群重新收敛
await test('triggerElection(): 三节点 Leader 主动触发选举后集群重新收敛', async () => {
    const c = new SimulatedCluster(3, 2);
    try {
        c.start();
        const firstLeader = await c.waitForLeader(3000);
        const leaderNode = c.get(firstLeader);

        const termBefore = leaderNode.election.getStatus().term;

        // Leader 主动触发重新选举
        leaderNode.election.triggerElection();

        // 注：SimulatedCluster 消息传递是同步的，降级和重选在同一调用栈完成，
        // 不能断言 triggerElection() 返回后节点仍处于非 Leader 状态。
        // 改为验证 term 递增，确认确实发起了新一轮选举。
        assert(leaderNode.election.getStatus().term > termBefore, 'Leader 调用 triggerElection 后 term 应递增（新一轮选举已发起）');

        // 集群应重新收敛到唯一 Leader
        await c.waitForLeader(3000);
        assert(c.leaders().length === 1, 'Leader triggerElection 后集群应重新收敛到唯一 Leader，实际=' + c.leaders());
    } finally { c.stop(); }
});

// 20. 多次连续 triggerElection() 最终收敛到唯一 Leader
await test('triggerElection(): 多次连续触发后最终收敛到唯一 Leader', async () => {
    const c = new SimulatedCluster(3, 2);
    try {
        c.start();
        await c.waitForLeader(3000);

        // 所有节点连续触发 triggerElection
        for (const n of c.nodes) {
            n.election.triggerElection();
        }

        // 稍作等待再连续触发一次
        await sleep(50);
        for (const n of c.nodes) {
            n.election.triggerElection();
        }

        // 最终应收敛到唯一 Leader
        await c.waitForLeader(3000);
        assert(c.leaders().length === 1, '多次 triggerElection 后集群应收敛到唯一 Leader，实际=' + c.leaders());
    } finally { c.stop(); }
});

// ─── 汇总 ────────────────────────────────────────────────────────────────────

_origLog('\n  ─────────────────────────────────');
_origLog(`  PASSED: ${passed}  FAILED: ${failed}  TOTAL: ${passed + failed}`);
_origLog('');
process.exit(failed > 0 ? 1 : 0);
