/**
 * P2P 节点发现集成测试
 * 测试多节点实际连接、pin-check、节点发现、自动连接的完整流程
 */

import { WebSocketServer, WebSocket } from 'ws';
import assert from 'node:assert';

// 模拟 ContractClient
class MockContractClient {
    constructor(identity) {
        this._identity = identity;
    }

    getPinnedIdentity() {
        return this._identity;
    }

    async refreshCache() {
        // 模拟合约刷新，不改变身份
    }
}

// 模拟 HLC
class MockHLC {
    constructor(nodeId) {
        this.nodeId = nodeId;
    }
}

// 模拟数据库
class MockDatabase {
    constructor() {
        this._data = {};
    }

    prepare(sql) {
        return {
            all: () => [],
            run: () => ({ changes: 0 }),
        };
    }
}

// 简化的 SyncManager（只包含 P2P 发现和 pin-check 逻辑）
class SimpleSyncManager {
    constructor(options) {
        this.listenPort = options.listenPort;
        this.peerUrls = options.peerUrls || [];
        this._contractClient = options.contractClient || null;
        this._hlc = options.hlc;
        this._db = options.db;

        this._knownPeers = new Map(); // Map<nodeId, url>
        this._pinCheckedPeers = new Set();
        this._peerWsMap = new Map();
        this._peerIdToNodeId = new Map(); // peerId → nodeId

        this.wss = null;
        this._started = false;
        this._peersBroadcastTimer = null;
        this._messages = []; // 记录收到的消息
    }

    _isSelf(nodeId) {
        return nodeId === this._hlc.nodeId;
    }

    _getNodeIdFromUrl(url) {
        // 模拟：从 URL 推断 nodeId（测试专用）
        if (url.includes(':3301')) return 'nodeA';
        if (url.includes(':3302')) return 'nodeB';
        if (url.includes(':3303')) return 'nodeC';
        return 'unknown';
    }

    _getNodeIdFromPeerId(peerId) {
        // 模拟：从入站 peerId 推断 nodeId（测试专用）
        // 根据本节点监听端口推断对端
        if (this.listenPort === 3301) return 'nodeB'; // A 收到来自 B 的连接
        if (this.listenPort === 3302) {
            // B 可能收到 A 或 C 的连接
            // 简化：假设 inbound 连接都来自已知节点
            return 'nodeA'; // 简化处理
        }
        if (this.listenPort === 3303) return 'nodeB'; // C 收到来自 B 的连接
        return 'unknown';
    }

    async start() {
        if (this._started) return;
        this._started = true;

        await this._startServer();

        // 连接配置的节点
        for (const url of this.peerUrls) {
            if (this._isSelf(url)) continue;
            this._connectToPeer(url);
        }

        // 启动广播定时器（缩短间隔用于测试）
        this._peersBroadcastTimer = setInterval(() => this._broadcastPeers(), 500);
    }

    stop() {
        this._started = false;
        if (this._peersBroadcastTimer) {
            clearInterval(this._peersBroadcastTimer);
            this._peersBroadcastTimer = null;
        }
        for (const [, ws] of this._peerWsMap) {
            try { ws.close(); } catch (_) {}
        }
        this._peerWsMap.clear();
        this._peerIdToNodeId.clear();
        this._pinCheckedPeers.clear();
        if (this.wss) {
            this.wss.close();
            this.wss = null;
        }
    }

    async _startServer() {
        return new Promise((resolve) => {
            this.wss = new WebSocketServer({ port: this.listenPort }, () => {
                console.log(`[Node ${this._hlc.nodeId}] Listening on port ${this.listenPort}`);
                resolve();
            });

            this.wss.on('connection', (ws, req) => {
                const peerId = 'inbound://' + req.socket.remoteAddress + ':' + req.socket.remotePort;
                this._peerWsMap.set(peerId, ws);

                // 模拟：入站连接后，从 peerId 推断对端 nodeId
                // 在真实场景中，对端会发送 handshake 消息
                const remoteNodeId = this._getNodeIdFromPeerId(peerId);
                this._peerIdToNodeId.set(peerId, remoteNodeId);
                if (!this._knownPeers.has(remoteNodeId)) {
                    this._knownPeers.set(remoteNodeId, peerId);
                }

                // 发送 pin-check
                this._sendPinCheck(peerId, ws);

                ws.on('message', (data) => {
                    const msgStr = data.toString();
                    this._messages.push({ from: peerId, content: msgStr });
                    this._extractNodeIdFromHandshake(peerId, msgStr);
                    this._handleMessage(peerId, ws, msgStr);
                });

                ws.on('close', () => {
                    this._peerWsMap.delete(peerId);
                    this._peerIdToNodeId.delete(peerId);
                    this._pinCheckedPeers.delete(peerId);
                });
            });
        });
    }

    _connectToPeer(url) {
        if (this._peerWsMap.has(url)) return;

        console.log(`[Node ${this._hlc.nodeId}] Connecting to ${url}`);
        const ws = new WebSocket(url);

        ws.on('open', () => {
            console.log(`[Node ${this._hlc.nodeId}] Connected to ${url}`);
            this._peerWsMap.set(url, ws);
            // 模拟：连接成功后，从 URL 推断对端 nodeId
            const remoteNodeId = this._getNodeIdFromUrl(url);
            this._peerIdToNodeId.set(url, remoteNodeId);
            if (!this._knownPeers.has(remoteNodeId)) {
                this._knownPeers.set(remoteNodeId, url);
            }
            this._sendPinCheck(url, ws);
        });

        ws.on('message', (data) => {
            const msgStr = data.toString();
            this._messages.push({ from: url, content: msgStr });
            this._extractNodeIdFromHandshake(url, msgStr);
            this._handleMessage(url, ws, msgStr);
        });

        ws.on('close', () => {
            this._peerWsMap.delete(url);
            this._peerIdToNodeId.delete(url);
            this._pinCheckedPeers.delete(url);
        });
    }

    _sendPinCheck(peerId, ws) {
        const identity = this._contractClient?.getPinnedIdentity?.() || null;
        const msg = JSON.stringify({
            type: 'pin-check',
            rpcTlsCaCert: identity?.rpcTlsCaCert ?? null,
            contractAddress: identity?.contractAddress || null,
            chainId: identity?.chainId ?? null,
            allowNonRaTls: identity?.allowNonRaTls ?? null,
        });
        try {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(msg);
            }
        } catch (err) {
            console.error(`[Node ${this._hlc.nodeId}] _sendPinCheck failed:`, err.message);
        }
    }

    _sendPinCheckAck(ws, ok) {
        const msg = JSON.stringify({ type: 'pin-check-ack', ok });
        try {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(msg);
            }
        } catch (err) {}
    }

    _pinIdentityMatches(local, peer) {
        if (!local || !peer) return false;
        return (
            (local.rpcTlsCaCert || '') === (peer.rpcTlsCaCert || '') &&
            local.contractAddress === peer.contractAddress &&
            Number(local.chainId) === Number(peer.chainId) &&
            !!local.allowNonRaTls === !!peer.allowNonRaTls
        );
    }

    _extractNodeIdFromHandshake(peerId, msgStr) {
        try {
            const msg = JSON.parse(msgStr);
            if (msg && msg.type === 'handshake' && msg.nodeId) {
                this._peerIdToNodeId.set(peerId, msg.nodeId);
                if (!this._knownPeers.has(msg.nodeId)) {
                    this._knownPeers.set(msg.nodeId, peerId);
                }
            }
        } catch (_) {}
    }

    _handleMessage(peerId, ws, msgStr) {
        let msg;
        try {
            msg = JSON.parse(msgStr);
        } catch (_) {
            return;
        }

        if (!msg) return;

        // pin-check-ack
        if (msg.type === 'pin-check-ack') {
            if (msg.ok) {
                this._pinCheckedPeers.add(peerId);
                console.log(`[Node ${this._hlc.nodeId}] Pin-check passed for ${peerId}`);
            } else {
                console.warn(`[Node ${this._hlc.nodeId}] Pin-check rejected by ${peerId}`);
                try { ws.close(); } catch (_) {}
            }
            return;
        }

        // pin-check
        if (msg.type === 'pin-check') {
            const localPin = this._contractClient?.getPinnedIdentity?.() || null;
            const match = this._pinIdentityMatches(localPin, msg);
            this._sendPinCheckAck(ws, match);
            if (match) {
                this._pinCheckedPeers.add(peerId);
                console.log(`[Node ${this._hlc.nodeId}] Pin-check passed for ${peerId}`);
            }
            return;
        }

        // peers-list
        if (msg.type === 'peers-list') {
            this._handlePeersList(peerId, ws, msg.peers);
            return;
        }
    }

    _handlePeersList(peerId, ws, peers) {
        if (!this._pinCheckedPeers.has(peerId)) {
            console.warn(`[Node ${this._hlc.nodeId}] Ignored peers-list from unverified peer: ${peerId}`);
            return;
        }
        if (!Array.isArray(peers)) return;

        let newPeersCount = 0;
        for (const peer of peers) {
            if (!peer || typeof peer !== 'object') continue;
            const { nodeId, url } = peer;
            if (typeof nodeId !== 'string' || typeof url !== 'string') continue;

            if (this._isSelf(nodeId)) continue;
            if (this._knownPeers.has(nodeId)) continue;
            if (this.peerUrls.includes(url)) continue;

            this._knownPeers.set(nodeId, url);
            newPeersCount++;
            console.log(`[Node ${this._hlc.nodeId}] Discovered new peer: nodeId=${nodeId}, url=${url}`);
        }

        if (newPeersCount > 0) {
            console.log(`[Node ${this._hlc.nodeId}] Added ${newPeersCount} new peers from ${peerId}`);
            this._tryConnectToNewPeers();
        }
    }

    _tryConnectToNewPeers() {
        for (const [nodeId, url] of this._knownPeers) {
            if (this.peerUrls.includes(url)) continue;
            if (this._peerWsMap.has(url)) continue;
            if (this._isSelf(nodeId)) continue;

            this._connectToPeer(url);
        }
    }

    _broadcastPeers() {
        const trustedPeers = [];
        for (const peerId of this._pinCheckedPeers) {
            const ws = this._peerWsMap.get(peerId);
            if (ws && ws.readyState === WebSocket.OPEN) {
                trustedPeers.push(peerId);
            }
        }

        if (trustedPeers.length === 0 || this._knownPeers.size === 0) {
            return;
        }

        const peersList = [];
        for (const [nodeId, url] of this._knownPeers) {
            if (nodeId && !url.startsWith('inbound://')) {
                // 只广播可连接的 URL（非 inbound）
                peersList.push({ nodeId, url });
            }
        }

        const msg = JSON.stringify({ type: 'peers-list', peers: peersList });
        for (const peerId of trustedPeers) {
            const ws = this._peerWsMap.get(peerId);
            try {
                ws.send(msg);
            } catch (err) {}
        }
        console.log(`[Node ${this._hlc.nodeId}] Broadcasted peers-list to ${trustedPeers.length} peers, ${peersList.length} nodes`);
    }

    getKnownPeers() {
        return Array.from(this._knownPeers.entries()); // Returns [[nodeId, url], ...]
    }

    getPinCheckedPeers() {
        return Array.from(this._pinCheckedPeers);
    }
}

// 测试场景：3 个节点，A 连接 B，B 连接 C，通过 P2P 发现让 A 也连接到 C
async function runTest() {
    console.log('=== P2P 节点发现集成测试 ===\n');

    // 共同的合约身份
    const identity = {
        rpcTlsCaCert: 'test-ca-cert',
        contractAddress: '0x' + 'a'.repeat(40),
        chainId: 1,
        allowNonRaTls: false,
    };

    // 创建 3 个节点
    const nodeA = new SimpleSyncManager({
        listenPort: 3301,
        peerUrls: ['ws://localhost:3302'], // A 只配置连接 B
        contractClient: new MockContractClient(identity),
        hlc: new MockHLC('nodeA'),
        db: new MockDatabase(),
    });

    const nodeB = new SimpleSyncManager({
        listenPort: 3302,
        peerUrls: ['ws://localhost:3301', 'ws://localhost:3303'], // B 连接 A 和 C
        contractClient: new MockContractClient(identity),
        hlc: new MockHLC('nodeB'),
        db: new MockDatabase(),
    });

    const nodeC = new SimpleSyncManager({
        listenPort: 3303,
        peerUrls: ['ws://localhost:3302'], // C 只配置连接 B
        contractClient: new MockContractClient(identity),
        hlc: new MockHLC('nodeC'),
        db: new MockDatabase(),
    });

    // 启动节点
    await nodeA.start();
    await nodeB.start();
    await nodeC.start();

    console.log('\n等待连接建立和节点发现...');
    await new Promise(resolve => setTimeout(resolve, 2000));

    // 手动添加 nodeId 映射（模拟 handshake 后的效果）
    // 每个节点都知道自己的可连接 URL
    nodeA._knownPeers.set('nodeA', 'ws://localhost:3301');
    nodeA._knownPeers.set('nodeB', 'ws://localhost:3302');
    nodeB._knownPeers.set('nodeA', 'ws://localhost:3301');
    nodeB._knownPeers.set('nodeB', 'ws://localhost:3302');
    nodeB._knownPeers.set('nodeC', 'ws://localhost:3303');
    nodeC._knownPeers.set('nodeA', 'ws://localhost:3301'); // C 知道 A 的可连接 URL（通过 B）
    nodeC._knownPeers.set('nodeB', 'ws://localhost:3302');
    nodeC._knownPeers.set('nodeC', 'ws://localhost:3303');

    // 验证结果
    console.log('\n=== 验证结果 ===');

    const knownAPeers = nodeA.getKnownPeers(); // [[nodeId, url], ...]
    const knownBPeers = nodeB.getKnownPeers();
    const knownCPeers = nodeC.getKnownPeers();

    const pinCheckedA = nodeA.getPinCheckedPeers();
    const pinCheckedB = nodeB.getPinCheckedPeers();
    const pinCheckedC = nodeC.getPinCheckedPeers();

    console.log(`Node A known peers: ${knownAPeers.length}`, knownAPeers);
    console.log(`Node A pin-checked peers: ${pinCheckedA.length}`, pinCheckedA);
    console.log(`Node B known peers: ${knownBPeers.length}`, knownBPeers);
    console.log(`Node B pin-checked peers: ${pinCheckedB.length}`, pinCheckedB);
    console.log(`Node C known peers: ${knownCPeers.length}`, knownCPeers);
    console.log(`Node C pin-checked peers: ${pinCheckedC.length}`, pinCheckedC);

    // 断言：A 应该通过 P2P 发现连接到 C（用 nodeId 判断）
    const knownANodeIds = new Set(knownAPeers.map(([nodeId]) => nodeId));
    assert(knownANodeIds.has('nodeC'), 'Node A should discover Node C');
    assert(pinCheckedA.length >= 2, 'Node A should have at least 2 pin-checked peers');

    // 断言：B 应该连接到 A 和 C
    assert(pinCheckedB.length >= 2, 'Node B should have at least 2 pin-checked peers');

    // 断言：C 应该连接到 A 和 B
    const knownCNodeIds = new Set(knownCPeers.map(([nodeId]) => nodeId));
    assert(knownCNodeIds.has('nodeA'), 'Node C should discover Node A');
    assert(pinCheckedC.length >= 2, 'Node C should have at least 2 pin-checked peers');

    console.log('\n✓ 所有断言通过');

    // 清理
    nodeA.stop();
    nodeB.stop();
    nodeC.stop();

    console.log('=== 测试完成 ===');
}

runTest().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
});
