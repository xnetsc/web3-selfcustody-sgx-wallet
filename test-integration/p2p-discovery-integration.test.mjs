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

        this._knownPeers = new Set(this.peerUrls);
        this._pinCheckedPeers = new Set();
        this._peerWsMap = new Map();
        this._localAddresses = new Set();
        this._localAddresses.add('ws://localhost:' + this.listenPort);
        this._localAddresses.add('wss://localhost:' + this.listenPort);

        this.wss = null;
        this._started = false;
        this._peersBroadcastTimer = null;
        this._messages = []; // 记录收到的消息
    }

    _isSelf(url) {
        if (this._localAddresses.has(url)) return true;
        try {
            const parsed = new URL(url);
            const normalized = parsed.protocol + '//' + parsed.hostname + ':' + (parsed.port || this.listenPort);
            if (this._localAddresses.has(normalized)) return true;
        } catch (_) {}
        return false;
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

                // 发送 pin-check
                this._sendPinCheck(peerId, ws);

                ws.on('message', (data) => {
                    const msgStr = data.toString();
                    this._messages.push({ from: peerId, content: msgStr });
                    this._handleMessage(peerId, ws, msgStr);
                });

                ws.on('close', () => {
                    this._peerWsMap.delete(peerId);
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
            this._sendPinCheck(url, ws);
        });

        ws.on('message', (data) => {
            const msgStr = data.toString();
            this._messages.push({ from: url, content: msgStr });
            this._handleMessage(url, ws, msgStr);
        });

        ws.on('close', () => {
            this._peerWsMap.delete(url);
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
        for (const peerUrl of peers) {
            if (typeof peerUrl !== 'string') continue;
            if (this._isSelf(peerUrl)) continue;
            if (this._knownPeers.has(peerUrl)) continue;
            if (this.peerUrls.includes(peerUrl)) continue;

            this._knownPeers.add(peerUrl);
            newPeersCount++;
            console.log(`[Node ${this._hlc.nodeId}] Discovered new peer: ${peerUrl}`);
        }

        if (newPeersCount > 0) {
            console.log(`[Node ${this._hlc.nodeId}] Added ${newPeersCount} new peers from ${peerId}`);
            this._tryConnectToNewPeers();
        }
    }

    _tryConnectToNewPeers() {
        for (const peerUrl of this._knownPeers) {
            if (this.peerUrls.includes(peerUrl)) continue;
            if (this._peerWsMap.has(peerUrl)) continue;
            if (this._isSelf(peerUrl)) continue;

            this._connectToPeer(peerUrl);
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

        const peersList = Array.from(this._knownPeers);
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
        return Array.from(this._knownPeers);
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

    // 验证结果
    console.log('\n=== 验证结果 ===');

    const knownAPeers = nodeA.getKnownPeers();
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

    // 断言：A 应该通过 P2P 发现连接到 C
    assert(knownAPeers.includes('ws://localhost:3303'), 'Node A should discover Node C');
    assert(pinCheckedA.length >= 2, 'Node A should have at least 2 pin-checked peers');

    // 断言：B 应该连接到 A 和 C
    assert(pinCheckedB.length >= 2, 'Node B should have at least 2 pin-checked peers');

    // 断言：C 应该连接到 A 和 B
    assert(knownCPeers.includes('ws://localhost:3301'), 'Node C should discover Node A');
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
