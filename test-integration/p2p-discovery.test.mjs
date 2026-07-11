/**
 * P2P 节点发现功能测试
 * 测试节点之间互相交换已知节点列表，实现病毒式传播
 */

import assert from 'node:assert';
import { WebSocketServer, WebSocket } from 'ws';

// 模拟 SyncManager 的 P2P 发现逻辑
class MockSyncManager {
    constructor(peerUrls = []) {
        this.peerUrls = peerUrls;
        this._knownPeers = new Set(peerUrls);
        this._pinCheckedPeers = new Set();
        this._peerWsMap = new Map();
        this._localAddresses = new Set();
        this._localAddresses.add('ws://localhost:3307');
        this._localAddresses.add('wss://localhost:3307');
    }

    _isSelf(url) {
        if (this._localAddresses.has(url)) return true;
        try {
            const parsed = new URL(url);
            const normalized = parsed.protocol + '//' + parsed.hostname + ':' + (parsed.port || 3307);
            if (this._localAddresses.has(normalized)) return true;
        } catch (_) {}
        return false;
    }

    _handlePeersList(peerId, ws, peers) {
        if (!this._pinCheckedPeers.has(peerId)) {
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
        }
        return newPeersCount;
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
        return { trustedPeers, peersList };
    }
}

// Test 1: 初始已知节点列表包含配置的节点
{
    const manager = new MockSyncManager(['ws://node1.example:3307', 'ws://node2.example:3307']);
    assert.equal(manager._knownPeers.size, 2);
    assert(manager._knownPeers.has('ws://node1.example:3307'));
    assert(manager._knownPeers.has('ws://node2.example:3307'));
    console.log('✓ Test 1 passed');
}

// Test 2: 从已验证 peer 收到 peers-list，合并新节点
{
    const manager = new MockSyncManager(['ws://node1.example:3307']);
    manager._pinCheckedPeers.add('peer1');

    const newPeers = ['ws://node2.example:3307', 'ws://node3.example:3307'];
    const added = manager._handlePeersList('peer1', null, newPeers);

    assert.equal(added, 2);
    assert.equal(manager._knownPeers.size, 3);
    assert(manager._knownPeers.has('ws://node2.example:3307'));
    assert(manager._knownPeers.has('ws://node3.example:3307'));
    console.log('✓ Test 2 passed');
}

// Test 3: 忽略未验证 peer 的 peers-list
{
    const manager = new MockSyncManager(['ws://node1.example:3307']);
    // peer1 未通过 pin-check

    const newPeers = ['ws://node2.example:3307', 'ws://node3.example:3307'];
    const added = manager._handlePeersList('peer1', null, newPeers);

    assert.equal(added, undefined);
    assert.equal(manager._knownPeers.size, 1);
    console.log('✓ Test 3 passed');
}

// Test 4: 跳过自己
{
    const manager = new MockSyncManager(['ws://node1.example:3307']);
    manager._pinCheckedPeers.add('peer1');

    const newPeers = ['ws://localhost:3307', 'ws://node2.example:3307'];
    const added = manager._handlePeersList('peer1', null, newPeers);

    assert.equal(added, 1);
    assert.equal(manager._knownPeers.size, 2);
    assert(!manager._knownPeers.has('ws://localhost:3307'));
    console.log('✓ Test 4 passed');
}

// Test 5: 跳过已知的节点
{
    const manager = new MockSyncManager(['ws://node1.example:3307', 'ws://node2.example:3307']);
    manager._pinCheckedPeers.add('peer1');

    const newPeers = ['ws://node2.example:3307', 'ws://node3.example:3307'];
    const added = manager._handlePeersList('peer1', null, newPeers);

    assert.equal(added, 1);
    assert.equal(manager._knownPeers.size, 3);
    console.log('✓ Test 5 passed');
}

// Test 6: 跳过配置中的节点
{
    const manager = new MockSyncManager(['ws://node1.example:3307']);
    manager._pinCheckedPeers.add('peer1');

    const newPeers = ['ws://node1.example:3307', 'ws://node2.example:3307'];
    const added = manager._handlePeersList('peer1', null, newPeers);

    assert.equal(added, 1);
    assert.equal(manager._knownPeers.size, 2);
    console.log('✓ Test 6 passed');
}

// Test 7: 广播只发给已验证的 peers
{
    const manager = new MockSyncManager(['ws://node1.example:3307']);
    manager._pinCheckedPeers.add('peer1');
    manager._pinCheckedPeers.add('peer2');

    const mockWs1 = { readyState: WebSocket.OPEN, send: () => {} };
    const mockWs2 = { readyState: WebSocket.OPEN, send: () => {} };
    manager._peerWsMap.set('peer1', mockWs1);
    manager._peerWsMap.set('peer2', mockWs2);

    const result = manager._broadcastPeers();

    assert(result.trustedPeers.length === 2);
    assert(result.peersList.length === 1);
    assert(result.peersList[0] === 'ws://node1.example:3307');
    console.log('✓ Test 7 passed');
}

// Test 8: 没有已验证 peers 时不广播
{
    const manager = new MockSyncManager(['ws://node1.example:3307']);
    // 没有 pin-checked peers

    const result = manager._broadcastPeers();

    assert.equal(result, undefined);
    console.log('✓ Test 8 passed');
}

// Test 9: 病毒式传播：节点 A → B → C
{
    const nodeA = new MockSyncManager(['ws://node1.example:3307']);
    const nodeB = new MockSyncManager(['ws://node2.example:3307']);
    const nodeC = new MockSyncManager(['ws://node3.example:3307']);

    // A 和 B 互相验证
    nodeA._pinCheckedPeers.add('nodeB');
    nodeB._pinCheckedPeers.add('nodeA');

    // B 收到 A 的 peers-list（A 知道 node1）
    nodeB._handlePeersList('nodeA', null, ['ws://node1.example:3307']);
    assert.equal(nodeB._knownPeers.size, 2);

    // B 和 C 互相验证
    nodeB._pinCheckedPeers.add('nodeC');
    nodeC._pinCheckedPeers.add('nodeB');

    // B 收到 C 的 peers-list（C 知道 node3）
    nodeB._handlePeersList('nodeC', null, ['ws://node3.example:3307']);
    assert.equal(nodeB._knownPeers.size, 3);

    // C 收到 B 的 peers-list（B 知道 node1, node2, node3）
    nodeC._handlePeersList('nodeB', null, Array.from(nodeB._knownPeers));
    assert.equal(nodeC._knownPeers.size, 3);
    assert(nodeC._knownPeers.has('ws://node1.example:3307'));
    assert(nodeC._knownPeers.has('ws://node2.example:3307'));
    assert(nodeC._knownPeers.has('ws://node3.example:3307'));
    console.log('✓ Test 9 passed');
}

console.log('All P2P discovery tests passed');
