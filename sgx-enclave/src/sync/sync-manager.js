/**
 * WSS 同步管理器（传输层）
 *
 * 本模块是 sync-lib（纯算法引擎）与外部世界的桥接层，负责：
 *   1. WSS 服务器：监听端口，接受其他节点的连接（含 RA-TLS mTLS）
 *   2. WSS 客户端：主动连接配置的远程节点
 *   3. 重连退避：连接失败或断开的节点递增间隔重连
 *   4. 自动跳过自己：所有节点共用同一份配置，启动时自动跳过连接自己
 *   5. 定时调度 sync-lib 的 tickPull / tickCleanup / tickHeartbeat
 *
 * 核心同步/2PC/选举/幂等逻辑全部委托给 sync-lib 的 SyncEngine。
 * 本模块不处理任何同步协议细节。
 */

import { WebSocketServer, WebSocket } from 'ws';
import { createRequire } from 'module';
import { SyncEngine } from '@xnetx/raft-hlc-sync';
import { createSQLiteAdapter, registerBusinessTables } from './sync-adapter.js';

const require_fn = createRequire(import.meta.url);
const os = require_fn('os');
const https = require_fn('https');
const fs = require_fn('fs');
const http = require_fn('http');

// ========== 常量 ==========

const DEFAULT_RECONNECT_INITIAL_MS = 5000;
const DEFAULT_RECONNECT_INCREMENT_MS = 30000;
const DEFAULT_RECONNECT_MAX_MS = 300000;
const RECONNECT_CHECK_MS = 1000;
const PULL_INTERVAL_MS = 10000;
const CLEANUP_INTERVAL_MS = 3600000;
const HEARTBEAT_INTERVAL_MS = 15000;
const HEARTBEAT_TIMEOUT_MS = 45000;
const DEFAULT_LISTEN_PORT = 3307;
const DEFAULT_NUM_SHARDS = 16;
const PROXY_WAIT_MS = 6000;
const PROXY_TIMEOUT_MS = 10000;
const PREPARE_TIMEOUT_MS = 5000;
const FOLLOWER_TXN_TIMEOUT_MS = 15000;

// ========== 工具函数 ==========

function shardForUserId(userId, numShards) {
    let hash = 0;
    for (let i = 0; i < userId.length; i++) {
        hash = (Math.imul(hash, 31) + userId.charCodeAt(i)) | 0;
    }
    return Math.abs(hash) % numShards;
}

function filterProxyHeaders(headers) {
    const result = {};
    for (const [key, value] of Object.entries(headers || {})) {
        const lk = key.toLowerCase();
        if (
            lk === 'content-type' ||
            lk === 'authorization' ||
            (lk.startsWith('x-') && !lk.startsWith('x-forwarded'))
        ) {
            result[lk] = value;
        }
    }
    result['content-type'] = 'application/json';
    return result;
}

// ========== SyncManager ==========

export class SyncManager {
    /**
     * @param {object} options
     * @param {import('better-sqlite3').Database} options.db - SQLite 数据库实例
     * @param {import('@xnetx/raft-hlc-sync').HLC} options.hlc - 本地 HLC 实例
     * @param {string[]} options.peerUrls - 配置的远程节点 WSS 地址列表
     * @param {number} [options.listenPort]
     * @param {object} [options.raTlsOptions]
     * @param {import('@xnetx/sgx-ra-tls-verify').CertificateVerifier} [options.verifier]
     * @param {object} [options.reconnect]
     * @param {number} [options.httpPort]
     * @param {number} [options.numShards]
     * @param {function(): number|Promise<number>} [options.getMinQuorum]
     */
    constructor(options) {
        this.peerUrls = options.peerUrls || [];
        this.listenPort = options.listenPort || DEFAULT_LISTEN_PORT;
        this._numShards = options.numShards || DEFAULT_NUM_SHARDS;
        this._httpPort = options.httpPort || 3000;

        // 重连退避参数
        const rc = options.reconnect || {};
        this._reconnectInitialMs = rc.initialMs || DEFAULT_RECONNECT_INITIAL_MS;
        this._reconnectIncrementMs = rc.incrementMs || DEFAULT_RECONNECT_INCREMENT_MS;
        this._reconnectMaxMs = rc.maxMs || DEFAULT_RECONNECT_MAX_MS;

        // RA-TLS
        this.raTlsOptions = options.raTlsOptions || null;
        this.verifier = options.verifier || null;
        this._cert = null;
        this._key = null;
        if (this.raTlsOptions && this.raTlsOptions.certPath && this.raTlsOptions.keyPem) {
            try {
                this._cert = fs.readFileSync(this.raTlsOptions.certPath, 'utf8');
                this._key = this.raTlsOptions.keyPem;
                console.log('[SyncManager] RA-TLS loaded: cert=' + this.raTlsOptions.certPath + ', key=in-memory');
            } catch (err) {
                console.error('[SyncManager] Failed to load RA-TLS certificate:', err.message);
            }
        }

        // ===== 创建 SyncEngine（核心算法引擎）=====
        const dbAdapter = createSQLiteAdapter(options.db);

        // peerId → ws 映射
        this._peerWsMap = new Map();

        const defaultMinQuorum = (this.peerUrls.length > 0) ? 2 : 1;
        this._getMinQuorum = typeof options.getMinQuorum === 'function'
            ? options.getMinQuorum
            : () => defaultMinQuorum;

        this.engine = new SyncEngine({
            nodeId: options.hlc.nodeId,
            db: dbAdapter,
            dialect: 'sqlite',
            getNow: () => ({ value: Date.now(), unit: 'ms' }),
            memonicNow: () => ({ value: Number(process.hrtime.bigint()), unit: 'ns' }),
            numShards: this._numShards,
            getMinQuorum: this._getMinQuorum,
            syncBatchSize: 500,
            heartbeatTimeoutMs: HEARTBEAT_TIMEOUT_MS,
            heartbeatIntervalMs: HEARTBEAT_INTERVAL_MS,
            pullIntervalMs: PULL_INTERVAL_MS,
            cleanupIntervalMs: CLEANUP_INTERVAL_MS,
            proxyWaitMs: PROXY_WAIT_MS,
            proxyTimeoutMs: PROXY_TIMEOUT_MS,
            prepareTimeoutMs: PREPARE_TIMEOUT_MS,
            followerTxnTimeoutMs: FOLLOWER_TXN_TIMEOUT_MS,
            timerAPI: {
                setTimeout,
                clearTimeout,
                setInterval,
                clearInterval,
            },

            onSendToPeer: (peerId, message) => {
                const ws = this._peerWsMap.get(peerId);
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(message);
                }
            },

            onClosePeer: (peerId) => {
                const ws = this._peerWsMap.get(peerId);
                if (ws) {
                    ws._dedupClosed = true;
                    try { ws.close(); } catch (_) {}
                }
            },

            onLeaderChanged: (shardId, leaderNodeId, isLocal) => {
                console.log('[SyncManager] shard=' + shardId + ' leader=' + (leaderNodeId || 'none') +
                    (isLocal ? ' (local)' : ''));
            },

            onWriteCompleted: () => {
                this.pushToAllPeers();
            },

            onError: (context, error) => {
                console.error('[SyncManager] Error in ' + context + ':', error.message);
            },

            onExecuteProxyRequest: async (payload) => {
                return this._executeLocally(payload.method, payload.path, filterProxyHeaders(payload.headers), payload.body);
            },
        });

        // 注册业务表
        registerBusinessTables(this.engine);

        // 传输层状态
        this.pendingConnections = new Map();
        this.wss = null;
        this._httpsServer = null;
        this._reconnectTimer = null;
        this._localAddresses = new Set();
        this._started = false;
    }

    // ========== 生命周期 ==========

    async start() {
        if (this._started) return;
        this._started = true;

        // 初始化 sync-lib（schema + 触发器）
        this.engine.initSchema();
        this.engine.initTriggers();
        this.engine.start();

        this._collectLocalAddresses();
        await this._startServer();

        for (const url of this.peerUrls) {
            if (this._isSelf(url)) {
                console.log('[SyncManager] Skipping self-connection: ' + url);
                continue;
            }
            this._connectToPeer(url);
        }

        this._reconnectTimer = setInterval(() => this._reconnectPending(), RECONNECT_CHECK_MS);

        console.log('[SyncManager] Started — listening on port ' + this.listenPort +
            ', peers: ' + this.peerUrls.length + ', shards: ' + this._numShards);
    }

    stop() {
        this._started = false;

        this.engine.stop();

        if (this._reconnectTimer) { clearInterval(this._reconnectTimer); this._reconnectTimer = null; }

        for (const [, ws] of this._peerWsMap) {
            try { ws.close(); } catch (_) {}
        }
        this._peerWsMap.clear();

        if (this.wss) { this.wss.close(); this.wss = null; }
        if (this._httpsServer) { this._httpsServer.close(); this._httpsServer = null; }
        this.pendingConnections.clear();
        console.log('[SyncManager] Stopped');
    }

    // ========== 对外 API（server.js / index.js 调用）==========

    /** push-on-write：本地写操作后推送 */
    pushToAllPeers() {
        this.engine.notifyLocalWrite();
    }

    /** 判断是否多节点部署 */
    isMultiNodeDeployment() {
        return this.peerUrls.length > 0;
    }

    /** 判断本节点是否是指定 userId 对应分片的 Leader */
    isLeaderForUser(userId) {
        const shardId = userId ? shardForUserId(userId, this._numShards) : 0;
        return this.engine.isLeaderForShard(shardId);
    }

    /** 根据 userId 返回所属分片 ID */
    getShardForUser(userId) {
        return userId ? shardForUserId(userId, this._numShards) : 0;
    }

    /** 获取分片的选举实例（server.js 读 term 用） */
    get _shardElections() {
        return this.engine._shardElections;
    }

    /**
     * Follower 将写请求代理给 Leader
     * @param {string|null} userId
     * @param {{ method: string, path: string, headers: object, body: object }} reqInfo
     * @returns {Promise<{ status: number, body: object }>}
     */
    async proxyWriteRequest(userId, reqInfo) {
        const shardKey = userId || '__shard0__';
        const result = await this.engine.proxyRequest(shardKey, {
            method: reqInfo.method,
            path: reqInfo.path,
            headers: reqInfo.headers,
            body: reqInfo.body,
        });
        return result;
    }

    /** 2PC: Leader 广播 prepare 并等待 quorum ack */
    waitForPrepareAck(writeId, entries, term, shardId = 0) {
        return this.engine.waitForPrepareAck(writeId, entries, term, shardId);
    }

    /** 2PC: Leader 广播 commit */
    broadcastCommit(writeId) {
        this.engine.broadcastCommit(writeId);
    }

    /** 2PC: Leader 广播 abort */
    broadcastAbort(writeId, reason) {
        this.engine.broadcastAbort(writeId, reason);
    }

    /** 2PC: 开启手动事务 */
    beginManualTransaction(writeId) {
        this.engine.beginManualTransaction(writeId);
    }

    /** 2PC: 读取手动事务新增的 _sync_log 条目 */
    getManualTransactionEntries(writeId) {
        return this.engine.getManualTransactionEntries(writeId);
    }

    /** 2PC: 提交手动事务 */
    commitManualTransaction(writeId) {
        this.engine.commitManualTransaction(writeId);
    }

    /** 2PC: 回滚手动事务 */
    rollbackManualTransaction(writeId) {
        this.engine.rollbackManualTransaction(writeId);
    }

    /** 状态查询 */
    getStatus() {
        return this.engine.getStatus();
    }

    // ========== WSS 服务器 ==========

    _startServer() {
        return new Promise((resolve, reject) => {
            const useRaTls = !!(this._cert && this._key);

            if (useRaTls) {
                const httpsOptions = {
                    cert: this._cert,
                    key: this._key,
                    requestCert: true,
                    rejectUnauthorized: false,
                };
                this._httpsServer = https.createServer(httpsOptions);
                this._httpsServer.on('secureConnection', (tlsSocket) => {
                    this._verifyPeerCert(tlsSocket, 'client').catch((err) => {
                        console.error('[SyncManager] Inbound RA-TLS verification failed:', err.message);
                        tlsSocket.destroy();
                    });
                });
                this.wss = new WebSocketServer({ server: this._httpsServer });
                this._httpsServer.listen(this.listenPort, () => {
                    console.log('[SyncManager] WSS RA-TLS server listening on port ' + this.listenPort);
                    resolve();
                });
                this._httpsServer.on('error', (err) => {
                    console.error('[SyncManager] HTTPS server error:', err.message);
                    if (!this._started) reject(err);
                });
            } else {
                console.warn('[SyncManager] No RA-TLS certificates — starting plain WS server (insecure)');
                this.wss = new WebSocketServer({ port: this.listenPort }, () => {
                    console.log('[SyncManager] WS server listening on port ' + this.listenPort);
                    resolve();
                });
                this.wss.on('error', (err) => {
                    console.error('[SyncManager] WS server error:', err.message);
                    if (!this._started) reject(err);
                });
            }

            this.wss.on('connection', (ws, req) => {
                const peerId = 'inbound://' + req.socket.remoteAddress + ':' + req.socket.remotePort;
                this._registerWs(peerId, ws);
                this.engine.peerConnected(peerId, { direction: 'inbound' });

                ws.on('message', (data) => {
                    this.engine.receiveMessage(peerId, data.toString());
                });
                ws.on('close', () => {
                    this.engine.peerDisconnected(peerId);
                    this._peerWsMap.delete(peerId);
                });
                ws.on('error', (err) => {
                    console.error('[SyncManager] Inbound error:', err.message);
                });
            });
        });
    }

    async _verifyPeerCert(tlsSocket, role) {
        const peerCert = tlsSocket.getPeerCertificate(true);
        if (!peerCert || !peerCert.subject) {
            if (this.raTlsOptions && !this.raTlsOptions.allowNonRaTls) {
                throw new Error(role + ' did not present a certificate and non-RaTls is not allowed');
            }
            return;
        }
        if (!this.verifier) return;
        const result = await this.verifier.verify(peerCert, role);
        if (!result.valid) {
            throw new Error('RA-TLS verification failed for ' + role + ': ' + result.reason);
        }
    }

    // ========== 连接远程节点 ==========

    _connectToPeer(url) {
        if (this._peerWsMap.has(url)) return;
        const pending = this.pendingConnections.get(url);
        if (pending && pending._connecting) return;

        try {
            console.log('[SyncManager] Connecting to peer: ' + url);
            if (pending) pending._connecting = true;

            const wsOptions = {};
            if (this._cert && this._key) {
                wsOptions.cert = this._cert;
                wsOptions.key = this._key;
                wsOptions.rejectUnauthorized = false;
            } else {
                wsOptions.rejectUnauthorized = false;
            }
            const ws = new WebSocket(url, wsOptions);

            ws.on('open', () => {
                console.log('[SyncManager] Connected to peer: ' + url);

                if (this._cert && this._key && this.verifier) {
                    const rawSocket = ws._socket;
                    if (rawSocket && typeof rawSocket.getPeerCertificate === 'function') {
                        this._verifyPeerCert(rawSocket, 'server').then(() => {
                            this._finishOutboundConnect(url, ws);
                        }).catch((err) => {
                            console.error('[SyncManager] Outbound RA-TLS failed for ' + url + ':', err.message);
                            ws.close();
                        });
                        return;
                    }
                }
                this._finishOutboundConnect(url, ws);
            });

            ws.on('message', (data) => {
                this.engine.receiveMessage(url, data.toString());
            });

            ws.on('close', () => {
                console.log('[SyncManager] Disconnected from peer: ' + url);
                this.engine.peerDisconnected(url);
                this._peerWsMap.delete(url);
                if (this._started && !ws._dedupClosed) {
                    this._addToPending(url);
                }
            });

            ws.on('error', (err) => {
                console.log('[SyncManager] Connection to ' + url + ' failed: ' + err.message);
                this.engine.peerDisconnected(url);
                this._peerWsMap.delete(url);
                if (this._started) {
                    this._addToPending(url);
                }
            });
        } catch (err) {
            console.log('[SyncManager] Failed to initiate connection to ' + url + ': ' + err.message);
            this._addToPending(url);
        }
    }

    _finishOutboundConnect(url, ws) {
        this.pendingConnections.delete(url);
        this._registerWs(url, ws);
        this.engine.peerConnected(url, { direction: 'outbound' });
    }

    _registerWs(peerId, ws) {
        this._peerWsMap.set(peerId, ws);
    }

    // ========== 重连 ==========

    _addToPending(url) {
        if (this._peerWsMap.has(url)) return;
        const existing = this.pendingConnections.get(url);
        if (existing) {
            existing._connecting = false;
            let nextInterval = existing.currentInterval + this._reconnectIncrementMs;
            if (nextInterval > this._reconnectMaxMs) {
                nextInterval = this._reconnectInitialMs;
            }
            existing.currentInterval = nextInterval;
            existing.nextRetryAt = Date.now() + nextInterval;
        } else {
            this.pendingConnections.set(url, {
                nextRetryAt: Date.now() + this._reconnectInitialMs,
                currentInterval: this._reconnectInitialMs,
                _connecting: false,
            });
        }
    }

    _reconnectPending() {
        if (this.pendingConnections.size === 0) return;
        const now = Date.now();
        for (const [url, info] of this.pendingConnections) {
            if (this._peerWsMap.has(url)) {
                this.pendingConnections.delete(url);
                continue;
            }
            if (info._connecting) continue;
            if (now < info.nextRetryAt) continue;
            this._connectToPeer(url);
        }
    }

    // ========== 自动跳过自己 ==========

    _collectLocalAddresses() {
        const port = this.listenPort;
        this._localAddresses.add('ws://localhost:' + port);
        this._localAddresses.add('wss://localhost:' + port);
        this._localAddresses.add('ws://127.0.0.1:' + port);
        this._localAddresses.add('wss://127.0.0.1:' + port);
        this._localAddresses.add('ws://0.0.0.0:' + port);
        this._localAddresses.add('wss://0.0.0.0:' + port);
        this._localAddresses.add('ws://[::1]:' + port);
        this._localAddresses.add('wss://[::1]:' + port);
        try {
            const interfaces = os.networkInterfaces();
            for (const name of Object.keys(interfaces)) {
                for (const iface of interfaces[name]) {
                    if (!iface.internal) {
                        this._localAddresses.add('ws://' + iface.address + ':' + port);
                        this._localAddresses.add('wss://' + iface.address + ':' + port);
                    }
                }
            }
        } catch (_) {}
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

    // ========== HTTP 回环（Leader 执行代理请求）==========

    _executeLocally(method, path, headers, body) {
        return new Promise((resolve, reject) => {
            const bodyStr = Buffer.isBuffer(body)?body:JSON.stringify(body ?? {});
            const reqHeaders = Object.assign({}, headers, {
                'content-type': 'application/json',
                'content-length': Buffer.from(bodyStr).byteLength.toString(),
            });
            const reqOptions = {
                hostname: '127.0.0.1',
                port: this._httpPort,
                path,
                method,
                headers: reqHeaders,
            };
            const req = http.request(reqOptions, (res) => {
                let data = [];
                res.on('data', chunk => { data.push(chunk); });
                res.on('end', () => {
                    try {
                        resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(data).toString()) });
                    } catch {
                        resolve({ status: res.statusCode, body: { raw: Buffer.concat(data).toString() } });
                    }
                });
            });
            req.on('error', reject);
            req.write(bodyStr);
            req.end();
        });
    }
}
