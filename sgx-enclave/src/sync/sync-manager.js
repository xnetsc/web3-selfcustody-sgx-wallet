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
import { createSQLiteAdapter, registerBusinessTables, ensureEntriesAppliedLocally } from './sync-adapter.js';
import { getMonotonicNow, getMonotonicMs } from '../utils/monotonic-clock.js';

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
const PULL_INTERVAL_MS = 2000; // 拉取周期：2026-11-08 由 10s 压到 2s，收窄 follower 写后读窗口的追赶档（commit 广播丢失时靠 pull 补齐）
const CLEANUP_INTERVAL_MS = 3600000;
const PEER_WATERMARK_RETENTION_MS = 7 * 24 * 3600 * 1000; // peer 水位保留期：节点超过 7 天未再出现即清理其 _sync_peers 水位行
const HEARTBEAT_INTERVAL_MS = 15000;
const HEARTBEAT_TIMEOUT_MS = 45000;
const DEFAULT_LISTEN_PORT = 3307;
const DEFAULT_NUM_SHARDS = 16;
const PROXY_WAIT_MS = 6000;
const PROXY_TIMEOUT_MS = 10000;
const PREPARE_TIMEOUT_MS = 5000;
const FOLLOWER_TXN_TIMEOUT_MS = 6000; // follower 暂存事务超时：2026-11-08 由 15s 压到 6s，commit 广播丢失时更快回滚并转入 pull 追赶；取值须大于 PREPARE_TIMEOUT_MS(5s)——协调者最迟在 prepare 预算耗尽时才发 commit，定得比它小会误杀慢 quorum 的正常提交
const PEERS_BROADCAST_INTERVAL_MS = 60000; // 每 60 秒广播一次已知节点列表
const MAX_URLS_PER_PEER = 8; // 单个节点在地址簿中保留的候选地址上限（防 gossip 膨胀）

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
     * @param {object} [options.contractClient] - ContractClient 实例，用于 peer pin-check 验证
     */
    constructor(options) {
        this.peerUrls = options.peerUrls || [];
        this._contractClient = options.contractClient || null;
        this.listenPort = options.listenPort || DEFAULT_LISTEN_PORT;
        this._numShards = options.numShards || DEFAULT_NUM_SHARDS;
        this._httpPort = options.httpPort || 3000;
        // 本节点对外通告的监听地址（用于 P2P 发现自报地址）。
        // 未配置时自动从网络接口推断。
        this.advertisedUrl = options.advertisedUrl || null;

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
        // 独立只读连接的适配器：供代理写补齐时校验"已提交可读"
        //（写连接会看到 follower 暂存事务的未提交数据，不能用作校验）
        this._readDbAdapter = options.readDb ? createSQLiteAdapter(options.readDb) : null;

        // peerId → ws 映射
        this._peerWsMap = new Map();
        // peerId → nodeId 映射（从 handshake 消息获取）
        this._peerIdToNodeId = new Map();
        // 已通过 pin-check 的 peerId 集合
        this._pinCheckedPeers = new Set();
        // 等待对端 pin-check 的 Promise resolve 队列
        this._pinCheckWaiters = new Map(); // peerId → { resolve, reject }

        // P2P 节点发现：已知节点地址簿（配置 + 动态发现）
        // Map<nodeId, string[]> - nodeId 是稳定身份标识；同一节点的多个候选
        // 连接地址去重保序排列：对端自报地址优先，其余按学到顺序补充
        this._knownPeers = new Map();
        // 本节点经入站连接 Host 头学到的自身可达地址（规范化后）。
        // Host 是已通过 pin-check 的对端实际拨通本节点时用的名字——实测可达，
        // 作为自报地址的补充对外通告（见 _learnOwnUrlFromInbound）
        this._hostLearnedOwnUrls = [];
        // Map<peerId, string> - 入站连接的 Host 头原文；对端通过 pin-check
        // 之前不使用，防止未验证连接影响本节点地址通告
        this._inboundHostByPeerId = new Map();
        // 本节点监听协议（'wss' | 'ws'），_startServer 时确定。
        // 生产形态必为 wss（RA-TLS）；Host 学习拼 URL 时据此定 scheme，
        // 没带端口的 Host 由 normalizeSyncUrl 按 scheme 补默认端口
        this._listenScheme = null;
        // Map<nodeId, ms> - 最近一次见到该节点的时刻（收到其 handshake 时更新），
        // 供 pruneStalePeerWatermarks 判断水位行是否过期
        this._peerLastSeenAt = new Map();
        // Map<nodeId, seq> - 从对端消息中观测到的其 _sync_log 最大序号
        //（handshake 的 lastSeq、sync/prepare 的条目 seq、ack 的 lastSeq），
        // 供新 leader 暖机闸判定需要追平的目标水位
        this._peerObservedMaxSeq = new Map();
        // Map<shardId, {startedAt, warned}> - 本机刚当选 leader、尚未追平
        // 已连接 peer 水位的分片；处于此集合的分片不接受写（暖机闸）
        this._shardWarmup = new Map();
        // 配置的节点暂时不加入（nodeId 未知，连接后从 handshake 获取）
        this._peersBroadcastTimer = null; // 定时广播节点列表

        const defaultMinQuorum = (this.peerUrls.length > 0) ? 2 : 1;
        this._getMinQuorum = typeof options.getMinQuorum === 'function'
            ? options.getMinQuorum
            : () => defaultMinQuorum;

        this.engine = new SyncEngine({
            nodeId: options.hlc.nodeId,
            db: dbAdapter,
            dialect: 'sqlite',
            getNow: () => getMonotonicNow(),
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
                // 暖机闸：本机当选新 leader 时先进入暖机，追平已连接 peer
                // 的水位后才接受该分片的写；失去 leader 时暖机作废
                if (isLocal) this._beginShardWarmup(shardId);
                else this._shardWarmup.delete(shardId);
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
            if (this._isSelfUrl(url)) {
                console.log('[SyncManager] Skipping self-connection: ' + url);
                continue;
            }
            this._connectToPeer(url);
        }

        this._reconnectTimer = setInterval(() => this._reconnectPending(), RECONNECT_CHECK_MS);
        this._peersBroadcastTimer = setInterval(() => this._broadcastPeers(), PEERS_BROADCAST_INTERVAL_MS);

        console.log('[SyncManager] Started — listening on port ' + this.listenPort +
            ', peers: ' + this.peerUrls.length + ', shards: ' + this._numShards);
    }

    stop() {
        this._started = false;

        this.engine.stop();

        if (this._reconnectTimer) { clearInterval(this._reconnectTimer); this._reconnectTimer = null; }
        if (this._peersBroadcastTimer) { clearInterval(this._peersBroadcastTimer); this._peersBroadcastTimer = null; }

        for (const [, ws] of this._peerWsMap) {
            try { ws.close(); } catch (_) {}
        }
        this._peerWsMap.clear();
        this._peerIdToNodeId.clear();
        this._pinCheckedPeers.clear();
        this._pinCheckWaiters.clear();
        this._inboundHostByPeerId.clear();

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

    // ═══════════════════════════════════════════════════
    //  新 leader 暖机闸
    //
    //  本库的选举不带日志完整性约束（投票只看 term 与基于 RTT 的
    //  priority），数据落后的节点同样可以当选。若新 leader 立刻接受
    //  写，冻结这类「拒绝型」状态在本机尚不可见时就会误放——该拒的
    //  没拒，比该放的晚放严重。因此本机当选任一分片的 leader 后，
    //  必须先追平「当前已连接 peer」的水位才接受该分片的写：能投出
    //  这一票的 peer 都连着，其水位就是本机上岗前必须达到的下限。
    //  追平判定用系统自身的记账：目标水位取观测到的对端最大序号与
    //  引擎握手保留值（peer.remoteMaxSeq）的较大者，本机进度取
    //  _sync_peers 的已应用水位；无水位行时按库的缺失水位语义，
    //  对端不比本机日志新即视为无可追赶。无已连接 peer 时 vacuously
    //  成立（单节点部署不会被卡住）。暖机不设超时自动放行：宁可该
    //  分片持续 503，也不带着落后状态接受写；超过 20 秒打 error 日志。
    // ═══════════════════════════════════════════════════

    /** 该分片是否处于暖机中（本机是 leader 但尚未追平，不接受写） */
    isShardWarming(shardId) {
        return this._shardWarmup.has(shardId);
    }

    _beginShardWarmup(shardId) {
        if (this._shardWarmup.has(shardId)) return;
        const state = { startedAt: Date.now(), warned: false };
        this._shardWarmup.set(shardId, state);
        this._runShardWarmup(shardId, state).catch(() => {});
    }

    async _runShardWarmup(shardId, state) {
        for (;;) {
            await new Promise(r => setTimeout(r, 200));
            try {
                if (this._shardWarmup.get(shardId) !== state) return;
                if (!this.engine.isLeaderForShard(shardId)) {
                    this._shardWarmup.delete(shardId);
                    return;
                }
                if (this._isCaughtUpWithConnectedPeers()) {
                    this._shardWarmup.delete(shardId);
                    console.log('[SyncManager] shard=' + shardId + ' warm-up complete in ' +
                        (Date.now() - state.startedAt) + 'ms; accepting writes');
                    return;
                }
                if (!state.warned && Date.now() - state.startedAt > 20000) {
                    state.warned = true;
                    console.error('[SyncManager] shard=' + shardId + ' warm-up exceeds 20s; writes stay gated until caught up with connected peers');
                }
                // 主动催一轮拉取，缩短暖机时长（引擎自身的拉取逻辑）
                try { this.engine._tickPull(); } catch (_) {}
            } catch (_) {
                // 引擎停止等场景下静默退出
                this._shardWarmup.delete(shardId);
                return;
            }
        }
    }

    /** 本机已应用水位是否追平所有「当前已连接且已握手」peer 的目标水位 */
    _isCaughtUpWithConnectedPeers() {
        const connectedNodeIds = new Set();
        for (const peerId of this._peerWsMap.keys()) {
            const nodeId = this._peerIdToNodeId.get(peerId);
            if (nodeId && !this._isSelf(nodeId)) connectedNodeIds.add(nodeId);
        }
        if (connectedNodeIds.size === 0) return true;

        // 本机对各 peer 日志的消费进度（pull 偏移，与 target 同为对方序号
        // 空间，可直接比对）。引擎旧版本没有 _sync_pull_offsets 表时退回
        // _sync_peers 读法，保持依赖升级前的闸门行为；升级后自动走精确偏移。
        let rows;
        try {
            rows = this.engine.db.all('SELECT peer_key, last_pulled_seq AS progress FROM _sync_pull_offsets', []);
        } catch (_) {
            rows = this.engine.db.all('SELECT peer_key, last_sync_id AS progress FROM _sync_peers', []);
        }
        const applied = new Map();
        for (const r of rows) applied.set(r.peer_key, r.progress);

        let localMaxSeq = null;
        for (const nodeId of connectedNodeIds) {
            let target = this._peerObservedMaxSeq.get(nodeId) || 0;
            for (const peer of this.engine._peers.values()) {
                if (peer.nodeId === nodeId && typeof peer.remoteMaxSeq === 'number') {
                    if (peer.remoteMaxSeq > target) target = peer.remoteMaxSeq;
                }
            }
            if (target === 0) continue;
            const wm = applied.get(nodeId);
            if (wm != null) {
                if (wm < target) return false;
            } else {
                if (localMaxSeq === null) {
                    const row = this.engine.db.get('SELECT MAX(id) AS m FROM _sync_log', []);
                    localMaxSeq = (row && row.m) || 0;
                }
                if (target > localMaxSeq) return false;
            }
        }
        return true;
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
            // 标记为代理写：leader 在响应中捎带本次写的 sync log 条目
            headers: { ...(reqInfo.headers || {}), 'x-sgx-proxied-write': '1' },
            body: reqInfo.body,
        });
        // 读己之写：leader 捎回的条目先在本机补齐（经引擎既有 sync 入口
        // 事务化应用），确认本机可读后才把响应返回给调用方；
        // syncEntries 是节点间字段，剥离后再向客户端返回。
        const syncEntries = result && result.body ? result.body.syncEntries : null;
        if (syncEntries && Array.isArray(syncEntries.entries) && syncEntries.entries.length > 0) {
            delete result.body.syncEntries;
            const leaderNodeId = this.engine.getLeaderForKey(shardKey);
            const leaderUrls = leaderNodeId ? this._knownPeers.get(leaderNodeId) : null;
            const peerId = (leaderUrls && leaderUrls[0]) || leaderNodeId || 'leader';
            await ensureEntriesAppliedLocally({ engine: this.engine, peerId, entries: syncEntries.entries, verifyDb: this._readDbAdapter });
        }
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
            this._listenScheme = useRaTls ? 'wss' : 'ws';

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
                // 记下拨号方实际使用的 Host（host[:port]）：待其通过 pin-check 后，
                // 据此学习本节点的一个实测可达地址（见 _learnOwnUrlFromInbound）
                if (req && req.headers && typeof req.headers.host === 'string') {
                    this._inboundHostByPeerId.set(peerId, req.headers.host);
                }
                this._registerWs(peerId, ws);
                this.engine.peerConnected(peerId, { direction: 'inbound' });

                // 先刷新合约缓存（可能合约有迁移），再发送 pin-check 握手
                this._refreshAndSendPinCheck(peerId, ws);

                ws.on('message', (data) => {
                    const msgStr = data.toString();
                    if (this._handlePinCheckMessage(peerId, ws, msgStr)) return;
                    // 拦截 handshake 消息以提取 nodeId
                    this._extractNodeIdFromHandshake(peerId, msgStr);
                    this.engine.receiveMessage(peerId, msgStr);
                });
                ws.on('close', () => {
                    this.engine.peerDisconnected(peerId);
                    this._peerWsMap.delete(peerId);
                    this._peerIdToNodeId.delete(peerId);
                    this._pinCheckedPeers.delete(peerId);
                    this._pinCheckWaiters.delete(peerId);
                    this._inboundHostByPeerId.delete(peerId);
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
                const msgStr = data.toString();
                if (this._handlePinCheckMessage(url, ws, msgStr)) return;
                // 拦截 handshake 消息以提取 nodeId
                this._extractNodeIdFromHandshake(url, msgStr);
                this.engine.receiveMessage(url, msgStr);
            });

            ws.on('close', () => {
                console.log('[SyncManager] Disconnected from peer: ' + url);
                this.engine.peerDisconnected(url);
                this._peerWsMap.delete(url);
                this._peerIdToNodeId.delete(url);
                this._pinCheckedPeers.delete(url);
                this._pinCheckWaiters.delete(url);
                if (this._started && !ws._dedupClosed) {
                    this._addToPending(url);
                }
            });

            ws.on('error', (err) => {
                console.log('[SyncManager] Connection to ' + url + ' failed: ' + err.message);
                this.engine.peerDisconnected(url);
                this._peerWsMap.delete(url);
                this._peerIdToNodeId.delete(url);
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
        // 先刷新合约缓存（可能合约有迁移），再发送 pin-check 握手
        this._refreshAndSendPinCheck(url, ws);
    }

    _registerWs(peerId, ws) {
        this._peerWsMap.set(peerId, ws);
    }

    /**
     * 从 handshake 消息中提取 nodeId 并更新映射
     */
    _extractNodeIdFromHandshake(peerId, msgStr) {
        try {
            const msg = JSON.parse(msgStr);
            if (!msg || typeof msg !== 'object') return;
            if (msg.type === 'handshake' && msg.nodeId) {
                // 跳过自己（意外的自连接场景）
                if (this._isSelf(msg.nodeId)) return;
                this._peerIdToNodeId.set(peerId, msg.nodeId);
                this._peerLastSeenAt.set(msg.nodeId, Date.now());
                if (typeof msg.lastSeq === 'number') this._notePeerProgress(msg.nodeId, msg.lastSeq);
                // 更新地址簿：出站连接用的 URL 是刚实测拨通的地址，并入该
                // 节点的候选集（自报地址到达时仍会前置，优先级更高）
                if (!peerId.startsWith('inbound://')) {
                    this._addKnownPeerUrls(msg.nodeId, [peerId]);
                }
                return;
            }
            // 非握手消息同样携带对端日志进度：sync/prepare 的条目序号、
            // ack 的 lastSeq。观测值供暖机闸判定目标水位。
            const nodeId = this._peerIdToNodeId.get(peerId);
            if (!nodeId) return;
            if ((msg.type === 'sync' || msg.type === 'prepare') && Array.isArray(msg.entries)) {
                let maxSeq = 0;
                for (const e of msg.entries) {
                    if (typeof e.seq === 'number' && e.seq > maxSeq) maxSeq = e.seq;
                }
                if (maxSeq > 0) this._notePeerProgress(nodeId, maxSeq);
            } else if (msg.type === 'ack' && typeof msg.lastSeq === 'number') {
                this._notePeerProgress(nodeId, msg.lastSeq);
            }
        } catch (_) {}
    }

    /** 记录观测到的对端 _sync_log 最大序号（单调递增；序号 0 也要落键，
     *  否则“已握手但尚无数据”的 peer 在观测表里缺席） */
    _notePeerProgress(nodeId, seq) {
        if (!nodeId || this._isSelf(nodeId)) return;
        const cur = this._peerObservedMaxSeq.get(nodeId);
        if (cur === undefined || seq > cur) this._peerObservedMaxSeq.set(nodeId, seq);
    }

    /**
     * 清理长期未再出现节点的同步水位行（_sync_peers）。
     *
     * 删除条件：节点超过保留期（7 天）未再出现，且当前未连接。
     * “未再出现”按最近一次见到该节点的时刻算（handshake 更新
     * _peerLastSeenAt），不按水位更新时间算——节点连着但长期没有新条目
     * 交换时水位不推进，不应因此被删。进程重启后内存记录丢失，此时以
     * 水位行自带的 last_sync_at 作为见到时刻的下界近似。
     * 水位行是节点本地状态，删除只影响本节点：该节点日后重连时靠握手
     * 交换最大序号与全量同步兜底追赶，不依赖旧水位。
     * @param {number} [nowMs] - 当前时刻（毫秒），测试可注入
     * @returns {Promise<number>} 删除的行数
     */
    async pruneStalePeerWatermarks(nowMs = Date.now()) {
        const db = this.engine?.db;
        if (!db) return 0;
        const rows = db.all('SELECT peer_key, last_sync_at FROM _sync_peers', []);
        const activeNodeIds = new Set(this._peerIdToNodeId.values());
        const staleKeys = selectStalePeerKeys(rows, {
            nowMs,
            retentionMs: PEER_WATERMARK_RETENTION_MS,
            activeNodeIds,
            lastSeenAtByNodeId: this._peerLastSeenAt,
        });
        for (const key of staleKeys) {
            db.run('DELETE FROM _sync_peers WHERE peer_key = ?', [key]);
            // pull 偏移表与水位行同生命周期（引擎旧版本无此表时忽略）
            try { db.run('DELETE FROM _sync_pull_offsets WHERE peer_key = ?', [key]); } catch (_) {}
            console.log(`[SyncManager] stale peer watermark pruned: peer=${key} (not seen for over 7 days)`);
        }
        return staleKeys.length;
    }

    // ========== Pin-Check 握手 ==========

    /**
     * 先刷新合约缓存（可能合约有迁移，需要拿到最新身份），再发送 pin-check。
     * 刷新失败不阻塞——用当前缓存的身份发送。
     */
    async _refreshAndSendPinCheck(peerId, ws) {
        try {
            if (this._contractClient) {
                await this._contractClient.refreshCache();
            }
        } catch (err) {
            console.warn('[SyncManager] pin-check: pre-send contract refresh failed for ' + peerId + ': ' + err.message);
        }
        this._sendPinCheck(peerId, ws);
    }

    /**
     * 发送本节点的 pinned 合约身份给对端。
     * 消息格式: JSON { type: 'pin-check', rpcTlsCaCert, contractAddress, chainId, allowNonRaTls, nodeId, listenUrl, listenUrls }
     * 比较 rpcTlsCaCert 而非 rpcUrl（证书是身份的真正锚点）。
     * nodeId + listenUrl/listenUrls 用于 P2P 发现自报地址（入站连接方也能学到本节点的全部可连接地址）。
     * 如果没有 contractClient 或尚未 pin，发送 type='pin-check' 且身份字段为 null。
     */
    _sendPinCheck(peerId, ws) {
        const identity = this._contractClient?.getPinnedIdentity?.() || null;
        const msg = JSON.stringify({
            type: 'pin-check',
            rpcTlsCaCert: identity?.rpcTlsCaCert ?? null,
            contractAddress: identity?.contractAddress || null,
            chainId: identity?.chainId ?? null,
            allowNonRaTls: identity?.allowNonRaTls ?? null,
            nodeId: this.engine.nodeId,
            listenUrl: this._getAdvertisedUrl(),
            listenUrls: this._getAdvertisedUrls(),
        });
        try {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(msg);
            }
        } catch (err) {
            console.error('[SyncManager] _sendPinCheck failed for ' + peerId + ':', err.message);
        }
    }

    /**
     * 处理收到的 pin-check 握手消息。如果是 pin-check 消息则拦截，返回 true。
     * 验证对端的 pinned 身份是否与本节点一致：
     *   - 一致 → 标记通过，允许后续通信
     *   - 不一致或本节点尚未 pin → 尝试刷新合约后再比较
     *   - 仍不一致 → 断开连接
     *
     * @returns {boolean} true 表示消息已被拦截（是 pin-check 消息），false 表示不是 pin-check 消息
     */
    _handlePinCheckMessage(peerId, ws, msgStr) {
        let msg;
        try {
            msg = JSON.parse(msgStr);
        } catch (_) {
            return false; // 不是 JSON，交给 SyncEngine
        }
        if (!msg || (msg.type !== 'pin-check' && msg.type !== 'pin-check-ack' && msg.type !== 'peers-list')) return false;

        // peers-list: 对端发来了它知道的节点列表
        if (msg.type === 'peers-list') {
            this._handlePeersList(peerId, ws, msg.peers);
            return true;
        }

        // pin-check-ack: 对端告知验证结果
        if (msg.type === 'pin-check-ack') {
            if (msg.ok) {
                this._pinCheckedPeers.add(peerId);
                this._resolvePinCheckWaiter(peerId, true);
            } else {
                this._resolvePinCheckWaiter(peerId, false);
                // 对端拒绝了我们的 pin-check，断开连接
                console.warn('[SyncManager] pin-check: rejected by peer ' + peerId + ' — disconnecting');
                try { ws.close(); } catch (_) {}
            }
            return true;
        }

        // pin-check: 对端发来了它的身份，需要验证

        // 已通过 pin-check 的 peer 不需要重复验证
        if (this._pinCheckedPeers.has(peerId)) {
            // 更新自报地址（对端可能重发 pin-check）；顺带处理本节点 Host 学习
            this._onPinCheckPassed(peerId, msg);
            // 回复 ack（对端可能还在等）
            this._sendPinCheckAck(ws, true);
            return true;
        }

        // 异步验证
        this._verifyPeerPin(peerId, ws, msg).catch((err) => {
            console.error('[SyncManager] pin-check verification error for ' + peerId + ':', err.message);
        });

        return true;
    }

    /**
     * 验证对端 pinned 身份是否与本节点一致。
     * 不一致时尝试刷新合约（可能合约迁移了），刷新后仍不一致则断开。
     */
    async _verifyPeerPin(peerId, ws, peerPin) {
        const localPin = this._contractClient?.getPinnedIdentity?.() || null;

        // 如果本节点尚未 pin，先尝试刷新合约以触发 pin
        if (!localPin) {
            console.warn('[SyncManager] pin-check: local node has no pinned identity — attempting contract refresh');
            try {
                await this._contractClient?.refreshCache();
            } catch (err) {
                console.error('[SyncManager] pin-check: contract refresh failed:', err.message);
            }
        }

        const localPinAfterRefresh = this._contractClient?.getPinnedIdentity?.() || null;

        // 对端也没有 pin（双方都是首次部署）
        if (!peerPin.rpcUrl && !peerPin.contractAddress && peerPin.chainId == null) {
            if (!localPinAfterRefresh) {
                // 双方都未 pin，允许通信（首次部署场景）
                console.log('[SyncManager] pin-check: both nodes unpinned — allowing (first deployment)');
                this._pinCheckedPeers.add(peerId);
                this._onPinCheckPassed(peerId, peerPin);
                this._sendPinCheckAck(ws, true);
                this._resolvePinCheckWaiter(peerId, true);
                return;
            }
            // 本节点已 pin 但对端没有 → 拒绝
            console.warn('[SyncManager] pin-check: local pinned but peer has no pin — rejecting ' + peerId);
            this._sendPinCheckAck(ws, false);
            this._rejectAndClose(peerId, ws, 'peer has no pinned identity');
            return;
        }

        // 比较三元组
        const match = this._pinIdentityMatches(localPinAfterRefresh, peerPin);
        if (match) {
            console.log('[SyncManager] pin-check: identity matches with ' + peerId);
            this._pinCheckedPeers.add(peerId);
            this._onPinCheckPassed(peerId, peerPin);
            this._sendPinCheckAck(ws, true);
            this._resolvePinCheckWaiter(peerId, true);
            return;
        }

        // 不一致 → 尝试刷新合约（可能合约刚迁移，本节点还没同步）
        console.warn('[SyncManager] pin-check: identity mismatch with ' + peerId +
            ' — local=' + JSON.stringify(localPinAfterRefresh) +
            ' peer=' + JSON.stringify({ rpcUrl: peerPin.rpcUrl, contractAddress: peerPin.contractAddress, chainId: peerPin.chainId }) +
            ' — attempting contract refresh');

        try {
            await this._contractClient?.refreshCache();
        } catch (err) {
            console.error('[SyncManager] pin-check: contract refresh failed:', err.message);
        }

        const localPinAfterRefresh2 = this._contractClient?.getPinnedIdentity?.() || null;
        const match2 = this._pinIdentityMatches(localPinAfterRefresh2, peerPin);
        if (match2) {
            console.log('[SyncManager] pin-check: identity matches after refresh with ' + peerId);
            this._pinCheckedPeers.add(peerId);
            this._onPinCheckPassed(peerId, peerPin);
            this._sendPinCheckAck(ws, true);
            this._resolvePinCheckWaiter(peerId, true);
            return;
        }

        // 仍不一致 → 断开连接
        console.warn('[SyncManager] pin-check: identity still mismatched after refresh — rejecting ' + peerId);
        this._sendPinCheckAck(ws, false);
        this._rejectAndClose(peerId, ws, 'pinned identity mismatch after refresh');
    }

    /**
     * pin-check 通过后的统一收尾：记录对端自报地址 + 学习本节点地址。
     * 只在验证通过的路径上调用——防止未验证节点污染地址簿，
     * 也防止未验证连接影响本节点的地址通告。
     */
    _onPinCheckPassed(peerId, peerPin) {
        this._recordPeerAdvertisedUrl(peerId, peerPin);
        this._learnOwnUrlFromInbound(peerId);
    }

    /**
     * 记录对端在 pin-check 中自报的 nodeId + 监听地址（listenUrl 为主地址，
     * listenUrls 为其全部候选）。自报地址优先级最高，前置进该节点的
     * 候选集；其余来源（拨通的地址、gossip 学到的）只作补充，不覆盖。
     * 解决入站连接方无法得知对端可连接地址的问题。
     */
    _recordPeerAdvertisedUrl(peerId, peerPin) {
        const { nodeId, listenUrl, listenUrls } = peerPin || {};
        if (typeof nodeId !== 'string' || !nodeId) return;
        // 只通过 nodeId 判断是否自己
        if (this._isSelf(nodeId)) return;

        this._peerIdToNodeId.set(peerId, nodeId);

        const incoming = [];
        if (Array.isArray(listenUrls)) incoming.push(...listenUrls);
        if (typeof listenUrl === 'string') incoming.push(listenUrl);
        const added = this._addKnownPeerUrls(nodeId, incoming, { front: true });
        if (added > 0) {
            console.log('[SyncManager] Recorded advertised urls for peer: nodeId=' + nodeId +
                ', urls=' + JSON.stringify(this._knownPeers.get(nodeId)));
        }
    }

    /**
     * 把地址并入某节点的候选集（规范化、去重、保序、上限截断）。
     * front=true 时新地址排到最前（自报语义）。返回实际新增的地址数。
     */
    _addKnownPeerUrls(nodeId, urls, { front = false } = {}) {
        if (!nodeId || this._isSelf(nodeId)) return 0;
        const before = this._knownPeers.get(nodeId) || [];
        const merged = mergePeerUrls(before, urls, { front });
        if (merged.length === 0) return 0;
        this._knownPeers.set(nodeId, merged);
        return merged.filter((u) => !before.includes(u)).length;
    }

    /**
     * 从一条已通过 pin-check 的入站连接学习本节点的可达地址：
     * 拨号方在 WS 升级请求里写下的 Host，就是它实际拨通本节点所用的
     * host[:port]（带端口用该端口，没带说明是协议默认端口，拼接时补齐）。
     * 该地址已被实测连通（至少从该对端的网络位置），作为配置/推断出的
     * 自报地址的补充；学到新地址后立即向已验证的对端重发 pin-check，
     * 让新地址随自报与 gossip 扩散。
     */
    _learnOwnUrlFromInbound(peerId) {
        if (!peerId.startsWith('inbound://')) return;
        const host = this._inboundHostByPeerId.get(peerId);
        if (!host) return;
        const url = urlFromHostHeader(host, this._listenScheme || 'wss');
        if (!url) return;
        if (this._getAdvertisedUrls().includes(url)) return;
        this._hostLearnedOwnUrls.push(url);
        console.log('[SyncManager] Learned own reachable url from inbound Host: ' + url);
        // 把新地址告诉已建连且已验证的对端（它们会前置记录并继续 gossip）
        for (const pid of this._pinCheckedPeers) {
            const ws = this._peerWsMap.get(pid);
            if (ws && ws.readyState === WebSocket.OPEN) {
                this._sendPinCheck(pid, ws);
            }
        }
    }

    /**
     * 本节点对外通告的全部候选地址：自报地址（配置优先、其次网卡推断）
     * 在前，Host 学到的实测地址在后，去重保序。
     */
    _getAdvertisedUrls() {
        const primary = this._getAdvertisedUrl();
        const all = primary ? [primary, ...this._hostLearnedOwnUrls] : [...this._hostLearnedOwnUrls];
        return mergePeerUrls([], all);
    }

    /**
     * 比较两个 pinned 身份是否一致（rpcTlsCaCert + contractAddress + chainId + allowNonRaTls）
     * 用 rpcTlsCaCert 替代 rpcUrl 做比较——证书是身份的真正锚点。
     * 一方有证书另一方没有即视为不匹配。
     */
    _pinIdentityMatches(local, peer) {
        if (!local || !peer) return false;
        return (
            (local.rpcTlsCaCert || '') === (peer.rpcTlsCaCert || '') &&
            local.contractAddress === peer.contractAddress &&
            Number(local.chainId) === Number(peer.chainId) &&
            !!local.allowNonRaTls === !!peer.allowNonRaTls
        );
    }

    /**
     * 发送 pin-check ack（让对端知道验证结果）
     */
    _sendPinCheckAck(ws, ok) {
        const msg = JSON.stringify({ type: 'pin-check-ack', ok });
        try {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(msg);
            }
        } catch (_) {}
    }

    /**
     * 拒绝并断开连接
     */
    _rejectAndClose(peerId, ws, reason) {
        console.warn('[SyncManager] pin-check REJECT: ' + peerId + ' — ' + reason + ' — disconnecting');
        this._resolvePinCheckWaiter(peerId, false);
        try { ws.close(); } catch (_) {}
    }

    /**
     * 解除等待 pin-check 结果的 Promise
     */
    _resolvePinCheckWaiter(peerId, ok) {
        const waiter = this._pinCheckWaiters.get(peerId);
        if (waiter) {
            this._pinCheckWaiters.delete(peerId);
            if (ok) waiter.resolve();
            else waiter.reject(new Error('pin-check failed for ' + peerId));
        }
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
            existing.nextRetryAt = getMonotonicMs() + nextInterval;
        } else {
            this.pendingConnections.set(url, {
                nextRetryAt: getMonotonicMs() + this._reconnectInitialMs,
                currentInterval: this._reconnectInitialMs,
                _connecting: false,
            });
        }
    }

    _reconnectPending() {
        if (this.pendingConnections.size === 0) return;
        const now = getMonotonicMs();
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

    /**
     * 用 URL 判断是否自己（用于连接前 nodeId 未知的场景，如配置的 peerUrls）
     */
    _isSelfUrl(url) {
        if (this._localAddresses.has(url)) return true;
        try {
            const parsed = new URL(url);
            const normalized = parsed.protocol + '//' + parsed.hostname + ':' + (parsed.port || this.listenPort);
            if (this._localAddresses.has(normalized)) return true;
        } catch (_) {}
        return false;
    }

    /**
     * 用 nodeId 判断是否自己（nodeId 是稳定身份标识，优先使用）
     */
    _isSelf(nodeId) {
        return nodeId === this.engine.nodeId;
    }

    /**
     * 获取本节点对外通告的监听地址。
     * 优先使用配置的 advertisedUrl；未配置时从第一个非内部网络接口推断。
     * 推断失败返回 null（不通告）。
     */
    _getAdvertisedUrl() {
        if (this.advertisedUrl) return this.advertisedUrl;
        try {
            const scheme = (this._cert && this._key) ? 'wss' : 'ws';
            const interfaces = os.networkInterfaces();
            for (const name of Object.keys(interfaces)) {
                for (const iface of interfaces[name]) {
                    if (!iface.internal && iface.family === 'IPv4') {
                        return scheme + '://' + iface.address + ':' + this.listenPort;
                    }
                }
            }
        } catch (_) {}
        return null;
    }

    // ========== P2P 节点发现 ==========

    /**
     * 向已通过 pin-check 的 peers 广播已知节点列表
     */
    _broadcastPeers() {
        // 只广播给已通过 pin-check 的 peers
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

        // 构造 peers-list: [{ nodeId, urls }, ...]（urls 为该节点的候选地址集）
        const peersList = [];
        for (const [nodeId, urls] of this._knownPeers) {
            // 跳过自己，只广播已知 nodeId 的可连接地址
            if (nodeId && !this._isSelf(nodeId) && urls.length > 0) {
                peersList.push({ nodeId, urls: [...urls] });
            }
        }

        const msg = JSON.stringify({ type: 'peers-list', peers: peersList });
        for (const peerId of trustedPeers) {
            const ws = this._peerWsMap.get(peerId);
            try {
                ws.send(msg);
            } catch (err) {
                console.error('[SyncManager] Failed to broadcast peers-list to ' + peerId + ':', err.message);
            }
        }
        console.log('[SyncManager] Broadcasted peers-list to ' + trustedPeers.length + ' trusted peers, ' + peersList.length + ' nodes');
    }

    /**
     * 处理收到的 peers-list 消息
     * 只接受已通过 pin-check 的 peers 的节点信息
     */
    _handlePeersList(peerId, ws, peers) {
        // 安全检查：只接受已通过 pin-check 的 peers 的节点信息
        if (!this._pinCheckedPeers.has(peerId)) {
            console.warn('[SyncManager] Ignored peers-list from unverified peer: ' + peerId);
            return;
        }

        if (!Array.isArray(peers)) {
            console.warn('[SyncManager] Invalid peers-list format from ' + peerId);
            return;
        }

        let changed = 0;
        for (const peer of peers) {
            if (!peer || typeof peer !== 'object') continue;
            const { nodeId, url, urls } = peer;
            if (typeof nodeId !== 'string') continue;
            // 跳过自己（只通过 nodeId）
            if (this._isSelf(nodeId)) continue;
            // 兼容两种格式：新版 urls 数组、旧版单个 url。
            // 已知节点也可借 gossip 补充新候选地址（合并去重，不覆盖）
            const incoming = [];
            if (Array.isArray(urls)) incoming.push(...urls);
            if (typeof url === 'string') incoming.push(url);
            const added = this._addKnownPeerUrls(nodeId, incoming);
            if (added > 0) {
                changed++;
                console.log('[SyncManager] Learned peer urls via P2P: nodeId=' + nodeId +
                    ', urls=' + JSON.stringify(this._knownPeers.get(nodeId)));
            }
        }

        if (changed > 0) {
            console.log('[SyncManager] Updated ' + changed + ' peers from ' + peerId + ', total known: ' + this._knownPeers.size);
            // 尝试连接新发现的节点
            this._tryConnectToNewPeers();
        }
    }

    /**
     * 尝试连接新发现的节点（去重 + 跳过自己）
     */
    _tryConnectToNewPeers() {
        // 已连接节点的 nodeId 集合（去重只通过 nodeId）
        const connectedNodeIds = new Set(this._peerIdToNodeId.values());

        for (const [nodeId, urls] of this._knownPeers) {
            // 跳过自己（只通过 nodeId）
            if (this._isSelf(nodeId)) continue;
            // 跳过已连接的节点（只通过 nodeId 去重）
            if (connectedNodeIds.has(nodeId)) continue;
            // 候选地址逐个尝试：某个地址不通不影响其余候选
            for (const url of urls) {
                if (this._peerWsMap.has(url)) continue;
                // 跳过已在 pending 队列的地址
                if (this.pendingConnections.has(url)) continue;
                this._connectToPeer(url);
            }
        }
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

/**
 * 把一个 ws/wss 地址规范化为可去重的 canonical 形式：scheme://host:port。
 * 端口缺省时按协议补默认端口（ws 80 / wss 443）——故 wss://a.com 与
 * wss://a.com:443 规范化后相同，去重时只保留一份。路径/query 一律丢弃
 * （同步地址只有 origin）。非法或非 ws/wss 输入返回 null。
 * （纯函数，供地址簿逻辑与测试使用。）
 */
export function normalizeSyncUrl(raw) {
    if (typeof raw !== 'string') return null;
    let parsed;
    try { parsed = new URL(raw.trim()); } catch (_) { return null; }
    if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') return null;
    if (!parsed.hostname) return null;
    const port = parsed.port || (parsed.protocol === 'wss:' ? '443' : '80');
    return parsed.protocol + '//' + parsed.hostname + ':' + port;
}

/**
 * 由入站连接的 Host 头还原“拨号方实际用来连到本节点的地址”。
 * Host 带端口就用该端口；没带端口说明拨号方用的是协议默认端口，
 * 由 normalizeSyncUrl 按 scheme 补齐（wss → 443）。
 * （纯函数，供 Host 学习与测试使用。）
 */
export function urlFromHostHeader(hostHeader, scheme) {
    if (typeof hostHeader !== 'string' || !hostHeader.trim()) return null;
    return normalizeSyncUrl(scheme + '://' + hostHeader.trim());
}

/**
 * 把 incoming 地址合并进 existing 候选集：规范化去重、保序。
 * front=true 时 incoming 排在前面（对端自报的地址优先级最高）；
 * 结果截断到 MAX_URLS_PER_PEER（截断丢弃排在后面的低优先级地址）。
 * （纯函数，供地址簿逻辑与测试使用。）
 * @returns {string[]} 新的候选地址数组（不修改入参）
 */
export function mergePeerUrls(existing, incoming, { front = false } = {}) {
    const norm = (list) => {
        const out = [];
        for (const u of list || []) {
            const n = normalizeSyncUrl(u);
            if (n && !out.includes(n)) out.push(n);
        }
        return out;
    };
    const inc = norm(incoming);
    const old = norm(existing);
    const merged = front
        ? [...inc, ...old.filter((u) => !inc.includes(u))]
        : [...old, ...inc.filter((u) => !old.includes(u))];
    return merged.slice(0, MAX_URLS_PER_PEER);
}

/**
 * 选出应删除的 peer 水位行（纯函数，供 pruneStalePeerWatermarks 与测试使用）。
 * lastSeen 取两个来源的较晚者：内存中记录的最近见到时刻，与水位行自带的
 * last_sync_at（进程重启后内存记录丢失时的下界近似）。
 * @param {Array<{peer_key: string, last_sync_at: string|null}>} rows
 * @param {{nowMs: number, retentionMs: number, activeNodeIds: Set<string>, lastSeenAtByNodeId: Map<string, number>}} opts
 * @returns {string[]} 应删除的 peer_key 列表
 */
export function selectStalePeerKeys(rows, { nowMs, retentionMs, activeNodeIds, lastSeenAtByNodeId }) {
    const stale = [];
    for (const row of rows || []) {
        const key = row.peer_key;
        if (activeNodeIds && activeNodeIds.has(key)) continue;
        let lastSeen = 0;
        const remembered = lastSeenAtByNodeId ? lastSeenAtByNodeId.get(key) : undefined;
        if (typeof remembered === 'number') lastSeen = Math.max(lastSeen, remembered);
        const watermarkAt = row.last_sync_at ? Date.parse(row.last_sync_at) : NaN;
        if (!Number.isNaN(watermarkAt)) lastSeen = Math.max(lastSeen, watermarkAt);
        if (nowMs - lastSeen > retentionMs) stale.push(key);
    }
    return stale;
}
