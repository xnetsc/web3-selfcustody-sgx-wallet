/**
 * RA-TLS 注册延迟端到端测试 —— 真实 SyncManager（WSS）+ 桩验证器
 *
 * 强制验证模式（本节点有 RA-TLS 身份且 allowNonRaTls=false）下，
 * 验证出结果前业务逻辑层不知道连接存在（不注册、事件不触发）：
 *   场景 1：验证耗时 500ms 且通过 —— 验证完成前客户端收不到任何字节，
 *           通过后连接才注册，handshake / pin-check 随之发出
 *   场景 2：验证不通过 —— 客户端零字节，连接被销毁（从未注册）
 *   场景 3：客户端不提供证书 —— 同样零字节并被销毁
 *   场景 4：非强制模式（allowNonRaTls=true）+ 同样耗时的验证器 ——
 *           不延迟注册，handshake 立即到达（证明延迟只由配置决定）
 *
 * 证书由 @xnetx/sgx-ra-tls-verify 的 generateRaTlsCertificate 生成
 * （非 SGX 环境无 quote，验证判定由注入的桩验证器给出——验证器正是
 * 钱包与验证库之间的注入点）。
 *
 * 运行: node p2p-verify-gate.test.mjs
 */

import assert from 'node:assert';
import { createRequire } from 'module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SyncManager } from '../sgx-enclave/src/sync/sync-manager.js';
import { HLC } from '../sgx-enclave/node_modules/@xnetx/raft-hlc-sync/index.js';
import { generateRaTlsCertificate } from '../sgx-enclave/node_modules/@xnetx/sgx-ra-tls-verify/index.mjs';
import { ALL_TABLE_SQLS } from '../sgx-enclave/src/database/schema.js';

const require_fn = createRequire(import.meta.url);
const Database = require_fn('../sgx-enclave/node_modules/better-sqlite3');
const { WebSocket } = require_fn('../sgx-enclave/node_modules/ws');

const VERIFY_DELAY_MS = 500;

async function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function createDb() {
    const db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    for (const { sql, indexes } of ALL_TABLE_SQLS) {
        db.exec(sql);
        for (const idx of indexes) db.exec(idx);
    }
    return db;
}

function createServer({ port, allowNonRaTls, verifier, certPath, keyPem }) {
    const db = createDb();
    const hlc = new HLC('gate-server-' + port, () => ({ value: Date.now(), unit: 'ms' }));
    const mgr = new SyncManager({
        db,
        hlc,
        peerUrls: [],
        listenPort: port,
        contractClient: null,
        getMinQuorum: () => 1,
        raTlsOptions: { certPath, keyPem, allowNonRaTls },
        verifier,
    });
    return { mgr, db };
}

// 以客户端身份连入，收集 (相对连接时刻, 消息) 并观察连接是否被关闭
function connectClient(port, { certPem, keyPem }, observeMs) {
    return new Promise((resolve) => {
        const t0 = Date.now();
        const received = [];
        let closed = false;
        const ws = new WebSocket('wss://127.0.0.1:' + port, {
            rejectUnauthorized: false,
            ...(certPem ? { cert: certPem, key: keyPem } : {}),
        });
        ws.on('message', (data) => {
            received.push({ at: Date.now() - t0, data: data.toString() });
        });
        ws.on('close', () => { closed = true; });
        ws.on('error', () => {});
        setTimeout(() => {
            try { ws.close(); } catch (_) {}
            resolve({ received, closed });
        }, observeMs);
    });
}

async function main() {
    console.log('=== RA-TLS 注册延迟端到端测试 ===\n');

    // 非 SGX 环境：produceQuote 返回 null → 生成无 quote 的自签证书
    // （与 launcher 在非 SGX 环境的行为一致）；验证判定由桩验证器给出
    const { certPem, keyPem } = await generateRaTlsCertificate({
        produceQuote: async () => null,
        subjectCommonName: 'SGX RA-TLS',
        validityDays: 365,
    });
    const certPath = path.join(os.tmpdir(), 'ratls-gate-test-cert.pem');
    fs.writeFileSync(certPath, certPem);

    const delayedOkVerifier = {
        verify: async () => { await sleep(VERIFY_DELAY_MS); return { valid: true }; },
    };
    const rejectingVerifier = {
        verify: async () => ({ valid: false, reason: 'stub reject' }),
    };

    // ---- 场景 1：强制模式 + 验证延迟通过 → 先零字节，后补发 ----
    {
        const { mgr, db } = createServer({
            port: 3341, allowNonRaTls: false, verifier: delayedOkVerifier, certPath, keyPem,
        });
        assert.equal(mgr._ratlsMandatory, true, 'scenario 1 should be in mandatory mode');
        await mgr.start();
        const { received } = await connectClient(3341, { certPem, keyPem }, 1600);
        console.log('[场景1] arrivals:', received.map((r) => r.at + 'ms'));
        assert(received.length > 0, 'messages should be sent once registration completes after verification');
        assert(received[0].at >= VERIFY_DELAY_MS - 100,
            'no bytes may leave before verification completes, first arrived at ' + received[0].at + 'ms');
        assert(received.some((r) => r.data.includes('"handshake"')),
            'engine handshake should be sent right after registration');
        console.log('✓ 场景 1 通过：验证前零字节，通过后注册并发出 handshake\n');
        mgr.stop(); db.close();
    }

    // ---- 场景 2：强制模式 + 验证不通过 → 零字节且连接销毁 ----
    {
        const { mgr, db } = createServer({
            port: 3342, allowNonRaTls: false, verifier: rejectingVerifier, certPath, keyPem,
        });
        await mgr.start();
        const { received, closed } = await connectClient(3342, { certPem, keyPem }, 1200);
        console.log('[场景2] arrivals:', received.length, ', closed by server:', closed);
        assert.equal(received.length, 0, 'failed verification must not let any byte out');
        assert.equal(closed, true, 'connection should be destroyed after failed verification');
        console.log('✓ 场景 2 通过：验证失败零字节，连接销毁（从未注册）\n');
        mgr.stop(); db.close();
    }

    // ---- 场景 3：强制模式 + 客户端无证书 → 零字节且连接销毁 ----
    {
        const { mgr, db } = createServer({
            port: 3343, allowNonRaTls: false, verifier: delayedOkVerifier, certPath, keyPem,
        });
        await mgr.start();
        const { received, closed } = await connectClient(3343, {}, 1200);
        console.log('[场景3] arrivals:', received.length, ', closed by server:', closed);
        assert.equal(received.length, 0, 'certless peer must not receive any byte in mandatory mode');
        assert.equal(closed, true, 'certless connection should be destroyed in mandatory mode');
        console.log('✓ 场景 3 通过：无证书对端零字节并被销毁\n');
        mgr.stop(); db.close();
    }

    // ---- 场景 4：非强制模式 → 不延迟注册，消息立即到达 ----
    {
        const { mgr, db } = createServer({
            port: 3344, allowNonRaTls: true, verifier: delayedOkVerifier, certPath, keyPem,
        });
        assert.equal(mgr._ratlsMandatory, false, 'scenario 4 should NOT be in mandatory mode');
        await mgr.start();
        const { received } = await connectClient(3344, { certPem, keyPem }, 1200);
        console.log('[场景4] arrivals:', received.map((r) => r.at + 'ms'));
        assert(received.length > 0, 'non-mandatory mode should deliver messages');
        assert(received[0].at < VERIFY_DELAY_MS - 100,
            'non-mandatory mode must not gate on verification, first arrived at ' + received[0].at + 'ms');
        console.log('✓ 场景 4 通过：配置不强制时不延迟注册\n');
        mgr.stop(); db.close();
    }

    // ---- 场景 5：验证等待期间到达的消息 → 注册后按原序补触发 ----
    {
        const { mgr, db } = createServer({
            port: 3345, allowNonRaTls: false, verifier: delayedOkVerifier, certPath, keyPem,
        });
        await mgr.start();
        const probeSeen = () => [...mgr._peerIdToNodeId.values()].includes('node-replay-probe');
        const ws = new WebSocket('wss://127.0.0.1:3345', {
            rejectUnauthorized: false, cert: certPem, key: keyPem,
        });
        ws.on('error', () => {});
        await new Promise((resolve) => ws.on('open', resolve));
        // 连接刚建立（验证尚需 ~500ms）就立刻发出 handshake
        ws.send(JSON.stringify({ type: 'handshake', nodeId: 'node-replay-probe', lastSeq: 0 }));
        await sleep(250);
        assert.equal(probeSeen(), false,
            'message arriving during verification must not be processed before registration');
        await sleep(1400);
        assert.equal(probeSeen(), true,
            'message buffered during verification must be replayed after registration');
        console.log('✓ 场景 5 通过：验证期间消息只缓冲不处理，注册后补触发\n');
        try { ws.close(); } catch (_) {}
        mgr.stop(); db.close();
    }

    fs.rmSync(certPath, { force: true });
    console.log('=== 全部通过 ===');
    process.exit(0);
}

main().catch((err) => {
    console.error('Test failed:', err);
    process.exit(1);
});
