#!/usr/bin/env node
/**
 * SGX Enclave Gramine Launcher (enclave entry point)
 *
 * Runs inside the Gramine enclave. Responsibilities:
 *   1. Generate RA-TLS certificate with embedded SGX quote (replaces gramine-ratls)
 *   2. Validate environment and run sgx-enclave business logic
 *
 * Architecture (single enclave, single Node.js process):
 *
 *   sgx-enclave HTTP API (Express, port SGX_HTTP_PORT)
 *     ↕ better-sqlite3 (in-process)
 *   SQLite database (encrypted partition)
 *     ↕ WSS RA-TLS (peer-to-peer sync)
 *   Remote peer nodes (each also an sgx-enclave)
 *
 * Certificate generation uses Node.js crypto + /dev/attestation/ interface
 * to replicate Gramine's gramine-ratls certificate generation. This eliminates
 * the need for allowed_files entries, enabling true encryption on disk via
 * Gramine's encrypted mounts.
 *
 * Environment variables (passthrough from Docker — manifest whitelist only):
 *   RATLS_CERT_PATH    - RA-TLS certificate path (public directory)
 *   SGX_HTTP_PORT      - HTTP server port (default 3000)
 *   SYNC_NODES         - comma-separated WSS addresses of peer nodes (optional)
 *   SYNC_LISTEN_PORT   - WSS sync server listening port (default 3307)
 *   CONTRACT_RPC_URL   - blockchain RPC endpoint (required for normal ops)
 *   CONTRACT_CHAIN_ID  - blockchain chain ID (required)
 *   CONTRACT_ADDRESS   - WalletTrustContract address (required)
 *   CONTRACT_RPC_TLS_CA_CERT - RPC server TLS CA certificate (base64, for TLS verification)
 *   PROXY_API_KEY      - Intel PCCS API key (sensitive)
 *
 * .env loading is disabled — dotenv is not imported, and .env is NOT in
 * sgx.allowed_files. All env vars must come via `docker run -e ...`.
 */
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { generateRaTlsCertificate } from '@xnetx/sgx-ra-tls-verify';

/**
 * Gramine-specific quote producer.
 * Writes user_report_data to Gramine pseudo-file, reads quote back.
 * Throws when the attestation device is unavailable (non-SGX environment).
 */
async function gramineProduceQuote(reportDataBytes) {
    const userReportData = Buffer.alloc(64);
    Buffer.from(reportDataBytes).copy(userReportData, 0);
    // 证明设备不可用时直接抛错（生产环境预期 SGX 必然存在，不做降级）：
    // 由上层捕获后终止启动。模拟器镜像在构建期打桩替换本函数（见
    // test-integration/sim-stub.cjs 与 Dockerfile 的 SGX_MODE 构建参数）。
    fs.writeFileSync('/dev/attestation/user_report_data', userReportData);
    return fs.readFileSync('/dev/attestation/quote');
}

const cert_path = "/app/sgx-enclave/ratls-cert.pem";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

console.log('[SGX-Enclave Launcher] ====================================');
console.log('[SGX-Enclave Launcher] SGX Wallet Enclave (Gramine)');
console.log('[SGX-Enclave Launcher] ====================================');

// ---------------------------------------------------------------
// 1. Generate RA-TLS certificate (replaces gramine-ratls binary)
// ---------------------------------------------------------------
const ratlsCertPath = process.env.RATLS_CERT_PATH || cert_path;

try {
    console.log('[SGX-Enclave Launcher] Generating RA-TLS certificate...');
    const result = await generateRaTlsCertificate({
        produceQuote: gramineProduceQuote,
        subjectCommonName: 'SGX RA-TLS',
        validityDays: 365,
    });
    fs.writeFileSync(ratlsCertPath, result.certPem);
    if (result.hasQuote) {
        console.log('[SGX-Enclave Launcher] RA-TLS certificate generated with SGX quote');
    } else {
        console.log('[SGX-Enclave Launcher] RA-TLS certificate generated (no SGX quote — non-SGX environment)');
    }
    // Store private key in global memory — never written to disk
    global.__ratlsPrivateKeyPem = result.keyPem;
    console.log('[SGX-Enclave Launcher] Private key stored in memory (not written to disk)');
} catch (err) {
    console.error('[SGX-Enclave Launcher] Failed to generate RA-TLS certificate:', err);
    process.exit(1);
}

// Verify certificate was written
if (!fs.existsSync(ratlsCertPath)) {
    console.error(`[SGX-Enclave Launcher] RA-TLS cert not found after generation: ${ratlsCertPath}`);
    process.exit(1);
}
// 把实际证书路径写回环境变量：index.js 只认 RATLS_CERT_PATH，未透传时它会
// 误判 RA-TLS 不可用并让同步退化。由生成方（本启动器）回填，保证两者一致。
process.env.RATLS_CERT_PATH = ratlsCertPath;
console.log(`[SGX-Enclave Launcher] RA-TLS cert: ${ratlsCertPath}`);
console.log('[SGX-Enclave Launcher] RA-TLS key:  in-memory only');

// ---------------------------------------------------------------
// 2. Log configuration status
// ---------------------------------------------------------------
// SQLITE_DB_PATH is hardcoded in constants.js (/app/sgx-enclave/wallet/sgx_wallet.db)
console.log('[SGX-Enclave Launcher] SQLite DB: /app/sgx-enclave/wallet/sgx_wallet.db (hardcoded)');

if (process.env.SYNC_NODES) {
    console.log(`[SGX-Enclave Launcher] SYNC_NODES=${process.env.SYNC_NODES}`);
} else {
    console.log('[SGX-Enclave Launcher] SYNC_NODES not set — single node mode');
}

if (process.env.CONTRACT_RPC_URL) {
    console.log(`[SGX-Enclave Launcher] CONTRACT_RPC_URL configured`);
} else {
    console.log('[SGX-Enclave Launcher] CONTRACT_RPC_URL not set — contract config will be unavailable');
}

// ---------------------------------------------------------------
// 3. Run sgx-enclave business logic (dynamic import)
// ---------------------------------------------------------------
// Dynamic import executes sgx-enclave/index.js in the same V8 isolate.
// index.js calls main().catch(...) which starts the HTTP server async.
// SQLite runs in-process, WSS sync is built-in — no child processes.
console.log('[SGX-Enclave Launcher] Starting sgx-enclave business logic...');

try {
    await import('./index.js');
} catch (err) {
    console.error('[SGX-Enclave Launcher] Failed to load sgx-enclave:', err);
    process.exit(1);
}

// ---------------------------------------------------------------
// 4. Process lifecycle
// ---------------------------------------------------------------
// sgx-enclave/index.js registers its own SIGTERM/SIGINT handlers
// which call process.exit(0). Since we share the same process,
// that exits everything. The OS cleans up all file handles.
process.on('exit', (code) => {
    console.log(`[SGX-Enclave Launcher] Process exiting (code=${code})`);
});
