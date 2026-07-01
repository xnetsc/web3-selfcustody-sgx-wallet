#!/usr/bin/env node
/**
 * SGX Enclave Integration Test
 *
 * Tests all HTTP API endpoints with real secp256k1 + P256 signatures.
 *
 * Architecture:
 *   sgx-enclave - SQLite in-process DB, HTTP API
 *
 * Run: node run-all-tests.mjs
 */

import { ethers } from 'ethers';
import crypto from 'crypto';
import http from 'http';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import cborPkg from 'cbor';
const { encode: cborEncode } = cborPkg;

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ============================================================
// Contract test helpers (ethers.js direct RPC, no Hardhat)
// ============================================================

/**
 * 读取合约测试环境变量文件（由 setup-contract.sh 生成）
 * @returns {{ contractAddress: string, rpcUrl: string, chainId: number, hardhatPid: number } | null}
 */
function loadContractEnv() {
  const envFile = path.join(__dirname, '.env.contract');
  if (!fs.existsSync(envFile)) return null;
  const lines = fs.readFileSync(envFile, 'utf8').split('\n');
  const env = {};
  for (const line of lines) {
    const m = line.match(/^(\w+)=(.*)$/);
    if (m) env[m[1]] = m[2].trim();
  }
  if (!env.CONTRACT_ADDRESS || !env.CONTRACT_RPC_URL) return null;
  return {
    contractAddress: env.CONTRACT_ADDRESS,
    rpcUrl: env.CONTRACT_RPC_URL,
    chainId: parseInt(env.CONTRACT_CHAIN_ID || '31337', 10),
    hardhatPid: parseInt(env.HARDHAT_PID || '0', 10),
  };
}

/**
 * 停止 Hardhat 节点
 */
function stopHardhatNode() {
  const envFile = path.join(__dirname, '.env.contract');
  if (!fs.existsSync(envFile)) return;
  const lines = fs.readFileSync(envFile, 'utf8').split('\n');
  for (const line of lines) {
    const m = line.match(/^HARDHAT_PID=(\d+)$/);
    if (m) {
      const pid = parseInt(m[1], 10);
      if (pid > 0) {
        try {
          process.kill(pid, 'SIGTERM');
          console.log(`[Cleanup] Hardhat node stopped (PID=${pid})`);
        } catch {}
      }
    }
  }
  try { fs.unlinkSync(envFile); } catch {}
  const pidFile = path.join(__dirname, '.hardhat.pid');
  try { fs.unlinkSync(pidFile); } catch {}
}

/**
 * WalletTrustContract ABI（仅包含测试所需的函数）
 */
const WALLET_TRUST_CONTRACT_ABI = [
  // 配置管理
  'function updateCodeRepository(string calldata _codeRepository) external',
  'function updateRuntimeParams(string calldata _runtimeParams) external',
  'function getCodeRepository() external view returns (string)',
  'function getRuntimeParams() external view returns (string)',
  'function getPublicInfo() external view returns (string, string, tuple(bytes32 mrenclave, bytes32 mrsigner, uint16 isvprodid, uint16 isvsvn, string description)[])',
  // 平台白名单
  'function addPlatformAddress(address _addr) external',
  'function removePlatformAddress(address _addr) external',
  'function isPlatformWhitelisted(address _addr) external view returns (bool)',
  'function getPlatformWhitelist() external view returns (address[])',
  // Enclave 白名单
  'function addEnclaveIdentity(bytes32 _mrenclave, bytes32 _mrsigner, uint16 _isvprodid, uint16 _isvsvn, string calldata _description) external',
  'function removeEnclaveIdentity(bytes32 _mrenclave) external',
  'function isEnclaveWhitelisted(bytes32 _mrenclave) external view returns (bool)',
  'function getEnclaveWhitelist() external view returns (tuple(bytes32 mrenclave, bytes32 mrsigner, uint16 isvprodid, uint16 isvsvn, string description)[])',
  // 授权撤销
  'function revokeAuthorization(string calldata _userId, string calldata _authorizationId, address _grantee, bytes32 _passkeyPubKeyX, bytes32 _passkeyPubKeyY, bytes32 _signatureR, bytes32 _signatureS) external',
  'function isAuthorizationRevoked(string calldata _userId, string calldata _authorizationId) external view returns (bool)',
  'function getRevokedAuthorizations(string calldata _userId) external view returns (tuple(string authorizationId, address grantee, bytes32 passkeyPubKeyX, bytes32 passkeyPubKeyY, uint256 revokedAt)[])',
  // Passkey 恢复
  'function setPasskeyRecovery(string calldata _userId, bytes32 _newPubKeyHash, bytes32 _oldPubKeyHash, string calldata _uuid, string calldata _memo) external',
  'function removePasskeyRecovery(string calldata _userId, bytes32 _newPubKeyHash) external',
  'function getPasskeyRecovery(string calldata _userId, bytes32 _newPubKeyHash) external view returns (bytes32 oldPubKeyHash, string uuid, string memo, uint256 createdAt)',
  'function passkeyRecoveryExists(string calldata _userId, bytes32 _newPubKeyHash) external view returns (bool)',
  // 事件
  'event CodeRepositoryUpdated(string codeRepository)',
  'event RuntimeParamsUpdated(string runtimeParams)',
  'event PlatformAddressAdded(address indexed addr)',
  'event PlatformAddressRemoved(address indexed addr)',
  'event EnclaveIdentityAdded(bytes32 mrenclave, bytes32 mrsigner, string description)',
  'event EnclaveIdentityRemoved(bytes32 mrenclave)',
  'event AuthorizationRevoked(string userId, string authorizationId, address grantee, bytes32 passkeyPubKeyX, bytes32 passkeyPubKeyY)',
];

/**
 * 对 P256 消息签名（用于合约 revokeAuthorization）
 * 消息格式：sha256(abi.encodePacked(userId, authorizationId, grantee))
 * 签名格式：IEEE P1363（r || s，各 32 字节），s 已规范化（low-s）
 */
function signP256ForRevocation(privateKey, userId, authorizationId, granteeAddress) {
  // 复现合约内的 sha256(abi.encodePacked(userId, authorizationId, grantee))
  const packed = ethers.solidityPacked(
    ['string', 'string', 'address'],
    [userId, authorizationId, granteeAddress]
  );
  const msgBytes = Buffer.from(ethers.getBytes(packed));

  const signer = crypto.createSign('SHA256');
  signer.update(msgBytes);
  const derSig = signer.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' });

  const r = '0x' + derSig.subarray(0, 32).toString('hex');
  let sBig = BigInt('0x' + derSig.subarray(32, 64).toString('hex'));
  // low-s 规范化
  const N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
  const HALF_N = N / 2n;
  if (sBig > HALF_N) sBig = N - sBig;
  const s = '0x' + sBig.toString(16).padStart(64, '0');
  return { r, s };
}

// Parse command line arguments
const KEEP_CONTAINER = process.argv.includes('--keep');
const CLEANUP_NETWORK_ONLY = process.argv.includes('--cleanup-network-only');
const FORCE_REBUILD = process.argv.includes('--force');

if (KEEP_CONTAINER) {
  console.log('[Setup] KEEP mode: containers will NOT be removed after tests');
} else if (CLEANUP_NETWORK_ONLY) {
  console.log('[Setup] CLEANUP-NETWORK-ONLY mode: only network will be removed, containers preserved');
}

/**
 * RSA PKCS1 v1.5 私钥解密（兼容 Node.js 22+）
 * Node.js 22 因 CVE-2023-46809 移除了 RSA_PKCS1_PADDING 用于 privateDecrypt，
 * 此处通过 openssl 命令行实现兼容。
 */
function rsaPkcs1Decrypt(privateKeyObj, encryptedBuffer) {
  const tmpDir = os.tmpdir();
  const ts = Date.now();
  const keyPath = path.join(tmpDir, `rsa-test-key-${ts}.pem`);
  const encPath = path.join(tmpDir, `rsa-test-enc-${ts}.bin`);
  try {
    fs.writeFileSync(keyPath, privateKeyObj.export({ type: 'pkcs8', format: 'pem' }));
    fs.writeFileSync(encPath, encryptedBuffer);
    return execSync(
      `openssl pkeyutl -decrypt -inkey "${keyPath}" -in "${encPath}" -pkeyopt rsa_padding_mode:pkcs1`,
      { stdio: 'pipe' }
    );
  } finally {
    try { fs.unlinkSync(keyPath); } catch (_) {}
    try { fs.unlinkSync(encPath); } catch (_) {}
  }
}

// ============================================================
// Config
// ============================================================
const DOCKER_NETWORK    = 'test-sgx-net';
const ENCLAVE_CONTAINER = 'test-sgx-enclave';

const ENCLAVE_HTTP_PORT = 3000;


// SGX mode detection (from environment or auto-detect)
const SGX_MODE = process.env.SGX_MODE || (
    (() => {
        try {
            execSync('ls -e /dev/sgx_enclave 2>/dev/null', { stdio: 'ignore' });
            return 'sgx';
        } catch {
            return 'direct';
        }
    })()
);
console.log(`[Setup] SGX_MODE: ${SGX_MODE}`);

// ============================================================
// 1. Key generation (real keypairs)
// ============================================================

const platformWallet = ethers.Wallet.createRandom();
const PLATFORM_ADDRESS = platformWallet.address;

const p256KeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const p256PublicDer = p256KeyPair.publicKey.export({ type: 'spki', format: 'der' });
const p256Uncompressed = p256PublicDer.subarray(26);
const PUBLIC_KEY_X = p256Uncompressed.subarray(1, 33);
const PUBLIC_KEY_Y = p256Uncompressed.subarray(33, 65);

// 构建 COSE 格式公钥（用于 passkey/import）
// COSE Map: { 1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y }
const PUBLIC_KEY_COSE = cborEncode(new Map([
  [1, 2],
  [3, -7],
  [-1, 1],
  [-2, PUBLIC_KEY_X],
  [-3, PUBLIC_KEY_Y],
]));

console.log(`[Setup] Platform address: ${PLATFORM_ADDRESS}`);
console.log(`[Setup] Platform private key: ${platformWallet.privateKey}`);
console.log(`[Setup] P256 publicKeyX: ${PUBLIC_KEY_X.toString('hex')}`);
console.log(`[Setup] P256 publicKeyY: ${PUBLIC_KEY_Y.toString('hex')}`);
console.log(`[Setup] P256 publicKeyCose (base64url): ${PUBLIC_KEY_COSE.toString('base64url').substring(0, 20)}...`);

// ============================================================
// 2. Helper functions
// ============================================================

async function signPayload(payloadStr) {
  return platformWallet.signMessage(payloadStr);
}

async function buildRequest(payloadObj) {
  const payload = JSON.stringify(payloadObj);
  const platformSignature = await signPayload(payload);
  return { payload, platformSignature };
}

function toBase64URL(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function derToRS(derSig) {
  let offset = 0;

  if (derSig[offset++] !== 0x30) throw new Error('Invalid DER');
  offset++;

  if (derSig[offset++] !== 0x02) throw new Error('Invalid DER');
  let rLen = derSig[offset++];
  let r = derSig.slice(offset, offset + rLen);
  offset += rLen;

  if (derSig[offset++] !== 0x02) throw new Error('Invalid DER');
  let sLen = derSig[offset++];
  let s = derSig.slice(offset, offset + sLen);

  if (r.length < 32) r = Buffer.concat([Buffer.alloc(32 - r.length), r]);
  if (s.length < 32) s = Buffer.concat([Buffer.alloc(32 - s.length), s]);

  return Buffer.concat([r, s]);
}

/**
 * 构建 WebAuthn 注册响应（attestationObject + clientDataJSON）
 * 用于 passkey/register/complete 接口
 *
 * @param {string} challenge - 服务器生成的挑战值（base64url 编码）
 * @param {Object} opts
 * @param {string} opts.rpId - RP ID（默认 'localhost'）
 * @param {string} opts.origin - Origin（默认 'https://localhost'）
 * @param {Buffer} opts.credentialId - 凭证 ID
 * @param {Buffer} opts.publicKeyX - P256 公钥 X 坐标（32 字节）
 * @param {Buffer} opts.publicKeyY - P256 公钥 Y 坐标（32 字节）
 * @returns {{ id, rawId, response: { attestationObject, clientDataJSON }, type }}
 */
function makeWebAuthnRegistrationResponse(challenge, {
  rpId = 'localhost',
  origin = 'https://localhost',
  credentialId = crypto.randomBytes(32),
  publicKeyX = PUBLIC_KEY_X,
  publicKeyY = PUBLIC_KEY_Y,
} = {}) {
  // 1. 构建 COSE 格式公钥
  const cosePublicKey = cborEncode(new Map([
    [1, 2],    // kty: EC2
    [3, -7],   // alg: ES256
    [-1, 1],   // crv: P-256
    [-2, publicKeyX],  // x
    [-3, publicKeyY],  // y
  ]));

  // 2. 构建 authData
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  const flags = Buffer.from([0x41]); // UP=0x01, AT=0x40 (包含 attestedCredentialData)
  const signCount = Buffer.alloc(4); // 0
  const aaguid = Buffer.alloc(16);   // 全零
  const credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(credentialId.length);

  const authData = Buffer.concat([
    rpIdHash,
    flags,
    signCount,
    aaguid,
    credIdLen,
    credentialId,
    cosePublicKey,
  ]);

  // 3. 构建 attestationObject（CBOR 编码）
  const attestationObject = cborEncode({
    fmt: 'none',
    attStmt: {},
    authData,
  });

  // 4. 构建 clientDataJSON
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: 'webauthn.create',
    challenge,
    origin,
    crossOrigin: false,
  }));

  const credIdBase64url = toBase64URL(credentialId);

  return {
    id: credIdBase64url,
    rawId: credIdBase64url,
    response: {
      attestationObject: toBase64URL(attestationObject),
      clientDataJSON: toBase64URL(clientDataJSON),
    },
    type: 'public-key',
  };
}

function makeWebAuthnSignature(challenge, {
  rpId = 'localhost',
  origin = 'https://localhost',
  signCount=null,                             // null 表示自动递增
  privateKey=p256KeyPair.privateKey,          // ✅ 必须是注册时对应的私钥
  credentialId=state.credentialId,            // ✅ 必须和注册一致（使用 state.credentialId）
} = {}) {

  // 自动递增 signCount（WebAuthn 要求单调递增）
  if (signCount === null) {
    state.signCount = (state.signCount || 0) + 1;
    signCount = state.signCount;
  }

  // ✅ rpIdHash
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();

  // ✅ flags：只设 UP
  const flags = Buffer.from([0x01]);

  // ✅ signCount 必须递增
  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32BE(signCount);

  const authenticatorData = Buffer.concat([
    rpIdHash,
    flags,
    counterBuf,
  ]);

  // ✅ challenge 必须 base64url
  const challengeB64 = typeof challenge === 'string'
    ? challenge
    : toBase64URL(challenge+"");

  const clientDataJSON = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge: challengeB64,
    origin,
    crossOrigin: false,
  }));

  const clientDataHash = crypto
    .createHash('sha256')
    .update(clientDataJSON)
    .digest();

  const signedData = Buffer.concat([
    authenticatorData,
    clientDataHash,
  ]);

  // ✅ 使用 DER 格式签名（@simplewebauthn/server 期望 DER 格式）
  const derSig = crypto
    .createSign('SHA256')
    .update(signedData)
    .end()
    .sign(privateKey);

  // credentialId 可能是字符串（base64url）或 Buffer
  const credIdBase64url = typeof credentialId === 'string'
    ? credentialId
    : toBase64URL(credentialId);

  return {
    id: credIdBase64url,
    rawId: credIdBase64url,
    type: 'public-key',
    response: {
      authenticatorData: toBase64URL(authenticatorData),
      clientDataJSON: toBase64URL(clientDataJSON),
      signature: toBase64URL(derSig),  // DER 格式（@simplewebauthn/server 会解析）
      userHandle: null,
    },
  };
}

function httpPost(apiPath, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({
      hostname: '127.0.0.1',
      port: ENCLAVE_HTTP_PORT,
      path: apiPath,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, (res) => {
      let chunks = '';
      res.on('data', (c) => (chunks += c));
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(chunks); } catch { parsed = chunks; }
        const result = { status: res.statusCode, body: parsed };
        // Auto-log non-200 responses for debugging
        if (res.statusCode !== 200) {
          const errMsg = typeof parsed === 'object' ? (parsed.error || JSON.stringify(parsed)) : parsed;
          console.log(`  [debug] ${apiPath} → ${res.statusCode}: ${errMsg}`);
        }
        resolve(result);
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

/**
 * 解析统一远程证明响应格式
 * 200 响应格式: { attestationQuote: "hex...", data: "JSON字符串" }
 * 非200响应格式: { error: "..." }
 *
 * @param {Object} res - httpPost 返回的 { status, body }
 * @returns {{ attestationQuote: string, data: Object }|null} 解析后的业务数据，非200返回 null
 */
function parseAttestationResponse(res) {
  if (res.status !== 200) return null;
  if (typeof res.body !== 'object' || typeof res.body.data !== 'string') return null;
  try {
    return {
      attestationQuote: res.body.attestationQuote || '',
      data: JSON.parse(res.body.data),
    };
  } catch {
    return null;
  }
}

async function waitForHTTP(port, host = '127.0.0.1', timeoutMs = 120000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const req = http.request({ hostname: host, port, path: '/', method: 'GET', timeout: 2000 }, (res) => {
          res.resume();
          resolve();
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
        req.end();
      });
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw new Error(`HTTP port ${port} not ready after ${timeoutMs}ms`);
}




// ============================================================
// 3. Test counters
// ============================================================
let passed = 0;
let failed = 0;
let skipped = 0;
const results = [];

function assert(condition, testName, detail = '') {
  if (condition) {
    passed++;
    results.push({ name: testName, status: 'PASS' });
    console.log(`  PASS ${testName}`);
  } else {
    failed++;
    results.push({ name: testName, status: 'FAIL', detail });
    console.log(`  FAIL ${testName} ${detail ? '-- ' + detail : ''}`);
  }
}

function skip(testName, reason) {
  skipped++;
  results.push({ name: testName, status: 'SKIP', detail: reason });
  console.log(`  SKIP ${testName} -- ${reason}`);
}

// ============================================================
// 4. Docker container management
// ============================================================

function dockerCmd(cmd) {
  try {
    return execSync(cmd, { stdio: 'pipe', timeout: 30000 }).toString().trim();
  } catch (e) {
    return e.stdout ? e.stdout.toString().trim() : '';
  }
}

function cleanupContainers() {
  console.log('[Cleanup] Removing containers...');
  for (const c of [ENCLAVE_CONTAINER]) {
    dockerCmd(`docker rm -f ${c} 2>/dev/null`);
  }
}

function cleanupNetwork() {
  console.log('[Cleanup] Removing network...');
  dockerCmd(`docker network rm ${DOCKER_NETWORK} 2>/dev/null`);
}

function cleanupEnv() {
  // Clean up temp .env.test
  const envTestPath = path.join(__dirname, '.env.test');
  if (fs.existsSync(envTestPath)) fs.unlinkSync(envTestPath);
}

function cleanup() {
  if (KEEP_CONTAINER) {
    console.log('[Cleanup] Skipping cleanup (KEEP mode)');
    return;
  }
  if (CLEANUP_NETWORK_ONLY) {
    console.log('[Cleanup] Removing network only (CLEANUP-NETWORK-ONLY mode)...');
    cleanupNetwork();
    cleanupEnv();
    return;
  }
  console.log('[Cleanup] Removing containers and network...');
  cleanupContainers();
  cleanupNetwork();
  cleanupEnv();
}

function setupDockerNetwork() {
  console.log('[Setup] Creating Docker network...');
  dockerCmd(`docker network rm ${DOCKER_NETWORK} 2>/dev/null`);
  execSync(`docker network create ${DOCKER_NETWORK}`, { stdio: 'pipe' });
  console.log(`[Setup] Network ${DOCKER_NETWORK} created`);
}

function runScript(scriptName, args = [], env = {}) {
  const scriptPath = path.join(__dirname, scriptName);
  const cmd = [scriptPath, ...args].join(' ');
  const mergedEnv = {
    ...process.env,
    DOCKER_NETWORK,
    ENCLAVE_CONTAINER,
    ENCLAVE_HTTP_PORT: String(ENCLAVE_HTTP_PORT),
    ...env,
  };
  execSync(cmd, { stdio: 'inherit', env: mergedEnv, timeout: 600000 });
}

function buildImages() {
  console.log('[Setup] Building Docker image (skip if already exists)...');
  const args = FORCE_REBUILD ? ['--force'] : [];
  runScript('build-sgx-enclave.sh', args);
}

function startEnclaveContainer(contractEnvOverride = {}) {
  console.log('[Setup] Starting sgx-enclave...');
  runScript('start-enclave.sh', [PLATFORM_ADDRESS], contractEnvOverride);
  console.log(`[Setup] Enclave container started: ${ENCLAVE_CONTAINER} (PLATFORM_WHITELIST=${PLATFORM_ADDRESS})`);
}

function showContainerLogs(containerName, lines = 80) {
  try {
    const logs = execSync(`docker logs --tail ${lines} ${containerName} 2>&1`, {
      stdio: 'pipe', timeout: 5000,
    }).toString();
    console.log(`\n--- ${containerName} logs (last ${lines} lines) ---`);
    console.log(logs);
    console.log(`--- end ${containerName} logs ---\n`);
  } catch {}
}

// ============================================================
// 5. API endpoint tests
// ============================================================

// credentialId 使用随机 Buffer，base64url 编码后作为字符串
const CREDENTIAL_ID_BUF = crypto.randomBytes(32);
const CREDENTIAL_ID2_BUF = crypto.randomBytes(32);

const state = {
  userId: null,
  credentialId: CREDENTIAL_ID_BUF.toString('base64url'),
  credentialIdBuf: CREDENTIAL_ID_BUF,
  walletId: null,
  walletAddress: null,
  authorizationId: `auth-${crypto.randomBytes(8).toString('hex')}`,
  challenge: null,
  importSessionId: null,
  exportSessionId: null,
  credentialId2: CREDENTIAL_ID2_BUF.toString('base64url'),
  credentialId2Buf: CREDENTIAL_ID2_BUF,
  importEnclavePublicKey: null,
  // RSA flow state
  rsaPrivateKey: null,
  rsaImportSessionId: null,
  rsaEncryptedAESKey: null,
  // WebAuthn sign counter (must be monotonically increasing)
  signCount: 0,
};

async function testEnclaveInfo() {
  console.log('\n=== 1. POST /api/enclave/info ===');
  const res = await httpPost('/api/enclave/info', {});
  assert(res.status === 200, 'enclave/info returns 200');
  assert(typeof res.body.data === 'string', 'enclave/info data is string');
  assert(typeof res.body.attestationQuote === 'string', 'enclave/info has attestationQuote');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data, 'enclave/info has runtimeParams');
}

async function testPasskeyRegisterChallenge() {
  console.log('\n=== 2. POST /api/challenge (purpose=register) ===');
  const body = await buildRequest({ purpose: 'register', userId: `user-${crypto.randomBytes(8).toString('hex')}` });
  const res = await httpPost('/api/challenge', body);
  assert(res.status === 200, 'register/challenge returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed !== null, 'register/challenge has valid attestation response');
  assert(parsed && parsed.data && parsed.data.challenge, 'register/challenge has challenge');
  assert(parsed && parsed.data && parsed.data.userId, 'register/challenge has userId');
  assert(typeof res.body.attestationQuote === 'string', 'register/challenge has attestationQuote');

  if (parsed && parsed.data) {
    state.userId = parsed.data.userId;
    state.challenge = parsed.data.challenge;
  }
}

async function testPasskeyRegisterComplete() {
  console.log('\n=== 3. POST /api/passkey/register/complete ===');
  if (!state.challenge) {
    assert(false, 'register/complete requires challenge from step 2');
    return;
  }

  // 使用服务器生成的 challenge 构建 WebAuthn 注册响应
  // credentialId 使用 state.credentialIdBuf（32 字节随机 Buffer）
  const attestationResponse = makeWebAuthnRegistrationResponse(state.challenge, {
    credentialId: state.credentialIdBuf,
    publicKeyX: PUBLIC_KEY_X,
    publicKeyY: PUBLIC_KEY_Y,
  });

  // attestationResponse.id 是 credentialIdBuf 的 base64url 编码，与 state.credentialId 一致
  // 因为 state.credentialId = CREDENTIAL_ID_BUF.toString('base64url')

  const body = await buildRequest({
    userId: state.userId,
    attestationResponse,
  });
  const res = await httpPost('/api/passkey/register/complete', body);
  assert(res.status === 200, 'register/complete returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && parsed.data.userId === state.userId, 'register/complete userId matches');
  assert(parsed && parsed.data && parsed.data.credentialId === state.credentialId, 'register/complete credentialId matches');
  assert(parsed && parsed.data && parsed.data.isFirstPasskey === true, 'register/complete isFirstPasskey=true');
}

async function testPasskeyRegisterExistingUser() {
  console.log('\n=== 3b. POST /api/passkey/register/complete (existing user, register_passkey) ===');
  // 测试已有用户添加新 Passkey 时，必须提供现有 Passkey 的 WebAuthn 签名
  // 新的安全流程：existingWebauthnSignature 的 challenge = SHA256(challenge1 + newCredentialId + newPublicKeyCose)
  // 生成第三个 P256 密钥对（用于新 Passkey）
  const p256_3 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const der3 = p256_3.publicKey.export({ type: 'spki', format: 'der' });
  const unc3 = der3.subarray(26);
  const pkx3 = unc3.subarray(1, 33);
  const pky3 = unc3.subarray(33, 65);
  const credentialId3Buf = crypto.randomBytes(32);
  const credentialId3 = credentialId3Buf.toString('base64url');

  // 1. 获取 register_passkey 挑战值（新流程：只传 userId + credentialId，不传 userIntentJson）
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'register_passkey',
  }));
  const challengeParsed = parseAttestationResponse(challengeRes);
  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    assert(false, 'register_passkey failed to get challenge');
    return;
  }
  const challenge1 = challengeParsed.data.challenge;

  // 2. 用 challenge1 创建新 Passkey（WebAuthn 注册仪式）
  // challenge1 是纯随机数，直接作为 WebAuthn 注册 challenge
  const attestationResponse = makeWebAuthnRegistrationResponse(challenge1, {
    credentialId: credentialId3Buf,
    publicKeyX: pkx3,
    publicKeyY: pky3,
  });

  // 3. 计算新 Passkey 的 COSE 格式公钥（base64url），用于计算 existingChallenge
  // 注意：这里需要与服务端提取的 publicKeyCose 完全一致
  // 服务端从 attestationObject 中提取，客户端需要用相同的 COSE 格式
  const newPublicKeyCose = cborEncode(new Map([
    [1, 2],    // kty: EC2
    [3, -7],   // alg: ES256
    [-1, 1],   // crv: P-256
    [-2, pkx3],  // x
    [-3, pky3],  // y
  ]));
  const newPublicKeyCoseBase64url = newPublicKeyCose.toString('base64url');

  // 4. 计算 existingChallenge = SHA256(challenge1 + newCredentialId + newPublicKeyCoseBase64url)
  const existingChallengeHash = crypto.createHash('sha256')
    .update(challenge1 + credentialId3 + newPublicKeyCoseBase64url)
    .digest('base64url');

  // 5. 用已有 Passkey 对 existingChallenge 签名
  const existingWebauthnSignature = makeWebAuthnSignature(existingChallengeHash);

  // 6. 提交注册请求
  const body = await buildRequest({
    userId: state.userId,
    attestationResponse,
    existingCredentialId: state.credentialId,
    existingWebauthnSignature,
  });
  const res = await httpPost('/api/passkey/register/complete', body);
  assert(res.status === 200, 'register_passkey returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && parsed.data.isFirstPasskey === false, 'register_passkey isFirstPasskey=false');
  assert(parsed && parsed.data && parsed.data.credentialId === credentialId3, 'register_passkey credentialId matches');
  console.log(`  [info] register_passkey success: credentialId=${parsed?.data?.credentialId}`);

  // 7. 测试：已有用户不提供现有 Passkey 签名时，应该被拒绝
  // 需要重新获取挑战值（因为上面的挑战值已被消费）
  const challengeRes2 = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'register_passkey',
  }));
  const challengeParsed2 = parseAttestationResponse(challengeRes2);
  if (challengeParsed2 && challengeParsed2.data && challengeParsed2.data.challenge) {
    const challenge2 = challengeParsed2.data.challenge;
    const badBody = await buildRequest({
      userId: state.userId,
      attestationResponse: makeWebAuthnRegistrationResponse(challenge2, {
        credentialId: crypto.randomBytes(32),
        publicKeyX: pkx3,
        publicKeyY: pky3,
      }),
      // 故意不提供 existingCredentialId 和 existingWebauthnSignature
    });
    const badRes = await httpPost('/api/passkey/register/complete', badBody);
    assert(badRes.status !== 200, 'register_passkey without existing signature is rejected');
    console.log(`  [info] register_passkey without existing signature correctly rejected with status=${badRes.status}`);
  }
}

async function testPasskeyImport() {
  console.log('\n=== 4. POST /api/passkey/register/complete (existing user, register credentialId2) ===');
  // passkey/import 接口已删除（平台侧批量导入无需用户签名，不安全）
  // 改用 register_passkey 流程注册 credentialId2，供后续 passkey/delete 测试使用
  const p256_2 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const der2 = p256_2.publicKey.export({ type: 'spki', format: 'der' });
  const unc2 = der2.subarray(26);
  const pkx2 = unc2.subarray(1, 33);
  const pky2 = unc2.subarray(33, 65);

  // 1. 获取 register_passkey 挑战值
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'register_passkey',
  }));
  const challengeParsed = parseAttestationResponse(challengeRes);
  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    assert(false, 'passkey/import (register credentialId2): failed to get challenge');
    return;
  }
  const challenge1 = challengeParsed.data.challenge;

  // 2. 构建新 Passkey 的注册响应
  const attestationResponse = makeWebAuthnRegistrationResponse(challenge1, {
    credentialId: state.credentialId2Buf,
    publicKeyX: pkx2,
    publicKeyY: pky2,
  });

  // 3. 计算 existingChallenge = SHA256(challenge1 + newCredentialId + newPublicKeyCoseBase64url)
  const newPublicKeyCose2 = cborEncode(new Map([
    [1, 2], [3, -7], [-1, 1], [-2, pkx2], [-3, pky2],
  ]));
  const newPublicKeyCose2Base64url = newPublicKeyCose2.toString('base64url');
  const existingChallengeHash = crypto.createHash('sha256')
    .update(challenge1 + state.credentialId2 + newPublicKeyCose2Base64url)
    .digest('base64url');

  // 4. 用已有 Passkey 签名
  const existingWebauthnSignature = makeWebAuthnSignature(existingChallengeHash);

  // 5. 提交注册请求
  const body = await buildRequest({
    userId: state.userId,
    attestationResponse,
    existingCredentialId: state.credentialId,
    existingWebauthnSignature,
  });
  const res = await httpPost('/api/passkey/register/complete', body);
  assert(res.status === 200, 'passkey/import returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && parsed.data.isFirstPasskey === false, 'passkey/import isFirstPasskey=false (user exists)');
  console.log(`  [info] credentialId2 registered: ${parsed?.data?.credentialId}`);
}

async function testPasskeyList() {
  console.log('\n=== 5. POST /api/passkey/list ===');
  const body = await buildRequest({ userId: state.userId });
  const res = await httpPost('/api/passkey/list', body);
  assert(res.status === 200, 'passkey/list returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && Array.isArray(parsed.data.passkeys), 'passkey/list has passkeys array');
  // 注意：测试3b（register_passkey）已注册第3个 Passkey，所以这里期望 >= 2
  assert(parsed && parsed.data && parsed.data.passkeys.length >= 2, 'passkey/list has >= 2 passkeys');
  console.log(`  [info] passkey count: ${parsed?.data?.passkeys?.length}`);
}

async function testWalletCreate() {
  console.log('\n=== 6. POST /api/wallet/create ===');
  // 构造 userIntentJson（用户意图，必须与实际业务参数一致）
  const walletCreateChains = [{ chainId: 1, coinType: 60 }];
  const walletCreateMnemonicStrength = 128;
  const walletCreateIntentJson = JSON.stringify({
    purpose: 'wallet_create',
    userId: state.userId,
    chains: walletCreateChains,
    mnemonicStrength: walletCreateMnemonicStrength,
  });

  // 新流程：获取挑战值时只传 userId + credentialId，不传 userIntentJson
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'wallet_create',
  }));
  const challengeParsed = parseAttestationResponse(challengeRes);
  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    assert(false, 'wallet/create failed to get challenge');
    return;
  }
  const rawChallenge = challengeParsed.data.challenge;

  // 新流程：计算 intentHash = SHA256(rawChallenge + userIntentJson)，用 intentHash 签名
  const intentHash = computeIntentHash(rawChallenge, walletCreateIntentJson);
  const webauthnSignature = makeWebAuthnSignature(intentHash);

  // 新流程：业务请求中携带 rawChallenge + userIntentJson + webauthnSignature
  const body = await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    webauthnSignature,
    rawChallenge,
    userIntentJson: walletCreateIntentJson,
    chains: walletCreateChains,
    mnemonicStrength: walletCreateMnemonicStrength,
  });
  const res = await httpPost('/api/wallet/create', body);
  assert(res.status === 200, 'wallet/create returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && parsed.data.walletId, 'wallet/create has walletId');

  if (parsed && parsed.data) {
    state.walletId = parsed.data.walletId;
    if (parsed.data.addresses && parsed.data.addresses.length > 0) {
      state.walletAddress = parsed.data.addresses[0].address;
    }
  }
  console.log(`  [info] walletId=${state.walletId}, address=${state.walletAddress || 'N/A'}`);
}

async function testWalletList() {
  console.log('\n=== 7. POST /api/wallet/list ===');
  const body = await buildRequest({ userId: state.userId });
  const res = await httpPost('/api/wallet/list', body);
  assert(res.status === 200, 'wallet/list returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && Array.isArray(parsed.data.wallets), 'wallet/list has wallets array');
  assert(parsed && parsed.data && parsed.data.wallets.length >= 1, 'wallet/list has >= 1 wallet');
}

async function testWalletGet() {
  console.log('\n=== 8. POST /api/wallet/get ===');
  if (!state.walletId) { skip('wallet/get', 'no walletId'); return; }
  const body = await buildRequest({ userId: state.userId, walletId: state.walletId });
  const res = await httpPost('/api/wallet/get', body);
  assert(res.status === 200, 'wallet/get returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && parsed.data.walletId === state.walletId, 'wallet/get walletId matches');

  // 从 wallet/get 响应中提取地址
  const walletData = parsed?.data?.wallet;
  if (walletData && walletData.wallets && walletData.wallets.length > 0) {
    const firstLogicalWallet = walletData.wallets[0];
    if (firstLogicalWallet.addresses && firstLogicalWallet.addresses.length > 0) {
      state.walletAddress = firstLogicalWallet.addresses[0].address;
      console.log(`  [info] extracted walletAddress=${state.walletAddress} from wallet/get`);
    }
  }
}

async function testAuthChallenge() {
  console.log('\n=== 9. POST /api/challenge (purpose=authorize, should be rejected) ===');
  // 授权JSON的WebAuthn challenge由客户端自行计算：SHA256(authJson)，不依赖服务端挑战值
  const body = await buildRequest({
    purpose: 'authorize',
    userId: state.userId,
    credentialId: state.credentialId,
    authorizationId: state.authorizationId,
  });
  const res = await httpPost('/api/challenge', body);
  assert(res.status !== 200, 'auth/challenge with authorize purpose is rejected (not 200)');
  console.log(`  [info] authorize purpose correctly rejected with status=${res.status}`);
}

/**
 * 计算授权 JSON 字符串的 SHA256 哈希
 * 重要：直接对字符串计算哈希，不做任何 parse/stringify 转换
 * 这样才能保证客户端和服务端对同一字符串计算哈希，WebAuthn 验证才能通过
 * @param {string} authorizationJson - 授权 JSON 字符串（不含 webauthnSignature）
 * @returns {string} base64url 编码的 SHA256 哈希
 */
function computeAuthorizationHash(authorizationJson) {
  return crypto.createHash('sha256').update(authorizationJson).digest('base64url');
}

/**
 * 计算 intentHash = SHA256(rawChallenge + userIntentJson)
 * 客户端收到 rawChallenge 后，用此哈希作为 WebAuthn challenge 进行签名
 * @param {string} rawChallenge - 服务端生成的原始随机挑战值（base64url）
 * @param {string} userIntentJson - 用户意图的原始 JSON 字符串
 * @returns {string} base64url 编码的 SHA256 哈希
 */
function computeIntentHash(rawChallenge, userIntentJson) {
  return crypto.createHash('sha256').update(rawChallenge + userIntentJson).digest('base64url');
}

async function testTxSign() {
  console.log('\n=== 10. POST /api/tx/sign (Standard Mode) ===');
  if (!state.walletAddress) { skip('tx/sign', 'no wallet address'); return; }

  // 构造符合服务端期望的 authorizationJson 字符串（不含 webauthnSignature）
  // 重要：authorizationJson 是不含 webauthnSignature 的原始 JSON 字符串
  // 客户端对这个字符串计算 SHA256 哈希作为 WebAuthn challenge
  // 服务端对同一字符串计算哈希，与 WebAuthn challenge 比对
  const authorizationJson = JSON.stringify({
    userId: state.userId,
    authorizationId: state.authorizationId,
    grantee: [PLATFORM_ADDRESS],
    credentialId: state.credentialId,
    scope: {
      targetAddresses: [{ chainId: '1', address: '0x' + '00'.repeat(20) }],
      signingWallets: [{ chainId: '1', address: state.walletAddress }],
      tokenRestrictions: [{ chainId: '1', tokenAddress: '1_native' }],
      cumulativeLimits: {
        maxTxCount: 100,
        tokenLimits: { '1_native': '10000000000000000000' },
      },
    },
    timePolicy: {
      deadline: new Date(Date.now() + 86400 * 1000).toISOString(),
    },
    revocationPolicy: {
      allowContractUnavailable: true,
    },
    createdAt: new Date().toISOString(),
  });

  // 计算 authHash = SHA256(authorizationJson)，作为 WebAuthn challenge
  const authHash = computeAuthorizationHash(authorizationJson);
  const webauthnSignature = makeWebAuthnSignature(authHash);

  // 新接口格式：authorizationJson（字符串）和 webauthnSignature 分开传
  const body = await buildRequest({
    guid: crypto.randomUUID(),
    authorizationJson,       // ← 不含 webauthnSignature 的原始 JSON 字符串
    webauthnSignature,       // ← WebAuthn 签名（单独字段）
    transaction: {
      chainId: '1',
      fromAddress: state.walletAddress,
      toAddress: '0x' + '00'.repeat(20),
      value: '0',
      data: '0x',
      gasLimit: '21000',
      maxFeePerGas: '1000000000',
      maxPriorityFeePerGas: '1000000',
      nonce: 0,
      type: 2,               // ← EIP-1559 交易类型（必须提供）
      amount: '0',
      tokenAddress: '1_native',
    },
  });
  const res = await httpPost('/api/tx/sign', body);
  assert(res.status === 200, 'tx/sign returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed !== null, 'tx/sign has valid attestation response');
  if (parsed?.data?.success !== true) console.log(`  [debug] tx/sign failed: reason=${parsed?.data?.reason}, step=${parsed?.data?.step}`);
  assert(parsed && parsed.data && parsed.data.success === true, 'tx/sign success=true');
  assert(parsed && parsed.data && parsed.data.signedTransaction, 'tx/sign has signedTransaction');
  assert(parsed && parsed.data && parsed.data.txHash, 'tx/sign has txHash');
  assert(typeof res.body.attestationQuote === 'string', 'tx/sign has attestationQuote');
  console.log(`  [info] tx/sign success: txHash=${parsed?.data?.txHash}`);
}

async function testTxSignRawHex() {
  console.log('\n=== 10b. POST /api/tx/sign (RawTxHex Mode) ===');
  if (!state.walletAddress) { skip('tx/sign rawTxHex', 'no wallet address'); return; }

  // ERC20 transfer 数据（用于场景2/3/4）
  const receiverAddress = '0x1234567890123456789012345678901234567890';
  const paddedAddress = receiverAddress.substring(2).padStart(64, '0');
  const amount = '1000000000000000000'; // 1 token
  const paddedAmount = BigInt(amount).toString(16).padStart(64, '0');
  const erc20Data = '0xa9059cbb' + paddedAddress + paddedAmount;

  /**
   * 构造符合服务端期望的 authorizationJson 字符串并计算 authHash
   * 新接口格式：authorizationJson（字符串）和 webauthnSignature 分开传
   * @param {string} authorizationId
   * @param {Object} scopeOverride - 覆盖 scope 字段
   * @returns {{ authorizationJson, authHash }}
   */
  function buildAuthJsonAndHash(authorizationId, scopeOverride = {}) {
    const authorizationJson = JSON.stringify({
      userId: state.userId,
      authorizationId,
      grantee: [PLATFORM_ADDRESS],
      credentialId: state.credentialId,
      scope: {
        targetAddresses: [
          { chainId: '1', address: '0x1234567890123456789012345678901234567890' },
          { chainId: '1', address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' },
        ],
        signingWallets: [{ chainId: '1', address: state.walletAddress }],
        tokenRestrictions: [
          { chainId: '1', tokenAddress: '1_native' },
          { chainId: '1', tokenAddress: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' },
        ],
        cumulativeLimits: {
          maxTxCount: 100,
          tokenLimits: {
            '1_native': '10000000000000000000',
            '1_0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48': '10000000000000000000',
          },
        },
        dataPolicy: {
          allowedTxTypes: [2],
          allowedOperations: ['transfer', 'contractCall'],
        },
        ...scopeOverride,
      },
      timePolicy: {
        deadline: new Date(Date.now() + 86400 * 1000).toISOString(),
      },
      revocationPolicy: {
        allowContractUnavailable: true,
      },
      createdAt: new Date().toISOString(),
    });
    const authHash = computeAuthorizationHash(authorizationJson);
    return { authorizationJson, authHash };
  }

  // 测试场景1: 原生代币转账
  console.log('  [Test 1] Native token transfer');
  const nativeTransferTx = {
    chainId: 1,
    to: '0x1234567890123456789012345678901234567890',
    value: '1000000000000000', // 0.001 ETH
    data: '0x',
    gasLimit: '21000',
    maxFeePerGas: '1000000000',
    maxPriorityFeePerGas: '1000000',
    nonce: 0,
    type: 2
  };
  
  // 使用ethers库序列化交易
  const nativeTx = ethers.Transaction.from(nativeTransferTx);
  const nativeRawTxHex = nativeTx.unsignedSerialized;
  
  const { authorizationJson: nativeAuthJson, authHash: nativeAuthHash } = buildAuthJsonAndHash(state.authorizationId + '-native');
  const nativeBody = await buildRequest({
    guid: crypto.randomUUID(),
    authorizationJson: nativeAuthJson,
    webauthnSignature: makeWebAuthnSignature(nativeAuthHash),
    transaction: {
      rawTxHex: nativeRawTxHex,
      walletAddress: state.walletAddress
    },
  });
  
  const nativeRes = await httpPost('/api/tx/sign', nativeBody);
  assert(nativeRes.status === 200, 'tx/sign rawTxHex native returns 200');
  const nativeParsed = parseAttestationResponse(nativeRes);
  if (nativeParsed?.data?.success !== true) console.log(`  [debug] tx/sign rawTxHex native failed: reason=${nativeParsed?.data?.reason}, step=${nativeParsed?.data?.step}`);
  assert(nativeParsed && nativeParsed.data && nativeParsed.data.success === true, 'tx/sign rawTxHex native success=true');
  console.log(`  [info] tx/sign rawTxHex native: txHash=${nativeParsed?.data?.txHash}`);
  
  // 测试场景2: ERC20代币转账
  console.log('  [Test 2] ERC20 token transfer');
  const erc20TransferTx = {
    chainId: 1,
    to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC合约地址
    value: '0',
    data: erc20Data,
    gasLimit: '100000',
    maxFeePerGas: '1000000000',
    maxPriorityFeePerGas: '1000000',
    nonce: 1,
    type: 2
  };
  
  const erc20Tx = ethers.Transaction.from(erc20TransferTx);
  const erc20RawTxHex = erc20Tx.unsignedSerialized;
  
  const { authorizationJson: erc20AuthJson, authHash: erc20AuthHash } = buildAuthJsonAndHash(state.authorizationId + '-erc20');
  const erc20Body = await buildRequest({
    guid: crypto.randomUUID(),
    authorizationJson: erc20AuthJson,
    webauthnSignature: makeWebAuthnSignature(erc20AuthHash),
    transaction: {
      rawTxHex: erc20RawTxHex,
      walletAddress: state.walletAddress
    },
  });
  
  const erc20Res = await httpPost('/api/tx/sign', erc20Body);
  assert(erc20Res.status === 200, 'tx/sign rawTxHex ERC20 returns 200');
  const erc20Parsed = parseAttestationResponse(erc20Res);
  if (erc20Parsed?.data?.success !== true) console.log(`  [debug] tx/sign rawTxHex ERC20 failed: reason=${erc20Parsed?.data?.reason}, step=${erc20Parsed?.data?.step}`);
  assert(erc20Parsed && erc20Parsed.data && erc20Parsed.data.success === true, 'tx/sign rawTxHex ERC20 success=true');
  console.log(`  [info] tx/sign rawTxHex ERC20: txHash=${erc20Parsed?.data?.txHash}`);
  
  // 测试场景3: 复合交易 (原生代币 + ERC20代币)
  console.log('  [Test 3] Composite transaction (Native + ERC20)');
  const compositeTx = {
    chainId: 1,
    to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC合约地址
    value: '1000000000000000', // 0.001 ETH
    data: erc20Data, // ERC20 transfer
    gasLimit: '100000',
    maxFeePerGas: '1000000000',
    maxPriorityFeePerGas: '1000000',
    nonce: 2,
    type: 2
  };
  
  const compositeTxObj = ethers.Transaction.from(compositeTx);
  const compositeRawTxHex = compositeTxObj.unsignedSerialized;
  
  const { authorizationJson: compositeAuthJson, authHash: compositeAuthHash } = buildAuthJsonAndHash(state.authorizationId + '-composite');
  const compositeBody = await buildRequest({
    guid: crypto.randomUUID(),
    authorizationJson: compositeAuthJson,
    webauthnSignature: makeWebAuthnSignature(compositeAuthHash),
    transaction: {
      rawTxHex: compositeRawTxHex,
      walletAddress: state.walletAddress
    },
  });
  
  const compositeRes = await httpPost('/api/tx/sign', compositeBody);
  assert(compositeRes.status === 200, 'tx/sign rawTxHex composite returns 200');
  const compositeParsed = parseAttestationResponse(compositeRes);
  assert(compositeParsed && compositeParsed.data && compositeParsed.data.success === true, 'tx/sign rawTxHex composite success=true');
  console.log(`  [info] tx/sign rawTxHex composite: txHash=${compositeParsed?.data?.txHash}`);
  
  // 测试场景4: 不在 tokenRestrictions 中的 token 应该被拒绝
  console.log('  [Test 4] Token not in restrictions (should be rejected)');
  const invalidTx = {
    chainId: 1,
    to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    value: '0',
    data: erc20Data,
    gasLimit: '100000',
    maxFeePerGas: '1000000000',
    maxPriorityFeePerGas: '1000000',
    nonce: 3,
    type: 2
  };
  
  const invalidTxObj = ethers.Transaction.from(invalidTx);
  const invalidRawTxHex = invalidTxObj.unsignedSerialized;
  
  // 构造只允许原生代币的授权（不允许 ERC20）
  const { authorizationJson: invalidAuthJson, authHash: invalidAuthHash } = buildAuthJsonAndHash(
    state.authorizationId + '-invalid',
    {
      tokenRestrictions: [{ chainId: '1', tokenAddress: '1_native' }],  // 只允许原生代币
      cumulativeLimits: {
        maxTxCount: 100,
        tokenLimits: { '1_native': '10000000000000000000' },
      },
    }
  );
  const invalidBody = await buildRequest({
    guid: crypto.randomUUID(),
    authorizationJson: invalidAuthJson,
    webauthnSignature: makeWebAuthnSignature(invalidAuthHash),
    transaction: {
      rawTxHex: invalidRawTxHex,
      walletAddress: state.walletAddress
    },
  });
  
  const invalidRes = await httpPost('/api/tx/sign', invalidBody);
  // 应该返回 success: false，因为 ERC20 token 不在 tokenRestrictions 中
  assert(invalidRes.status === 200, 'tx/sign rawTxHex invalid token returns 200 (structured rejection)');
  const invalidParsed = parseAttestationResponse(invalidRes);
  assert(invalidParsed && invalidParsed.data && invalidParsed.data.success === false, 'tx/sign rawTxHex invalid token success=false');
  console.log(`  [info] tx/sign rawTxHex invalid token correctly rejected: ${invalidParsed?.data?.reason}`);
}

async function testKeyImportInit() {
  console.log('\n=== 11. POST /api/key/import/init (ECDH) ===');

  // 1. 获取 key_import_init 挑战值
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'key_import_init',
  }));
  const challengeParsed = parseAttestationResponse(challengeRes);
  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    assert(false, 'key/import/init ECDH: failed to get challenge');
    return;
  }
  const rawChallenge = challengeParsed.data.challenge;

  // 2. 构造 userIntentJson，计算 intentHash，用 Passkey 签名
  const importType = 'private_key';
  const intentJson = JSON.stringify({ purpose: 'key_import_init', userId: state.userId, importType });
  const intentHash = computeIntentHash(rawChallenge, intentJson);
  const webauthnSignature = makeWebAuthnSignature(intentHash);

  // 3. 调用 key/import/init
  const body = await buildRequest({
    userId: state.userId,
    importType,
    credentialId: state.credentialId,
    webauthnSignature,
    rawChallenge,
    userIntentJson: intentJson,
  });
  const res = await httpPost('/api/key/import/init', body);
  assert(res.status === 200, 'key/import/init ECDH returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && parsed.data.sessionId, 'key/import/init ECDH has sessionId');
  assert(parsed && parsed.data && parsed.data.enclavePublicKey, 'key/import/init ECDH has enclavePublicKey');
  assert(parsed && parsed.data && parsed.data.keyType === 'ecdh', 'key/import/init ECDH keyType=ecdh');
  assert(typeof res.body.attestationQuote === 'string', 'key/import/init ECDH has attestationQuote');

  if (parsed && parsed.data) {
    state.importSessionId = parsed.data.sessionId;
    state.importEnclavePublicKey = parsed.data.enclavePublicKey;
  }
}

async function testKeyImportComplete() {
  console.log('\n=== 12. POST /api/key/import/complete (ECDH) ===');
  if (!state.importSessionId || !state.importEnclavePublicKey) {
    skip('key/import/complete ECDH', 'no sessionId'); return;
  }

  // ECDH 加密
  const ecdhClient = crypto.createECDH('prime256v1');
  ecdhClient.generateKeys();
  const peerPublicKey = ecdhClient.getPublicKey('hex');
  const sharedSecret = ecdhClient.computeSecret(Buffer.from(state.importEnclavePublicKey, 'hex'));
  const aesKey = crypto.createHash('sha256').update(sharedSecret).digest();
  const testPrivateKey = '0x' + crypto.randomBytes(32).toString('hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(testPrivateKey, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const encryptedData = {
    ciphertext: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  };
  const chains = [{ chainId: 1, coinType: 60 }];
  const walletId = null;

  // 1. 获取 key_import_complete 挑战值
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'key_import_complete',
  }));
  const challengeParsed = parseAttestationResponse(challengeRes);
  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    assert(false, 'key/import/complete ECDH: failed to get challenge');
    return;
  }
  const rawChallenge = challengeParsed.data.challenge;

  // 2. 构造 userIntentJson，计算 intentHash，用 Passkey 签名
  const intentJson = JSON.stringify({
    purpose: 'key_import_complete',
    userId: state.userId,
    sessionId: state.importSessionId,
    walletId,
    chains,
  });
  const intentHash = computeIntentHash(rawChallenge, intentJson);
  const webauthnSignature = makeWebAuthnSignature(intentHash);

  // 3. 调用 key/import/complete
  const body = await buildRequest({
    userId: state.userId,
    sessionId: state.importSessionId,
    peerPublicKey,
    encryptedData,
    walletId,
    chains,
    credentialId: state.credentialId,
    webauthnSignature,
    rawChallenge,
    userIntentJson: intentJson,
  });
  const res = await httpPost('/api/key/import/complete', body);
  assert(res.status === 200, 'key/import/complete ECDH returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && parsed.data.success === true, 'key/import/complete ECDH success=true');
  assert(parsed && parsed.data && parsed.data.walletId, 'key/import/complete ECDH has walletId');
  console.log(`  [info] key/import/complete ECDH walletId=${parsed?.data?.walletId}`);
}

async function testKeyImportInitRSA() {
  console.log('\n=== 11b. POST /api/key/import/init (RSA) ===');

  // 生成 RSA-2048 密钥对
  const { publicKey: rsaPubKey, privateKey: rsaPrivKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const rsaPublicKeyPem = rsaPubKey.export({ type: 'spki', format: 'pem' });
  state.rsaPrivateKey = rsaPrivKey;

  // 1. 获取 key_import_init 挑战值
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'key_import_init',
  }));
  const challengeParsed = parseAttestationResponse(challengeRes);
  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    assert(false, 'key/import/init RSA: failed to get challenge');
    return;
  }
  const rawChallenge = challengeParsed.data.challenge;

  // 2. 构造 userIntentJson，计算 intentHash，用 Passkey 签名
  const importType = 'private_key';
  const intentJson = JSON.stringify({ purpose: 'key_import_init', userId: state.userId, importType });
  const intentHash = computeIntentHash(rawChallenge, intentJson);
  const webauthnSignature = makeWebAuthnSignature(intentHash);

  // 3. 调用 key/import/init（传入 rsaPublicKey 触发 RSA 模式）
  const body = await buildRequest({
    userId: state.userId,
    importType,
    rsaPublicKey: rsaPublicKeyPem,
    credentialId: state.credentialId,
    webauthnSignature,
    rawChallenge,
    userIntentJson: intentJson,
  });
  const res = await httpPost('/api/key/import/init', body);
  assert(res.status === 200, 'key/import/init RSA returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && parsed.data.sessionId, 'key/import/init RSA has sessionId');
  assert(parsed && parsed.data && parsed.data.encryptedAESKey, 'key/import/init RSA has encryptedAESKey');
  assert(parsed && parsed.data && parsed.data.keyType === 'rsa-2048', 'key/import/init RSA keyType=rsa-2048');
  assert(parsed && parsed.data && !parsed.data.enclavePublicKey, 'key/import/init RSA has no enclavePublicKey');
  assert(typeof res.body.attestationQuote === 'string', 'key/import/init RSA has attestationQuote');

  if (parsed && parsed.data) {
    state.rsaImportSessionId = parsed.data.sessionId;
    state.rsaEncryptedAESKey = parsed.data.encryptedAESKey;
  }
}

async function testKeyImportCompleteRSA() {
  console.log('\n=== 12b. POST /api/key/import/complete (RSA) ===');
  if (!state.rsaImportSessionId || !state.rsaEncryptedAESKey || !state.rsaPrivateKey) {
    skip('key/import/complete RSA', 'no RSA session'); return;
  }

  // RSA 私钥解密 AES 密钥，AES-256-GCM 加密测试私钥
  const aesKey = rsaPkcs1Decrypt(state.rsaPrivateKey, Buffer.from(state.rsaEncryptedAESKey, 'base64'));
  assert(aesKey.length === 32, 'RSA decrypted AES key is 32 bytes');
  const testPrivateKey = '0x' + crypto.randomBytes(32).toString('hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(testPrivateKey, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const encryptedData = {
    ciphertext: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  };
  const chains = [{ chainId: 1, coinType: 60 }];
  const walletId = null;

  // 1. 获取 key_import_complete 挑战值
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'key_import_complete',
  }));
  const challengeParsed = parseAttestationResponse(challengeRes);
  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    assert(false, 'key/import/complete RSA: failed to get challenge');
    return;
  }
  const rawChallenge = challengeParsed.data.challenge;

  // 2. 构造 userIntentJson，计算 intentHash，用 Passkey 签名
  const intentJson = JSON.stringify({
    purpose: 'key_import_complete',
    userId: state.userId,
    sessionId: state.rsaImportSessionId,
    walletId,
    chains,
  });
  const intentHash = computeIntentHash(rawChallenge, intentJson);
  const webauthnSignature = makeWebAuthnSignature(intentHash);

  // 3. 调用 key/import/complete（RSA 模式无需 peerPublicKey）
  const body = await buildRequest({
    userId: state.userId,
    sessionId: state.rsaImportSessionId,
    encryptedData,
    walletId,
    chains,
    credentialId: state.credentialId,
    webauthnSignature,
    rawChallenge,
    userIntentJson: intentJson,
  });
  const res = await httpPost('/api/key/import/complete', body);
  assert(res.status === 200, 'key/import/complete RSA returns 200');
  const parsedRsaComplete = parseAttestationResponse(res);
  assert(parsedRsaComplete && parsedRsaComplete.data && parsedRsaComplete.data.success === true, 'key/import/complete RSA success=true');
  assert(parsedRsaComplete && parsedRsaComplete.data && parsedRsaComplete.data.walletId, 'key/import/complete RSA has walletId');
  console.log(`  [info] key/import/complete RSA walletId=${parsedRsaComplete?.data?.walletId}`);
}

async function testKeyImportInitUserSide() {
  console.log('\n=== 11c. POST /api/key/import/init (User-side WebAuthn, ECDH) ===');

  // 用户端导入：需要先获取 key_import_init 挑战值，然后用 WebAuthn 签名
  const importType = 'private_key';

  // 1. 获取 key_import_init 挑战值
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'key_import_init',
  }));
  const challengeParsed = parseAttestationResponse(challengeRes);
  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    assert(false, 'key/import/init user-side: failed to get challenge');
    return;
  }
  const rawChallenge = challengeParsed.data.challenge;

  // 2. 构造 userIntentJson，计算 intentHash，用 Passkey 签名
  const importInitIntentJson = JSON.stringify({
    purpose: 'key_import_init',
    userId: state.userId,
    importType,
  });
  const intentHash = computeIntentHash(rawChallenge, importInitIntentJson);
  const webauthnSignature = makeWebAuthnSignature(intentHash);

  // 3. 调用 key/import/init，携带 WebAuthn 签名
  const body = await buildRequest({
    userId: state.userId,
    importType,
    credentialId: state.credentialId,
    webauthnSignature,
    rawChallenge,
    userIntentJson: importInitIntentJson,
  });
  const res = await httpPost('/api/key/import/init', body);
  assert(res.status === 200, 'key/import/init user-side returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && parsed.data.sessionId, 'key/import/init user-side has sessionId');
  assert(parsed && parsed.data && parsed.data.enclavePublicKey, 'key/import/init user-side has enclavePublicKey');
  assert(parsed && parsed.data && parsed.data.keyType === 'ecdh', 'key/import/init user-side keyType=ecdh');

  if (parsed && parsed.data) {
    state.userSideImportSessionId = parsed.data.sessionId;
    state.userSideEnclavePublicKey = parsed.data.enclavePublicKey;
    console.log(`  [info] user-side import sessionId=${state.userSideImportSessionId}`);
  }

  // 4. 测试：错误的 importType 在 userIntentJson 中应该被拒绝
  // 重新获取挑战值（上一个已被消费）
  const challengeRes2 = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'key_import_init',
  }));
  const challengeParsed2 = parseAttestationResponse(challengeRes2);
  if (challengeParsed2 && challengeParsed2.data && challengeParsed2.data.challenge) {
    const rawChallenge2 = challengeParsed2.data.challenge;
    // userIntentJson 中 importType=mnemonic，但实际请求 importType=private_key → 应该被拒绝
    const mismatchIntentJson = JSON.stringify({
      purpose: 'key_import_init',
      userId: state.userId,
      importType: 'mnemonic',  // 故意与实际不一致
    });
    const mismatchHash = computeIntentHash(rawChallenge2, mismatchIntentJson);
    const mismatchSig = makeWebAuthnSignature(mismatchHash);
    const mismatchBody = await buildRequest({
      userId: state.userId,
      importType: 'private_key',  // 实际请求 private_key
      credentialId: state.credentialId,
      webauthnSignature: mismatchSig,
      rawChallenge: rawChallenge2,
      userIntentJson: mismatchIntentJson,  // 但 intent 中是 mnemonic
    });
    const mismatchRes = await httpPost('/api/key/import/init', mismatchBody);
    assert(mismatchRes.status !== 200, 'key/import/init user-side: importType mismatch is rejected');
    console.log(`  [info] importType mismatch correctly rejected: status=${mismatchRes.status}`);
  }
}

async function testKeyImportCompleteUserSide() {
  console.log('\n=== 12c. POST /api/key/import/complete (User-side WebAuthn, ECDH) ===');
  if (!state.userSideImportSessionId || !state.userSideEnclavePublicKey) {
    skip('key/import/complete user-side', 'no user-side import session');
    return;
  }

  // 客户端用 ECDH 共享密钥加密私钥
  const ecdhClient = crypto.createECDH('prime256v1');
  ecdhClient.generateKeys();
  const peerPublicKey = ecdhClient.getPublicKey('hex');
  const sharedSecret = ecdhClient.computeSecret(Buffer.from(state.userSideEnclavePublicKey, 'hex'));
  const aesKey = crypto.createHash('sha256').update(sharedSecret).digest();

  const testPrivateKey = '0x' + crypto.randomBytes(32).toString('hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(testPrivateKey, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const encryptedData = {
    ciphertext: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  };

  const chains = [{ chainId: 1, coinType: 60 }];
  const walletId = null;  // 不指定，服务端随机生成

  // 1. 获取 key_import_complete 挑战值
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'key_import_complete',
  }));
  const challengeParsed = parseAttestationResponse(challengeRes);
  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    assert(false, 'key/import/complete user-side: failed to get challenge');
    return;
  }
  const rawChallenge = challengeParsed.data.challenge;

  // 2. 构造 userIntentJson（绑定 userId + sessionId + walletId + chains）
  const importCompleteIntentJson = JSON.stringify({
    purpose: 'key_import_complete',
    userId: state.userId,
    sessionId: state.userSideImportSessionId,
    walletId,
    chains,
  });
  const intentHash = computeIntentHash(rawChallenge, importCompleteIntentJson);
  const webauthnSignature = makeWebAuthnSignature(intentHash);

  // 3. 调用 key/import/complete，携带 WebAuthn 签名（用户端导入需要传 userId）
  const body = await buildRequest({
    userId: state.userId,
    sessionId: state.userSideImportSessionId,
    peerPublicKey,
    encryptedData,
    walletId,
    chains,
    credentialId: state.credentialId,
    webauthnSignature,
    rawChallenge,
    userIntentJson: importCompleteIntentJson,
  });
  const res = await httpPost('/api/key/import/complete', body);
  assert(res.status === 200, 'key/import/complete user-side returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && parsed.data.success === true, 'key/import/complete user-side success=true');
  assert(parsed && parsed.data && parsed.data.walletId, 'key/import/complete user-side has walletId');
  console.log(`  [info] user-side import complete: walletId=${parsed?.data?.walletId}`);

  // 4. 测试：错误的 sessionId 在 userIntentJson 中应该被拒绝
  // 先创建一个新的导入会话（用于测试 sessionId 篡改）
  const challengeRes2 = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'key_import_init',
  }));
  const challengeParsed2 = parseAttestationResponse(challengeRes2);
  if (challengeParsed2 && challengeParsed2.data && challengeParsed2.data.challenge) {
    const rawChallenge2 = challengeParsed2.data.challenge;
    const initIntentJson2 = JSON.stringify({
      purpose: 'key_import_init',
      userId: state.userId,
      importType: 'private_key',
    });
    const initHash2 = computeIntentHash(rawChallenge2, initIntentJson2);
    const initSig2 = makeWebAuthnSignature(initHash2);
    const initBody2 = await buildRequest({
      userId: state.userId,
      importType: 'private_key',
      credentialId: state.credentialId,
      webauthnSignature: initSig2,
      rawChallenge: rawChallenge2,
      userIntentJson: initIntentJson2,
    });
    const initRes2 = await httpPost('/api/key/import/init', initBody2);
    const initParsed2 = parseAttestationResponse(initRes2);
    if (initParsed2 && initParsed2.data && initParsed2.data.sessionId) {
      const newSessionId = initParsed2.data.sessionId;
      const newEnclavePublicKey = initParsed2.data.enclavePublicKey;

      // 获取 complete 挑战值
      const challengeRes3 = await httpPost('/api/challenge', await buildRequest({
        userId: state.userId,
        credentialId: state.credentialId,
        purpose: 'key_import_complete',
      }));
      const challengeParsed3 = parseAttestationResponse(challengeRes3);
      if (challengeParsed3 && challengeParsed3.data && challengeParsed3.data.challenge) {
        const rawChallenge3 = challengeParsed3.data.challenge;

        // 客户端加密数据（用新会话的公钥）
        const ecdhClient3 = crypto.createECDH('prime256v1');
        ecdhClient3.generateKeys();
        const peerPublicKey3 = ecdhClient3.getPublicKey('hex');
        const sharedSecret3 = ecdhClient3.computeSecret(Buffer.from(newEnclavePublicKey, 'hex'));
        const aesKey3 = crypto.createHash('sha256').update(sharedSecret3).digest();
        const iv3 = crypto.randomBytes(12);
        const cipher3 = crypto.createCipheriv('aes-256-gcm', aesKey3, iv3);
        const encrypted3 = Buffer.concat([cipher3.update('0x' + crypto.randomBytes(32).toString('hex'), 'utf8'), cipher3.final()]);
        const authTag3 = cipher3.getAuthTag();
        const encryptedData3 = {
          ciphertext: encrypted3.toString('hex'),
          iv: iv3.toString('hex'),
          authTag: authTag3.toString('hex'),
        };

        // userIntentJson 中 sessionId 是新会话，但实际请求中 sessionId 也是新会话
        // 测试：userIntentJson 中 sessionId 与实际不一致时应该被拒绝
        const mismatchCompleteIntentJson = JSON.stringify({
          purpose: 'key_import_complete',
          userId: state.userId,
          sessionId: 'fake-session-id-that-does-not-exist',  // 故意错误的 sessionId
          walletId: null,
          chains: [{ chainId: 1, coinType: 60 }],
        });
        const mismatchCompleteHash = computeIntentHash(rawChallenge3, mismatchCompleteIntentJson);
        const mismatchCompleteSig = makeWebAuthnSignature(mismatchCompleteHash);
        const mismatchCompleteBody = await buildRequest({
          userId: state.userId,
          sessionId: newSessionId,  // 实际 sessionId 是新会话
          peerPublicKey: peerPublicKey3,
          encryptedData: encryptedData3,
          walletId: null,
          chains: [{ chainId: 1, coinType: 60 }],
          credentialId: state.credentialId,
          webauthnSignature: mismatchCompleteSig,
          rawChallenge: rawChallenge3,
          userIntentJson: mismatchCompleteIntentJson,  // 但 intent 中是 fake sessionId
        });
        const mismatchCompleteRes = await httpPost('/api/key/import/complete', mismatchCompleteBody);
        assert(mismatchCompleteRes.status !== 200, 'key/import/complete user-side: sessionId mismatch is rejected');
        console.log(`  [info] sessionId mismatch correctly rejected: status=${mismatchCompleteRes.status}`);
      }
    }
  }
}

async function testKeyExportInit() {
  console.log('\n=== 13. POST /api/key/export/init (ECDH, 批量多钱包) ===');
  if (!state.walletId) { skip('key/export/init ECDH', 'no walletId'); return; }
  if (!state.walletAddress) { skip('key/export/init ECDH', 'no wallet address'); return; }

  // 先创建第二个钱包，用于测试多钱包批量导出
  let secondWalletId = null;
  let secondWalletAddress = null;
  {
    const chains2 = [{ chainId: 10, coinType: 60 }];
    const intentJson2 = JSON.stringify({
      purpose: 'wallet_create',
      userId: state.userId,
      chains: chains2,
    });
    const challengeRes2 = await httpPost('/api/challenge', await buildRequest({
      userId: state.userId,
      credentialId: state.credentialId,
      purpose: 'wallet_create',
    }));
    const challengeParsed2 = parseAttestationResponse(challengeRes2);
    if (challengeParsed2 && challengeParsed2.data && challengeParsed2.data.challenge) {
      const ch2 = challengeParsed2.data.challenge;
      const ws2 = makeWebAuthnSignature(computeIntentHash(ch2, intentJson2));
      const createBody2 = await buildRequest({
        userId: state.userId,
        credentialId: state.credentialId,
        webauthnSignature: ws2,
        rawChallenge: ch2,
        userIntentJson: intentJson2,
        chains: chains2,
      });
      const createRes2 = await httpPost('/api/wallet/create', createBody2);
      const createParsed2 = parseAttestationResponse(createRes2);
      if (createParsed2 && createParsed2.data && createParsed2.data.walletId) {
        secondWalletId = createParsed2.data.walletId;
        // 通过 wallet/get 获取地址
        const getBody2 = await buildRequest({ userId: state.userId, walletId: secondWalletId });
        const getRes2 = await httpPost('/api/wallet/get', getBody2);
        const getParsed2 = parseAttestationResponse(getRes2);
        const wd2 = getParsed2?.data?.wallet;
        if (wd2 && wd2.wallets && wd2.wallets[0]?.addresses?.[0]?.address) {
          secondWalletAddress = wd2.wallets[0].addresses[0].address;
        }
        console.log(`  [info] Created second wallet: walletId=${secondWalletId}, address=${secondWalletAddress}`);
      }
    }
  }

  // ECDH init：客户端传 peerPublicKey，SGX 生成 ECDH 密钥对算出共享密钥加密数据，返回 enclavePublicKey + encryptedData
  const ecdhKeyPair = crypto.createECDH('prime256v1');
  ecdhKeyPair.generateKeys();
  state.ecdhClientKeyPair = ecdhKeyPair;
  const peerPublicKey = ecdhKeyPair.getPublicKey('hex');

  // 构造 exportInfo 数组：
  //   - 第一个钱包：指定 address（只导出该地址对应的逻辑钱包）
  //   - 第二个钱包（若存在）：addresses 为空（导出该 walletId 下所有私钥）
  const exportInfo = [
    { walletId: state.walletId, addresses: [state.walletAddress] },
  ];
  if (secondWalletId) {
    exportInfo.push({ walletId: secondWalletId, addresses: [] });
  }

  // 获取挑战值
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'key_export',
  }));
  const challengeParsed = parseAttestationResponse(challengeRes);
  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    skip('key/export/init ECDH', 'could not get challenge');
    return;
  }
  const rawChallenge = challengeParsed.data.challenge;

  // 构造 userIntentJson（包含 exportInfo 数组 + peerPublicKey 防止中间人替换）
  const keyExportIntentJson = JSON.stringify({
    purpose: 'key_export',
    userId: state.userId,
    exportInfo,
    peerPublicKey,
  });

  // 计算 intentHash = SHA256(rawChallenge + userIntentJson)，用 intentHash 签名
  const intentHash = computeIntentHash(rawChallenge, keyExportIntentJson);
  const webauthnSignature = makeWebAuthnSignature(intentHash);

  // 业务请求中携带 rawChallenge + userIntentJson + webauthnSignature + exportInfo
  const body = await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    webauthnSignature,
    rawChallenge,
    userIntentJson: keyExportIntentJson,
    exportInfo,
    peerPublicKey,
  });
  const res = await httpPost('/api/key/export/init', body);
  assert(res.status === 200, 'key/export/init ECDH returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed && parsed.data && parsed.data.keyType === 'ecdh', 'key/export/init ECDH keyType=ecdh');
  assert(parsed && parsed.data && parsed.data.enclavePublicKey, 'key/export/init ECDH has enclavePublicKey');
  assert(parsed && parsed.data && parsed.data.encryptedData, 'key/export/init ECDH has encryptedData');
  assert(parsed && parsed.data && !parsed.data.encryptedAESKey, 'key/export/init ECDH has NO encryptedAESKey');

  if (parsed && parsed.data) {
    state.exportSessionId = parsed.data.sessionId;
    state.enclavePublicKey = parsed.data.enclavePublicKey;
    console.log(`  [info] exportSessionId=${state.exportSessionId}, keyType=${parsed.data.keyType}, enclavePublicKey=${state.enclavePublicKey.substring(0, 20)}...`);
  }

  // 验证可以用 ECDH 共享密钥解密钱包数据
  // 新格式：{ userId, wallets: [{ userId, walletId, wallets: [{ walletType, mnemonic, keys: [...] }] }] }
  if (parsed && parsed.data && parsed.data.encryptedData && parsed.data.enclavePublicKey) {
    try {
      const sharedKey = ecdhKeyPair.computeSecret(Buffer.from(parsed.data.enclavePublicKey, 'hex'));
      const aesKey = crypto.createHash('sha256').update(sharedKey).digest();

      const ed = parsed.data.encryptedData;
      const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(ed.iv, 'hex'));
      decipher.setAuthTag(Buffer.from(ed.authTag, 'hex'));
      const decrypted = Buffer.concat([decipher.update(Buffer.from(ed.ciphertext, 'hex')), decipher.final()]);
      const walletJson = JSON.parse(decrypted.toString('utf8'));
      assert(walletJson.userId === state.userId, 'key/export/init ECDH: decrypted wallet has correct userId');
      assert(Array.isArray(walletJson.wallets), 'key/export/init ECDH: decrypted data has wallets array');
      assert(walletJson.wallets.length >= 1, 'key/export/init ECDH: decrypted wallets array has >= 1 entry');
      // 验证第一个容器的 walletId 正确
      assert(walletJson.wallets[0].walletId === state.walletId, 'key/export/init ECDH: first wallet container walletId matches');
      // 验证每个容器有 wallets 数组（逻辑钱包列表）
      assert(Array.isArray(walletJson.wallets[0].wallets), 'key/export/init ECDH: first wallet container has wallets array');
      // 验证每个逻辑钱包有 keys 数组
      assert(Array.isArray(walletJson.wallets[0].wallets[0].keys), 'key/export/init ECDH: first logical wallet has keys array');
      if (secondWalletId && walletJson.wallets.length >= 2) {
        assert(walletJson.wallets[1].walletId === secondWalletId, 'key/export/init ECDH: second wallet container walletId matches');
      }
      console.log(`  [info] ECDH export decrypt success: userId=${walletJson.userId}, containers count=${walletJson.wallets.length}`);
    } catch (err) {
      assert(false, 'key/export/init ECDH: decrypt wallet data', err.message);
    }
  }
}

async function testKeyExportInitRSA() {
  console.log('\n=== 13b. POST /api/key/export/init (RSA, 批量多钱包) ===');

  // 创建第一个钱包用于 RSA 导出测试（指定 address 导出）
  const rsaExportCreateChains1 = [{ chainId: 42161, coinType: 60 }];
  const rsaExportCreateIntentJson1 = JSON.stringify({
    purpose: 'wallet_create',
    userId: state.userId,
    chains: rsaExportCreateChains1,
  });
  const createChallengeRes1 = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'wallet_create',
  }));
  const createChallengeParsed1 = parseAttestationResponse(createChallengeRes1);
  if (!createChallengeParsed1 || !createChallengeParsed1.data || !createChallengeParsed1.data.challenge) {
    skip('key/export/init RSA', 'could not get wallet_create challenge (wallet 1)');
    return;
  }
  const ch1 = createChallengeParsed1.data.challenge;
  const ws1 = makeWebAuthnSignature(computeIntentHash(ch1, rsaExportCreateIntentJson1));
  const createBody1 = await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    webauthnSignature: ws1,
    rawChallenge: ch1,
    userIntentJson: rsaExportCreateIntentJson1,
    chains: rsaExportCreateChains1,
  });
  const createRes1 = await httpPost('/api/wallet/create', createBody1);
  const createParsed1 = parseAttestationResponse(createRes1);
  if (!createParsed1 || !createParsed1.data || !createParsed1.data.walletId) {
    skip('key/export/init RSA', 'could not create test wallet 1');
    return;
  }
  const rsaExportWalletId1 = createParsed1.data.walletId;

  // 获取第一个钱包的地址
  const getBody1 = await buildRequest({ userId: state.userId, walletId: rsaExportWalletId1 });
  const getRes1 = await httpPost('/api/wallet/get', getBody1);
  const getParsed1 = parseAttestationResponse(getRes1);
  const walletData1 = getParsed1?.data?.wallet;
  let rsaExportAddress1 = null;
  if (walletData1 && walletData1.wallets && walletData1.wallets.length > 0) {
    const first = walletData1.wallets[0];
    if (first.addresses && first.addresses.length > 0) {
      rsaExportAddress1 = first.addresses[0].address;
    }
  }
  if (!rsaExportAddress1) { skip('key/export/init RSA', 'no address from wallet/get (wallet 1)'); return; }

  // 创建第二个钱包用于 RSA 导出测试（addresses 为空，导出所有）
  const rsaExportCreateChains2 = [{ chainId: 8453, coinType: 60 }];
  const rsaExportCreateIntentJson2 = JSON.stringify({
    purpose: 'wallet_create',
    userId: state.userId,
    chains: rsaExportCreateChains2,
  });
  const createChallengeRes2 = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'wallet_create',
  }));
  const createChallengeParsed2 = parseAttestationResponse(createChallengeRes2);
  let rsaExportWalletId2 = null;
  if (createChallengeParsed2 && createChallengeParsed2.data && createChallengeParsed2.data.challenge) {
    const ch2 = createChallengeParsed2.data.challenge;
    const ws2 = makeWebAuthnSignature(computeIntentHash(ch2, rsaExportCreateIntentJson2));
    const createBody2 = await buildRequest({
      userId: state.userId,
      credentialId: state.credentialId,
      webauthnSignature: ws2,
      rawChallenge: ch2,
      userIntentJson: rsaExportCreateIntentJson2,
      chains: rsaExportCreateChains2,
    });
    const createRes2 = await httpPost('/api/wallet/create', createBody2);
    const createParsed2 = parseAttestationResponse(createRes2);
    if (createParsed2 && createParsed2.data && createParsed2.data.walletId) {
      rsaExportWalletId2 = createParsed2.data.walletId;
      console.log(`  [info] Created second wallet for RSA export: walletId=${rsaExportWalletId2}`);
    }
  }

  // 生成 RSA-2048 密钥对
  const { publicKey: rsaPubKey, privateKey: rsaPrivKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const rsaPublicKeyPem = rsaPubKey.export({ type: 'spki', format: 'pem' });

  // 构造 exportInfo 数组：
  //   - 第一个钱包：指定 address（只导出该地址对应的逻辑钱包）
  //   - 第二个钱包（若存在）：addresses 为空（导出该 walletId 下所有私钥）
  const rsaExportInfo = [
    { walletId: rsaExportWalletId1, addresses: [rsaExportAddress1] },
  ];
  if (rsaExportWalletId2) {
    rsaExportInfo.push({ walletId: rsaExportWalletId2, addresses: [] });
  }

  // 获取挑战值
  const exportChallengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'key_export',
  }));
  const exportChallengeParsed = parseAttestationResponse(exportChallengeRes);
  if (!exportChallengeParsed || !exportChallengeParsed.data || !exportChallengeParsed.data.challenge) {
    skip('key/export/init RSA', 'could not get key_export challenge');
    return;
  }
  const rawChallenge = exportChallengeParsed.data.challenge;

  // 构造 userIntentJson（包含 exportInfo 数组 + rsaPublicKey 防止中间人替换）
  const rsaKeyExportIntentJson = JSON.stringify({
    purpose: 'key_export',
    userId: state.userId,
    exportInfo: rsaExportInfo,
    rsaPublicKey: rsaPublicKeyPem,
  });

  // 计算 intentHash = SHA256(rawChallenge + userIntentJson)，用 intentHash 签名
  const intentHash = computeIntentHash(rawChallenge, rsaKeyExportIntentJson);
  const webauthnSignature = makeWebAuthnSignature(intentHash);

  // 业务请求中携带 rawChallenge + userIntentJson + webauthnSignature + exportInfo
  const body = await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    webauthnSignature,
    rawChallenge,
    userIntentJson: rsaKeyExportIntentJson,
    exportInfo: rsaExportInfo,
    rsaPublicKey: rsaPublicKeyPem,
  });
  const res = await httpPost('/api/key/export/init', body);
  assert(res.status === 200, 'key/export/init RSA returns 200');
  const parsedExport = parseAttestationResponse(res);
  assert(parsedExport && parsedExport.data && parsedExport.data.keyType === 'rsa-2048', 'key/export/init RSA keyType=rsa-2048');
  assert(parsedExport && parsedExport.data && parsedExport.data.encryptedAESKey, 'key/export/init RSA has encryptedAESKey');
  assert(parsedExport && parsedExport.data && parsedExport.data.encryptedData, 'key/export/init RSA has encryptedData');
  assert(parsedExport && parsedExport.data && !parsedExport.data.enclavePublicKey, 'key/export/init RSA has no enclavePublicKey');

  // 验证可以用 RSA 私钥解密 AES 密钥，再用 AES 密钥解密钱包数据（新格式：{ userId, wallets: [...] }）
  if (parsedExport && parsedExport.data && parsedExport.data.encryptedAESKey && parsedExport.data.encryptedData) {
    try {
      const aesKey = rsaPkcs1Decrypt(
        rsaPrivKey,
        Buffer.from(parsedExport.data.encryptedAESKey, 'base64')
      );
      assert(aesKey.length === 32, 'key/export/init RSA: decrypted AES key is 32 bytes');

      // 解密钱包数据
      const ed = parsedExport.data.encryptedData;
      const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(ed.iv, 'hex'));
      decipher.setAuthTag(Buffer.from(ed.authTag, 'hex'));
      const decrypted = Buffer.concat([decipher.update(Buffer.from(ed.ciphertext, 'hex')), decipher.final()]);
      const walletJson = JSON.parse(decrypted.toString('utf8'));
      assert(walletJson.userId === state.userId, 'key/export/init RSA: decrypted wallet has correct userId');
      assert(Array.isArray(walletJson.wallets), 'key/export/init RSA: decrypted data has wallets array');
      assert(walletJson.wallets.length >= 1, 'key/export/init RSA: decrypted wallets array has >= 1 entry');
      // 验证第一个容器的 walletId 正确
      assert(walletJson.wallets[0].walletId === rsaExportWalletId1, 'key/export/init RSA: first wallet container walletId matches');
      // 验证每个容器有 wallets 数组（逻辑钱包列表）
      assert(Array.isArray(walletJson.wallets[0].wallets), 'key/export/init RSA: first wallet container has wallets array');
      // 验证每个逻辑钱包有 keys 数组
      assert(Array.isArray(walletJson.wallets[0].wallets[0].keys), 'key/export/init RSA: first logical wallet has keys array');
      if (rsaExportWalletId2 && walletJson.wallets.length >= 2) {
        assert(walletJson.wallets[1].walletId === rsaExportWalletId2, 'key/export/init RSA: second wallet container walletId matches');
      }
      console.log(`  [info] RSA export decrypt success: userId=${walletJson.userId}, containers count=${walletJson.wallets.length}`);
    } catch (err) {
      assert(false, 'key/export/init RSA: decrypt wallet data', err.message);
    }
  }
}

async function testKeyExportComplete() {
  console.log('\n=== 14. POST /api/key/export/complete (ECDH) ===');
  if (!state.exportSessionId) { skip('key/export/complete ECDH', 'no exportSessionId'); return; }

  // ECDH complete：需要用户 WebAuthn 签名确认已收到数据，防止攻击者在用户未解密前触发删除
  // 新流程：获取挑战值时只传 userId + credentialId，不传 userIntentJson
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'key_export_confirm',
  }));
  const challengeParsed = parseAttestationResponse(challengeRes);
  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    assert(false, 'key/export/complete ECDH failed to get key_export_confirm challenge');
    return;
  }
  const rawChallenge = challengeParsed.data.challenge;

  // 新流程：构造 userIntentJson（包含 sessionId，防止 sessionId 被替换）
  const exportConfirmIntentJson = JSON.stringify({
    purpose: 'key_export_confirm',
    userId: state.userId,
    sessionId: state.exportSessionId,
  });

  // 新流程：计算 intentHash = SHA256(rawChallenge + userIntentJson)，用 intentHash 签名
  const intentHash = computeIntentHash(rawChallenge, exportConfirmIntentJson);
  const webauthnSignature = makeWebAuthnSignature(intentHash);

  // 新流程：业务请求中携带 rawChallenge + userIntentJson + webauthnSignature
  const body = await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    webauthnSignature,
    rawChallenge,
    userIntentJson: exportConfirmIntentJson,
    sessionId: state.exportSessionId,
  });
  const res = await httpPost('/api/key/export/complete', body);
  assert(res.status === 200, 'key/export/complete ECDH returns 200');
  const parsedComplete = parseAttestationResponse(res);
  assert(parsedComplete && parsedComplete.data && parsedComplete.data.deleted === true, 'key/export/complete ECDH deleted=true');
  assert(parsedComplete && parsedComplete.data && Array.isArray(parsedComplete.data.walletIds), 'key/export/complete ECDH has walletIds array');
  assert(parsedComplete && parsedComplete.data && !parsedComplete.data.encryptedData, 'key/export/complete ECDH has NO encryptedData (data was in init)');
  console.log(`  [info] key/export/complete ECDH: walletIds=${JSON.stringify(parsedComplete?.data?.walletIds)}, deletedCount=${parsedComplete?.data?.deletedCount}`);

  // 验证导出的钱包已从数据库中删除（通过 wallet/get 确认，钱包不存在时服务端返回非 200）
  if (parsedComplete && parsedComplete.data && Array.isArray(parsedComplete.data.walletIds)) {
    for (const deletedWalletId of parsedComplete.data.walletIds) {
      const getBody = await buildRequest({ userId: state.userId, walletId: deletedWalletId });
      const getRes = await httpPost('/api/wallet/get', getBody);
      // wallet/get 在钱包不存在时抛出错误，返回非 200 状态码
      assert(getRes.status !== 200, `key/export/complete ECDH: wallet ${deletedWalletId} is deleted from DB (wallet/get returns non-200)`);
      console.log(`  [info] wallet ${deletedWalletId} confirmed deleted: wallet/get status=${getRes.status}`);
    }
  }
}

async function testEvidenceGet() {
  console.log('\n=== 15. POST /api/evidence/get ===');
  const body = await buildRequest({
    userId: state.userId,
    authorizationId: state.authorizationId,
  });
  const res = await httpPost('/api/evidence/get', body);
  assert(res.status !== 401, 'evidence/get auth passed (not 401)');
  console.log(`  [info] evidence/get status=${res.status}`);
}

async function testEvidenceList() {
  console.log('\n=== 16. POST /api/evidence/list ===');
  const body = await buildRequest({ userId: state.userId });
  const res = await httpPost('/api/evidence/list', body);
  assert(res.status === 200, 'evidence/list returns 200');
  const parsed = parseAttestationResponse(res);
  assert(parsed !== null, 'evidence/list has valid attestation response');
}

async function testAuthStatus() {
  console.log('\n=== 17. POST /api/auth/status ===');
  const body = await buildRequest({
    userId: state.userId,
    authorizationId: state.authorizationId,
  });
  const res = await httpPost('/api/auth/status', body);
  assert(res.status !== 401, 'auth/status auth passed (not 401)');
  console.log(`  [info] auth/status status=${res.status}, body=${JSON.stringify(res.body).substring(0, 120)}`);
}

async function testWalletEntryDelete() {
  console.log('\n=== 18. POST /api/wallet/entry/delete ===');

  // 先创建一个新钱包用于 entry/delete 测试（原钱包可能已被 export/complete 删除）
  // 新流程：获取挑战值时只传 userId + credentialId，不传 userIntentJson
  const entryDeleteCreateChains = [{ chainId: 137, coinType: 60 }];
  const entryDeleteCreateIntentJson = JSON.stringify({
    purpose: 'wallet_create',
    userId: state.userId,
    chains: entryDeleteCreateChains,
  });
  const createChallengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'wallet_create',
  }));
  const createChallengeParsed = parseAttestationResponse(createChallengeRes);
  if (!createChallengeParsed || !createChallengeParsed.data || !createChallengeParsed.data.challenge) {
    skip('wallet/entry/delete', 'could not get wallet_create challenge');
    return;
  }
  const ch0 = createChallengeParsed.data.challenge;
  const ws0 = makeWebAuthnSignature(computeIntentHash(ch0, entryDeleteCreateIntentJson));
  const createBody = await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    webauthnSignature: ws0,
    rawChallenge: ch0,
    userIntentJson: entryDeleteCreateIntentJson,
    chains: entryDeleteCreateChains,
  });
  const createRes = await httpPost('/api/wallet/create', createBody);
  const createParsed = parseAttestationResponse(createRes);
  if (!createParsed || !createParsed.data || !createParsed.data.walletId) {
    skip('wallet/entry/delete', 'could not create test wallet');
    return;
  }
  const entryWalletId = createParsed.data.walletId;

  // 通过 wallet/get 获取地址
  const getBody = await buildRequest({ userId: state.userId, walletId: entryWalletId });
  const getRes = await httpPost('/api/wallet/get', getBody);
  const getParsed = parseAttestationResponse(getRes);
  const walletData = getParsed?.data?.wallet;
  let entryAddress = null;
  if (walletData && walletData.wallets && walletData.wallets.length > 0) {
    const first = walletData.wallets[0];
    if (first.addresses && first.addresses.length > 0) {
      entryAddress = first.addresses[0].address;
    }
  }
  if (!entryAddress) { skip('wallet/entry/delete', 'no address from wallet/get'); return; }

  // 新流程：获取挑战值时只传 userId + credentialId，不传 userIntentJson
  const deleteChallengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'wallet_entry_delete',
  }));
  const deleteChallengeParsed = parseAttestationResponse(deleteChallengeRes);
  if (!deleteChallengeParsed || !deleteChallengeParsed.data || !deleteChallengeParsed.data.challenge) {
    skip('wallet/entry/delete', 'could not get wallet_entry_delete challenge');
    return;
  }
  const rawChallenge = deleteChallengeParsed.data.challenge;

  // 新流程：构造 userIntentJson
  const entryDeleteIntentJson = JSON.stringify({
    purpose: 'wallet_entry_delete',
    userId: state.userId,
    walletId: entryWalletId,
    address: entryAddress,
  });

  // 新流程：计算 intentHash = SHA256(rawChallenge + userIntentJson)，用 intentHash 签名
  const intentHash = computeIntentHash(rawChallenge, entryDeleteIntentJson);
  const webauthnSignature = makeWebAuthnSignature(intentHash);

  // 新流程：业务请求中携带 rawChallenge + userIntentJson + webauthnSignature
  const body = await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    webauthnSignature,
    rawChallenge,
    userIntentJson: entryDeleteIntentJson,
    walletId: entryWalletId,
    address: entryAddress,
  });
  const res = await httpPost('/api/wallet/entry/delete', body);
  assert(res.status === 200, 'wallet/entry/delete returns 200');
  const parsedDel = parseAttestationResponse(res);
  if (parsedDel && parsedDel.data) {
    assert(parsedDel.data.success === true, 'wallet/entry/delete success');
  }
  console.log(`  [info] wallet/entry/delete status=${res.status}`);
}

async function testWalletDelete() {
  console.log('\n=== 19. POST /api/wallet/delete ===');
  // 新流程：获取 wallet_create 挑战值时只传 userId + credentialId
  const walletDeleteCreateChains = [{ chainId: 56, coinType: 60 }];
  const walletDeleteCreateIntentJson = JSON.stringify({
    purpose: 'wallet_create',
    userId: state.userId,
    chains: walletDeleteCreateChains,
  });
  const createChallengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'wallet_create',
  }));
  const createChallengeParsed = parseAttestationResponse(createChallengeRes);
  if (!createChallengeParsed || !createChallengeParsed.data || !createChallengeParsed.data.challenge) {
    skip('wallet/delete', 'could not get wallet_create challenge');
    return;
  }
  const challenge1 = createChallengeParsed.data.challenge;
  const ws1 = makeWebAuthnSignature(computeIntentHash(challenge1, walletDeleteCreateIntentJson));
  const createBody = await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    webauthnSignature: ws1,
    rawChallenge: challenge1,
    userIntentJson: walletDeleteCreateIntentJson,
    chains: walletDeleteCreateChains,
  });
  const createRes = await httpPost('/api/wallet/create', createBody);
  const createParsed = parseAttestationResponse(createRes);
  if (!createParsed || !createParsed.data || !createParsed.data.walletId) {
    skip('wallet/delete', 'could not create test wallet');
    return;
  }
  const deleteWalletId = createParsed.data.walletId;

  // 新流程：获取 wallet_delete 挑战值时只传 userId + credentialId
  const walletDeleteIntentJson = JSON.stringify({
    purpose: 'wallet_delete',
    userId: state.userId,
    walletId: deleteWalletId,
  });
  const deleteChallengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'wallet_delete',
  }));
  const deleteChallengeParsed = parseAttestationResponse(deleteChallengeRes);
  if (!deleteChallengeParsed || !deleteChallengeParsed.data || !deleteChallengeParsed.data.challenge) {
    skip('wallet/delete', 'could not get wallet_delete challenge');
    return;
  }
  const challenge2 = deleteChallengeParsed.data.challenge;
  const ws2 = makeWebAuthnSignature(computeIntentHash(challenge2, walletDeleteIntentJson));
  const body = await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    webauthnSignature: ws2,
    rawChallenge: challenge2,
    userIntentJson: walletDeleteIntentJson,
    walletId: deleteWalletId,
  });
  const res = await httpPost('/api/wallet/delete', body);
  assert(res.status === 200, 'wallet/delete returns 200');
  const parsedWalletDel = parseAttestationResponse(res);
  assert(parsedWalletDel !== null, 'wallet/delete has valid attestation response');
}

async function testPasskeyDelete() {
  console.log('\n=== 20. POST /api/passkey/delete ===');
  // 新流程：获取挑战值时只传 userId + credentialId，不传 userIntentJson
  const passkeyDeleteIntentJson = JSON.stringify({
    purpose: 'passkey_delete',
    userId: state.userId,
    credentialIdsToDelete: [state.credentialId2],
  });
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    purpose: 'passkey_delete',
  }));
  const challengeParsed = parseAttestationResponse(challengeRes);
  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    assert(false, 'passkey/delete failed to get challenge');
    return;
  }
  const rawChallenge = challengeParsed.data.challenge;

  // 新流程：计算 intentHash = SHA256(rawChallenge + userIntentJson)，用 intentHash 签名
  const intentHash = computeIntentHash(rawChallenge, passkeyDeleteIntentJson);
  const webauthnSignature = makeWebAuthnSignature(intentHash);

  // 新流程：业务请求中携带 rawChallenge + userIntentJson + webauthnSignature
  const body = await buildRequest({
    userId: state.userId,
    credentialId: state.credentialId,
    webauthnSignature,
    rawChallenge,
    userIntentJson: passkeyDeleteIntentJson,
    credentialIdsToDelete: [state.credentialId2],
  });
  const res = await httpPost('/api/passkey/delete', body);
  assert(res.status === 200, 'passkey/delete returns 200');
  const parsed = parseAttestationResponse(res);
  if (parsed && parsed.data) {
    assert(parsed.data.deletedCount === 1, 'passkey/delete deletedCount=1');
    assert(parsed.data.accountDeleted === false, 'passkey/delete accountDeleted=false');
  }
}

async function testPlatformWalletList() {
  console.log('\n=== 21. POST /api/admin/userId/list ===');
  
  // Test 1: Default pagination
  const body1 = await buildRequest({});
  const res1 = await httpPost('/api/admin/userId/list', body1);
  assert(res1.status === 200, 'admin/userId/list returns 200');
  const parsed1 = parseAttestationResponse(res1);
  assert(parsed1 !== null, 'admin/userId/list has valid attestation response');
  assert(parsed1 && parsed1.data && typeof parsed1.data.totalUsers === 'number', 'admin/userId/list has totalUsers');
  assert(parsed1 && parsed1.data && typeof parsed1.data.page === 'number', 'admin/userId/list has page');
  assert(parsed1 && parsed1.data && typeof parsed1.data.pageSize === 'number', 'admin/userId/list has pageSize');
  assert(parsed1 && parsed1.data && typeof parsed1.data.totalPages === 'number', 'admin/userId/list has totalPages');
  assert(parsed1 && parsed1.data && Array.isArray(parsed1.data.users), 'admin/userId/list has users array');
  
  // Test 2: With user data (after creating wallet and auth)
  if (state.userId && parsed1.data.users.length > 0) {
    const userData = parsed1.data.users.find(u => u.userId === state.userId);
    if (userData) {
      assert(Array.isArray(userData.authorizationIds), 'user data has authorizationIds array');
      
      // 验证返回的数据中不包含敏感信息
      assert(!userData.wallets, 'user data does not contain wallet details');
      assert(!userData.mnemonic, 'user data has no mnemonic field');
      assert(!userData.privateKey, 'user data has no privateKey field');
    }
  }
  
  // Test 3: Custom pagination parameters
  const body3 = await buildRequest({ page: 1, pageSize: 10 });
  const res3 = await httpPost('/api/admin/userId/list', body3);
  assert(res3.status === 200, 'admin/userId/list with pagination returns 200');
  const parsed3 = parseAttestationResponse(res3);
  assert(parsed3 && parsed3.data && parsed3.data.page === 1, 'admin/userId/list page=1');
  assert(parsed3 && parsed3.data && parsed3.data.pageSize <= 10, 'admin/userId/list pageSize respects limit');
  
  // Test 4: Pagination limit (pageSize max 100)
  const body4 = await buildRequest({ page: 1, pageSize: 200 });
  const res4 = await httpPost('/api/admin/userId/list', body4);
  assert(res4.status === 200, 'admin/userId/list with large pageSize returns 200');
  const parsed4 = parseAttestationResponse(res4);
  assert(parsed4 && parsed4.data && parsed4.data.pageSize <= 100, 'admin/userId/list pageSize capped at 100');
  
  console.log(`  [info] admin/userId/list: totalUsers=${parsed1?.data?.totalUsers}`);
}

// ============================================================
// 6. Auth error tests
// ============================================================
async function testAuthErrors() {
  console.log('\n=== Auth error tests ===');

  const badBody = { payload: JSON.stringify({ userId: 'test' }), platformSignature: '0x' + '00'.repeat(65) };
  const res1 = await httpPost('/api/passkey/list', badBody);
  assert(res1.status === 401, 'invalid signature returns 401');

  const otherWallet = ethers.Wallet.createRandom();
  const payloadStr = JSON.stringify({ userId: 'test' });
  const otherSig = await otherWallet.signMessage(payloadStr);
  const res2 = await httpPost('/api/passkey/list', { payload: payloadStr, platformSignature: otherSig });
  assert(res2.status === 401, 'non-whitelisted address returns 401');

  const body3 = await buildRequest({});
  const res3 = await httpPost('/api/passkey/list', body3);
  assert(res3.status === 400, 'missing required fields returns 400');
}

// ============================================================
// 7. Contract standalone tests (no TEE required)
// ============================================================

/**
 * 合约独立接口测试（不依赖 TEE，直接通过 ethers.js 调用合约）
 * 测试内容：
 *   - 配置管理（codeRepository / runtimeParams）
 *   - 平台白名单（add / remove / query）
 *   - Enclave 白名单（add / remove / query）
 *   - 授权撤销（revokeAuthorization + isAuthorizationRevoked + getRevokedAuthorizations）
 *   - 权限控制（非 owner 操作被拒绝）
 */
async function testContractStandalone() {
  console.log('\n=== Contract Standalone Tests ===');

  const contractEnv = loadContractEnv();
  if (!contractEnv) {
    skip('contract/standalone', 'no .env.contract file (run setup-contract.sh first)');
    return;
  }

  // 每次创建新的 provider 实例，避免 nonce 缓存问题
  const provider = new ethers.JsonRpcProvider(contractEnv.rpcUrl);

  // Hardhat 默认账户（私钥固定）
  const HARDHAT_OWNER_PRIVKEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
  const HARDHAT_ADDR1_PRIVKEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
  const ownerSigner = new ethers.Wallet(HARDHAT_OWNER_PRIVKEY, provider);
  const addr1Signer = new ethers.Wallet(HARDHAT_ADDR1_PRIVKEY, provider);

  // 等待 provider 连接稳定
  await provider.getBlockNumber();

  // 手动管理 nonce：从链上获取初始 nonce，然后手动递增
  // 这是最可靠的方式，避免 ethers.js 的 nonce 缓存问题
  const ownerAddr = ownerSigner.address;
  const addr1Addr = addr1Signer.address;
  let ownerNonce = await provider.getTransactionCount(ownerAddr, 'latest');
  let addr1Nonce = await provider.getTransactionCount(addr1Addr, 'latest');
  const getOwnerNonce = () => ownerNonce++;
  const getAddr1Nonce = () => addr1Nonce++;

  const contract = new ethers.Contract(contractEnv.contractAddress, WALLET_TRUST_CONTRACT_ABI, ownerSigner);
  const contractAsAddr1 = contract.connect(addr1Signer);

  // ---- 配置管理 ----
  console.log('\n  [Contract] Configuration Management');

  const testRepo = 'https://github.com/test/sgx-wallet-' + Date.now();
  const txRepo = await contract.updateCodeRepository(testRepo, { nonce: getOwnerNonce() });
  await txRepo.wait();
  const storedRepo = await contract.getCodeRepository();
  assert(storedRepo === testRepo, 'contract: updateCodeRepository + getCodeRepository');

  const testParams = JSON.stringify({ session: { importTtlSeconds: 600 }, test: true });
  const txParams = await contract.updateRuntimeParams(testParams, { nonce: getOwnerNonce() });
  await txParams.wait();
  const storedParams = await contract.getRuntimeParams();
  assert(storedParams === testParams, 'contract: updateRuntimeParams + getRuntimeParams');
  const parsedParams = JSON.parse(storedParams);
  assert(parsedParams.session && parsedParams.session.importTtlSeconds === 600, 'contract: runtimeParams JSON structure');

  // 非 owner 不能更新配置
  try {
    await contractAsAddr1.updateCodeRepository('https://evil.com');
    assert(false, 'contract: non-owner updateCodeRepository should revert');
  } catch (err) {
    assert(err.message.includes('OwnableUnauthorizedAccount') || err.message.includes('revert'), 'contract: non-owner updateCodeRepository reverts');
  }

  // ---- 平台白名单 ----
  console.log('\n  [Contract] Platform Whitelist');

  const testPlatformAddr = ethers.Wallet.createRandom().address;
  const txAdd = await contract.addPlatformAddress(testPlatformAddr, { nonce: getOwnerNonce() });
  await txAdd.wait();
  const isWhitelisted = await contract.isPlatformWhitelisted(testPlatformAddr);
  assert(isWhitelisted === true, 'contract: addPlatformAddress + isPlatformWhitelisted');

  const whitelist = await contract.getPlatformWhitelist();
  assert(whitelist.some(a => a.toLowerCase() === testPlatformAddr.toLowerCase()), 'contract: getPlatformWhitelist contains added address');

  const txRemove = await contract.removePlatformAddress(testPlatformAddr, { nonce: getOwnerNonce() });
  await txRemove.wait();
  const isWhitelistedAfter = await contract.isPlatformWhitelisted(testPlatformAddr);
  assert(isWhitelistedAfter === false, 'contract: removePlatformAddress');

  // 重复添加应该 revert
  const txAdd2 = await contract.addPlatformAddress(testPlatformAddr, { nonce: getOwnerNonce() });
  await txAdd2.wait();
  try {
    await contract.addPlatformAddress(testPlatformAddr);
    assert(false, 'contract: duplicate addPlatformAddress should revert');
  } catch (err) {
    assert(err.message.includes('Already whitelisted') || err.message.includes('revert'), 'contract: duplicate addPlatformAddress reverts');
  }
  // 清理
  await (await contract.removePlatformAddress(testPlatformAddr, { nonce: getOwnerNonce() })).wait();

  // 非 owner 不能操作白名单
  try {
    await contractAsAddr1.addPlatformAddress(testPlatformAddr);
    assert(false, 'contract: non-owner addPlatformAddress should revert');
  } catch (err) {
    assert(err.message.includes('OwnableUnauthorizedAccount') || err.message.includes('revert'), 'contract: non-owner addPlatformAddress reverts');
  }

  // ---- Enclave 白名单 ----
  console.log('\n  [Contract] Enclave Whitelist');

  const testMrenclave = ethers.encodeBytes32String('test-enclave-' + Date.now().toString().slice(-8));
  const testMrsigner = ethers.encodeBytes32String('test-signer');
  const txEnc = await contract.addEnclaveIdentity(testMrenclave, testMrsigner, 1, 0, 'Test Enclave v1', { nonce: getOwnerNonce() });
  await txEnc.wait();
  const isEncWhitelisted = await contract.isEnclaveWhitelisted(testMrenclave);
  assert(isEncWhitelisted === true, 'contract: addEnclaveIdentity + isEnclaveWhitelisted');

  const encWhitelist = await contract.getEnclaveWhitelist();
  const encEntry = encWhitelist.find(e => e.mrenclave === testMrenclave);
  assert(encEntry !== undefined, 'contract: getEnclaveWhitelist contains added entry');
  assert(encEntry && encEntry.isvprodid === 1n, 'contract: enclave identity isvprodid=1');
  assert(encEntry && encEntry.description === 'Test Enclave v1', 'contract: enclave identity description');

  const txEncRm = await contract.removeEnclaveIdentity(testMrenclave, { nonce: getOwnerNonce() });
  await txEncRm.wait();
  const isEncWhitelistedAfter = await contract.isEnclaveWhitelisted(testMrenclave);
  assert(isEncWhitelistedAfter === false, 'contract: removeEnclaveIdentity');

  // ---- getPublicInfo ----
  console.log('\n  [Contract] Public Info Query');

  const publicInfo = await contract.getPublicInfo();
  assert(typeof publicInfo[0] === 'string', 'contract: getPublicInfo[0] is string (codeRepository)');
  assert(typeof publicInfo[1] === 'string', 'contract: getPublicInfo[1] is string (runtimeParams)');
  assert(Array.isArray(publicInfo[2]), 'contract: getPublicInfo[2] is array (enclaveWhitelist)');

  // ---- 授权撤销 ----
  console.log('\n  [Contract] Authorization Revocation');

  const revokeUserId = 'test-user-' + crypto.randomBytes(4).toString('hex');
  const revokeAuthId = 'test-auth-' + crypto.randomBytes(4).toString('hex');
  const revokeGrantee = addr1Signer.address;

  // 生成 P256 密钥对
  const p256KeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const p256PubDer = p256KeyPair.publicKey.export({ type: 'spki', format: 'der' });
  const p256Uncompressed = p256PubDer.subarray(p256PubDer.length - 65);
  const pubKeyX = '0x' + p256Uncompressed.subarray(1, 33).toString('hex');
  const pubKeyY = '0x' + p256Uncompressed.subarray(33, 65).toString('hex');

  // 签名
  const { r, s } = signP256ForRevocation(p256KeyPair.privateKey, revokeUserId, revokeAuthId, revokeGrantee);

  // 撤销前检查
  const isRevokedBefore = await contract.isAuthorizationRevoked(revokeUserId, revokeAuthId);
  assert(isRevokedBefore === false, 'contract: isAuthorizationRevoked=false before revocation');

  // 执行撤销（任何人都可以调用，只要签名正确）
  const txRevoke = await contractAsAddr1.revokeAuthorization(
    revokeUserId, revokeAuthId, revokeGrantee,
    pubKeyX, pubKeyY, r, s,
    { nonce: getAddr1Nonce() }
  );
  await txRevoke.wait();

  // 撤销后检查
  const isRevokedAfter = await contract.isAuthorizationRevoked(revokeUserId, revokeAuthId);
  assert(isRevokedAfter === true, 'contract: isAuthorizationRevoked=true after revocation');

  // 获取撤销记录
  const records = await contract.getRevokedAuthorizations(revokeUserId);
  assert(records.length === 1, 'contract: getRevokedAuthorizations has 1 record');
  assert(records[0].authorizationId === revokeAuthId, 'contract: revocation record authorizationId matches');
  assert(records[0].grantee.toLowerCase() === revokeGrantee.toLowerCase(), 'contract: revocation record grantee matches');
  assert(records[0].passkeyPubKeyX === pubKeyX, 'contract: revocation record pubKeyX matches');
  assert(records[0].passkeyPubKeyY === pubKeyY, 'contract: revocation record pubKeyY matches');
  assert(records[0].revokedAt > 0n, 'contract: revocation record revokedAt > 0');

  // 重复撤销应该 revert
  try {
    await contractAsAddr1.revokeAuthorization(
      revokeUserId, revokeAuthId, revokeGrantee,
      pubKeyX, pubKeyY, r, s
    );
    assert(false, 'contract: duplicate revokeAuthorization should revert');
  } catch (err) {
    assert(err.message.includes('Already revoked') || err.message.includes('revert'), 'contract: duplicate revokeAuthorization reverts');
  }

  // 错误签名应该 revert
  const wrongKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { r: wrongR, s: wrongS } = signP256ForRevocation(wrongKeyPair.privateKey, revokeUserId, 'wrong-auth', revokeGrantee);
  try {
    await contractAsAddr1.revokeAuthorization(
      revokeUserId, 'another-auth-' + crypto.randomBytes(4).toString('hex'), revokeGrantee,
      pubKeyX, pubKeyY, wrongR, wrongS
    );
    assert(false, 'contract: wrong signature revokeAuthorization should revert');
  } catch (err) {
    assert(err.message.includes('Invalid P256 signature') || err.message.includes('revert'), 'contract: wrong signature revokeAuthorization reverts');
  }

  // 恢复 runtimeParams（确保 cache.refreshInterval=5000，供后续 TEE 协作测试使用）
  const restoreParams = JSON.stringify({
    session: { importTtlSeconds: 300, exportTtlSeconds: 86400 },
    cache: { refreshInterval: 5000 },
  });
  await (await contract.updateRuntimeParams(restoreParams, { nonce: getOwnerNonce() })).wait();
  console.log(`  [info] runtimeParams restored (refreshInterval=5s)`);

  console.log(`  [info] Contract standalone tests completed`);
}

// ============================================================
// 8. Contract + TEE collaboration tests
// ============================================================

/**
 * 合约与 TEE 协作测试
 * 测试内容：
 *   1. TEE 从合约读取 runtimeParams（通过 /api/enclave/info 验证）
 *   2. TEE 从合约读取平台白名单（通过白名单验证机制测试）
 *   3. 授权撤销联动：在合约上撤销授权后，TEE 的 tx/sign 应该被拒绝
 */
async function testContractTeeCollaboration() {
  console.log('\n=== Contract + TEE Collaboration Tests ===');

  const contractEnv = loadContractEnv();
  if (!contractEnv) {
    skip('contract/tee/collaboration', 'no .env.contract file (run setup-contract.sh first)');
    return;
  }

  if (!state.userId || !state.walletAddress) {
    skip('contract/tee/collaboration', 'no userId or walletAddress (TEE tests must run first)');
    return;
  }

  const provider = new ethers.JsonRpcProvider(contractEnv.rpcUrl);
  const HARDHAT_OWNER_PRIVKEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
  const ownerSigner = new ethers.Wallet(HARDHAT_OWNER_PRIVKEY, provider);
  await provider.getBlockNumber();
  const ownerAddrTee = ownerSigner.address;
  let ownerNonceTee = await provider.getTransactionCount(ownerAddrTee, 'latest');
  const getOwnerNonceTee = () => ownerNonceTee++;
  const contract = new ethers.Contract(contractEnv.contractAddress, WALLET_TRUST_CONTRACT_ABI, ownerSigner);

  // ---- 测试 1: TEE 从合约读取 runtimeParams ----
  console.log('\n  [Contract+TEE] Test 1: TEE reads runtimeParams from contract');

  // 更新合约 runtimeParams（保持 refreshInterval=5s，便于后续白名单测试）
  const newParams = JSON.stringify({
    session: { importTtlSeconds: 300, exportTtlSeconds: 86400, cleanupIntervalSeconds: 3600 },
    cache: { refreshInterval: 5000 },
  });
  const txParams = await contract.updateRuntimeParams(newParams, { nonce: getOwnerNonceTee() });
  await txParams.wait();

  // 通过 /api/enclave/info 验证 TEE 能读取到合约配置
  // 注意：TEE 有缓存，可能不会立即反映最新值，这里只验证接口可用
  const infoRes = await httpPost('/api/enclave/info', {});
  assert(infoRes.status === 200, 'contract+tee: enclave/info returns 200 (contract connected)');
  const infoParsed = parseAttestationResponse(infoRes);
  assert(infoParsed !== null, 'contract+tee: enclave/info has valid response');
  console.log(`  [info] enclave/info status=${infoRes.status}, has runtimeParams=${!!infoParsed?.data}`);

  // ---- 测试 2: 合约平台白名单覆盖 env 白名单 ----
  console.log('\n  [Contract+TEE] Test 2: Contract platform whitelist overrides env whitelist');

  // 测试思路：
  // 1. 在合约上添加一个全新的随机地址（不在 env PLATFORM_WHITELIST 中）
  // 2. 等待 TEE 缓存刷新（setup-contract.sh 设置 refreshInterval=5s，等待 8 秒）
  // 3. 用这个新地址签名，验证 TEE 接受它（证明合约白名单覆盖了 env 白名单）
  // 4. 清理：从合约移除该地址，等待缓存刷新，验证 TEE 拒绝该地址

  // 在合约上添加一个新的随机地址（不在 env 白名单中）
  const newPlatformWallet = ethers.Wallet.createRandom();
  const newPlatformAddr = newPlatformWallet.address;
  const txAddNew = await contract.addPlatformAddress(newPlatformAddr, { nonce: getOwnerNonceTee() });
  await txAddNew.wait();
  const isNewAddrWhitelisted = await contract.isPlatformWhitelisted(newPlatformAddr);
  assert(isNewAddrWhitelisted === true, 'contract+tee: new address added to contract whitelist');
  console.log(`  [info] New address added to contract whitelist: ${newPlatformAddr}`);

  // 等待 TEE 缓存刷新（refreshInterval=5s，等待 12 秒确保刷新完成）
  console.log(`  [info] Waiting 12s for TEE cache refresh (refreshInterval=5s)...`);
  await new Promise(r => setTimeout(r, 12000));

  // 用新地址签名，验证 TEE 接受它（证明合约白名单覆盖了 env 白名单）
  const newAddrPayload = JSON.stringify({ userId: state.userId });
  const newAddrSig = await newPlatformWallet.signMessage(newAddrPayload);
  const newAddrRes = await httpPost('/api/passkey/list', {
    payload: newAddrPayload,
    platformSignature: newAddrSig,
  });
  // 新地址在合约白名单中，TEE 应该接受（返回 200 或 400，不是 401）
  assert(newAddrRes.status !== 401, 'contract+tee: new contract-whitelisted address is accepted by TEE (not 401)');
  console.log(`  [info] New contract-whitelisted address accepted by TEE: status=${newAddrRes.status}`);

  // 清理：从合约移除新添加的地址
  await (await contract.removePlatformAddress(newPlatformAddr, { nonce: getOwnerNonceTee() })).wait();
  console.log(`  [info] New address removed from contract whitelist`);

  // 等待 TEE 缓存刷新（确保移除生效，等待 12 秒）
  console.log(`  [info] Waiting 12s for TEE cache refresh after removal...`);
  await new Promise(r => setTimeout(r, 12000));

  // 验证移除后 TEE 拒绝该地址
  const removedAddrSig = await newPlatformWallet.signMessage(newAddrPayload);
  const removedAddrRes = await httpPost('/api/passkey/list', {
    payload: newAddrPayload,
    platformSignature: removedAddrSig,
  });
  assert(removedAddrRes.status === 401, 'contract+tee: removed address is rejected by TEE (401)');
  console.log(`  [info] Removed address correctly rejected by TEE: status=${removedAddrRes.status}`);

  // 验证合约白名单中有测试平台地址（已在 setup-contract.sh 中添加）
  const isTestAddrWhitelisted = await contract.isPlatformWhitelisted(PLATFORM_ADDRESS);
  assert(isTestAddrWhitelisted === true, 'contract+tee: test platform address is in contract whitelist');

  // 用非白名单地址签名，TEE 应该拒绝（基本白名单功能验证）
  const nonWhitelistedWallet = ethers.Wallet.createRandom();
  const testPayload = JSON.stringify({ userId: state.userId });
  const nonWhitelistedSig = await nonWhitelistedWallet.signMessage(testPayload);
  const nonWhitelistedRes = await httpPost('/api/passkey/list', {
    payload: testPayload,
    platformSignature: nonWhitelistedSig,
  });
  assert(nonWhitelistedRes.status === 401, 'contract+tee: non-whitelisted address returns 401');
  console.log(`  [info] non-whitelisted address correctly rejected: status=${nonWhitelistedRes.status}`);

  // ---- 测试 3: 授权撤销联动 ----
  console.log('\n  [Contract+TEE] Test 3: Authorization revocation via contract');

  // 3a. 先创建一个新钱包用于撤销测试（原钱包可能已被 export/complete 删除）
  let revokeTestWalletAddress = state.walletAddress;
  try {
    const revokeCreateChains = [{ chainId: 1, coinType: 60 }];
    const revokeCreateIntentJson = JSON.stringify({
      purpose: 'wallet_create',
      userId: state.userId,
      chains: revokeCreateChains,
    });
    const revokeCreateChallengeRes = await httpPost('/api/challenge', await buildRequest({
      userId: state.userId,
      credentialId: state.credentialId,
      purpose: 'wallet_create',
    }));
    const revokeCreateChallengeParsed = parseAttestationResponse(revokeCreateChallengeRes);
    if (revokeCreateChallengeParsed && revokeCreateChallengeParsed.data && revokeCreateChallengeParsed.data.challenge) {
      const ch = revokeCreateChallengeParsed.data.challenge;
      const ws = makeWebAuthnSignature(computeIntentHash(ch, revokeCreateIntentJson));
      const revokeCreateBody = await buildRequest({
        userId: state.userId,
        credentialId: state.credentialId,
        webauthnSignature: ws,
        rawChallenge: ch,
        userIntentJson: revokeCreateIntentJson,
        chains: revokeCreateChains,
      });
      const revokeCreateRes = await httpPost('/api/wallet/create', revokeCreateBody);
      const revokeCreateParsed = parseAttestationResponse(revokeCreateRes);
      if (revokeCreateParsed && revokeCreateParsed.data && revokeCreateParsed.data.walletId) {
        const revokeWalletId = revokeCreateParsed.data.walletId;
        const revokeGetBody = await buildRequest({ userId: state.userId, walletId: revokeWalletId });
        const revokeGetRes = await httpPost('/api/wallet/get', revokeGetBody);
        const revokeGetParsed = parseAttestationResponse(revokeGetRes);
        const revokeWalletData = revokeGetParsed?.data?.wallet;
        if (revokeWalletData && revokeWalletData.wallets && revokeWalletData.wallets[0]?.addresses?.[0]?.address) {
          revokeTestWalletAddress = revokeWalletData.wallets[0].addresses[0].address;
          console.log(`  [info] Created new wallet for revocation test: ${revokeTestWalletAddress}`);
        }
      }
    }
  } catch (err) {
    console.warn(`  [warn] Failed to create new wallet for revocation test, using existing: ${err.message}`);
  }

  // 3b. 先创建一个新的授权并成功签名一次
  const revokeTestAuthId = `revoke-test-${crypto.randomBytes(6).toString('hex')}`;
  const revokeAuthJson = JSON.stringify({
    userId: state.userId,
    authorizationId: revokeTestAuthId,
    grantee: [PLATFORM_ADDRESS],
    credentialId: state.credentialId,
    scope: {
      targetAddresses: [{ chainId: '1', address: '0x' + '00'.repeat(20) }],
      signingWallets: [{ chainId: '1', address: revokeTestWalletAddress }],
      tokenRestrictions: [{ chainId: '1', tokenAddress: '1_native' }],
      cumulativeLimits: {
        maxTxCount: 10,
        tokenLimits: { '1_native': '1000000000000000000' },
      },
    },
    timePolicy: {
      deadline: new Date(Date.now() + 86400 * 1000).toISOString(),
    },
    revocationPolicy: {
      allowContractUnavailable: false,  // 必须检查合约撤销状态
    },
    createdAt: new Date().toISOString(),
  });

  const revokeAuthHash = computeAuthorizationHash(revokeAuthJson);
  const revokeWebauthnSig = makeWebAuthnSignature(revokeAuthHash);

  // 第一次签名（应该成功）
  const signBody1 = await buildRequest({
    guid: crypto.randomUUID(),
    authorizationJson: revokeAuthJson,
    webauthnSignature: revokeWebauthnSig,
    transaction: {
      chainId: '1',
      fromAddress: revokeTestWalletAddress,
      toAddress: '0x' + '00'.repeat(20),
      value: '0',
      data: '0x',
      gasLimit: '21000',
      maxFeePerGas: '1000000000',
      maxPriorityFeePerGas: '1000000',
      nonce: 0,
      type: 2,
      amount: '0',
      tokenAddress: '1_native',
    },
  });
  const signRes1 = await httpPost('/api/tx/sign', signBody1);
  assert(signRes1.status === 200, 'contract+tee: first tx/sign before revocation returns 200');
  const signParsed1 = parseAttestationResponse(signRes1);
  assert(signParsed1 && signParsed1.data && signParsed1.data.success === true, 'contract+tee: first tx/sign success=true');
  console.log(`  [info] First sign before revocation: success=${signParsed1?.data?.success}`);

  // 3b. 在合约上撤销该授权
  // 需要用 Passkey P256 私钥签名（测试中使用 p256KeyPair.privateKey）
  const { r: revokeR, s: revokeS } = signP256ForRevocation(
    p256KeyPair.privateKey,
    state.userId,
    revokeTestAuthId,
    PLATFORM_ADDRESS
  );
  const p256PubDer = p256KeyPair.publicKey.export({ type: 'spki', format: 'der' });
  const p256Uncompressed = p256PubDer.subarray(p256PubDer.length - 65);
  const pubKeyX = '0x' + p256Uncompressed.subarray(1, 33).toString('hex');
  const pubKeyY = '0x' + p256Uncompressed.subarray(33, 65).toString('hex');

  const txRevoke = await contract.revokeAuthorization(
    state.userId, revokeTestAuthId, PLATFORM_ADDRESS,
    pubKeyX, pubKeyY, revokeR, revokeS,
    { nonce: getOwnerNonceTee() }
  );
  await txRevoke.wait();
  console.log(`  [info] Authorization revoked on contract: authId=${revokeTestAuthId}`);

  // 验证合约上已撤销
  const isRevoked = await contract.isAuthorizationRevoked(state.userId, revokeTestAuthId);
  assert(isRevoked === true, 'contract+tee: isAuthorizationRevoked=true after revocation');

  // 3c. 再次尝试签名（应该被拒绝，因为 allowContractUnavailable=false 且合约已撤销）
  // 注意：TEE 有合约查询缓存，可能需要等待缓存过期
  // 这里等待 2 秒后重试（实际生产中缓存间隔更长，测试中用短间隔）
  await new Promise(r => setTimeout(r, 2000));

  const revokeAuthHash2 = computeAuthorizationHash(revokeAuthJson);
  const revokeWebauthnSig2 = makeWebAuthnSignature(revokeAuthHash2);
  const signBody2 = await buildRequest({
    guid: crypto.randomUUID(),  // 新的 guid（防重放）
    authorizationJson: revokeAuthJson,
    webauthnSignature: revokeWebauthnSig2,
    transaction: {
      chainId: '1',
      fromAddress: revokeTestWalletAddress,
      toAddress: '0x' + '00'.repeat(20),
      value: '0',
      data: '0x',
      gasLimit: '21000',
      maxFeePerGas: '1000000000',
      maxPriorityFeePerGas: '1000000',
      nonce: 1,
      type: 2,
      amount: '0',
      tokenAddress: '1_native',
    },
  });
  const signRes2 = await httpPost('/api/tx/sign', signBody2);
  // 撤销后签名应该失败（success=false 或 status!=200）
  const signParsed2 = parseAttestationResponse(signRes2);
  const isRejectedAfterRevocation = (
    signRes2.status !== 200 ||
    (signParsed2 && signParsed2.data && signParsed2.data.success === false)
  );
  assert(isRejectedAfterRevocation, 'contract+tee: tx/sign after revocation is rejected');
  console.log(`  [info] Sign after revocation: status=${signRes2.status}, success=${signParsed2?.data?.success}, reason=${signParsed2?.data?.reason || 'N/A'}`);

  // ---- 测试 4: 合约 runtimeParams 影响 TEE 行为 ----
  console.log('\n  [Contract+TEE] Test 4: Contract runtimeParams affects TEE behavior');

  // 验证 TEE 能正常响应（合约连接正常时）
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    purpose: 'register',
    userId: `contract-test-user-${crypto.randomBytes(4).toString('hex')}`,
  }));
  assert(challengeRes.status === 200, 'contract+tee: challenge returns 200 (contract connected)');
  console.log(`  [info] Challenge with contract connected: status=${challengeRes.status}`);

  console.log(`  [info] Contract + TEE collaboration tests completed`);
}

// ============================================================
// Passkey Recovery Tests (Contract + TEE)
// ============================================================

async function testPasskeyRecovery() {
  console.log('\n=== Passkey Recovery Tests (Contract + TEE, Scenario C) ===');

  const contractEnv = loadContractEnv();
  if (!contractEnv) {
    skip('recovery/all', 'no .env.contract file (run setup-contract.sh first)');
    return;
  }

  const provider = new ethers.JsonRpcProvider(contractEnv.rpcUrl);
  const HARDHAT_OWNER_PRIVKEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
  const ownerSigner = new ethers.Wallet(HARDHAT_OWNER_PRIVKEY, provider);
  await provider.getBlockNumber();
  let ownerNonce = await provider.getTransactionCount(ownerSigner.address, 'latest');
  const getOwnerNonce = () => ownerNonce++;
  const contract = new ethers.Contract(contractEnv.contractAddress, WALLET_TRUST_CONTRACT_ABI, ownerSigner);

  // ---- Pre-setup: set short freeze duration (5s) so replay test can run after freeze expires ----
  // testContractTeeCollaboration() may have reset runtimeParams without security.freezeDurationSeconds
  // We need 5s freeze so the replay test (Test 4) can wait for it to expire.
  {
    const currentParamsStr = await contract.getRuntimeParams();
    let currentParams = {};
    try { currentParams = JSON.parse(currentParamsStr); } catch {}
    currentParams.security = currentParams.security || {};
    currentParams.security.freezeDurationSeconds = 5;
    const txFreezeShort = await contract.updateRuntimeParams(JSON.stringify(currentParams), { nonce: getOwnerNonce() });
    await txFreezeShort.wait();
    console.log('  [Recovery] Set security.freezeDurationSeconds=5 on contract, waiting 12s for TEE cache refresh...');
    await new Promise(r => setTimeout(r, 12000));
  }

  // ---- Setup: create a user with passkey + wallet (needed for recovery) ----
  console.log('\n  [Recovery] Setup: create user with passkey and wallet');

  // Generate "old" P256 keypair (the one the user will "lose")
  const oldP256 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const oldPubDer = oldP256.publicKey.export({ type: 'spki', format: 'der' });
  const oldUnc = oldPubDer.subarray(26);
  const oldPkX = oldUnc.subarray(1, 33);
  const oldPkY = oldUnc.subarray(33, 65);
  const oldCredIdBuf = crypto.randomBytes(32);
  const oldCredId = oldCredIdBuf.toString('base64url');
  const oldPublicKeyCose = cborEncode(new Map([
    [1, 2], [3, -7], [-1, 1], [-2, oldPkX], [-3, oldPkY],
  ]));

  // Register the old passkey
  const setupChallengeRes = await httpPost('/api/challenge', await buildRequest({
    purpose: 'register',
  }));
  const setupChallengeParsed = parseAttestationResponse(setupChallengeRes);
  assert(setupChallengeParsed && setupChallengeParsed.data && setupChallengeParsed.data.challenge, 'recovery/setup: register challenge OK');
  if (!setupChallengeParsed?.data?.challenge) return;

  const recoveryUserId = setupChallengeParsed.data.userId;
  const setupAttestation = makeWebAuthnRegistrationResponse(setupChallengeParsed.data.challenge, {
    credentialId: oldCredIdBuf,
    publicKeyX: oldPkX,
    publicKeyY: oldPkY,
  });
  const setupRegRes = await httpPost('/api/passkey/register/complete', await buildRequest({
    userId: recoveryUserId,
    attestationResponse: setupAttestation,
  }));
  assert(setupRegRes.status === 200, 'recovery/setup: register old passkey OK');
  console.log(`  [info] Recovery user created: ${recoveryUserId}, credentialId=${oldCredId}`);

  // Create a wallet for this user (so recovery triggers freeze)
  // Need to track signCount for the old key separately
  let oldSignCount = 0;
  function makeOldWebAuthnSignature(challenge) {
    oldSignCount++;
    const rpIdHash = crypto.createHash('sha256').update('localhost').digest();
    const flags = Buffer.from([0x01]);
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(oldSignCount);
    const authenticatorData = Buffer.concat([rpIdHash, flags, counterBuf]);
    const challengeB64 = typeof challenge === 'string' ? challenge : toBase64URL(challenge + '');
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.get', challenge: challengeB64, origin: 'https://localhost', crossOrigin: false,
    }));
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
    const signedData = Buffer.concat([authenticatorData, clientDataHash]);
    const derSig = crypto.createSign('SHA256').update(signedData).end().sign(oldP256.privateKey);
    return {
      id: oldCredId, rawId: oldCredId, type: 'public-key',
      response: {
        authenticatorData: toBase64URL(authenticatorData),
        clientDataJSON: toBase64URL(clientDataJSON),
        signature: toBase64URL(derSig),
        userHandle: null,
      },
    };
  }

  const walletCreateChains = [{ chainId: 1, coinType: 60 }];
  const walletCreateIntentJson = JSON.stringify({
    purpose: 'wallet_create', userId: recoveryUserId, chains: walletCreateChains,
  });
  const walletChRes = await httpPost('/api/challenge', await buildRequest({
    userId: recoveryUserId, credentialId: oldCredId, purpose: 'wallet_create',
  }));
  const walletChParsed = parseAttestationResponse(walletChRes);
  if (walletChParsed?.data?.challenge) {
    const ch = walletChParsed.data.challenge;
    const ws = makeOldWebAuthnSignature(computeIntentHash(ch, walletCreateIntentJson));
    const createWalletRes = await httpPost('/api/wallet/create', await buildRequest({
      userId: recoveryUserId, credentialId: oldCredId,
      webauthnSignature: ws, rawChallenge: ch, userIntentJson: walletCreateIntentJson,
      chains: walletCreateChains,
    }));
    assert(createWalletRes.status === 200, 'recovery/setup: wallet create OK');
    console.log(`  [info] Wallet created for recovery user`);
  }

  // ---- Test 1: Recovery without contract entry → rejected ----
  console.log('\n  [Recovery] Test 1: No contract recovery entry → rejected');

  // Generate "new" P256 keypair (recovery passkey)
  const newP256 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const newPubDer = newP256.publicKey.export({ type: 'spki', format: 'der' });
  const newUnc = newPubDer.subarray(26);
  const newPkX = newUnc.subarray(1, 33);
  const newPkY = newUnc.subarray(33, 65);
  const newCredIdBuf = crypto.randomBytes(32);
  const newCredId = newCredIdBuf.toString('base64url');
  const newPublicKeyCose = cborEncode(new Map([
    [1, 2], [3, -7], [-1, 1], [-2, newPkX], [-3, newPkY],
  ]));

  // Compute hashes (same as PasskeyManager.computePubKeyHash)
  const newPubKeyHash = '0x' + crypto.createHash('sha256').update(newPublicKeyCose).digest('hex');
  const oldPubKeyHash = '0x' + crypto.createHash('sha256').update(oldPublicKeyCose).digest('hex');

  // Try recovery WITHOUT setting contract entry — should be rejected
  const noEntryChRes = await httpPost('/api/challenge', await buildRequest({
    purpose: 'register', userId: recoveryUserId,
  }));
  const noEntryChParsed = parseAttestationResponse(noEntryChRes);
  if (noEntryChParsed?.data?.challenge) {
    const attestation = makeWebAuthnRegistrationResponse(noEntryChParsed.data.challenge, {
      credentialId: newCredIdBuf, publicKeyX: newPkX, publicKeyY: newPkY,
    });
    const noEntryRes = await httpPost('/api/passkey/register/complete', await buildRequest({
      userId: recoveryUserId, attestationResponse: attestation,
      // No existingCredentialId or existingWebauthnSignature → triggers recovery path
    }));
    assert(noEntryRes.status !== 200, 'recovery/noEntry: rejected without contract entry');
    console.log(`  [info] No contract entry → status=${noEntryRes.status}`);
  }

  // ---- Test 2: Recovery with wrong oldPubKeyHash → rejected ----
  console.log('\n  [Recovery] Test 2: Wrong oldPubKeyHash → rejected');

  // Set a recovery entry with a WRONG oldPubKeyHash
  const wrongOldHash = '0x' + crypto.randomBytes(32).toString('hex');
  const txWrong = await contract.setPasskeyRecovery(
    recoveryUserId, newPubKeyHash, wrongOldHash, 'wrong-uuid-001', 'test wrong hash',
    { nonce: getOwnerNonce() }
  );
  await txWrong.wait();

  const wrongChRes = await httpPost('/api/challenge', await buildRequest({
    purpose: 'register', userId: recoveryUserId,
  }));
  const wrongChParsed = parseAttestationResponse(wrongChRes);
  if (wrongChParsed?.data?.challenge) {
    const attestation = makeWebAuthnRegistrationResponse(wrongChParsed.data.challenge, {
      credentialId: newCredIdBuf, publicKeyX: newPkX, publicKeyY: newPkY,
    });
    const wrongRes = await httpPost('/api/passkey/register/complete', await buildRequest({
      userId: recoveryUserId, attestationResponse: attestation,
    }));
    assert(wrongRes.status !== 200, 'recovery/wrongHash: rejected with wrong oldPubKeyHash');
    console.log(`  [info] Wrong oldPubKeyHash → status=${wrongRes.status}`);
  }

  // Clean up wrong entry
  await (await contract.removePasskeyRecovery(recoveryUserId, newPubKeyHash, { nonce: getOwnerNonce() })).wait();

  // ---- Test 3: Recovery with correct entry → success ----
  console.log('\n  [Recovery] Test 3: Correct recovery entry → success with freeze');

  const recoveryUuid = `recovery-${crypto.randomBytes(6).toString('hex')}`;
  const txCorrect = await contract.setPasskeyRecovery(
    recoveryUserId, newPubKeyHash, oldPubKeyHash, recoveryUuid, 'test correct recovery',
    { nonce: getOwnerNonce() }
  );
  await txCorrect.wait();

  // Verify entry exists on contract
  const exists = await contract.passkeyRecoveryExists(recoveryUserId, newPubKeyHash);
  assert(exists === true, 'recovery/correct: contract entry exists');

  const correctChRes = await httpPost('/api/challenge', await buildRequest({
    purpose: 'register', userId: recoveryUserId,
  }));
  const correctChParsed = parseAttestationResponse(correctChRes);
  assert(correctChParsed?.data?.challenge, 'recovery/correct: got challenge');

  if (correctChParsed?.data?.challenge) {
    const attestation = makeWebAuthnRegistrationResponse(correctChParsed.data.challenge, {
      credentialId: newCredIdBuf, publicKeyX: newPkX, publicKeyY: newPkY,
    });
    const correctRes = await httpPost('/api/passkey/register/complete', await buildRequest({
      userId: recoveryUserId, attestationResponse: attestation,
    }));
    assert(correctRes.status === 200, 'recovery/correct: returns 200');
    const correctParsed = parseAttestationResponse(correctRes);
    assert(correctParsed?.data?.recovery === true, 'recovery/correct: recovery=true');
    assert(correctParsed?.data?.recoveryUuid === recoveryUuid, 'recovery/correct: recoveryUuid matches');
    assert(correctParsed?.data?.frozen === true, 'recovery/correct: frozen=true (account has wallets)');
    assert(!!correctParsed?.data?.freezeUntil, 'recovery/correct: freezeUntil is set');
    console.log(`  [info] Recovery success: recovery=${correctParsed?.data?.recovery}, uuid=${correctParsed?.data?.recoveryUuid}, frozen=${correctParsed?.data?.frozen}, freezeUntil=${correctParsed?.data?.freezeUntil}`);
  }

  // Wait for the 5s freeze to expire before testing replay
  console.log('  [Recovery] Waiting 8s for freeze to expire (freezeDurationSeconds=5)...');
  await new Promise(r => setTimeout(r, 8000));

  // ---- Test 4: Replay recovery → rejected (old passkey already replaced) ----
  console.log('\n  [Recovery] Test 4: Replay recovery → rejected');

  // The old passkey has been replaced, so oldPubKeyHash no longer matches any existing passkey
  // Need a NEW newPubKeyHash for a new recovery attempt (same newPubKeyHash challenge was consumed)
  const replayP256 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const replayPubDer = replayP256.publicKey.export({ type: 'spki', format: 'der' });
  const replayUnc = replayPubDer.subarray(26);
  const replayPkX = replayUnc.subarray(1, 33);
  const replayPkY = replayUnc.subarray(33, 65);
  const replayCredIdBuf = crypto.randomBytes(32);
  const replayPublicKeyCose = cborEncode(new Map([
    [1, 2], [3, -7], [-1, 1], [-2, replayPkX], [-3, replayPkY],
  ]));
  const replayNewPubKeyHash = '0x' + crypto.createHash('sha256').update(replayPublicKeyCose).digest('hex');

  // Set a new recovery entry using the OLD oldPubKeyHash (which no longer matches any passkey)
  const txReplay = await contract.setPasskeyRecovery(
    recoveryUserId, replayNewPubKeyHash, oldPubKeyHash, 'replay-uuid', 'test replay',
    { nonce: getOwnerNonce() }
  );
  await txReplay.wait();

  const replayChRes = await httpPost('/api/challenge', await buildRequest({
    purpose: 'register', userId: recoveryUserId,
  }));
  const replayChParsed = parseAttestationResponse(replayChRes);
  if (replayChParsed?.data?.challenge) {
    const attestation = makeWebAuthnRegistrationResponse(replayChParsed.data.challenge, {
      credentialId: replayCredIdBuf, publicKeyX: replayPkX, publicKeyY: replayPkY,
    });
    const replayRes = await httpPost('/api/passkey/register/complete', await buildRequest({
      userId: recoveryUserId, attestationResponse: attestation,
    }));
    // Should fail because oldPubKeyHash doesn't match any current passkey (it was replaced)
    assert(replayRes.status !== 200, 'recovery/replay: rejected (old passkey already replaced)');
    console.log(`  [info] Replay recovery → status=${replayRes.status}`);
  }

  console.log(`  [info] Passkey recovery tests completed`);
}

// ============================================================
// Account Freeze Tests
// ============================================================


// 注：有钱包无Passkey的状态设计上不可能出现，相关测试已移除

async function testAccountFreezeNoFreezeNewUser() {
  console.log('\n=== Freeze Test 1: New user registration does NOT trigger freeze ===');

  // 全新用户，不提供 userId（由服务端生成）
  const challengeRes = await httpPost('/api/challenge', await buildRequest({
    purpose: 'register',
  }));
  assert(challengeRes.status === 200, 'freeze/noFreezeNewUser: register challenge returns 200');
  const challengeParsed = parseAttestationResponse(challengeRes);
  assert(challengeParsed && challengeParsed.data && challengeParsed.data.challenge, 'freeze/noFreezeNewUser: has challenge');

  if (!challengeParsed || !challengeParsed.data || !challengeParsed.data.challenge) {
    return;
  }

  const newUserId = challengeParsed.data.userId;
  const newCredIdBuf = crypto.randomBytes(32);
  const newP256Key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const newPubDer = newP256Key.publicKey.export({ type: 'spki', format: 'der' });
  const newUnc = newPubDer.subarray(26);
  const newPkX = newUnc.subarray(1, 33);
  const newPkY = newUnc.subarray(33, 65);

  const attestationResponse = makeWebAuthnRegistrationResponse(challengeParsed.data.challenge, {
    credentialId: newCredIdBuf,
    publicKeyX: newPkX,
    publicKeyY: newPkY,
  });

  const registerBody = await buildRequest({
    attestationResponse,
  });
  const registerRes = await httpPost('/api/passkey/register/complete', registerBody);
  assert(registerRes.status === 200, 'freeze/noFreezeNewUser: register returns 200');
  const registerParsed = parseAttestationResponse(registerRes);
  assert(registerParsed && registerParsed.data && registerParsed.data.isFirstPasskey === true, 'freeze/noFreezeNewUser: isFirstPasskey=true');
  assert(registerParsed && registerParsed.data && !registerParsed.data.frozen, 'freeze/noFreezeNewUser: frozen is NOT present (new user, no wallets)');
  console.log(`  [info] New user ${newUserId} registered without freeze`);
}

// ============================================================
// 9. Main
// ============================================================

// Parse additional command line arguments
const RUN_CONTRACT_TESTS = process.argv.includes('--contract') || process.argv.includes('--with-contract');
const CONTRACT_TESTS_ONLY = process.argv.includes('--contract-only');

if (RUN_CONTRACT_TESTS) {
  console.log('[Setup] CONTRACT mode: will run contract tests (requires setup-contract.sh)');
}
if (CONTRACT_TESTS_ONLY) {
  console.log('[Setup] CONTRACT-ONLY mode: only contract standalone tests (no TEE required)');
}

async function main() {
  console.log('==================================================');
  console.log('  SGX Enclave Integration Test');
  console.log('  Docker + HTTP API + real crypto');
  if (RUN_CONTRACT_TESTS || CONTRACT_TESTS_ONLY) {
    console.log('  + WalletTrustContract tests');
  }
  console.log('==================================================');
  console.log(`Platform address: ${PLATFORM_ADDRESS}`);
  console.log(`P256 pubkey X: ${PUBLIC_KEY_X.toString('hex').substring(0, 16)}...`);
  console.log(`P256 pubkey Y: ${PUBLIC_KEY_Y.toString('hex').substring(0, 16)}...`);

  let exitCode = 0;

  // ============================================================
  // CONTRACT-ONLY mode: 只跑合约独立测试，不启动 TEE
  // ============================================================
  if (CONTRACT_TESTS_ONLY) {
    try {
      await testContractStandalone();
    } catch (err) {
      console.error('\n[FATAL] Contract standalone test error:', err);
      exitCode = 1;
    } finally {
      if (!KEEP_CONTAINER) stopHardhatNode();
    }

    console.log('\n==================================================');
    console.log('  Test Results Summary (Contract Only)');
    console.log('==================================================');
    console.log(`  PASSED:  ${passed}`);
    console.log(`  FAILED:  ${failed}`);
    console.log(`  SKIPPED: ${skipped}`);
    console.log(`  TOTAL:   ${passed + failed + skipped}`);
    if (failed > 0) {
      console.log('\n  Failed:');
      for (const r of results.filter((r) => r.status === 'FAIL')) {
        console.log(`    FAIL ${r.name} ${r.detail ? '-- ' + r.detail : ''}`);
      }
      exitCode = 1;
    }
    process.exit(exitCode);
    return;
  }

  // ============================================================
  // 完整测试流程（TEE + 可选合约测试）
  // ============================================================
  try {
    cleanup();

    // 如果需要合约测试，先启动 Hardhat 节点并部署合约
    if (RUN_CONTRACT_TESTS) {
      console.log('\n[Setup] Setting up WalletTrustContract...');
      try {
        execSync(
          `${path.join(__dirname, 'setup-contract.sh')} ${PLATFORM_ADDRESS}`,
          { stdio: 'inherit', timeout: 120000 }
        );
        console.log('[Setup] Contract setup completed');
      } catch (err) {
        console.error('[Setup] Contract setup failed:', err.message);
        console.warn('[Setup] Continuing without contract (contract tests will be skipped)');
      }
    }

    buildImages();
    setupDockerNetwork();

    // 如果有合约，将合约地址注入 enclave 启动配置
    // start-enclave.sh 通过 .manifest-patch.py 注入 PLATFORM_WHITELIST
    // 合约地址通过 .env.contract 文件传递给 TEE（需要 start-enclave.sh 支持）
    // 当前实现：合约地址通过环境变量传入容器
    const contractEnvForEnclave = {};

    if (RUN_CONTRACT_TESTS) {
      const contractEnv = loadContractEnv();
      if (contractEnv) {
        contractEnvForEnclave.CONTRACT_ADDRESS = contractEnv.contractAddress;
        // 将 127.0.0.1 替换为 Docker 网络中宿主机的 IP（172.17.0.1）
        // 因为 TEE 容器内的 127.0.0.1 指向容器自身，而不是宿主机
        const dockerHostRpcUrl = contractEnv.rpcUrl.replace('127.0.0.1', '172.17.0.1').replace('localhost', '172.17.0.1');
        contractEnvForEnclave.CONTRACT_RPC_URL = dockerHostRpcUrl;
        contractEnvForEnclave.CONTRACT_CHAIN_ID = String(contractEnv.chainId);
        console.log(`[Setup] Enclave will connect to contract: ${contractEnv.contractAddress} via ${dockerHostRpcUrl}`);

        // 通过合约 runtimeParams.security.freezeDurationSeconds 配置冻结时长（合约优先于环境变量）
        // 这样可以测试合约配置覆盖逻辑
        const provider = new ethers.JsonRpcProvider(contractEnv.rpcUrl);
        const HARDHAT_OWNER_PRIVKEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
        const ownerSigner = new ethers.Wallet(HARDHAT_OWNER_PRIVKEY, provider);
        await provider.getBlockNumber();
        const contract = new ethers.Contract(contractEnv.contractAddress, WALLET_TRUST_CONTRACT_ABI, ownerSigner);

        // 读取当前 runtimeParams，合并 security.freezeDurationSeconds = 5
        const currentParamsStr = await contract.getRuntimeParams();
        let currentParams = {};
        try { currentParams = JSON.parse(currentParamsStr); } catch {}
        currentParams.security = currentParams.security || {};
        currentParams.security.freezeDurationSeconds = 5;  // 5 秒，用于测试
        const newParamsStr = JSON.stringify(currentParams);

        let ownerNonce = await provider.getTransactionCount(ownerSigner.address, 'latest');
        const txParams = await contract.updateRuntimeParams(newParamsStr, { nonce: ownerNonce++ });
        await txParams.wait();
        console.log(`[Setup] Contract runtimeParams updated: security.freezeDurationSeconds=5 (contract overrides env)`);

        provider.destroy();
      }
    }

    // 当合约不可用时，通过环境变量配置冻结时长（合约优先，环境变量次之）
    if (!contractEnvForEnclave.CONTRACT_ADDRESS) {
      // 设置短冻结时长用于测试（5 秒），使测试可以验证冻结期过后的行为
      contractEnvForEnclave.FREEZE_DURATION_SECONDS = '5';
      console.log(`[Setup] No contract configured, using env FREEZE_DURATION_SECONDS=5`);
    }

    // 单节点测试：清除 Dockerfile 里默认的生产 SYNC_NODES，确保单节点可正常选主
    contractEnvForEnclave.SYNC_NODES = '';
    contractEnvForEnclave.MIN_QUORUM = '1';
    // NODE_ID：整合测试显式注入一个稳定值，便于在日志里定位，同时也验证 env 透传链路
    // （manifest passthrough → start-enclave.sh → index.js）。
    contractEnvForEnclave.NODE_ID = contractEnvForEnclave.NODE_ID || 'integration-test-node';

    startEnclaveContainer(contractEnvForEnclave);
    console.log('[Setup] Waiting for sgx-enclave HTTP API...');
    await waitForHTTP(ENCLAVE_HTTP_PORT, '127.0.0.1', 120000);
    await new Promise((r) => setTimeout(r, 5000));
    console.log('[Setup] sgx-enclave HTTP API is ready\n');

    // 验证 NODE_ID env 透传链路：enclave 启动日志应包含注入的 nodeId
    try {
      const logs = execSync(`docker logs ${ENCLAVE_CONTAINER} 2>&1`, { stdio: 'pipe', timeout: 5000 }).toString();
      const expectedNodeId = contractEnvForEnclave.NODE_ID;
      assert(
        logs.includes(`nodeId=${expectedNodeId}`),
        `NODE_ID env passthrough: expected "nodeId=${expectedNodeId}" in container logs`
      );
      console.log(`[Setup] NODE_ID env passthrough verified: nodeId=${expectedNodeId}`);
    } catch (e) {
      if (e.message && e.message.startsWith('Assertion')) throw e;
      console.warn(`[Setup] NODE_ID passthrough check skipped: ${e.message}`);
    }

    // ---- TEE API 测试 ----
    await testEnclaveInfo();
    await testPasskeyRegisterChallenge();
    await testPasskeyRegisterComplete();
    await testPasskeyRegisterExistingUser();
    await testPasskeyImport();
    await testPasskeyList();
    await testWalletCreate();
    await testWalletList();
    await testWalletGet();
    await testAuthChallenge();
    await testTxSign();
    await testTxSignRawHex();
    await testKeyImportInit();
    await testKeyImportComplete();
    await testKeyImportInitRSA();
    await testKeyImportCompleteRSA();
    await testKeyImportInitUserSide();
    await testKeyImportCompleteUserSide();
    await testKeyExportInit();
    await testKeyExportComplete();
    await testKeyExportInitRSA();
    await testEvidenceGet();
    await testEvidenceList();
    await testAuthStatus();
    await testWalletEntryDelete();
    await testWalletDelete();
    await testPasskeyDelete();
    await testPlatformWalletList();
    await testAccountFreezeNoFreezeNewUser();
    await testAuthErrors();

    // ---- 合约独立接口测试（不依赖 TEE） ----
    if (RUN_CONTRACT_TESTS) {
      await testContractStandalone();
    }

    // ---- 合约 + TEE 协作测试 ----
    if (RUN_CONTRACT_TESTS) {
      await testContractTeeCollaboration();
      await testPasskeyRecovery();
    }

    // Dump enclave logs after API tests for debugging
    console.log('\n--- Enclave container logs (after API tests) ---');
    showContainerLogs(ENCLAVE_CONTAINER, 40);

  } catch (err) {
    console.error('\n[FATAL] Unexpected error:', err);
    exitCode = 1;
    showContainerLogs(ENCLAVE_CONTAINER);
  } finally {
    if (KEEP_CONTAINER || CLEANUP_NETWORK_ONLY) {
      console.log('\n[Cleanup] Skipping automatic cleanup...');
      if (KEEP_CONTAINER) {
        console.log('  Containers are kept running:');
        console.log(`    - ${ENCLAVE_CONTAINER}`);
        console.log('\n  To manually stop and remove:');
        console.log(`    docker stop ${ENCLAVE_CONTAINER}`);
        console.log(`    docker rm ${ENCLAVE_CONTAINER}`);
      }
    } else {
      console.log('\n[Cleanup] Stopping containers...');
      cleanup();
      if (RUN_CONTRACT_TESTS) stopHardhatNode();
    }
  }

  console.log('\n==================================================');
  console.log('  Test Results Summary');
  console.log('==================================================');
  console.log(`  PASSED:  ${passed}`);
  console.log(`  FAILED:  ${failed}`);
  console.log(`  SKIPPED: ${skipped}`);
  console.log(`  TOTAL:   ${passed + failed + skipped}`);

  if (failed > 0) {
    console.log('\n  Failed:');
    for (const r of results.filter((r) => r.status === 'FAIL')) {
      console.log(`    FAIL ${r.name} ${r.detail ? '-- ' + r.detail : ''}`);
    }
    exitCode = 1;
  }

  if (skipped > 0) {
    console.log('\n  Skipped:');
    for (const r of results.filter((r) => r.status === 'SKIP')) {
      console.log(`    SKIP ${r.name} -- ${r.detail}`);
    }
  }

  process.exit(exitCode);
}

main();
