// 临时端到端驱动（手工三节点真实执行用，跑完删除，不属于仓库测试集）
// 链：本地 Hardhat（setup-contract.sh 已部署）；节点：3 个 enclave 进程（direct 模式）
import { ethers } from 'ethers';
import crypto from 'crypto';
import { readFileSync } from 'fs';
import cborPkg from 'cbor';
const { encode: cborEncode } = cborPkg;

const RPC = 'http://127.0.0.1:8545';
const CONTRACT_ADDRESS = '0x5FbDB2315678afecb367f032d93F642f64180aa3';
const OWNER_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const PLATFORM_KEY = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a';
const SINGLE = process.env.SINGLE === '1';
const PORTS = SINGLE ? { 'node-1': 3000 } : { 'node-1': 3000, 'node-2': 3001, 'node-3': 3002 };

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
let failures = 0;
function check(name, cond, extra = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);
  if (!cond) failures++;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const provider = new ethers.JsonRpcProvider(RPC);
const owner = new ethers.Wallet(OWNER_KEY, provider);
const platform = new ethers.Wallet(PLATFORM_KEY, provider);
const artifact = JSON.parse(readFileSync(new URL('../contracts/artifacts/contracts/WalletTrustContract.sol/WalletTrustContract.json', import.meta.url), 'utf8'));
const contract = new ethers.Contract(CONTRACT_ADDRESS, artifact.abi, owner);
let _nonce = await provider.getTransactionCount(owner.address, 'latest');
const nextNonce = () => _nonce++;

async function envelope(obj) {
  const payload = JSON.stringify(obj);
  return { payload, platformSignature: await platform.signMessage(payload) };
}
async function post(port, path, body) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60000),
  });
  let parsed = null;
  try { parsed = await res.json(); } catch { /* 非 JSON 响应 */ }
  return { status: res.status, body: parsed };
}
const dataOf = (res) => (res.body && typeof res.body.data === 'string' ? JSON.parse(res.body.data) : null);

// ---------- 1. 运营方 Passkey（真实 P-256）+ 注册到节点 ----------
const opKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const spki = opKeys.publicKey.export({ type: 'spki', format: 'der' });
const point = spki.subarray(26);
const pubX = point.subarray(1, 33), pubY = point.subarray(33, 65);
const credId = crypto.randomBytes(32);
const credIdB64 = b64url(credId);
const cose = cborEncode(new Map([[1, 2], [3, -7], [-1, 1], [-2, pubX], [-3, pubY]]));
const pubKeyHash = '0x' + sha256(cose).toString('hex');
const OPERATOR = 'ops-gov';

const chRes = await post(PORTS['node-1'], '/api/challenge', await envelope({ purpose: 'register', userId: OPERATOR }));
const chData = dataOf(chRes);
check('register challenge 200', chRes.status === 200 && !!chData?.challenge, `status=${chRes.status}`);
const rpIdHash = sha256('localhost');
const regAuthData = Buffer.concat([
  rpIdHash, Buffer.from([0x41]), Buffer.alloc(4), Buffer.alloc(16),
  (() => { const b = Buffer.alloc(2); b.writeUInt16BE(credId.length); return b; })(),
  credId, cose,
]);
const attObj = cborEncode({ fmt: 'none', attStmt: {}, authData: regAuthData });
const regClientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: chData.challenge, origin: 'https://localhost', crossOrigin: false }));
const regRes = await post(PORTS['node-1'], '/api/passkey/register/complete', await envelope({
  userId: chData.userId,
  attestationResponse: {
    id: credIdB64, rawId: credIdB64, type: 'public-key',
    response: { attestationObject: b64url(attObj), clientDataJSON: b64url(regClientData) },
  },
}));
const regData = dataOf(regRes);
check('operator passkey registered', regRes.status === 200 && regData?.credentialId === credIdB64, `status=${regRes.status} body=${JSON.stringify(regRes.body).slice(0, 160)}`);

// ---------- 2. 链上：指定治理 Passkey + 授权全文存档 ----------
await (await contract.designateGovernancePasskey(OPERATOR, pubKeyHash, { nonce: nextNonce() })).wait();
check('governance designated on-chain', await contract.isGovernancePasskey(OPERATOR, pubKeyHash));

const deadlineMs = Math.floor((Date.now() + 3600_000) / 1000) * 1000;
const auth = {
  authorizationId: 'emg-e2e-0001',
  type: 'emergency',
  operatorUserId: OPERATOR,
  operatorCredentialId: credIdB64,
  grantee: platform.address,
  wallets: [
    { userId: 'victim-e2e', policy: { operations: { wallet_create: { chains: [1] } } } },
    { userId: 'victim-e2e-2', policy: { operations: { wallet_create: { chains: [1] } } } },
  ],
  timePolicy: { deadline: new Date(deadlineMs).toISOString() },
  createdAt: '2026-11-10T00:00:00.000Z',
};
const text = JSON.stringify(auth);
const challengeBytes = sha256(Buffer.from(text, 'utf8'));
const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64url(challengeBytes), origin: 'https://localhost', crossOrigin: false }));
const counter = Buffer.alloc(4); counter.writeUInt32BE(1);
const authData = Buffer.concat([rpIdHash, Buffer.from([0x05]), counter]);
const derSig = crypto.createSign('SHA256').update(Buffer.concat([authData, sha256(clientData)])).end().sign(opKeys.privateKey);
const sigObj = { authenticatorData: b64url(authData), clientDataJSON: b64url(clientData), signature: b64url(derSig) };

await (await contract.setEmergencyAuthorization(
  auth.authorizationId, text, JSON.stringify(sigObj), OPERATOR, pubKeyHash, platform.address, Math.floor(deadlineMs / 1000),
  { nonce: nextNonce() },
)).wait();
const record = await contract.getEmergencyAuthorization(auth.authorizationId);
check('authorization stored on-chain, authHash matches', record.exists && record.authHash.toLowerCase() === '0x' + challengeBytes.toString('hex'));

// ---------- 3. 负控制：递进文本与链上存档不一致（多一个空格）→ 必须拒绝 ----------
await sleep(6000); // 等运营方 Passkey 同步到各节点
const badRes = await post(PORTS['node-1'], '/api/wallet/create', await envelope({
  userId: 'victim-e2e', chains: [{ chainId: 1, coinType: 60 }], emergencyAuthorizationJson: text + ' ', emergencySignature: sigObj,
}));
check('tampered text rejected', badRes.status !== 200, `status=${badRes.status} body=${JSON.stringify(badRes.body).slice(0, 160)}`);

// ---------- 4. 真实应急执行：经 node-1 建 victim-e2e 的钱包 ----------
let createRes = null, createData = null;
for (let i = 0; i < 4; i++) {
  createRes = await post(PORTS['node-1'], '/api/wallet/create', await envelope({
    userId: 'victim-e2e', chains: [{ chainId: 1, coinType: 60 }], emergencyAuthorizationJson: text, emergencySignature: sigObj,
  }));
  createData = dataOf(createRes);
  if (createRes.status === 200) break;
  console.log(`  create attempt ${i + 1}: status=${createRes.status} body=${JSON.stringify(createRes.body).slice(0, 200)}`);
  await sleep(5000);
}
check('emergency wallet_create succeeded', createRes.status === 200 && !!createData?.walletId, `walletId=${createData?.walletId}`);
check('response carries executionLog', !!createData?.executionLog?.entryHash, `entryHash=${createData?.executionLog?.entryHash}`);
const entryHash = createData?.executionLog?.entryHash;

// ---------- 5. 三节点公开日志一致性 ----------
await sleep(6000);
const perNode = {};
for (const [name, port] of Object.entries(PORTS)) {
  const q = await post(port, '/api/emergency/execution-log/query', { authorizationId: auth.authorizationId, pageSize: 10 });
  const d = dataOf(q);
  perNode[name] = d;
  const found = (d?.logs || []).find((l) => l.entryHash === entryHash);
  check(`${name} log has the entry`, !!found && found.operation === 'wallet_create' && found.targetUserId === 'victim-e2e',
    `count=${d?.count} latest=${d?.latestEntryHash?.slice(0, 18)}`);
}
if (!SINGLE) {
  check('latestEntryHash identical on all nodes',
    perNode['node-1']?.latestEntryHash === perNode['node-2']?.latestEntryHash &&
    perNode['node-2']?.latestEntryHash === perNode['node-3']?.latestEntryHash);
}

// ---------- 6. 链上撤销 → 经 node-2 再执行必须拒绝 ----------
await (await contract.revokeEmergencyAuthorization(auth.authorizationId, { nonce: nextNonce() })).wait();
const afterRevoke = await post(SINGLE ? PORTS['node-1'] : PORTS['node-2'], '/api/wallet/create', await envelope({
  userId: 'victim-e2e-2', chains: [{ chainId: 1, coinType: 60 }], emergencyAuthorizationJson: text, emergencySignature: sigObj,
}));
const revokeMsg = JSON.stringify(afterRevoke.body);
check(`post-revoke execution rejected on ${SINGLE ? 'node-1' : 'node-2'}`, afterRevoke.status !== 200 && /revoked/i.test(revokeMsg), `status=${afterRevoke.status} body=${revokeMsg.slice(0, 200)}`);

console.log(failures === 0 ? 'E2E ALL PASS' : `E2E FAILURES: ${failures}`);
process.exit(failures === 0 ? 0 : 1);
