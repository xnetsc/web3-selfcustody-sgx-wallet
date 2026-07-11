/**
 * SGX Enclave 入口文件
 * 初始化所有依赖，组装模块，启动 HTTP 服务
 *
 * 配置加载策略：
 *   - 仅以下"本地透传环境变量"由 docker -e 注入（manifest passthrough 白名单过滤）；
 *   - 其余所有配置（runtimeParams / 平台白名单 / Enclave 白名单 / codeRepository
 *     / freezeDuration / numShards / minQuorum 等）一律从合约读取，不再有 env 兜底。
 *   - .env 文件不被 enclave 加载（dotenv 已移除，allowed_files 也不含 .env）。
 *
 * 本地透传环境变量（仅以下 10 项，由 manifest 显式 passthrough）：
 *   CONTRACT_RPC_URL    — 区块链 RPC 地址（引导）
 *   CONTRACT_CHAIN_ID   — 链 ID（引导）
 *   CONTRACT_ADDRESS    — WalletTrustContract 合约地址（引导）
 *   CONTRACT_RPC_TLS_CA_CERT — RPC 服务器 TLS CA 证书（base64，引导）
 *   SGX_HTTP_PORT       — 本地 HTTP 监听端口（默认 3000）
 *   SYNC_NODES          — 同步节点 WSS 地址（逗号分隔，可选）
 *   SYNC_LISTEN_PORT    — 本地 WSS 监听端口（默认 3307）
 *   SYNC_ADVERTISED_URL — 本节点对外通告的监听地址（P2P 发现自报地址，可选）
 *   RATLS_CERT_PATH     — RA-TLS 证书路径（与 allowed_files 绑定）
 *   PROXY_API_KEY       — Intel PCCS API key（敏感，永不上链）
 *
 * SQLite 数据库路径硬编码为 /app/sgx-enclave/wallet/sgx_wallet.db（不可配置）
 */

import crypto from 'crypto';

import { LazyConnectionManager, DB_PATH, cleanExpiredSessions, cleanExpiredExportSessions } from './src/database/index.js';
import { CertificateVerifier } from '@xnetx/sgx-ra-tls-verify';
import { createContractClientFromEnv } from './src/modules/contract-client/index.js';
import { ContractPinStore } from './src/modules/contract-client/contract-pin-store.js';
import { SyncManager } from './src/sync/sync-manager.js';
import { HLC } from '@xnetx/raft-hlc-sync';

import { WhitelistVerifier } from './src/modules/whitelist/whitelist-verifier.js';
import { PasskeyManager } from './src/modules/webauthn/passkey-manager.js';
import { WebAuthnChallengeManager } from './src/modules/webauthn/challenge-manager.js';
import { AccountFreezeManager } from './src/modules/webauthn/account-freeze-manager.js';
import { WalletManager } from './src/modules/wallet-management/wallet-manager.js';
import { SessionManager } from './src/modules/key-management/session-manager.js';
import { KeyImporter } from './src/modules/key-management/key-import.js';
import { KeyExporter } from './src/modules/key-management/key-export.js';
import { AuthEngine } from './src/modules/auth-engine/auth-engine.js';
import { StateManager } from './src/modules/state-management/state-manager.js';
import { TransactionSigner } from './src/modules/signing/transaction-signer.js';

import {
  PasskeyRegisterHandler,
  PasskeyListHandler,
  ChallengeHandler,
  AuthStatusHandler,
  TxSigningHandler,
  KeyImportHandler,
  WalletCrudHandler,
  WalletGetHandler,
  WalletEntryDeleteHandler,
  ExportFlowHandler,
  EvidenceQueryHandler,
  EnclaveInfoHandler,
  WalletListForPlatformHandler,
} from './src/api/index.js';

import { createApp, startServer } from './src/server.js';
import { getMonotonicNow, calibrateFromNtp, getLastNtpServers } from './src/utils/monotonic-clock.js';

async function main() {
  console.log('[SGX Enclave] Starting...');

  // 1. SQLite 配置（硬编码路径，不可配置）
  const sqliteConfig = { dbPath: DB_PATH };
  console.log(`[SGX Enclave] SQLite config: dbPath=${sqliteConfig.dbPath}`);

  // 2. 创建数据库连接管理器并立即初始化。
  //    必须在合约客户端之前完成：合约身份钉住存储（ContractPinStore）依赖 sealed DB。
  const connectionManager = new LazyConnectionManager(sqliteConfig);
  // 强制初始化以获取 db 实例（合约钉住 / sync-manager 启动前需要）
  connectionManager.readQuery('SELECT 1');
  console.log('[SGX Enclave] ConnectionManager initialized');

  // 3. 加载配置：读取合约 → 唯一配置来源。
  //    合约身份钉住（TOFU）：首次成功读到合约后永久锁定合约身份，
  //    忽略环境变量里的合约连接参数；钉住合约不可达时用最后已知快照，绝不回退 env。
  //    合约配置缺失/不全/连不上时只报错，不抛异常，不退出。
  const pinStore = new ContractPinStore(connectionManager);
  const contractClient = createContractClientFromEnv(pinStore);
  await contractClient.initialize();
  console.log(`[SGX Enclave] Config client initialized (contractAvailable=${contractClient.isContractAvailable()})`);

  // 同步节点配置（可选，不设置则单节点运行）
  const syncNodesStr = process.env.SYNC_NODES || '';
  const syncNodes = syncNodesStr ? syncNodesStr.split(',').map((s) => s.trim()).filter(Boolean) : [];
  if (syncNodes.length > 0) {
    console.log(`[SGX Enclave] Sync nodes configured: ${syncNodes.length} node(s)`);
  } else {
    console.log('[SGX Enclave] No sync nodes configured — running as standalone node');
  }

  // HTTP 端口（供 Leader 做回环代理请求使用，需在 SyncManager 启动前确定）
  const httpPort = parseInt(process.env.SGX_HTTP_PORT || '3000', 10);

  // 3. 从合并后的 runtimeParams 获取会话 TTL 等参数
  //    合并规则：环境变量 RUNTIME_PARAMS 为基础，合约 runtimeParams 覆盖同名字段
  //    如果合约和环境都没有，则用空对象 {}，后续各处用到时判断字段是否存在再用默认值
  const runtimeParams = contractClient.getRuntimeParams() || {};
  const sessionConfig = runtimeParams.session || {};
  const importTtlSeconds = sessionConfig.importTtlSeconds || 300;
  const exportTtlSeconds = sessionConfig.exportTtlSeconds || 86400;

  // 3.1 NTP 时间源校正：如果合约配置了 security.ntpServers，用 NTP 校正单调时钟锚点
  //     确保所有节点的时间基准一致，消除宿主机时钟偏差。
  //     若合约明确配置了 NTP 服务器但全部校准失败，则直接报错退出，避免在不可信时间基准下运行。
  const ntpServers = runtimeParams.security?.ntpServers;
  if (Array.isArray(ntpServers) && ntpServers.length > 0) {
    console.log(`[SGX Enclave] NTP calibration: servers=${ntpServers.join(', ')}`);
    const calibrated = await calibrateFromNtp(ntpServers);
    if (!calibrated) {
      throw new Error(`[SGX Enclave] NTP calibration failed for all configured servers (${ntpServers.join(', ')}). Refusing to start with untrusted local clock.`);
    }
    console.log('[SGX Enclave] NTP calibration succeeded');
  } else {
    console.log('[SGX Enclave] No NTP servers configured, using local clock as monotonic anchor');
  }

  // 分片数（部署后不得修改，默认 16）—— 仅来自合约 runtimeParams.sync.numShards
  const numShards = parseInt(
    String((runtimeParams.sync && runtimeParams.sync.numShards) || 16),
    10
  );

  // getMinQuorum：每次选举前全量刷新合约缓存，然后读取最少票数
  // 刷新失败时 contractClient 保留上次缓存值，fallback 链：合约缓存 > 默认值
  const defaultMinQuorum = syncNodes.length > 0 ? 2 : 1;
  const getMinQuorum = async () => {
    try {
      await contractClient.refreshCache();
    } catch (err) {
      console.warn('[getMinQuorum] Contract refresh failed:', err.message);
    }
    const params = contractClient.getRuntimeParams() || {};
    const fromContract = params?.sync?.minQuorum;
    if (fromContract != null) {
      const v = parseInt(fromContract, 10);
      if (!isNaN(v) && v >= 1) return v;
    }
    return defaultMinQuorum;
  };

  // 4. 最终校验：配置已加载
  //    无合约配置且无 pin 时，ContractClient 已从 env RUNTIME_PARAMS 加载（env fallback mode）；
  //    否则 runtimeParams 来自合约或 pin 快照，绝不回退到环境变量。
  //    SQLite DB path 硬编码在 constants.js 中，不需要环境变量
  if (!contractClient.isContractAvailable()) {
    console.warn('[SGX Enclave] Contract connection unavailable — using last-known-good pinned snapshot or env fallback; some functions (e.g. authorization revocation) may be limited');
  } else {
    console.log('[SGX Enclave] All config sources loaded successfully');
  }

  // 7. 启动 WSS 同步管理器（如果有 peer 节点或需要监听）
  let syncManager = null;
  const listenPort = parseInt(process.env.SYNC_LISTEN_PORT || '3307', 10);
  // nodeId：环境变量 NODE_ID 透传，否则随机生成 UUID。
  // 只支持环境变量注入，不走合约配置 —— 每个节点实例必须不同，无法共享。
  // 稳定的 nodeId 使发送方重启后仍可触发全量同步的断点续传；
  // 随机 fallback 只适合一次性/短命实例，发送方重启后会从头重传（幂等，不丢数据，只浪费带宽）。
  const nodeId = (process.env.NODE_ID && process.env.NODE_ID.trim()) || crypto.randomUUID();
  const hlc = new HLC(nodeId, () => getMonotonicNow());

  // Attestation 配置 — 从 runtimeParams.attestation 读取（合约 > env RUNTIME_PARAMS > 默认值）
  // 但如果已 pin，allowNonRaTls 以 pin 的值为准，忽略合约/env 的值
  const attestationConfig = runtimeParams.attestation || {};
  const pinnedIdentity = contractClient.getPinnedIdentity();
  const allowNonRaTls = pinnedIdentity
    ? pinnedIdentity.allowNonRaTls
    : !!attestationConfig.allowNonRaTls;
  if (pinnedIdentity) {
    console.log(`[SGX Enclave] allowNonRaTls=${allowNonRaTls} (from pinned identity, ignoring env/contract)`);
  }

  // 构建 RA-TLS 选项（enclaveWhitelist 数组等，仅来自合约/pin 快照，无 env 兜底）
  const raTlsOpts = {};

  // 从 enclaveWhitelist 数组构建（支持多版本共存和滚动升级）
  let enclaveWhitelist = [];
  try { enclaveWhitelist = contractClient.getEnclaveWhitelist(); } catch (_) { /* 未初始化或不可用 */ }

  if (enclaveWhitelist.length > 0) {
    raTlsOpts.enclaveIdentities = enclaveWhitelist;
  }

  // PCCS 配置（从 runtimeParams）
  if (attestationConfig.pccsUrl) {
    raTlsOpts.pccsUrl = attestationConfig.pccsUrl;
    console.log(`[SGX Enclave] PCCS URL (from runtimeParams): ${raTlsOpts.pccsUrl}`);
  }
  // PROXY_API_KEY 是敏感参数，只走环境变量透传（合约里永远不会有）
  if (process.env.PROXY_API_KEY) {
    raTlsOpts.apiKey = process.env.PROXY_API_KEY;
    console.log('[SGX Enclave] PCCS API key configured (env passthrough)');
  }
  // 可信根 CA（从 runtimeParams）
  if (attestationConfig.trustedRootCAs) {
    const cas = Array.isArray(attestationConfig.trustedRootCAs)
      ? attestationConfig.trustedRootCAs
      : String(attestationConfig.trustedRootCAs).split(',').map(s => s.trim()).filter(Boolean);
    if (cas.length > 0) {
      raTlsOpts.trustedRootCAs = cas;
      console.log(`[SGX Enclave] Trusted root CAs (from runtimeParams): ${cas.length} entries`);
    }
  }
  // TCB 容忍选项（从 runtimeParams，默认 false）
  raTlsOpts.allowOutdatedTcb = !!attestationConfig.allowOutdatedTcb;
  raTlsOpts.allowDebugEnclave = !!attestationConfig.allowDebugEnclave;
  raTlsOpts.allowHwConfigNeeded = !!attestationConfig.allowHwConfigNeeded;
  raTlsOpts.allowSwHardeningNeeded = !!attestationConfig.allowSwHardeningNeeded;

  const verifier = new CertificateVerifier({
    allowNonRaTls,
    raTlsOptions: raTlsOpts,
  });

  // RA-TLS: certificate on disk (public), private key in memory (from gramine-launcher.js)
  const ratlsCertPath = process.env.RATLS_CERT_PATH;
  const ratlsKeyPem = global.__ratlsPrivateKeyPem || null;
  const raTlsOptions = (ratlsCertPath && ratlsKeyPem) ? {
    certPath: ratlsCertPath,
    keyPem: ratlsKeyPem,
    allowNonRaTls,
  } : null;
  if (raTlsOptions) {
    console.log('[SGX Enclave] RA-TLS: cert from disk, key from memory');
  } else {
    console.warn('[SGX Enclave] RA-TLS: not available (missing cert path or in-memory key)');
  }

  syncManager = new SyncManager({
    db: connectionManager.getDatabase(),
    hlc,
    peerUrls: syncNodes,
    listenPort,
    advertisedUrl: process.env.SYNC_ADVERTISED_URL || null,
    raTlsOptions,
    verifier,
    reconnect: runtimeParams.reconnect || {},
    httpPort,
    numShards,
    getMinQuorum,
    contractClient,
  });

  await syncManager.start();
  console.log(`[SGX Enclave] SyncManager started (nodeId=${nodeId}, peers=${syncNodes.length}, port=${listenPort})`);

  // 注册 push-on-write 回调：本地写操作后主动推送给所有 peer
  connectionManager.onWrite(() => {
    if (syncManager) syncManager.pushToAllPeers();
  });

  // 注入 SyncEngine 手动事务检测：2PC 期间 connectionManager 跳过 push-on-write
  connectionManager.setExternalManualTxnCheck(() => {
    return syncManager ? syncManager.engine.hasActiveManualTransaction() : false;
  });

  // 8. 创建模块实例
  const engine = syncManager.engine;
  const whitelistVerifier = new WhitelistVerifier(contractClient);
  const passkeyManager = new PasskeyManager(connectionManager, engine);
  const challengeManager = new WebAuthnChallengeManager(connectionManager);
  // 冻结时长：仅来自合约 runtimeParams.security.freezeDurationSeconds，缺失时默认 259200 秒（72 小时）
  // 使用动态获取函数，确保合约配置变更后新冻结使用最新的冻结时长
  // 已冻结账户的 freeze_until 在冻结时已写入数据库，不受后续配置变更影响
  const getFreezeDurationSeconds = () => {
    const latestRuntimeParams = contractClient.getRuntimeParams() || {};
    const security = latestRuntimeParams.security || {};
    const duration = parseFloat(security.freezeDurationSeconds) || 259200;
    return duration;
  };
  const accountFreezeManager = new AccountFreezeManager(connectionManager, { freezeDurationSeconds: getFreezeDurationSeconds });
  const initialDuration = getFreezeDurationSeconds();
  console.log(`[SGX Enclave] Account freeze duration: ${initialDuration}s (dynamic, source: contract > env > default)`);
  const walletManager = new WalletManager(connectionManager, engine);
  const sessionManager = new SessionManager(connectionManager, engine);
  const keyImporter = new KeyImporter(sessionManager, walletManager, { importTtlSeconds, engine });
  const keyExporter = new KeyExporter(walletManager, connectionManager, { exportTtlSeconds, engine });
  const stateManager = new StateManager(connectionManager, engine);
  const transactionSigner = new TransactionSigner(stateManager, walletManager);
  const authEngine = new AuthEngine({
    whitelistVerifier,
    contractClient,
    passkeyManager,
    stateManager,
    walletManager,
  });

  // 9. 创建 API handler 实例
  const handlers = {
    challengeHandler: new ChallengeHandler({
      whitelistVerifier,
      passkeyManager,
      challengeManager,
    }),
    registerHandler: new PasskeyRegisterHandler({
      whitelistVerifier,
      passkeyManager,
      challengeManager,
      accountFreezeManager,
      walletManager,
      contractClient,
    }),
    walletCrudHandler: new WalletCrudHandler({
      whitelistVerifier,
      passkeyManager,
      challengeManager,
      walletManager,
    }),
    txSigningHandler: new TxSigningHandler({
      authEngine,
      transactionSigner,
      stateManager,
      walletManager,
      engine,
    }),
    keyImportHandler: new KeyImportHandler({
      whitelistVerifier,
      keyImporter,
      passkeyManager,
      challengeManager,
    }),
    exportFlowHandler: new ExportFlowHandler({
      whitelistVerifier,
      passkeyManager,
      challengeManager,
      walletManager,
      keyExporter,
    }),
    evidenceQueryHandler: new EvidenceQueryHandler({
      whitelistVerifier,
      stateManager,
      passkeyManager,
      challengeManager,
    }),
    passkeyListHandler: new PasskeyListHandler({
      whitelistVerifier,
      passkeyManager,
    }),
    walletGetHandler: new WalletGetHandler({
      whitelistVerifier,
      walletManager,
    }),
    walletEntryDeleteHandler: new WalletEntryDeleteHandler({
      whitelistVerifier,
      passkeyManager,
      challengeManager,
      walletManager,
    }),
    authStatusHandler: new AuthStatusHandler({
      whitelistVerifier,
      stateManager,
    }),
    enclaveInfoHandler: new EnclaveInfoHandler({
      contractClient,
    }),
    walletListForPlatformHandler: new WalletListForPlatformHandler({
      authEngine,
      walletManager,
    }),
  };

  // 10. 启动过期会话定时清理（import + export + 挑战值）
  //     清理间隔从 runtimeParams.session.cleanupIntervalSeconds 读取，默认 3600（1小时）
  const cleanupIntervalMs = (sessionConfig.cleanupIntervalSeconds || 3600) * 1000;
  const cleanupTimer = setInterval(async () => {
    try {
      cleanExpiredSessions(connectionManager);
      cleanExpiredExportSessions(connectionManager);
      // 清理已失效的授权缓存（revoked / expired / exceeded）
      await stateManager.cleanInvalidatedStates();
      // 清理过期的 WebAuthn 挑战值
      challengeManager.cleanExpiredChallenges();
      // 检查合约 NTP 配置是否变更，变更则重新校正单调时钟
      const latestParams = contractClient.getRuntimeParams() || {};
      const latestNtp = latestParams.security?.ntpServers;
      const lastNtp = getLastNtpServers();
      if (Array.isArray(latestNtp) && latestNtp.length > 0) {
        const changed = !lastNtp ||
          lastNtp.length !== latestNtp.length ||
          latestNtp.some((s, i) => s !== lastNtp[i]);
        if (changed) {
          console.log('[SGX Enclave] NTP servers changed in contract, re-calibrating...');
          const ok = await calibrateFromNtp(latestNtp);
          if (!ok) {
            console.error(`[SGX Enclave] NTP re-calibration failed for all configured servers (${latestNtp.join(', ')}). Stopping enclave.`);
            process.exit(1);
          }
        }
      }
    } catch (err) {
      console.error('[SGX Enclave] Session cleanup error:', err.message);
    }
  }, cleanupIntervalMs);
  console.log(`[SGX Enclave] Session cleanup timer started (interval=${cleanupIntervalMs / 1000}s)`);

  // 11. 创建 Express 应用并启动 HTTP 服务
  const app = createApp(handlers, accountFreezeManager, syncManager);
  const server = await startServer(app);

  // 12. 优雅退出
  const shutdown = (signal) => {
    console.log(`[SGX Enclave] Received ${signal}, shutting down...`);
    clearInterval(cleanupTimer);
    server.close(() => {
      console.log('[SGX Enclave] HTTP server closed');
    });
    if (syncManager) syncManager.stop();
    contractClient.close();
    connectionManager.close();
    console.log('[SGX Enclave] All connections closed');
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error('[SGX Enclave] Fatal error during startup:', err);
  process.exit(1);
});
