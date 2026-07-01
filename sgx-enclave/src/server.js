/**
 * SGX Enclave HTTP REST API 服务
 *
 * 所有接口均为 POST，请求体为 JSON。
 * 端口通过环境变量 SGX_HTTP_PORT 配置，默认 3000。
 *
 * 路由映射：
 *   POST /api/challenge                    → ChallengeHandler.handleChallenge        (统一挑战值接口，支持所有 purpose)
 *   POST /api/passkey/register/complete    → PasskeyRegisterHandler.handleComplete
 *   POST /api/passkey/delete               → WalletCrudHandler.handleDeletePasskey
 *   POST /api/passkey/list                 → PasskeyListHandler.handleList
 *   POST /api/wallet/create                → WalletCrudHandler.handleCreate
 *   POST /api/wallet/list                  → WalletCrudHandler.handleList
 *   POST /api/wallet/get                   → WalletGetHandler.handleGet
 *   POST /api/wallet/delete                → WalletCrudHandler.handleDelete
 *   POST /api/wallet/entry/delete          → WalletEntryDeleteHandler.handleDelete
 *   POST /api/auth/status                  → AuthStatusHandler.handleGetStatus
 *   POST /api/tx/sign                      → TxSigningHandler.handleSigningRequest    (支持txParams和rawTxHex两种模式)
 *   POST /api/key/import/init              → KeyImportHandler.handleInit              (密钥导入：私钥/助记词)
 *   POST /api/key/import/complete          → KeyImportHandler.handleComplete          (密钥导入确认)
 *   POST /api/key/export/init              → ExportFlowHandler.handleInit             (密钥导出：原状导出)
 *   POST /api/key/export/complete          → ExportFlowHandler.handleComplete         (密钥导出确认+删除)
 *   POST /api/evidence/get                 → EvidenceQueryHandler.handleGetRecord     (双鉴权：平台/用户)
 *   POST /api/evidence/list                → EvidenceQueryHandler.handleListRecords   (双鉴权：平台/用户)
 *   POST /api/enclave/info                 → EnclaveInfoHandler.handleGetInfo         (无需鉴权)
 *   POST /api/admin/userId/list            → WalletListForPlatformHandler.handleListAll  (平台签名)
 *
 * 账户冻结机制：
 *   当已有账户（有钱包但无 Passkey）通过用户端注册补绑 Passkey 时，
 *   若该账户下存在钱包，则自动冻结账户 72 小时。
 *   - 72h 内：该 userId 的所有请求均被拒绝
 *   - 72h 后：仅允许使用冻结时绑定的 Passkey 发起的带 webauthnSignature 的请求
 *     - 有 webauthnSignature 且 credentialId 匹配的请求成功后永久解除冻结
 *     - 无 webauthnSignature 的请求（如 /api/challenge）仍然被拒绝
 *   - 冻结不会自动解除，必须通过绑定的 Passkey 发起签名请求才能解除
 *   - /api/enclave/info 和 /api/admin/userId/list 不受冻结影响
 *
 * 两阶段提交（2PC）同步复制：
 *   当 syncManager 存在且有已连接的 peer 时，写操作路径使用 2PC：
 *   1. Leader 开启手动 SQLite 事务（BEGIN IMMEDIATE）
 *   2. 执行业务逻辑（handler）
 *   3. 读取 _sync_log 新增条目，广播 prepare 给所有 Follower
 *   4. 等待 quorum 数量的 Follower 确认（prepare_ack）
 *   5. 收到足够确认 → COMMIT → 广播 commit → 返回成功
 *   6. 超时 → ROLLBACK → 广播 abort → 返回 503
 */

import express from 'express';
import crypto from 'crypto';
import { getAttestationQuote } from './modules/remote-attestation/index.js';

/**
 * 写操作路由集合（这些路径需要路由到分片 Leader 执行，且需要 2PC 同步复制）
 * 读操作（list/get/status/evidence）直接在本地执行，因为数据已通过 sync 全量复制
 */
const WRITE_PATHS = new Set([
  '/api/challenge',
  '/api/passkey/register/complete',
  '/api/passkey/delete',
  '/api/wallet/create',
  '/api/wallet/delete',
  '/api/wallet/entry/delete',
  '/api/tx/sign',
  '/api/key/import/init',
  '/api/key/import/complete',
  '/api/key/export/init',
  '/api/key/export/complete',
]);

/**
 * 从请求 body 中提取 userId（用于分片路由）
 * 多种接口的 payload 结构不同，按优先级依次尝试
 * @param {object} reqBody
 * @returns {string|null}
 */
function _extractUserIdForRouting(reqBody) {
  try {
    if (!reqBody?.payload) return null;
    const payload = typeof reqBody.payload === 'string'
      ? JSON.parse(reqBody.payload)
      : reqBody.payload;
    if (payload.userId) return payload.userId;
    // tx/sign：userId 在 authorizationJson 内
    if (payload.authorizationJson) {
      const auth = typeof payload.authorizationJson === 'string'
        ? JSON.parse(payload.authorizationJson)
        : payload.authorizationJson;
      if (auth.userId) return auth.userId;
    }
  } catch {}
  return null;
}

/**
 * 创建写请求代理中间件
 * 当本节点不是该 userId 对应分片的 Leader 时，透明代理给 Leader 执行
 * @param {import('./sync/sync-manager.js').SyncManager|null} syncManager
 * @returns {express.RequestHandler}
 */
function createWriteProxyMiddleware(syncManager) {
  return async (req, res, next) => {
    // 单节点模式或路径不是写操作，直接放行
    if (!syncManager || !WRITE_PATHS.has(req.path)) return next();

    const userId = _extractUserIdForRouting(req.body);

    // 本节点是该用户分片的 Leader，直接本地处理
    if (syncManager.isLeaderForUser(userId)) return next();

    // 本节点是 Follower，代理给对应 Leader
    try {
      const result = await syncManager.proxyWriteRequest(userId, {
        method: req.method,
        path: req.path,
        headers: req.headers,
        body: req.body,
      });
      return res.status(result.status).json(result.body);
    } catch (err) {
      return res.status(503).json({ error: 'No leader available: ' + err.message });
    }
  };
}

/**
 * 创建 Express 应用并注册所有路由
 *
 * @param {Object} handlers - 所有 API handler 实例
 * @param {import('./api/challenge.js').ChallengeHandler} handlers.challengeHandler
 * @param {import('./api/passkey-register.js').PasskeyRegisterHandler} handlers.registerHandler
 * @param {import('./api/wallet-crud.js').WalletCrudHandler} handlers.walletCrudHandler
 * @param {import('./api/tx-signing.js').TxSigningHandler} handlers.txSigningHandler
 * @param {import('./api/key-import.js').KeyImportHandler} handlers.keyImportHandler
 * @param {import('./api/export-flow.js').ExportFlowHandler} handlers.exportFlowHandler
 * @param {import('./api/evidence-query.js').EvidenceQueryHandler} handlers.evidenceQueryHandler
 * @param {import('./api/passkey-list.js').PasskeyListHandler} handlers.passkeyListHandler
 * @param {import('./api/wallet-get.js').WalletGetHandler} handlers.walletGetHandler
 * @param {import('./api/wallet-entry-delete.js').WalletEntryDeleteHandler} handlers.walletEntryDeleteHandler
 * @param {import('./api/auth-status.js').AuthStatusHandler} handlers.authStatusHandler
 * @param {import('./api/enclave-info.js').EnclaveInfoHandler} handlers.enclaveInfoHandler
 * @param {import('./api/wallet-list-for-platform.js').WalletListForPlatformHandler} handlers.walletListForPlatformHandler
 * @param {import('./modules/webauthn/account-freeze-manager.js').AccountFreezeManager} [accountFreezeManager] - 账户冻结管理器
 * @param {import('./sync/sync-manager.js').SyncManager|null} [syncManager] - 同步管理器（2PC 用）
 * @returns {express.Application}
 */
export function createApp(handlers, accountFreezeManager, syncManager = null) {
  const app = express();

  // JSON body parsing
  app.use(express.json());

  // 写请求代理中间件：Follower 自动将写操作转发给对应分片 Leader
  app.use(createWriteProxyMiddleware(syncManager));

  // --- 路由注册 ---

  // 统一挑战值接口（支持所有 purpose）
  // allowPurposeRegister: 冻结账户可通过 purpose=register 获取挑战值以重新注册 Passkey
  app.post('/api/challenge', wrap(req => handlers.challengeHandler.handleChallenge(req.body), accountFreezeManager, syncManager, req => req.path, { allowPurposeRegister: true }));

  // Passkey 注册
  // 冻结账户可通过此接口重新注册 Passkey（替换旧的冻结 Passkey）
  // 中间件自动检测：userId 冻结 + 有 attestationResponse + credentialId 与冻结记录不同 → 跳过冻结检查
  app.post('/api/passkey/register/complete', wrap(req => handlers.registerHandler.handleComplete(req.body), accountFreezeManager, syncManager, req => req.path));

  // Passkey 删除
  app.post('/api/passkey/delete', wrap(req => handlers.walletCrudHandler.handleDeletePasskey(req.body), accountFreezeManager, syncManager, req => req.path));

  // Passkey 列表（读操作，不需要 2PC）
  app.post('/api/passkey/list', wrap(req => handlers.passkeyListHandler.handleList(req.body), accountFreezeManager, null, null, req => req.path));

  // 钱包 CRUD
  app.post('/api/wallet/create', wrap(req => handlers.walletCrudHandler.handleCreate(req.body), accountFreezeManager, syncManager, req => req.path));
  app.post('/api/wallet/list', wrap(req => handlers.walletCrudHandler.handleList(req.body), accountFreezeManager, null, null, req => req.path));
  app.post('/api/wallet/get', wrap(req => handlers.walletGetHandler.handleGet(req.body), accountFreezeManager, null, null, req => req.path));
  app.post('/api/wallet/delete', wrap(req => handlers.walletCrudHandler.handleDelete(req.body), accountFreezeManager, syncManager, req => req.path));

  // 单个逻辑钱包删除
  app.post('/api/wallet/entry/delete', wrap(req => handlers.walletEntryDeleteHandler.handleDelete(req.body), accountFreezeManager, syncManager, req => req.path));

  // 授权状态查询（读操作）
  app.post('/api/auth/status', wrap(req => handlers.authStatusHandler.handleGetStatus(req.body), accountFreezeManager, null, null, req => req.path));

  // 交易签名
  app.post('/api/tx/sign', wrap(req => handlers.txSigningHandler.handleSigningRequest(req.body), accountFreezeManager, syncManager, req => req.path));

  // 密钥导入（支持私钥 + 助记词）
  app.post('/api/key/import/init', wrap(req => handlers.keyImportHandler.handleInit(req.body), accountFreezeManager, syncManager, req => req.path));
  app.post('/api/key/import/complete', wrap(req => handlers.keyImportHandler.handleComplete(req.body), accountFreezeManager, syncManager, req => req.path));

  // 密钥导出（原状导出：助记词钱包导出助记词+所有链地址，纯私钥钱包导出单个私钥+地址）
  app.post('/api/key/export/init', wrap(req => handlers.exportFlowHandler.handleInit(req.body), accountFreezeManager, syncManager, req => req.path));
  app.post('/api/key/export/complete', wrap(req => handlers.exportFlowHandler.handleComplete(req.body), accountFreezeManager, syncManager, req => req.path));

  // 取证查询（统一平台签名，payload 区分平台/用户发起）
  app.post('/api/evidence/get', wrap(req => handlers.evidenceQueryHandler.handleGetRecord(req.body), accountFreezeManager, null, null, req => req.path));
  app.post('/api/evidence/list', wrap(req => handlers.evidenceQueryHandler.handleListRecords(req.body), accountFreezeManager, null, null, req => req.path));

  // Enclave 信息（无需鉴权，不受冻结影响）
  app.post('/api/enclave/info', wrap(req => handlers.enclaveInfoHandler.handleGetInfo(req.body), null, null, null, req => req.path));

  // 管理员用户ID列表查询（平台签名，不受冻结影响）
  app.post('/api/admin/userId/list', wrap(req => handlers.walletListForPlatformHandler.handleListAll(req.body), null, null, null, req => req.path));

  return app;
}

/**
 * 通用路由包装器：将 handler 方法的返回值和异常映射为统一的远程证明响应格式
 *
 * 集成账户冻结检查 + 两阶段提交（2PC）同步复制：
 *   - 从请求 payload 中提取 userId、credentialId、webauthnSignature
 *   - 调用 AccountFreezeManager.checkRequest() 判断是否拦截
 *   - 若请求通过且可解除冻结，在 handler 成功后自动解除
 *   - 自动检测 Passkey 注册替换场景：userId 冻结 + 有 attestationResponse + credentialId 与冻结记录不同 → 跳过冻结检查
 *   - 若 syncManager 存在且是多节点部署，使用 2PC 同步复制：
 *     - 开启手动事务 → 执行 handler → 等待 Follower 确认 → COMMIT/ROLLBACK
 *
 * 成功（200）响应格式：
 *   { attestationQuote: "hex...", data: "JSON序列化字符串" }
 *   - data 是 handler 返回值的 JSON.stringify 结果，客户端需自行反序列化
 *   - attestationQuote 是对 data 计算 SHA256 后注入 user_report_data 获取的 SGX quote
 *   - 非 SGX 环境下 attestationQuote 为空字符串
 *
 * 异常响应（非 200）：
 *   { error: "错误消息" }
 *
 * @param {(req: express.Request) => Promise<any>} fn
 * @param {import('./modules/webauthn/account-freeze-manager.js').AccountFreezeManager|null} accountFreezeManager
 * @param {import('./sync/sync-manager.js').SyncManager|null} syncManager - 同步管理器（2PC 用，null 则不走 2PC）
 * @param {(req: express.Request) => string} getPath - 获取请求路径的函数
 * @param {Object} [options] - 冻结检查选项
 * @param {boolean} [options.allowPurposeRegister] - 若为 true，当 payload.purpose=register 时跳过冻结检查（用于 challenge 接口）
 * @returns {express.RequestHandler}
 */
function wrap(fn, accountFreezeManager, syncManager, getPath, options = {}) {
  return async (req, res) => {
    try {
      // 账户冻结检查（accountFreezeManager 为 null 的路由跳过检查）
      let canLiftFreeze = false;
      if (accountFreezeManager && req.body && req.body.payload) {
        try {
          const payload = JSON.parse(req.body.payload);

          // 检查是否应跳过冻结检查
          let skipFreezeCheck = false;

          // 1. challenge 接口：purpose=register 时跳过冻结检查
          if (options.allowPurposeRegister && payload.purpose === 'register') {
            skipFreezeCheck = true;
          }

          // 2. 自动检测 Passkey 注册替换场景：
          //    userId 冻结 + 有 attestationResponse + credentialId 与冻结记录不同 → 跳过冻结检查
          //    这是冻结账户通过 purpose=register 重新注册新 Passkey 的场景
          if (!skipFreezeCheck && payload.attestationResponse && payload.userId) {
            const newCredentialId = payload.attestationResponse.id;
            if (newCredentialId) {
              const freezeStatus = accountFreezeManager.getFreezeStatus(payload.userId);
              if (freezeStatus.frozen && freezeStatus.withinFreezePeriod && newCredentialId !== freezeStatus.credentialId) {
                // 冻结账户注册新 Passkey（credentialId 不同），跳过冻结检查
                // handler 内部会处理：删除旧冻结 Passkey → 注册新 Passkey → 重置冻结时间
                skipFreezeCheck = true;
                console.log(`[FreezeCheck] Auto-detected passkey replacement for frozen account: userId=${payload.userId}, newCredentialId=${newCredentialId}`);
              }
            }
          }

          if (!skipFreezeCheck) {
            const { userId, credentialId, hasWebauthnSignature } = _extractFreezeCheckFields(payload);

            if (userId) {
              const freezeCheck = accountFreezeManager.checkRequest(userId, credentialId, hasWebauthnSignature);
              if (freezeCheck.blocked) {
                console.log(`[FreezeCheck] Request blocked for userId=${userId}: ${freezeCheck.reason}`);
                const status = freezeCheck.reason.startsWith('Account is frozen') ? 403 : 401;
                return res.status(status).json({ error: freezeCheck.reason });
              }
              canLiftFreeze = freezeCheck.canLiftFreeze;
            }
          }
        } catch (parseErr) {
          // payload 解析失败，让 handler 处理（不影响正常流程）
        }
      }

      // 判断是否需要 2PC 同步复制
      // 条件：syncManager 存在 + 是多节点部署（配置了 peerUrls）+ 是写操作
      // 注意：即使当前无连接（其他节点都死了），多节点部署也需要走 2PC 路径
      // 这样当无连接时，waitForPrepareAck 会 reject，防止数据分叉
      const path = getPath ? getPath(req) : req.path;
      const needs2PC = syncManager && WRITE_PATHS.has(path) && syncManager.isMultiNodeDeployment();

      let result;

      if (needs2PC) {
        // ===== 2PC 模式 =====
        const writeId = crypto.randomUUID();
        let prepareSent = false;
        let committed = false;

        // 1. 开启手动事务
        syncManager.beginManualTransaction(writeId);

        try {
          // 2. 执行业务逻辑（handler 内部的 writeTransaction 会在已有事务中执行）
          result = await fn(req);

          // 3. 读取本次事务新增的 _sync_log 条目
          const newEntries = syncManager.getManualTransactionEntries(writeId);

          if (newEntries.length > 0) {
            // 4. 广播 prepare，等待 quorum 确认
            const userId2pc = _extractUserIdForRouting(req.body);
            const shardId = syncManager.getShardForUser(userId2pc);
            const term = syncManager._shardElections.get(shardId)?._currentTerm || 0;
            prepareSent = true;
            await syncManager.waitForPrepareAck(writeId, newEntries, term, shardId);

            // 4b. 验证 term 未变（防止 prepare 等待期间发生选举导致脑裂）
            const termAfter = syncManager._shardElections.get(shardId)?._currentTerm || 0;
            if (termAfter !== term) {
              throw new Error('2PC prepare rejected: term changed during prepare (was ' + term + ', now ' + termAfter + ')');
            }
          }

          // 5. 提交事务
          syncManager.commitManualTransaction(writeId);
          committed = true;

          // 6. 广播 commit 给所有 Follower（fire-and-forget，不能因广播失败回滚已提交的事务）
          if (newEntries && newEntries.length > 0) {
            try { syncManager.broadcastCommit(writeId); } catch (bcErr) {
              console.error('[2PC] broadcastCommit failed (data committed locally, followers will sync via pull):', bcErr.message);
            }
          }
        } catch (err) {
          // 回滚事务（如果已 COMMIT 则 rollback 无效，安全忽略）
          if (!committed) {
            syncManager.rollbackManualTransaction(writeId);
          }
          // 如果 prepare 已发出，广播 abort 让 Follower 立即释放事务锁
          if (prepareSent && !committed) {
            try { syncManager.broadcastAbort(writeId, err.message); } catch (_) {}
          }
          throw err;
        }
      } else {
        // ===== 普通模式（单节点或读操作）=====
        result = await fn(req);
      }

      // 若请求成功且可解除冻结，自动解除
      if (canLiftFreeze && accountFreezeManager && req.body && req.body.payload) {
        try {
          const payload = JSON.parse(req.body.payload);
          const { userId } = _extractFreezeCheckFields(payload);
          if (userId) {
            accountFreezeManager.liftFreeze(userId);
            console.log(`[FreezeCheck] Account unfrozen after successful passkey-signed request: userId=${userId}`);
          }
        } catch (parseErr) {
          // 解析失败不影响已成功的请求
        }
      }

      // 将 handler 返回值序列化为 JSON 字符串
      const data = JSON.stringify(result);
      // 对 data 计算 SHA256 → 注入 user_report_data → 获取 SGX quote
      const attestationQuote = getAttestationQuote(data);
      return res.json({ attestationQuote, data });
    } catch (err) {
      // 只返回 message，不暴露 stack trace 或内部细节
      const msg = err.message || 'Internal server error';
      const status = classifyError(msg);
      return res.status(status).json({ error: msg });
    }
  };
}

/**
 * 从请求 payload 中提取冻结检查所需的字段
 * 不同接口的 payload 结构不同：
 *   - 大部分接口：userId/credentialId/webauthnSignature 在顶层
 *   - tx-signing：userId/credentialId 在 authorizationJson 内，webauthnSignature 在顶层
 *
 * @param {Object} payload - 解析后的请求 payload
 * @returns {{ userId: string|null, credentialId: string|null, hasWebauthnSignature: boolean }}
 */
function _extractFreezeCheckFields(payload) {
  let userId = payload.userId || null;
  let credentialId = payload.credentialId || null;
  const hasWebauthnSignature = !!payload.webauthnSignature;

  // tx-signing 特殊处理：从 authorizationJson 中提取 userId 和 credentialId
  if (payload.authorizationJson && typeof payload.authorizationJson === 'string') {
    try {
      const auth = JSON.parse(payload.authorizationJson);
      if (!userId && auth.userId) userId = auth.userId;
      if (!credentialId && auth.credentialId) credentialId = auth.credentialId;
    } catch (_) {
      // authorizationJson 解析失败，忽略
    }
  }

  return { userId, credentialId, hasWebauthnSignature };
}

/**
 * 根据错误消息决定 HTTP 状态码
 * @param {string} msg
 * @returns {number}
 */
function classifyError(msg) {
  if (msg.startsWith('Platform verification failed')) return 401;
  if (msg.startsWith('Passkey not bound')) return 401;
  if (msg.startsWith('Passkey not found')) return 401;
  if (msg.startsWith('WebAuthn verification failed')) return 401;
  if (msg.startsWith('Account is frozen')) return 403;
  if (msg.startsWith('Authentication is required')) return 400;
  if (msg.startsWith('Invalid payload')) return 400;
  if (msg.includes('is required')) return 400;
  if (msg.includes('not found')) return 404;
  if (msg.includes('2PC')) return 503;
  return 500;
}

/**
 * 启动 HTTP 服务
 *
 * @param {express.Application} app
 * @param {number} [port] - 端口号，默认从 SGX_HTTP_PORT 环境变量读取，再默认 3000
 * @returns {Promise<import('http').Server>}
 */
export function startServer(app, port) {
  const listenPort = port || parseInt(process.env.SGX_HTTP_PORT || '3000', 10);
  return new Promise((resolve) => {
    const server = app.listen(listenPort, () => {
      console.log(`[SGX HTTP] Server listening on port ${listenPort}`);
      resolve(server);
    });
  });
}
