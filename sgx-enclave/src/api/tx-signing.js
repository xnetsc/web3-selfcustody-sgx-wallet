/**
 * TODO-17: 交易签名流程 API
 * 完整签名请求处理：接收平台签名请求 → 14 项授权验证 → 签名执行 → 状态更新 → 返回签名结果
 *
 * 重要：全成功或全失败，不允许半成功状态。
 * 签名成功后若状态更新失败（重试耗尽），丢弃签名结果，返回纯失败，客户端可重试整个请求。
 *
 * HTTP body 仅包含 { payload, platformSignature }，
 * 所有业务参数从验证后的 payload 解析获取。
 *
 * 支持两种模式：
 *   模式一（txParams）：平台提供结构化 txParams，所有字段被视为可信
 *   模式二/三（rawTxHex）：rawTxHex 模式，所有鉴权相关字段必须从 raw bytes 解析得出
 *
 * 判断依据：若 payload.transaction 包含 rawTxHex 字段，则为模式二/三
 */

import { createConnProxy } from '../sync/sync-adapter.js';

export class TxSigningHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/auth-engine/auth-engine.js').AuthEngine} deps.authEngine
   * @param {import('../modules/signing/transaction-signer.js').TransactionSigner} deps.transactionSigner
   * @param {import('../modules/state-management/state-manager.js').StateManager} deps.stateManager
   * @param {import('../modules/wallet-management/wallet-manager.js').WalletManager} deps.walletManager
   * @param {import('@xnetx/raft-hlc-sync').SyncEngine} deps.engine
   */
  constructor(deps) {
    if (!deps.authEngine) throw new Error('TxSigningHandler requires authEngine');
    if (!deps.transactionSigner) throw new Error('TxSigningHandler requires transactionSigner');
    if (!deps.stateManager) throw new Error('TxSigningHandler requires stateManager');
    if (!deps.walletManager) throw new Error('TxSigningHandler requires walletManager');
    if (!deps.engine) throw new Error('TxSigningHandler requires engine');
    this._authEngine = deps.authEngine;
    this._signer = deps.transactionSigner;
    this._state = deps.stateManager;
    this._wallet = deps.walletManager;
    this._engine = deps.engine;
  }

  /**
   * 处理签名请求
   *
   * payload JSON: {
   *   authorizationJson: string,  // 授权 JSON 字符串（不含 webauthnSignature，用于计算哈希）
   *   webauthnSignature: Object,  // WebAuthn 签名（单独字段）
   *   transaction: Object | { rawTxHex: string, walletAddress: string }
   * }
   *
   * 重要：authorizationJson 是不含 webauthnSignature 的原始 JSON 字符串。
   * 客户端对 authorizationJson 计算 SHA256 哈希作为 WebAuthn challenge，
   * 服务端对同一字符串计算哈希验证签名。
   * 这样才能保证客户端和服务端对同一字符串计算哈希，WebAuthn 验证才能通过。
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<{ success: boolean, signedTransaction?: string, txHash?: string, step?: number, reason?: string }>}
   */
  async handleSigningRequest(request) {
    // 0. 验证平台白名单签名 + 解析 payload
    const whitelistResult = this._authEngine._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }
    // 保存原始 payload 和 platformSignature，供 auth-engine 内部重复验证使用
    const originalPayload = request.payload;
    const originalPlatformSignature = request.platformSignature;
    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    if (!request.authorizationJson) {
      throw new Error('authorizationJson is required (authorization JSON string without webauthnSignature)');
    }
    if (!request.webauthnSignature) {
      throw new Error('webauthnSignature is required');
    }
    if (!request.transaction) {
      throw new Error('transaction is required');
    }

    // authorizationJson 必须是字符串（原始 JSON 字符串，不含 webauthnSignature）
    if (typeof request.authorizationJson !== 'string') {
      throw new Error('authorizationJson must be a JSON string');
    }

    // 解析授权 JSON 字符串
    let auth;
    try {
      auth = JSON.parse(request.authorizationJson);
    } catch (err) {
      throw new Error('authorizationJson is not valid JSON string');
    }

    // 将 webauthnSignature 注入到 auth 对象中（供 auth-engine 验证）
    auth.webauthnSignature = request.webauthnSignature;

    // 保存原始授权 JSON 字符串（不含 webauthnSignature），用于计算哈希（与客户端保持一致）
    const authorizationJson = request.authorizationJson;

    const tx = request.transaction;

    if (!auth.userId) throw new Error('authorizationJson.userId is required');
    if (!auth.authorizationId) throw new Error('authorizationJson.authorizationId is required');
    if (!request.guid) throw new Error('guid is required for replay protection');

    const guid = request.guid;

    console.log(`[TxSigning] handleSigningRequest: userId=${auth.userId}, authorizationId=${auth.authorizationId}, guid=${guid}`);

    // ===== 判断模式：rawTxHex 模式 vs txParams 模式 =====
    const isRawMode = !!tx.rawTxHex;

    // 将解析后的 auth 对象（含 webauthnSignature）和原始 authorizationJson 字符串一起传给处理函数
    // 同时保留原始 payload 和 platformSignature，供 auth-engine 内部验证平台签名使用
    const enrichedRequest = { ...request, authorization: auth, authorizationJson, payload: originalPayload, platformSignature: originalPlatformSignature };

    if (isRawMode) {
      // ===== 模式二/三：rawTxHex 模式 =====
      return this._handleRawMode(enrichedRequest, whitelistResult.address);
    } else {
      // ===== 模式一：结构化 txParams 模式 =====
      return this._handleTxParamsMode(enrichedRequest, whitelistResult.address);
    }
  }

  /**
   * 模式一：结构化 txParams 模式（平台提供所有字段，可信）
   */
  async _handleTxParamsMode(request, platformAddress) {
    const { authorization: auth, transaction: tx, guid } = request;

    if (!tx.chainId) throw new Error('transaction.chainId is required');
    if (!tx.fromAddress) throw new Error('transaction.fromAddress is required');

    console.log(`[TxSigning] _handleTxParamsMode: userId=${auth.userId}, authorizationId=${auth.authorizationId}, chainId=${tx.chainId}`);

    // 1. 验证授权（14 项检查）
    const verifyResult = await this._authEngine.verify(request);
    if (!verifyResult.approved) {
      console.log(`[TxSigning] _handleTxParamsMode: REJECTED at step ${verifyResult.step} - ${verifyResult.reason}`);
      return {
        success: false,
        step: verifyResult.step,
        reason: verifyResult.reason,
      };
    }

    // 2. 从数据库获取私钥
    const wallet = await this._wallet.getWalletByAddress(
      auth.userId,
      tx.chainId,
      tx.fromAddress
    );
    if (!wallet) {
      console.log(`[TxSigning] _handleTxParamsMode: wallet not found for ${tx.fromAddress}`);
      return {
        success: false,
        step: 0,
        reason: `Wallet not found: address=${tx.fromAddress}`,
      };
    }

    const privateKey = wallet.privateKey.startsWith('0x')
      ? wallet.privateKey
      : '0x' + wallet.privateKey;

    // 3. 执行交易签名
    let signResult;
    try {
      signResult = this._signer.signRawTransaction(tx, privateKey);
    } catch (err) {
      console.log(`[TxSigning] _handleTxParamsMode: signing failed - ${err.message}`);
      return {
        success: false,
        step: 0,
        reason: `Signing failed: ${err.message}`,
      };
    }

    // 4. 参数验证
    if (tx.amount === undefined || tx.amount === null) {
      return {
        success: false,
        step: 0,
        reason: 'tx.amount is required: must be explicitly provided by the requester',
      };
    }
    if (tx.tokenAddress === undefined || tx.tokenAddress === null) {
      return {
        success: false,
        step: 0,
        reason: `tx.tokenAddress is required: must be explicitly provided by the requester (use "${tx.chainId}_native" for native token)`,
      };
    }
    // 验证 tokenAddress 格式：合法以太坊地址、或带 chainId 前缀的特殊标识符
    // 不允许裸 "native" / "unknown"，必须带 chainId 前缀（如 "1_native"）
    const isValidTxTokenAddress = (addr, chainId) => {
      if (/^0x[0-9a-fA-F]{40}$/.test(addr)) return true;
      if (addr === `${chainId}_native` || addr === `${chainId}_unknown`) return true;
      return false;
    };
    if (!isValidTxTokenAddress(tx.tokenAddress, tx.chainId)) {
      return {
        success: false,
        step: 0,
        reason: `tx.tokenAddress format invalid: "${tx.tokenAddress}". Must be a valid Ethereum address (0x...) or "${tx.chainId}_native" / "${tx.chainId}_unknown"`,
      };
    }

    // 5. 在同一事务中执行所有状态相关操作（原子性保证）
    // 注意：better-sqlite3 事务回调必须是同步函数，所有内部方法均为同步实现
    const { computeAuthorizationHash } = await import('../modules/auth-engine/authorization-parser.js');
    // 使用原始 JSON 字符串计算哈希（与客户端保持一致）
    const authHash = computeAuthorizationHash(request.authorizationJson);
    const granteeList = Array.isArray(auth.grantee) ? auth.grantee : [auth.grantee];

    try {
      await this._engine.write(async (db) => {
        const conn = createConnProxy(db);
        this._state._checkAndRecordNonceInTransaction(conn, auth.authorizationId, guid);
        this._state._ensureStateExists(conn, auth.authorizationId, auth.userId, granteeList);
        // 在事务内再次检查累计限制（与 incrementUsage 原子执行，消除 TOCTOU 竞态）
        if (auth.scope?.cumulativeLimits) {
          this._state._checkLimitsInTransaction(conn, auth.authorizationId, auth.scope.cumulativeLimits, {
            amount: tx.amount,
            chainId: tx.chainId,
            tokenAddress: tx.tokenAddress,
          });
        }
        this._state._saveAuthorizationRecordInTransaction(
          conn,
          auth.userId,
          auth.authorizationId,
          granteeList,
          auth,
          authHash
        );
        this._state._incrementUsageInTransaction(
          conn,
          auth.authorizationId,
          tx.amount,
          tx.chainId,
          tx.tokenAddress
        );
      }, auth.userId);
    } catch (err) {
      console.error(`[TxSigning] _handleTxParamsMode: FAILED - transaction rolled back: ${err.message}`);
      return {
        success: false,
        step: 0,
        reason: `Transaction failed: ${err.message}`,
      };
    }

    console.log(`[TxSigning] _handleTxParamsMode: success, txHash=${signResult.txHash}`);
    return {
      success: true,
      signedTransaction: signResult.signedTransaction,
      txHash: signResult.txHash,
    };
  }

  /**
   * 模式二/三：rawTxHex 模式
   *
   * 安全原则：所有鉴权相关字段必须从 raw bytes 解析得出，不能信任平台提供的显式字段
   *
   * 原子性保证：签名（纯内存操作）完成后，所有 DB 写操作（nonce 记录、状态创建、
   * 授权记录保存、incrementUsage）在同一事务中完成，确保全成功或全失败。
   */
  async _handleRawMode(request, platformAddress) {
    const { authorization: auth, transaction: tx, guid } = request;
    const { rawTxHex, walletAddress } = tx;

    if (!rawTxHex) throw new Error('transaction.rawTxHex is required for raw mode');
    if (!walletAddress) throw new Error('transaction.walletAddress is required for raw mode');

    console.log(`[TxSigning] _handleRawMode: userId=${auth.userId}, authorizationId=${auth.authorizationId}, rawTxHex present`);

    // ===== 第一步：解析 rawTxHex，获取所有鉴权相关字段 =====
    let parsedTx;
    let tokenInfo;
    try {
      parsedTx = this._signer.parseRawTransactionHex(rawTxHex);
      console.log(`[TxSigning] _handleRawMode: parsed rawTxHex: chainId=${parsedTx.chainId}, to=${parsedTx.to}, value=${parsedTx.value}, data=${parsedTx.data}`);
    } catch (err) {
      throw new Error('Failed to parse rawTxHex: ' + err.message);
    }

    // 从解析结果推导 tokenAddress 和 amount
    tokenInfo = this._signer.deriveTokenAddressFromParsedTx(parsedTx);
    console.log(`[TxSigning] _handleRawMode: derived tokenInfo: totalTokens=${tokenInfo.tokens.length}`);
    
    // 记录所有识别出的token
    if (tokenInfo.tokens.length > 0) {
      console.log(`[TxSigning] _handleRawMode: transaction with ${tokenInfo.tokens.length} tokens:`);
      tokenInfo.tokens.forEach((token, index) => {
        console.log(`[TxSigning] _handleRawMode: token[${index}]: tokenAddress=${token.tokenAddress}, amount=${token.amount}, isNative=${token.isNative}`);
      });
    }

    // ===== 第二步：用解析出的字段构建鉴权用的 derivedTx 对象 =====
    // 重要：不能信任平台提供的显式字段，必须用 raw bytes 解析出的值
    // deriveTokenAddressFromParsedTx 保证 tokens.length >= 1，fallback 仅作防御性保护
    const derivedTx = {
      chainId: parsedTx.chainId,
      toAddress: parsedTx.to,
      fromAddress: walletAddress,
      // 使用第一个token的信息用于向后兼容
      amount: tokenInfo.tokens[0]?.amount || '0',
      tokenAddress: tokenInfo.tokens[0]?.tokenAddress || `${parsedTx.chainId}_unknown`,
      // 添加所有识别出的token信息，以便授权引擎可以进行更全面的检查
      allTokens: tokenInfo.tokens,
    };

    // 构建鉴权请求（用 derivedTx 替换平台提供的显式 tx 字段）
    // 注意：必须传入 authorizationJson，供 auth-engine 计算哈希验证 WebAuthn 签名
    const authRequest = {
      authorization: auth,
      authorizationJson: request.authorizationJson,
      transaction: derivedTx,
      platformSignature: request.platformSignature,
      payload: request.payload,
      guid,
    };

    // ===== 第三步：执行 14 项鉴权检查（使用 derivedTx） =====
    const verifyResult = await this._authEngine.verify(authRequest);
    if (!verifyResult.approved) {
      console.log(`[TxSigning] _handleRawMode: REJECTED at step ${verifyResult.step} - ${verifyResult.reason}`);
      return {
        success: false,
        step: verifyResult.step,
        reason: verifyResult.reason,
      };
    }

    // ===== 第四步：执行签名（纯内存操作，不涉及 DB） =====
    // 注意：此处直接调用底层签名方法，不调用 signAndUpdate，
    // 因为 signAndUpdate 内部会调用 incrementUsage（独立事务），
    // 而我们需要将 incrementUsage 与其他 DB 写操作合并到同一事务中（第五步）。
    const identification = this._signer.identifyTransactionType(rawTxHex);
    const operationType = this._signer.identifyOperation(identification);

    // 检查 dataPolicy
    const policyCheck = this._signer.checkDataPolicy(auth.scope?.dataPolicy, identification, operationType);
    if (!policyCheck.allowed) {
      console.log(`[TxSigning] _handleRawMode: REJECTED - DataPolicy check failed: ${policyCheck.reason}`);
      return {
        success: false,
        step: 0,
        reason: `DataPolicy check failed: ${policyCheck.reason}`,
      };
    }

    // 从数据库取私钥
    const effectiveChainId = identification.recognized ? identification.parsed.chainId : parsedTx.chainId;
    const walletInfo = await this._wallet.getWalletByAddress(auth.userId, effectiveChainId, walletAddress);
    if (!walletInfo) {
      console.log(`[TxSigning] _handleRawMode: wallet not found for ${walletAddress}`);
      return {
        success: false,
        step: 0,
        reason: `Wallet not found: address=${walletAddress}`,
      };
    }

    const privateKey = walletInfo.privateKey.startsWith('0x')
      ? walletInfo.privateKey
      : '0x' + walletInfo.privateKey;

    // 执行签名（纯内存操作）
    let signResult;
    try {
      if (identification.recognized) {
        // 模式二：已识别的交易类型，对预构造的字节直接签名
        const rawResult = this._signer.signRawBytes(rawTxHex, privateKey);
        signResult = {
          signedTransaction: rawResult.signedTransaction,
          txHash: rawResult.txHash,
        };
      } else {
        // 模式三：不可识别的任意二进制数据，做以太坊格式签名
        signResult = this._signer.signArbitraryData(rawTxHex, privateKey);
      }
    } catch (err) {
      console.log(`[TxSigning] _handleRawMode: signing failed - ${err.message}`);
      return {
        success: false,
        step: 0,
        reason: `Signing failed: ${err.message}`,
      };
    }

    // ===== 第五步：在同一事务中执行所有 DB 写操作（原子性保证） =====
    // 包括：nonce 记录、状态创建、授权记录保存、incrementUsage（多 token 循环）
    // 任何一步失败都会回滚整个事务，确保全成功或全失败。
    const { computeAuthorizationHash } = await import('../modules/auth-engine/authorization-parser.js');
    // 使用原始 JSON 字符串计算哈希（与客户端保持一致）
    const authHash = computeAuthorizationHash(request.authorizationJson);
    const granteeList = Array.isArray(auth.grantee) ? auth.grantee : [auth.grantee];

    try {
      await this._engine.write(async (db) => {
        const conn = createConnProxy(db);
        // 5a. 检查并记录 nonce（防重放）
        this._state._checkAndRecordNonceInTransaction(conn, auth.authorizationId, guid);
        // 5b. 确保授权状态记录存在
        this._state._ensureStateExists(conn, auth.authorizationId, auth.userId, granteeList);
        // 5c. 在事务内再次检查累计限制（与 incrementUsage 原子执行，消除 TOCTOU 竞态）
        // rawTxHex 模式下，对每个 token 分别检查（使用第一个 token 做总量检查）
        if (auth.scope?.cumulativeLimits && tokenInfo.tokens.length > 0) {
          this._state._checkLimitsInTransaction(conn, auth.authorizationId, auth.scope.cumulativeLimits, {
            amount: tokenInfo.tokens[0].amount,
            chainId: effectiveChainId,
            tokenAddress: tokenInfo.tokens[0].tokenAddress,
          });
        }
        // 5d. 保存授权原文记录（争议取证）
        this._state._saveAuthorizationRecordInTransaction(
          conn,
          auth.userId,
          auth.authorizationId,
          granteeList,
          auth,
          authHash
        );
        // 5e. 递增累计用量（多 token 循环，使用从 raw bytes 解析出的 tokenAddress 和 amount）
        for (const token of tokenInfo.tokens) {
          console.log(`[TxSigning] _handleRawMode: incrementing usage for token: tokenAddress=${token.tokenAddress}, amount=${token.amount}`);
          this._state._incrementUsageInTransaction(
            conn,
            auth.authorizationId,
            token.amount,
            effectiveChainId,
            token.tokenAddress
          );
        }
      }, auth.userId);
    } catch (err) {
      console.error(`[TxSigning] _handleRawMode: FAILED - transaction rolled back: ${err.message}`);
      return {
        success: false,
        step: 0,
        reason: `Transaction failed: ${err.message}`,
      };
    }

    console.log(`[TxSigning] _handleRawMode: success, txHash=${signResult.txHash || signResult.messageHash}`);
    return {
      success: true,
      signedTransaction: signResult.signedTransaction,
      txHash: signResult.txHash,
    };
  }
}
