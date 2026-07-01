/**
 * TODO-20: 授权导出流程 API
 *
 * 支持两种密钥交换方式，流程相似：
 *
 * ECDH（默认）：
 *   init: 客户端传 peerPublicKey → SGX 生成 ECDH 密钥对，算出共享密钥加密钱包数据 → 返回 enclavePublicKey + encryptedData
 *   complete: 客户端确认已收到 → SGX 删除钱包
 *
 * RSA：
 *   init: 客户端传 rsaPublicKey → SGX 生成 AES 密钥加密钱包数据，RSA 加密 AES 密钥 → 返回 encryptedAESKey + encryptedData
 *   complete: 客户端确认已收到 → SGX 删除钱包
 *
 * 两种模式的 complete 都只是通知删除，不返回加密数据。
 * 加密使用 AES-256-GCM
 * 导出后自动删除对应钱包数据（两步确认机制防止误操作）
 * 导出会话有 TTL，TTL 到期后自动删除会话及对应钱包
 *
 * HTTP body 仅包含 { payload, platformSignature }，
 * 所有业务参数从验证后的 payload 解析获取。
 *
 * payload 中需要携带：
 *   - rawChallenge：从 /api/challenge 获取的原始挑战值
 *   - userIntentJson：用户意图的原始 JSON 字符串
 *   - webauthnSignature：用 intentHash = SHA256(rawChallenge + userIntentJson) 做的 WebAuthn 签名
 *
 * 批量导出：
 *   exportInfo 是一个数组，每个元素为 { walletId, addresses }
 *   - addresses 为空数组时，导出该 walletId 下的所有私钥
 *   - addresses 有值时，导出该 walletId 下指定地址的私钥
 *   userIntentJson 结构：
 *     { purpose: "key_export", userId, peerPublicKey, exportInfo: [{walletId, addresses}] }
 *   或 RSA 模式：
 *     { purpose: "key_export", userId, rsaPublicKey, exportInfo: [{walletId, addresses}] }
 */

import { verifyWebAuthnSignature } from '../modules/webauthn/verifier.js';

export class ExportFlowHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/whitelist/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../modules/webauthn/passkey-manager.js').PasskeyManager} deps.passkeyManager
   * @param {import('../modules/webauthn/challenge-manager.js').WebAuthnChallengeManager} deps.challengeManager
   * @param {import('../modules/wallet-management/wallet-manager.js').WalletManager} deps.walletManager
   * @param {import('../modules/key-management/key-export.js').KeyExporter} deps.keyExporter
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('ExportFlowHandler requires whitelistVerifier');
    if (!deps.passkeyManager) throw new Error('ExportFlowHandler requires passkeyManager');
    if (!deps.challengeManager) throw new Error('ExportFlowHandler requires challengeManager');
    if (!deps.walletManager) throw new Error('ExportFlowHandler requires walletManager');
    if (!deps.keyExporter) throw new Error('ExportFlowHandler requires keyExporter');
    this._whitelist = deps.whitelistVerifier;
    this._passkey = deps.passkeyManager;
    this._challenge = deps.challengeManager;
    this._wallet = deps.walletManager;
    this._keyExporter = deps.keyExporter;
  }

  /**
   * 第一步：初始化批量导出会话
   *
   * payload JSON: {
   *   userId, credentialId, webauthnSignature,
   *   rawChallenge,    // 从 /api/challenge 获取的原始挑战值
   *   userIntentJson,  // 用户意图 JSON 字符串：
   *                    //   ECDH: { purpose: "key_export", userId, peerPublicKey, exportInfo: [{walletId, addresses}] }
   *                    //   RSA:  { purpose: "key_export", userId, rsaPublicKey, exportInfo: [{walletId, addresses}] }
   *   exportInfo,      // 数组：[{ walletId, addresses }]，addresses 为空数组时导出该 walletId 下所有私钥
   *   peerPublicKey?,  // ECDH 模式
   *   rsaPublicKey?    // RSA 模式
   * }
   * - 传 peerPublicKey：ECDH 模式（默认），返回 enclavePublicKey + encryptedData
   * - 传 rsaPublicKey：RSA 模式，返回 encryptedAESKey + encryptedData
   * - 二者必传其一，优先 rsaPublicKey
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<Object>} 响应含 keyType 字段标明密钥交换类型
   */
  async handleInit(request) {
    // 1. 验证平台白名单签名
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[ExportFlow] handleInit: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 2. 解析验证过的 payload，替换 request
    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    console.log(`[ExportFlow] handleInit: userId=${request.userId}, exportInfo=${JSON.stringify(request.exportInfo)}`);

    if (!request.userId) throw new Error('userId is required');
    if (!request.credentialId) throw new Error('credentialId is required');
    if (!Array.isArray(request.exportInfo) || request.exportInfo.length === 0) {
      throw new Error('exportInfo must be a non-empty array');
    }
    // 验证 exportInfo 每个元素的结构
    for (const item of request.exportInfo) {
      if (!item.walletId) throw new Error('Each exportInfo item must have a walletId');
      // addresses 不传或为 null 时，默认为空数组（导出该 walletId 下所有私钥）
      if (!item.addresses) {
        item.addresses = [];
      } else if (!Array.isArray(item.addresses)) {
        throw new Error('Each exportInfo item addresses must be an array (can be empty to export all)');
      } else {
        // 验证 addresses 元素格式：可以是字符串（纯地址）或 {address, chainId} 对象
        for (const addr of item.addresses) {
          if (typeof addr !== 'string' && !(addr && typeof addr === 'object' && addr.address)) {
            throw new Error('Each address in addresses must be a string or {address, chainId} object');
          }
        }
      }
    }
    if (!request.peerPublicKey && !request.rsaPublicKey) {
      throw new Error('Either peerPublicKey (ECDH) or rsaPublicKey (RSA) is required');
    }
    if (!request.webauthnSignature) throw new Error('webauthnSignature is required');
    if (!request.rawChallenge) throw new Error('rawChallenge is required');
    if (!request.userIntentJson) throw new Error('userIntentJson is required');

    // 3. 验证 Passkey 归属
    const ownershipValid = await this._passkey.verifyPasskeyOwnership(request.userId, request.credentialId);
    if (!ownershipValid) {
      console.log(`[ExportFlow] handleInit: REJECTED - passkey not bound to userId=${request.userId}`);
      throw new Error('Passkey not bound to this user');
    }

    const passkey = await this._passkey.getPasskey(request.userId, request.credentialId);
    if (!passkey) throw new Error('Passkey not found');

    // 4. 验证 userIntentJson 是合法 JSON（提前验证）
    let intent;
    try {
      intent = JSON.parse(request.userIntentJson);
    } catch {
      throw new Error('userIntentJson must be a valid JSON string');
    }

    // 5. 验证 WebAuthn 签名
    // - rawChallenge：服务端生成的原始随机挑战值（用于查询 DB 记录）
    // - userIntentJson：用户意图 JSON 字符串（用于计算 intentHash）
    // - verifier 内部计算 intentHash = SHA256(rawChallenge + userIntentJson) 作为 expectedChallenge
    const sigResult = await verifyWebAuthnSignature({
      userId: request.userId,
      credentialId: request.credentialId,
      webauthnSignature: request.webauthnSignature,
      challengeManager: this._challenge,
      purpose: 'key_export',
      rawChallenge: request.rawChallenge,
      userIntentJson: request.userIntentJson,
      publicKeyCose: passkey.publicKeyCose,
    });
    if (!sigResult.verified) {
      console.log(`[ExportFlow] handleInit: REJECTED - WebAuthn signature invalid`);
      throw new Error(`WebAuthn verification failed: ${sigResult.reason}`);
    }

    // 6. 验证 userIntentJson 中的业务参数与实际请求参数一致
    // 原则：userIntentJson 中的值不允许转换，直接与实际请求参数比对，不一致则拒绝
    // 所有需要验证的字段（包括密钥交换参数，防止中间人替换）
    // ECDH 模式：userIntentJson 必须包含 peerPublicKey
    // RSA 模式：userIntentJson 必须包含 rsaPublicKey（原始 PEM 字符串，不做任何转换）

    // 验证简单字符串字段
    const simpleFields = {
      purpose: 'key_export',
      userId: request.userId,
      ...(request.rsaPublicKey ? { rsaPublicKey: request.rsaPublicKey } : {}),
      ...(request.peerPublicKey ? { peerPublicKey: request.peerPublicKey } : {}),
    };
    for (const [key, actualValue] of Object.entries(simpleFields)) {
      if (intent[key] !== actualValue) {
        console.log(`[ExportFlow] handleInit: REJECTED - userIntent.${key} mismatch`);
        throw new Error(`userIntent parameter mismatch: ${key} was signed as ${JSON.stringify(intent[key])} but actual value is ${JSON.stringify(actualValue)}`);
      }
    }

    // 验证 exportInfo 数组（逐字段深度比较，避免对象属性顺序问题）
    const intentExportInfo = intent.exportInfo;
    const actualExportInfo = request.exportInfo;
    if (!Array.isArray(intentExportInfo) || intentExportInfo.length !== actualExportInfo.length) {
      console.log(`[ExportFlow] handleInit: REJECTED - userIntent.exportInfo length mismatch`);
      throw new Error(`userIntent parameter mismatch: exportInfo length was signed as ${intentExportInfo?.length} but actual value is ${actualExportInfo.length}`);
    }
    for (let i = 0; i < actualExportInfo.length; i++) {
      const intentItem = intentExportInfo[i];
      const actualItem = actualExportInfo[i];
      // 比较 walletId
      if (intentItem.walletId !== actualItem.walletId) {
        console.log(`[ExportFlow] handleInit: REJECTED - userIntent.exportInfo[${i}].walletId mismatch`);
        throw new Error(`userIntent parameter mismatch: exportInfo[${i}].walletId was signed as ${JSON.stringify(intentItem.walletId)} but actual value is ${JSON.stringify(actualItem.walletId)}`);
      }
      // 比较 addresses 数组
      const intentAddresses = intentItem.addresses || [];
      const actualAddresses = actualItem.addresses || [];
      if (intentAddresses.length !== actualAddresses.length) {
        console.log(`[ExportFlow] handleInit: REJECTED - userIntent.exportInfo[${i}].addresses length mismatch`);
        throw new Error(`userIntent parameter mismatch: exportInfo[${i}].addresses length was signed as ${intentAddresses.length} but actual value is ${actualAddresses.length}`);
      }
      for (let j = 0; j < actualAddresses.length; j++) {
        const intentAddr = intentAddresses[j];
        const actualAddr = actualAddresses[j];
        if (typeof actualAddr === 'string') {
          // 纯地址字符串：直接比较
          if (intentAddr !== actualAddr) {
            console.log(`[ExportFlow] handleInit: REJECTED - userIntent.exportInfo[${i}].addresses[${j}] mismatch`);
            throw new Error(`userIntent parameter mismatch: exportInfo[${i}].addresses[${j}] was signed as ${JSON.stringify(intentAddr)} but actual value is ${JSON.stringify(actualAddr)}`);
          }
        } else {
          // {address, chainId} 对象：逐字段比较
          if (!intentAddr || typeof intentAddr !== 'object') {
            console.log(`[ExportFlow] handleInit: REJECTED - userIntent.exportInfo[${i}].addresses[${j}] type mismatch`);
            throw new Error(`userIntent parameter mismatch: exportInfo[${i}].addresses[${j}] type mismatch`);
          }
          if (intentAddr.address !== actualAddr.address) {
            console.log(`[ExportFlow] handleInit: REJECTED - userIntent.exportInfo[${i}].addresses[${j}].address mismatch`);
            throw new Error(`userIntent parameter mismatch: exportInfo[${i}].addresses[${j}].address was signed as ${JSON.stringify(intentAddr.address)} but actual value is ${JSON.stringify(actualAddr.address)}`);
          }
          // chainId 可能是数字或字符串，统一转为数字比较
          if (actualAddr.chainId !== undefined) {
            if (Number(intentAddr.chainId) !== Number(actualAddr.chainId)) {
              console.log(`[ExportFlow] handleInit: REJECTED - userIntent.exportInfo[${i}].addresses[${j}].chainId mismatch`);
              throw new Error(`userIntent parameter mismatch: exportInfo[${i}].addresses[${j}].chainId was signed as ${JSON.stringify(intentAddr.chainId)} but actual value is ${JSON.stringify(actualAddr.chainId)}`);
            }
          }
        }
      }
    }
    console.log(`[ExportFlow] handleInit: userIntent verification passed`);

    // 7. 验证所有 walletId 对应的钱包容器存在
    for (const item of request.exportInfo) {
      const wallet = await this._wallet.getWallet(request.userId, item.walletId);
      if (!wallet) {
        throw new Error(`Wallet not found: walletId=${item.walletId}`);
      }
    }

    // 8. 发起批量导出（两种模式都在 init 时加密数据并返回）
    const keyExchangeParams = request.rsaPublicKey
      ? { rsaPublicKey: request.rsaPublicKey }
      : { peerPublicKey: request.peerPublicKey };

    const exportResult = await this._keyExporter.initiateExport(
      request.userId,
      request.exportInfo,
      keyExchangeParams
    );

    console.log(`[ExportFlow] handleInit: session created, sessionId=${exportResult.sessionId}, keyType=${exportResult.keyType}`);

    // 9. 构建响应（根据 keyType 返回不同字段，两种模式都在 init 返回加密数据）
    const response = {
      sessionId: exportResult.sessionId,
      keyType: exportResult.keyType,
      encryptedData: exportResult.encryptedWalletData,
    };

    if (exportResult.keyType === 'ecdh') {
      // ECDH：返回 SGX 的 ECDH 公钥（客户端用自己私钥+此公钥算出共享密钥解密）
      response.enclavePublicKey = exportResult.enclavePublicKey;
    } else {
      // RSA：返回加密的 AES 密钥（客户端用 RSA 私钥解密得到 AES 密钥，再解密数据）
      response.encryptedAESKey = exportResult.encryptedAESKey;
    }

    return response;
  }

  /**
   * 第二步：确认导出（通知删除）
   *
   * 两种模式都一样：客户端确认已收到并解密数据后，通知 SGX 删除导出过的钱包数据。
   * 不返回任何加密数据。
   *
   * 安全要求：此操作会不可逆地删除钱包，必须验证用户 WebAuthn 签名，
   * 防止攻击者拿到 sessionId 后在用户未成功解密前触发钱包删除。
   *
   * payload JSON: {
   *   userId, credentialId, webauthnSignature,
   *   rawChallenge,    // 从 /api/challenge（purpose=key_export_confirm）获取的原始挑战值
   *   userIntentJson,  // 用户意图 JSON 字符串：{ purpose: "key_export_confirm", userId, sessionId }
   *   sessionId
   * }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<{ success: boolean, walletIds: string[], deletedCount: number, deleted: boolean }>}
   */
  async handleComplete(request) {
    // 1. 验证平台白名单签名
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[ExportFlow] handleComplete: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 2. 解析验证过的 payload，替换 request
    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    console.log(`[ExportFlow] handleComplete: userId=${request.userId}, sessionId=${request.sessionId}`);

    if (!request.userId) throw new Error('userId is required');
    if (!request.credentialId) throw new Error('credentialId is required');
    if (!request.webauthnSignature) throw new Error('webauthnSignature is required');
    if (!request.sessionId) throw new Error('sessionId is required');
    if (!request.rawChallenge) throw new Error('rawChallenge is required');
    if (!request.userIntentJson) throw new Error('userIntentJson is required');

    // 3. 查找导出会话（验证 sessionId 有效性，并获取 exportInfo 和 userId）
    const session = await this._keyExporter.findExportSession(request.sessionId);
    if (!session) {
      throw new Error('Export session not found or expired');
    }

    // 4. 验证 userId 与会话中的 userId 一致（防止跨用户操作）
    if (session.user_id !== request.userId) {
      console.log(`[ExportFlow] handleComplete: REJECTED - userId mismatch: session.user_id=${session.user_id}, request.userId=${request.userId}`);
      throw new Error('userId mismatch: not authorized to confirm this export session');
    }

    // 5. 验证 Passkey 归属
    const ownershipValid = await this._passkey.verifyPasskeyOwnership(request.userId, request.credentialId);
    if (!ownershipValid) {
      console.log(`[ExportFlow] handleComplete: REJECTED - passkey not bound to userId=${request.userId}`);
      throw new Error('Passkey not bound to this user');
    }

    const passkey = await this._passkey.getPasskey(request.userId, request.credentialId);
    if (!passkey) throw new Error('Passkey not found');

    // 6. 验证 userIntentJson 是合法 JSON（提前验证）
    let intent;
    try {
      intent = JSON.parse(request.userIntentJson);
    } catch {
      throw new Error('userIntentJson must be a valid JSON string');
    }

    // 7. 验证 WebAuthn 签名
    // - rawChallenge：服务端生成的原始随机挑战值（用于查询 DB 记录）
    // - userIntentJson：用户意图 JSON 字符串（用于计算 intentHash）
    // - verifier 内部计算 intentHash = SHA256(rawChallenge + userIntentJson) 作为 expectedChallenge
    const sigResult = await verifyWebAuthnSignature({
      userId: request.userId,
      credentialId: request.credentialId,
      webauthnSignature: request.webauthnSignature,
      challengeManager: this._challenge,
      purpose: 'key_export_confirm',
      rawChallenge: request.rawChallenge,
      userIntentJson: request.userIntentJson,
      publicKeyCose: passkey.publicKeyCose,
    });
    if (!sigResult.verified) {
      console.log(`[ExportFlow] handleComplete: REJECTED - WebAuthn signature invalid`);
      throw new Error(`WebAuthn verification failed: ${sigResult.reason}`);
    }

    // 8. 验证 userIntentJson 中的业务参数与实际请求参数一致
    // 关键：sessionId 必须在用户签名时已确认，防止 sessionId 被替换
    // 这里都是简单字符串字段，直接比较即可
    const intentFields = {
      purpose: 'key_export_confirm',
      userId: request.userId,
      sessionId: request.sessionId,
    };
    for (const [key, actualValue] of Object.entries(intentFields)) {
      if (intent[key] !== actualValue) {
        console.log(`[ExportFlow] handleComplete: REJECTED - userIntent.${key} mismatch`);
        throw new Error(`userIntent parameter mismatch: ${key} was signed as ${JSON.stringify(intent[key])} but actual value is ${JSON.stringify(actualValue)}`);
      }
    }
    console.log(`[ExportFlow] handleComplete: userIntent verification passed`);

    // 9. 确认导出并删除钱包
    const result = await this._keyExporter.confirmExport(request.sessionId);

    console.log(`[ExportFlow] handleComplete: success, walletIds=${JSON.stringify(result.walletIds)}, deletedCount=${result.deletedCount}`);

    return {
      success: true,
      walletIds: result.walletIds,
      deletedCount: result.deletedCount,
      deleted: result.deletedCount > 0,
    };
  }
}
