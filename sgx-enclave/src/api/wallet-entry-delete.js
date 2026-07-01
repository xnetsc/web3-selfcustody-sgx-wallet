/**
 * 单个逻辑钱包删除 API
 * 按 address 精确删除钱包容器内的单个逻辑钱包
 *
 * HTTP body 仅包含 { payload, platformSignature }，
 * 所有业务参数从验证后的 payload 解析获取。
 *
 * payload 中需要携带：
 *   - rawChallenge：从 /api/challenge 获取的原始挑战值
 *   - userIntentJson：用户意图 JSON 字符串：{ purpose: "wallet_entry_delete", userId, walletId, address }
 *   - webauthnSignature：用 intentHash = SHA256(rawChallenge + userIntentJson) 做的 WebAuthn 签名
 */

import { verifyWebAuthnSignature } from '../modules/webauthn/verifier.js';

export class WalletEntryDeleteHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/whitelist/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../modules/webauthn/passkey-manager.js').PasskeyManager} deps.passkeyManager
   * @param {import('../modules/webauthn/challenge-manager.js').WebAuthnChallengeManager} deps.challengeManager
   * @param {import('../modules/wallet-management/wallet-manager.js').WalletManager} deps.walletManager
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('WalletEntryDeleteHandler requires whitelistVerifier');
    if (!deps.passkeyManager) throw new Error('WalletEntryDeleteHandler requires passkeyManager');
    if (!deps.challengeManager) throw new Error('WalletEntryDeleteHandler requires challengeManager');
    if (!deps.walletManager) throw new Error('WalletEntryDeleteHandler requires walletManager');
    this._whitelist = deps.whitelistVerifier;
    this._passkey = deps.passkeyManager;
    this._challenge = deps.challengeManager;
    this._wallet = deps.walletManager;
  }

  /**
   * 删除单个逻辑钱包
   *
   * payload JSON: {
   *   userId, credentialId, webauthnSignature,
   *   rawChallenge,    // 从 /api/challenge 获取的原始挑战值
   *   userIntentJson,  // 用户意图 JSON 字符串：{ purpose: "wallet_entry_delete", userId, walletId, address }
   *   walletId, address
   * }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<{ success: boolean, walletId: string, address: string }>}
   */
  async handleDelete(request) {
    // 1. 验证平台白名单签名
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[WalletEntryDelete] handleDelete: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 2. 解析验证过的 payload，替换 request
    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    if (!request.userId) throw new Error('userId is required');
    if (!request.credentialId) throw new Error('credentialId is required');
    if (!request.walletId) throw new Error('walletId is required');
    if (!request.address) throw new Error('address is required');
    if (!request.webauthnSignature) throw new Error('webauthnSignature is required');
    if (!request.rawChallenge) throw new Error('rawChallenge is required');
    if (!request.userIntentJson) throw new Error('userIntentJson is required');

    console.log(`[WalletEntryDelete] handleDelete: userId=${request.userId}, walletId=${request.walletId}, address=${request.address}`);

    // 3. 验证 Passkey 归属
    const ownershipValid = await this._passkey.verifyPasskeyOwnership(request.userId, request.credentialId);
    if (!ownershipValid) {
      console.log(`[WalletEntryDelete] handleDelete: REJECTED - passkey not bound to userId=${request.userId}`);
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
      purpose: 'wallet_entry_delete',
      rawChallenge: request.rawChallenge,
      userIntentJson: request.userIntentJson,
      publicKeyCose: passkey.publicKeyCose,
    });
    if (!sigResult.verified) {
      console.log(`[WalletEntryDelete] handleDelete: REJECTED - WebAuthn signature invalid`);
      throw new Error(`WebAuthn verification failed: ${sigResult.reason}`);
    }

    // 6. 验证 userIntentJson 中的业务参数与实际请求参数一致
    const intentFields = {
      purpose: 'wallet_entry_delete',
      userId: request.userId,
      walletId: request.walletId,
      address: request.address,
    };
    for (const [key, actualValue] of Object.entries(intentFields)) {
      if (JSON.stringify(intent[key]) !== JSON.stringify(actualValue)) {
        console.log(`[WalletEntryDelete] handleDelete: REJECTED - userIntent.${key} mismatch`);
        throw new Error(`userIntent parameter mismatch: ${key} was signed as ${JSON.stringify(intent[key])} but actual value is ${JSON.stringify(actualValue)}`);
      }
    }
    console.log(`[WalletEntryDelete] handleDelete: userIntent verification passed`);

    // 7. 删除单个逻辑钱包
    await this._wallet.deleteWalletEntry(request.userId, request.walletId, request.address);

    console.log(`[WalletEntryDelete] handleDelete: success, walletId=${request.walletId}, address=${request.address}`);

    return {
      success: true,
      walletId: request.walletId,
      address: request.address,
    };
  }
}
