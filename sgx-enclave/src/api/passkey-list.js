/**
 * Passkey 列表查询 API
 * 列出用户绑定的所有 Passkey
 *
 * HTTP body 仅包含 { payload, platformSignature }，
 * 所有业务参数从验证后的 payload 解析获取。
 */

export class PasskeyListHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/whitelist/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../modules/webauthn/passkey-manager.js').PasskeyManager} deps.passkeyManager
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('PasskeyListHandler requires whitelistVerifier');
    if (!deps.passkeyManager) throw new Error('PasskeyListHandler requires passkeyManager');
    this._whitelist = deps.whitelistVerifier;
    this._passkey = deps.passkeyManager;
  }

  /**
   * 列出用户的所有 Passkey
   *
   * payload JSON: { userId }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<{ userId: string, passkeys: Object[] }>}
   */
  async handleList(request) {
    // 1. 验证平台白名单签名
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[PasskeyList] handleList: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 2. 解析验证过的 payload，替换 request
    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    if (!request.userId) throw new Error('userId is required');

    console.log(`[PasskeyList] handleList: userId=${request.userId}`);

    // 3. 列出 Passkey
    const passkeys = await this._passkey.listPasskeys(request.userId);

    console.log(`[PasskeyList] handleList: success, count=${passkeys.length}`);

    return {
      userId: request.userId,
      passkeys: passkeys.map(p => ({
        credentialId: p.credentialId,
        createdAt: p.createdAt,
        signCount: p.signCount,
      })),
    };
  }
}
