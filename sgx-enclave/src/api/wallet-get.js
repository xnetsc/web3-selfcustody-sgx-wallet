/**
 * 钱包详情查询 API
 * 查询指定钱包容器的详细信息（含地址列表）
 *
 * HTTP body 仅包含 { payload, platformSignature }，
 * 所有业务参数从验证后的 payload 解析获取。
 */

export class WalletGetHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/whitelist/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../modules/wallet-management/wallet-manager.js').WalletManager} deps.walletManager
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('WalletGetHandler requires whitelistVerifier');
    if (!deps.walletManager) throw new Error('WalletGetHandler requires walletManager');
    this._whitelist = deps.whitelistVerifier;
    this._wallet = deps.walletManager;
  }

  /**
   * 查询指定钱包详情
   *
   * payload JSON: { userId, walletId }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<{ userId: string, walletId: string, wallet: Object }>}
   */
  async handleGet(request) {
    // 1. 验证平台白名单签名
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[WalletGet] handleGet: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 2. 解析验证过的 payload，替换 request
    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    if (!request.userId) throw new Error('userId is required');
    if (!request.walletId) throw new Error('walletId is required');

    console.log(`[WalletGet] handleGet: userId=${request.userId}, walletId=${request.walletId}`);

    // 3. 查询钱包
    const wallet = await this._wallet.getWallet(request.userId, request.walletId);
    if (!wallet) {
      throw new Error(`Wallet not found: walletId=${request.walletId}`);
    }

    console.log(`[WalletGet] handleGet: success, walletId=${request.walletId}`);

    return {
      userId: request.userId,
      walletId: request.walletId,
      wallet,
    };
  }
}
