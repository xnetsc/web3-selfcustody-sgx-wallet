/**
 * 授权状态查询 API
 * 查询授权的累计用量、状态（active/revoked/expired/exceeded）
 *
 * HTTP body 仅包含 { payload, platformSignature }，
 * 所有业务参数从验证后的 payload 解析获取。
 */

export class AuthStatusHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/whitelist/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../modules/state-management/state-manager.js').StateManager} deps.stateManager
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('AuthStatusHandler requires whitelistVerifier');
    if (!deps.stateManager) throw new Error('AuthStatusHandler requires stateManager');
    this._whitelist = deps.whitelistVerifier;
    this._state = deps.stateManager;
  }

  /**
   * 查询授权状态
   *
   * payload JSON: { userId, authorizationId }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<Object>}
   */
  async handleGetStatus(request) {
    // 1. 验证平台白名单签名
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[AuthStatus] handleGetStatus: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 2. 解析验证过的 payload，替换 request
    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    if (!request.userId) throw new Error('userId is required');
    if (!request.authorizationId) throw new Error('authorizationId is required');

    console.log(`[AuthStatus] handleGetStatus: userId=${request.userId}, authorizationId=${request.authorizationId}`);

    // 3. 查询授权状态
    const state = await this._state.getStateByCompositeKey(request.userId, request.authorizationId);
    if (!state) {
      throw new Error(`Authorization state not found: authorizationId=${request.authorizationId}`);
    }

    // 4. 查询分 token 状态
    const tokenStates = await this._state.listTokenStates(request.authorizationId);

    console.log(`[AuthStatus] handleGetStatus: success, status=${state.status}`);

    return {
      authorizationId: request.authorizationId,
      userId: request.userId,
      grantee: state.grantee,
      status: state.status,
      totalAmountUsed: state.total_amount_used,
      totalCountUsed: state.total_count_used,
      createdAt: state.created_at,
      updatedAt: state.updated_at,
      tokenStates: tokenStates.map(t => ({
        chainId: t.chain_id,
        tokenAddress: t.token_address,
        amountUsed: t.amount_used,
      })),
    };
  }
}
