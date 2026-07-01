/**
 * 管理员用户ID列表API
 *
 * 用于管理员获取所有用户的授权ID列表（不包含敏感信息）
 * 主要用于管理员统计当前数据库中的用户数据，以便后续调用其他API获取详细信息
 *
 * 路径: /api/admin/userId/list
 *
 * 安全要求：
 * 1. 必须验证平台签名
 * 2. 不返回任何敏感信息（助记词、私钥等）
 * 3. 支持分页查询，避免数据量过大
 */

export class WalletListForPlatformHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/auth-engine/auth-engine.js').AuthEngine} deps.authEngine
   * @param {import('../modules/wallet-management/wallet-manager.js').WalletManager} deps.walletManager
   */
  constructor(deps) {
    if (!deps.authEngine) throw new Error('WalletListForPlatformHandler requires authEngine');
    if (!deps.walletManager) throw new Error('WalletListForPlatformHandler requires walletManager');
    
    this._authEngine = deps.authEngine;
    this._walletManager = deps.walletManager;
  }

  /**
   * 处理管理员获取用户授权ID列表请求
   *
   * @param {Object} request - HTTP请求体 { payload, platformSignature }
   * @returns {Promise<{ success: boolean, users?: Array<{ userId: string, authorizationIds: Array<string> }>, totalUsers?: number, page?: number, pageSize?: number, totalPages?: number, reason?: string }>}
   */
  async handleListAll(request) {
    // 1. 验证平台白名单签名 + 解析 payload
    const whitelistResult = this._authEngine._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    // 2. 解析分页参数
    const page = parseInt(request.page) || 1;
    const pageSize = parseInt(request.pageSize) || 100;
    
    if (page < 1) {
      throw new Error('page must be greater than or equal to 1');
    }
    
    if (pageSize < 1 || pageSize > 1000) {
      throw new Error('pageSize must be between 1 and 1000');
    }

    // 3. 获取用户授权ID列表
        try {
          const result = await this._walletManager.listAllWalletsForPlatform(page, pageSize);
          
          return {
            success: true,
            users: result.users,
            totalUsers: result.totalUsers,
            page: result.page,
            pageSize: result.pageSize,
            totalPages: result.totalPages
          };
    } catch (err) {
      console.error(`[WalletListForPlatform] handleListAll: failed - ${err.message}`);
      return {
        success: false,
        reason: `Failed to retrieve user authorization IDs: ${err.message}`
      };
    }
  }
}
