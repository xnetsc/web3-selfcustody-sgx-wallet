/**
 * Enclave 信息查询 API
 * 返回 Enclave 白名单及公开信息，供客户端 TEE 验证
 *
 * 无需鉴权（公开信息）
 */

export class EnclaveInfoHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/contract-client/index.js').ContractClient} deps.contractClient
   */
  constructor(deps) {
    if (!deps.contractClient) throw new Error('EnclaveInfoHandler requires contractClient');
    this._contract = deps.contractClient;
  }

  /**
   * 获取 Enclave 信息
   *
   * 无需 payload，直接返回 Enclave 公开信息
   *
   * @param {Object} request - HTTP body（可为空）
   * @returns {Promise<Object>}
   */
  async handleGetInfo(request) {
    console.log(`[EnclaveInfo] handleGetInfo`);

    const enclaveWhitelist = this._contract.getEnclaveWhitelist();
    const codeRepository = this._contract.getCodeRepository();
    const runtimeParams = this._contract.getRuntimeParams();

    console.log(`[EnclaveInfo] handleGetInfo: success`);

    return {
      enclaveWhitelist,
      codeRepository,
      runtimeParams,
    };
  }
}
