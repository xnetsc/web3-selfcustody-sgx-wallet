/**
 * 白名单验证模块
 * 验证中心化平台请求签名（secp256k1）并检查平台白名单
 * 作为 14 项检查清单第 1 项的底层实现
 */

import { ethers } from 'ethers';

export class WhitelistVerifier {
  /**
   * @param {import('../contract-client/index.js').ContractClient} contractClient - 合约交互客户端实例
   */
  constructor(contractClient) {
    if (!contractClient) {
      throw new Error('WhitelistVerifier requires a ContractClient instance');
    }
    this._contractClient = contractClient;
  }

  /**
   * 验证请求签名并检查白名单
   *
   * @param {string|Buffer} payload - 请求体内容（被签名的原始数据）
   * @param {string} signature - secp256k1 签名（十六进制，含 0x 前缀）
   * @returns {{ valid: boolean, address: string|null, reason: string }}
   */
  verifyRequest(payload, signature) {
    // 1. 从签名恢复地址
    let recoveredAddress;
    try {
      recoveredAddress = ethers.verifyMessage(payload, signature);
    } catch (err) {
      console.log(`[WhitelistVerifier] verifyRequest: REJECTED - invalid signature format`);
      return { valid: false, address: null, reason: 'Invalid signature format' };
    }

    // 2. 检查地址是否在平台白名单
    const isWhitelisted = this._contractClient.isPlatformWhitelisted(recoveredAddress);
    if (!isWhitelisted) {
      console.log(`[WhitelistVerifier] verifyRequest: REJECTED - address ${recoveredAddress} not in whitelist`);
      return { valid: false, address: recoveredAddress, reason: 'Address not in platform whitelist' };
    }

    console.log(`[WhitelistVerifier] verifyRequest: PASSED - address ${recoveredAddress} is whitelisted`);
    return { valid: true, address: recoveredAddress, reason: 'OK' };
  }

  /**
   * 仅验证签名，恢复地址（不检查白名单）
   *
   * @param {string|Buffer} payload - 被签名的原始数据
   * @param {string} signature - secp256k1 签名
   * @returns {{ valid: boolean, address: string|null, reason: string }}
   */
  recoverAddress(payload, signature) {
    try {
      const address = ethers.verifyMessage(payload, signature);
      return { valid: true, address, reason: 'OK' };
    } catch (err) {
      return { valid: false, address: null, reason: 'Invalid signature: ' + err.message };
    }
  }

  /**
   * 直接检查地址是否在白名单（不做签名验证）
   *
   * @param {string} address - 以太坊地址
   * @returns {boolean}
   */
  isWhitelisted(address) {
    return this._contractClient.isPlatformWhitelisted(address);
  }
}
