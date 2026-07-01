/**
 * HD 钱包派生模块
 * BIP-39 助记词生成 + BIP-32/BIP-44 多链私钥派生
 */

import { ethers } from 'ethers';
import * as bip39 from 'bip39';

/**
 * 生成助记词
 * @param {number} strength - 助记词强度（128=12词, 256=24词），默认 128
 * @returns {string} 助记词
 */
export function generateMnemonic(strength = 128) {
  return bip39.generateMnemonic(strength);
}

/**
 * 验证助记词是否有效
 * @param {string} mnemonic - 助记词
 * @returns {boolean}
 */
export function validateMnemonic(mnemonic) {
  return bip39.validateMnemonic(mnemonic);
}

/**
 * 从助记词派生指定链的钱包
 * @param {string} mnemonic - 助记词
 * @param {number} coinType - BIP-44 coin type（60=ETH, 0=BTC 等）
 * @param {number} index - 地址索引，默认 0
 * @returns {{ address: string, privateKey: string, derivationPath: string }}
 */
export function deriveWallet(mnemonic, coinType, index = 0) {
  if (!validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic');
  }

  const path = `m/44'/${coinType}'/0'/0/${index}`;
  const hdNode = ethers.HDNodeWallet.fromMnemonic(
    ethers.Mnemonic.fromPhrase(mnemonic),
    path
  );

  return {
    address: hdNode.address,
    privateKey: hdNode.privateKey,
    derivationPath: path,
  };
}

/**
 * 从私钥计算地址
 * @param {string} privateKey - 私钥（十六进制，含或不含 0x 前缀）
 * @returns {string} 以太坊格式地址
 */
export function privateKeyToAddress(privateKey) {
  const wallet = new ethers.Wallet(privateKey);
  return wallet.address;
}
