/**
 * 远程证明模块
 *
 * 对待证明的数据算 SHA256 哈希后注入 user_report_data，然后获取 SGX quote。
 * 在非 SGX 环境（Direct 模式）下，/dev/attestation/ 不存在，返回空字符串。
 *
 * 调用方式：
 *   const quote = getAttestationQuote(dataString);
 *   // quote 是十六进制字符串（SGX 模式）或空字符串（Direct 模式）
 */

import crypto from 'crypto';
import fs from 'fs';

const ATTESTATION_USER_REPORT_DATA = '/dev/attestation/user_report_data';
const ATTESTATION_QUOTE = '/dev/attestation/quote';

/**
 * 获取远程证明 quote
 *
 * 1. 对 dataToAttest 计算 SHA256 哈希（32 字节）
 * 2. 写入 /dev/attestation/user_report_data（64 字节，前 32 = hash，后 32 = 0）
 * 3. 读取 /dev/attestation/quote
 * 4. 返回 quote 的十六进制字符串
 *
 * @param {string} dataToAttest - 需要被证明的数据（通常是 JSON 序列化字符串）
 * @returns {string} SGX quote 十六进制字符串，非 SGX 环境返回空字符串
 */
export function getAttestationQuote(dataToAttest) {
  const hash = crypto.createHash('sha256').update(dataToAttest).digest();

  // user_report_data = 64 bytes: [SHA256(data) | 0x00...00]
  const userReportData = Buffer.alloc(64, 0);
  hash.copy(userReportData, 0, 0, 32);

  try {
    fs.writeFileSync(ATTESTATION_USER_REPORT_DATA, userReportData);
    const quote = fs.readFileSync(ATTESTATION_QUOTE);
    console.log(`[RemoteAttestation] SGX quote generated (${quote.length} bytes), dataHash=${hash.toString('hex').substring(0, 16)}...`);
    return quote.toString('hex');
  } catch (err) {
    // Direct 模式或非 SGX 环境：/dev/attestation/ 不存在
    console.log(`[RemoteAttestation] SGX quote not available (${err.code || err.message}), returning empty`);
    return '';
  }
}
