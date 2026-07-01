/**
 * ECDH 密钥交换模块
 * 使用 prime256v1（NIST P-256 / secp256r1）曲线，与 Node.js 标准一致
 */

import crypto from 'crypto';

/**
 * 生成 ECDH 密钥对
 * @returns {{ publicKey: string, privateKey: string }} hex 编码的公钥和私钥
 */
export function generateECDHKeyPair() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return {
    publicKey: ecdh.getPublicKey('hex'),
    privateKey: ecdh.getPrivateKey('hex'),
  };
}

/**
 * 派生对称密钥（共享秘密 → SHA-256 → 32 字节 AES 密钥）
 * @param {string} myPrivateKey - 己方 ECDH 私钥（hex）
 * @param {string} peerPublicKey - 对方 ECDH 公钥（hex）
 * @returns {Buffer} 32 字节对称密钥
 */
export function deriveSharedSecret(myPrivateKey, peerPublicKey) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(myPrivateKey, 'hex');
  const sharedSecret = ecdh.computeSecret(peerPublicKey, 'hex');
  return crypto.createHash('sha256').update(sharedSecret).digest();
}

/**
 * AES-256-GCM 加密
 * @param {Buffer} key - 32 字节密钥
 * @param {Buffer|string} plaintext - 明文
 * @returns {{ ciphertext: string, iv: string, authTag: string }} 均为 hex 编码
 */
export function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(12); // GCM 推荐 12 字节 IV
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintextBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  };
}

/**
 * AES-256-GCM 解密
 * @param {Buffer} key - 32 字节密钥
 * @param {string} ciphertext - 密文（hex）
 * @param {string} iv - 初始化向量（hex）
 * @param {string} authTag - 认证标签（hex）
 * @returns {Buffer} 明文
 */
export function decrypt(key, ciphertext, iv, authTag) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(iv, 'hex')
  );
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'hex')),
    decipher.final(),
  ]);
  return decrypted;
}
