/**
 * RSA 辅助模块
 * 用于 RSA 模式下的 AES 密钥生成、RSA 加密（保护 AES 密钥传输）、公钥验证与检测
 *
 * RSA 流程（与 ECDH 互斥，需客户端显式传入 rsaPublicKey）：
 * - 客户端生成 RSA 密钥对，在请求中提供 RSA 公钥（Base64 DER 或 PEM）
 * - SGX 生成 256 位 AES-GCM 对称密钥，保存到会话
 * - SGX 用客户端 RSA 公钥（RSA/PKCS1Padding，即 PKCS#1 v1.5）加密该 AES 密钥，返回密文
 * - 客户端用自己的 RSA 私钥解密得到 AES 密钥明文
 * - 后续数据加解密均使用该 AES-256-GCM 密钥（复用 ecdh.js 的 encrypt/decrypt）
 *
 * 支持的 RSA 公钥位数：1024、2048、3072（自动从公钥检测，无需客户端指定）
 * 公钥格式兼容：PEM 格式 或 Base64 编码的 DER（X.509/SPKI）
 */

import crypto from 'crypto';

const SUPPORTED_RSA_MODULUS_BYTES = {
  128: 'rsa-1024',
  256: 'rsa-2048',
  384: 'rsa-3072',
};

/**
 * 解析 RSA 公钥：兼容 PEM 和 Base64 编码 DER（X.509/SPKI）两种格式
 * @param {string} rsaPublicKey - RSA 公钥（PEM 或 Base64 DER）
 * @returns {crypto.KeyObject} Node.js KeyObject
 */
function parseRSAPublicKey(rsaPublicKey) {
  if (rsaPublicKey.trimStart().startsWith('-----BEGIN')) {
    return crypto.createPublicKey(rsaPublicKey);
  }
  // Base64 编码的 DER（Java X509EncodedKeySpec 格式）
  return crypto.createPublicKey({
    key: Buffer.from(rsaPublicKey, 'base64'),
    format: 'der',
    type: 'spki',
  });
}

/**
 * 生成 256 位（32 字节）随机 AES 密钥
 * @returns {Buffer} 32 字节 AES 密钥
 */
export function generateAESKey() {
  return crypto.randomBytes(32);
}

/**
 * 用客户端 RSA 公钥加密 AES 密钥（RSA/PKCS1Padding，即 PKCS#1 v1.5）
 * @param {string} rsaPublicKey - 客户端 RSA 公钥（PEM 或 Base64 DER）
 * @param {Buffer} aesKey - 32 字节 AES 密钥
 * @returns {string} Base64 编码的 RSA 加密密文
 */
export function encryptAESKeyWithRSA(rsaPublicKey, aesKey) {
  const keyObject = parseRSAPublicKey(rsaPublicKey);
  const encrypted = crypto.publicEncrypt(
    {
      key: keyObject,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    aesKey
  );
  return encrypted.toString('base64');
}

/**
 * 验证 RSA 公钥格式并检测密钥位数（keyType）
 *
 * @param {string} rsaPublicKey - RSA 公钥（PEM 或 Base64 DER）
 * @returns {{ valid: boolean, keyType?: string, modulusBits?: number, error?: string }}
 *   - valid=true 时：keyType 为 'rsa-1024' | 'rsa-2048' | 'rsa-3072'，modulusBits 为位数
 *   - valid=false 时：error 描述错误原因
 */
export function validateAndDetectRSAPublicKey(rsaPublicKey) {
  try {
    const keyObject = parseRSAPublicKey(rsaPublicKey);

    if (keyObject.asymmetricKeyType !== 'rsa') {
      return { valid: false, error: `Not an RSA key: ${keyObject.asymmetricKeyType}` };
    }

    // 通过 JWK 导出获取 modulus 字节长度，自动检测密钥位数
    const jwk = keyObject.export({ format: 'jwk' });
    const modulusByteLength = Buffer.from(jwk.n, 'base64url').length;
    const keyType = SUPPORTED_RSA_MODULUS_BYTES[modulusByteLength];

    if (!keyType) {
      return {
        valid: false,
        error: `Unsupported RSA key size: ${modulusByteLength * 8} bits. Supported: 1024, 2048, 3072`,
      };
    }

    return {
      valid: true,
      keyType,
      modulusBits: modulusByteLength * 8,
    };
  } catch (err) {
    return { valid: false, error: `Invalid RSA public key: ${err.message}` };
  }
}
