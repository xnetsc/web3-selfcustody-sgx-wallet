/**
 * WebAuthn 签名验证模块
 * 使用 @simplewebauthn/server 验证 WebAuthn 认证签名
 *
 * 挑战值验证：
 * - 挑战值由服务器生成并存储在 webauthn_challenges 表（纯随机数）
 * - 客户端计算 intentHash = SHA256(rawChallenge + userIntentJson)，用 intentHash 做 WebAuthn 签名
 * - 验证时：
 *   1. 根据 rawChallenge 查询挑战值记录（验证存在性），消费后删除
 *   2. 重新计算 intentHash = SHA256(rawChallenge + userIntentJson)
 *   3. 用 intentHash 作为 expectedChallenge 验证 WebAuthn 签名
 *
 * 注意：不验证 origin 和 rpid（无需钓鱼验证），直接使用用户提交的值
 * - expectedOrigin 设为用户提交的 origin
 * - expectedRPID 设为从 origin 中提取的 hostname（与 authenticatorData 中的 rpIdHash 匹配）
 */

import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { computeIntentHash } from './challenge-manager.js';

/**
 * 从 clientDataJSON（base64url 编码）中提取 origin 和 challenge
 * @param {string} clientDataJSONBase64url
 * @returns {{ origin: string, challenge: string }}
 */
function parseClientDataJSON(clientDataJSONBase64url) {
  try {
    const json = JSON.parse(Buffer.from(clientDataJSONBase64url, 'base64url').toString());
    return {
      origin: json.origin || 'https://unknown',
      challenge: json.challenge || '',
    };
  } catch {
    return { origin: 'https://unknown', challenge: '' };
  }
}

/**
 * 从 origin URL 中提取 hostname（作为 rpId）
 * @param {string} origin - 例如 'https://example.com'
 * @returns {string} hostname，例如 'example.com'
 */
function extractRpIdFromOrigin(origin) {
  try {
    return new URL(origin).hostname;
  } catch {
    return origin;
  }
}

/**
 * 验证 WebAuthn 认证签名
 *
 * 支持两种挑战值验证模式：
 * 模式1（challengeManager + rawChallenge + userIntentJson）：
 *   - rawChallenge：服务端生成的原始随机挑战值
 *   - userIntentJson：用户意图的原始 JSON 字符串
 *   - 服务端验证流程：
 *     1. 根据 rawChallenge 查询挑战值记录（验证存在性），消费后删除
 *     2. 计算 intentHash = SHA256(rawChallenge + userIntentJson)
 *     3. 用 intentHash 作为 expectedChallenge 验证 WebAuthn 签名
 *   - clientDataJSON 中的 challenge 应为 intentHash
 *
 * 模式1b（challengeManager，无 userIntentJson）：
 *   - 用于 register/authenticate 等不需要绑定业务意图的场景
 *   - clientDataJSON 中的 challenge 直接是 rawChallenge
 *   - 服务端直接用 rawChallenge 验证并消费
 *
 * 模式2（expectedChallenge）：直接比对挑战值（用于 auth-engine 的 authHash 验证等特殊场景）
 *
 * @param {Object} params
 * @param {string} params.userId - 用户 ID（必须指定）
 * @param {string} params.credentialId - Passkey 凭证 ID（必须指定）
 * @param {Object} params.webauthnSignature - WebAuthn 认证响应对象
 *   格式1（Browser WebAuthn API response）：{ response: { authenticatorData, clientDataJSON, signature } }
 *   格式2（直接格式）：{ authenticatorData, clientDataJSON, signature }
 * @param {import('./challenge-manager.js').WebAuthnChallengeManager} [params.challengeManager] - 挑战值管理器（模式1/1b）
 * @param {string} [params.purpose] - 期望的挑战值用途（模式1/1b，可选）
 * @param {string} [params.rawChallenge] - 原始挑战值（模式1，服务端生成的随机数）
 * @param {string} [params.userIntentJson] - 用户意图 JSON 字符串（模式1，用于计算 intentHash）
 * @param {string} [params.expectedChallenge] - 期望的挑战值（模式2，直接比对）
 * @param {Buffer|Uint8Array} params.publicKeyCose - COSE 格式公钥
 * @param {number} [params.signCount] - 当前签名计数（用于防重放，0 表示不验证）
 * @returns {Promise<{ verified: boolean, reason: string, newSignCount?: number }>}
 */
export async function verifyWebAuthnSignature(params) {
  if (!params.userId) {
    return { verified: false, reason: 'userId is required' };
  }
  if (!params.credentialId) {
    return { verified: false, reason: 'credentialId is required' };
  }
  if (!params.webauthnSignature) {
    return { verified: false, reason: 'webauthnSignature is required' };
  }
  if (!params.publicKeyCose) {
    return { verified: false, reason: 'publicKeyCose is required' };
  }
  // 必须提供 challengeManager 或 expectedChallenge 之一
  if (!params.challengeManager && params.expectedChallenge === undefined) {
    return { verified: false, reason: 'challengeManager or expectedChallenge is required' };
  }

  // 1. 规范化 webauthnSignature 为 Browser WebAuthn API response 格式
  let responseObj;
  if (params.webauthnSignature.response && typeof params.webauthnSignature.response === 'object') {
    // 格式1：已经是 Browser WebAuthn API response 格式
    responseObj = params.webauthnSignature.response;
  } else {
    // 格式2：直接字段，转换为格式1
    responseObj = {
      authenticatorData: params.webauthnSignature.authenticatorData,
      clientDataJSON: params.webauthnSignature.clientDataJSON,
      signature: params.webauthnSignature.signature,
    };
  }

  // 2. 将所有字段转换为 base64url 字符串（@simplewebauthn/server 需要）
  const toBase64url = (val) => {
    if (typeof val === 'string') return val;
    if (val instanceof Buffer || val instanceof Uint8Array) return Buffer.from(val).toString('base64url');
    throw new Error('Invalid field type: expected string or Buffer');
  };

  const authenticatorDataBase64url = toBase64url(responseObj.authenticatorData);
  const clientDataJSONBase64url = toBase64url(responseObj.clientDataJSON);
  const signatureBase64url = toBase64url(responseObj.signature);

  // 3. 从 clientDataJSON 中提取 origin（challenge 字段仅用于日志，不用于验证）
  const { origin } = parseClientDataJSON(clientDataJSONBase64url);
  const rpId = extractRpIdFromOrigin(origin);

  // 4. 确定 expectedChallenge
  let expectedChallenge;
  if (params.challengeManager) {
    if (params.rawChallenge && params.userIntentJson) {
      // 模式1：有 rawChallenge + userIntentJson，验证 rawChallenge 存在性，计算 intentHash
      const challengeResult = params.challengeManager.verifyAndConsumeChallenge(
        params.rawChallenge,
        params.userId,
        params.purpose
      );
      if (!challengeResult.valid) {
        return { verified: false, reason: 'Challenge validation failed: ' + challengeResult.reason };
      }
      // 计算 intentHash = SHA256(rawChallenge + userIntentJson)
      expectedChallenge = computeIntentHash(params.rawChallenge, params.userIntentJson);
    } else if (params.rawChallenge) {
      // 模式1b：只有 rawChallenge，无 userIntentJson（register/authenticate 场景）
      // clientDataJSON 中的 challenge 直接是 rawChallenge
      const challengeResult = params.challengeManager.verifyAndConsumeChallenge(
        params.rawChallenge,
        params.userId,
        params.purpose
      );
      if (!challengeResult.valid) {
        return { verified: false, reason: 'Challenge validation failed: ' + challengeResult.reason };
      }
      expectedChallenge = params.rawChallenge;
    } else {
      // 兼容旧模式：从 clientDataJSON 提取 challenge 作为 rawChallenge（仅用于 register/authenticate）
      const { challenge: clientChallenge } = parseClientDataJSON(clientDataJSONBase64url);
      if (!clientChallenge) {
        return { verified: false, reason: 'challenge not found in clientDataJSON' };
      }
      const challengeResult = params.challengeManager.verifyAndConsumeChallenge(
        clientChallenge,
        params.userId,
        params.purpose
      );
      if (!challengeResult.valid) {
        return { verified: false, reason: 'Challenge validation failed: ' + challengeResult.reason };
      }
      expectedChallenge = clientChallenge;
    }
  } else {
    // 模式2：直接使用 expectedChallenge
    expectedChallenge = params.expectedChallenge;
  }

  // 5. 使用 @simplewebauthn/server 验证认证响应
  // 注意：将 expectedOrigin 设为用户提交的 origin，将 expectedRPID 设为从 origin 提取的 hostname
  // 这样就不会有钓鱼验证（origin/rpid 验证直接通过）
  try {
    const publicKeyCose = params.publicKeyCose instanceof Uint8Array
      ? params.publicKeyCose
      : new Uint8Array(params.publicKeyCose);

    const verification = await verifyAuthenticationResponse({
      response: {
        id: params.credentialId,
        rawId: params.credentialId,
        response: {
          authenticatorData: authenticatorDataBase64url,
          clientDataJSON: clientDataJSONBase64url,
          signature: signatureBase64url,
        },
        type: 'public-key',
      },
      expectedChallenge,
      expectedOrigin: origin,   // 使用用户提交的 origin，绕过钓鱼验证
      expectedRPID: rpId,       // 从 origin 提取的 hostname，与 authenticatorData 中的 rpIdHash 匹配
      authenticator: {
        // @simplewebauthn/server v10: credentialID is Base64URLString (string), not Uint8Array
        credentialID: params.credentialId,
        credentialPublicKey: publicKeyCose,
        counter: params.signCount || 0,
      },
      requireUserVerification: false,   // 不强制要求用户验证（PIN/生物识别）
    });

    if (!verification.verified) {
      return { verified: false, reason: 'WebAuthn authentication verification failed' };
    }

    return {
      verified: true,
      reason: 'OK',
      newSignCount: verification.authenticationInfo?.newCounter,
    };
  } catch (err) {
    return { verified: false, reason: 'Signature verification error: ' + err.message };
  }
}
