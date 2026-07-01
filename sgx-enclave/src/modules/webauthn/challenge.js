/**
 * WebAuthn 挑战值生成与管理
 * 生成随机挑战值
 */

import crypto from 'crypto';

/**
 * 生成 WebAuthn 挑战值
 * @param {string} userId - 用户 ID
 * @param {string} purpose - 用途（'register' | 'authenticate' | 'authorize'）
 * @returns {{ challenge: string }}
 */
export function generateChallenge(userId, purpose) {
  if (!userId) {
    throw new Error('userId is required for challenge generation');
  }
  if (!purpose) {
    throw new Error('purpose is required for challenge generation');
  }

  const challenge = crypto.randomBytes(32).toString('base64url');

  return { challenge };
}
