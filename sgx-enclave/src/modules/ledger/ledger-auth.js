/**
 * 账本操作授权校验（所有权人 / 用户两类，同一构造）
 *
 * 授权载荷是调用方出示的一段 JSON 原文，签名为出示方 Passkey 对该原文的
 * WebAuthn 签名（challenge = SHA256(原文)，与应急授权同一构造）：
 *
 *   {
 *     "type": "ledger_op", "version": 1,
 *     "ledgerId": "...", "actorUserId": "...", "credentialId": "...",
 *     "operation": "create_ledger" | "freeze" | "unfreeze" | "claim_deposit"
 *                | "transfer" | "withdraw" | "convert_out",
 *     "params": { ...与本次请求逐项对应的参数... },
 *     "opId": "全局唯一操作号（防重放，记入流水幂等键）",
 *     "expiresAt": "ISO 时间，签发后短期有效"
 *   }
 *
 * 所有权人操作额外实时查合约：账本指定存在、已启用、指定所有权人正是签名者
 * 且指定公钥哈希正是签名 Passkey——合约不可用即拒绝（fail-closed）。
 * 用户操作只验本地账本存在与签名归属，params 必须与实际请求逐项一致。
 */

import { createHash } from 'crypto';
import { verifyWebAuthnSignature } from '../webauthn/verifier.js';
import { PasskeyManager } from '../webauthn/passkey-manager.js';
import { computeAuthorizationHash } from '../auth-engine/authorization-parser.js';
import { getMonotonicDate } from '../../utils/monotonic-clock.js';

const MAX_VALIDITY_MS = 60 * 60 * 1000; // 授权最长有效期 1 小时

function paramsMatch(expected, actual) {
  if (expected === null || expected === undefined) return actual === null || actual === undefined;
  if (typeof expected !== 'object') return String(expected) === String(actual);
  if (Array.isArray(expected)) {
    return Array.isArray(actual) && expected.length === actual.length
      && expected.every((v, i) => paramsMatch(v, actual[i]));
  }
  if (typeof actual !== 'object' || actual === null) return false;
  return Object.keys(expected).every((k) => paramsMatch(expected[k], actual[k]));
}

export class LedgerAuthorizer {
  /**
   * @param {Object} deps
   * @param {import('../webauthn/passkey-manager.js').PasskeyManager} deps.passkeyManager
   * @param {import('../contract-client/index.js').ContractClient} deps.contractClient
   * @param {Function} [deps.verifyWebAuthnSignatureFn] - 测试注入用
   */
  constructor(deps) {
    this._passkey = deps.passkeyManager;
    this._contract = deps.contractClient;
    this._verifySignature = deps.verifyWebAuthnSignatureFn || verifyWebAuthnSignature;
  }

  /**
   * @param {Object} args
   * @param {string} args.payloadJson - 授权 JSON 原文
   * @param {Object} args.signature - WebAuthn 签名（浏览器格式）
   * @param {'owner'|'user'} args.actorRole
   * @param {string} args.ledgerId
   * @param {string} args.operation
   * @param {Object} args.params - 本次请求的实际参数（与载荷 params 逐项比对）
   * @returns {Promise<{approved: boolean, reason?: string, actorUserId?: string, credentialId?: string, opId?: string}>}
   */
  async verify({ payloadJson, signature, actorRole, ledgerId, operation, params }) {
    const reject = (reason) => ({ approved: false, reason });

    if (!payloadJson || !signature) return reject('ledger authorization payload and signature are required');
    let payload;
    try {
      payload = JSON.parse(payloadJson);
    } catch {
      return reject('ledger authorization payload is not valid JSON');
    }
    if (payload.type !== 'ledger_op' || payload.version !== 1) return reject('unsupported ledger authorization payload');
    if (payload.ledgerId !== ledgerId) return reject('authorization ledgerId does not match the request');
    if (payload.operation !== operation) return reject('authorization operation does not match the request');
    if (!payload.actorUserId || !payload.credentialId) return reject('authorization actor is incomplete');
    if (!payload.opId) return reject('authorization opId is required');
    if (!paramsMatch(payload.params || {}, params || {})) return reject('authorization params do not match the request');

    const expiresMs = Date.parse(payload.expiresAt || '');
    const now = getMonotonicDate().getTime();
    if (!Number.isFinite(expiresMs) || expiresMs <= now) return reject('ledger authorization has expired');
    if (expiresMs - now > MAX_VALIDITY_MS) return reject('ledger authorization validity window too long');

    // 签名 Passkey 必须真实属于签名者账户
    const passkey = await this._passkey.getPasskey(payload.actorUserId, payload.credentialId);
    if (!passkey) return reject('passkey is not bound to the actor account');

    let designation = null;
    if (actorRole === 'owner') {
      // 实时查合约指定：存在、启用、所有权人与公钥哈希都对得上，缺一不可
      try {
        designation = await this._contract.getLedger(ledgerId);
      } catch (err) {
        return reject(`Contract unavailable: cannot verify ledger designation (${err.message})`);
      }
      if (!designation) return reject('ledger is not designated on contract');
      if (!designation.enabled) return reject('ledger is disabled on contract');
      if (designation.ownerUserId !== payload.actorUserId) {
        return reject('signer is not the designated owner of this ledger');
      }
      const pubKeyHash = PasskeyManager.computePubKeyHash(passkey.publicKeyCose);
      if (pubKeyHash.toLowerCase() !== String(designation.ownerPubKeyHash).toLowerCase()) {
        return reject('signer passkey does not match the designated owner passkey');
      }
    }

    const expectedChallenge = computeAuthorizationHash(payloadJson);
    const sigResult = await this._verifySignature({
      userId: payload.actorUserId,
      credentialId: payload.credentialId,
      webauthnSignature: signature,
      expectedChallenge,
      publicKeyCose: passkey.publicKeyCose,
    });
    if (!sigResult.verified) return reject(`passkey signature invalid: ${sigResult.reason || 'verification failed'}`);

    return {
      approved: true,
      actorUserId: payload.actorUserId,
      credentialId: payload.credentialId,
      opId: payload.opId,
      designation,
      payloadHash: createHash('sha256').update(payloadJson, 'utf8').digest('hex'),
    };
  }

  /**
   * 只读实时核对：某用户当前是否仍是指定账本的所有权人且账本启用
   * （敏感操作在执行点复查所有权时用，不依赖某次授权载荷）
   * @returns {Promise<{ok: boolean, reason?: string, designation?: Object}>}
   */
  async checkOwnerLive(ledgerId, ownerUserId) {
    let designation;
    try {
      designation = await this._contract.getLedger(ledgerId);
    } catch (err) {
      return { ok: false, reason: `Contract unavailable: cannot verify ledger designation (${err.message})` };
    }
    if (!designation) return { ok: false, reason: 'ledger is not designated on contract' };
    if (!designation.enabled) return { ok: false, reason: 'ledger is disabled on contract' };
    if (designation.ownerUserId !== ownerUserId) return { ok: false, reason: 'not the designated owner of this ledger' };
    return { ok: true, designation };
  }
}
