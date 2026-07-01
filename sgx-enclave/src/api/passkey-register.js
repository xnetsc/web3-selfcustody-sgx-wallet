/**
 * Passkey 注册流程 API
 * 单步注册：提交 WebAuthn 注册响应
 *
 * 三种场景：
 * - 场景A（无 Passkey，purpose=register）：直接绑定 Passkey，无需现有 Passkey 验证
 *   适用于：
 *   1. 全新用户（userId 不存在）：userId 可选，若未提供则从 challenge 记录中获取（challenge 接口生成）
 *   2. 已有账户但尚无 Passkey 的用户（userId 已存在但 passkeys 表无记录）：userId 必须提供
 *   注意：若 userId 未提供，服务端从 challenge 记录中获取 userId（challenge 接口生成的随机 userId）
 *   安全增强：场景A中，若 userId 已存在且该账户下有钱包（助记词或纯私钥），
 *   则自动冻结账户 72 小时，防止冒充绑定 Passkey 盗取资产。
 * - 场景B（已有 Passkey，purpose=register_passkey）：添加新 Passkey，需要现有 Passkey 的 WebAuthn 签名验证
 *   userId 必须提供
 * - 场景C（Passkey 恢复，purpose=register）：用户丢失所有 Passkey，Owner 通过合约授权恢复
 *   Owner 预先在合约设置 setPasskeyRecovery(userId, newPubKeyHash, oldPubKeyHash, uuid, memo)。
 *   用户用新 Passkey 注册时，SGX 查询合约匹配 (userId, SHA256(newPublicKeyCose))：
 *   - 找到恢复条目 → 验证 oldPubKeyHash 匹配现有某个 Passkey
 *   - 保留匹配的旧 Passkey 记录（防止级联删除），删除其余 Passkey
 *   - 用新 Passkey 替换保留的记录，触发冻结（72h）
 *   合约不可用时此功能不可用。
 *
 * 冻结账户替换逻辑：
 *   当账户处于冻结状态时，若通过 purpose=register 重新注册，则：
 *   - 删除旧的冻结 Passkey（导致冻结的那个）
 *   - 注册新的 Passkey
 *   - 重置冻结时间为 72 小时（从当前时刻重新计算）
 *   目的：若之前的注册是冒充的，真正的账户所有人可以重新注册，延长冻结期作为缓冲。
 *
 * 场景B（已有 Passkey）的安全流程：
 *   1. 客户端调用 /api/challenge（purpose=register_passkey）获取 challenge1（纯随机数）
 *   2. 客户端用 challenge1 创建新 Passkey → 得到 newCredentialId 和 newPublicKeyCose
 *   3. 客户端计算 existingChallenge = SHA256(challenge1 + newCredentialId + newPublicKeyCoseBase64url)
 *   4. 客户端用已有 Passkey 对 existingChallenge 签名（existingWebauthnSignature）
 *   5. 客户端提交：attestationResponse（新 Passkey 注册仪式）+ existingWebauthnSignature（已有 Passkey 签名）
 *
 * 服务端验证逻辑（场景B）：
 *   1. 从 attestationResponse.clientDataJSON 提取 challenge1
 *   2. 验证 challenge1 是有效的 register_passkey 挑战值（从 DB 查找，不消费）
 *   3. 验证 attestationResponse（使用 challenge1 作为 expectedChallenge），提取 newCredentialId 和 newPublicKeyCose
 *   4. 计算 expectedExistingChallenge = SHA256(challenge1 + newCredentialId + newPublicKeyCoseBase64url)
 *   5. 验证 existingWebauthnSignature 中的 challenge == expectedExistingChallenge
 *   6. 验证已有 Passkey 的签名（使用 expectedExistingChallenge 作为 expectedChallenge）
 *   7. 消费 challenge1（从 DB 删除）
 *
 * HTTP body 仅包含 { payload, platformSignature }，
 * 所有业务参数从验证后的 payload 解析获取。
 */

import crypto from 'crypto';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { verifyWebAuthnSignature } from '../modules/webauthn/verifier.js';
import { PasskeyManager } from '../modules/webauthn/passkey-manager.js';

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
 * 计算 existingChallenge = SHA256(challenge1 + newCredentialId + newPublicKeyCoseBase64url)
 * @param {string} challenge1 - 服务端生成的 register_passkey 挑战值（base64url，纯随机数）
 * @param {string} newCredentialId - 新 Passkey 的凭证 ID（base64url）
 * @param {string} newPublicKeyCoseBase64url - 新 Passkey 的 COSE 格式公钥（base64url）
 * @returns {string} base64url 编码的 SHA256 哈希
 */
function computeExistingChallenge(challenge1, newCredentialId, newPublicKeyCoseBase64url) {
  return crypto.createHash('sha256')
    .update(challenge1 + newCredentialId + newPublicKeyCoseBase64url)
    .digest('base64url');
}

/**
 * Passkey 注册流程处理器
 */
export class PasskeyRegisterHandler {
  /**
   * @param {Object} deps - 依赖注入
   * @param {import('../modules/whitelist/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../modules/webauthn/passkey-manager.js').PasskeyManager} deps.passkeyManager
   * @param {import('../modules/webauthn/challenge-manager.js').WebAuthnChallengeManager} deps.challengeManager
   * @param {import('../modules/webauthn/account-freeze-manager.js').AccountFreezeManager} deps.accountFreezeManager
   * @param {import('../modules/wallet-management/wallet-manager.js').WalletManager} deps.walletManager
   * @param {import('../modules/contract-client/index.js').ContractClient} deps.contractClient
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('PasskeyRegisterHandler requires whitelistVerifier');
    if (!deps.passkeyManager) throw new Error('PasskeyRegisterHandler requires passkeyManager');
    if (!deps.challengeManager) throw new Error('PasskeyRegisterHandler requires challengeManager');
    if (!deps.accountFreezeManager) throw new Error('PasskeyRegisterHandler requires accountFreezeManager');
    if (!deps.walletManager) throw new Error('PasskeyRegisterHandler requires walletManager');
    if (!deps.contractClient) throw new Error('PasskeyRegisterHandler requires contractClient');
    this._whitelist = deps.whitelistVerifier;
    this._passkey = deps.passkeyManager;
    this._challenge = deps.challengeManager;
    this._accountFreeze = deps.accountFreezeManager;
    this._wallet = deps.walletManager;
    this._contract = deps.contractClient;
  }

  /**
   * 提交注册结果
   *
   * 场景A（无 Passkey，purpose=register）：
   *   payload JSON: { userId?, attestationResponse }
   *   - userId 可选：
   *     - 若提供 userId：使用该 userId（可能是已有账户但无 Passkey，也可能是全新账户）
   *     - 若未提供 userId：从 challenge 记录中获取（challenge 接口生成的随机 userId）
   *   - 无需现有 Passkey 验证，直接绑定新 Passkey
   *   - 挑战值由 /api/challenge（purpose=register）提供（纯随机数）
   *
   * 场景B（已有 Passkey，purpose=register_passkey）：
   *   payload JSON: { userId, attestationResponse, existingCredentialId, existingWebauthnSignature }
   *   - userId 必须提供
   *   - attestationResponse：新 Passkey 的注册仪式响应（challenge = challenge1，纯随机数）
   *   - existingWebauthnSignature：已有 Passkey 的签名（challenge = SHA256(challenge1 + newCredentialId + newPublicKeyCose)）
   *   - 服务端验证两个签名，确保新 Passkey 的公钥和 ID 未被中途替换
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<{ success: boolean, userId: string, credentialId: string, isFirstPasskey: boolean, frozen?: boolean, freezeUntil?: string }>}
   */
  async handleComplete(request) {
    // 1. 验证平台白名单签名
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      console.log(`[PasskeyRegister] handleComplete: REJECTED - ${whitelistResult.reason}`);
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 2. 解析验证过的 payload，替换 request
    try {
      request = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    console.log(`[PasskeyRegister] handleComplete: userId=${request.userId || '(not provided, will use from challenge)'}`);

    if (!request.attestationResponse) {
      throw new Error('attestationResponse is required');
    }

    const attestationResponse = request.attestationResponse;
    if (!attestationResponse.response || !attestationResponse.response.attestationObject || !attestationResponse.response.clientDataJSON) {
      throw new Error('attestationResponse.response.attestationObject and clientDataJSON are required');
    }

    // 3. 从 attestationResponse.clientDataJSON 中提取 origin 和 challenge1
    const clientDataJSONBase64url = attestationResponse.response.clientDataJSON;
    const { origin, challenge: challenge1 } = parseClientDataJSON(clientDataJSONBase64url);
    const rpId = extractRpIdFromOrigin(origin);

    if (!challenge1) {
      throw new Error('challenge not found in attestationResponse.clientDataJSON');
    }

    // 4. 判断场景：
    //   - 若 userId 未提供：一定是场景A（全新用户，userId 从 challenge 记录中获取）
    //   - 若 userId 已提供：查询该用户是否有 Passkey
    //     - 无 Passkey → 场景A（已有账户但尚无 Passkey）
    //     - 有 Passkey → 场景B（需要现有 Passkey 的 WebAuthn 签名验证）
    //   - 特殊：若账户被冻结且 challenge purpose=register → 冻结替换场景
    let finalUserId = request.userId || null;
    let hasNoPasskeys = true;
    let isExistingAccount = false; // 标记是否为已有账户（用于冻结判断）
    let isFrozenReplacement = false; // 标记是否为冻结账户的 Passkey 替换
    let frozenOldCredentialId = null; // 冻结替换时记录旧 credentialId，用于原地替换
    let isPotentialRecovery = false; // 场景C：用户有 Passkey 但未提供 existingWebauthnSignature，可能是合约授权恢复

    if (finalUserId) {
      // 4a. 优先检查账户是否被冻结（仅当 withinFreezePeriod=true 时才视为冻结；过期的冻结记录忽略）
      const freezeStatus = this._accountFreeze.getFreezeStatus(finalUserId);
      if (freezeStatus.frozen && freezeStatus.withinFreezePeriod) {
        // 账户被冻结，检查 challenge purpose 是否为 register
        const registerChallenge = this._challenge.findChallenge(challenge1, finalUserId, 'register');
        if (registerChallenge.found) {
          // 冻结账户通过 purpose=register 重新注册 → 替换旧 Passkey
          isFrozenReplacement = true;
          // 记录旧 credentialId，待提取新 Passkey 信息后原地替换（不删除，保留 wallets 等关联数据）
          frozenOldCredentialId = freezeStatus.credentialId;
          console.log(`[PasskeyRegister] handleComplete: frozen account passkey replacement, will replace credentialId=${freezeStatus.credentialId}`);
          // 强制场景A逻辑（无需现有 Passkey 验证）
          hasNoPasskeys = true;
          isExistingAccount = true;
        } else {
          // 冻结账户但 challenge purpose 不是 register → 拒绝
          throw new Error('Account is frozen: only purpose=register is allowed for re-registration');
        }
      } else {
        // 账户未冻结，正常判断场景
        const existingPasskeys = await this._passkey.listPasskeys(finalUserId);
        hasNoPasskeys = existingPasskeys.length === 0;
        if (hasNoPasskeys) {
          // 若 userId 已提供且无 Passkey，说明是已有账户补绑 Passkey
          isExistingAccount = true;
        } else if (!request.existingWebauthnSignature) {
          // 用户有 Passkey 但未提供现有 Passkey 签名 → 标记为潜在恢复场景（Scenario C）
          // 后续在验证 attestation 并获取新公钥哈希后，查询合约恢复条目
          isPotentialRecovery = true;
          // 按场景A逻辑走 challenge 验证（purpose=register）
          hasNoPasskeys = true;
          isExistingAccount = true;
          console.log(`[PasskeyRegister] handleComplete: user has passkeys but no existingWebauthnSignature, checking contract recovery`);
        }
      }
    }
    // 若 finalUserId 为 null，一定是场景A（全新用户），hasNoPasskeys 保持 true

    // 用于记录 challenge1 的 DB 记录 ID（场景B中需要手动消费）
    let challenge1DbId = null;

    if (hasNoPasskeys) {
      // 场景A：无 Passkey，使用 purpose=register 的挑战值，直接绑定新 Passkey
      // challenge1 是纯随机数，直接验证并消费
      // 若 userId 未提供，从 challenge 记录中获取（不传 userId 给 verifyAndConsumeChallenge）
      const challengeResult = this._challenge.verifyAndConsumeChallenge(
        challenge1,
        finalUserId,  // 若为 null，则不验证 userId，从 challenge 记录中获取
        'register'
      );
      if (!challengeResult.valid) {
        throw new Error('Challenge validation failed: ' + challengeResult.reason);
      }
      // 若 userId 未提供，从 challenge 记录中获取
      if (!finalUserId) {
        finalUserId = challengeResult.userId;
        console.log(`[PasskeyRegister] handleComplete: userId not provided, using from challenge: ${finalUserId}`);
        // 从 challenge 获取的 userId 是新生成的，不是已有账户
        isExistingAccount = false;
      }
    } else {
      // 场景B：已有 Passkey，必须提供现有 Passkey 的 WebAuthn 签名
      if (!request.existingCredentialId) {
        throw new Error('existingCredentialId is required when adding a new Passkey to an existing account');
      }
      if (!request.existingWebauthnSignature) {
        throw new Error('existingWebauthnSignature is required when adding a new Passkey to an existing account');
      }

      // 步骤4a：验证 challenge1 是有效的 register_passkey 挑战值（查找但不消费）
      // challenge1 是纯随机数，直接查找
      const challenge1Record = this._challenge.findChallenge(challenge1, request.userId, 'register_passkey');
      if (!challenge1Record.found) {
        throw new Error('register_passkey challenge validation failed: ' + challenge1Record.reason);
      }
      challenge1DbId = challenge1Record.id;
    }

    // 5. 使用 @simplewebauthn/server 验证注册响应（attestationResponse）
    // 提取新 Passkey 的 credentialId 和 publicKeyCose
    // challenge1 是纯随机数，直接作为 expectedChallenge
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: {
          id: attestationResponse.id || attestationResponse.rawId,
          rawId: attestationResponse.rawId || attestationResponse.id,
          response: {
            attestationObject: attestationResponse.response.attestationObject,
            clientDataJSON: clientDataJSONBase64url,
          },
          type: 'public-key',
        },
        expectedChallenge: challenge1,
        expectedOrigin: origin,   // 使用用户提交的 origin，绕过钓鱼验证
        expectedRPID: rpId,       // 从 origin 提取的 hostname
        requireUserVerification: false,
      });
    } catch (err) {
      throw new Error('WebAuthn registration verification failed: ' + err.message);
    }

    if (!verification.verified) {
      throw new Error('WebAuthn registration verification failed');
    }

    // 6. 从验证结果中提取 COSE 格式公钥和凭证 ID
    const { credentialID, credentialPublicKey } = verification.registrationInfo;
    const publicKeyCose = Buffer.from(credentialPublicKey);
    // @simplewebauthn/server v10: credentialID is already a Base64URLString (string), no encoding needed
    const credentialId = credentialID;
    const publicKeyCoseBase64url = publicKeyCose.toString('base64url');

    console.log(`[PasskeyRegister] handleComplete: credentialId=${credentialId}`);

    // 6.5. 场景C：合约授权 Passkey 恢复
    //   用户有 Passkey 但未提供 existingWebauthnSignature → 查询合约恢复条目
    //   若合约中存在 (userId, SHA256(newPublicKeyCose)) 的恢复条目，执行恢复流程
    let isRecovery = false;
    let recoveryEntry = null;
    if (isPotentialRecovery) {
      const newPubKeyHash = PasskeyManager.computePubKeyHash(publicKeyCose);
      recoveryEntry = await this._contract.getPasskeyRecovery(finalUserId, newPubKeyHash);
      if (!recoveryEntry) {
        // 合约无恢复条目 → 无法恢复，也无法走场景B（缺少 existingWebauthnSignature）
        throw new Error('Passkey recovery not authorized: no recovery entry found in contract for this userId and new passkey public key');
      }

      // 验证 oldPubKeyHash 在用户现有 Passkey 中存在
      const allPasskeys = await this._passkey.listPasskeys(finalUserId);
      const oldPubKeyHash = recoveryEntry.oldPubKeyHash;
      let oldMatchFound = false;
      for (const pk of allPasskeys) {
        if (PasskeyManager.computePubKeyHash(pk.publicKeyCose) === oldPubKeyHash) {
          oldMatchFound = true;
          break;
        }
      }
      if (!oldMatchFound) {
        throw new Error('Passkey recovery failed: oldPubKeyHash from contract does not match any existing passkey for this user');
      }

      isRecovery = true;
      console.log(`[PasskeyRegister] handleComplete: contract recovery entry found, uuid=${recoveryEntry.uuid}, proceeding with recovery`);
    }

    // 7. 场景B：验证已有 Passkey 的签名
    if (!hasNoPasskeys) {
      // 验证现有 Passkey 的归属
      const ownershipValid = await this._passkey.verifyPasskeyOwnership(finalUserId, request.existingCredentialId);
      if (!ownershipValid) {
        console.log(`[PasskeyRegister] handleComplete: REJECTED - existing passkey not bound to userId=${finalUserId}`);
        throw new Error('Passkey not bound to this user');
      }

      // 获取现有 Passkey 的公钥
      const existingPasskey = await this._passkey.getPasskey(finalUserId, request.existingCredentialId);
      if (!existingPasskey) {
        throw new Error('Passkey not found');
      }

      // 计算 expectedExistingChallenge = SHA256(challenge1 + newCredentialId + newPublicKeyCoseBase64url)
      // 这样已有 Passkey 的签名就绑定了新 Passkey 的公钥和 ID，防止中途替换
      const expectedExistingChallenge = computeExistingChallenge(challenge1, credentialId, publicKeyCoseBase64url);

      // 验证已有 Passkey 的签名（使用 expectedExistingChallenge 作为 expectedChallenge）
      const sigResult = await verifyWebAuthnSignature({
        userId: finalUserId,
        credentialId: request.existingCredentialId,
        webauthnSignature: request.existingWebauthnSignature,
        expectedChallenge: expectedExistingChallenge,
        publicKeyCose: existingPasskey.publicKeyCose,
      });
      if (!sigResult.verified) {
        console.log(`[PasskeyRegister] handleComplete: REJECTED - existing Passkey WebAuthn signature invalid: ${sigResult.reason}`);
        throw new Error(`WebAuthn verification failed: ${sigResult.reason}`);
      }

      console.log(`[PasskeyRegister] handleComplete: existing Passkey signature verified, new Passkey binding confirmed`);

      // 消费 challenge1（从 DB 删除）
      this._challenge.consumeChallengeById(challenge1DbId);
    }

    // 8. 注册/替换 Passkey（存储 COSE 格式公钥）
    //    冻结替换场景：原地替换（UPDATE），保留 wallets 等关联数据，避免级联删除
    //    恢复场景（Scenario C）：保留匹配旧公钥的 Passkey，删除其余，用新 Passkey 替换保留的
    //    其他场景：正常注册（INSERT）
    let result;
    if (isRecovery) {
      // 场景C：合约授权 Passkey 恢复
      const recoveryResult = await this._passkey.recoveryReplace(
        finalUserId, recoveryEntry.oldPubKeyHash, credentialId, publicKeyCose
      );
      if (!recoveryResult.success) {
        throw new Error('Passkey recovery replace failed: old passkey matching oldPubKeyHash not found');
      }
      result = { userId: finalUserId, credentialId };
      console.log(`[PasskeyRegister] handleComplete: RECOVERY complete, userId=${finalUserId}, replaced=${recoveryResult.replacedCredentialId}, deletedOthers=${recoveryResult.deletedCount}, uuid=${recoveryEntry.uuid}`);
    } else if (isFrozenReplacement) {
      const replaced = await this._passkey.replacePasskey(finalUserId, frozenOldCredentialId, credentialId, publicKeyCose);
      if (!replaced) {
        throw new Error('Frozen passkey replacement failed: old credentialId not found');
      }
      result = { userId: finalUserId, credentialId };
    } else {
      result = await this._passkey.registerPasskey(finalUserId, credentialId, publicKeyCose);
    }

    // 9. 安全增强：处理冻结逻辑
    //    a. 冻结替换场景：重置冻结时间（用新 credentialId 替换旧的，72h 重新计算）
    //    b. 恢复场景（Scenario C）：触发冻结（账户有钱包，新 Passkey 通过合约授权注册）
    //    c. 场景A补绑场景：若为已有账户且有钱包，则冻结账户 72 小时
    let freezeResult = null;
    if (isFrozenReplacement) {
      // 9a. 冻结替换：重置冻结（新 credentialId + 重新计算 72h）
      freezeResult = this._accountFreeze.resetFreeze(finalUserId, credentialId);
      console.log(`[PasskeyRegister] handleComplete: frozen account passkey REPLACED, userId=${finalUserId}, new freezeUntil=${freezeResult.freezeUntil}`);
    } else if (isRecovery) {
      // 9b. 恢复场景：触发冻结（恢复后账户一定有钱包，否则不需要恢复）
      freezeResult = this._accountFreeze.freezeAccount(finalUserId, credentialId);
      console.log(`[PasskeyRegister] handleComplete: RECOVERY account FROZEN, userId=${finalUserId}, freezeUntil=${freezeResult.freezeUntil}, uuid=${recoveryEntry.uuid}`);
    } else if (isExistingAccount && hasNoPasskeys) {
      // 9c. 场景A补绑：若该 userId 下有钱包（助记词或纯私钥），则冻结账户 72 小时
      const wallets = await this._wallet.listWallets(finalUserId);
      if (wallets.length > 0) {
        freezeResult = this._accountFreeze.freezeAccount(finalUserId, credentialId);
        console.log(`[PasskeyRegister] handleComplete: account FROZEN, userId=${finalUserId}, freezeUntil=${freezeResult.freezeUntil}`);
      }
    }

    console.log(`[PasskeyRegister] handleComplete: success, userId=${result.userId}, isFirstPasskey=${hasNoPasskeys}, frozen=${!!freezeResult}, frozenReplacement=${isFrozenReplacement}, recovery=${isRecovery}`);

    const response = {
      success: true,
      userId: result.userId,
      credentialId: result.credentialId,
      isFirstPasskey: hasNoPasskeys,
    };

    if (isRecovery) {
      response.recovery = true;
      response.recoveryUuid = recoveryEntry.uuid;
    }

    if (freezeResult) {
      response.frozen = true;
      response.freezeUntil = freezeResult.freezeUntil;
    }

    return response;
  }
}
