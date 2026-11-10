/**
 * 授权撤销（平台转发）API
 *
 * 日常撤销通道：用户签署撤销声明后，由平台转发到 SGX，SGX 验证签名后把
 * 撤销记录直接存入本地数据库（source=platform）。此后交易签名优先查本地
 * 记录，不再为已知撤销反复调用合约。合约撤销（revokeAuthorization）只作
 * 兜底：平台不配合转发时，用户可绕过平台直接上链，SGX 在本地未命中时查
 * 合约发现并缓存（source=contract）。
 *
 * 撤销证明与合约 revokeAuthorization 完全同构，平台转发哪份、上链提交
 * 哪份，是同一份签名：
 *   digest = SHA256(utf8(userId) || utf8(authorizationId) || grantee 地址 20 字节)
 *   由授权归属用户的 Passkey（P256）对 digest 签名，给出 (r, s) 与公钥 X/Y。
 * SGX 校验：X/Y 必须与该 userId + credentialId 绑定的 Passkey 公钥一致，
 * 且签名对 digest 有效。平台签名（外层信封）只证明转发方在平台白名单内，
 * 不能代替用户签名——平台自己无法凭空撤销用户授权。
 *
 * 到期时间的可信来源：被撤销授权的到期时间只能取自经验证的授权原文
 * （SGX 已存的 authorization_records，或本次随附并验签通过的
 * authorizationJson），不采信请求中裸填的到期字段，防止平台用假的过去
 * 时间让撤销记录被提前清理。
 *
 * 落库证明：本 handler 的返回值会被 server 的 wrap 序列化为 data 并计算
 * SHA256 注入 user_report_data 生成 attestationQuote。返回值中包含落库后
 * 的撤销记录与授权原文记录，发起人验证 quote 即等于验证 SGX 确实按这份
 * 授权原文记住了这条撤销。
 *
 * HTTP body 仅包含 { payload, platformSignature }，
 * 所有业务参数从验证后的 payload 解析获取。
 */

import crypto from 'crypto';
import elliptic from 'elliptic';
import cbor from 'cbor';
import { verifyWebAuthnSignature } from '../modules/webauthn/verifier.js';
import { parseAuthorization, computeAuthorizationHash } from '../modules/auth-engine/authorization-parser.js';

const EC = new elliptic.ec('p256');

/**
 * 规范化 bytes32 十六进制字段
 * @param {string} value - 0x 前缀或裸 hex
 * @param {string} field - 字段名（报错用）
 * @returns {string} 无 0x 前缀的小写 hex（64 字符）
 */
function normalizeBytes32Hex(value, field) {
  if (typeof value !== 'string') {
    throw new Error(`${field} is required and must be a hex string`);
  }
  const hex = value.startsWith('0x') ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`${field} must be a 32-byte hex string`);
  }
  return hex.toLowerCase();
}

/**
 * 从 COSE 公钥中提取 P256 公钥坐标
 * @param {Buffer|Uint8Array} publicKeyCose
 * @returns {{ x: string, y: string }} 无 0x 前缀的小写 hex
 */
function extractP256Coordinates(publicKeyCose) {
  const decoded = cbor.decodeFirstSync(Buffer.from(publicKeyCose));
  const x = decoded.get(-2);
  const y = decoded.get(-3);
  if (!Buffer.isBuffer(x) || !Buffer.isBuffer(y) || x.length !== 32 || y.length !== 32) {
    throw new Error('Passkey public key is not a P256 COSE key');
  }
  return { x: x.toString('hex'), y: y.toString('hex') };
}

/**
 * 验证合约同构的 P256 撤销签名：签名对象为 digest 本身（与合约
 * P256.verify(messageHash, r, s, x, y) 的语义一致，不再二次哈希）
 * @param {{ x: string, y: string, digest: Buffer, r: string, s: string }} params - x/y/r/s 为无 0x hex
 * @returns {boolean}
 */
function verifyRevocationSignature({ x, y, digest, r, s }) {
  try {
    const key = EC.keyFromPublic({ x, y }, 'hex');
    return key.verify(digest, { r, s });
  } catch {
    return false;
  }
}

export class AuthRevocationHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/whitelist/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../modules/webauthn/passkey-manager.js').PasskeyManager} deps.passkeyManager
   * @param {import('../modules/state-management/state-manager.js').StateManager} deps.stateManager
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('AuthRevocationHandler requires whitelistVerifier');
    if (!deps.passkeyManager) throw new Error('AuthRevocationHandler requires passkeyManager');
    if (!deps.stateManager) throw new Error('AuthRevocationHandler requires stateManager');
    this._whitelist = deps.whitelistVerifier;
    this._passkey = deps.passkeyManager;
    this._state = deps.stateManager;
    // 应急授权校验器（可选注入）：治理授权可代替目标用户撤销其普通授权，
    // 落库来源记为 source=emergency（与 platform 同为本地权威来源）
    this._emergency = deps.emergencyAuthorizer || null;
  }

  /**
   * 处理平台转发的授权撤销
   *
   * payload JSON: {
   *   userId, authorizationId, grantee, credentialId,
   *   passkeyPubKeyX, passkeyPubKeyY, signatureR, signatureS,
   *   authorizationJson?,    // SGX 无该授权原文记录时必填（原始 JSON 字符串）
   *   authorizationSignature? // 与 authorizationJson 配套的用户 WebAuthn 签名
   * }
   *
   * @param {Object} request - HTTP body: { payload, platformSignature }
   * @returns {Promise<Object>} 落库后的撤销记录 + 授权原文记录（随响应 data 一起进入远程证明）
   */
  async handleRevoke(request) {
    // 1. 验证平台白名单签名（转发方身份）
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }

    // 2. 解析验证过的 payload
    let payload;
    try {
      payload = JSON.parse(request.payload);
    } catch (err) {
      throw new Error('Invalid payload: must be valid JSON');
    }

    // 应急撤销路径：payload 携带 emergencyAuthorizationJson 时，治理授权
    // 替代目标用户的撤销签名（用户已无法操作的前提下，撤销签名无从取得）
    if (payload.emergencyAuthorizationJson) {
      return this._handleEmergencyRevoke(payload, whitelistResult.address);
    }

    const { userId, authorizationId, credentialId } = payload;
    if (!userId) throw new Error('userId is required');
    if (!authorizationId) throw new Error('authorizationId is required');
    if (!credentialId) throw new Error('credentialId is required');
    if (!payload.grantee || !/^0x[0-9a-fA-F]{40}$/.test(payload.grantee)) {
      throw new Error('grantee is required and must be an Ethereum address');
    }
    const grantee = payload.grantee;

    const pubKeyX = normalizeBytes32Hex(payload.passkeyPubKeyX, 'passkeyPubKeyX');
    const pubKeyY = normalizeBytes32Hex(payload.passkeyPubKeyY, 'passkeyPubKeyY');
    const signatureR = normalizeBytes32Hex(payload.signatureR, 'signatureR');
    const signatureS = normalizeBytes32Hex(payload.signatureS, 'signatureS');

    console.log(`[AuthRevocation] handleRevoke: userId=${userId}, authorizationId=${authorizationId}, grantee=${grantee}, forwardedBy=${whitelistResult.address}`);

    // 3. 校验 X/Y 与绑定的 Passkey 公钥一致（防止拿别人的公钥配签名蒙混）
    const passkey = await this._passkey.getPasskey(userId, credentialId);
    if (!passkey) {
      throw new Error(`Passkey not found: userId=${userId}, credentialId=${credentialId}`);
    }
    const coords = extractP256Coordinates(passkey.publicKeyCose);
    if (coords.x !== pubKeyX || coords.y !== pubKeyY) {
      throw new Error('Revocation signature verification failed: passkey public key does not match the bound Passkey');
    }

    // 4. 验证用户撤销签名（与合约 revokeAuthorization 同构）
    const digest = crypto.createHash('sha256').update(Buffer.concat([
      Buffer.from(userId, 'utf8'),
      Buffer.from(authorizationId, 'utf8'),
      Buffer.from(grantee.slice(2), 'hex'),
    ])).digest();
    if (!verifyRevocationSignature({ x: pubKeyX, y: pubKeyY, digest, r: signatureR, s: signatureS })) {
      throw new Error('Revocation signature verification failed: invalid P256 signature');
    }

    // 5. 确定授权原文记录（到期时间与哈希的可信来源）
    const authorizationRecord = await this._resolveAuthorizationRecord(payload, { userId, authorizationId, grantee });

    // 6. 落库（source=platform），并同步授权状态；无已存授权原文时，
    //    授权原文与撤销记录在同一个事务内写入（同事务前置回调），不存在只成功一半
    const toSave = authorizationRecord.authorizationToSave;
    const stored = await this._state.recordRevocation({
      userId,
      authorizationId,
      grantee,
      source: 'platform',
      authorizationExpiresAt: authorizationRecord.authorizationJson?.timePolicy?.deadline || null,
      authorizationHash: authorizationRecord.authorizationHash,
    }, toSave
      ? (conn) => this._state._saveAuthorizationRecordInTransaction(conn, userId, authorizationId, toSave.grantee, toSave.authorizationJson, authorizationRecord.authorizationHash)
      : null);

    console.log(`[AuthRevocation] handleRevoke: recorded platform revocation for userId=${userId}, authorizationId=${authorizationId}`);

    // 返回值整体进入远程证明的 data：撤销记录 + 授权原文记录都在其中
    return {
      revoked: true,
      userId,
      authorizationId,
      grantee,
      source: 'platform',
      revocationRecord: stored,
      authorizationRecord: {
        userId,
        authorizationId,
        grantee: authorizationRecord.grantee,
        authorizationJson: authorizationRecord.authorizationJson,
        authorizationHash: authorizationRecord.authorizationHash,
        createdAt: authorizationRecord.createdAt,
      },
    };
  }

  /**
   * 应急撤销：凭合约治理授权撤销目标用户的某份普通授权
   *
   * payload JSON: {
   *   userId, authorizationId, grantee,           // 被撤销的普通授权的标识
   *   emergencyAuthorizationJson, emergencySignature,
   *   authorizationJson?, authorizationSignature? // SGX 无目标授权原文记录时必填，
   *                                               // 语义与平台转发路径完全相同
   * }
   * 撤销的到期时间/哈希可信来源规则与用户签名路径一致（复用
   * _resolveAuthorizationRecord），落库来源记为 source=emergency。
   *
   * @private
   */
  async _handleEmergencyRevoke(payload, platformAddress) {
    if (!this._emergency) {
      throw new Error('Emergency authorization is not enabled on this enclave');
    }
    const { userId, authorizationId } = payload;
    if (!userId) throw new Error('userId is required');
    if (!authorizationId) throw new Error('authorizationId is required');
    if (!payload.grantee || !/^0x[0-9a-fA-F]{40}$/.test(payload.grantee)) {
      throw new Error('grantee is required and must be an Ethereum address');
    }
    const grantee = payload.grantee;

    console.log(`[AuthRevocation] handleRevoke (emergency): userId=${userId}, authorizationId=${authorizationId}, grantee=${grantee}, forwardedBy=${platformAddress}`);

    const emgResult = await this._emergency.verify({
      authorizationJson: payload.emergencyAuthorizationJson,
      signature: payload.emergencySignature,
      platformAddress,
      operation: 'auth_revoke',
      userId,
      actualParams: { authorizationId, grantee },
    });
    if (!emgResult.approved) {
      throw new Error(`Emergency authorization verification failed: ${emgResult.reason}`);
    }

    // 到期时间与哈希的可信来源与用户路径同一规则
    const authorizationRecord = await this._resolveAuthorizationRecord(payload, { userId, authorizationId, grantee });

    const toSave = authorizationRecord.authorizationToSave;
    const stored = await this._state.recordRevocation({
      userId,
      authorizationId,
      grantee,
      source: 'emergency',
      authorizationExpiresAt: authorizationRecord.authorizationJson?.timePolicy?.deadline || null,
      authorizationHash: authorizationRecord.authorizationHash,
    }, toSave
      ? (conn) => this._state._saveAuthorizationRecordInTransaction(conn, userId, authorizationId, toSave.grantee, toSave.authorizationJson, authorizationRecord.authorizationHash)
      : null);

    const usedCount = await this._emergency.recordUse(emgResult.auth, userId, 'auth_revoke');
    const executionLog = await this._emergency.recordExecution(emgResult, {
      platformAddress,
      userId,
      operation: 'auth_revoke',
      executionIndex: usedCount,
      detail: { revokedAuthorizationId: authorizationId, revokedGrantee: grantee },
      outcome: { revoked: true },
    });

    console.log(`[AuthRevocation] handleRevoke (emergency): recorded emergency revocation for userId=${userId}, authorizationId=${authorizationId}, emergencyAuthorizationId=${emgResult.auth.authorizationId}`);

    return {
      revoked: true,
      userId,
      authorizationId,
      grantee,
      source: 'emergency',
      emergencyAuthorizationId: emgResult.auth.authorizationId,
      executionLog,
      revocationRecord: stored,
      authorizationRecord: {
        userId,
        authorizationId,
        grantee: authorizationRecord.grantee,
        authorizationJson: authorizationRecord.authorizationJson,
        authorizationHash: authorizationRecord.authorizationHash,
        createdAt: authorizationRecord.createdAt,
      },
    };
  }

  /**
   * 查询本地撤销记录（公开接口，无需任何身份验证）
   *
   * 只读 SGX 本地 authorization_revocations 表：无论记录来自平台转发
   * （source=platform）还是合约同步缓存（source=contract）都可查到。
   * 本接口不查合约、不验证平台签名或 Passkey，任何人可调用；返回值同样
   * 经 server 的 wrap 生成 attestationQuote，查询者可验证结果确出自 enclave。
   *
   * 请求体（直传字段，或放在 payload 中均可），三种查询方式：
   *   1. 批量精确查询：{ keys: [{ userId, authorizationId }, ...] }
   *      单次最多 5 个 key，超过直接报错。每项返回 revoked（是否存在）与
   *      revocationRecord（原始数据）；
   *   2. 单条精确查询：{ userId, authorizationId }（完整主键）→ 返回 revoked
   *      布尔值表示该撤销记录是否存在，存在时 revocationRecord 为原始数据；
   *   3. 列表查询：{ userId?, authorizationId?, grantee?, source?, page?, pageSize? }
   *      按 key 字段等值精确匹配（无模糊），至少提供一个 key。除当前页的
   *      revocationRecords（原始数据）外，还返回总条数 count 与总页数
   *      totalPages。分页：page 从 1 开始（默认 1），pageSize 默认 10、
   *      下限 1、上限 10，超出范围直接报错。
   *
   * @param {Object} request - HTTP body（无需 platformSignature）
   * @returns {Promise<Object>}
   */
  async handleQuery(request) {
    let query = request || {};
    if (typeof query.payload === 'string') {
      try {
        query = JSON.parse(query.payload);
      } catch {
        throw new Error('Invalid payload: must be valid JSON');
      }
    } else if (query.payload && typeof query.payload === 'object') {
      query = query.payload;
    }

    // 批量精确查询：单次 key 数量硬上限 5 个，超过报错（防止无鉴权接口被批量拖库）
    if (query.keys !== undefined) {
      if (!Array.isArray(query.keys) || query.keys.length === 0) {
        throw new Error('keys must be a non-empty array');
      }
      if (query.keys.length > 5) {
        throw new Error('keys must contain at most 5 items per query');
      }
      const results = [];
      for (const key of query.keys) {
        if (!key?.userId || !key?.authorizationId) {
          throw new Error('each key must include userId and authorizationId');
        }
        const records = await this._state.listRevocations({ userId: key.userId, authorizationId: key.authorizationId });
        results.push({
          userId: key.userId,
          authorizationId: key.authorizationId,
          revoked: records.length > 0,
          revocationRecord: records[0] || null,
        });
      }
      console.log(`[AuthRevocation] handleQuery(batch exact): keys=${results.length}, found=${results.filter(r => r.revoked).length}`);
      return { count: results.length, results };
    }

    const { userId, authorizationId, grantee, source } = query;
    if (!userId && !authorizationId && !grantee && !source) {
      throw new Error('at least one query key is required (userId, authorizationId, grantee or source)');
    }
    const filter = { userId, authorizationId, grantee, source };

    if (userId && authorizationId) {
      const records = await this._state.listRevocations(filter);
      console.log(`[AuthRevocation] handleQuery(exact): userId=${userId}, authorizationId=${authorizationId}, found=${records.length}`);
      return {
        userId,
        authorizationId,
        revoked: records.length > 0,
        revocationRecord: records[0] || null,
      };
    }

    // 列表查询：分页参数校验（pageSize 下限 1、上限 10，防止无鉴权接口被用来全量拖库）
    const page = query.page === undefined ? 1 : parseInt(query.page, 10);
    if (!Number.isInteger(page) || page < 1) {
      throw new Error('page must be greater than or equal to 1');
    }
    const pageSize = query.pageSize === undefined ? 10 : parseInt(query.pageSize, 10);
    if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 10) {
      throw new Error('pageSize must be between 1 and 10');
    }

    const total = await this._state.countRevocations(filter);
    const records = await this._state.listRevocations(
      filter,
      { limit: pageSize, offset: (page - 1) * pageSize }
    );
    console.log(`[AuthRevocation] handleQuery(list): filter=${JSON.stringify(filter)}, page=${page}, pageSize=${pageSize}, total=${total}, returned=${records.length}`);

    return {
      userId: userId || null,
      authorizationId: authorizationId || null,
      grantee: grantee || null,
      source: source || null,
      count: total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
      revocationRecords: records,
    };
  }

  /**
   * 解析可信的授权原文记录：
   *   - SGX 已存记录优先；请求另附 authorizationJson 时必须与已存记录哈希一致；
   *   - 无已存记录时，必须随附 authorizationJson + 原授权的 WebAuthn 签名，
   *     验签通过后经 authorizationToSave 交由调用方与撤销记录同事务落库。
   * 同时校验授权原文的 grantee 包含本次撤销的 grantee。
   *
   * @param {Object} payload
   * @param {{ userId: string, authorizationId: string, grantee: string }} ids
   * @returns {Promise<{ grantee: string[], authorizationJson: Object, authorizationHash: string, createdAt: string|null }>}
   */
  async _resolveAuthorizationRecord(payload, { userId, authorizationId, grantee }) {
    const existing = await this._state.getAuthorizationRecord(userId, authorizationId);

    if (existing) {
      if (payload.authorizationJson) {
        const providedHash = computeAuthorizationHash(payload.authorizationJson);
        if (providedHash !== existing.authorization_hash) {
          throw new Error('authorizationJson does not match the stored authorization record');
        }
      }
      this._assertGranteeCovered(existing.grantee, grantee);
      return {
        grantee: existing.grantee,
        authorizationJson: existing.authorization_json,
        authorizationHash: existing.authorization_hash,
        createdAt: existing.created_at,
      };
    }

    // 无已存记录：必须随附授权原文并验签
    if (!payload.authorizationJson || typeof payload.authorizationJson !== 'string') {
      throw new Error('authorizationJson is required when SGX has no stored authorization record');
    }
    if (!payload.authorizationSignature) {
      throw new Error('authorizationSignature is required when SGX has no stored authorization record');
    }

    let auth;
    try {
      auth = JSON.parse(payload.authorizationJson);
    } catch {
      throw new Error('authorizationJson is not valid JSON string');
    }
    if (auth.userId !== userId || auth.authorizationId !== authorizationId) {
      throw new Error('authorizationJson userId/authorizationId do not match the revocation');
    }

    const authForValidation = { ...auth, webauthnSignature: payload.authorizationSignature };
    const parseResult = parseAuthorization(authForValidation);
    if (!parseResult.valid) {
      throw new Error(`Invalid authorization: ${parseResult.reason}`);
    }
    this._assertGranteeCovered(auth.grantee, grantee);

    const authorizationHash = computeAuthorizationHash(payload.authorizationJson);
    const authPasskey = await this._passkey.getPasskey(userId, auth.credentialId);
    if (!authPasskey) {
      throw new Error(`Passkey not found: userId=${userId}, credentialId=${auth.credentialId}`);
    }
    const sigResult = await verifyWebAuthnSignature({
      userId,
      credentialId: auth.credentialId,
      webauthnSignature: payload.authorizationSignature,
      expectedChallenge: authorizationHash,
      publicKeyCose: authPasskey.publicKeyCose,
      signCount: authPasskey.signCount,
    });
    if (!sigResult.verified) {
      throw new Error(`Authorization signature verification failed: ${sigResult.reason}`);
    }

    // 验签通过。授权原文不在此处单独落库：由 handleRevoke 把它与撤销记录
    // 放进同一个事务写入（见 authorizationToSave），避免只成功一半
    // （授权存了、撤销没记上，或反过来）
    const granteeList = Array.isArray(auth.grantee) ? auth.grantee : [auth.grantee];

    return {
      grantee: granteeList,
      authorizationJson: authForValidation,
      authorizationHash,
      createdAt: null,
      authorizationToSave: { grantee: granteeList, authorizationJson: authForValidation },
    };
  }

  /**
   * 校验授权原文的 grantee 列表覆盖本次撤销的 grantee
   * @param {string|string[]} granteeList
   * @param {string} grantee
   */
  _assertGranteeCovered(granteeList, grantee) {
    const list = Array.isArray(granteeList) ? granteeList : [granteeList];
    const covered = list.some((g) => g === '*' || (typeof g === 'string' && g.toLowerCase() === grantee.toLowerCase()));
    if (!covered) {
      throw new Error('Revocation grantee is not covered by the authorization record');
    }
  }
}
