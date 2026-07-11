/**
 * 账户冻结管理器
 * 当已有账户（有钱包但无 Passkey）通过用户端注册补绑 Passkey 时，
 * 若该账户下存在钱包，则冻结账户以保护资产安全。
 *
 * 冻结时长配置优先级：
 *   1. 合约 runtimeParams.security.freezeDurationSeconds
 *   2. 环境变量 FREEZE_DURATION_SECONDS
 *   3. 代码默认值 259200 秒（72 小时）
 *
 * 冻结规则：
 *   - 冻结期内：该 userId 的所有请求均被拒绝
 *   - 冻结期后：仅允许使用冻结时绑定的 Passkey（credentialId）发起的带 webauthnSignature 的请求
 *     - 有 webauthnSignature 且 credentialId 匹配：允许，成功后永久解除冻结
 *     - 无 webauthnSignature 的请求：拒绝（即使 credentialId 匹配）
 *     - credentialId 不匹配的请求：拒绝
 *   - 冻结不会自动解除，必须通过绑定的 Passkey 发起签名请求才能解除
 *   - 冻结解除后：所有接口调用恢复正常
 */

import { getMonotonicDate, getMonotonicSqliteNow } from '../../utils/monotonic-clock.js';

/**
 * 默认冻结时长（秒），72 小时 = 259200 秒
 */
const DEFAULT_FREEZE_DURATION_SECONDS = 259200;

export class AccountFreezeManager {
  /**
   * @param {import('../../database/connection-manager.js').default} connectionManager
   * @param {Object} options
   * @param {number|function():number} options.freezeDurationSeconds - 冻结时长（秒），支持固定值或动态获取函数
   *   - 固定值：直接使用（如 259200）
   *   - 函数：每次冻结时调用，获取最新配置（如 () => contractClient.getFreezeDuration()）
   *   - 默认值：259200 秒（72 小时）
   */
  constructor(connectionManager, options = {}) {
    if (!connectionManager) {
      throw new Error('AccountFreezeManager requires a ConnectionManager instance');
    }
    this._db = connectionManager;
    this._freezeDurationSeconds = options.freezeDurationSeconds || DEFAULT_FREEZE_DURATION_SECONDS;
  }

  /**
   * 获取当前冻结时长（秒）
   * 支持固定值和动态获取函数，确保合约配置变更后新冻结使用最新的冻结时长
   * @returns {number}
   */
  _getFreezeDurationSeconds() {
    if (typeof this._freezeDurationSeconds === 'function') {
      const duration = this._freezeDurationSeconds();
      return duration > 0 ? duration : DEFAULT_FREEZE_DURATION_SECONDS;
    }
    return this._freezeDurationSeconds || DEFAULT_FREEZE_DURATION_SECONDS;
  }

  /**
   * 冻结账户
   * 若该 userId 已有冻结记录且状态为 frozen，则幂等返回已有记录
   *
   * @param {string} userId - 用户 ID
   * @param {string} credentialId - 触发冻结的 Passkey 凭证 ID
   * @returns {{ userId: string, credentialId: string, frozenAt: string, freezeUntil: string }}
   */
  freezeAccount(userId, credentialId) {
    if (!userId) throw new Error('userId is required');
    if (!credentialId) throw new Error('credentialId is required');

    // 检查是否已有冻结记录
    const existing = this._db.readQuery(
      "SELECT user_id, credential_id, frozen_at, freeze_until, status FROM account_freezes WHERE user_id = ?",
      [userId]
    );

    if (existing.length > 0 && existing[0].status === 'frozen') {
      // 已有冻结记录且仍为 frozen 状态，幂等返回
      console.log(`[AccountFreeze] freezeAccount: userId=${userId} already frozen until ${existing[0].freeze_until}`);
      return {
        userId: existing[0].user_id,
        credentialId: existing[0].credential_id,
        frozenAt: existing[0].frozen_at,
        freezeUntil: existing[0].freeze_until,
      };
    }

    // 计算冻结截止时间（动态获取最新冻结时长，确保合约配置变更后新冻结使用新值）
    const freezeDurationSeconds = this._getFreezeDurationSeconds();
    const frozenAt = getMonotonicDate();
    const freezeUntil = new Date(frozenAt.getTime() + freezeDurationSeconds * 1000);
    const frozenAtStr = frozenAt.toISOString().slice(0, 19).replace('T', ' ');
    const freezeUntilStr = freezeUntil.toISOString().slice(0, 19).replace('T', ' ');

    if (existing.length > 0) {
      // 已有记录但状态为 lifted，更新为 frozen
      this._db.writeQuery(
        `UPDATE account_freezes SET credential_id = ?, frozen_at = ?, freeze_until = ?, status = 'frozen', lifted_at = NULL WHERE user_id = ?`,
        [credentialId, frozenAtStr, freezeUntilStr, userId]
      );
    } else {
      // 插入新冻结记录
      this._db.writeQuery(
        `INSERT INTO account_freezes (user_id, credential_id, frozen_at, freeze_until, status) VALUES (?, ?, ?, ?, 'frozen')`,
        [userId, credentialId, frozenAtStr, freezeUntilStr]
      );
    }

    console.log(`[AccountFreeze] freezeAccount: userId=${userId} frozen until ${freezeUntilStr} (${freezeDurationSeconds}s), credentialId=${credentialId}`);

    return {
      userId,
      credentialId,
      frozenAt: frozenAtStr,
      freezeUntil: freezeUntilStr,
    };
  }

  /**
   * 获取账户冻结状态
   *
   * @param {string} userId - 用户 ID
   * @returns {{
   *   frozen: boolean,
   *   withinFreezePeriod: boolean,
   *   credentialId: string|null,
   *   frozenAt: string|null,
   *   freezeUntil: string|null
   * }}
   *   - frozen: 账户是否处于冻结状态（包括冻结期内和冻结期后未解除的）
   *   - withinFreezePeriod: 是否在冻结期内
   *   - credentialId: 触发冻结的 Passkey 凭证 ID
   *   - frozenAt: 冻结开始时间
   *   - freezeUntil: 冻结截止时间
   */
  getFreezeStatus(userId) {
    if (!userId) {
      return { frozen: false, withinFreezePeriod: false, credentialId: null, frozenAt: null, freezeUntil: null };
    }

    const rows = this._db.readQuery(
      "SELECT credential_id, frozen_at, freeze_until, status FROM account_freezes WHERE user_id = ?",
      [userId]
    );

    if (rows.length === 0 || rows[0].status !== 'frozen') {
      return { frozen: false, withinFreezePeriod: false, credentialId: null, frozenAt: null, freezeUntil: null };
    }

    const row = rows[0];
    const now = getMonotonicDate();
    const freezeUntil = new Date(row.freeze_until + 'Z'); // 确保 UTC 解析
    const withinFreezePeriod = now < freezeUntil;

    return {
      frozen: true,
      withinFreezePeriod,
      credentialId: row.credential_id,
      frozenAt: row.frozen_at,
      freezeUntil: row.freeze_until,
    };
  }

  /**
   * 检查账户是否被冻结（便捷方法）
   *
   * @param {string} userId - 用户 ID
   * @returns {boolean}
   */
  isAccountFrozen(userId) {
    return this.getFreezeStatus(userId).frozen;
  }

  /**
   * 重置账户冻结（用于冻结账户的 Passkey 替换场景）
   * 当冻结账户通过 purpose=register 重新注册时，用新的 credentialId 替换旧的，
   * 并将冻结时间重置。
   *
   * @param {string} userId - 用户 ID
   * @param {string} newCredentialId - 新的 Passkey 凭证 ID
   * @returns {{ reset: boolean, userId: string, credentialId: string, frozenAt: string, freezeUntil: string }}
   */
  resetFreeze(userId, newCredentialId) {
    if (!userId) throw new Error('userId is required');
    if (!newCredentialId) throw new Error('newCredentialId is required');

    const existing = this._db.readQuery(
      "SELECT user_id, status FROM account_freezes WHERE user_id = ?",
      [userId]
    );

    if (existing.length === 0 || existing[0].status !== 'frozen') {
      console.log(`[AccountFreeze] resetFreeze: userId=${userId} no active freeze to reset`);
      return { reset: false, userId, credentialId: null, frozenAt: null, freezeUntil: null };
    }

    // 计算新的冻结时间（动态获取最新冻结时长）
    const freezeDurationSeconds = this._getFreezeDurationSeconds();
    const frozenAt = getMonotonicDate();
    const freezeUntil = new Date(frozenAt.getTime() + freezeDurationSeconds * 1000);
    const frozenAtStr = frozenAt.toISOString().slice(0, 19).replace('T', ' ');
    const freezeUntilStr = freezeUntil.toISOString().slice(0, 19).replace('T', ' ');

    this._db.writeQuery(
      `UPDATE account_freezes SET credential_id = ?, frozen_at = ?, freeze_until = ?, lifted_at = NULL WHERE user_id = ? AND status = 'frozen'`,
      [newCredentialId, frozenAtStr, freezeUntilStr, userId]
    );

    console.log(`[AccountFreeze] resetFreeze: userId=${userId} freeze reset until ${freezeUntilStr} (${freezeDurationSeconds}s), newCredentialId=${newCredentialId}`);

    return {
      reset: true,
      userId,
      credentialId: newCredentialId,
      frozenAt: frozenAtStr,
      freezeUntil: freezeUntilStr,
    };
  }

  /**
   * 解除账户冻结
   *
   * @param {string} userId - 用户 ID
   * @returns {{ lifted: boolean, userId: string }}
   */
  liftFreeze(userId) {
    if (!userId) throw new Error('userId is required');

    const now = getMonotonicSqliteNow();

    const result = this._db.writeQuery(
      `UPDATE account_freezes SET status = 'lifted', lifted_at = ? WHERE user_id = ? AND status = 'frozen'`,
      [now, userId]
    );

    if (result.changes > 0) {
      console.log(`[AccountFreeze] liftFreeze: userId=${userId} freeze lifted at ${now}`);
      return { lifted: true, userId };
    }

    console.log(`[AccountFreeze] liftFreeze: userId=${userId} no active freeze to lift`);
    return { lifted: false, userId };
  }

  /**
   * 检查请求是否被冻结拦截，并返回拦截结果
   * 用于中间件统一检查
   *
   * 冻结规则：
   *   - 冻结期内：该 userId 的所有请求均被拒绝
   *   - 冻结期后：仅允许使用冻结时绑定的 Passkey（credentialId）发起的带 webauthnSignature 的请求
   *     - 有 webauthnSignature 且 credentialId 匹配：允许，成功后永久解除冻结
   *     - 无 webauthnSignature 的请求：拒绝（即使 credentialId 匹配）
   *     - credentialId 不匹配的请求：拒绝
   *   - 冻结不会自动解除，必须通过绑定的 Passkey 发起签名请求才能解除
   *
   * @param {string} userId - 用户 ID
   * @param {string|null} credentialId - 请求中的 credentialId（可能为空）
   * @param {boolean} hasWebauthnSignature - 请求是否包含 webauthnSignature
   * @returns {{
   *   blocked: boolean,
   *   reason: string,
   *   canLiftFreeze: boolean,
   *   freezeUntil: string|null
   * }}
   */
  checkRequest(userId, credentialId = null, hasWebauthnSignature = false) {
    const status = this.getFreezeStatus(userId);

    if (!status.frozen) {
      return { blocked: false, reason: '', canLiftFreeze: false, freezeUntil: null };
    }

    if (status.withinFreezePeriod) {
      // 冻结期内：拒绝所有请求
      return {
        blocked: true,
        reason: `Account is frozen: new passkey bound to existing account with wallets, account suspended until ${status.freezeUntil}`,
        canLiftFreeze: false,
        freezeUntil: status.freezeUntil,
      };
    }

    // 冻结期已过：仅允许使用冻结时绑定的 Passkey 发起的带签名的请求
    // 无 webauthnSignature 的请求一律拒绝（即使 credentialId 匹配）
    if (!hasWebauthnSignature) {
      return {
        blocked: true,
        reason: 'Account is frozen: passkey signature required to unfreeze account',
        canLiftFreeze: false,
        freezeUntil: status.freezeUntil,
      };
    }

    // 有 webauthnSignature，检查 credentialId 是否匹配
    if (credentialId !== status.credentialId) {
      return {
        blocked: true,
        reason: 'Account is frozen: request must use the passkey that was bound during registration to unfreeze account',
        canLiftFreeze: false,
        freezeUntil: status.freezeUntil,
      };
    }

    // credentialId 匹配且有 webauthnSignature：允许，且成功后可解除冻结
    return {
      blocked: false,
      reason: '',
      canLiftFreeze: true,
      freezeUntil: status.freezeUntil,
    };
  }
}
