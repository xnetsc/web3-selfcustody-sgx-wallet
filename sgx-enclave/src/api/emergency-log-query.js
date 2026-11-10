/**
 * 应急授权执行日志查询 API（公开接口，无需任何鉴权）
 *
 * 只读 SGX 本地 emergency_execution_logs 表：任何人可查，与授权撤销的
 * 公开查询同一姿态。返回值经 server 的 wrap 生成 attestationQuote，
 * 且每条日志带 prev_hash/entry_hash 哈希链与 auth_hash（授权 JSON 原文
 * 的 SHA256）：读者可独立核验——重算哈希链检出改删插、用手中的授权
 * JSON 重算 auth_hash 与链上合约记录互证、验 quote 确认出自 enclave。
 *
 * 过滤与分页：
 *   - 过滤字段（全部等值精确匹配）：authorizationId、userId（目标用户）、
 *     operatorUserId、operation（必须是已知操作名）、platformAddress、
 *     result、logId（整数）、fromCreatedAt / toCreatedAt（ISO 时间范围）
 *   - 分页：page 从 1 开始（默认 1），pageSize 默认 10、范围 1–100，
 *     超出范围直接报错；order 为 asc（默认）或 desc（按 logId）
 *   - SQL 安全：StateManager 只用固定列名片段拼 WHERE，所有过滤值一律
 *     参数绑定；排序方向只取代码内白名单字面量。注入字符串只会被当作
 *     普通过滤值（匹配不到任何行），不会改变查询语义。
 *
 * 请求体（直传字段，或放在 payload 中均可）。
 */

import { EMERGENCY_OPERATIONS } from '../modules/emergency-auth/emergency-authorization-parser.js';

export class EmergencyLogQueryHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/state-management/state-manager.js').StateManager} deps.stateManager
   */
  constructor(deps) {
    if (!deps.stateManager) throw new Error('EmergencyLogQueryHandler requires stateManager');
    this._state = deps.stateManager;
  }

  /**
   * 查询执行日志（分页 + 过滤）
   * @param {Object} request - HTTP body（无需 platformSignature）
   * @returns {Promise<Object>} { logs, count, totalPages, page, pageSize, latestEntryHash }
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

    // 分页参数：必须是整数且在范围内（与撤销查询同一纪律：越界报错不静默修正）
    const page = query.page === undefined ? 1 : query.page;
    if (!Number.isInteger(page) || page < 1) {
      throw new Error('page must be a positive integer');
    }
    const pageSize = query.pageSize === undefined ? 10 : query.pageSize;
    if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 100) {
      throw new Error('pageSize must be an integer between 1 and 100');
    }
    const order = query.order === undefined ? 'asc' : query.order;
    if (order !== 'asc' && order !== 'desc') {
      throw new Error("order must be 'asc' or 'desc'");
    }

    // 过滤参数校验（值本身一律由 StateManager 参数绑定，这里只做形状校验）
    if (query.operation !== undefined && !EMERGENCY_OPERATIONS.includes(query.operation)) {
      throw new Error(`unknown operation filter: ${query.operation}`);
    }
    if (query.logId !== undefined && (!Number.isInteger(query.logId) || query.logId < 1)) {
      throw new Error('logId must be a positive integer');
    }
    for (const timeField of ['fromCreatedAt', 'toCreatedAt']) {
      if (query[timeField] !== undefined && Number.isNaN(Date.parse(query[timeField]))) {
        throw new Error(`${timeField} must be a valid ISO date string`);
      }
    }

    const filter = {
      authorizationId: query.authorizationId,
      targetUserId: query.targetUserId !== undefined ? query.targetUserId : query.userId,
      operatorUserId: query.operatorUserId,
      operation: query.operation,
      platformAddress: query.platformAddress,
      result: query.result,
      logId: query.logId,
      fromCreatedAt: query.fromCreatedAt,
      toCreatedAt: query.toCreatedAt,
    };

    const resultPage = await this._state.listExecutionLogs(filter, page, pageSize, order);

    // 全表最新一条的 entry_hash（链头）：读者据此确认自己看到的链是否完整到最新
    const head = await this._state.listExecutionLogs({}, 1, 1, 'desc');

    console.log(`[EmergencyLogQuery] handleQuery: count=${resultPage.count}, page=${page}, pageSize=${pageSize}, returned=${resultPage.logs.length}`);

    return {
      logs: resultPage.logs,
      count: resultPage.count,
      totalPages: resultPage.totalPages,
      page: resultPage.page,
      pageSize: resultPage.pageSize,
      latestEntryHash: head.logs[0]?.entryHash || null,
      latestLogId: head.logs[0]?.logId || 0,
    };
  }
}
