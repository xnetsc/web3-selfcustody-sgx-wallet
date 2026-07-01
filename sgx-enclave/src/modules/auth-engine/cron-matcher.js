/**
 * Cron 时间窗口匹配器
 * 支持 5 字段标准 cron 语法：分 时 日 月 星期
 * 特殊规则：* * * * * 表示立即执行，不区分时间段
 */

/**
 * 匹配单个 cron 字段
 * 支持：*、具体值、范围（1-5）、列表（1,3,5）、范围+列表混合（1-3,7,9-11）
 *
 * @param {string} field - cron 字段表达式
 * @param {number} value - 当前时间对应的值
 * @returns {boolean}
 */
function matchField(field, value) {
  if (field === '*') {
    return true;
  }

  // 支持列表（逗号分隔），每个元素可能是范围或具体值
  const parts = field.split(',');
  for (const part of parts) {
    if (part.includes('-')) {
      // 范围匹配
      const [start, end] = part.split('-').map(Number);
      if (value >= start && value <= end) {
        return true;
      }
    } else {
      // 具体值匹配
      if (Number(part) === value) {
        return true;
      }
    }
  }

  return false;
}

/**
 * 检查当前时间是否匹配 cron 表达式
 * 特殊规则：* * * * * 表示立即执行，不区分时间段
 *
 * @param {string} cronExpr - 5 字段 cron 表达式（分 时 日 月 星期）
 * @param {Date} now - 当前时间
 * @returns {boolean}
 */
export function matchCron(cronExpr, now) {
  if (!cronExpr || typeof cronExpr !== 'string') {
    return false;
  }

  const trimmed = cronExpr.trim();

  // 全星号特殊处理：立即执行，任何时间都匹配
  if (trimmed === '* * * * *') {
    return true;
  }

  const fields = trimmed.split(/\s+/);
  if (fields.length !== 5) {
    return false; // 不合法的 cron 表达式
  }

  const [minute, hour, dayOfMonth, month, dayOfWeek] = fields;

  return (
    matchField(minute, now.getUTCMinutes()) &&
    matchField(hour, now.getUTCHours()) &&
    matchField(dayOfMonth, now.getUTCDate()) &&
    matchField(month, now.getUTCMonth() + 1) &&
    matchField(dayOfWeek, now.getUTCDay())
  );
}
