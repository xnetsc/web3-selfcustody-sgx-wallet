/**
 * 单调时钟工具
 *
 * 以 process.hrtime.bigint() 为基础维持单调递增时间，
 * 防止系统时钟因 NTP 校准、手动调整、DST 切换等原因导致时间跳跃或倒退。
 *
 * 做法：
 *   启动时各记录一次 Date.now() 和 process.hrtime.bigint()，生命周期内永不再变。
 *   后续每次调用，以当前 hrtime 减去起始 hrtime 得到经过纳秒，
 *   换算为毫秒后加到起始 Date.now() 上，得到单调递增的毫秒时间戳。
 *
 * 该时间戳在进程启动时与系统墙钟对齐，之后严格单调递增，
 * 适合注入到 HLC / SyncEngine 中作为时间源。
 */

const _startDateNowMs = Date.now();
const _startHrtimeBigInt = process.hrtime.bigint();

/**
 * 返回单调递增的当前时间（毫秒，与 Date.now() 起始值对齐）。
 * @returns {{ value: number, unit: 'ms' }}
 */
export function getMonotonicNow() {
    const elapsedNs = process.hrtime.bigint() - _startHrtimeBigInt;
    const elapsedMs = Number(elapsedNs+BigInt(50)) / 1_000_000;//当前函数本身也可能消耗30～80ns，补齐这个消耗
    return { value: _startDateNowMs + elapsedMs, unit: 'ms' };
}
