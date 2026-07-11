/**
 * 单调时钟工具
 *
 * 以 process.hrtime.bigint() 为基础维持单调递增时间，
 * 防止系统时钟因 NTP 校准、手动调整、DST 切换等原因导致时间跳跃或倒退。
 *
 * 做法：
 *   启动时各记录一次 Date.now() 和 process.hrtime.bigint()，生命周期内永不再变。
 *   后续每次调用，以当前 hrtime 减去起始 hrtime 得到经过纳秒，
 *   换算为毫秒后加到起始锚点上，得到单调递增的毫秒时间戳。
 *
 * 锚点校准：
 *   启动锚点初始为 Date.now()（宿主机墙钟）。
 *   如果合约配置了 NTP 时间源，调用 calibrateFromNtp() 用 NTP 返回的绝对时间校正锚点，
 *   使所有节点的时间基准一致。校正后仍用 hrtime 单调递增，不受后续系统时钟变化影响。
 *   合约 NTP 配置更新时再次调用 calibrateFromNtp() 重新校正。
 *
 * 该时间戳在进程启动时与系统墙钟对齐，之后严格单调递增，
 * 适合注入到 HLC / SyncEngine 中作为时间源。
 *
 * 本模块是项目中唯一的时间源，所有需要时间的接口都应使用本模块导出的函数，
 * 禁止在其他地方直接使用 Date.now() 或 new Date()。
 */

import dgram from 'node:dgram';

let _anchorMs = Date.now();
const _startHrtimeBigInt = process.hrtime.bigint();
let _lastNtpServers = null;

function _monotonicMs() {
    const elapsedNs = process.hrtime.bigint() - _startHrtimeBigInt;
    const elapsedMs = Number(elapsedNs + BigInt(50)) / 1_000_000;
    return _anchorMs + elapsedMs;
}

/**
 * 向单个 NTP 服务器发送查询，返回该服务器报告的绝对时间戳（毫秒）。
 * 超时或出错时返回 null。
 * @param {string} host - NTP 服务器主机名
 * @param {number} [port=123] - NTP 端口
 * @param {number} [timeoutMs=5000] - 超时毫秒
 * @returns {Promise<number|null>}
 */
function _queryNtpServer(host, port = 123, timeoutMs = 5000) {
    return new Promise((resolve) => {
        const socket = dgram.createSocket('udp4');
        const ntpData = Buffer.alloc(48);
        ntpData[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)

        let settled = false;
        const timer = setTimeout(() => {
            if (!settled) {
                settled = true;
                socket.close();
                resolve(null);
            }
        }, timeoutMs);

        socket.on('error', () => {
            if (!settled) {
                settled = true;
                clearTimeout(timer);
                socket.close();
                resolve(null);
            }
        });

        socket.on('message', (msg) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            socket.close();

            // NTP 时间戳从 1900-01-01 起算，秒数在第 40-43 字节（大端），小数在第 44-47 字节
            const secondsSince1900 = msg.readUInt32BE(40);
            const fraction = msg.readUInt32BE(44);
            const msSince1900 = secondsSince1900 * 1000 + Math.floor(fraction / 4294967296 * 1000);
            // Unix 纪元与 NTP 纪元相差 2208988800 秒
            const unixMs = msSince1900 - 2208988800000;
            resolve(unixMs);
        });

        socket.send(ntpData, port, host, (err) => {
            if (err) {
                if (!settled) {
                    settled = true;
                    clearTimeout(timer);
                    socket.close();
                    resolve(null);
                }
            }
        });
    });
}

/**
 * 从多个 NTP 服务器获取时间，取中位数作为可信时间。
 * @param {string[]} servers - NTP 服务器主机名列表
 * @returns {Promise<number|null>} 可信时间戳（毫秒），或 null（全部失败）
 */
async function _getMedianNtpTime(servers) {
    const results = await Promise.all(
        servers.map((s) => _queryNtpServer(s.trim()).catch(() => null))
    );
    const valid = results.filter((r) => r !== null);
    if (valid.length === 0) return null;

    valid.sort((a, b) => a - b);
    const mid = Math.floor(valid.length / 2);
    // 偶数个取中间两个的平均值，奇数个取中位数
    if (valid.length % 2 === 0) {
        return Math.floor((valid[mid - 1] + valid[mid]) / 2);
    }
    return valid[mid];
}

/**
 * 用 NTP 时间源校正单调时钟的起始锚点。
 *
 * 计算当前 hrtime 偏移对应的本地时间，与 NTP 可信时间比较，得到偏差，
 * 然后将锚点调整为 NTP 可信时间。校正后后续所有 _monotonicMs() 调用
 * 都基于新锚点，保证跨节点时间一致。
 *
 * 如果所有 NTP 服务器都不可达，保持当前锚点不变并输出警告。
 *
 * @param {string[]} ntpServers - NTP 服务器主机名列表
 * @returns {Promise<boolean>} 是否成功校正
 */
export async function calibrateFromNtp(ntpServers) {
    if (!Array.isArray(ntpServers) || ntpServers.length === 0) {
        return false;
    }

    const trustedMs = await _getMedianNtpTime(ntpServers);
    if (trustedMs === null) {
        console.warn(`[MonotonicClock] NTP calibration failed: all servers unreachable (${ntpServers.join(', ')})`);
        return false;
    }

    // 计算当前 hrtime 偏移
    const elapsedNs = process.hrtime.bigint() - _startHrtimeBigInt;
    const elapsedMs = Number(elapsedNs + BigInt(50)) / 1_000_000;

    // 新锚点 = NTP时间 - 已经过的 hrtime 偏移
    // 这样 _monotonicMs() = 新锚点 + 当前hrtime偏移 = NTP时间 + (当前hrtime偏移 - 校正时hrtime偏移)
    // 校正瞬间结果 = NTP时间，之后单调递增
    const oldAnchor = _anchorMs;
    _anchorMs = trustedMs - elapsedMs;
    _lastNtpServers = [...ntpServers];

    const driftMs = _anchorMs - oldAnchor;
    console.log(`[MonotonicClock] NTP calibration: anchor adjusted by ${driftMs >= 0 ? '+' : ''}${driftMs}ms (old=${oldAnchor}, new=${_anchorMs}, ntp=${trustedMs}, servers=${ntpServers.join(', ')})`);
    return true;
}

/**
 * 返回上次 NTP 校正使用的服务器列表（用于检测配置变更）。
 * @returns {string[]|null}
 */
export function getLastNtpServers() {
    return _lastNtpServers;
}

/**
 * 返回单调递增的当前时间（毫秒，与锚点对齐）。
 * 用于 HLC / SyncEngine 时间源。
 * @returns {{ value: number, unit: 'ms' }}
 */
export function getMonotonicNow() {
    return { value: _monotonicMs(), unit: 'ms' };
}

/**
 * 返回单调递增的毫秒时间戳。等价于 Date.now()，但不受系统时钟篡改影响。
 * @returns {number}
 */
export function getMonotonicMs() {
    return _monotonicMs();
}

/**
 * 返回基于单调时钟的 Date 对象。等价于 new Date()，但不受系统时钟篡改影响。
 * @returns {Date}
 */
export function getMonotonicDate() {
    return new Date(_monotonicMs());
}

/**
 * 返回 SQLite datetime 格式的单调时间字符串 'YYYY-MM-DD HH:MM:SS'（UTC）。
 * 等价于 SQLite datetime('now')，但不受系统时钟篡改影响。
 * @returns {string}
 */
export function getMonotonicSqliteNow() {
    return getMonotonicDate().toISOString().slice(0, 19).replace('T', ' ');
}

/**
 * 返回基于单调时钟加上指定秒数后的 SQLite datetime 格式字符串。
 * 等价于 SQLite datetime('now', '+N seconds')，但不受系统时钟篡改影响。
 * @param {number} seconds - 要增加的秒数
 * @returns {string}
 */
export function getMonotonicSqliteAfter(seconds) {
    const ms = _monotonicMs() + seconds * 1000;
    return new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
}
