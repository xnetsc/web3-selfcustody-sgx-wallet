// 模拟器桩补丁（仅测试构建使用，生产源码不含桩）：
// 把 gramine-launcher.js 的 gramineProduceQuote 替换为直接返回 null 的桩，
// 使无 SGX 证明设备的 direct/sim 镜像能生成无 quote 的普通自签证书并启动。
// 生产源码中的 gramineProduceQuote 在证明设备不可用时直接抛错退出，
// 不含任何环境检测与降级逻辑；本脚本只在镜像构建期（Dockerfile 的
// SGX_MODE=direct）经构建挂载临时执行，不落入镜像。本地无 Docker 验证时也可
// 对工作区文件执行同一脚本（验证结束后以 git checkout 还原）。
// 用法: node sim-stub.cjs <path-to-gramine-launcher.js>
const fs = require('node:fs');

const file = process.argv[2];
if (!file) {
    console.error('usage: node sim-stub.cjs <gramine-launcher.js>');
    process.exit(2);
}
const src = fs.readFileSync(file, 'utf8');
if (src.includes('[SIM STUB]')) {
    console.log('[sim-stub] already patched, skipping');
    process.exit(0);
}
const anchor = 'async function gramineProduceQuote(reportDataBytes) {';
const start = src.indexOf(anchor);
if (start < 0) {
    console.error('[sim-stub] anchor not found — production launcher shape changed, refusing to patch');
    process.exit(1);
}
const end = src.indexOf('\n}\n', start);
if (end < 0) {
    console.error('[sim-stub] function end not found');
    process.exit(1);
}
const stub = `async function gramineProduceQuote(reportDataBytes) {
    // [SIM STUB] 模拟器/测试镜像专用（构建期打桩，生产源码无此逻辑）：
    // 无 SGX 证明设备，直接返回 null，生成无 quote 的普通自签证书。
    return null;
}`;
fs.writeFileSync(file, src.slice(0, start) + stub + src.slice(end + 2));
console.log('[sim-stub] launcher patched: gramineProduceQuote -> null stub');
