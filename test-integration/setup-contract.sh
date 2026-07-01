#!/bin/bash
# 编译、部署 WalletTrustContract 并初始化
#
# 功能：
#   1. 启动本地 Hardhat 节点（后台运行）
#   2. 编译合约
#   3. 部署合约到本地节点
#   4. 初始化合约（设置 runtimeParams、平台白名单）
#   5. 将合约地址写入 .env.contract（供测试脚本读取）
#
# 用法：
#   ./setup-contract.sh <PLATFORM_ADDRESS>
#   ./setup-contract.sh <PLATFORM_ADDRESS> --keep-node   # 保留 Hardhat 节点（测试结束后手动停止）
#
# 输出环境变量文件：
#   test-integration/.env.contract
#     CONTRACT_ADDRESS=0x...
#     CONTRACT_RPC_URL=http://127.0.0.1:8545
#     CONTRACT_CHAIN_ID=31337
#
# 依赖：
#   - Node.js + npm
#   - contracts/ 目录下已有 package.json（含 hardhat）
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACTS_DIR="$PROJECT_ROOT/contracts"
ENV_CONTRACT_FILE="$SCRIPT_DIR/.env.contract"
HARDHAT_PID_FILE="$SCRIPT_DIR/.hardhat.pid"

PLATFORM_ADDRESS="$1"
KEEP_NODE=false
if [ "$2" = "--keep-node" ]; then
    KEEP_NODE=true
fi

if [ -z "$PLATFORM_ADDRESS" ]; then
    echo "[setup-contract] 错误: 必须提供 PLATFORM_ADDRESS 参数"
    echo "用法: $0 <PLATFORM_ADDRESS> [--keep-node]"
    exit 1
fi

echo "[setup-contract] PLATFORM_ADDRESS=$PLATFORM_ADDRESS"
echo "[setup-contract] KEEP_NODE=$KEEP_NODE"

# ============================================================
# 1. 安装合约依赖（如果 node_modules 不存在）
# ============================================================
if [ ! -d "$CONTRACTS_DIR/node_modules" ]; then
    echo "[setup-contract] 安装合约依赖..."
    cd "$CONTRACTS_DIR" && npm install --silent
    cd "$SCRIPT_DIR"
fi

# ============================================================
# 2. 处理 Node.js 版本兼容性（Node.js 18 + ESM + Hardhat）
# ============================================================
# Node.js 18 上，Hardhat 无法用 require() 加载 ESM 的 hardhat.config.js
# 解决方案：如果 hardhat.config.cjs 不存在，临时创建一个 CJS 版本
NODE_MAJOR=$(node --version | sed 's/v//' | cut -d. -f1)
HARDHAT_CONFIG_CJS="$CONTRACTS_DIR/hardhat.config.cjs"
CREATED_CJS=false

if [ "$NODE_MAJOR" -lt 20 ] && [ ! -f "$HARDHAT_CONFIG_CJS" ]; then
    echo "[setup-contract] Node.js v${NODE_MAJOR} 检测到，创建 hardhat.config.cjs 兼容文件..."
    # 将 ESM import 转换为 CJS require
    cat > "$HARDHAT_CONFIG_CJS" << 'CJS_EOF'
require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      chainId: 31337,
    },
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 31337,
    }
  }
};
CJS_EOF
    CREATED_CJS=true
    echo "[setup-contract] hardhat.config.cjs 已创建"
fi

# 设置 Hardhat 配置文件参数
if [ -f "$HARDHAT_CONFIG_CJS" ]; then
    HARDHAT_CONFIG_ARG="--config $HARDHAT_CONFIG_CJS"
else
    HARDHAT_CONFIG_ARG=""
fi

# ============================================================
# 3. 编译合约
# ============================================================
echo "[setup-contract] 编译合约..."
cd "$CONTRACTS_DIR"
npx hardhat $HARDHAT_CONFIG_ARG compile --quiet
echo "[setup-contract] 合约编译完成"

# ============================================================
# 4. 停止已有的 Hardhat 节点（如果存在）
# ============================================================
if [ -f "$HARDHAT_PID_FILE" ]; then
    OLD_PID=$(cat "$HARDHAT_PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "[setup-contract] 停止已有 Hardhat 节点 (PID=$OLD_PID)..."
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
    fi
    rm -f "$HARDHAT_PID_FILE"
fi

# 检查 8545 端口是否被占用
if lsof -i :8545 -t >/dev/null 2>&1; then
    echo "[setup-contract] 警告: 端口 8545 已被占用，尝试终止..."
    lsof -i :8545 -t | xargs kill -9 2>/dev/null || true
    sleep 1
fi

# ============================================================
# 5. 启动本地 Hardhat 节点（后台）
# ============================================================
echo "[setup-contract] 启动本地 Hardhat 节点..."
cd "$CONTRACTS_DIR"
# 监听所有接口（0.0.0.0），允许 Docker 容器通过宿主机 IP 访问
npx hardhat $HARDHAT_CONFIG_ARG node --port 8545 --hostname 0.0.0.0 > /tmp/hardhat-node.log 2>&1 &
HARDHAT_PID=$!
echo "$HARDHAT_PID" > "$HARDHAT_PID_FILE"
echo "[setup-contract] Hardhat 节点已启动 (PID=$HARDHAT_PID)"

# 等待节点就绪（最多 30 秒）
echo "[setup-contract] 等待 Hardhat 节点就绪..."
for i in $(seq 1 30); do
    if curl -s -X POST http://127.0.0.1:8545 \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        | grep -q '"result"'; then
        echo "[setup-contract] Hardhat 节点已就绪 (${i}s)"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "[setup-contract] 错误: Hardhat 节点启动超时"
        cat /tmp/hardhat-node.log
        exit 1
    fi
    sleep 1
done

# ============================================================
# 6. 部署合约
# ============================================================
echo "[setup-contract] 部署 WalletTrustContract..."
cd "$CONTRACTS_DIR"
DEPLOY_OUTPUT=$(npx hardhat $HARDHAT_CONFIG_ARG run scripts/deploy.js --network localhost 2>&1)
echo "$DEPLOY_OUTPUT"

# 从输出中提取合约地址
CONTRACT_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep "WalletTrustContract deployed to:" | awk '{print $NF}')
if [ -z "$CONTRACT_ADDRESS" ]; then
    echo "[setup-contract] 错误: 无法从部署输出中提取合约地址"
    echo "部署输出: $DEPLOY_OUTPUT"
    # 清理临时文件
    [ "$CREATED_CJS" = true ] && rm -f "$HARDHAT_CONFIG_CJS"
    exit 1
fi
echo "[setup-contract] 合约地址: $CONTRACT_ADDRESS"

# ============================================================
# 7. 初始化合约（设置 runtimeParams + 平台白名单）
# ============================================================
echo "[setup-contract] 初始化合约（测试模式：短缓存刷新间隔）..."
cd "$CONTRACTS_DIR"
# 使用测试专用的初始化脚本（短缓存刷新间隔，便于测试合约白名单覆盖效果）
# 使用独立的 Node.js 脚本（不通过 npx hardhat run），避免 Hardhat ethers 插件的 resolveName bug
# 直接使用 ethers.js 连接到 Hardhat 节点
INIT_SCRIPT="$CONTRACTS_DIR/_init-contract-test-tmp.mjs"
cat > "$INIT_SCRIPT" << 'INIT_EOF'
import { ethers } from 'ethers';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const contractAddress = process.env.CONTRACT_ADDRESS;
const OWNER_PRIVKEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

const provider = new ethers.JsonRpcProvider('http://127.0.0.1:8545');
const ownerWallet = new ethers.Wallet(OWNER_PRIVKEY, provider);
console.log("Owner account:", ownerWallet.address);

// 从 artifacts 加载 ABI
const artifact = JSON.parse(readFileSync(join(__dirname, 'artifacts/contracts/WalletTrustContract.sol/WalletTrustContract.json'), 'utf8'));
const contract = new ethers.Contract(contractAddress, artifact.abi, ownerWallet);

// 手动管理 nonce，避免 ethers.js nonce 缓存问题
let nonce = await provider.getTransactionCount(ownerWallet.address, 'latest');
const nextNonce = () => nonce++;

// 测试模式：cache.refreshInterval=5000（5秒），便于测试合约白名单覆盖效果
const runtimeParams = JSON.stringify({
    session: { importTtlSeconds: 300, exportTtlSeconds: 86400 },
    cache: { refreshInterval: 5000 },
});
const tx1 = await contract.updateRuntimeParams(runtimeParams, { nonce: nextNonce() });
await tx1.wait();
console.log("runtimeParams set (test mode: refreshInterval=5s)");

const tx2 = await contract.addPlatformAddress(ownerWallet.address, { nonce: nextNonce() });
await tx2.wait();
console.log("Platform address added:", ownerWallet.address);

const params = await contract.getRuntimeParams();
const parsed = JSON.parse(params);
console.log("Verified runtimeParams: session=" + (parsed.session ? "OK" : "FAILED") + ", cache.refreshInterval=" + parsed.cache.refreshInterval);

const whitelist = await contract.getPlatformWhitelist();
console.log("Verified platform whitelist:", whitelist.length, "entries");
INIT_EOF

# 使用 node 直接运行（不通过 npx hardhat run）
CONTRACT_ADDRESS="$CONTRACT_ADDRESS" node "$INIT_SCRIPT"
rm -f "$INIT_SCRIPT"

# 额外：将测试用的 PLATFORM_ADDRESS 加入白名单
# init-contract.js 已将 owner 地址加入白名单，这里再加入测试平台地址
# 使用临时 Hardhat 脚本（通过 npx hardhat run 执行，确保 hardhat 环境正确加载）
# 使用独立的 Node.js 脚本（不通过 npx hardhat run），避免 Hardhat ethers 插件的 resolveName bug
TEMP_SCRIPT="$CONTRACTS_DIR/_add-platform-tmp.mjs"
cat > "$TEMP_SCRIPT" << 'SCRIPT_EOF'
import { ethers } from 'ethers';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const contractAddress = process.env.CONTRACT_ADDRESS;
const platformAddress = process.env.PLATFORM_ADDRESS;
const OWNER_PRIVKEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

const provider = new ethers.JsonRpcProvider('http://127.0.0.1:8545');
const ownerWallet = new ethers.Wallet(OWNER_PRIVKEY, provider);

const artifact = JSON.parse(readFileSync(join(__dirname, 'artifacts/contracts/WalletTrustContract.sol/WalletTrustContract.json'), 'utf8'));
const contract = new ethers.Contract(contractAddress, artifact.abi, ownerWallet);

const isWhitelisted = await contract.isPlatformWhitelisted(platformAddress);
if (!isWhitelisted) {
    const nonce = await provider.getTransactionCount(ownerWallet.address, 'latest');
    const tx = await contract.addPlatformAddress(platformAddress, { nonce });
    await tx.wait();
    console.log('[setup-contract] 测试平台地址已加入白名单:', platformAddress);
} else {
    console.log('[setup-contract] 测试平台地址已在白名单:', platformAddress);
}
SCRIPT_EOF

CONTRACT_ADDRESS="$CONTRACT_ADDRESS" PLATFORM_ADDRESS="$PLATFORM_ADDRESS" \
    node "$TEMP_SCRIPT"
rm -f "$TEMP_SCRIPT"

# 清理临时 CJS 配置文件
if [ "$CREATED_CJS" = true ]; then
    rm -f "$HARDHAT_CONFIG_CJS"
    echo "[setup-contract] 临时 hardhat.config.cjs 已清理"
fi

# ============================================================
# 7. 写入环境变量文件
# ============================================================
cat > "$ENV_CONTRACT_FILE" << EOF
CONTRACT_ADDRESS=$CONTRACT_ADDRESS
CONTRACT_RPC_URL=http://127.0.0.1:8545
CONTRACT_CHAIN_ID=31337
HARDHAT_PID=$HARDHAT_PID
EOF

echo "[setup-contract] 环境变量已写入: $ENV_CONTRACT_FILE"
echo "[setup-contract] CONTRACT_ADDRESS=$CONTRACT_ADDRESS"
echo "[setup-contract] CONTRACT_RPC_URL=http://127.0.0.1:8545"
echo "[setup-contract] CONTRACT_CHAIN_ID=31337"

if [ "$KEEP_NODE" = false ]; then
    echo "[setup-contract] 提示: Hardhat 节点将在测试结束后由调用方停止"
    echo "[setup-contract] 停止命令: kill $HARDHAT_PID"
fi

echo "[setup-contract] 完成"
