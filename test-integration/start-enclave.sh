#!/bin/bash
# 启动 sgx-enclave 容器
# 如果容器已在运行则跳过
# 用法: start-enclave.sh <PLATFORM_ADDRESS>
#
# SGX_MODE 环境变量控制运行模式:
#   "sgx"           → 真实 SGX 硬件模式 (gramine-sgx, RA-TLS, 需要 SGX 设备)
#   "direct" / "sim" → 模拟模式 (gramine-direct, 自签名证书, 无需 SGX 硬件)
#   未设置           → 自动检测: 有 /dev/sgx_enclave 则 sgx, 否则 direct
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DOCKER_NETWORK="${DOCKER_NETWORK:-test-sgx-net}"
ENCLAVE_CONTAINER="${ENCLAVE_CONTAINER:-test-sgx-enclave}"
ENCLAVE_HTTP_PORT="${ENCLAVE_HTTP_PORT:-3000}"
SYNC_LISTEN_PORT="${SYNC_LISTEN_PORT:-3307}"

# SGX_MODE: 自动检测 — 有 SGX 设备则 sgx, 否则 direct
if [ -z "$SGX_MODE" ]; then
    if [ -e /dev/sgx_enclave ]; then
        SGX_MODE="sgx"
    else
        SGX_MODE="direct"
    fi
    echo "[start-enclave] SGX_MODE 未设置, 自动检测: $SGX_MODE"
fi

PLATFORM_ADDRESS="$1"
if [ -z "$PLATFORM_ADDRESS" ]; then
    echo "[start-enclave] 错误: 必须提供 PLATFORM_ADDRESS 参数"
    echo "用法: $0 <PLATFORM_ADDRESS>"
    exit 1
fi

# 检查容器是否已在运行
if docker ps --format '{{.Names}}' | grep -q "^${ENCLAVE_CONTAINER}$"; then
    echo "[start-enclave] 容器 $ENCLAVE_CONTAINER 已在运行，跳过"
    exit 0
fi

# 如果容器存在但未运行，删除后重建
if docker ps -a --format '{{.Names}}' | grep -q "^${ENCLAVE_CONTAINER}$"; then
    echo "[start-enclave] 删除已停止的容器 $ENCLAVE_CONTAINER ..."
    docker rm -f "$ENCLAVE_CONTAINER" >/dev/null 2>&1
fi

# 确保 Docker 网络存在
if ! docker network inspect "$DOCKER_NETWORK" >/dev/null 2>&1; then
    echo "[start-enclave] 创建 Docker 网络 $DOCKER_NETWORK ..."
    docker network create "$DOCKER_NETWORK"
fi

# --- 生成 bash wrapper 脚本（仅做 direct 模式 cert CN 修复，不再 patch .env）---
# 所有 enclave 配置改为通过 docker create -e ...（受 manifest passthrough 白名单约束）注入；
# PLATFORM_WHITELIST 等改由合约 setup-contract.sh 注入合约。
WRAPPER_PATH="$SCRIPT_DIR/.test-wrapper.sh"
cat > "$WRAPPER_PATH" << 'WRAPPER_EOF'
#!/bin/bash
set -e
if [ "$SGX_MODE" = "direct" ] || [ "$SGX_MODE" = "sim" ]; then
    sed -i 's/CN=direct-mode-fallback/CN=SGX-Wallet-Client/' /usr/local/bin/gramine-entrypoint.sh
fi
exec /usr/local/bin/gramine-entrypoint.sh
WRAPPER_EOF
chmod +x "$WRAPPER_PATH"

# Step 1: docker create (mode-dependent flags)
echo "[start-enclave] 创建并启动 $ENCLAVE_CONTAINER (SGX_MODE=$SGX_MODE, PLATFORM_ADDRESS=$PLATFORM_ADDRESS) ..."

# 通用 env 透传 — 受 sgx-enclave/node.manifest.template 中
# loader.env.X.passthrough = true 的白名单过滤后才会到达 enclave 内的 Node.js 进程。
COMMON_ENVS=(
    -e "SGX_MODE=$SGX_MODE"
    -e "CONTRACT_RPC_URL=${CONTRACT_RPC_URL:-}"
    -e "CONTRACT_CHAIN_ID=${CONTRACT_CHAIN_ID:-}"
    -e "CONTRACT_ADDRESS=${CONTRACT_ADDRESS:-}"
    -e "SYNC_NODES=${SYNC_NODES:-}"
    -e "SGX_HTTP_PORT=${SGX_HTTP_PORT:-3000}"
    -e "SYNC_LISTEN_PORT=${SYNC_LISTEN_PORT_INSIDE:-3307}"
    -e "NODE_ID=${NODE_ID:-}"
)

if [ "$SGX_MODE" = "direct" ] || [ "$SGX_MODE" = "sim" ]; then
    # Direct/simulation mode — no SGX devices needed
    docker create \
        --name "$ENCLAVE_CONTAINER" \
        --network "$DOCKER_NETWORK" \
        "${COMMON_ENVS[@]}" \
        -p "${ENCLAVE_HTTP_PORT}:3000" \
        -p "${SYNC_LISTEN_PORT}:3307" \
        --security-opt seccomp=unconfined \
        --entrypoint /test-wrapper.sh \
        sgx-enclave >/dev/null
else
    # Real SGX mode — mount SGX devices + AESM socket (gramine-sgx needs AESM to load enclave)
    # Note: AESM socket is started inside the container by gramine-entrypoint.sh,
    # so we do NOT mount the host aesm.socket here.
    docker create \
        --name "$ENCLAVE_CONTAINER" \
        --network "$DOCKER_NETWORK" \
        "${COMMON_ENVS[@]}" \
        --device /dev/sgx_enclave \
        --device /dev/sgx_provision \
        -p "${ENCLAVE_HTTP_PORT}:3000" \
        -p "${SYNC_LISTEN_PORT}:3307" \
        --security-opt seccomp=unconfined \
        --entrypoint /test-wrapper.sh \
        sgx-enclave >/dev/null
fi

# Step 2: docker cp wrapper only (no .env patcher)
docker cp "$WRAPPER_PATH" "$ENCLAVE_CONTAINER":/test-wrapper.sh

# Step 3: docker start
docker start "$ENCLAVE_CONTAINER" >/dev/null

echo "[start-enclave] 容器已启动: $ENCLAVE_CONTAINER (SGX_MODE=$SGX_MODE)"
