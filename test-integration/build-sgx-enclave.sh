#!/bin/bash
# 构建 sgx-enclave Docker 镜像
# 如果镜像已存在则跳过（使用 --force 强制重建）
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="sgx-enclave"

# 检查是否需要强制重建
FORCE=false
if [ "$1" = "--force" ]; then
    FORCE=true
fi

# 检查镜像是否已存在
if docker image inspect "$IMAGE_NAME" &>/dev/null; then
    if [ "$FORCE" = false ]; then
        echo "[build-sgx-enclave] 镜像 $IMAGE_NAME 已存在，跳过构建（使用 --force 强制重建）"
        exit 0
    fi
fi

echo "[build-sgx-enclave] 开始构建 $IMAGE_NAME ..."
docker build -f "$PROJECT_ROOT/sgx-enclave/Dockerfile" -t "$IMAGE_NAME" "$PROJECT_ROOT"
echo "[build-sgx-enclave] 构建完成: $IMAGE_NAME"
