#!/usr/bin/env bash
# ============================================================================
# update-runtime-params.sh
# 用于更新合约 runtimeParams 的交互式/自动化脚本
#
# 默认为「更新模式」：先读取合约当前值，将用户提供的字段合并到现有 JSON 上，
# 写入前校验合约值未被他人修改（乐观锁），冲突时报错。
# 加 --overwrite 参数切换为「覆盖模式」：用户提供的 JSON 直接覆盖合约全部内容。
#
# 用法:
#   交互模式（无参数，默认更新模式）:
#     bash update-runtime-params.sh
#
#   交互模式（覆盖模式）:
#     bash update-runtime-params.sh --overwrite
#
#   自动化模式（更新模式，默认）:
#     bash update-runtime-params.sh \
#       --json '{"session":{"importTtlSeconds":300}}' \
#       [--rpc-url URL] [--chain-id ID] [--contract-address ADDR] [--private-key KEY]
#
#   自动化模式（覆盖模式）:
#     bash update-runtime-params.sh --overwrite \
#       --json '{"session":{"importTtlSeconds":300}}' \
#       [--rpc-url URL] [--chain-id ID] [--contract-address ADDR] [--private-key KEY]
#
# 环境变量（可通过 .env 文件提供）:
#   CONTRACT_RPC_URL          — RPC 节点 URL
#   CONTRACT_CHAIN_ID         — 链 ID
#   CONTRACT_ADDRESS          — 合约地址
#   CONTRACT_OWNER_PRIVATE_KEY — Owner 私钥
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENCLAVE_DIR="$PROJECT_ROOT/sgx-enclave"
NODE_WORK_DIR="$SCRIPT_DIR"

# ============ 颜色输出 ============

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ============ 加载 .env ============

load_dotenv() {
  local env_file="$1"
  if [[ -f "$env_file" ]]; then
    info "从 $env_file 加载环境变量..."
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
      line="${line#"${line%%[![:space:]]*}"}"
      local key="${line%%=*}"
      if [[ -z "${!key:-}" ]]; then
        export "$line" 2>/dev/null || true
      fi
    done < "$env_file"
  fi
}

# 尝试加载各处 .env（优先级: 脚本目录 > sgx-enclave > 项目根目录）
load_dotenv "$SCRIPT_DIR/.env"
load_dotenv "$ENCLAVE_DIR/.env"
load_dotenv "$PROJECT_ROOT/.env"

# ============ 解析命令行参数 ============

AUTO_MODE=false
OVERWRITE_MODE=false
JSON_CONTENT=""
CLI_RPC_URL=""
CLI_CHAIN_ID=""
CLI_CONTRACT_ADDRESS=""
CLI_PRIVATE_KEY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)
      AUTO_MODE=true
      JSON_CONTENT="$2"
      shift 2
      ;;
    --overwrite)
      OVERWRITE_MODE=true
      shift
      ;;
    --rpc-url)
      CLI_RPC_URL="$2"
      shift 2
      ;;
    --chain-id)
      CLI_CHAIN_ID="$2"
      shift 2
      ;;
    --contract-address)
      CLI_CONTRACT_ADDRESS="$2"
      shift 2
      ;;
    --private-key)
      CLI_PRIVATE_KEY="$2"
      shift 2
      ;;
    -h|--help)
      echo "用法:"
      echo "  交互模式（更新模式）: bash $0"
      echo "  交互模式（覆盖模式）: bash $0 --overwrite"
      echo "  自动化模式（更新模式）: bash $0 --json '{...}' [options]"
      echo "  自动化模式（覆盖模式）: bash $0 --overwrite --json '{...}' [options]"
      echo ""
      echo "选项:"
      echo "  --json JSON        要写入的 JSON 字符串（启用自动化模式）"
      echo "  --overwrite        覆盖模式（默认为更新模式）"
      echo "  --rpc-url URL      RPC 节点 URL"
      echo "  --chain-id ID      链 ID"
      echo "  --contract-address ADDR  合约地址"
      echo "  --private-key KEY  Owner 私钥"
      echo ""
      echo "模式说明:"
      echo "  更新模式（默认）: 读取合约当前值，合并用户提供的字段后写回。"
      echo "                    写入前校验合约值未被他人修改（乐观锁）。"
      echo "  覆盖模式:         用户提供的 JSON 直接替换合约全部内容。"
      echo ""
      echo "环境变量（可通过 .env 文件提供，脚本目录 > sgx-enclave/.env > 项目根目录/.env）:"
      echo "  CONTRACT_RPC_URL, CONTRACT_CHAIN_ID, CONTRACT_ADDRESS, CONTRACT_OWNER_PRIVATE_KEY"
      exit 0
      ;;
    *)
      err "未知参数: $1"
      exit 1
      ;;
  esac
done

# ============ 确定合约参数 ============

get_param() {
  local cli_val="$1"
  local env_val="$2"
  local prompt_msg="$3"
  local is_secret="${4:-false}"

  if [[ -n "$cli_val" ]]; then
    echo "$cli_val"
    return
  fi

  if [[ -n "$env_val" ]]; then
    echo "$env_val"
    return
  fi

  if $AUTO_MODE; then
    err "自动化模式下缺少必要参数: $prompt_msg"
    exit 1
  fi

  if [[ "$is_secret" == "true" ]]; then
    read -rsp "$prompt_msg: " val
    echo "" >&2
  else
    read -rp "$prompt_msg: " val
  fi

  if [[ -z "$val" ]]; then
    err "参数不能为空"
    exit 1
  fi

  echo "$val"
}

RPC_URL="$(get_param "$CLI_RPC_URL" "${CONTRACT_RPC_URL:-}" "请输入 RPC URL (如 http://127.0.0.1:8545)")"
CHAIN_ID="$(get_param "$CLI_CHAIN_ID" "${CONTRACT_CHAIN_ID:-}" "请输入 Chain ID (如 31337)")"
CONTRACT_ADDR="$(get_param "$CLI_CONTRACT_ADDRESS" "${CONTRACT_ADDRESS:-}" "请输入合约地址")"
PRIVATE_KEY="$(get_param "$CLI_PRIVATE_KEY" "${CONTRACT_OWNER_PRIVATE_KEY:-}" "请输入 Owner 私钥" "true")"

info "RPC URL:        $RPC_URL"
info "Chain ID:       $CHAIN_ID"
info "合约地址:       $CONTRACT_ADDR"
info "私钥:           ${PRIVATE_KEY:0:6}...${PRIVATE_KEY: -4}"
if $OVERWRITE_MODE; then
  info "写入模式:       覆盖模式（完全替换合约内容）"
else
  info "写入模式:       更新模式（合并字段到现有内容）"
fi

# ============ 自动安装 Node.js 依赖 ============

ensure_node_deps() {
  if [[ ! -d "$NODE_WORK_DIR/node_modules/ethers" ]]; then
    info "首次运行，正在安装 ethers 依赖到 $NODE_WORK_DIR ..."
    # 如果没有 package.json 则创建一个
    if [[ ! -f "$NODE_WORK_DIR/package.json" ]]; then
      echo '{"private":true,"type":"module"}' > "$NODE_WORK_DIR/package.json"
    fi
    (cd "$NODE_WORK_DIR" && npm install --save ethers 2>&1) || {
      err "安装 ethers 失败，请检查 npm 是否可用"
      exit 1
    }
    ok "ethers 依赖安装完成"
  fi
}

ensure_node_deps

# ============ Node.js 辅助函数 ============

# 读取合约当前 runtimeParams 值
# 输出: JSON 字符串（合约存储的原始值）
# 如果合约值为空或不是有效 JSON，输出 "{}"
read_contract_value() {
  cd "$NODE_WORK_DIR"
  _SCRIPT_RPC_URL="$RPC_URL" \
  _SCRIPT_CHAIN_ID="$CHAIN_ID" \
  _SCRIPT_PRIVATE_KEY="$PRIVATE_KEY" \
  _SCRIPT_CONTRACT_ADDR="$CONTRACT_ADDR" \
  node --input-type=module <<'NODEJS_READ'
import { ethers } from 'ethers';

const ABI = [
  'function getRuntimeParams() view returns (string)',
  'function owner() view returns (address)',
];

async function main() {
  const rpcUrl = process.env._SCRIPT_RPC_URL;
  const chainId = parseInt(process.env._SCRIPT_CHAIN_ID);
  const privateKey = process.env._SCRIPT_PRIVATE_KEY;
  const contractAddr = process.env._SCRIPT_CONTRACT_ADDR;

  const provider = new ethers.JsonRpcProvider(rpcUrl, chainId);
  const wallet = new ethers.Wallet(privateKey, provider);
  const contract = new ethers.Contract(contractAddr, ABI, wallet);

  // 验证 owner 身份
  const owner = await contract.owner();
  if (owner.toLowerCase() !== wallet.address.toLowerCase()) {
    console.error('__ERROR__NOT_OWNER__' + wallet.address + '__' + owner);
    process.exit(1);
  }

  const stored = await contract.getRuntimeParams();
  if (!stored || stored.trim() === '') {
    console.log('{}');
  } else {
    try {
      JSON.parse(stored);
      console.log(stored);
    } catch {
      console.log('{}');
    }
  }
}

main().catch(e => { console.error('__ERROR__' + e.message); process.exit(1); });
NODEJS_READ
}

# 写入合约并回读验证
# 参数: $1 = 要写入的 JSON 字符串
#        $2 = 乐观锁校验值（可选，为空则不校验）
# 返回: 0=成功, 1=失败, 2=冲突（乐观锁失败）
write_contract_value() {
  local json_to_write="$1"
  local expected_current="${2:-}"

  cd "$NODE_WORK_DIR"
  _SCRIPT_RPC_URL="$RPC_URL" \
  _SCRIPT_CHAIN_ID="$CHAIN_ID" \
  _SCRIPT_PRIVATE_KEY="$PRIVATE_KEY" \
  _SCRIPT_CONTRACT_ADDR="$CONTRACT_ADDR" \
  _SCRIPT_JSON_CONTENT="$json_to_write" \
  _SCRIPT_EXPECTED_CURRENT="$expected_current" \
  node --input-type=module <<'NODEJS_WRITE'
import { ethers } from 'ethers';

const ABI = [
  'function updateRuntimeParams(string) external',
  'function getRuntimeParams() view returns (string)',
  'function owner() view returns (address)',
];

async function main() {
  const rpcUrl = process.env._SCRIPT_RPC_URL;
  const chainId = parseInt(process.env._SCRIPT_CHAIN_ID);
  const privateKey = process.env._SCRIPT_PRIVATE_KEY;
  const contractAddr = process.env._SCRIPT_CONTRACT_ADDR;
  const jsonContent = process.env._SCRIPT_JSON_CONTENT;
  const expectedCurrent = process.env._SCRIPT_EXPECTED_CURRENT || '';

  const provider = new ethers.JsonRpcProvider(rpcUrl, chainId);
  const wallet = new ethers.Wallet(privateKey, provider);
  const contract = new ethers.Contract(contractAddr, ABI, wallet);

  // 验证 owner 身份
  const owner = await contract.owner();
  if (owner.toLowerCase() !== wallet.address.toLowerCase()) {
    console.error('[ERROR] 当前私钥地址 ' + wallet.address + ' 不是合约 Owner (' + owner + ')');
    process.exit(1);
  }

  // 乐观锁校验：写入前检查合约当前值是否与预期一致
  if (expectedCurrent) {
    const currentVal = await contract.getRuntimeParams();
    let normalizedCurrent, normalizedExpected;
    try {
      normalizedCurrent = JSON.stringify(JSON.parse(currentVal || '{}'));
    } catch {
      normalizedCurrent = currentVal || '';
    }
    try {
      normalizedExpected = JSON.stringify(JSON.parse(expectedCurrent));
    } catch {
      normalizedExpected = expectedCurrent;
    }

    if (normalizedCurrent !== normalizedExpected) {
      console.error('__CONFLICT__');
      console.error('__CONFLICT_CURRENT__' + currentVal);
      process.exit(2);
    }
  }

  console.log('[INFO] 写入内容: ' + jsonContent);

  const tx = await contract.updateRuntimeParams(jsonContent);
  console.log('[INFO] 交易已发送: ' + tx.hash);
  const receipt = await tx.wait();
  console.log('[OK] 交易已确认，区块: ' + receipt.blockNumber);

  // 回读验证并解析展示
  const stored = await contract.getRuntimeParams();
  console.log('[OK] 合约回读原始值: ' + stored);
  try {
    const parsed = JSON.parse(stored);
    console.log('[OK] 合约当前存储（解析后）:');
    console.log(JSON.stringify(parsed, null, 2));
    console.log('[OK] 字段明细:');
    let idx = 1;
    for (const [k, v] of Object.entries(parsed)) {
      console.log('  ' + idx + '. ' + k + ' = ' + JSON.stringify(v));
      idx++;
    }
  } catch {
    console.log('[WARN] 合约存储内容无法解析为 JSON: ' + stored);
  }
}

main().catch(e => { console.error('[ERROR] ' + e.message); process.exit(1); });
NODEJS_WRITE
  return $?
}

# JSON 合并：将 user_json 的字段合并到 base_json 上（user 覆盖 base 的同名字段）
merge_json() {
  local base_json="$1"
  local user_json="$2"
  node -e "
    const base = JSON.parse(process.argv[1] || '{}');
    const user = JSON.parse(process.argv[2] || '{}');
    const merged = { ...base, ...user };
    console.log(JSON.stringify(merged));
  " "$base_json" "$user_json"
}

# 展示 JSON 内容（解析后逐字段显示）
display_json() {
  local json_str="$1"
  node -e "
    const parsed = JSON.parse(process.argv[1] || '{}');
    console.log(JSON.stringify(parsed, null, 2));
    console.log('');
    console.log('字段明细:');
    let idx = 1;
    for (const [k, v] of Object.entries(parsed)) {
      console.log('  ' + idx + '. ' + k + ' = ' + JSON.stringify(v));
      idx++;
    }
  " "$json_str"
}

# ============ 自动化模式 ============

if $AUTO_MODE; then
  # 验证 JSON 格式
  if ! node -e "JSON.parse(process.argv[1])" "$JSON_CONTENT" 2>/dev/null; then
    err "提供的 JSON 格式无效: $JSON_CONTENT"
    exit 1
  fi

  if $OVERWRITE_MODE; then
    # ---- 自动化 + 覆盖模式: 直接写入，无合并，无乐观锁 ----
    info "自动化覆盖模式：直接写入合约..."
    COMPACT_JSON="$(node -e "console.log(JSON.stringify(JSON.parse(process.argv[1])))" "$JSON_CONTENT")"

    set +e
    write_output="$(write_contract_value "$COMPACT_JSON" "" 2>&1)"
    write_rc=$?
    set -e

    if [[ $write_rc -ne 0 ]]; then
      echo "$write_output"
      err "合约写入失败"
      exit 1
    fi
    echo "$write_output"
    ok "合约更新成功！（覆盖模式）"
  else
    # ---- 自动化 + 更新模式: 读取 -> 合并 -> 乐观锁校验 -> 写入 ----
    info "自动化更新模式：读取合约当前值..."

    set +e
    contract_current="$(read_contract_value 2>&1)"
    read_rc=$?
    set -e

    if [[ $read_rc -ne 0 ]]; then
      if echo "$contract_current" | grep -q '__ERROR__NOT_OWNER__'; then
        err "当前私钥不是合约 Owner"
      fi
      err "读取合约失败"
      echo "$contract_current"
      exit 1
    fi

    info "合约当前值: $contract_current"

    # 合并用户 JSON 到合约当前值
    merged_json="$(merge_json "$contract_current" "$JSON_CONTENT")"
    compact_merged="$(node -e "console.log(JSON.stringify(JSON.parse(process.argv[1])))" "$merged_json")"

    info "合并后的值: $compact_merged"

    # 乐观锁写入
    set +e
    write_output="$(write_contract_value "$compact_merged" "$contract_current" 2>&1)"
    write_rc=$?
    set -e

    if [[ $write_rc -eq 2 ]] || echo "$write_output" | grep -q '__CONFLICT__'; then
      err "乐观锁冲突：合约值已被他人修改！"
      conflict_current="$(echo "$write_output" | grep '__CONFLICT_CURRENT__' | sed 's/.*__CONFLICT_CURRENT__//')"
      if [[ -n "$conflict_current" ]]; then
        err "合约最新值:"
        display_json "$conflict_current" 2>/dev/null || echo "$conflict_current"
      fi
      err "请重新获取最新值后再试"
      exit 1
    elif [[ $write_rc -ne 0 ]]; then
      echo "$write_output"
      err "合约写入失败"
      exit 1
    fi

    echo "$write_output"
    ok "合约更新成功！（更新模式）"
  fi

  exit 0
fi

# ============ 交互模式 ============

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  合约 runtimeParams 更新工具（交互模式）${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

if $OVERWRITE_MODE; then
  echo -e "${YELLOW}当前为覆盖模式：您输入的内容将完全替换合约现有值${NC}"
else
  echo -e "${CYAN}当前为更新模式：您输入的内容将合并到合约现有值上${NC}"

  info "正在读取合约当前值..."
  set +e
  CONTRACT_SNAPSHOT="$(read_contract_value 2>&1)"
  read_rc=$?
  set -e

  if [[ $read_rc -ne 0 ]]; then
    if echo "$CONTRACT_SNAPSHOT" | grep -q '__ERROR__NOT_OWNER__'; then
      err "当前私钥不是合约 Owner"
    fi
    err "读取合约失败"
    echo "$CONTRACT_SNAPSHOT"
    exit 1
  fi
  info "合约当前值: $CONTRACT_SNAPSHOT"
fi

# 使用关联数组存储键值对（需要 bash 4+）
declare -A PARAMS
declare -a PARAM_KEYS_ORDER

# 更新模式下，预填充合约现有字段
if ! $OVERWRITE_MODE && [[ -n "${CONTRACT_SNAPSHOT:-}" && "$CONTRACT_SNAPSHOT" != "{}" ]]; then
  info "预填充合约现有字段..."
  prefill_data="$(node -e "
    const obj = JSON.parse(process.argv[1] || '{}');
    for (const [k, v] of Object.entries(obj)) {
      console.log(k + '\x1f' + JSON.stringify(v));
    }
  " "$CONTRACT_SNAPSHOT")"

  while IFS= read -r prefill_line; do
    [[ -z "$prefill_line" ]] && continue
    pkey="${prefill_line%%$'\x1f'*}"
    pval="${prefill_line#*$'\x1f'}"
    PARAMS["$pkey"]="$pval"
    PARAM_KEYS_ORDER+=("$pkey")
    info "  已加载: $pkey = $pval"
  done <<< "$prefill_data"
fi

add_or_update_key() {
  local key="$1"
  local val="$2"

  local found=false
  for k in "${PARAM_KEYS_ORDER[@]:-}"; do
    if [[ "$k" == "$key" ]]; then
      found=true
      break
    fi
  done
  if ! $found; then
    PARAM_KEYS_ORDER+=("$key")
  fi

  PARAMS["$key"]="$val"
}

remove_key() {
  local key="$1"
  unset 'PARAMS['"$key"']' 2>/dev/null || true

  local new_order=()
  for k in "${PARAM_KEYS_ORDER[@]:-}"; do
    if [[ "$k" != "$key" ]]; then
      new_order+=("$k")
    fi
  done
  PARAM_KEYS_ORDER=("${new_order[@]:-}")
}

parse_field_input() {
  local input="$1"
  input="$(echo "$input" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

  local key=""
  local value=""

  if [[ "$input" =~ ^\"([^\"]*)\": ]]; then
    key="${BASH_REMATCH[1]}"
    local rest="${input#*:}"
    rest="$(echo "$rest" | sed 's/^[[:space:]]*//')"
    if [[ "$rest" =~ ^\"(.*)\"$ ]]; then
      value="${BASH_REMATCH[1]}"
    else
      value="$rest"
    fi
  elif [[ "$input" =~ ^([^:\"]+): ]]; then
    key="${BASH_REMATCH[1]}"
    key="$(echo "$key" | sed 's/[[:space:]]*$//')"
    local rest="${input#*:}"
    rest="$(echo "$rest" | sed 's/^[[:space:]]*//')"
    if [[ "$rest" =~ ^\"(.*)\"$ ]]; then
      value="${BASH_REMATCH[1]}"
    else
      value="$rest"
    fi
  else
    return 1
  fi

  if [[ -z "$key" ]]; then
    return 1
  fi

  printf '%s\x1f%s' "$key" "$value"
  return 0
}

build_json() {
  node -e "
    const keys = process.argv.slice(1);
    const obj = {};
    for (let i = 0; i < keys.length; i += 2) {
      const key = keys[i];
      const val = keys[i+1];
      try {
        obj[key] = JSON.parse(val);
      } catch {
        obj[key] = val;
      }
    }
    console.log(JSON.stringify(obj, null, 2));
  " "${@}"
}

# ---- 输入循环 ----

while true; do
  echo ""
  echo -e "${CYAN}--- 输入字段 ---${NC}"
  echo -e "格式: ${BOLD}字段名:值${NC}  (支持 \"key\":\"value\"、key:value 等格式)"
  echo -e "值可以是字符串、数字、JSON 对象/数组（如 {\"a\":1} 或 [1,2,3]）"
  echo -e "输入 ${BOLD}done${NC} 结束输入进入复核"
  echo ""

  while true; do
    read -rp "> " line

    [[ -z "$line" ]] && continue

    if [[ "$line" == "done" || "$line" == "DONE" ]]; then
      break
    fi

    local_output="$(parse_field_input "$line")" || {
      warn "格式无法识别，请使用 字段名:值 格式（如 session:{\"ttl\":300}）"
      continue
    }

    key="${local_output%%$'\x1f'*}"
    value="${local_output#*$'\x1f'}"

    if [[ -z "$value" ]]; then
      if [[ -n "${PARAMS[$key]:-}" ]]; then
        remove_key "$key"
        info "已删除字段: $key"
      else
        warn "字段 '$key' 不存在，无需删除"
      fi
    else
      add_or_update_key "$key" "$value"
      ok "已设置: $key = $value"
    fi
  done

  # ---- 复核展示 ----

  echo ""
  echo -e "${BOLD}========================================${NC}"
  echo -e "${BOLD}  当前字段列表（复核）${NC}"
  echo -e "${BOLD}========================================${NC}"

  if [[ ${#PARAM_KEYS_ORDER[@]} -eq 0 ]]; then
    warn "当前没有任何字段"
  else
    build_args=()
    for k in "${PARAM_KEYS_ORDER[@]}"; do
      build_args+=("$k" "${PARAMS[$k]}")
    done

    json_preview="$(build_json "${build_args[@]}")"
    echo ""
    echo -e "${GREEN}$json_preview${NC}"
    echo ""

    echo -e "${CYAN}字段明细:${NC}"
    idx=1
    for k in "${PARAM_KEYS_ORDER[@]}"; do
      echo -e "  ${idx}. ${BOLD}$k${NC} = ${PARAMS[$k]}"
      ((idx++))
    done
  fi

  echo ""
  echo -e "选项:"
  echo -e "  ${BOLD}edit${NC}  — 继续编辑（添加/覆盖/删除字段）"
  echo -e "  ${BOLD}yes${NC}   — 确认提交到合约"
  echo -e "  ${BOLD}quit${NC}  — 放弃退出（不保存任何数据）"
  echo ""

  read -rp "请选择 [edit/yes/quit]: " choice

  case "$choice" in
    edit|EDIT|e|E)
      info "继续编辑..."
      continue
      ;;
    yes|YES|y|Y)
      if [[ ${#PARAM_KEYS_ORDER[@]} -eq 0 ]]; then
        warn "没有任何字段可提交，请先添加字段"
        continue
      fi

      # 构建最终 JSON
      build_args=()
      for k in "${PARAM_KEYS_ORDER[@]}"; do
        build_args+=("$k" "${PARAMS[$k]}")
      done
      FINAL_JSON="$(build_json "${build_args[@]}")"
      FINAL_JSON_COMPACT="$(node -e "console.log(JSON.stringify(JSON.parse(process.argv[1])))" "$FINAL_JSON")"

      echo ""
      info "即将写入合约的内容:"
      echo -e "${GREEN}$FINAL_JSON${NC}"
      echo ""

      read -rp "确认写入合约？请输入 yes 确认: " confirm
      if [[ "$confirm" != "yes" ]]; then
        warn "已取消提交，返回编辑"
        continue
      fi

      info "正在写入合约..."

      if $OVERWRITE_MODE; then
        # ---- 交互 + 覆盖模式: 直接写入 ----
        set +e
        write_output="$(write_contract_value "$FINAL_JSON_COMPACT" "" 2>&1)"
        write_rc=$?
        set -e

        if [[ $write_rc -ne 0 ]]; then
          echo "$write_output"
          err "合约写入失败"
          continue
        fi
        echo "$write_output"
        ok "合约更新成功！（覆盖模式）"
        exit 0
      else
        # ---- 交互 + 更新模式: 乐观锁校验后写入 ----
        set +e
        write_output="$(write_contract_value "$FINAL_JSON_COMPACT" "${CONTRACT_SNAPSHOT:-}" 2>&1)"
        write_rc=$?
        set -e

        if [[ $write_rc -eq 2 ]] || echo "$write_output" | grep -q '__CONFLICT__'; then
          warn "检测到冲突：合约值已被他人修改！"
          echo ""

          conflict_current="$(echo "$write_output" | grep '__CONFLICT_CURRENT__' | sed 's/.*__CONFLICT_CURRENT__//')"
          if [[ -n "$conflict_current" ]]; then
            echo -e "${YELLOW}合约最新值:${NC}"
            display_json "$conflict_current" 2>/dev/null || echo "$conflict_current"
            echo ""
          fi

          echo -e "选项:"
          echo -e "  ${BOLD}reload${NC}  — 重新加载合约最新值，保留您的编辑内容并重试"
          echo -e "  ${BOLD}quit${NC}    — 放弃退出"
          echo ""
          read -rp "请选择 [reload/quit]: " conflict_choice

          case "$conflict_choice" in
            reload|RELOAD|r|R)
              info "重新读取合约最新值..."
              set +e
              CONTRACT_SNAPSHOT="$(read_contract_value 2>&1)"
              reload_rc=$?
              set -e

              if [[ $reload_rc -ne 0 ]]; then
                err "读取合约失败"
                echo "$CONTRACT_SNAPSHOT"
                continue
              fi
              info "已更新合约快照: $CONTRACT_SNAPSHOT"

              # 将合约最新值的新字段加入（用户编辑的字段保持不变）
              new_base_data="$(node -e "
                const obj = JSON.parse(process.argv[1] || '{}');
                for (const [k, v] of Object.entries(obj)) {
                  console.log(k + '\x1f' + JSON.stringify(v));
                }
              " "$CONTRACT_SNAPSHOT")"

              declare -A USER_KEYS
              for k in "${PARAM_KEYS_ORDER[@]:-}"; do
                USER_KEYS["$k"]=1
              done

              while IFS= read -r nb_line; do
                [[ -z "$nb_line" ]] && continue
                nbkey="${nb_line%%$'\x1f'*}"
                nbval="${nb_line#*$'\x1f'}"
                if [[ -z "${USER_KEYS[$nbkey]:-}" ]]; then
                  add_or_update_key "$nbkey" "$nbval"
                  info "  从合约加载新字段: $nbkey = $nbval"
                fi
              done <<< "$new_base_data"
              unset USER_KEYS

              warn "已重新加载，请检查字段后重新提交"
              continue
              ;;
            *)
              warn "已放弃，不保存任何数据"
              exit 0
              ;;
          esac
        elif [[ $write_rc -ne 0 ]]; then
          echo "$write_output"
          err "合约写入失败"
          continue
        else
          echo "$write_output"
          ok "合约更新成功！（更新模式）"
          exit 0
        fi
      fi
      ;;
    quit|QUIT|q|Q)
      warn "已放弃，不保存任何数据"
      exit 0
      ;;
    *)
      warn "无效选项，请输入 edit / yes / quit"
      ;;
  esac
done
