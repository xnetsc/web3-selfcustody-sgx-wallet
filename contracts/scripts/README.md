# update-runtime-params.sh — 合约 runtimeParams 更新工具

用于读写智能合约 `WalletTrustContract` 中 `runtimeParams` 字段的命令行工具。支持交互模式和自动化模式，支持更新（合并）和覆盖两种写入语义。

## 目录

- [快速开始](#快速开始)
- [工作原理](#工作原理)
- [四种运行模式](#四种运行模式)
- [命令行参数](#命令行参数)
- [环境变量](#环境变量)
- [依赖管理](#依赖管理)
- [更新模式 vs 覆盖模式](#更新模式-vs-覆盖模式)
- [乐观锁与冲突处理](#乐观锁与冲突处理)
- [交互模式详细说明](#交互模式详细说明)
- [自动化模式详细说明](#自动化模式详细说明)
- [JSON 格式说明](#json-格式说明)
- [退出码](#退出码)
- [使用示例](#使用示例)
- [常见问题](#常见问题)

---

## 快速开始

```bash
# 交互模式（更新模式，默认）— 逐步引导输入
bash contracts/scripts/update-runtime-params.sh

# 自动化模式 — 合并指定字段到合约现有值
bash contracts/scripts/update-runtime-params.sh \
  --json '{"session":{"importTtlSeconds":300}}'

# 自动化覆盖模式 — 完全替换合约内容
bash contracts/scripts/update-runtime-params.sh \
  --overwrite --json '{"session":{"importTtlSeconds":300}}'
```

> **前提条件**: 需要 Node.js (>=16) 和 npm。脚本会自动在自身目录下安装所需的 `ethers` 依赖，无需手动安装任何 npm 包。

---

## 工作原理

```
┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
│  用户输入     │ ──► │  本地合并     │ ──► │  写入合约         │
│  (JSON字段)  │     │  (更新模式)   │     │  (乐观锁校验)     │
└──────────────┘     └──────────────┘     └──────────────────┘
                           │                       │
                           ▼                       ▼
                     ┌──────────────┐     ┌──────────────────┐
                     │  读取合约     │     │  回读合约最新值   │
                     │  当前值      │     │  解析并展示       │
                     └──────────────┘     └──────────────────┘
```

1. **读取** — 从合约读取当前 `runtimeParams`（更新模式）
2. **编辑** — 用户通过交互式输入或 `--json` 参数提供要修改的字段
3. **合并** — 将用户字段合并到合约现有 JSON 上（更新模式），或直接使用用户 JSON（覆盖模式）
4. **校验** — 写入前检查合约值是否被他人修改（乐观锁，仅更新模式）
5. **写入** — 调用合约 `updateRuntimeParams(string)` 方法
6. **回读** — 写入成功后回读合约最新值，解析并展示字段明细供复核

---

## 四种运行模式

| 模式 | 命令 | 说明 |
|------|------|------|
| 交互 + 更新 | `bash update-runtime-params.sh` | 读取合约 → 预填充字段 → 用户逐步编辑 → 乐观锁写入。冲突时允许重新加载重试 |
| 交互 + 覆盖 | `bash update-runtime-params.sh --overwrite` | 用户从零输入所有字段 → 直接覆盖合约内容 |
| 自动化 + 更新 | `bash update-runtime-params.sh --json '{...}'` | 读取合约 → 自动合并 → 乐观锁写入。冲突时报错退出 |
| 自动化 + 覆盖 | `bash update-runtime-params.sh --overwrite --json '{...}'` | 直接覆盖合约，不读取不合并 |

---

## 命令行参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `--json JSON` | 要写入的 JSON 字符串（启用自动化模式） | `--json '{"key":"value"}'` |
| `--overwrite` | 切换为覆盖模式（默认为更新模式） | `--overwrite` |
| `--rpc-url URL` | RPC 节点 URL（覆盖环境变量） | `--rpc-url http://127.0.0.1:8545` |
| `--chain-id ID` | 区块链 Chain ID（覆盖环境变量） | `--chain-id 31337` |
| `--contract-address ADDR` | 合约地址（覆盖环境变量） | `--contract-address 0x1234...` |
| `--private-key KEY` | 合约 Owner 私钥（覆盖环境变量） | `--private-key 0xac09...` |
| `-h`, `--help` | 显示帮助信息 | `-h` |

**参数优先级**: 命令行参数 > 环境变量（.env 文件） > 交互式提示输入

---

## 环境变量

可通过 `.env` 文件提供，脚本按以下优先级加载（先加载的优先）：

1. **脚本所在目录** `contracts/scripts/.env`
2. **sgx-enclave 目录** `sgx-enclave/.env`
3. **项目根目录** `.env`

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `CONTRACT_RPC_URL` | RPC 节点 URL | `http://127.0.0.1:8545` |
| `CONTRACT_CHAIN_ID` | 区块链 Chain ID | `31337` |
| `CONTRACT_ADDRESS` | 合约部署地址 | `0xD429...7Cee` |
| `CONTRACT_OWNER_PRIVATE_KEY` | 合约 Owner 私钥 | `0xac09...ff80` |

> **安全提示**: 私钥仅在脚本运行期间存在于进程环境变量中，不会被脚本持久化存储。建议在 `.env` 文件中设置合适的文件权限（`chmod 600 .env`）。

---

## 依赖管理

脚本采用 **自包含** 设计，不依赖项目其他目录的 `node_modules`：

- 首次运行时，脚本会自动在自身目录（`contracts/scripts/`）下执行 `npm install ethers`
- 后续运行会检测 `node_modules/ethers` 是否存在，已安装则跳过
- 自动生成的 `package.json`、`node_modules/`、`package-lock.json` 已通过 `.gitignore` 排除，不会被提交到仓库

```
contracts/scripts/
├── update-runtime-params.sh    # 主脚本
├── README.md                   # 本文档
├── .gitignore                  # 排除 node_modules 等
├── init-contract.js            # 合约初始化脚本
├── package.json                # (自动生成，已 gitignore)
├── package-lock.json           # (自动生成，已 gitignore)
└── node_modules/               # (自动安装，已 gitignore)
    └── ethers/
```

---

## 更新模式 vs 覆盖模式

### 更新模式（默认）

- **行为**: 读取合约当前 JSON → 将用户字段合并到现有 JSON 上 → 写回合约
- **合并规则**: 顶层字段以用户输入为准（覆盖同名字段），不存在的字段新增，合约原有但用户未提供的字段保留
- **适用场景**: 只需修改部分字段，不影响其他字段

```
合约当前值:    {"a": 1, "b": 2, "c": 3}
用户提供:      {"b": 99, "d": 4}
合并结果:      {"a": 1, "b": 99, "c": 3, "d": 4}
```

### 覆盖模式（`--overwrite`）

- **行为**: 用户提供的 JSON 直接替换合约全部内容，不做合并
- **适用场景**: 需要完全重置合约参数，或需要删除某些字段

```
合约当前值:    {"a": 1, "b": 2, "c": 3}
用户提供:      {"b": 99, "d": 4}
写入结果:      {"b": 99, "d": 4}          ← a、c 字段被删除
```

---

## 乐观锁与冲突处理

### 什么是乐观锁

在更新模式下，脚本实现了乐观锁机制来防止并发写入导致的数据丢失：

1. 读取合约当前值（快照）
2. 本地合并用户字段
3. 写入前再次读取合约值，与快照比较
4. 如果相同，执行写入
5. 如果不同，说明有其他人同时修改了合约，触发冲突

### 冲突处理

**交互模式**下发生冲突时：
- 显示合约最新值的详细内容
- 提供两个选项：
  - `reload` — 重新加载合约最新值，保留用户已编辑的字段，合约新增的字段会自动加入
  - `quit` — 放弃退出
- 选择 reload 后回到复核界面，用户可以检查合并结果并重新提交

**自动化模式**下发生冲突时：
- 输出错误信息和合约最新值
- 以退出码 `1` 退出（无法交互确认）
- 调用方可根据退出码判断是否需要重试

### 冲突场景示例

```
时间线:
  T1: 脚本A 读取合约值 = {"a":1}
  T2: 脚本B 修改合约值为 {"a":1, "b":2}
  T3: 脚本A 尝试写入 {"a":1, "c":3}
  T4: 脚本A 检测到冲突（当前值 {"a":1,"b":2} ≠ 快照 {"a":1}）
  T5: 脚本A 报错，展示最新值
```

---

## 交互模式详细说明

### 流程

```
启动 → 读取合约（更新模式） → 预填充现有字段
  ↓
输入字段（循环）
  ├── 字段名:值  →  添加/覆盖字段
  ├── 字段名:    →  删除字段
  └── done       →  进入复核
  ↓
复核展示（JSON 格式 + 字段明细）
  ├── edit  →  回到输入循环
  ├── yes   →  二次确认后写入合约
  └── quit  →  放弃退出
  ↓
写入合约 → 回读并展示最新值 → 结束
```

### 字段输入格式

脚本支持多种输入格式，以下均为合法输入：

| 输入 | 解析结果 |
|------|----------|
| `key:value` | key = `"value"` |
| `"key":"value"` | key = `"value"` |
| `key:"value"` | key = `"value"` |
| `"key":value` | key = `"value"` |
| `key:123` | key = `123`（数字） |
| `key:{"a":1,"b":2}` | key = `{"a":1,"b":2}`（JSON 对象） |
| `key:[1,2,3]` | key = `[1,2,3]`（JSON 数组） |
| `key:true` | key = `true`（布尔值） |
| `key:` | **删除** key 字段 |

> **值的类型判断**: 脚本会尝试将值解析为 JSON（数字、布尔值、对象、数组）。如果解析失败，则作为字符串处理。

### 操作说明

- **添加字段**: 输入新的 `字段名:值`
- **覆盖字段**: 输入已存在的 `字段名:新值`，会覆盖原来的值
- **删除字段**: 输入 `字段名:`（冒号后无值），会删除该字段
- **结束输入**: 输入 `done` 进入复核
- **编辑/确认/退出**: 复核时输入 `edit`（继续编辑）、`yes`（提交）、`quit`（退出）
- **二次确认**: 选择 `yes` 后还需要再次输入 `yes` 才会真正写入合约

### 交互示例

```
========================================
  合约 runtimeParams 更新工具（交互模式）
========================================

当前为更新模式：您输入的内容将合并到合约现有值上
[INFO] 正在读取合约当前值...
[INFO] 合约当前值: {"session":{"importTtlSeconds":300}}
[INFO] 预填充合约现有字段...
[INFO]   已加载: session = {"importTtlSeconds":300}

--- 输入字段 ---
格式: 字段名:值
输入 done 结束输入进入复核

> cache:{"refreshInterval":600000}
[OK] 已设置: cache = {"refreshInterval":600000}
> session:{"importTtlSeconds":600,"exportTtlSeconds":86400}
[OK] 已设置: session = {"importTtlSeconds":600,"exportTtlSeconds":86400}
> done

========================================
  当前字段列表（复核）
========================================

{
  "session": {
    "importTtlSeconds": 600,
    "exportTtlSeconds": 86400
  },
  "cache": {
    "refreshInterval": 600000
  }
}

字段明细:
  1. session = {"importTtlSeconds":600,"exportTtlSeconds":86400}
  2. cache = {"refreshInterval":600000}

选项:
  edit  — 继续编辑
  yes   — 确认提交到合约
  quit  — 放弃退出

请选择 [edit/yes/quit]: yes
确认写入合约？请输入 yes 确认: yes
[INFO] 正在写入合约...
[OK] 交易已确认，区块: 42
[OK] 合约更新成功！（更新模式）
```

---

## 自动化模式详细说明

### 触发条件

传入 `--json` 参数即启用自动化模式，无需任何用户交互。

### 必需参数

自动化模式下，合约连接参数必须通过以下之一提供（否则报错退出）：
- 命令行参数（`--rpc-url`, `--chain-id`, `--contract-address`, `--private-key`）
- 环境变量（`.env` 文件或系统环境变量）

### 自动化更新模式

```bash
# 只修改 session 的 TTL，保留合约其他字段
bash contracts/scripts/update-runtime-params.sh \
  --json '{"session":{"importTtlSeconds":600}}'
```

流程: 读取合约 → 合并字段 → 乐观锁校验 → 写入 → 回读展示

### 自动化覆盖模式

```bash
# 完全替换合约内容
bash contracts/scripts/update-runtime-params.sh \
  --overwrite --json '{"session":{"importTtlSeconds":600},"cache":{"refreshInterval":300000}}'
```

流程: 直接写入 → 回读展示

### 带完整参数的自动化调用

```bash
bash contracts/scripts/update-runtime-params.sh \
  --json '{"session":{"importTtlSeconds":600}}' \
  --rpc-url http://10.0.1.1:8545 \
  --chain-id 1 \
  --contract-address 0x1234567890abcdef1234567890abcdef12345678 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

### 在 CI/CD 中使用

```yaml
# GitHub Actions 示例
- name: Update contract params
  run: |
    bash contracts/scripts/update-runtime-params.sh \
      --json '{"session":{"importTtlSeconds":600}}'
  env:
    CONTRACT_RPC_URL: ${{ secrets.RPC_URL }}
    CONTRACT_CHAIN_ID: "1"
    CONTRACT_ADDRESS: ${{ secrets.CONTRACT_ADDRESS }}
    CONTRACT_OWNER_PRIVATE_KEY: ${{ secrets.OWNER_PRIVATE_KEY }}
```

---

## JSON 格式说明

合约 `runtimeParams` 存储的是一个 JSON 字符串，典型结构：

```json
{
  "session": {
    "importTtlSeconds": 300,
    "exportTtlSeconds": 86400
  },
  "cache": {
    "refreshInterval": 600000
  }
}
```

- 顶层字段为配置项分组
- 值可以是任意合法 JSON 类型（字符串、数字、布尔值、对象、数组）
- 合约本身对 JSON 内容没有 schema 约束，存储为原始字符串
- 更新模式的合并只作用于**顶层字段**（shallow merge），不会递归合并嵌套对象

> **注意**: 更新模式下，如果修改嵌套对象的某个子字段，需要提供整个顶层字段的完整值。例如只想修改 `session.importTtlSeconds`，需要提供完整的 `session` 对象：`session:{"importTtlSeconds":600,"exportTtlSeconds":86400}`

---

## 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 成功（写入完成或用户主动退出） |
| `1` | 错误（参数缺失、JSON 格式无效、合约写入失败、Owner 身份验证失败、冲突等） |

---

## 使用示例

### 1. 首次配置（覆盖模式）

```bash
bash contracts/scripts/update-runtime-params.sh \
  --overwrite \
  --json '{
    "session": {"importTtlSeconds": 300, "exportTtlSeconds": 86400},
    "cache": {"refreshInterval": 600000}
  }'
```

### 2. 更新单个字段（更新模式）

```bash
# 只更新 cache 字段，保留 session 等其他字段
bash contracts/scripts/update-runtime-params.sh \
  --json '{"cache":{"refreshInterval":300000}}'
```

### 3. 添加新字段

```bash
# 添加 newFeature 字段，保留所有现有字段
bash contracts/scripts/update-runtime-params.sh \
  --json '{"newFeature":{"enabled":true,"maxRetries":3}}'
```

### 4. 交互式修改

```bash
# 启动交互模式，会自动读取并预填充合约当前值
bash contracts/scripts/update-runtime-params.sh
```

### 5. 使用自定义 .env 文件

```bash
# 在脚本目录放置 .env 文件
cat > contracts/scripts/.env << 'EOF'
CONTRACT_RPC_URL=http://10.0.1.1:8545
CONTRACT_CHAIN_ID=1
CONTRACT_ADDRESS=0x1234567890abcdef1234567890abcdef12345678
CONTRACT_OWNER_PRIVATE_KEY=0xac0974...
EOF

# 脚本会自动加载该 .env
bash contracts/scripts/update-runtime-params.sh --json '{"key":"value"}'
```

---

## 常见问题

### Q: 提示 "安装 ethers 失败"

确保系统已安装 Node.js (>=16) 和 npm，且网络可以访问 npm registry。

### Q: 提示 "当前私钥不是合约 Owner"

只有合约 Owner 才能调用 `updateRuntimeParams`。请检查 `CONTRACT_OWNER_PRIVATE_KEY` 是否正确。可以通过合约的 `owner()` 方法查询当前 Owner 地址。

### Q: 提示 "乐观锁冲突"

说明在您读取合约和写入之间，有其他人（或其他脚本实例）修改了合约值。
- **交互模式**: 选择 `reload` 重新加载最新值后重试
- **自动化模式**: 脚本会退出，请稍后重试

### Q: 更新模式下如何删除某个字段？

更新模式的合并是"添加或覆盖"语义，无法通过更新模式删除字段。要删除字段，请使用覆盖模式 (`--overwrite`)，提供不含目标字段的完整 JSON。

在交互模式下，输入 `字段名:` （冒号后无值）可以从待提交列表中删除该字段。

### Q: 嵌套 JSON 对象如何修改？

合并仅作用于顶层字段。要修改嵌套字段，需提供整个顶层字段的完整值：

```bash
# 错误: 这不会只修改 importTtlSeconds
# --json '{"session.importTtlSeconds": 600}'

# 正确: 提供完整的 session 对象
bash contracts/scripts/update-runtime-params.sh \
  --json '{"session":{"importTtlSeconds":600,"exportTtlSeconds":86400}}'
```

### Q: 脚本可以在任意目录下运行吗？

可以。脚本通过 `BASH_SOURCE` 自动定位自身所在目录，所有路径均基于脚本位置计算。在任何目录下使用绝对路径或相对路径运行脚本均可正常工作。

### Q: node_modules 会被提交到 Git 吗？

不会。`contracts/scripts/.gitignore` 已排除 `node_modules/`、`package.json` 和 `package-lock.json`。
