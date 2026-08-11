# SGX Enclave HTTP API 文档


---

## 概述

- **端口**：环境变量 `SGX_HTTP_PORT`，默认 `3000`
- **基础地址**：`http://localhost:3000`
- **所有接口均为 `POST`**，Content-Type: `application/json`
- **共 20 个接口**（挑战值统一由 `/api/challenge` 提供）

---

## 统一请求格式

除 `/api/enclave/info` 外，所有接口的 HTTP body 均为：

```json
{
  "payload": "<JSON 字符串>",
  "platformSignature": "<EIP-191 secp256k1 签名>"
}
```

- `payload`：JSON 字符串（string 类型，不是 object）。每个接口对 payload 解析后得到的字段不同，见各接口的 **payload 字段定义**。
- `platformSignature`：平台对 `payload` 的 EIP-191 `personal_sign` 签名。hex 格式含 `0x` 前缀，132 字符。服务端通过 `ethers.verifyMessage(payload, platformSignature)` 恢复签名者地址，验证该地址是否在链上白名单合约中。

验签通过后，服务端执行 `request = JSON.parse(payload)`，后续业务逻辑从解析后的对象取字段。

**公共 curl 请求样例**：

```bash
curl -X POST http://localhost:3000/api/<接口路径> \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "{\"字段1\":\"值1\",\"字段2\":\"值2\"}",
    "platformSignature": "0xabc123...signature_hex"
  }'
```

---

## 统一响应格式

所有接口的 HTTP 响应格式统一为：

```json
{
  "attestationQuote": "<SGX quote hex 字符串>",
  "data": "<handler 返回值的 JSON 序列化字符串>"
}
```

- `attestationQuote`：SGX 远程证明 quote，对 `data` 字段计算 SHA256 后注入 `user_report_data` 生成。非 SGX 环境下为空字符串。
- `data`：handler 返回值的 JSON 字符串，客户端需自行 `JSON.parse(data)` 反序列化。

**错误响应**（HTTP 400/401/404/500）：

```json
{ "error": "错误描述" }
```

**HTTP 状态码**：

| 状态码 | 含义 |
|--------|------|
| 200 | 请求处理成功 |
| 400 | 请求参数缺失或格式错误 |
| 401 | 平台签名验证失败或 WebAuthn 鉴权失败 |
| 403 | 账户被冻结（安全保护机制） |
| 404 | 资源不存在 |
| 500 | 服务器内部错误 |

---

## WebAuthn 签名格式

以下接口中出现的 `webauthnSignature` 字段结构（Browser WebAuthn API 断言响应格式）：

| 子字段 | 类型 | 说明 |
|--------|------|------|
| `authenticatorData` | string | 认证器数据，base64url 编码 |
| `clientDataJSON` | string | 客户端数据 JSON，base64url 编码（包含 challenge、origin 等） |
| `signature` | string | P256 签名，base64url 编码（DER 格式） |

> **注意**：`challenge` 字段无需单独传递，服务端从 `clientDataJSON` 中自动提取并验证。

---

## 接口列表

| 序号 | 路径 | 用途 |
|------|------|------|
| 1 | `/api/challenge` | **统一挑战值接口**（支持所有 purpose） |
| 2 | `/api/passkey/register/complete` | Passkey 注册 — 提交注册结果 |
| 3 | `/api/passkey/delete` | 删除 Passkey |
| 4 | `/api/passkey/list` | 列出用户的 Passkey |
| 5 | `/api/wallet/create` | 创建钱包 |
| 6 | `/api/wallet/list` | 列出钱包 |
| 7 | `/api/wallet/get` | 查询钱包详情 |
| 8 | `/api/wallet/delete` | 删除钱包容器 |
| 9 | `/api/wallet/entry/delete` | 删除单个逻辑钱包 |
| 10 | `/api/auth/status` | 查询授权状态 |
| 11 | `/api/tx/sign` | 交易签名 |
| 12 | `/api/key/import/init` | 密钥导入 — 初始化 |
| 13 | `/api/key/import/complete` | 密钥导入 — 完成 |
| 14 | `/api/key/export/init` | 密钥导出 — 初始化 |
| 15 | `/api/key/export/complete` | 密钥导出 — 确认 |
| 16 | `/api/evidence/get` | 取证 — 查询单条记录 |
| 17 | `/api/evidence/list` | 取证 — 列出记录摘要 |
| 18 | `/api/enclave/info` | 查询 Enclave 信息（无需鉴权） |
| 19 | `/api/admin/userId/list` | 管理员 — 列出所有用户 |

---

## 1. POST /api/challenge

**统一挑战值接口**。所有需要 WebAuthn 签名的操作都通过此接口获取挑战值。根据 `purpose` 字段决定验证逻辑和返回内容。

### 挑战值安全机制

**完整流程**（非 `register` purpose）：

**步骤 1**：调用 `/api/challenge` 获取 `rawChallenge`（纯随机数）

```
// payload
{ "purpose": "wallet_create", "userId": "user-xxx", "credentialId": "cred-xxx" }
// 响应 data
{ "challenge": "rawChallenge_base64url", "userId": "user-xxx", "expiresAt": "..." }
```

**步骤 2**：客户端构造 `userIntentJson`，计算 `intentHash`，用 Passkey 签名

```
userIntentJson = JSON.stringify({ purpose, userId, ...业务参数 })
intentHash = SHA256(rawChallenge + userIntentJson)
webauthnSignature = Passkey.sign(intentHash)
```

**步骤 3**：调用业务接口，携带 `rawChallenge + userIntentJson + webauthnSignature`

```json
// payload（以 wallet/create 为例）
{
  "userId": "user-xxx",
  "credentialId": "cred-xxx",
  "rawChallenge": "rawChallenge_base64url",
  "userIntentJson": "{\"purpose\":\"wallet_create\",\"userId\":\"user-xxx\",\"chains\":[{\"chainId\":\"1\"}]}",
  "webauthnSignature": { "authenticatorData": "...", "clientDataJSON": "...", "signature": "..." },
  "chains": [{ "chainId": "1" }]
}
```

**服务端验证流程**（业务接口）：

1. 根据 `rawChallenge` 查询挑战值记录，不存在则拒绝（防重放）
2. 计算 `intentHash = SHA256(rawChallenge + userIntentJson)`
3. 验证 WebAuthn 签名（`expectedChallenge = intentHash`）
4. 解析 `userIntentJson`，逐字段与实际业务参数比对（防止平台替换参数）
5. 消费（删除）挑战值记录

> **注意**：授权JSON（`/api/tx/sign` 中的 `authorizationJson` 字段）的 WebAuthn challenge 由客户端自行计算（`SHA256(authorizationJson)`），不需要调用 `/api/challenge` 接口。

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `purpose` | string | 是 | 操作用途（见下方枚举） |
| `userId` | string | 视 purpose 而定 | `register` 时可选（不传则自动生成），其他 purpose 必填 |
| `credentialId` | string | 非 register 时必填 | Passkey 凭证 ID（base64url 编码），用于验证 Passkey 归属 |

`purpose` 枚举值：

| 值 | 对应操作 | 是否需要 Passkey 归属验证 |
|----|---------|--------------------------|
| `register` | 新用户 Passkey 注册 | 否（userId 可选） |
| `register_passkey` | 已有用户添加新 Passkey | 是 |
| `wallet_create` | 创建钱包 | 是 |
| `wallet_delete` | 删除钱包容器 | 是 |
| `passkey_delete` | 删除 Passkey | 是 |
| `wallet_entry_delete` | 删除单个逻辑钱包 | 是 |
| `key_export` | 密钥导出初始化 | 是 |
| `key_export_confirm` | 密钥导出确认（授权删除钱包） | 是 |
| `evidence_query` | 取证查询（用户发起） | 是 |
| `key_import_init` | 用户端密钥导入初始化 | 是 |
| `key_import_complete` | 用户端密钥导入完成 | 是 |

**各 purpose 的 userIntentJson 字段规范**（业务请求时使用，不在此接口传入）：

| purpose | userIntentJson 必填字段 | 说明 |
|---------|------------------------|------|
| `register_passkey` | `{ purpose, userId }` | 已有用户添加新 Passkey 时使用 |
| `wallet_create` | `{ purpose, userId, chains, mnemonicStrength? }` | `chains` 为链配置数组，`mnemonicStrength` 可选 |
| `wallet_delete` | `{ purpose, userId, walletId }` | 指定要删除的钱包 ID |
| `passkey_delete` | `{ purpose, userId, credentialIdsToDelete }` | 指定要删除的凭证 ID 列表 |
| `wallet_entry_delete` | `{ purpose, userId, walletId, address }` | 指定要删除的逻辑钱包地址 |
| `key_export`（ECDH） | `{ purpose, userId, exportInfo, peerPublicKey }` | `exportInfo` 为 `[{walletId, addresses}]` 数组，`addresses` 为空时导出该 walletId 下所有私钥；`addresses` 元素可为纯地址字符串或 `{address, chainId}` 对象（精确匹配指定链）；`peerPublicKey` 为客户端 ECDH 公钥（hex），防止中间人替换 |
| `key_export`（RSA） | `{ purpose, userId, exportInfo, rsaPublicKey }` | `exportInfo` 为 `[{walletId, addresses}]` 数组，`addresses` 为空时导出该 walletId 下所有私钥；`addresses` 元素可为纯地址字符串或 `{address, chainId}` 对象（精确匹配指定链）；`rsaPublicKey` 为客户端 RSA 公钥（PEM 原始字符串），防止中间人替换 |
| `key_export_confirm` | `{ purpose, userId, sessionId }` | 确认已收到数据并授权删除钱包，`sessionId` 防止被替换 |
| `evidence_query` | `{ purpose, userId, authorizationId? }` | 查询特定授权时需提供 authorizationId |
| `key_import_init` | `{ purpose, userId, importType }` | 用户端导入初始化，`importType` 防止平台替换导入类型 |
| `key_import_complete` | `{ purpose, userId, sessionId, walletId, chains }` | 用户端导入完成，`userId` 与 Passkey 归属绑定，`sessionId` 防止替换会话，`walletId`/`chains` 防止平台篡改存储目标和派生链（可为 null） |

> **重要**：
> - `userIntentJson` 在**业务接口**（非此接口）的 payload 中传入，此接口不需要 `userIntentJson`。
> - `userIntentJson` 中的值不允许转换，服务端直接与实际请求参数比对，不一致则拒绝。
> - `key_export` 的 `peerPublicKey`/`rsaPublicKey` 必须纳入 `userIntentJson`，防止中间人替换密钥交换参数。
> - `intentHash = SHA256(rawChallenge + userIntentJson)`，客户端用此哈希作为 WebAuthn challenge 签名。

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `challenge` | string | base64url 编码的纯随机挑战值（rawChallenge，TTL 300 秒） |
| `userId` | string | 用户 ID（`register` 时若未传则为服务端生成值） |
| `expiresAt` | string | 挑战值过期时间（ISO 8601） |

**请求示例（Passkey 注册，无需 credentialId）**：

```json
{
  "payload": "{\"purpose\":\"register\",\"userId\":\"user-xxx\"}",
  "platformSignature": "0x..."
}
```

**请求示例（钱包创建，只需 userId + credentialId）**：

```json
{
  "payload": "{\"purpose\":\"wallet_create\",\"userId\":\"user-xxx\",\"credentialId\":\"cred-xxx\"}",
  "platformSignature": "0x..."
}
```

> **说明**：此接口返回的 `challenge` 是纯随机数（rawChallenge）。客户端收到后，需构造 `userIntentJson`，计算 `intentHash = SHA256(rawChallenge + userIntentJson)`，再用 Passkey 对 `intentHash` 签名，最后在业务接口中携带 `rawChallenge + userIntentJson + webauthnSignature`。

---

## 2. POST /api/passkey/register/complete

Passkey 注册流程第二步。提交 WebAuthn 注册仪式完成后的响应数据，服务端使用 `@simplewebauthn/server` 验证并提取 COSE 格式公钥存储。

支持三种场景：
- **场景A（无 Passkey，purpose=register）**：直接提交 `attestationResponse`，使用 `purpose=register` 的挑战值
  - `userId` 可选：若提供则使用该 userId；若未提供则从 challenge 记录中获取（challenge 接口生成的随机 userId）
  - 适用于全新用户（userId 不存在）或已有账户但尚无 Passkey 的用户
  - ⚠️ **安全增强**：若为已有账户（userId 已存在）且该账户下有钱包（助记词或纯私钥），则自动触发账户冻结（详见附录 E）
  - ⚠️ **冻结账户替换**：若账户已处于冻结状态，通过 `purpose=register` 重新注册时，新 Passkey 将替换旧的冻结 Passkey，冻结时间重置（默认 72 小时，可配置，详见附录 E）
- **场景B（已有 Passkey，purpose=register_passkey）**：额外提供 `existingCredentialId` + `existingWebauthnSignature`，使用 `purpose=register_passkey` 的挑战值
  - `userId` 必须提供
  - ⚠️ 冻结账户不允许使用 `purpose=register_passkey`
- **场景C（Passkey 恢复，purpose=register）**：用户丢失所有 Passkey，Owner 通过合约授权恢复
  - `userId` 必须提供，**不提供** `existingWebauthnSignature`
  - 前置条件：Owner 已在合约中调用 `setPasskeyRecovery(userId, newPubKeyHash, oldPubKeyHash, uuid, memo)`
  - SGX 查询合约匹配 `(userId, SHA256(newPublicKeyCose))`，验证 `oldPubKeyHash` 匹配现有 Passkey
  - 保留匹配的旧 Passkey 记录，删除其余 Passkey，用新 Passkey 替换保留记录
  - 自动触发账户冻结（72h），响应包含 `recovery=true` 和 `recoveryUuid`
  - ⚠️ 合约不可用时此功能不可用
>
> **安全增强**：为防止攻击者利用此后门冒充绑定 Passkey 盗取资产，当已有账户（有钱包）通过场景A补绑 Passkey 时，系统自动冻结账户（默认 72 小时，可配置）。详见附录 E。

**场景B的安全流程**：
1. 客户端调用 `/api/challenge`（`purpose=register_passkey`）获取 `challenge1`
2. 客户端用 `challenge1` 创建新 Passkey → 得到 `newCredentialId` 和 `newPublicKeyCose`
3. 客户端计算 `existingChallenge = SHA256(challenge1 + newCredentialId + newPublicKeyCoseBase64url)`
4. 客户端用已有 Passkey 对 `existingChallenge` 签名（`existingWebauthnSignature`）
5. 服务端验证两个签名，确保新 Passkey 的公钥和 ID 未被中途替换

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 场景B必填，场景A可选 | 用户 ID。场景A若未提供，从 challenge 记录中获取（challenge 接口生成的随机 userId） |
| `attestationResponse` | object | 是 | WebAuthn 注册响应（子字段见下） |
| `existingCredentialId` | string | 场景B必填 | 已有 Passkey 的凭证 ID（用于验证身份） |
| `existingWebauthnSignature` | object | 场景B必填 | 已有 Passkey 的 WebAuthn 签名（challenge = SHA256(challenge1 + newCredentialId + newPublicKeyCoseBase64url)） |

`attestationResponse` 子字段（Browser WebAuthn API 注册响应格式）：

| 子字段 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| `id` | string | 是 | base64url 编码的凭证 ID |
| `rawId` | string | 是 | base64url 编码的凭证 ID（同 `id`） |
| `response.attestationObject` | string | 是 | base64url 编码的 attestation object（CBOR 格式） |
| `response.clientDataJSON` | string | 是 | base64url 编码的 clientDataJSON（包含 challenge、origin） |
| `type` | string | 是 | 固定为 `"public-key"` |

> **注意**：
> - 服务端从 `clientDataJSON` 中提取 `challenge`，与数据库中存储的挑战值比对（一次性使用）
> - 服务端从 `clientDataJSON` 中提取 `origin`，并以此作为 `expectedOrigin` 和 `expectedRPID`（无钓鱼验证）
> - 公钥以 COSE 格式存储，无需客户端提供 `publicKeyX/Y`
> - 场景B中，`existingWebauthnSignature` 的 challenge 不是服务端直接生成的，而是 `SHA256(challenge1 + newCredentialId + newPublicKeyCoseBase64url)`，这样已有 Passkey 的签名就绑定了新 Passkey 的公钥和 ID，防止中途替换

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 固定 `true` |
| `userId` | string | 用户 ID |
| `credentialId` | string | 已注册的凭证 ID（base64url） |
| `isFirstPasskey` | boolean | 该 userId 下此前无 Passkey 时为 `true`（包括全新用户和已有账户但尚无 Passkey 的用户） |
| `recovery` | boolean | 可选。若为 `true`，表示本次注册是合约授权的 Passkey 恢复（场景C） |
| `recoveryUuid` | string | 可选。恢复条目的唯一标识符，仅在 `recovery=true` 时返回 |
| `frozen` | boolean | 可选。若为 `true`，表示账户已被冻结（场景A补绑有钱包、场景C恢复时触发） |
| `freezeUntil` | string | 可选。冻结截止时间（ISO 8601 格式），仅在 `frozen=true` 时返回 |

---

## 3. POST /api/passkey/delete

删除 Passkey（支持批量）。删除后若该用户无剩余 Passkey，级联删除该用户所有数据（钱包、授权状态等）。

**前置步骤**：
1. 调用 `/api/challenge`（purpose=`passkey_delete`）获取 `rawChallenge`（纯随机数）
2. 构造 `userIntentJson = { purpose, userId, credentialIdsToDelete }`
3. 计算 `intentHash = SHA256(rawChallenge + userIntentJson)`，用 Passkey 对 `intentHash` 签名
4. 调用本接口，携带 `rawChallenge + userIntentJson + webauthnSignature`

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |
| `credentialId` | string | 是 | 发起操作的 Passkey 凭证 ID（用于身份验证） |
| `webauthnSignature` | object | 是 | WebAuthn 断言签名（格式见上方"WebAuthn 签名格式"），challenge = intentHash |
| `rawChallenge` | string | 是 | 从 `/api/challenge` 获取的原始挑战值（base64url） |
| `userIntentJson` | string | 是 | 用户意图 JSON 字符串：`{ purpose, userId, credentialIdsToDelete }` |
| `credentialIdsToDelete` | string[] | 是 | 要删除的 Passkey 凭证 ID 列表（必须与 `userIntentJson.credentialIdsToDelete` 一致） |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 固定 `true` |
| `deletedCount` | number | 实际删除的 Passkey 数量 |
| `accountDeleted` | boolean | 删除后无剩余 Passkey 时为 `true`（触发级联删除） |

---

## 4. POST /api/passkey/list

列出用户绑定的所有 Passkey。

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `userId` | string | 用户 ID |
| `passkeys` | array | Passkey 列表 |
| `passkeys[].credentialId` | string | 凭证 ID（base64url） |
| `passkeys[].createdAt` | string | 注册时间（ISO 8601） |
| `passkeys[].signCount` | number | 签名计数器 |

---

## 5. POST /api/wallet/create

创建原生 HD 钱包。Enclave 内部生成助记词，按指定链列表派生多链地址。

**前置步骤**：
1. 调用 `/api/challenge`（purpose=`wallet_create`）获取 `rawChallenge`（纯随机数）
2. 构造 `userIntentJson = { purpose, userId, chains, mnemonicStrength? }`
3. 计算 `intentHash = SHA256(rawChallenge + userIntentJson)`，用 Passkey 对 `intentHash` 签名
4. 调用本接口，携带 `rawChallenge + userIntentJson + webauthnSignature`

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |
| `credentialId` | string | 是 | Passkey 凭证 ID |
| `webauthnSignature` | object | 是 | WebAuthn 断言签名（格式见上方"WebAuthn 签名格式"），challenge = intentHash |
| `rawChallenge` | string | 是 | 从 `/api/challenge` 获取的原始挑战值（base64url） |
| `userIntentJson` | string | 是 | 用户意图 JSON 字符串：`{ purpose, userId, chains, mnemonicStrength? }` |
| `walletId` | string | 否 | 钱包 ID。不传则服务端随机生成（UUIDv4） |
| `chains` | object[] | 是 | 链配置数组，指定需要派生地址的链（必须与 `userIntentJson.chains` 一致） |
| `mnemonicStrength` | number | 否 | 助记词强度，默认 128（12 词），可选 256（24 词）（必须与 `userIntentJson.mnemonicStrength` 一致） |

`chains` 数组元素字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `chainId` | string | 是 | 链 ID（如 `"1"` 表示以太坊主网） |
| `coinType` | number | 否 | BIP-44 coin type（如 60 表示 ETH） |
| `derivationPath` | string | 否 | 自定义派生路径（如 `"m/44'/60'/0'/0/0"`） |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 固定 `true` |
| `walletId` | string | 钱包 ID |
| `addresses` | array | 派生的各链地址列表 |
| `addresses[].chainId` | string | 链 ID |
| `addresses[].address` | string | 派生地址 |

---

## 6. POST /api/wallet/list

列出用户的所有钱包（仅需平台签名，无需 WebAuthn）。

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 固定 `true` |
| `wallets` | array | 钱包列表 |
| `wallets[].walletId` | string | 钱包 ID |
| `wallets[].type` | string | 钱包类型（`native` 或 `imported`） |
| `wallets[].createdAt` | string | 创建时间（ISO 8601） |

---

## 7. POST /api/wallet/get

查询指定钱包的详细信息（含地址列表）。仅需平台签名，无需 WebAuthn。

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |
| `walletId` | string | 是 | 钱包 ID |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `userId` | string | 用户 ID |
| `walletId` | string | 钱包 ID |
| `wallet` | object | 钱包详情 |
| `wallet.walletId` | string | 钱包 ID |
| `wallet.type` | string | 钱包类型 |
| `wallet.addresses` | array | 地址列表 |
| `wallet.addresses[].chainId` | string | 链 ID |
| `wallet.addresses[].address` | string | 地址 |

---

## 8. POST /api/wallet/delete

删除整个钱包容器及其下所有逻辑钱包。

**前置步骤**：
1. 调用 `/api/challenge`（purpose=`wallet_delete`）获取 `rawChallenge`（纯随机数）
2. 构造 `userIntentJson = { purpose, userId, walletId }`
3. 计算 `intentHash = SHA256(rawChallenge + userIntentJson)`，用 Passkey 对 `intentHash` 签名
4. 调用本接口，携带 `rawChallenge + userIntentJson + webauthnSignature`

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |
| `credentialId` | string | 是 | Passkey 凭证 ID |
| `webauthnSignature` | object | 是 | WebAuthn 断言签名（格式见上方"WebAuthn 签名格式"），challenge = intentHash |
| `rawChallenge` | string | 是 | 从 `/api/challenge` 获取的原始挑战值（base64url） |
| `userIntentJson` | string | 是 | 用户意图 JSON 字符串：`{ purpose, userId, walletId }` |
| `walletId` | string | 是 | 要删除的钱包 ID（必须与 `userIntentJson.walletId` 一致） |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 固定 `true` |
| `walletId` | string | 已删除的钱包 ID |

---

## 9. POST /api/wallet/entry/delete

按 address 精确删除钱包容器内的单个逻辑钱包。

**前置步骤**：
1. 调用 `/api/challenge`（purpose=`wallet_entry_delete`）获取 `rawChallenge`（纯随机数）
2. 构造 `userIntentJson = { purpose, userId, walletId, address }`
3. 计算 `intentHash = SHA256(rawChallenge + userIntentJson)`，用 Passkey 对 `intentHash` 签名
4. 调用本接口，携带 `rawChallenge + userIntentJson + webauthnSignature`

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |
| `credentialId` | string | 是 | Passkey 凭证 ID |
| `webauthnSignature` | object | 是 | WebAuthn 断言签名（格式见上方"WebAuthn 签名格式"），challenge = intentHash |
| `rawChallenge` | string | 是 | 从 `/api/challenge` 获取的原始挑战值（base64url） |
| `userIntentJson` | string | 是 | 用户意图 JSON 字符串：`{ purpose, userId, walletId, address }` |
| `walletId` | string | 是 | 钱包容器 ID（必须与 `userIntentJson.walletId` 一致） |
| `address` | string | 是 | 要删除的逻辑钱包地址（必须与 `userIntentJson.address` 一致） |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 固定 `true` |
| `walletId` | string | 钱包容器 ID |
| `address` | string | 已删除的逻辑钱包地址 |

---

## 10. POST /api/auth/status

查询授权的累计用量和状态。

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |
| `authorizationId` | string | 是 | 授权 ID |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `authorizationId` | string | 授权 ID |
| `userId` | string | 用户 ID |
| `grantee` | string | 被授权方地址 |
| `status` | string | 状态：`active` / `revoked` / `expired` / `exceeded` |
| `totalAmountUsed` | string | 累计已用总额 |
| `totalCountUsed` | number | 累计已用次数 |
| `createdAt` | string | 创建时间（ISO 8601） |
| `updatedAt` | string | 最后更新时间（ISO 8601） |
| `tokenStates` | array | 分 token 用量明细 |
| `tokenStates[].chainId` | string | 链 ID |
| `tokenStates[].tokenAddress` | string | 代币合约地址 |
| `tokenStates[].amountUsed` | string | 该 token 已用额度 |

---

## 11. POST /api/tx/sign

交易签名。服务端执行授权验证后，用 enclave 内私钥签名交易。

支持两种模式，通过 `transaction` 对象中是否包含 `rawTxHex` 字段来区分：
- **模式一（txParams）**：平台提供结构化交易参数，所有字段被视为可信
- **模式二/三（rawTxHex）**：平台提供原始交易字节，服务端从 raw bytes 解析所有鉴权相关字段（不信任平台提供的显式字段）

> **重要**：`authorizationJson` 必须是**字符串**（不含 `webauthnSignature`），`webauthnSignature` 单独传。
> 客户端对 `authorizationJson` 字符串计算 SHA256 哈希作为 WebAuthn challenge，服务端对同一字符串计算哈希验证签名。
> 这样才能保证客户端和服务端对同一字符串计算哈希，WebAuthn 验证才能通过。

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `authorizationJson` | string | 是 | 授权 JSON 字符串（不含 `webauthnSignature`，用于计算哈希） |
| `webauthnSignature` | object | 是 | WebAuthn 断言签名（格式见上方"WebAuthn 签名格式"） |
| `transaction` | object | 是 | 交易对象（子字段见下，两种模式二选一） |
| `guid` | string | 是 | 请求唯一 ID（防重放） |

`authorizationJson` 字符串解析后的字段（不含 `webauthnSignature`）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |
| `authorizationId` | string | 是 | 授权 ID |
| `grantee` | string[] | 是 | 被授权方地址数组 |
| `credentialId` | string | 是 | Passkey 凭证 ID |
| `scope` | object | 是 | 授权范围（targetAddresses, signingWallets, tokenRestrictions 等） |
| `timePolicy` | object | 是 | 时间策略（deadline, cronWindows 等） |
| `revocationPolicy` | object | 是 | 撤销策略（`allowContractUnavailable` 必填） |
| `createdAt` | string | 是 | 创建时间（ISO 8601） |

**`transaction` 子字段（模式一：txParams，结构化参数）**：

| 子字段 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| `chainId` | string | 是 | 链 ID |
| `fromAddress` | string | 是 | 发送方地址 |
| `toAddress` | string | 是 | 接收方地址 |
| `amount` | string | 是 | 交易金额 |
| `tokenAddress` | string | 是 | 代币合约地址（原生代币用 `"{chainId}_native"`，如 `"1_native"`） |
| `type` | number | 是 | 交易类型（`0`=Legacy，`2`=EIP-1559），必须显式提供 |
| `data` | string | 否 | 交易 data 字段 |
| `nonce` | number | 否 | 交易 nonce |
| `gasLimit` | string | 否 | gas 上限 |
| `gasPrice` | string | 否 | gas 价格（Legacy 模式） |
| `maxFeePerGas` | string | 否 | 最大 gas 费用（EIP-1559 模式） |
| `maxPriorityFeePerGas` | string | 否 | 最大优先费用（EIP-1559 模式） |
| `value` | string | 否 | 原生代币转账金额（Wei 字符串） |

**`transaction` 子字段（模式二/三：rawTxHex，原始字节）**：

| 子字段 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| `rawTxHex` | string | 是 | 原始交易字节（hex 编码，含 `0x` 前缀）。服务端从 raw bytes 解析 chainId、toAddress、amount、tokenAddress 等鉴权字段，不信任平台提供的显式字段 |
| `walletAddress` | string | 是 | 签名钱包地址（发送方地址，用于从 DB 查询私钥） |

> **模式二/三安全说明**：
> - 服务端从 `rawTxHex` 解析出的字段（chainId、toAddress、amount、tokenAddress）用于鉴权，平台无法通过显式字段绕过限制
> - 支持已识别的以太坊交易类型（Legacy/EIP-2930/EIP-1559/EIP-7702）和任意二进制数据
> - 已识别类型（模式二）：对预构造的字节直接签名，返回 `signedTransaction`
> - 不可识别类型（模式三）：做以太坊格式签名（`eth_sign`），返回 `signedTransaction`

**data 字段（JSON.parse 后，成功）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | `true` 表示签名成功 |
| `signedTransaction` | string | 已签名的交易原始数据（hex） |
| `txHash` | string | 交易哈希（模式三任意数据签名时为消息哈希） |

**data 字段（JSON.parse 后，授权验证失败）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | `false` |
| `step` | number | 失败的验证步骤编号 |
| `reason` | string | 失败原因描述 |

---

## 12. POST /api/key/import/init

密钥导入第一步。初始化密钥交换会话，支持两种密钥交换模式：

- **ECDH 模式（默认）**：不传 `rsaPublicKey`，Enclave 生成 ECDH 密钥对（prime256v1），返回公钥。客户端用此公钥派生共享密钥后加密传输私钥。
- **RSA 模式**：传入 `rsaPublicKey`（客户端 RSA 公钥，PEM 或 Base64 DER），Enclave 生成 256 位 AES 密钥，用 RSA/PKCS1Padding（PKCS#1 v1.5）加密后返回。客户端用自己的 RSA 私钥解密得到 AES 密钥，用于后续数据加密。

支持的 RSA 公钥位数：1024、2048、3072（自动从公钥检测，无需额外指定）。

**安全要求**：两步导入均强制要求用户 WebAuthn Passkey 签名，平台无法绕过用户授权静默导入私钥。

**前置步骤**：
1. 调用 `/api/challenge`（purpose=`key_import_init`）获取 `rawChallenge`（纯随机数）
2. 构造 `userIntentJson = { purpose: "key_import_init", userId, importType }`
3. 计算 `intentHash = SHA256(rawChallenge + userIntentJson)`，用 Passkey 对 `intentHash` 签名
4. 调用本接口，携带 `rawChallenge + userIntentJson + webauthnSignature`

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |
| `importType` | string | 是 | 导入类型：`private_key`（纯私钥）、`mnemonic`（助记词）或 `batch`（批量） |
| `rsaPublicKey` | string | 否 | 客户端 RSA 公钥（PEM 或 Base64 DER）。传入则走 RSA 模式，不传则默认 ECDH |
| `credentialId` | string | 是 | Passkey 凭证 ID（base64url 编码） |
| `webauthnSignature` | object | 是 | WebAuthn 断言签名（格式见上方"WebAuthn 签名格式"），challenge = intentHash |
| `rawChallenge` | string | 是 | 从 `/api/challenge` 获取的原始挑战值（base64url） |
| `userIntentJson` | string | 是 | 用户意图 JSON 字符串：`{ purpose: "key_import_init", userId, importType }` |

**data 字段（JSON.parse 后，ECDH 模式）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `sessionId` | string | 会话 ID |
| `keyType` | string | 固定 `"ecdh"` |
| `enclavePublicKey` | string | Enclave 的 ECDH 公钥（prime256v1，未压缩格式 hex，04 开头） |

**data 字段（JSON.parse 后，RSA 模式）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `sessionId` | string | 会话 ID |
| `keyType` | string | `"rsa-1024"` / `"rsa-2048"` / `"rsa-3072"` |
| `encryptedAESKey` | string | 用客户端 RSA 公钥加密后的 AES-256 密钥（Base64） |

---

## 13. POST /api/key/import/complete

密钥导入第二步。客户端用对称密钥加密私钥/助记词后提交，Enclave 解密并存储。

解密方式由会话的 `keyType` 自动决定：
- **ECDH**：需传 `peerPublicKey`，服务端用 ECDH 共享密钥解密
- **RSA**：无需 `peerPublicKey`，服务端用已存储的 AES 密钥解密

**安全要求**：强制要求用户 WebAuthn Passkey 签名，`sessionId` 必须纳入 `userIntentJson` 防止中途替换。

**前置步骤**：
1. 调用 `/api/challenge`（purpose=`key_import_complete`）获取 `rawChallenge`（纯随机数）
2. 构造 `userIntentJson = { purpose: "key_import_complete", userId, sessionId, walletId, chains }`（`walletId`/`chains` 不指定时填 `null`）
3. 计算 `intentHash = SHA256(rawChallenge + userIntentJson)`，用 Passkey 对 `intentHash` 签名
4. 调用本接口，携带 `rawChallenge + userIntentJson + webauthnSignature`

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sessionId` | string | 是 | 初始化时返回的会话 ID（必须与 `userIntentJson.sessionId` 一致） |
| `peerPublicKey` | string | ECDH 时必填 | 客户端的 ECDH 公钥（hex，04 开头未压缩格式），RSA 模式不需要 |
| `encryptedData` | object | 是 | AES-256-GCM 加密后的私钥/助记词数据 |
| `walletId` | string | 否 | 钱包 ID。不传则随机生成 |
| `chains` | object[] | 否 | 链配置数组（助记词导入时用于派生多链地址） |
| `userId` | string | 是 | 用户 ID（用于 Passkey 归属验证，必须与 `userIntentJson.userId` 一致） |
| `credentialId` | string | 是 | Passkey 凭证 ID（base64url 编码） |
| `webauthnSignature` | object | 是 | WebAuthn 断言签名（格式见上方"WebAuthn 签名格式"），challenge = intentHash |
| `rawChallenge` | string | 是 | 从 `/api/challenge` 获取的原始挑战值（base64url） |
| `userIntentJson` | string | 是 | 用户意图 JSON 字符串：`{ purpose: "key_import_complete", userId, sessionId, walletId, chains }`（`walletId`/`chains` 不指定时填 `null`，必须与实际请求参数一致） |

`encryptedData` 子字段：

| 子字段 | 类型 | 说明 |
|--------|------|------|
| `ciphertext` | string | AES-256-GCM 加密后的数据（Base64） |
| `iv` | string | 初始化向量（Base64，12 字节） |
| `authTag` | string | GCM 认证标签（Base64，16 字节） |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 固定 `true` |
| `walletId` | string | 导入的钱包 ID |
| `addresses` | array | 派生的地址列表 |
| `addresses[].chainId` | string | 链 ID |
| `addresses[].address` | string | 地址 |

---

## 14. POST /api/key/export/init

密钥导出第一步。初始化批量密钥交换会话，加密多个钱包数据并一次性返回。需 WebAuthn 签名确认。支持两种模式，两种模式都在 init 时加密并返回数据：

- **ECDH 模式**：传 `peerPublicKey`，Enclave 生成 ECDH 密钥对，算出共享密钥加密钱包数据，返回 `enclavePublicKey` + `encryptedData`。
- **RSA 模式**：传 `rsaPublicKey`，Enclave 生成 AES-256 密钥加密钱包数据，RSA/PKCS1Padding 加密 AES 密钥，返回 `encryptedAESKey` + `encryptedData`。
- 二者必传其一（`peerPublicKey` 或 `rsaPublicKey`），优先 `rsaPublicKey`。

**批量导出说明**：
- `exportInfo` 是一个数组，每个元素指定一个 `walletId` 及其要导出的 `addresses`
- `addresses` 为空数组时，导出该 `walletId` 下的**所有**私钥
- `addresses` 有值时，每个元素可以是：
  - 纯地址字符串 `"0x..."`：导出该地址在所有链上的私钥
  - `{address, chainId}` 对象：精确导出指定链上的指定地址私钥（同一地址在不同链上的私钥可以分别导出）
- 所有钱包数据加密为一个 JSON 对象后一次性返回，只需一次 WebAuthn 签名

**前置步骤**：
1. 调用 `/api/challenge`（purpose=`key_export`）获取 `rawChallenge`（纯随机数）
2. 构造 `userIntentJson`（ECDH：`{ purpose, userId, exportInfo, peerPublicKey }` 或 RSA：`{ purpose, userId, exportInfo, rsaPublicKey }`）
3. 计算 `intentHash = SHA256(rawChallenge + userIntentJson)`，用 Passkey 对 `intentHash` 签名
4. 调用本接口，携带 `rawChallenge + userIntentJson + webauthnSignature`

> **注意**：`peerPublicKey`/`rsaPublicKey` 必须纳入 `userIntentJson`，防止中间人替换密钥交换参数。`exportInfo` 也必须纳入 `userIntentJson`，防止平台替换导出范围。

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |
| `credentialId` | string | 是 | Passkey 凭证 ID |
| `webauthnSignature` | object | 是 | WebAuthn 断言签名（格式见上方"WebAuthn 签名格式"），challenge = intentHash |
| `rawChallenge` | string | 是 | 从 `/api/challenge` 获取的原始挑战值（base64url） |
| `userIntentJson` | string | 是 | 用户意图 JSON 字符串（含 exportInfo、peerPublicKey 或 rsaPublicKey） |
| `exportInfo` | array | 是 | 导出信息数组（必须与 `userIntentJson.exportInfo` 一致） |
| `peerPublicKey` | string | ECDH 时必填 | 客户端的 ECDH 公钥（hex，04 开头），与 `rsaPublicKey` 二选一（必须与 `userIntentJson.peerPublicKey` 完全一致） |
| `rsaPublicKey` | string | RSA 时必填 | 客户端 RSA 公钥（PEM 或 Base64 DER），与 `peerPublicKey` 二选一（必须与 `userIntentJson.rsaPublicKey` 完全一致） |

`exportInfo` 数组元素字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `walletId` | string | 是 | 钱包容器 ID |
| `addresses` | array | 是 | 要导出的地址列表。空数组表示导出该 walletId 下所有私钥。元素可为：纯地址字符串（不限链）或 `{address: string, chainId: number}` 对象（精确匹配指定链） |

`addresses` 元素格式（二选一）：

| 格式 | 示例 | 说明 |
|------|------|------|
| 纯地址字符串 | `"0x1234..."` | 导出该地址在所有链上的私钥 |
| `{address, chainId}` 对象 | `{"address": "0x1234...", "chainId": 1}` | 精确导出指定链（chainId=1 即 ETH 主网）上的私钥 |

**data 字段（JSON.parse 后，ECDH 模式）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `sessionId` | string | 导出会话 ID |
| `keyType` | string | 固定 `"ecdh"` |
| `enclavePublicKey` | string | Enclave 的 ECDH 公钥（prime256v1，未压缩 hex） |
| `encryptedData` | object | AES-256-GCM 加密的钱包数据（含 ciphertext, iv, authTag） |

**data 字段（JSON.parse 后，RSA 模式）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `sessionId` | string | 导出会话 ID |
| `keyType` | string | `"rsa-1024"` / `"rsa-2048"` / `"rsa-3072"` |
| `encryptedAESKey` | string | 用客户端 RSA 公钥加密后的 AES-256 密钥（Base64） |
| `encryptedData` | object | AES-256-GCM 加密的钱包数据（含 ciphertext, iv, authTag） |

**encryptedData 解密后的钱包数据格式（批量）**：

> **结构说明**：
> - 顶层 `wallets` 数组按 `walletId` 分组，每个元素代表一个**钱包容器**
> - 每个容器内的 `wallets` 数组包含该容器下的所有**逻辑钱包**（一个助记词 = 一个逻辑钱包，纯私钥钱包每个私钥独立）
> - 每个逻辑钱包的 `keys` 数组包含该助记词下所有链的私钥（或纯私钥钱包的单个私钥）
> - 纯私钥钱包（`imported_key`）的 `mnemonic` 为 `null`，`keys` 数组只有一个元素

```json
{
  "userId": "user-xxx",
  "wallets": [
    {
      "userId": "user-xxx",
      "walletId": "wallet-001",
      "wallets": [
        {
          "walletType": "native",
          "mnemonic": "word1 word2 ... word12",
          "keys": [
            { "chainId": 1, "coinType": 60, "address": "0x...", "privateKey": "0x...", "derivationPath": "m/44'/60'/0'/0/0" },
            { "chainId": 137, "coinType": 60, "address": "0x...", "privateKey": "0x...", "derivationPath": "m/44'/60'/0'/0/0" }
          ]
        },
        {
          "walletType": "imported_mnemonic",
          "mnemonic": "another word1 word2 ... word12",
          "keys": [
            { "chainId": 1, "coinType": 60, "address": "0x...", "privateKey": "0x...", "derivationPath": "m/44'/60'/0'/0/0" }
          ]
        },
        {
          "walletType": "imported_key",
          "mnemonic": null,
          "keys": [
            { "chainId": 1, "coinType": 60, "address": "0x...", "privateKey": "0x...", "derivationPath": null }
          ]
        }
      ]
    },
    {
      "userId": "user-xxx",
      "walletId": "wallet-002",
      "wallets": [
        {
          "walletType": "native",
          "mnemonic": "word1 word2 ... word12",
          "keys": [
            { "chainId": 10, "coinType": 60, "address": "0x...", "privateKey": "0x...", "derivationPath": "m/44'/60'/0'/0/0" }
          ]
        }
      ]
    }
  ]
}
```

---

## 15. POST /api/key/export/complete

密钥导出第二步。客户端确认已收到并解密数据后，通知 SGX 删除导出过的钱包数据。

两种模式都一样：数据已在 init 时返回，complete 仅删除钱包，不返回加密数据。

> ⚠️ **安全说明**：此操作会**不可逆地删除钱包**，必须验证用户 WebAuthn 签名，防止攻击者拿到 `sessionId` 后在用户未成功解密前触发钱包删除。

**前置步骤**：
1. 调用 `/api/challenge`（purpose=`key_export_confirm`）获取 `rawChallenge`（纯随机数）
2. 构造 `userIntentJson = { purpose, userId, sessionId }`
3. 计算 `intentHash = SHA256(rawChallenge + userIntentJson)`，用 Passkey 对 `intentHash` 签名
4. 调用本接口，携带 `rawChallenge + userIntentJson + webauthnSignature`

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |
| `credentialId` | string | 是 | Passkey 凭证 ID |
| `webauthnSignature` | object | 是 | WebAuthn 断言签名（格式见上方"WebAuthn 签名格式"），challenge = intentHash |
| `rawChallenge` | string | 是 | 从 `/api/challenge` 获取的原始挑战值（base64url） |
| `userIntentJson` | string | 是 | 用户意图 JSON 字符串：`{ purpose, userId, sessionId }` |
| `sessionId` | string | 是 | 初始化时返回的导出会话 ID（必须与 `userIntentJson.sessionId` 一致，防止 sessionId 被替换） |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 固定 `true` |
| `walletIds` | string[] | 已删除的钱包 ID 列表 |
| `deletedCount` | number | 实际删除的数据库行数 |
| `deleted` | boolean | 是否成功删除（deletedCount > 0） |

---

## 16. POST /api/evidence/get

查询单条授权原文记录，用于争议取证。

payload 区分两种发起方式：
- **平台发起**：payload 不含 `credentialId`/`webauthnSignature`，服务端验证平台地址在该授权的 grantee 列表中
- **用户发起（平台转发）**：payload 含 `credentialId` + `webauthnSignature`，额外验证 WebAuthn 签名

**用户发起时的前置步骤**：
1. 调用 `/api/challenge`（purpose=`evidence_query`）获取 `rawChallenge`（纯随机数）
2. 构造 `userIntentJson = { purpose, userId, authorizationId? }`
3. 计算 `intentHash = SHA256(rawChallenge + userIntentJson)`，用 Passkey 对 `intentHash` 签名
4. 调用本接口，携带 `rawChallenge + userIntentJson + webauthnSignature`

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |
| `authorizationId` | string | 是 | 授权 ID |
| `credentialId` | string | 否 | Passkey 凭证 ID（用户发起时必填） |
| `webauthnSignature` | object | 否 | WebAuthn 断言签名（用户发起时必填，格式见上方"WebAuthn 签名格式"），challenge = intentHash |
| `rawChallenge` | string | 否 | 从 `/api/challenge` 获取的原始挑战值（用户发起时必填） |
| `userIntentJson` | string | 否 | 用户意图 JSON 字符串（用户发起时必填）：`{ purpose, userId, authorizationId? }` |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `authorizationId` | string | 授权 ID |
| `userId` | string | 用户 ID |
| `grantee` | string[] | 被授权方地址列表 |
| `authorizationJson` | object | 授权原文 JSON |
| `authorizationHash` | string | 授权原文的 SHA256 哈希（base64url） |
| `createdAt` | string | 创建时间（ISO 8601） |

---

## 17. POST /api/evidence/list

列出用户的所有授权记录摘要，用于争议取证。payload 区分方式同接口 17。

**用户发起时的前置步骤**：
1. 调用 `/api/challenge`（purpose=`evidence_query`）获取 `rawChallenge`（纯随机数）
2. 构造 `userIntentJson = { purpose, userId }`（不含 `authorizationId`）
3. 计算 `intentHash = SHA256(rawChallenge + userIntentJson)`，用 Passkey 对 `intentHash` 签名
4. 调用本接口，携带 `rawChallenge + userIntentJson + webauthnSignature`

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `userId` | string | 是 | 用户 ID |
| `credentialId` | string | 否 | Passkey 凭证 ID（用户发起时必填） |
| `webauthnSignature` | object | 否 | WebAuthn 断言签名（用户发起时必填，格式见上方"WebAuthn 签名格式"），challenge = intentHash |
| `rawChallenge` | string | 否 | 从 `/api/challenge` 获取的原始挑战值（用户发起时必填） |
| `userIntentJson` | string | 否 | 用户意图 JSON 字符串（用户发起时必填）：`{ purpose, userId }` |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `userId` | string | 用户 ID |
| `records` | array | 授权记录摘要列表 |
| `records[].authorizationId` | string | 授权 ID |
| `records[].grantee` | string[] | 被授权方地址列表 |
| `records[].authorizationHash` | string | 授权原文的 SHA256 哈希 |
| `records[].createdAt` | string | 创建时间（ISO 8601） |

---

## 18. POST /api/enclave/info

查询 Enclave 公开信息。**无需鉴权**，不需要 payload/platformSignature。

**payload 字段定义**：无（HTTP body 可为空或任意 JSON）

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `enclaveWhitelist` | array | Enclave 白名单列表（mrenclave/mrsigner 等） |
| `codeRepository` | string | 代码仓库地址 |
| `runtimeParams` | object | 运行时参数（session TTL、attestation 配置等） |

---

## 19. POST /api/admin/userId/list

管理员接口：列出所有用户的授权 ID 列表（不含敏感信息）。支持分页。

**payload 字段定义**：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `page` | number | 否 | 页码，从 1 开始，默认 1 |
| `pageSize` | number | 否 | 每页条数，默认 100，最大 1000 |

**data 字段（JSON.parse 后）**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 固定 `true` |
| `users` | array | 用户列表 |
| `users[].userId` | string | 用户 ID |
| `users[].authorizationIds` | string[] | 该用户的授权 ID 列表 |
| `totalUsers` | number | 总用户数 |
| `page` | number | 当前页码 |
| `pageSize` | number | 每页条数 |
| `totalPages` | number | 总页数 |

---

## 附录 A：接口路由汇总

**主要接口（推荐使用）**：

| 路由 | 说明 | 鉴权级别 |
|------|------|---------|
| `POST /api/challenge` | **统一挑战值接口**（所有 purpose） | 平台签名（非 register 时 + Passkey 归属验证） |
| `POST /api/passkey/register/complete` | Passkey 注册 - 提交 WebAuthn 注册响应 | 平台签名 |
| `POST /api/passkey/delete` | Passkey 删除 | 平台签名 + WebAuthn 签名 |
| `POST /api/passkey/list` | Passkey 列表查询 | 平台签名 |
| `POST /api/wallet/create` | 钱包创建 | 平台签名 + WebAuthn 签名 |
| `POST /api/wallet/list` | 钱包列表查询 | 平台签名 |
| `POST /api/wallet/get` | 钱包详情查询 | 平台签名 |
| `POST /api/wallet/delete` | 钱包删除 | 平台签名 + WebAuthn 签名 |
| `POST /api/wallet/entry/delete` | 单个逻辑钱包删除 | 平台签名 + WebAuthn 签名 |
| `POST /api/auth/status` | 授权状态查询 | 平台签名 |
| `POST /api/tx/sign` | 交易签名 | 平台签名 + 授权验证 + WebAuthn 签名 |
| `POST /api/key/import/init` | 密钥导入 - 初始化（私钥/助记词） | 平台签名（用户端导入时 + WebAuthn 签名） |
| `POST /api/key/import/complete` | 密钥导入 - 完成 | 平台签名（用户端导入时 + WebAuthn 签名） |
| `POST /api/key/export/init` | 密钥导出 - 初始化（原状导出） | 平台签名 + WebAuthn 签名 |
| `POST /api/key/export/complete` | 密钥导出 - 确认删除（不可逆） | 平台签名 + WebAuthn 签名 |
| `POST /api/evidence/get` | 取证查询 - 单条授权记录 | 平台签名+grantee **或** WebAuthn 签名 |
| `POST /api/evidence/list` | 取证查询 - 授权记录列表 | 平台签名 **或** WebAuthn 签名 |
| `POST /api/enclave/info` | Enclave 信息查询 | 无需鉴权 |
| `POST /api/admin/userId/list` | 管理员用户列表 | 平台签名 |


---

## 附录 B：写操作流程（需要 WebAuthn 签名）

以下写操作需要**两步**完成（以 `wallet_create` 为例）：

**步骤 1**：调用 `/api/challenge` 获取 `rawChallenge`（纯随机数）

```json
// payload
{
  "purpose": "wallet_create",
  "userId": "user-xxx",
  "credentialId": "cred-xxx"
}
// 响应 data
{
  "challenge": "rawChallenge_base64url",
  "userId": "user-xxx",
  "expiresAt": "2026-04-06T06:00:00.000Z"
}
```

**步骤 2**：客户端构造 `userIntentJson`，计算 `intentHash`，用 Passkey 签名，然后调用写操作接口

```
userIntentJson = JSON.stringify({ purpose, userId, chains, ... })
intentHash = SHA256(rawChallenge + userIntentJson)
webauthnSignature = Passkey.sign(intentHash)
```

```json
// payload（以 wallet/create 为例）
{
  "userId": "user-xxx",
  "credentialId": "cred-xxx",
  "rawChallenge": "rawChallenge_base64url",
  "userIntentJson": "{\"purpose\":\"wallet_create\",\"userId\":\"user-xxx\",\"chains\":[{\"chainId\":\"1\"}]}",
  "webauthnSignature": {
    "authenticatorData": "base64url_authenticator_data",
    "clientDataJSON": "base64url_client_data_json_with_intentHash",
    "signature": "base64url_der_signature"
  },
  "chains": [{ "chainId": "1" }]
}
```

> **业务接口验证逻辑**：
> 1. 根据 `rawChallenge` 查询挑战值记录，不存在则拒绝（防重放）
> 2. 计算 `intentHash = SHA256(rawChallenge + userIntentJson)`
> 3. 验证 WebAuthn 签名（`expectedChallenge = intentHash`）
> 4. 解析 `userIntentJson`，逐字段与实际业务参数比对（防止平台替换参数）
> 5. 消费（删除）挑战值记录

**安全保证**：
- `intentHash = SHA256(rawChallenge + userIntentJson)` 将随机性（防重放）和业务语义（防参数篡改）绑定在一起
- 平台无法在用户签名后替换业务参数，因为任何修改都会导致 intentHash 不匹配
- `rawChallenge` 确保每次挑战值唯一，防止重放攻击
- `userIntentJson` 中的参数必须与实际业务请求参数一致，服务端逐字段比对

---

## 附录 C：椭圆曲线使用规则

| 场景 | 曲线 |
|------|------|
| ECDH 密钥交换 | prime256v1 (P-256) |
| WebAuthn 签名 | P-256 (secp256r1) |
| 平台签名 | secp256k1 |
| 链上交易签名 | secp256k1 |

---

## 附录 D：环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `SGX_HTTP_PORT` | HTTP 服务监听端口 | `3000` |
| `CONTRACT_RPC_URL` | 区块链 RPC 地址 | - |
| `CONTRACT_CHAIN_ID` | 链 ID | - |
| `CONTRACT_ADDRESS` | WalletTrustContract 合约地址 | - |
| `PLATFORM_WHITELIST` | 平台白名单地址（逗号分隔） | - |
| `FREEZE_DURATION_SECONDS` | 账户冻结时长（秒），合约 `runtimeParams.security.freezeDurationSeconds` 优先 | `259200`（72 小时） |
| `RUNTIME_PARAMS` | 运行时参数 JSON（session TTL 等） | `{}` |
| `SYNC_NODES` | 同步节点 WSS 地址（逗号分隔，可选） | - |

---

## 附录 E：账户冻结机制

### 触发条件

当已有账户（userId 已存在）通过 `/api/passkey/register/complete` 场景A（无 Passkey，purpose=register）补绑 Passkey 时，若该账户下存在至少一个钱包（助记词钱包或纯私钥钱包），则自动触发账户冻结。

**不触发冻结的情况**：
- 全新用户（userId 不存在）
- 已有账户但无钱包
- 场景B（已有 Passkey，添加新 Passkey）

### 冻结规则

> **核心原则**：冻结不会自动解除。冻结期过后，必须使用冻结时绑定的 Passkey 发起一条带签名的请求，请求成功后才能永久解除冻结。否则账户将一直处于冻结状态。

**冻结时长配置**（优先级从高到低）：

| 来源 | 配置路径 | 说明 |
|------|---------|------|
| 智能合约 | `runtimeParams.security.freezeDurationSeconds` | 合约配置，优先级最高 |
| 环境变量 | `FREEZE_DURATION_SECONDS` | 未配置合约时使用 |
| 代码默认值 | - | 259200 秒（72 小时） |

| 阶段 | 时间范围 | 行为 |
|------|---------|------|
| 冻结期 | 冻结开始后配置时长内（默认 72 小时） | 该 userId 的**所有请求**均被拒绝（HTTP 403） |
| 解冻条件期 | 冻结期过后 | 仅允许使用冻结时绑定的 Passkey（credentialId 匹配）发起的**带 webauthnSignature 的请求**；无签名的请求仍然被拒绝 |
| 解冻 | 冻结期过后，使用绑定的 Passkey 发起带签名的请求成功 | 永久解除冻结，所有接口恢复正常 |

**冻结期过后详细规则**：

| 请求类型 | credentialId 匹配 | webauthnSignature | 结果 |
|---------|-------------------|-------------------|------|
| 任意 | 不匹配 | - | 拒绝（403） |
| 任意 | 匹配 | 无（如 `/api/challenge`、`/api/wallet/list`） | 拒绝（403） |
| 任意 | 匹配 | 有 | 允许，成功后永久解除冻结 |

### 豁免接口

以下接口不受账户冻结影响，即使账户被冻结也可正常调用：

| 接口 | 说明 |
|------|------|
| `/api/enclave/info` | Enclave 信息查询（无需鉴权） |
| `/api/admin/userId/list` | 管理员用户列表（平台签名） |

### 冻结响应格式

冻结期间被拒绝的请求返回 HTTP 403：

```json
{
  "error": "Account is frozen: new passkey bound to existing account with wallets, account suspended until 2026-04-11 12:00:00"
}
```

冻结期过后无 webauthnSignature 的请求返回 HTTP 403：

```json
{
  "error": "Account is frozen: passkey signature required to unfreeze account"
}
```

冻结期过后 credentialId 不匹配的请求返回 HTTP 403：

```json
{
  "error": "Account is frozen: request must use the passkey that was bound during registration to unfreeze account"
}
```

### 注册接口冻结响应

当 `/api/passkey/register/complete` 触发冻结时，注册本身仍然成功（Passkey 已绑定），但响应中包含冻结信息：

```json
{
  "success": true,
  "userId": "user-xxx",
  "credentialId": "cred-xxx",
  "isFirstPasskey": true,
  "frozen": true,
  "freezeUntil": "2026-04-11 12:00:00"
}
```

### 安全设计说明

此机制旨在防止以下攻击场景：

1. 攻击者获知某用户的 userId
2. 该用户通过平台批量导入创建了账户（有钱包但无 Passkey）
3. 攻击者利用场景A的"已有账户补绑 Passkey"功能，绑定自己的 Passkey
4. 攻击者使用绑定的 Passkey 访问该用户的钱包资产

冻结期（默认 72 小时，可通过合约或环境变量配置）为用户和平台提供了发现异常并采取行动的时间窗口。冻结期结束后，只有使用冻结时绑定的 Passkey 发起带签名的请求才能解除冻结，确保了 Passkey 持有者的资产访问权。冻结不会因时间流逝而自动解除——必须主动发起签名请求验证 Passkey 归属后方可恢复。

### 冻结账户的 Passkey 替换

当账户处于冻结状态时，允许通过 `purpose=register` 重新注册 Passkey。此机制为真正的账户所有人提供了争议缓冲期：

**替换流程**：
1. 调用 `/api/challenge`（`purpose=register`）获取挑战值（冻结账户允许此 purpose）
2. 创建新 Passkey
3. 调用 `/api/passkey/register/complete` 提交注册

**替换效果**：
- 旧的冻结 Passkey 被删除
- 新 Passkey 被注册
- 冻结时间从当前时刻重新计算（默认 72 小时，可配置）
- 冻结的 credentialId 更新为新 Passkey 的 credentialId

**设计目的**：若之前的注册是冒充的，真正的账户所有人可以重新注册，每次重新注册都会延长冻结期，为争议解决提供更多缓冲时间，而不是到期后强制解锁。

**限制**：
- 冻结账户不允许使用 `purpose=register_passkey`（因为无法验证冻结 Passkey 的签名）
- 替换后账户仍然处于冻结状态，需要等待新的冻结期满后才能通过签名请求解冻
