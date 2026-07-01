/**
 * 合约交互客户端模块
 * 负责与 WalletTrustContract 智能合约交互，读取配置、白名单、撤销列表
 * 提供本地缓存机制和定期刷新
 */

import { ethers } from 'ethers';
import { CONTRACT_ABI } from './abi.js';
import https from 'node:https';
import tls from 'node:tls';

/** 默认缓存刷新间隔（毫秒），合约连接成功后的正常刷新间隔 */
const DEFAULT_REFRESH_INTERVAL = 60000;

/** 重连退避参数默认值（实际值从 runtimeParams.reconnect 读取） */
const DEFAULT_RECONNECT_INITIAL_MS = 5000;
const DEFAULT_RECONNECT_INCREMENT_MS = 30000;
const DEFAULT_RECONNECT_MAX_MS = 300000;

/**
 * 判断 RPC URL 是否为本地地址（127.0.0.1 / localhost），本地地址跳过 TLS 证书验证
 */
function isLocalRpcUrl(rpcUrl) {
  try {
    const u = new URL(rpcUrl);
    return u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === '::1';
  } catch (_) {
    return false;
  }
}

/**
 * 创建带自定义 CA 证书验证的 FetchRequest（用于 ethers v6 JsonRpcProvider）
 * 127.0.0.1 / localhost 跳过 TLS 验证（本地测试通常用 HTTP）
 * @param {string} rpcUrl
 * @param {string} caCertBase64 - base64 编码的 CA 证书（PEM 或 DER）
 * @returns {ethers.FetchRequest}
 */
function createFetchRequest(rpcUrl, caCertBase64) {
  const req = new ethers.FetchRequest(rpcUrl);
  const u = new URL(rpcUrl);
  // HTTP (non-TLS) 和本地地址跳过 TLS 验证
  if (u.protocol === 'http:' || isLocalRpcUrl(rpcUrl)) {
    return req;
  }
  // HTTPS 非本地地址必须提供 CA 证书
  if (!caCertBase64) {
    throw new Error(`HTTPS RPC URL ${rpcUrl} requires TLS CA certificate but none provided`);
  }
  // 解码 base64 CA 证书
  const caCertPem = caCertBase64.includes('-----BEGIN')
    ? caCertBase64
    : Buffer.from(caCertBase64, 'base64').toString('utf8');
  const agent = new https.Agent({
    ca: caCertPem,
    rejectUnauthorized: true,
  });
  req.getUrlFunc = ethers.FetchRequest.createGetUrlFunc({ agent });
  return req;
}

/**
 * 判断值是否为纯对象（非数组、非 null、非 Date 等）
 * @param {*} val
 * @returns {boolean}
 */
function isPlainObject(val) {
  return val !== null && typeof val === 'object' && !Array.isArray(val) && !(val instanceof Date);
}

/**
 * 深度合并两个配置对象（合约优先）
 *
 * 合并规则（递归应用）：
 *   - 数组: 取并集（按 JSON.stringify 去重，合约元素优先保留）
 *   - 纯对象: 递归合并子字段
 *   - 标量（字符串、数字、布尔等）: 合约值覆盖环境变量值
 *   - 类型不同: 合约值覆盖环境变量值
 *
 * @param {*} envVal  - 环境变量侧的值（基础）
 * @param {*} contractVal - 合约侧的值（优先）
 * @returns {*} 合并后的值
 */
export function deepMergeConfig(envVal, contractVal) {
  // 只有一方有值时直接返回
  if (contractVal === undefined || contractVal === null) return envVal;
  if (envVal === undefined || envVal === null) return contractVal;

  // 两方都是数组 → 取并集
  if (Array.isArray(envVal) && Array.isArray(contractVal)) {
    const seen = new Map(); // key=JSON.stringify → value
    for (const item of envVal) {
      seen.set(JSON.stringify(item), item);
    }
    for (const item of contractVal) {
      seen.set(JSON.stringify(item), item); // 合约覆盖同值
    }
    return Array.from(seen.values());
  }

  // 两方都是纯对象 → 递归合并
  if (isPlainObject(envVal) && isPlainObject(contractVal)) {
    const merged = { ...envVal };
    for (const key of Object.keys(contractVal)) {
      if (key in merged) {
        merged[key] = deepMergeConfig(merged[key], contractVal[key]);
      } else {
        merged[key] = contractVal[key];
      }
    }
    return merged;
  }

  // 其余情况（标量 or 类型不同）→ 合约优先
  return contractVal;
}

/**
 * ContractClient - 合约交互客户端
 *
 * 功能：
 * 1. 从合约读取所有配置参数（runtimeParams）
 * 2. 读取平台白名单、Enclave 白名单（缓存 + 定期刷新）
 * 3. 读取授权撤销列表（实时查询，不走缓存）
 * 4. 提供 O(1) 白名单查询
 */
export class ContractClient {
  /**
   * @param {Object} options
   * @param {string} options.rpcUrl - 区块链 RPC 地址
   * @param {number|string} options.chainId - 链 ID
   * @param {string} options.contractAddress - 合约部署地址
   * @param {import('./contract-pin-store.js').ContractPinStore} [options.pinStore] - 合约身份钉住存储（可选）
   */
  constructor(options) {
    this._rpcUrl = options.rpcUrl || null;
    this._chainId = options.chainId ? Number(options.chainId) : null;
    this._contractAddress = options.contractAddress || null;
    this._rpcTlsCaCert = options.rpcTlsCaCert || '';

    // 合约身份钉住存储（sealed）。存在时启用 TOFU 钉住 + 永久忽略 env 的安全策略。
    this._pinStore = options.pinStore || null;
    this._pinned = false; // 本次运行是否已加载到钉住记录

    this._provider = null;
    this._contract = null;
    this._refreshTimer = null;
    this._initialized = false;
    this._contractAvailable = false;

    // 重连退避状态
    this._reconnecting = false;           // 当前是否处于重连退避模式
    this._reconnectDelay = DEFAULT_RECONNECT_INITIAL_MS; // 当前重连间隔

    // 缓存数据
    this._cache = {
      runtimeParams: null,
      platformWhitelist: [],
      platformWhitelistSet: new Set(),
      enclaveWhitelist: [],
      enclaveWhitelistMap: new Map(),
      codeRepository: '',
      lastRefreshedAt: 0,
    };
  }

  /**
   * 初始化：读取环境变量和合约配置 → 合并成唯一配置 → 启动定时刷新
   * 合约配置缺失/不全/连不上时只报错，不抛异常，不退出
   */
  async initialize() {
    console.log(`[ContractClient] initialize: rpcUrl=${this._rpcUrl}, contractAddress=${this._contractAddress}, chainId=${this._chainId}`);

    // 0. 合约身份钉住（TOFU）：若曾成功读到过合约，永久锁定该合约身份，
    //    忽略环境变量里的合约连接参数；并预载最近一次已知的安全配置快照。
    this._loadPinAndOverrideIdentity();

    // 1. 读取合约数据（合约配置不全或连不上时为 null，只报错不抛异常）
    let contractData = null;
    if (this._rpcUrl && this._chainId && this._contractAddress) {
      try {
        // 使用 staticNetwork 避免 ethers.js 内部连接共享导致 destroy 互相影响
        const network = ethers.Network.from(this._chainId);
        const fetchReq = createFetchRequest(this._rpcUrl, this._rpcTlsCaCert);
        this._provider = new ethers.JsonRpcProvider(fetchReq, network, { staticNetwork: network });
        this._contract = new ethers.Contract(
          this._contractAddress,
          CONTRACT_ABI,
          this._provider
        );
      } catch (err) {
        console.error(`[ContractClient] initialize: failed to create provider/contract: ${err.message}`);
      }
      if (this._contract) {
        try {
          contractData = await this._readContractData();
          this._contractAvailable = true;
        } catch (err) {
          console.error(`[ContractClient] initialize: failed to read contract data: ${err.message}`);
        }
      }
    } else {
      const missing = [];
      if (!this._rpcUrl) missing.push('CONTRACT_RPC_URL');
      if (!this._chainId) missing.push('CONTRACT_CHAIN_ID');
      if (!this._contractAddress) missing.push('CONTRACT_ADDRESS');
      console.warn(`[ContractClient] initialize: contract config incomplete (missing: ${missing.join(', ')}), skipping contract read`);
    }

    // 2. 应用合约数据。合约不可读时保留已预载的最后已知快照（或初始空缓存），
    //    绝不回退到环境变量提供的配置。
    //    例外：从未配置合约且无 pin 记录时（首次裸启动），允许从 env RUNTIME_PARAMS 启动，
    //    但必须包含必须参数，否则报错退出。
    if (contractData) {
      this._applyContractData(contractData);
    } else if (!this._pinned && !this._rpcUrl && !this._chainId && !this._contractAddress) {
      // 无合约配置且无 pin → 首次裸启动，从 env RUNTIME_PARAMS 加载
      this._loadFromEnv();
    } else {
      console.warn(`[ContractClient] initialize: contract data unavailable, using ${this._pinned ? 'last-known-good snapshot' : 'code defaults'} (env config is NOT used)`);
    }

    // 3. 启动定时器（仅当 RPC URL 已配置时）
    if (this._rpcUrl && this._chainId && this._contractAddress) {
      if (this._contractAvailable) {
        // 连接成功 → 正常刷新间隔
        this._reconnecting = false;
        this._startRefreshTimer();
      } else {
        // 连接失败 → 进入重连退避模式
        this._reconnecting = true;
        this._reconnectDelay = this._getReconnectInitialMs();
        this._scheduleReconnect();
      }
    } else {
      console.log(`[ContractClient] initialize: RPC not configured, no periodic refresh`);
    }

    this._initialized = true;
    console.log(`[ContractClient] initialize: complete (contractAvailable=${this._contractAvailable})`);
  }

  /**
   * 从合约重新读取数据并与环境变量合并
   * 定时刷新回调使用；合约连接不存在时跳过
   */
  async refreshCache() {
    if (!this._contract) return;
    const contractData = await this._readContractData();
    this._contractAvailable = true;
    this._applyContractData(contractData);
  }

  /**
   * 从合约并行读取所有原始数据
   * @returns {Object} 合约原始数据（runtimeParams, codeRepository, whitelists）
   */
  async _readContractData() {
    const [
      runtimeParamsStr,
      codeRepository,
      platformWhitelistRaw,
      enclaveWhitelistRaw,
      migrationTarget,
      rpcTlsCaCert,
    ] = await Promise.all([
      this._contract.getRuntimeParams(),
      this._contract.getCodeRepository(),
      this._contract.getPlatformWhitelist(),
      this._contract.getEnclaveWhitelist(),
      this._contract.getMigrationTarget(),
      this._contract.getRpcTlsCaCert(),
    ]);

    let runtimeParams = null;
    if (runtimeParamsStr && runtimeParamsStr.length > 0) {
      runtimeParams = JSON.parse(runtimeParamsStr);
    }

    let migration = null;
    if (migrationTarget && migrationTarget.rpcUrl && migrationTarget.contractAddress && Number(migrationTarget.chainId) > 0) {
      migration = {
        rpcUrl: migrationTarget.rpcUrl,
        contractAddress: migrationTarget.contractAddress,
        chainId: Number(migrationTarget.chainId),
        rpcTlsCaCert: migrationTarget.rpcTlsCaCert || '',
      };
    }

    return {
      runtimeParams,
      codeRepository,
      platformWhitelist: Array.from(platformWhitelistRaw),
      enclaveWhitelist: enclaveWhitelistRaw.map((item) => ({
        mrenclave: item.mrenclave, mrsigner: item.mrsigner,
        isvprodid: Number(item.isvprodid), isvsvn: Number(item.isvsvn),
        description: item.description,
      })),
      rpcTlsCaCert: rpcTlsCaCert || '',
      migration,
    };
  }

  /**
   * 应用一次成功读到的合约数据：
   *   1. 用合约数据原子替换缓存（合约是唯一真理源；env 不提供 fallback）
   *   2. 持久化钉住记录（身份 + 最近一次已知的安全配置快照）
   * 仅在成功读到合约数据时调用（contractData 非空）。
   * @param {Object} contractData - 从合约读取的数据
   */
  _applyContractData(contractData) {
    this._buildCache(contractData, true);
    this._savePin(contractData);

    // 合约迁移：当前合约声明了迁移目标（rpcUrl + contractAddress + chainId）
    if (contractData.migration) {
      this._handleMigration(contractData.migration).catch((err) => {
        console.error(`[ContractClient] migration failed: ${err.message}`);
      });
    }
  }

  /**
   * 首次裸启动（无合约配置且无 pin）：从环境变量 RUNTIME_PARAMS 加载配置。
   * 必须参数缺失时报错退出。
   */
  _loadFromEnv() {
    const envParamsStr = process.env.RUNTIME_PARAMS;
    let envParams = null;
    if (envParamsStr) {
      try {
        envParams = JSON.parse(envParamsStr);
      } catch (err) {
        console.error(`[ContractClient] _loadFromEnv: failed to parse RUNTIME_PARAMS env: ${err.message}`);
      }
    }

    // 校验必须参数
    const missing = [];
    if (!envParams || !envParams.session || envParams.session.importTtlSeconds == null) {
      missing.push('runtimeParams.session.importTtlSeconds');
    }
    if (!envParams || !envParams.session || envParams.session.exportTtlSeconds == null) {
      missing.push('runtimeParams.session.exportTtlSeconds');
    }
    if (!envParams || !envParams.sync || envParams.sync.numShards == null) {
      missing.push('runtimeParams.sync.numShards');
    }
    if (!envParams || !envParams.attestation || envParams.attestation.allowNonRaTls == null) {
      missing.push('runtimeParams.attestation.allowNonRaTls');
    }

    if (missing.length > 0) {
      console.error(`[ContractClient] _loadFromEnv: no contract configured, no pin data, and missing required env params: ${missing.join(', ')}`);
      console.error(`[ContractClient] _loadFromEnv: set RUNTIME_PARAMS env with required fields or configure CONTRACT_RPC_URL / CONTRACT_CHAIN_ID / CONTRACT_ADDRESS`);
      process.exit(1);
    }

    // 用 env 参数构建缓存（无白名单，无 codeRepository）
    this._rpcTlsCaCert = process.env.CONTRACT_RPC_TLS_CA_CERT || '';
    this._cache = {
      runtimeParams: envParams,
      platformWhitelist: [],
      platformWhitelistSet: new Set(),
      enclaveWhitelist: [],
      enclaveWhitelistMap: new Map(),
      codeRepository: '',
      lastRefreshedAt: 0,
    };
    this._envFallbackMode = true;
    console.warn(`[ContractClient] _loadFromEnv: no contract configured and no pin — started with env RUNTIME_PARAMS (env fallback mode)`);
    console.log(`[ContractClient] _buildCache: platformWhitelist=0, enclaveWhitelist=0, hasRuntimeParams=true, fresh=false, contractAvailable=false`);
  }

  /**
   * 根据合约数据（或快照）构建缓存
   * @param {Object|null} contractData - 合约数据 / 快照（同结构）
   * @param {boolean} markRefreshed - true 表示这是新鲜的合约数据（更新 lastRefreshedAt）；
   *                                  false 表示这是预载的历史快照（保留原 lastRefreshedAt）
   */
  _buildCache(contractData, markRefreshed) {
    const contract = contractData || {};

    const runtimeParams = contract.runtimeParams || null;

    const platformWhitelist = Array.from(contract.platformWhitelist || []);
    const platformWhitelistSet = new Set(
      platformWhitelist.map((addr) => addr.toLowerCase())
    );

    const enclaveWhitelist = Array.from(contract.enclaveWhitelist || []);
    const enclaveWhitelistMap = new Map(
      enclaveWhitelist.map((item) => [item.mrenclave, item])
    );

    const mergedCodeRepository = contract.codeRepository || '';

    // 原子替换缓存
    this._cache = {
      runtimeParams,
      platformWhitelist,
      platformWhitelistSet,
      enclaveWhitelist,
      enclaveWhitelistMap,
      codeRepository: mergedCodeRepository,
      lastRefreshedAt: markRefreshed ? Date.now() : (this._cache?.lastRefreshedAt || 0),
    };

    console.log(`[ContractClient] _buildCache: platformWhitelist=${platformWhitelist.length}, enclaveWhitelist=${enclaveWhitelist.length}, hasRuntimeParams=${!!runtimeParams}, fresh=${markRefreshed}, contractAvailable=${this._contractAvailable}`);
    if (runtimeParams) {
      console.log(`[ContractClient] _buildCache: runtimeParams keys=${Object.keys(runtimeParams).join(', ')}`);
    }

    // 更新定时器间隔（仅在正常刷新模式下生效；重连模式下由 _onReconnectTick 管理）
    if (markRefreshed && !this._reconnecting && runtimeParams?.cache?.refreshInterval) {
      this._restartRefreshTimer(runtimeParams.cache.refreshInterval);
    }
  }

  /**
   * 加载钉住记录并覆盖合约身份（在 initialize 最开始调用）
   *
   * 安全策略：
   *   - 若存在钉住记录，永久使用钉住的合约身份，忽略环境变量里的连接参数；
   *   - 预载最近一次已知的安全配置快照，使得钉住合约不可达时也有可用配置，
   *     绝不回退到环境变量。
   */
  _loadPinAndOverrideIdentity() {
    if (!this._pinStore) return;

    let pinned = null;
    try {
      pinned = this._pinStore.load();
    } catch (err) {
      console.error(`[ContractClient] _loadPinAndOverrideIdentity: failed to load pin: ${err.message}`);
      return;
    }
    if (!pinned) {
      console.log('[ContractClient] no pinned contract yet (TOFU): will pin on first successful contract read');
      return;
    }

    this._pinned = true;

    const envDiffers =
      this._rpcUrl !== pinned.rpcUrl ||
      this._chainId !== pinned.chainId ||
      this._contractAddress !== pinned.contractAddress;
    if (envDiffers) {
      console.warn(
        `[ContractClient] SECURITY: env contract identity differs from pinned identity — ignoring env. ` +
          `env=(rpcUrl=${this._rpcUrl}, chainId=${this._chainId}, address=${this._contractAddress}), ` +
          `pinned=(rpcUrl=${pinned.rpcUrl}, chainId=${pinned.chainId}, address=${pinned.contractAddress})`
      );
    }

    // 永久锁定钉住身份
    this._rpcUrl = pinned.rpcUrl;
    this._chainId = pinned.chainId;
    this._contractAddress = pinned.contractAddress;
    this._pinnedAllowNonRaTls = pinned.allowNonRaTls;
    this._rpcTlsCaCert = pinned.rpcTlsCaCert || '';

    // 预载最后已知快照（不标记为新鲜）
    if (pinned.snapshot) {
      this._buildCache(pinned.snapshot, false);
      console.log('[ContractClient] preloaded last-known-good contract snapshot from sealed store');
    }
  }

  /**
   * 持久化钉住记录：首次成功读到合约数据时钉住身份，之后每次刷新更新快照。
   * 身份一旦钉住不可更改（由 ContractPinStore 保证）。
   * @param {Object} contractData - 成功读到的合约数据（作为最后已知快照）
   */
  _savePin(contractData) {
    if (!this._pinStore) return;
    try {
      const allowNonRaTls = !!(contractData.runtimeParams?.attestation?.allowNonRaTls);
      const rpcTlsCaCert = contractData.rpcTlsCaCert || this._rpcTlsCaCert || '';
      this._pinStore.save({
        rpcUrl: this._rpcUrl,
        chainId: this._chainId,
        contractAddress: this._contractAddress,
        allowNonRaTls,
        rpcTlsCaCert,
        snapshot: contractData,
      });
      this._pinned = true;
      this._pinnedAllowNonRaTls = allowNonRaTls;
      this._rpcTlsCaCert = rpcTlsCaCert;
    } catch (err) {
      console.error(`[ContractClient] _savePin: failed to persist pin: ${err.message}`);
    }
  }

  /**
   * 获取当前钉住的合约身份（供 SyncManager peer 验证用）
   * @returns {{ rpcUrl: string, chainId: number, contractAddress: string }|null}
   */
  getPinnedIdentity() {
    if (!this._pinStore) return null;
    try {
      const pinned = this._pinStore.load();
      if (!pinned) return null;
      return {
        rpcUrl: pinned.rpcUrl,
        chainId: pinned.chainId,
        contractAddress: pinned.contractAddress,
        allowNonRaTls: pinned.allowNonRaTls,
        rpcTlsCaCert: pinned.rpcTlsCaCert || '',
      };
    } catch (err) {
      console.error(`[ContractClient] getPinnedIdentity: ${err.message}`);
      return null;
    }
  }

  // ===== 配置查询（缓存） =====

  /**
   * 获取运行参数（缓存）
   * @returns {Object|null} 解析后的 runtimeParams JSON 对象
   */
  getRuntimeParams() {
    this._ensureInitialized();
    return this._cache.runtimeParams;
  }

  /**
   * 获取代码仓库链接（缓存）
   * @returns {string}
   */
  getCodeRepository() {
    this._ensureInitialized();
    return this._cache.codeRepository;
  }

  // ===== 平台白名单查询（缓存，O(1)） =====

  /**
   * 检查平台地址是否在白名单（从缓存 Set 中查找，O(1)）
   * @param {string} address - 以太坊地址
   * @returns {boolean}
   */
  isPlatformWhitelisted(address) {
    this._ensureInitialized();
    return this._cache.platformWhitelistSet.has(address.toLowerCase());
  }

  /**
   * 获取所有平台白名单地址（缓存）
   * @returns {string[]}
   */
  getPlatformWhitelist() {
    this._ensureInitialized();
    return [...this._cache.platformWhitelist];
  }

  // ===== Enclave 白名单查询（缓存，O(1)） =====

  /**
   * 检查 Enclave 是否在白名单（从缓存 Map 中查找，O(1)）
   * @param {string} mrenclave - bytes32 hex string
   * @returns {boolean}
   */
  isEnclaveWhitelisted(mrenclave) {
    this._ensureInitialized();
    return this._cache.enclaveWhitelistMap.has(mrenclave);
  }

  /**
   * 获取所有 Enclave 白名单（缓存）
   * @returns {Array<{ mrenclave: string, mrsigner: string, isvprodid: number, isvsvn: number, description: string }>}
   */
  getEnclaveWhitelist() {
    this._ensureInitialized();
    return [...this._cache.enclaveWhitelist];
  }

  // ===== 授权撤销（实时查询合约，不走缓存） =====

  /**
   * 检查授权是否被撤销（实时查询合约）
   * 合约不可用时抛出异常，由调用方根据 revocationPolicy 决定是否放行
   * @param {string} userId
   * @param {string} authorizationId
   * @returns {Promise<boolean>}
   * @throws {Error} 合约不可用时抛出
   */
  async isAuthorizationRevoked(userId, authorizationId) {
    this._ensureInitialized();
    if (!this._contractAvailable) {
      console.error(`[ContractClient] isAuthorizationRevoked: contract not available, cannot query revocation status for userId=${userId}, authorizationId=${authorizationId}`);
      throw new Error('Contract not available: cannot query authorization revocation status');
    }
    const revoked = await this._contract.isAuthorizationRevoked(userId, authorizationId);
    console.log(`[ContractClient] isAuthorizationRevoked: userId=${userId}, authorizationId=${authorizationId}, revoked=${revoked}`);
    return revoked;
  }

  /**
   * 检查平台是否被用户授权（综合检查）
   * 授权模型：平台白名单（必要条件）+ 用户授权给该 grantee（充分条件）
   * 两者缺一不可：只在白名单不够，必须被用户明确授权
   *
   * @param {string} userId - 用户 ID
   * @param {string} authorizationId - 授权 ID
   * @param {string} granteeAddress - 请求发起人的平台地址
   * @returns {Promise<{ authorized: boolean, reason: string }>}
   */
  /**
   * @param {Object} [options]
   * @param {boolean} [options.allowContractUnavailable=false] - 合约不可达时是否放行撤销检查
   */
  async checkAuthorization(userId, authorizationId, granteeAddress, options = {}) {
    this._ensureInitialized();
    console.log(`[ContractClient] checkAuthorization: userId=${userId}, authorizationId=${authorizationId}, grantee=${granteeAddress}, allowContractUnavailable=${!!options.allowContractUnavailable}`);

    // 1. 检查 grantee 是否在平台白名单（必要条件）
    if (!this.isPlatformWhitelisted(granteeAddress)) {
      console.log(`[ContractClient] checkAuthorization: REJECTED - grantee not in whitelist`);
      return { authorized: false, reason: 'Grantee not in platform whitelist' };
    }

    // 2. 检查授权是否已被撤销
    try {
      const revoked = await this.isAuthorizationRevoked(userId, authorizationId);
      if (revoked) {
        console.log(`[ContractClient] checkAuthorization: REJECTED - authorization revoked`);
        return { authorized: false, reason: 'Authorization has been revoked' };
      }
    } catch (err) {
      // 合约不可达
      if (options.allowContractUnavailable) {
        console.warn(`[ContractClient] checkAuthorization: contract unreachable but allowContractUnavailable=true, skipping revocation check`);
        console.log(`[ContractClient] checkAuthorization: AUTHORIZED (revocation check skipped)`);
        return { authorized: true, reason: 'OK (revocation check skipped: contract unavailable, allowContractUnavailable=true)' };
      } else {
        console.error(`[ContractClient] checkAuthorization: contract unreachable, treating as unauthorized: ${err.message}`);
        return { authorized: false, reason: 'Contract unavailable: cannot verify revocation status' };
      }
    }

    // 授权有效：平台在白名单 + 授权未被撤销（或已按策略跳过）
    console.log(`[ContractClient] checkAuthorization: AUTHORIZED`);
    return { authorized: true, reason: 'OK' };
  }

  // ===== Passkey 恢复（实时查询合约，不走缓存） =====

  /**
   * 查询 Passkey 恢复条目（实时查询合约）
   * 合约不可用时返回 null（此功能依赖合约，无法降级）
   * @param {string} userId
   * @param {string} newPubKeyHash - bytes32 hex string (0x...)
   * @returns {Promise<{ oldPubKeyHash: string, uuid: string, memo: string, createdAt: number } | null>}
   */
  async getPasskeyRecovery(userId, newPubKeyHash) {
    this._ensureInitialized();
    if (!this._contractAvailable || !this._contract) {
      console.log(`[ContractClient] getPasskeyRecovery: contract not available`);
      return null;
    }
    try {
      const exists = await this._contract.passkeyRecoveryExists(userId, newPubKeyHash);
      if (!exists) return null;
      const result = await this._contract.getPasskeyRecovery(userId, newPubKeyHash);
      return {
        oldPubKeyHash: result.oldPubKeyHash,
        uuid: result.uuid,
        memo: result.memo,
        createdAt: Number(result.createdAt),
      };
    } catch (err) {
      console.error(`[ContractClient] getPasskeyRecovery: failed: ${err.message}`);
      return null;
    }
  }

  /**
   * 获取缓存最后刷新时间戳
   * @returns {number}
   */
  getLastRefreshedAt() {
    return this._cache.lastRefreshedAt;
  }

  /**
   * 合约是否可用
   * @returns {boolean}
   */
  isContractAvailable() {
    return this._contractAvailable;
  }

  /**
   * 停止缓存刷新定时器，断开 provider 连接
   */
  close() {
    console.log(`[ContractClient] close: shutting down`);
    if (this._refreshTimer) {
      clearTimeout(this._refreshTimer);
      clearInterval(this._refreshTimer);
      this._refreshTimer = null;
    }
    // 注意：不调用 provider.destroy()，因为 ethers.js v6 的 JsonRpcProvider
    // 内部共享连接池，destroy 一个 provider 可能影响其他同 URL 的 provider。
    // 只需解除引用，让 GC 回收即可。
    this._provider = null;
    this._contract = null;
    this._initialized = false;
  }

  // ===== 内部方法 =====

  _ensureInitialized() {
    if (!this._initialized) {
      throw new Error('ContractClient not initialized. Call initialize() first.');
    }
  }

  /**
   * 启动正常刷新定时器（合约已连通时使用）
   * 合约配置随时可能更新，所以连上之后也不停止，持续定时刷新
   */
  _startRefreshTimer() {
    if (this._refreshTimer) {
      clearTimeout(this._refreshTimer);
      clearInterval(this._refreshTimer);
    }
    const interval = this._cache.runtimeParams?.cache?.refreshInterval
      || DEFAULT_REFRESH_INTERVAL;
    this._currentRefreshInterval = interval;
    console.log(`[ContractClient] _startRefreshTimer: interval=${interval}ms`);
    this._refreshTimer = setInterval(() => this._onNormalRefresh(), interval);
  }

  /**
   * 重启正常刷新定时器（runtimeParams 中有新间隔时）
   */
  _restartRefreshTimer(newInterval) {
    if (this._currentRefreshInterval === newInterval) {
      return; // 间隔未变，无需重启
    }
    if (this._refreshTimer) {
      clearTimeout(this._refreshTimer);
      clearInterval(this._refreshTimer);
    }
    this._currentRefreshInterval = newInterval;
    this._refreshTimer = setInterval(() => this._onNormalRefresh(), newInterval);
    console.log(`[ContractClient] _restartRefreshTimer: newInterval=${newInterval}ms`);
  }

  /**
   * 调度一次重连退避（setTimeout，非 setInterval）
   * 用于合约连不上 / 刷新失败时的递增间隔重试
   */
  _scheduleReconnect() {
    if (this._refreshTimer) {
      clearTimeout(this._refreshTimer);
      clearInterval(this._refreshTimer);
    }
    console.log(`[ContractClient] _scheduleReconnect: next attempt in ${this._reconnectDelay}ms`);
    this._refreshTimer = setTimeout(() => this._onReconnectTick(), this._reconnectDelay);
  }

  /**
   * 从 runtimeParams.reconnect 读取重连参数（合约 > env RUNTIME_PARAMS > 默认值）
   */
  _getReconnectInitialMs() {
    return this._cache.runtimeParams?.reconnect?.initialMs || DEFAULT_RECONNECT_INITIAL_MS;
  }
  _getReconnectIncrementMs() {
    return this._cache.runtimeParams?.reconnect?.incrementMs || DEFAULT_RECONNECT_INCREMENT_MS;
  }
  _getReconnectMaxMs() {
    return this._cache.runtimeParams?.reconnect?.maxMs || DEFAULT_RECONNECT_MAX_MS;
  }

  /**
   * 递增重连间隔（5s → 35s → 65s → ... → max → 重置为 initial）
   */
  _advanceReconnectDelay() {
    this._reconnectDelay += this._getReconnectIncrementMs();
    const maxMs = this._getReconnectMaxMs();
    if (this._reconnectDelay > maxMs) {
      const initialMs = this._getReconnectInitialMs();
      this._reconnectDelay = initialMs;
      console.log(`[ContractClient] _advanceReconnectDelay: reset to ${initialMs}ms`);
    }
  }

  /**
   * 正常刷新回调（合约已连通，定时读取最新配置）
   * 刷新失败时切换到重连退避模式
   */
  async _onNormalRefresh() {
    if (!this._rpcUrl || !this._chainId || !this._contractAddress) return;

    try {
      // 合约对象不存在时先重建
      if (!this._contract) {
        const network = ethers.Network.from(this._chainId);
        this._provider = new ethers.JsonRpcProvider(this._rpcUrl, network, { staticNetwork: network });
        this._contract = new ethers.Contract(this._contractAddress, CONTRACT_ABI, this._provider);
      }
      await this.refreshCache();
      // 刷新成功，确保仍处于正常刷新模式
      if (this._reconnecting) {
        console.log(`[ContractClient] _onNormalRefresh: contract recovered, switching to normal refresh`);
        this._reconnecting = false;
        this._reconnectDelay = this._getReconnectInitialMs();
      }
    } catch (err) {
      console.error(`[ContractClient] _onNormalRefresh: refresh failed: ${err.message}, switching to reconnect mode`);
      this._contractAvailable = false;
      this._reconnecting = true;
      this._reconnectDelay = this._getReconnectInitialMs();
      this._scheduleReconnect();
    }
  }

  /**
   * 重连退避回调（合约连不上时，递增间隔重试）
   * 连上后切换回正常刷新模式
   */
  async _onReconnectTick() {
    if (!this._rpcUrl || !this._chainId || !this._contractAddress) return;

    // 合约对象不存在时先重建
    if (!this._contract) {
      try {
        const network = ethers.Network.from(this._chainId);
        this._provider = new ethers.JsonRpcProvider(this._rpcUrl, network, { staticNetwork: network });
        this._contract = new ethers.Contract(this._contractAddress, CONTRACT_ABI, this._provider);
        console.log('[ContractClient] _onReconnectTick: provider/contract recreated');
      } catch (err) {
        console.error(`[ContractClient] _onReconnectTick: failed to create provider: ${err.message}`);
        this._advanceReconnectDelay();
        this._scheduleReconnect();
        return;
      }
    }

    try {
      await this.refreshCache();
      // 成功！切换到正常刷新模式
      console.log(`[ContractClient] _onReconnectTick: contract connected, switching to normal refresh`);
      this._contractAvailable = true;
      this._reconnecting = false;
      this._reconnectDelay = this._getReconnectInitialMs();
      this._startRefreshTimer();
    } catch (err) {
      // 失败，继续退避
      console.error(`[ContractClient] _onReconnectTick: refresh failed: ${err.message}`);
      this._advanceReconnectDelay();
      this._scheduleReconnect();
    }
  }

  /**
   * 合约迁移：当前合约声明了迁移目标，验证新合约可用后切换。
   *
   * 流程：
   *   1. 用迁移目标参数创建新 provider/contract
   *   2. 从新合约读取数据（必须返回非空 runtimeParams）
   *   3. 验证通过 → 更新 pin 身份 + 快照，切换 provider/contract，重建缓存
   *   4. 验证失败 → 保持旧合约不变，仅日志告警
   *
   * @param {{ rpcUrl: string, contractAddress: string, chainId: number, rpcTlsCaCert: string }} migration
   */
  async _handleMigration(migration) {
    // 如果迁移目标和当前身份一致，无需迁移
    if (
      migration.rpcUrl === this._rpcUrl &&
      migration.contractAddress === this._contractAddress &&
      migration.chainId === this._chainId
    ) {
      return;
    }

    console.log(
      `[ContractClient] migration target detected: rpcUrl=${migration.rpcUrl}, chainId=${migration.chainId}, address=${migration.contractAddress}`
    );

    // 1. 创建新 provider/contract（用迁移目标的 CA 证书）
    let newProvider, newContract;
    try {
      const network = ethers.Network.from(migration.chainId);
      const migrationCaCert = migration.rpcTlsCaCert || this._rpcTlsCaCert || '';
      const fetchReq = createFetchRequest(migration.rpcUrl, migrationCaCert);
      newProvider = new ethers.JsonRpcProvider(fetchReq, network, { staticNetwork: network });
      newContract = new ethers.Contract(migration.contractAddress, CONTRACT_ABI, newProvider);
    } catch (err) {
      console.error(`[ContractClient] migration: failed to create new provider/contract: ${err.message}`);
      return;
    }

    // 2. 从新合约读取数据
    let newData;
    try {
      newData = await this._readContractDataFrom(newContract);
    } catch (err) {
      console.error(`[ContractClient] migration: failed to read from new contract: ${err.message}`);
      return;
    }

    // 3. 验证：新合约必须返回非空 runtimeParams（必须的运行时参数）
    if (!newData.runtimeParams) {
      console.error(`[ContractClient] migration: new contract returned empty runtimeParams — aborting migration`);
      return;
    }

    // 4. 验证通过 → 更新 pin 身份 + 快照
    if (this._pinStore) {
      try {
        const allowNonRaTls = !!(newData.runtimeParams?.attestation?.allowNonRaTls);
        const rpcTlsCaCert = newData.rpcTlsCaCert || migration.rpcTlsCaCert || '';
        this._pinStore.updateIdentity({
          rpcUrl: migration.rpcUrl,
          chainId: migration.chainId,
          contractAddress: migration.contractAddress,
          allowNonRaTls,
          rpcTlsCaCert,
          snapshot: newData,
        });
        this._pinnedAllowNonRaTls = allowNonRaTls;
        this._rpcTlsCaCert = rpcTlsCaCert;
      } catch (err) {
        console.error(`[ContractClient] migration: failed to update pin: ${err.message}`);
        return;
      }
    }

    // 5. 切换 provider/contract，更新身份
    this._rpcUrl = migration.rpcUrl;
    this._chainId = migration.chainId;
    this._contractAddress = migration.contractAddress;
    this._rpcTlsCaCert = newData.rpcTlsCaCert || migration.rpcTlsCaCert || this._rpcTlsCaCert;
    this._provider = newProvider;
    this._contract = newContract;

    // 6. 用新合约数据重建缓存
    this._buildCache(newData, true);
    this._pinned = true;

    console.log(
      `[ContractClient] migration complete: switched to rpcUrl=${migration.rpcUrl}, chainId=${migration.chainId}, address=${migration.contractAddress}`
    );
  }

  /**
   * 从指定的 contract 实例读取数据（不使用 this._contract）
   * 供迁移时读取新合约使用
   * @param {import('ethers').Contract} contract
   * @returns {Promise<Object>}
   */
  async _readContractDataFrom(contract) {
    const [
      runtimeParamsStr,
      codeRepository,
      platformWhitelistRaw,
      enclaveWhitelistRaw,
      migrationTarget,
      rpcTlsCaCert,
    ] = await Promise.all([
      contract.getRuntimeParams(),
      contract.getCodeRepository(),
      contract.getPlatformWhitelist(),
      contract.getEnclaveWhitelist(),
      contract.getMigrationTarget(),
      contract.getRpcTlsCaCert(),
    ]);

    let runtimeParams = null;
    if (runtimeParamsStr && runtimeParamsStr.length > 0) {
      runtimeParams = JSON.parse(runtimeParamsStr);
    }

    let migration = null;
    if (migrationTarget && migrationTarget.rpcUrl && migrationTarget.contractAddress && Number(migrationTarget.chainId) > 0) {
      migration = {
        rpcUrl: migrationTarget.rpcUrl,
        contractAddress: migrationTarget.contractAddress,
        chainId: Number(migrationTarget.chainId),
        rpcTlsCaCert: migrationTarget.rpcTlsCaCert || '',
      };
    }

    return {
      runtimeParams,
      codeRepository,
      platformWhitelist: Array.from(platformWhitelistRaw),
      enclaveWhitelist: enclaveWhitelistRaw.map((item) => ({
        mrenclave: item.mrenclave, mrsigner: item.mrsigner,
        isvprodid: Number(item.isvprodid), isvsvn: Number(item.isvsvn),
        description: item.description,
      })),
      rpcTlsCaCert: rpcTlsCaCert || '',
      migration,
    };
  }
}

/**
 * 从环境变量读取合约连接参数并创建 ContractClient
 *
 * 注意：环境变量里的合约连接参数只在“尚未钉住任何合约”（TOFU 首次运行）时生效。
 * 一旦成功读过合约并钉住身份，pinStore 会在 initialize 时覆盖这些 env 参数，
 * 使 enclave 永久使用钉住的合约身份，防止通过 env 注入替换合约。
 *
 * @param {import('./contract-pin-store.js').ContractPinStore} [pinStore] - 合约身份钉住存储（可选）
 * @returns {ContractClient}
 */
export function createContractClientFromEnv(pinStore = null) {
  const rpcUrl = process.env.CONTRACT_RPC_URL;
  const chainId = process.env.CONTRACT_CHAIN_ID;
  const contractAddress = process.env.CONTRACT_ADDRESS;
  const rpcTlsCaCert = process.env.CONTRACT_RPC_TLS_CA_CERT || '';
  console.log(`[ContractClient] createContractClientFromEnv: rpcUrl=${rpcUrl}, chainId=${chainId}, contractAddress=${contractAddress}, hasCaCert=${!!rpcTlsCaCert}, pinStore=${!!pinStore}`);
  return new ContractClient({ rpcUrl, chainId, contractAddress, rpcTlsCaCert, pinStore });
}
