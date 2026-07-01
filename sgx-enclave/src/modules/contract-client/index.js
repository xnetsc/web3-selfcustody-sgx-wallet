/**
 * 合约交互客户端模块
 * 负责与 WalletTrustContract 智能合约交互，读取配置、白名单、撤销列表
 * 提供本地缓存机制和定期刷新
 */

import { ethers } from 'ethers';
import { CONTRACT_ABI } from './abi.js';

/** 默认缓存刷新间隔（毫秒），合约连接成功后的正常刷新间隔 */
const DEFAULT_REFRESH_INTERVAL = 60000;

/** 重连退避参数默认值（实际值从 runtimeParams.reconnect 读取） */
const DEFAULT_RECONNECT_INITIAL_MS = 5000;
const DEFAULT_RECONNECT_INCREMENT_MS = 30000;
const DEFAULT_RECONNECT_MAX_MS = 300000;

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
   */
  constructor(options) {
    this._rpcUrl = options.rpcUrl || null;
    this._chainId = options.chainId ? Number(options.chainId) : null;
    this._contractAddress = options.contractAddress || null;

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

    // 1. 读取合约数据（合约配置不全或连不上时为 null，只报错不抛异常）
    let contractData = null;
    if (this._rpcUrl && this._chainId && this._contractAddress) {
      try {
        // 使用 staticNetwork 避免 ethers.js 内部连接共享导致 destroy 互相影响
        const network = ethers.Network.from(this._chainId);
        this._provider = new ethers.JsonRpcProvider(this._rpcUrl, network, { staticNetwork: network });
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

    // 2. 合并环境变量 + 合约数据 → 唯一配置
    this._mergeAndApplyCache(contractData);

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
    this._mergeAndApplyCache(contractData);
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
    ] = await Promise.all([
      this._contract.getRuntimeParams(),
      this._contract.getCodeRepository(),
      this._contract.getPlatformWhitelist(),
      this._contract.getEnclaveWhitelist(),
    ]);

    let runtimeParams = null;
    if (runtimeParamsStr && runtimeParamsStr.length > 0) {
      runtimeParams = JSON.parse(runtimeParamsStr);
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
    };
  }

  /**
   * 用合约数据原子替换缓存
   * 合约是唯一真理源；env 不再提供 fallback
   * @param {Object|null} contractData - 从合约读取的数据（null 表示合约数据不可用）
   */
  _mergeAndApplyCache(contractData) {
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
      lastRefreshedAt: Date.now(),
    };

    console.log(`[ContractClient] _mergeAndApplyCache: platformWhitelist=${platformWhitelist.length}, enclaveWhitelist=${enclaveWhitelist.length}, hasRuntimeParams=${!!runtimeParams}, contractAvailable=${this._contractAvailable}`);
    if (runtimeParams) {
      console.log(`[ContractClient] _mergeAndApplyCache: runtimeParams keys=${Object.keys(runtimeParams).join(', ')}`);
    }

    // 更新定时器间隔（仅在正常刷新模式下生效；重连模式下由 _onReconnectTick 管理）
    if (!this._reconnecting && runtimeParams?.cache?.refreshInterval) {
      this._restartRefreshTimer(runtimeParams.cache.refreshInterval);
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
}

/**
 * 从环境变量读取合约连接参数并创建 ContractClient
 * @returns {ContractClient}
 */
export function createContractClientFromEnv() {
  const rpcUrl = process.env.CONTRACT_RPC_URL;
  const chainId = process.env.CONTRACT_CHAIN_ID;
  const contractAddress = process.env.CONTRACT_ADDRESS;
  console.log(`[ContractClient] createContractClientFromEnv: rpcUrl=${rpcUrl}, chainId=${chainId}, contractAddress=${contractAddress}`);
  return new ContractClient({ rpcUrl, chainId, contractAddress });
}
