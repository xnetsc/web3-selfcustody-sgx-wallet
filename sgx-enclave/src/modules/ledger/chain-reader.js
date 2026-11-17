/**
 * 资产读链通道（与操作合约的 RPC 完全分开）
 *
 * 配置以（链名，chainId）为键写在合约里，本模块每次读取前实时从合约拉取，
 * 不用缓存快照；读不到配置、或配置内出现非 https 端点，整条链视为未正确
 * 配置并拒绝使用。端点启用前先验其实际 chainId 与配置一致，并以创世区块
 * 哈希为链身份锚：首次使用时由端点集共识确立并记录，之后每次校验，
 * 不一致的端点剔除。关键读数（交易证据）须至少两个锚定端点交叉一致才采信。
 */

import { ethers } from 'ethers';
import https from 'node:https';
import { createHash } from 'node:crypto';

export const TRANSFER_TOPIC = ethers.id('Transfer(address,address,uint256)');
const NATIVE_LOG_INDEX = -1;

function buildProvider(url, caCert) {
  if (!caCert) return new ethers.JsonRpcProvider(url);
  const caPem = caCert.includes('-----BEGIN')
    ? caCert
    : Buffer.from(caCert, 'base64').toString('utf8');
  const req = new ethers.FetchRequest(url);
  const agent = new https.Agent({ ca: caPem, rejectUnauthorized: true });
  req.getUrlFunc = ethers.FetchRequest.createGetUrlFunc({ agent });
  return new ethers.JsonRpcProvider(req);
}

export class ChainReader {
  /**
   * @param {Object} deps
   * @param {import('../contract-client/index.js').ContractClient} deps.contractClient
   * @param {import('../../database/connection-manager.js').default} [deps.connectionManager] - 仅用于本地保存链身份锚
   * @param {Function} [deps.providerFactory] - (url, caCert) => provider，测试注入用
   */
  constructor(deps) {
    this._contract = deps.contractClient;
    this._providerFactory = deps.providerFactory || buildProvider;
    this._memoryAnchors = new Map();
    this._db = deps.connectionManager?.db || null;
    if (this._db) {
      this._db.exec(`CREATE TABLE IF NOT EXISTS chain_identity_anchors (
        chain_id INTEGER PRIMARY KEY,
        genesis_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
      )`);
    }
  }

  _getAnchor(chainId) {
    if (this._db) {
      const row = this._db.prepare('SELECT genesis_hash FROM chain_identity_anchors WHERE chain_id = ?').get(chainId);
      return row ? row.genesis_hash : null;
    }
    return this._memoryAnchors.get(chainId) || null;
  }

  _setAnchor(chainId, genesisHash) {
    if (this._db) {
      this._db.prepare(
        'INSERT OR IGNORE INTO chain_identity_anchors (chain_id, genesis_hash, created_at) VALUES (?, ?, ?)'
      ).run(chainId, genesisHash, new Date().toISOString());
      return this._getAnchor(chainId);
    }
    if (!this._memoryAnchors.has(chainId)) this._memoryAnchors.set(chainId, genesisHash);
    return this._memoryAnchors.get(chainId);
  }

  /** 实时读合约配置并完成端点校验（chainId + 创世锚），返回可用端点集 */
  async getVerifiedChain(chainId) {
    let config;
    try {
      config = await this._contract.getChainRpcConfig(chainId);
    } catch (err) {
      throw new Error(`Contract unavailable: cannot read chain RPC config (${err.message})`);
    }
    if (!config) throw new Error(`chain ${chainId} is not configured for asset reading`);
    for (const url of config.rpcUrls) {
      if (!/^https:\/\//i.test(url)) {
        throw new Error(`chain ${chainId} config contains a non-https endpoint; chain treated as not configured`);
      }
    }

    const candidates = config.rpcUrls.map((url, i) => ({
      url,
      provider: this._providerFactory(url, config.caCerts[i] || ''),
    }));

    // 端点健康检查：实际 chainId 一致 + 创世哈希
    const probed = [];
    for (const c of candidates) {
      try {
        const network = await c.provider.getNetwork();
        if (Number(network.chainId) !== Number(chainId)) continue;
        const genesis = await c.provider.getBlock(0);
        if (!genesis || !genesis.hash) continue;
        probed.push({ ...c, genesisHash: genesis.hash.toLowerCase() });
      } catch {
        // 端点不可用，剔除
      }
    }
    if (probed.length === 0) throw new Error(`chain ${chainId}: no healthy endpoints`);

    let anchor = this._getAnchor(chainId);
    if (!anchor) {
      // 首次使用：至少两个端点对创世哈希达成共识才确立身份锚
      const byHash = new Map();
      for (const p of probed) {
        if (!byHash.has(p.genesisHash)) byHash.set(p.genesisHash, []);
        byHash.get(p.genesisHash).push(p);
      }
      const consensus = [...byHash.values()].find((g) => g.length >= 2);
      if (!consensus) throw new Error(`chain ${chainId}: endpoints cannot reach genesis consensus`);
      anchor = this._setAnchor(chainId, consensus[0].genesisHash);
    }
    const anchored = probed.filter((p) => p.genesisHash === anchor);
    if (anchored.length < 2) {
      throw new Error(`chain ${chainId}: fewer than two endpoints match the genesis anchor`);
    }
    return { config, providers: anchored };
  }

  /**
   * 交叉核对地读取一笔交易的转账证据
   * @returns {Promise<{ blockNumber: number, confirmations: number, requiredConfirmations: number,
   *                     transfers: Array<{assetId: string, from: string, to: string, amount: string, logIndex: number}> }>}
   */
  async fetchTransferEvidence(chainId, txHash) {
    const { config, providers } = await this.getVerifiedChain(chainId);

    const observations = [];
    let notFoundCount = 0;
    for (const { provider } of providers) {
      try {
        const [receipt, tx] = await Promise.all([
          provider.getTransactionReceipt(txHash),
          provider.getTransaction(txHash),
        ]);
        if (!receipt && !tx) { notFoundCount++; continue; }
        if (!receipt || !tx) continue;
        const logsDigest = createHash('sha256').update(JSON.stringify(
          (receipt.logs || []).map((l) => [l.address, l.topics, l.data, l.index])
        )).digest('hex');
        const key = [receipt.blockNumber, receipt.status, tx.from, tx.to, String(tx.value), logsDigest].join('|');
        observations.push({ key, receipt, tx, provider });
      } catch {
        // 该端点读失败，跳过
      }
    }
    const groups = new Map();
    for (const o of observations) {
      if (!groups.has(o.key)) groups.set(o.key, []);
      groups.get(o.key).push(o);
    }
    const agreed = [...groups.values()].filter((g) => g.length >= 2).sort((a, b) => b.length - a.length)[0];
    if (!agreed) {
      if (observations.length === 0 && notFoundCount >= 2) {
        return {
          found: false, blockNumber: null, status: null, confirmations: 0,
          requiredConfirmations: config.confirmations, transfers: [],
        };
      }
      throw new Error(`chain ${chainId}: endpoints disagree on transaction ${txHash}`);
    }

    const { receipt, tx } = agreed[0];
    // 确认数以一致端点中最低的当前高度保守计算
    let head = Infinity;
    for (const o of agreed) {
      try {
        const n = await o.provider.getBlockNumber();
        if (n < head) head = n;
      } catch { /* 忽略单个端点失败 */ }
    }
    if (!Number.isFinite(head)) throw new Error(`chain ${chainId}: cannot determine chain head`);
    const confirmations = Math.max(0, head - receipt.blockNumber + 1);

    return {
      found: true,
      blockNumber: receipt.blockNumber,
      status: receipt.status,
      confirmations,
      requiredConfirmations: config.confirmations,
      transfers: receipt.status === 1 ? parseTransfers(tx, receipt) : [],
    };
  }

  /** 广播通道：任一已锚定端点即可广播（广播不依赖读数一致性） */
  async getBroadcastChannel(chainId) {
    const { config, providers } = await this.getVerifiedChain(chainId);
    return { provider: providers[0].provider, requiredConfirmations: config.confirmations };
  }
}

/** 从交易与收据中解析全部转账（原生币一笔 + 每条 ERC20 Transfer 日志一笔） */
export function parseTransfers(tx, receipt) {
  const transfers = [];
  if (tx.to && tx.value && BigInt(tx.value) > 0n) {
    transfers.push({
      assetId: 'native',
      from: String(tx.from).toLowerCase(),
      to: String(tx.to).toLowerCase(),
      amount: BigInt(tx.value).toString(),
      logIndex: NATIVE_LOG_INDEX,
    });
  }
  for (const log of receipt.logs || []) {
    if (!log.topics || log.topics[0] !== TRANSFER_TOPIC || log.topics.length < 3) continue;
    transfers.push({
      assetId: String(log.address).toLowerCase(),
      from: `0x${log.topics[1].slice(26)}`.toLowerCase(),
      to: `0x${log.topics[2].slice(26)}`.toLowerCase(),
      amount: BigInt(log.data).toString(),
      logIndex: log.index,
    });
  }
  return transfers;
}
