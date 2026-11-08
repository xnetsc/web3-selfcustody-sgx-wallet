/**
 * 合约身份钉住存储（Contract Pin Store）
 *
 * 安全目的：一旦 enclave 成功从合约读到过数据，就把合约身份
 * （rpcUrl / chainId / contractAddress）以及最近一次已知的安全相关合约配置
 * 快照持久化到 sealed SQLite（加密分区，key = MRENCLAVE）。
 * 之后：
 *   - 永久使用钉住的合约身份，忽略环境变量里的合约连接参数
 *     （防止攻击者通过 env 把 enclave 指向自己控制的合约）；
 *   - 钉住的合约不可达时，使用该快照作为最后已知配置，绝不回退到环境变量。
 *
 * 本表参与跨节点同步（HLC LWW），确保所有节点用同一份钉住数据。
 * 写操作统一走 SyncEngine 的 engine.write（统一事务 + 跨节点同步），不直接写库。
 *
 * 启动顺序例外：ContractClient 在 SyncEngine 创建之前就要 initialize 并首次
 * 钉住（同步引擎的 peer 验证本身依赖钉住身份）。此时发生的 save/updateIdentity
 * 先暂存（pending），setEngine() 注入引擎后立即用同一条统一通道补写落库；
 * 进程在补写前崩溃则钉住丢失，但此时尚未对外服务，下次启动会重新读合约再钉。
 */

const PIN_ROW_ID = 1;

import { getMonotonicSqliteNow } from '../../utils/monotonic-clock.js';
import { createConnProxy, shouldExecuteInternalWrite } from '../../sync/sync-adapter.js';

export class ContractPinStore {
  /**
   * @param {import('../../database/connection-manager.js').default|import('../../database/connection-manager.js').LazyConnectionManager} connMgr
   */
  constructor(connMgr) {
    if (!connMgr) throw new Error('ContractPinStore requires a ConnectionManager instance');
    this._connMgr = connMgr;
    this._engine = null;
    this._pending = null;
  }

  /**
   * 注入 SyncEngine（在 SyncManager 创建后由启动流程调用）。
   * 注入前暂存的钉住写入会在此立即经统一通道补写落库。
   * @param {import('@xnetx/raft-hlc-sync').SyncEngine} engine
   */
  async setEngine(engine) {
    this._engine = engine;
    if (this._pending) {
      const pending = this._pending;
      this._pending = null;
      console.log('[ContractPinStore] engine injected, flushing pending pin write');
      if (pending.mode === 'identity') {
        await this._writeIdentity(pending.record);
      } else {
        await this._writeSave(pending.record);
      }
    }
  }

  /**
   * 读取已钉住的合约身份 + 快照
   * @returns {{ rpcUrl: string, chainId: number, contractAddress: string, allowNonRaTls: boolean, rpcTlsCaCert: string, snapshot: Object|null }|null}
   */
  load() {
    const rows = this._connMgr.readQuery(
      'SELECT rpc_url, chain_id, contract_address, allow_non_ra_tls, rpc_tls_ca_cert, snapshot_json FROM pinned_contract WHERE id = ?',
      [PIN_ROW_ID]
    );
    if (!rows || rows.length === 0) return null;
    const row = rows[0];

    let snapshot = null;
    if (row.snapshot_json) {
      try {
        snapshot = JSON.parse(row.snapshot_json);
      } catch (err) {
        console.error(`[ContractPinStore] load: failed to parse snapshot_json: ${err.message}`);
        snapshot = null;
      }
    }

    return {
      rpcUrl: row.rpc_url,
      chainId: row.chain_id != null ? Number(row.chain_id) : null,
      contractAddress: row.contract_address,
      allowNonRaTls: !!row.allow_non_ra_tls,
      rpcTlsCaCert: row.rpc_tls_ca_cert || '',
      snapshot,
    };
  }

  /**
   * 写入/更新钉住记录（upsert 单行 id=1）
   * 首次成功读到合约数据时钉住身份；后续每次成功刷新更新快照，
   * 但绝不修改已钉住的身份（rpcUrl/chainId/contractAddress）。
   *
   * @param {Object} record
   * @param {string} record.rpcUrl
   * @param {number|string} record.chainId
   * @param {string} record.contractAddress
   * @param {Object|null} [record.snapshot] - 安全相关合约配置快照
   */
  async save(record) {
    const { rpcUrl, chainId, contractAddress } = record;
    if (!rpcUrl || chainId == null || !contractAddress) {
      throw new Error('ContractPinStore.save: rpcUrl/chainId/contractAddress are all required');
    }
    if (!this._engine) {
      // SyncEngine 尚未注入（启动早期）：暂存，setEngine 后补写（见文件头说明）
      this._pending = { mode: 'save', record };
      console.log('[ContractPinStore] engine not ready, pin write queued');
      return;
    }
    await this._writeSave(record);
  }

  /**
   * save 的实际落库（单个 engine.write 事务内完成读判 + 写，避免两段式）
   * @param {Object} record
   */
  async _writeSave(record) {
    // leader 纪律（shouldExecuteInternalWrite）：pinned_contract 属 shard 0，
    // leader 是其它节点时不本地落库，由 leader 节点钉住同一份数据后同步过来；
    // 无 leader 时本地兜底落库，后续靠同步传播。
    if (!shouldExecuteInternalWrite(this._engine, null)) {
      console.log('[ContractPinStore] skip pin save: shard 0 leader is another node');
      return;
    }
    const { rpcUrl, chainId, contractAddress, allowNonRaTls, rpcTlsCaCert } = record;
    const snapshotJson = record.snapshot ? JSON.stringify(record.snapshot) : null;
    const allowNonRaTlsVal = allowNonRaTls ? 1 : 0;
    const caCert = rpcTlsCaCert || '';

    let firstPin = false;
    await this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      const ts = this._engine.hlc.tick();
      const existing = conn.query(
        'SELECT rpc_url, chain_id, contract_address FROM pinned_contract WHERE id = ?',
        [PIN_ROW_ID]
      );

      if (!existing || existing.length === 0) {
        // 首次钉住
        firstPin = true;
        conn.query(
          `INSERT INTO pinned_contract (id, rpc_url, chain_id, contract_address, allow_non_ra_tls, rpc_tls_ca_cert, snapshot_json, pinned_at, updated_at, _hlc)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [PIN_ROW_ID, rpcUrl, Number(chainId), contractAddress, allowNonRaTlsVal, caCert, snapshotJson, getMonotonicSqliteNow(), getMonotonicSqliteNow(), ts]
        );
      } else {
        // 已钉住：只更新快照，身份保持不变（即使传入的身份不同也忽略，防止被覆盖）
        conn.query(
          `UPDATE pinned_contract SET snapshot_json = ?, updated_at = ?, _hlc = ? WHERE id = ?`,
          [snapshotJson, getMonotonicSqliteNow(), ts, PIN_ROW_ID]
        );
      }
    });

    if (firstPin) {
      console.log(
        `[ContractPinStore] pinned contract identity: rpcUrl=${rpcUrl}, chainId=${Number(chainId)}, address=${contractAddress}, allowNonRaTls=${!!allowNonRaTlsVal}, hasCaCert=${!!caCert}`
      );
    }
  }

  /**
   * 迁移专用：更新钉住的合约身份 + 快照（整体替换）。
   * 仅在合约迁移成功验证后调用——新合约已确认可读且返回了必须的运行时参数。
   * 旧身份被永久遗忘。
   *
   * @param {Object} record
   * @param {string} record.rpcUrl
   * @param {number|string} record.chainId
   * @param {string} record.contractAddress
   * @param {Object|null} [record.snapshot]
   */
  async updateIdentity(record) {
    const { rpcUrl, chainId, contractAddress } = record;
    if (!rpcUrl || chainId == null || !contractAddress) {
      throw new Error('ContractPinStore.updateIdentity: rpcUrl/chainId/contractAddress are all required');
    }
    if (!this._engine) {
      this._pending = { mode: 'identity', record };
      console.log('[ContractPinStore] engine not ready, pin identity write queued');
      return;
    }
    await this._writeIdentity(record);
  }

  /**
   * updateIdentity 的实际落库（engine.write 统一通道）
   * @param {Object} record
   */
  async _writeIdentity(record) {
    // 同 _writeSave 的 leader 纪律：leader 是其它节点时跳过本地落库
    if (!shouldExecuteInternalWrite(this._engine, null)) {
      console.log('[ContractPinStore] skip pin identity write: shard 0 leader is another node');
      return;
    }
    const { rpcUrl, chainId, contractAddress, allowNonRaTls, rpcTlsCaCert } = record;
    const snapshotJson = record.snapshot ? JSON.stringify(record.snapshot) : null;
    const allowNonRaTlsVal = allowNonRaTls ? 1 : 0;
    const caCert = rpcTlsCaCert || '';

    await this._engine.write(async (db) => {
      const conn = createConnProxy(db);
      conn.query(
        `INSERT INTO pinned_contract (id, rpc_url, chain_id, contract_address, allow_non_ra_tls, rpc_tls_ca_cert, snapshot_json, pinned_at, updated_at, _hlc)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           rpc_url = excluded.rpc_url,
           chain_id = excluded.chain_id,
           contract_address = excluded.contract_address,
           allow_non_ra_tls = excluded.allow_non_ra_tls,
           rpc_tls_ca_cert = excluded.rpc_tls_ca_cert,
           snapshot_json = excluded.snapshot_json,
           updated_at = excluded.updated_at,
           _hlc = excluded._hlc`,
        [PIN_ROW_ID, rpcUrl, Number(chainId), contractAddress, allowNonRaTlsVal, caCert, snapshotJson, getMonotonicSqliteNow(), getMonotonicSqliteNow(), this._engine.hlc.tick()]
      );
    });
    console.log(
      `[ContractPinStore] contract identity migrated to: rpcUrl=${rpcUrl}, chainId=${Number(chainId)}, address=${contractAddress}, allowNonRaTls=${!!allowNonRaTlsVal}, hasCaCert=${!!caCert}`
    );
  }
}

export default ContractPinStore;
