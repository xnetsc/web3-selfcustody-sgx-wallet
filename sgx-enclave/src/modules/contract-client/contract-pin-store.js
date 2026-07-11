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
 * 使用 ConnectionManager 的标准 readQuery / writeQuery 接口，
 * 与其它所有业务表走相同的数据库逻辑。
 */

const PIN_ROW_ID = 1;

import { getMonotonicSqliteNow } from '../../utils/monotonic-clock.js';

export class ContractPinStore {
  /**
   * @param {import('../../database/connection-manager.js').default|import('../../database/connection-manager.js').LazyConnectionManager} connMgr
   */
  constructor(connMgr) {
    if (!connMgr) throw new Error('ContractPinStore requires a ConnectionManager instance');
    this._connMgr = connMgr;
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
  save(record) {
    const { rpcUrl, chainId, contractAddress, allowNonRaTls, rpcTlsCaCert } = record;
    if (!rpcUrl || chainId == null || !contractAddress) {
      throw new Error('ContractPinStore.save: rpcUrl/chainId/contractAddress are all required');
    }
    const snapshotJson = record.snapshot ? JSON.stringify(record.snapshot) : null;
    const allowNonRaTlsVal = allowNonRaTls ? 1 : 0;
    const caCert = rpcTlsCaCert || '';

    const existing = this._connMgr.readQuery(
      'SELECT rpc_url, chain_id, contract_address FROM pinned_contract WHERE id = ?',
      [PIN_ROW_ID]
    );

    if (!existing || existing.length === 0) {
      // 首次钉住
      this._connMgr.writeQuery(
        `INSERT INTO pinned_contract (id, rpc_url, chain_id, contract_address, allow_non_ra_tls, rpc_tls_ca_cert, snapshot_json)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [PIN_ROW_ID, rpcUrl, Number(chainId), contractAddress, allowNonRaTlsVal, caCert, snapshotJson]
      );
      console.log(
        `[ContractPinStore] pinned contract identity: rpcUrl=${rpcUrl}, chainId=${Number(chainId)}, address=${contractAddress}, allowNonRaTls=${!!allowNonRaTlsVal}, hasCaCert=${!!caCert}`
      );
      return;
    }

    // 已钉住：只更新快照，身份保持不变（即使传入的身份不同也忽略，防止被覆盖）
    this._connMgr.writeQuery(
      `UPDATE pinned_contract SET snapshot_json = ?, updated_at = ? WHERE id = ?`,
      [snapshotJson, getMonotonicSqliteNow(), PIN_ROW_ID]
    );
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
  updateIdentity(record) {
    const { rpcUrl, chainId, contractAddress, allowNonRaTls, rpcTlsCaCert } = record;
    if (!rpcUrl || chainId == null || !contractAddress) {
      throw new Error('ContractPinStore.updateIdentity: rpcUrl/chainId/contractAddress are all required');
    }
    const snapshotJson = record.snapshot ? JSON.stringify(record.snapshot) : null;
    const allowNonRaTlsVal = allowNonRaTls ? 1 : 0;
    const caCert = rpcTlsCaCert || '';

    this._connMgr.writeQuery(
      `INSERT INTO pinned_contract (id, rpc_url, chain_id, contract_address, allow_non_ra_tls, rpc_tls_ca_cert, snapshot_json)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         rpc_url = excluded.rpc_url,
         chain_id = excluded.chain_id,
         contract_address = excluded.contract_address,
         allow_non_ra_tls = excluded.allow_non_ra_tls,
         rpc_tls_ca_cert = excluded.rpc_tls_ca_cert,
         snapshot_json = excluded.snapshot_json,
         updated_at = ?`,
      [PIN_ROW_ID, rpcUrl, Number(chainId), contractAddress, allowNonRaTlsVal, caCert, snapshotJson, getMonotonicSqliteNow()]
    );
    console.log(
      `[ContractPinStore] contract identity migrated to: rpcUrl=${rpcUrl}, chainId=${Number(chainId)}, address=${contractAddress}, allowNonRaTls=${!!allowNonRaTlsVal}, hasCaCert=${!!caCert}`
    );
  }
}

export default ContractPinStore;
