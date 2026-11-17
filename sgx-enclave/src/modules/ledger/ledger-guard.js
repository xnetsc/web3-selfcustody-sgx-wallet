/**
 * 账本资金护栏（挂在既有签名/导出路径上的执行点检查）
 *
 * 转账护栏（签名之前）：先判定转出地址是不是账本绑定地址（某账本的专属
 * 充值地址，或在其合约公布集内）。不是，普通转账不受影响；是，则实时查
 * 合约核对：账本启用、（普通路径）签名者是该账本所有权人且签名用的正是
 * 合约指定的那把所有权人 Passkey（同一账号的其它 Passkey 不能动绑定
 * 地址）、目标地址在合约为（账本、源地址）配置的出金目标集内；目标若是
 * SGX 托管钱包，还须是原生钱包（导入钱包私钥在外部存在过，不合格）。
 * 任一不合，拒绝签名。
 *
 * 导出护栏（密钥释放之前）：专属充值地址永久禁止导出；地址在任一账本的
 * 合约公布集内时禁止导出（移出公布集后锁定解除）；本地存在账本而合约
 * 不可用时拒绝导出（无法核对即不放行）。
 */

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

/** 从交易 data 解出实际收款方（ERC20 transfer / transferFrom），非转账调用返回 tx 的 to */
export function decodeEffectiveTarget(toAddress, data) {
  const to = String(toAddress || '').toLowerCase();
  if (!data || typeof data !== 'string' || !data.startsWith('0x') || data.length < 10) {
    return { target: to, isPlainTransfer: true };
  }
  const selector = data.slice(0, 10).toLowerCase();
  try {
    if (selector === '0xa9059cbb' && data.length >= 138) {
      // transfer(address,uint256)：第一个参数字即收款方
      return { target: `0x${data.slice(34, 74)}`.toLowerCase(), isPlainTransfer: true };
    }
    if (selector === '0x23b872dd' && data.length >= 202) {
      // transferFrom(address,address,uint256)：第二个参数字是收款方
      return { target: `0x${data.slice(98, 138)}`.toLowerCase(), isPlainTransfer: true };
    }
  } catch { /* 落入下方非普通转账处理 */ }
  return { target: to, isPlainTransfer: false };
}

import { PasskeyManager } from '../webauthn/passkey-manager.js';

export class LedgerGuard {
  /**
   * @param {Object} deps
   * @param {import('../../database/connection-manager.js').default} deps.connectionManager
   * @param {import('../contract-client/index.js').ContractClient} deps.contractClient
   * @param {import('../webauthn/passkey-manager.js').PasskeyManager} deps.passkeyManager - 指定 Passkey 校验用（普通路径）
   */
  constructor(deps) {
    this._db = deps.connectionManager;
    this._contract = deps.contractClient;
    this._passkeys = deps.passkeyManager || null;
  }

  _localLedgers() {
    return this._db.readQuery('SELECT ledger_id, owner_user_id FROM ledgers', []);
  }

  /**
   * 判定地址的账本绑定：先查专属充值地址归属（本地定论），再逐个本地账本
   * 实时查合约公布集。无任何本地账本时恒为未绑定（护栏不介入）。
   * @returns {Promise<{ledgerId: string, kind: 'deposit_address'|'pool'}|null>}
   */
  async findBinding(address) {
    const target = String(address).toLowerCase();
    const assignments = this._db.readQuery(
      'SELECT ledger_id FROM ledger_deposit_addresses WHERE LOWER(address) = ?',
      [target]
    );
    if (assignments.length > 0) return { ledgerId: assignments[0].ledger_id, kind: 'deposit_address' };

    const ledgers = this._localLedgers();
    for (const ledger of ledgers) {
      const designation = await this._contract.getLedger(ledger.ledger_id); // 合约不可用即抛错（fail-closed）
      if (!designation) continue;
      if (designation.poolAddresses.some((a) => a.toLowerCase() === target)) {
        return { ledgerId: ledger.ledger_id, kind: 'pool' };
      }
    }
    return null;
  }

  /**
   * 转账签名前的护栏。未绑定地址直接放行；绑定地址任一检查不合即抛错拒绝。
   * @param {Object} args
   * @param {string} args.signerUserId - 签名账户（普通路径）或目标账户（应急路径传目标用户并关闭所有权检查）
   * @param {string} [args.signerCredentialId] - 本次授权实际签名用的 Passkey（普通路径）：绑定地址只认合约指定的那把
   * @param {string} args.fromAddress
   * @param {string} args.toAddress
   * @param {string} [args.data] - 交易 data（raw 模式解实际收款方用）
   * @param {boolean} [args.requireSignerIsOwner=true] - 应急代行路径传 false：授权依据不同，但出金目标约束同样生效
   * @returns {Promise<{bound: boolean, ledgerId?: string}>}
   */
  async assertTransferAllowed({ signerUserId, signerCredentialId = null, fromAddress, toAddress, data = null, requireSignerIsOwner = true }) {
    const binding = await this.findBinding(fromAddress);
    if (!binding) return { bound: false };
    const { ledgerId } = binding;

    let designation;
    try {
      designation = await this._contract.getLedger(ledgerId);
    } catch (err) {
      throw new Error(`Ledger guard: contract unavailable, refusing to sign from a ledger-bound address (${err.message})`);
    }
    if (!designation) throw new Error(`Ledger guard: ledger ${ledgerId} is not designated on contract`);
    if (!designation.enabled) throw new Error(`Ledger guard: ledger ${ledgerId} is disabled`);
    if (requireSignerIsOwner) {
      if (designation.ownerUserId !== signerUserId) {
        throw new Error('Ledger guard: source address is ledger-bound and the signer is not the ledger owner');
      }
      // 指定 Passkey：绑定地址只能由合约指定的那把所有权人 Passkey 签动，
      // 同一账号下的其它 Passkey 不得操作专属充值地址与归集地址
      if (!this._passkeys) {
        throw new Error('Ledger guard: passkey verification unavailable, refusing to sign from a ledger-bound address');
      }
      if (!signerCredentialId) {
        throw new Error('Ledger guard: bound addresses can only be moved by the contract-designated owner passkey (authorization carries no credential)');
      }
      const passkey = await this._passkeys.getPasskey(signerUserId, signerCredentialId);
      if (!passkey) {
        throw new Error('Ledger guard: signing passkey not found on the signer account');
      }
      const signingHash = PasskeyManager.computePubKeyHash(passkey.publicKeyCose);
      if (signingHash.toLowerCase() !== String(designation.ownerPubKeyHash).toLowerCase()) {
        throw new Error('Ledger guard: bound addresses can only be moved by the contract-designated owner passkey');
      }
    }

    const { target, isPlainTransfer } = decodeEffectiveTarget(toAddress, data);
    if (!isPlainTransfer) {
      throw new Error('Ledger guard: ledger-bound funds may only move via plain transfers to configured targets');
    }
    let targets;
    try {
      targets = await this._contract.getCollectionPayoutTargets(ledgerId, fromAddress);
    } catch (err) {
      throw new Error(`Ledger guard: contract unavailable, cannot verify payout targets (${err.message})`);
    }
    if (!targets.some((a) => a.toLowerCase() === target)) {
      throw new Error(`Ledger guard: target ${target} is not a configured payout target for this collection address`);
    }

    // 目标若是 SGX 托管钱包：必须是原生钱包（私钥从未在 SGX 外存在过）
    const held = this._db.readQuery('SELECT wallet_type FROM wallets WHERE LOWER(address) = ?', [target]);
    if (held.length > 0 && held[0].wallet_type !== 'native') {
      throw new Error('Ledger guard: target wallet is not key-qualified (imported wallets cannot receive collection funds)');
    }
    return { bound: true, ledgerId };
  }

  /**
   * 导出密钥释放前的护栏：逐行检查待导出钱包
   * @param {Array<{address: string, export_locked: number}>} walletRows
   */
  async assertExportAllowed(walletRows) {
    for (const row of walletRows) {
      if (Number(row.export_locked) === 1) {
        throw new Error(`Export locked: address ${row.address} is a dedicated deposit address and can never be exported`);
      }
    }
    if (this._localLedgers().length === 0) return;
    for (const row of walletRows) {
      const binding = await this.findBinding(row.address); // 合约不可用即抛错（fail-closed）
      if (binding && binding.kind === 'pool') {
        throw new Error(`Export locked: address ${row.address} is currently published as a collection address of ledger ${binding.ledgerId}`);
      }
      if (binding && binding.kind === 'deposit_address') {
        throw new Error(`Export locked: address ${row.address} is a dedicated deposit address of ledger ${binding.ledgerId}`);
      }
    }
  }

  /** 出金目标/归集资格复用：某地址是否是合格的账本归集目标（原生钱包或外部地址均可，导入钱包不可） */
  async isQualifiedCollectionWallet(address) {
    const held = this._db.readQuery('SELECT wallet_type FROM wallets WHERE LOWER(address) = ?', [String(address).toLowerCase()]);
    if (held.length === 0) return true; // 外部地址：无密钥资格问题
    return held[0].wallet_type === 'native';
  }

  static get ZERO_ADDRESS() { return ZERO_ADDRESS; }
}
