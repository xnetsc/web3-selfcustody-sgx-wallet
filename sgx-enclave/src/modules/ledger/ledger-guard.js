/**
 * 账本资金护栏（挂在既有签名/导出路径上的执行点检查）
 *
 * 资产身份只认（链，合约地址）：ERC20 以代币合约地址区分，原生币为零
 * 地址；名称与符号不作任何判定依据（任何人都能发一个同名代币）。
 * 可归集资产按（账本，链，币种）逐项登记在合约上，与账本资产一一对应。
 *
 * 转账护栏（签名之前）：先按（链，币种）判定转出地址是不是账本绑定地址
 * （该链的专属充值地址，或被某账本登记为该（链，币种）的归集地址）。
 * 不是，普通转账不受影响；是，则逐个绑定账本做完整核对：账本启用、签名
 * 者是该账本所有权人且签名用的正是合约指定的那把所有权人 Passkey（同一
 * 账号的其它 Passkey 不能动绑定地址）、目标地址在合约为（账本，链，币种，
 * 源地址）配置的出金目标集内——任一绑定账本全项通过即放行（同一地址可
 * 登记为多个账本的归集地址，出金按其中一个账本的完整授权执行）。目标
 * 若是 SGX 托管钱包，还须是原生钱包（导入钱包私钥在外部存在过，不合
 * 格）。本护栏只挂普通授权路径：应急授权路径不经此护栏，应急操作只按
 * 应急授权自身的合约校验与 policy 执行。
 *
 * 导出护栏（密钥释放之前）：专属充值地址永久禁止导出；地址被登记为任一
 * 账本任一（链，币种）的归集地址时禁止导出（全部移出登记后锁定解除）；
 * 本地存在账本而合约不可用时拒绝导出（无法核对即不放行）。
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

/**
 * 从交易形态导出资产身份（账本形态）：data 是 ERC20 转账调用时，to 即代币
 * 合约地址；否则为原生币（'native'，与合约交互时译为零地址）。
 */
export function deriveAssetId(toAddress, data) {
  if (data && typeof data === 'string' && data.startsWith('0x') && data.length >= 10) {
    const selector = data.slice(0, 10).toLowerCase();
    if (selector === '0xa9059cbb' || selector === '0x23b872dd') {
      return String(toAddress || '').toLowerCase();
    }
  }
  return 'native';
}

/** 账本资产标识译为合约资产参数：原生币为零地址，ERC20 为其合约地址 */
function toContractAsset(assetId) {
  return assetId === 'native' ? ZERO_ADDRESS : assetId;
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
   * 判定地址在（链，币种）下的全部账本绑定：专属充值地址按链归属（该链
   * 任意币种的资金都属其账本）；归集登记逐个本地账本实时查合约在该
   * （链，币种）下的登记集，同一地址可被多个账本登记、返回多个绑定。
   * @returns {Promise<Array<{ledgerId: string, kind: 'deposit_address'|'pool'}>>}
   */
  async findBindings(chainId, assetId, address) {
    const target = String(address).toLowerCase();
    const bindings = [];
    const assignments = this._db.readQuery(
      'SELECT ledger_id FROM ledger_deposit_addresses WHERE chain_id = ? AND LOWER(address) = ?',
      [Number(chainId), target]
    );
    if (assignments.length > 0) {
      bindings.push({ ledgerId: assignments[0].ledger_id, kind: 'deposit_address' });
    }
    for (const ledger of this._localLedgers()) {
      const pool = await this._contract.getLedgerPoolAddresses(ledger.ledger_id, Number(chainId), toContractAsset(assetId)); // 合约不可用即抛错（fail-closed）
      if (pool.some((a) => a.toLowerCase() === target)) {
        bindings.push({ ledgerId: ledger.ledger_id, kind: 'pool' });
      }
    }
    return bindings;
  }

  /** 第一个绑定（无绑定返回 null） */
  async findBinding(chainId, assetId, address) {
    const all = await this.findBindings(chainId, assetId, address);
    return all[0] || null;
  }

  /**
   * 对单个绑定账本做完整授权核对：全部通过返回 null，否则返回拒绝原因。
   * 合约读取失败直接抛错（fail-closed），不降级为某个账本的拒绝原因。
   */
  async _evaluateBinding({ ledgerId, signerUserId, signerCredentialId, chainId, assetId, fromAddress, target }) {
    let designation;
    try {
      designation = await this._contract.getLedger(ledgerId);
    } catch (err) {
      throw new Error(`Ledger guard: contract unavailable, refusing to sign from a ledger-bound address (${err.message})`);
    }
    if (!designation) return `Ledger guard: ledger ${ledgerId} is not designated on contract`;
    if (!designation.enabled) return `Ledger guard: ledger ${ledgerId} is disabled`;
    if (designation.ownerUserId !== signerUserId) {
      return 'Ledger guard: source address is ledger-bound and the signer is not the ledger owner';
    }
    // 指定 Passkey：绑定地址只能由合约指定的那把所有权人 Passkey 签动，
    // 同一账号下的其它 Passkey 不得操作专属充值地址与归集地址
    if (!this._passkeys) {
      throw new Error('Ledger guard: passkey verification unavailable, refusing to sign from a ledger-bound address');
    }
    if (!signerCredentialId) {
      return 'Ledger guard: bound addresses can only be moved by the contract-designated owner passkey (authorization carries no credential)';
    }
    const passkey = await this._passkeys.getPasskey(signerUserId, signerCredentialId);
    if (!passkey) {
      return 'Ledger guard: signing passkey not found on the signer account';
    }
    const signingHash = PasskeyManager.computePubKeyHash(passkey.publicKeyCose);
    if (signingHash.toLowerCase() !== String(designation.ownerPubKeyHash).toLowerCase()) {
      return 'Ledger guard: bound addresses can only be moved by the contract-designated owner passkey';
    }
    let targets;
    try {
      targets = await this._contract.getCollectionPayoutTargets(ledgerId, Number(chainId), toContractAsset(assetId), fromAddress);
    } catch (err) {
      throw new Error(`Ledger guard: contract unavailable, cannot verify payout targets (${err.message})`);
    }
    if (!targets.some((a) => a.toLowerCase() === target)) {
      return `Ledger guard: target ${target} is not a configured payout target for this collection address on this chain and asset`;
    }
    return null;
  }

  /**
   * 转账签名前的护栏。在（链，币种）下未绑定直接放行；绑定时逐个绑定
   * 账本核对，任一账本完整授权即放行，全部不合则以第一个拒绝原因拒绝。
   * @param {Object} args
   * @param {string} args.signerUserId - 签名账户
   * @param {string} [args.signerCredentialId] - 本次授权实际签名用的 Passkey：绑定地址只认合约指定的那把
   * @param {number} args.chainId
   * @param {string} args.assetId - 资产标识：ERC20 合约地址，或原生币 'native'
   * @param {string} args.fromAddress
   * @param {string} args.toAddress
   * @param {string} [args.data] - 交易 data（raw 模式解实际收款方用）
   * @returns {Promise<{bound: boolean, ledgerId?: string}>}
   */
  async assertTransferAllowed({ signerUserId, signerCredentialId = null, chainId, assetId, fromAddress, toAddress, data = null }) {
    const bindings = await this.findBindings(chainId, assetId, fromAddress);
    if (bindings.length === 0) return { bound: false };

    const { target, isPlainTransfer } = decodeEffectiveTarget(toAddress, data);
    if (!isPlainTransfer) {
      throw new Error('Ledger guard: ledger-bound funds may only move via plain transfers to configured targets');
    }
    // 目标若是 SGX 托管钱包：必须是原生钱包（私钥从未在 SGX 外存在过）；与账本无关，先验
    const held = this._db.readQuery('SELECT wallet_type FROM wallets WHERE LOWER(address) = ?', [target]);
    if (held.length > 0 && held[0].wallet_type !== 'native') {
      throw new Error('Ledger guard: target wallet is not key-qualified (imported wallets cannot receive collection funds)');
    }

    let firstReason = null;
    for (const binding of bindings) {
      const reason = await this._evaluateBinding({
        ledgerId: binding.ledgerId, signerUserId, signerCredentialId,
        chainId, assetId, fromAddress, target,
      });
      if (!reason) return { bound: true, ledgerId: binding.ledgerId };
      if (!firstReason) firstReason = reason;
    }
    throw new Error(firstReason);
  }

  /**
   * 导出密钥释放前的护栏：逐行检查待导出钱包。密钥不分链不分币：地址在
   * 任一（链，币种）下登记为归集地址即锁；专属充值地址永久锁。
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
      const assignments = this._db.readQuery(
        'SELECT ledger_id FROM ledger_deposit_addresses WHERE LOWER(address) = ?',
        [String(row.address).toLowerCase()]
      );
      if (assignments.length > 0) {
        throw new Error(`Export locked: address ${row.address} is a dedicated deposit address of ledger ${assignments[0].ledger_id}`);
      }
      const registered = await this._contract.isCollectionAddress(row.address); // 合约不可用即抛错（fail-closed）
      if (registered) {
        throw new Error(`Export locked: address ${row.address} is registered as a collection address`);
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
