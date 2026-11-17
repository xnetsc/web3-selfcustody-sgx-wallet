/**
 * 平台账本（站内资产）API
 *
 * 全部请求走平台信封（payload + platformSignature，白名单验签）。
 * 写请求的信封 payload.userId 固定填账本所有权人 userId——它是分片路由键，
 * 账本全部记账写在所有权人写域内完成；实际操作人的身份由账本操作授权
 * 载荷（ledgerAuthorizationJson + ledgerSignature，Passkey 签名）证明，
 * 与路由键互不替代。账本操作不受 C 端账户冻结包装层检查：账本有独立的
 * 授权与冻结体系，管辖范围只及站内资产。
 *
 * 写：create / deposit-address/get-or-create / deposit/observe / deposit/claim /
 *     transfer / freeze / unfreeze / withdraw/request / withdraw/payout /
 *     withdraw/refresh / withdraw/cancel / convert/to-chain（= 提现到自有地址）
 * 读：get / list / balance / balances / entries / liabilities / deposits /
 *     deposit-addresses / withdrawals / freezes
 */

export class LedgerHandler {
  /**
   * @param {Object} deps
   * @param {import('../modules/auth-engine/whitelist-verifier.js').WhitelistVerifier} deps.whitelistVerifier
   * @param {import('../modules/ledger/ledger-service.js').LedgerService} deps.ledgerService
   * @param {import('../modules/ledger/ledger-deposits.js').LedgerDepositService} deps.ledgerDepositService
   * @param {import('../modules/ledger/ledger-withdrawals.js').LedgerWithdrawalService} deps.ledgerWithdrawalService
   * @param {import('../modules/contract-client/index.js').ContractClient} deps.contractClient
   */
  constructor(deps) {
    if (!deps.whitelistVerifier) throw new Error('LedgerHandler requires whitelistVerifier');
    if (!deps.ledgerService) throw new Error('LedgerHandler requires ledgerService');
    if (!deps.ledgerDepositService) throw new Error('LedgerHandler requires ledgerDepositService');
    if (!deps.ledgerWithdrawalService) throw new Error('LedgerHandler requires ledgerWithdrawalService');
    this._whitelist = deps.whitelistVerifier;
    this._ledger = deps.ledgerService;
    this._deposits = deps.ledgerDepositService;
    this._withdrawals = deps.ledgerWithdrawalService;
    this._contract = deps.contractClient || null;
  }

  /** 验平台信封并解析 payload；业务错误转 { success:false, reason } */
  async _handle(request, fn) {
    const whitelistResult = this._whitelist.verifyRequest(request.payload, request.platformSignature);
    if (!whitelistResult.valid) {
      throw new Error(`Platform verification failed: ${whitelistResult.reason}`);
    }
    let payload;
    try {
      payload = JSON.parse(request.payload);
    } catch {
      throw new Error('Invalid payload: must be valid JSON');
    }
    try {
      const data = await fn(payload);
      return { success: true, ...data };
    } catch (err) {
      return { success: false, reason: err.message };
    }
  }

  _requireLedgerId(payload) {
    if (!payload.ledgerId) throw new Error('ledgerId is required');
    return payload.ledgerId;
  }

  _authz(payload) {
    if (!payload.ledgerAuthorizationJson || !payload.ledgerSignature) {
      throw new Error('ledgerAuthorizationJson and ledgerSignature are required');
    }
    return { payloadJson: payload.ledgerAuthorizationJson, signature: payload.ledgerSignature };
  }

  // ---------- 写 ----------

  async handleCreate(request) {
    return this._handle(request, async (payload) => {
      const ledger = await this._ledger.createLedger({
        ledgerId: this._requireLedgerId(payload), ...this._authz(payload),
      });
      return { ledger };
    });
  }

  async handleGetOrCreateDepositAddress(request) {
    return this._handle(request, async (payload) => {
      // 信封 userId 是所有权人（分片路由键）；开通对象是 targetUserId
      if (!payload.targetUserId) throw new Error('targetUserId is required');
      if (payload.chainId === undefined) throw new Error('chainId is required');
      const result = await this._deposits.getOrCreateDepositAddress({
        ledgerId: this._requireLedgerId(payload),
        userId: payload.targetUserId,
        chainId: payload.chainId,
      });
      return result;
    });
  }

  async handleObserveDeposit(request) {
    return this._handle(request, async (payload) => {
      if (payload.chainId === undefined) throw new Error('chainId is required');
      if (!payload.txHash) throw new Error('txHash is required');
      const results = await this._deposits.observeDeposit({
        ledgerId: this._requireLedgerId(payload), chainId: payload.chainId, txHash: payload.txHash,
      });
      return { results };
    });
  }

  async handleClaimDeposit(request) {
    return this._handle(request, async (payload) => {
      if (!payload.depositId) throw new Error('depositId is required');
      if (!payload.targetUserId) throw new Error('targetUserId is required');
      const result = await this._deposits.claimDeposit({
        ledgerId: this._requireLedgerId(payload), ...this._authz(payload),
        depositId: payload.depositId, targetUserId: payload.targetUserId,
      });
      return result;
    });
  }

  async handleTransfer(request) {
    return this._handle(request, async (payload) => {
      const result = await this._ledger.transfer({
        ledgerId: this._requireLedgerId(payload), ...this._authz(payload),
        toUserId: payload.toUserId, chainId: payload.chainId,
        assetId: payload.assetId, amount: payload.amount,
      });
      return result;
    });
  }

  async handleFreeze(request) {
    return this._handle(request, async (payload) => {
      if (!payload.targetUserId) throw new Error('targetUserId is required');
      const result = await this._ledger.freeze({
        ledgerId: this._requireLedgerId(payload), ...this._authz(payload),
        targetUserId: payload.targetUserId,
        chainId: payload.chainId ?? null, assetId: payload.assetId ?? null,
        targetAmount: payload.targetAmount ?? null, reason: payload.reason ?? null,
      });
      return { freezeId: result.freezeId, moved: result.moved.toString() };
    });
  }

  async handleUnfreeze(request) {
    return this._handle(request, async (payload) => {
      if (!payload.freezeId) throw new Error('freezeId is required');
      const result = await this._ledger.unfreeze({
        ledgerId: this._requireLedgerId(payload), ...this._authz(payload),
        freezeId: payload.freezeId, amount: payload.amount ?? null, liftAll: !!payload.liftAll,
      });
      return { released: result.released.toString(), lifted: result.lifted };
    });
  }

  async handleWithdrawRequest(request) {
    return this._handle(request, async (payload) => {
      const withdrawal = await this._withdrawals.requestWithdrawal({
        ledgerId: this._requireLedgerId(payload), ...this._authz(payload),
        chainId: payload.chainId, assetId: payload.assetId, amount: payload.amount,
        toAddress: payload.toAddress, sourceAddress: payload.sourceAddress,
      });
      return { withdrawal };
    });
  }

  /** 链上 → 站内互转即充值观察入账（handleObserveDeposit）；站内 → 链上即提现到自有地址 */
  async handleConvertToChain(request) {
    return this.handleWithdrawRequest(request);
  }

  async handleWithdrawPayout(request) {
    return this._handle(request, async (payload) => {
      if (!payload.withdrawalId) throw new Error('withdrawalId is required');
      const result = await this._withdrawals.executePayout({
        ledgerId: this._requireLedgerId(payload), withdrawalId: payload.withdrawalId,
      });
      return result;
    });
  }

  async handleWithdrawRefresh(request) {
    return this._handle(request, async (payload) => {
      if (!payload.withdrawalId) throw new Error('withdrawalId is required');
      const result = await this._withdrawals.refreshWithdrawal({
        ledgerId: this._requireLedgerId(payload), withdrawalId: payload.withdrawalId,
      });
      return result;
    });
  }

  async handleWithdrawCancel(request) {
    return this._handle(request, async (payload) => {
      if (!payload.withdrawalId) throw new Error('withdrawalId is required');
      const result = await this._withdrawals.cancelWithdrawal({
        ledgerId: this._requireLedgerId(payload), ...this._authz(payload),
        withdrawalId: payload.withdrawalId,
      });
      return result;
    });
  }

  // ---------- 读（只出账本侧数据；链上余额由外部自查） ----------

  async handleGet(request) {
    return this._handle(request, async (payload) => {
      const ledgerId = this._requireLedgerId(payload);
      const ledger = this._ledger.getLedgerRow(ledgerId);
      if (!ledger) return { success: false, reason: `ledger ${ledgerId} does not exist (not created in SGX)` };
      let designation = null;
      if (this._contract) {
        try { designation = await this._contract.getLedger(ledgerId); } catch { designation = null; }
      }
      return { ledger, designation };
    });
  }

  async handleList(request) {
    return this._handle(request, async (payload) => {
      const ledgers = this._ledger.listLedgers(payload.ownerUserId || null);
      return { ledgers };
    });
  }

  async handleBalance(request) {
    return this._handle(request, async (payload) => {
      const ledgerId = this._requireLedgerId(payload);
      if (!payload.userId) throw new Error('userId is required');
      if (payload.chainId !== undefined && payload.assetId) {
        const balance = this._ledger.getBalance(ledgerId, payload.userId, payload.chainId, payload.assetId);
        return { balance };
      }
      const balances = this._ledger.listUserBalances(ledgerId, payload.userId);
      return { balances };
    });
  }

  async handleBalances(request) {
    return this._handle(request, async (payload) => {
      const balances = this._ledger.listLedgerBalances(this._requireLedgerId(payload), {
        limit: payload.limit || 100, offset: payload.offset || 0,
      });
      return { balances };
    });
  }

  async handleEntries(request) {
    return this._handle(request, async (payload) => {
      const entries = this._ledger.listEntries(this._requireLedgerId(payload), {
        userId: payload.userId || null, kind: payload.kind || null,
        limit: payload.limit || 100, offset: payload.offset || 0,
      });
      return { entries };
    });
  }

  async handleLiabilities(request) {
    return this._handle(request, async (payload) => {
      const liabilities = this._ledger.totalLiabilities(
        this._requireLedgerId(payload), payload.chainId, payload.assetId
      );
      return { liabilities };
    });
  }

  async handleDeposits(request) {
    return this._handle(request, async (payload) => {
      const ledgerId = this._requireLedgerId(payload);
      if (payload.txHash) {
        const deposits = this._deposits.getDepositsByTxHash(payload.chainId, payload.txHash)
          .filter((d) => d.ledger_id === ledgerId);
        return { deposits };
      }
      const deposits = this._deposits.listDeposits(ledgerId, {
        userId: payload.userId || null, status: payload.status || null,
        limit: payload.limit || 100, offset: payload.offset || 0,
      });
      return { deposits };
    });
  }

  async handleDepositAddresses(request) {
    return this._handle(request, async (payload) => {
      const ledgerId = this._requireLedgerId(payload);
      const addresses = this._deposits.listDepositAddresses(ledgerId);
      const creditedTotals = payload.chainId !== undefined
        ? this._deposits.creditedTotalsByAddress(ledgerId, payload.chainId)
        : [];
      return { addresses, creditedTotals };
    });
  }

  async handleWithdrawals(request) {
    return this._handle(request, async (payload) => {
      const ledgerId = this._requireLedgerId(payload);
      if (payload.withdrawalId) {
        const withdrawal = this._withdrawals.getWithdrawal(payload.withdrawalId);
        if (!withdrawal || withdrawal.ledger_id !== ledgerId) {
          return { success: false, reason: 'withdrawal not found' };
        }
        return { withdrawal };
      }
      const withdrawals = this._withdrawals.listWithdrawals(ledgerId, {
        userId: payload.userId || null, status: payload.status || null,
        limit: payload.limit || 100, offset: payload.offset || 0,
      });
      return { withdrawals };
    });
  }

  async handleFreezes(request) {
    return this._handle(request, async (payload) => {
      const freezes = this._ledger.listActiveFreezes(
        this._requireLedgerId(payload), payload.userId || null
      );
      return { freezes };
    });
  }
}
