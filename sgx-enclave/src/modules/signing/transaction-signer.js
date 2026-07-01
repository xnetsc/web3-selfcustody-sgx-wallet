/**
 * 交易签名核心模块
 * 使用低层 raw transaction 方法构造并签名交易
 *
 * 禁止使用任何结构化的高层接口发起交易
 * 包括但不限于 Wallet/Signer 的高层发送方法、Contract 方法直接调用、Provider 广播方法等
 *
 * 本模块仅负责签名，不负责广播交易
 */

import { ethers } from 'ethers';
import { KNOWN_TX_TYPES, KNOWN_OPERATIONS } from '../auth-engine/authorization-parser.js';

export class TransactionSigner {
  /**
   * @param {import('../state-management/state-manager.js').StateManager} stateManager - 状态管理器
   * @param {import('../wallet-management/wallet-manager.js').WalletManager} walletManager - 钱包管理器
   */
  constructor(stateManager, walletManager) {
    if (!stateManager) {
      throw new Error('TransactionSigner requires a StateManager instance');
    }
    if (!walletManager) {
      throw new Error('TransactionSigner requires a WalletManager instance');
    }
    this._stateManager = stateManager;
    this._walletManager = walletManager;
  }

  /**
   * 签名原始交易（低层实现，禁止使用高层接口）
   *
   * @param {Object} txParams - 原始交易参数
   * @param {number} txParams.chainId - 链 ID
   * @param {string} txParams.to - 目标地址
   * @param {string} txParams.value - 转账金额（Wei 字符串）
   * @param {string} txParams.data - 交易数据（合约调用 calldata，普通转账请显式传入 '0x'）
   * @param {string} txParams.gasLimit - Gas 上限
   * @param {string} [txParams.gasPrice] - Gas 价格（Legacy 交易）
   * @param {string} [txParams.maxFeePerGas] - EIP-1559 最大费用
   * @param {string} [txParams.maxPriorityFeePerGas] - EIP-1559 优先费
   * @param {number} txParams.nonce - 交易 nonce
   * @param {number} txParams.type - 交易类型（0=Legacy, 2=EIP-1559），必须由请求者显式传入
   * @param {string} privateKey - 签名私钥（十六进制，含 0x 前缀）
   * @returns {{ signedTransaction: string, txHash: string }}
   */
  signRawTransaction(txParams, privateKey) {
    if (!txParams || !privateKey) {
      throw new Error('txParams and privateKey are required');
    }

    // 所有交易参数必须由请求者显式传入，JS 代码不允许自行设置任何默认值
    if (txParams.type === undefined || txParams.type === null) {
      throw new Error('txParams.type is required: must be explicitly provided by the requester (0=Legacy, 2=EIP-1559)');
    }
    if (txParams.nonce === undefined || txParams.nonce === null) {
      throw new Error('txParams.nonce is required: must be explicitly provided by the requester');
    }
    if (txParams.gasLimit === undefined || txParams.gasLimit === null) {
      throw new Error('txParams.gasLimit is required: must be explicitly provided by the requester');
    }
    if (txParams.chainId === undefined || txParams.chainId === null) {
      throw new Error('txParams.chainId is required: must be explicitly provided by the requester');
    }
    if (txParams.value === undefined || txParams.value === null) {
      throw new Error('txParams.value is required: must be explicitly provided by the requester');
    }
    if (txParams.data === undefined || txParams.data === null) {
      throw new Error('txParams.data is required: must be explicitly provided by the requester (use "0x" for no data)');
    }

    const txType = txParams.type;

    if (txType === 2) {
      if (txParams.maxFeePerGas === undefined || txParams.maxFeePerGas === null) {
        throw new Error('txParams.maxFeePerGas is required for EIP-1559 (type=2) transactions');
      }
      if (txParams.maxPriorityFeePerGas === undefined || txParams.maxPriorityFeePerGas === null) {
        throw new Error('txParams.maxPriorityFeePerGas is required for EIP-1559 (type=2) transactions');
      }
    } else {
      if (txParams.gasPrice === undefined || txParams.gasPrice === null) {
        throw new Error('txParams.gasPrice is required for Legacy (type=0/1) transactions');
      }
    }

    // 构造 Transaction 对象（低层 API）— 所有字段直接来自请求者，无任何默认值
    const txData = {
      chainId: txParams.chainId,
      to: txParams.to,
      value: txParams.value,
      data: txParams.data,
      gasLimit: txParams.gasLimit,
      nonce: txParams.nonce,
      type: txType,
    };

    if (txType === 2) {
      // EIP-1559
      txData.maxFeePerGas = txParams.maxFeePerGas;
      txData.maxPriorityFeePerGas = txParams.maxPriorityFeePerGas;
    } else {
      // Legacy
      txData.gasPrice = txParams.gasPrice;
    }

    const tx = ethers.Transaction.from(txData);

    console.log(`[TransactionSigner] signRawTransaction: type=${txType}, chainId=${txParams.chainId}, to=${txParams.to}, nonce=${txParams.nonce}, value=${txParams.value}`);

    // 使用私钥签名（低层操作：SigningKey + sign）
    const signingKey = new ethers.SigningKey(privateKey);
    const signature = signingKey.sign(tx.unsignedHash);

    tx.signature = signature;

    console.log(`[TransactionSigner] signRawTransaction: success, txHash=${tx.hash}`);

    return {
      signedTransaction: tx.serialized,
      txHash: tx.hash,
    };
  }

  /**
   * 从二进制字节（十六进制字符串）识别交易类型
   *
   * 识别规则：
   *   - 已知类型（0, 1, 2, 4）→ 返回 { recognized: true, txType, parsed }
   *   - 无法识别 → 返回 { recognized: false }
   *
   * @param {string} rawTxHex - 十六进制字符串
   * @returns {{ recognized: boolean, txType?: number, parsed?: Object }}
   */
  identifyTransactionType(rawTxHex) {
    if (!rawTxHex) {
      throw new Error('rawTxHex is required');
    }

    const hex = rawTxHex.startsWith('0x') ? rawTxHex : '0x' + rawTxHex;
    console.log(`[TransactionSigner] identifyTransactionType: hexLength=${hex.length}`);

    try {
      const parsed = ethers.Transaction.from(hex);
      const txType = parsed.type;

      // 检查是否为已知类型
      const knownTypes = Object.values(KNOWN_TX_TYPES);
      if (knownTypes.includes(txType)) {
        console.log(`[TransactionSigner] identifyTransactionType: recognized, txType=${txType}, chainId=${Number(parsed.chainId)}, to=${parsed.to}`);
        return {
          recognized: true,
          txType,
          parsed: {
            chainId: Number(parsed.chainId),
            to: parsed.to,
            value: parsed.value.toString(),
            data: parsed.data || '0x',
            gasLimit: parsed.gasLimit.toString(),
            nonce: parsed.nonce,
            type: txType,
            gasPrice: parsed.gasPrice ? parsed.gasPrice.toString() : undefined,
            maxFeePerGas: parsed.maxFeePerGas ? parsed.maxFeePerGas.toString() : undefined,
            maxPriorityFeePerGas: parsed.maxPriorityFeePerGas ? parsed.maxPriorityFeePerGas.toString() : undefined,
          },
        };
      }

      // ethers 解析成功但类型不在已知列表中
      // 即使类型不识别，也应返回 parsed 以便后续使用
      console.log(`[TransactionSigner] identifyTransactionType: unrecognized txType=${txType}`);
      return {
        recognized: false,
        txType,
        parsed: {
          chainId: Number(parsed.chainId),
          to: parsed.to,
          value: parsed.value.toString(),
          data: parsed.data || '0x',
          gasLimit: parsed.gasLimit.toString(),
          nonce: parsed.nonce,
          type: txType,
          gasPrice: parsed.gasPrice ? parsed.gasPrice.toString() : undefined,
          maxFeePerGas: parsed.maxFeePerGas ? parsed.maxFeePerGas.toString() : undefined,
          maxPriorityFeePerGas: parsed.maxPriorityFeePerGas ? parsed.maxPriorityFeePerGas.toString() : undefined,
        },
      };
    } catch (_err) {
      // ethers 无法解析 → 不可识别的二进制数据
      console.log(`[TransactionSigner] identifyTransactionType: parse failed, treating as arbitrary data`);
      return { recognized: false };
    }
  }

  /**
   * 根据已识别的交易类型和解析字段，进一步分类操作类型
   *
   * @param {{ recognized: boolean, txType?: number, parsed?: Object }} identification
   * @returns {string} KNOWN_OPERATIONS 之一
   */
  identifyOperation(identification) {
    if (!identification.recognized) {
      console.log(`[TransactionSigner] identifyOperation: unrecognized data -> arbitraryData`);
      return 'arbitraryData';
    }

    const { txType, parsed } = identification;

    // type 4 = EIP-7702 交易
    if (txType === KNOWN_TX_TYPES.EIP_7702) {
      console.log(`[TransactionSigner] identifyOperation: txType=4 -> eip7702Tx`);
      return 'eip7702Tx';
    }

    // type 0/1/2: 根据 to 和 data 区分
    const to = parsed.to;
    const data = parsed.data;
    const hasData = data && data !== '0x' && data !== '0x00' && data.length > 2;

    let op;
    if (!to || to === '0x' || to === ethers.ZeroAddress) {
      // to 为 null/空 = 合约部署
      op = hasData ? 'contractDeploy' : 'arbitraryData';
    } else if (hasData) {
      op = 'contractCall';
    } else {
      op = 'transfer';
    }

    console.log(`[TransactionSigner] identifyOperation: txType=${txType}, to=${to}, hasData=${hasData} -> ${op}`);
    return op;
  }

  /**
   * 统一的地址匹配函数，支持 "*" 通配符
   * @param {string} ruleAddress - 规则中的地址（或 "*"）
   * @param {string} actualAddress - 实际地址
   * @returns {boolean}
   */
  addressMatch(ruleAddress, actualAddress) {
    if (ruleAddress === '*') return true;
    return ruleAddress.toLowerCase() === actualAddress.toLowerCase();
  }

  /**
   * 检查 dataPolicy 是否允许签名该类型的数据
   *
   * @param {Object|undefined} dataPolicy - 授权 JSON 中的 scope.dataPolicy
   * @param {{ recognized: boolean, txType?: number }} identification - identifyTransactionType 返回值
   * @param {string} [operationType] - 操作类型（由 identifyOperation 返回）
   * @returns {{ allowed: boolean, reason: string }}
   */
  checkDataPolicy(dataPolicy, identification, operationType) {
    console.log(`[TransactionSigner] checkDataPolicy: recognized=${identification.recognized}, operationType=${operationType}, hasPolicy=${!!dataPolicy}`);

    // 没有 dataPolicy 时，默认行为：只允许已知交易类型，不允许任意二进制
    if (!dataPolicy) {
      if (!identification.recognized) {
        console.log(`[TransactionSigner] checkDataPolicy: REJECTED - unrecognized data, no policy`);
        return { allowed: false, reason: 'Unrecognized binary data not allowed: no dataPolicy configured' };
      }
      // 没有 dataPolicy 且是已知类型 → 允许（不限制类型）
      return { allowed: true, reason: 'OK' };
    }

    // 不可识别的二进制数据 → 检查 allowArbitraryData
    if (!identification.recognized) {
      if (dataPolicy.allowArbitraryData === true) {
        return { allowed: true, reason: 'Arbitrary binary data allowed by dataPolicy' };
      }
      return { allowed: false, reason: 'Unrecognized binary data not allowed by dataPolicy' };
    }

    // 已知交易类型 → 检查 allowedTxTypes
    if (dataPolicy.allowedTxTypes) {
      if (!dataPolicy.allowedTxTypes.includes(identification.txType)) {
        return { allowed: false, reason: `Transaction type ${identification.txType} not in allowedTxTypes` };
      }
    }

    // 检查 allowedOperations
    if (operationType && dataPolicy.allowedOperations) {
      if (!dataPolicy.allowedOperations.includes(operationType)) {
        console.log(`[TransactionSigner] checkDataPolicy: REJECTED - operation '${operationType}' not in allowedOperations`);
        return { allowed: false, reason: `Operation type '${operationType}' not in allowedOperations` };
      }
    }

    console.log(`[TransactionSigner] checkDataPolicy: ALLOWED`);
    return { allowed: true, reason: 'OK' };
  }

  /**
   * 检查 EIP-7702 策略
   * 适用于 eip7702Auth 和 eip7702Tx 操作
   *
   * @param {Object|undefined} eip7702Policy - 授权 JSON 中的 scope.eip7702Policy
   * @param {string} operationType - 操作类型
   * @param {Object} [context] - 上下文信息
   * @param {string} [context.delegateContract] - 委托合约地址
   * @param {number} [context.chainId] - 链 ID
   * @param {string} [context.functionSelector] - 函数选择器（4 字节 hex）
   * @returns {{ allowed: boolean, reason: string }}
   */
  checkEip7702Policy(eip7702Policy, operationType, context) {
    // 非 EIP-7702 操作不需要检查
    if (operationType !== 'eip7702Auth' && operationType !== 'eip7702Tx') {
      return { allowed: true, reason: 'OK' };
    }

    console.log(`[TransactionSigner] checkEip7702Policy: operationType=${operationType}, hasPolicy=${!!eip7702Policy}`);

    // EIP-7702 操作但没有策略 → 拒绝
    if (!eip7702Policy) {
      console.log(`[TransactionSigner] checkEip7702Policy: REJECTED - no policy for EIP-7702 operation`);
      return { allowed: false, reason: 'EIP-7702 operation requires eip7702Policy in authorization' };
    }

    // 检查委托合约地址
    if (context && context.delegateContract && eip7702Policy.allowedDelegateContracts) {
      const contractAllowed = eip7702Policy.allowedDelegateContracts.some(
        (c) => c.chainId === context.chainId && this.addressMatch(c.address, context.delegateContract)
      );
      if (!contractAllowed) {
        console.log(`[TransactionSigner] checkEip7702Policy: REJECTED - delegate contract ${context.delegateContract} not allowed`);
        return { allowed: false, reason: 'Delegate contract not in allowedDelegateContracts' };
      }
    }

    // 检查函数选择器
    if (context && context.functionSelector && eip7702Policy.allowedFunctionSelectors) {
      const selectorAllowed = eip7702Policy.allowedFunctionSelectors.some(
        (s) => s.toLowerCase() === context.functionSelector.toLowerCase()
      );
      if (!selectorAllowed) {
        console.log(`[TransactionSigner] checkEip7702Policy: REJECTED - selector ${context.functionSelector} not allowed`);
        return { allowed: false, reason: 'Function selector not in allowedFunctionSelectors' };
      }
    }

    console.log(`[TransactionSigner] checkEip7702Policy: ALLOWED`);
    return { allowed: true, reason: 'OK' };
  }

  /**
   * 解析预构造的交易十六进制字符串，提取授权规则匹配所需参数
   *
   * @param {string} rawTxHex - 预构造的未签名交易（十六进制字符串，含 0x 前缀）
   * @returns {{ chainId: number, to: string, value: string, data: string, gasLimit: string, nonce: number, type: number }}
   */
  parseRawTransactionHex(rawTxHex) {
    if (!rawTxHex) {
      throw new Error('rawTxHex is required');
    }

    const hex = rawTxHex.startsWith('0x') ? rawTxHex : '0x' + rawTxHex;

    let parsed;
    try {
      parsed = ethers.Transaction.from(hex);
    } catch (err) {
      throw new Error('Failed to parse raw transaction hex: ' + err.message);
    }

    return {
      chainId: Number(parsed.chainId),
      to: parsed.to,
      value: parsed.value.toString(),
      data: parsed.data || '0x',
      gasLimit: parsed.gasLimit.toString(),
      nonce: parsed.nonce,
      type: parsed.type,
      gasPrice: parsed.gasPrice ? parsed.gasPrice.toString() : undefined,
      maxFeePerGas: parsed.maxFeePerGas ? parsed.maxFeePerGas.toString() : undefined,
      maxPriorityFeePerGas: parsed.maxPriorityFeePerGas ? parsed.maxPriorityFeePerGas.toString() : undefined,
    };
  }

  /**
   * 对预构造的交易十六进制字符串直接做密码学签名
   * 输入为已构造好的未签名交易的 RLP 编码（十六进制字符串）
   *
   * @param {string} rawTxHex - 未签名交易的十六进制字符串
   * @param {string} privateKey - 签名私钥（十六进制，含 0x 前缀）
   * @returns {{ signedTransaction: string, txHash: string, parsedParams: Object }}
   */
  signRawBytes(rawTxHex, privateKey) {
    if (!rawTxHex || !privateKey) {
      throw new Error('rawTxHex and privateKey are required');
    }

    const hex = rawTxHex.startsWith('0x') ? rawTxHex : '0x' + rawTxHex;

    // 从十六进制字符串反序列化为 Transaction 对象
    const tx = ethers.Transaction.from(hex);

    console.log(`[TransactionSigner] signRawBytes: type=${tx.type}, chainId=${Number(tx.chainId)}, to=${tx.to}, nonce=${tx.nonce}`);

    // 使用私钥签名（低层操作：SigningKey + sign）
    const signingKey = new ethers.SigningKey(privateKey);
    const signature = signingKey.sign(tx.unsignedHash);

    tx.signature = signature;

    console.log(`[TransactionSigner] signRawBytes: success, txHash=${tx.hash}`);

    // 同时返回解析出的参数，供授权匹配使用
    const parsedParams = {
      chainId: Number(tx.chainId),
      to: tx.to,
      value: tx.value.toString(),
      data: tx.data || '0x',
      gasLimit: tx.gasLimit.toString(),
      nonce: tx.nonce,
      type: tx.type,
    };

    return {
      signedTransaction: tx.serialized,
      txHash: tx.hash,
      parsedParams,
    };
  }

  /**
   * 对任意二进制数据（十六进制字符串）做以太坊格式签名
   * 仅在 dataPolicy.allowArbitraryData === true 时才应调用
   * 使用 keccak256 哈希后 SigningKey.sign
   *
   * @param {string} dataHex - 任意二进制数据的十六进制字符串
   * @param {string} privateKey - 签名私钥（十六进制，含 0x 前缀）
   * @returns {{ signature: string, messageHash: string }}
   */
  signArbitraryData(dataHex, privateKey) {
    if (!dataHex || !privateKey) {
      throw new Error('dataHex and privateKey are required');
    }

    const hex = dataHex.startsWith('0x') ? dataHex : '0x' + dataHex;

    console.log(`[TransactionSigner] signArbitraryData: dataLength=${hex.length}`);

    // keccak256 哈希
    const messageHash = ethers.keccak256(hex);

    // 使用私钥签名（低层操作：SigningKey + sign）
    const signingKey = new ethers.SigningKey(privateKey);
    const sig = signingKey.sign(messageHash);

    console.log(`[TransactionSigner] signArbitraryData: success, messageHash=${messageHash}`);

    return {
      signature: ethers.Signature.from(sig).serialized,
      messageHash,
    };
  }

  /**
   * 从解析后的交易数据推导 tokenAddress
   *
   * 核心规则：
   * 1. 交易可能同时包含多种操作（复合交易），需要全面分析所有维度
   * 2. value > 0 表示有原生币转账，但不排除同时有ERC20转账
   * 3. to 不是合法地址，data 有值 → 合约部署
   * 4. to 是合法地址，data 有值 → 根据函数选择器识别 ERC20 操作
   *
   * 注意：value、to、data 三个维度完全独立，没有绑定或互斥关系
   *
   * 支持的 ERC20 函数选择器：
   *   - 0xa9059cbb: transfer(address,uint256)
   *   - 0x095ea7b3: approve(address,uint256)
   *   - 0x23b872dd: transferFrom(address,address,uint256)
   *   - 0x70a08231: balanceOf(address)（只读，amount=0）
   *
   * @param {{ to: string|null, value: string, data: string, chainId: number }} parsedTx - parseRawTransactionHex 返回值
   * @returns {{ tokens: Array<{tokenAddress: string, amount: string, isNative: boolean}>, reason: string }}
   */
  deriveTokenAddressFromParsedTx(parsedTx) {
    const { to, value, data, chainId } = parsedTx;
    const hasData = data && data !== '0x' && data.length > 2;
    const effectiveValue = value || '0';
    const valueBigInt = BigInt(effectiveValue);
    const isValidAddress = to && to !== '0x' && to !== '0x0000000000000000000000000000000000000000' && to.length === 42;
    
    // 用于存储识别出的所有token
    const tokens = [];
    let reason = '';
    
    // 1. 检查是否有原生币转账 (value > 0)
    if (valueBigInt > 0n) {
      tokens.push({
        tokenAddress: `${chainId}_native`,
        amount: effectiveValue,
        isNative: true
      });
      reason += 'Native token transfer (value > 0). ';
    }
    
    // 2. 检查是否有合约交互
    if (hasData) {
      if (!isValidAddress) {
        // 合约部署
        tokens.push({
          tokenAddress: `${chainId}_unknown`,
          amount: '0',
          isNative: false
        });
        reason += 'Contract deployment (to is null/invalid, data non-empty). ';
      } else {
        // 检查函数选择器（前 4 字节 = 10 个十六进制字符含 0x 前缀）
        const functionSelector = data.substring(0, 10).toLowerCase();
        
        if (functionSelector === '0xa9059cbb') {
          // ERC20 transfer(address,uint256)
          // 参数布局：[4字节选择器][32字节地址][32字节金额]
          // data 十六进制：0x + 8(selector) + 64(address padded) + 64(amount)
          try {
            const addressHex = '0x' + data.substring(34, 74);
            const amountHex = '0x' + data.substring(74, 138);
            const amount = BigInt(amountHex).toString();
            tokens.push({
              tokenAddress: to, // ERC20 合约地址
              amount: amount,
              isNative: false
            });
            reason += `ERC20 transfer(address,uint256) detected to ${addressHex} (selector: 0xa9059cbb). `;
          } catch (err) {
            throw new Error(`Failed to parse ERC20 transfer parameters: ${err.message}`);
          }
          
        } else if (functionSelector === '0x095ea7b3') {
          // ERC20 approve(address,uint256)
          // 参数布局：[4字节选择器][32字节spender地址][32字节金额]
          try {
            const spenderHex = '0x' + data.substring(34, 74);
            const amountHex = '0x' + data.substring(74, 138);
            const amount = BigInt(amountHex).toString();
            tokens.push({
              tokenAddress: to, // ERC20 合约地址
              amount: amount,
              isNative: false
            });
            reason += `ERC20 approve(address,uint256) detected for spender ${spenderHex} (selector: 0x095ea7b3). `;
          } catch (err) {
            throw new Error(`Failed to parse ERC20 approve parameters: ${err.message}`);
          }
          
        } else if (functionSelector === '0x23b872dd') {
          // ERC20 transferFrom(address,address,uint256)
          // 参数布局：[4字节选择器][32字节from地址][32字节to地址][32字节金额]
          try {
            const fromHex = '0x' + data.substring(34, 74);
            const toHex = '0x' + data.substring(74, 114);
            const amountHex = '0x' + data.substring(114, 178);
            const amount = BigInt(amountHex).toString();
            tokens.push({
              tokenAddress: to, // ERC20 合约地址
              amount: amount,
              isNative: false
            });
            reason += `ERC20 transferFrom(address,address,uint256) detected from ${fromHex} to ${toHex} (selector: 0x23b872dd). `;
          } catch (err) {
            throw new Error(`Failed to parse ERC20 transferFrom parameters: ${err.message}`);
          }
          
        } else if (functionSelector === '0x70a08231') {
          // ERC20 balanceOf(address) — 只读查询，不涉及转账，amount = 0
          // 参数布局：[4字节选择器][32字节account地址]
          try {
            const accountHex = '0x' + data.substring(34, 74);
            tokens.push({
              tokenAddress: to, // ERC20 合约地址
              amount: '0',
              isNative: false
            });
            reason += `ERC20 balanceOf(address) detected for account ${accountHex} (selector: 0x70a08231). `;
          } catch (err) {
            throw new Error(`Failed to parse ERC20 balanceOf parameters: ${err.message}`);
          }
          
        } else {
          // 不可识别的函数选择器，抛出异常终止流程
          throw new Error(`Unrecognized function selector: ${functionSelector}. Supported selectors: 0xa9059cbb (transfer), 0x095ea7b3 (approve), 0x23b872dd (transferFrom), 0x70a08231 (balanceOf).`);
        }
      }
    }
    
    // 如果没有识别出任何token（空交易）
    if (tokens.length === 0) {
      tokens.push({
        tokenAddress: `${chainId}_unknown`,
        amount: '0',
        isNative: false
      });
      reason = 'Empty transaction (value == 0, data empty)';
    }
    
    return {
      tokens: tokens,
      reason: reason.trim()
    };
  }

  /**
   * 完整签名流程：从数据库取私钥 → 校验 dataPolicy → 签名 → 更新状态
   *
   * 支持三种输入模式：
   *   模式一：传入结构化 txParams 对象（仅基本转账）
   *   模式二：传入预构造的 rawTxHex 十六进制字符串（所有其它交易类型）
   *   模式三：rawTxHex 为不可识别的任意二进制数据（需 dataPolicy.allowArbitraryData=true）
   *
   * @param {Object} params
   * @param {string} params.userId - 用户 ID
   * @param {string} params.authorizationId - 授权 ID
   * @param {Object} [params.txParams] - 结构化交易参数（模式一，仅基本转账）
   * @param {string} [params.rawTxHex] - 预构造的交易十六进制字符串（模式二/三）
   * @param {string} params.walletAddress - 签名钱包地址
   * @param {string} params.tokenAddress - Token 地址（原生代币使用 "{chainId}_native" 格式，模式一必传）
   * @param {number} [params.chainId] - 链 ID（模式三不可识别时必传，用于查钱包）
   * @param {Object} [params.dataPolicy] - 授权 JSON 中的 scope.dataPolicy
   * @returns {Promise<{ signedTransaction?: string, txHash?: string, signature?: string, messageHash?: string, derivedTokenInfo?: Object }>}
   */
  async signAndUpdate(params) {
    const { userId, authorizationId, txParams, rawTxHex, walletAddress, tokenAddress, dataPolicy } = params;

    console.log(`[TransactionSigner] signAndUpdate: userId=${userId}, authorizationId=${authorizationId}, walletAddress=${walletAddress}, mode=${txParams ? 'txParams' : 'rawTxHex'}`);

    if (!userId || !authorizationId || !walletAddress) {
      throw new Error('userId, authorizationId, and walletAddress are required');
    }
    if (!txParams && !rawTxHex) {
      throw new Error('Either txParams or rawTxHex must be provided');
    }

    // ===== 模式一：结构化参数（仅基本转账） =====
    if (txParams && !rawTxHex) {
      console.log(`[TransactionSigner] signAndUpdate: mode=txParams, chainId=${txParams.chainId}, to=${txParams.to}, value=${txParams.value}`);
      // 结构化参数直接签名，无需交易类型识别
      const walletInfo = await this._walletManager.getWalletByAddress(
        userId,
        txParams.chainId,
        walletAddress
      );
      if (!walletInfo) {
        throw new Error(`Wallet not found: userId=${userId}, chainId=${txParams.chainId}, address=${walletAddress}`);
      }

      const privateKey = walletInfo.privateKey.startsWith('0x')
        ? walletInfo.privateKey
        : '0x' + walletInfo.privateKey;

      let result;
      try {
        result = this.signRawTransaction(txParams, privateKey);
      } catch (err) {
        throw new Error('Transaction signing failed: ' + err.message);
      }

      // 签名成功后递增累计值 — amount 和 tokenAddress 必须由请求者显式传入
      if (tokenAddress === undefined || tokenAddress === null) {
        throw new Error('tokenAddress is required: must be explicitly provided by the requester');
      }
      await this._stateManager.incrementUsage(
        authorizationId,
        txParams.value,
        txParams.chainId,
        tokenAddress
      );

      console.log(`[TransactionSigner] signAndUpdate: mode=txParams complete, txHash=${result.txHash}`);
      return result;
    }

    // ===== 模式二/三：rawTxHex 二进制字节 =====
    // 第一步：识别交易类型 + 操作类型
    let identification;
    if (params._identification && params._parsedTx) {
      // 来自 API 预解析（rawTxHex 模式，API 层已从 raw bytes 解析鉴权字段）
      identification = params._identification;
      console.log(`[TransactionSigner] signAndUpdate: using pre-parsed identification, recognized=${identification.recognized}`);
    } else {
      // 未预解析，主动解析 raw bytes
      // identifyTransactionType 会在解析失败时抛出异常
      // 现在它总是返回 parsed（即使 recognized=false），所以后续可以直接使用
      identification = this.identifyTransactionType(rawTxHex);
    }
    const operationType = this.identifyOperation(identification);
    console.log(`[TransactionSigner] signAndUpdate: mode=rawTxHex, recognized=${identification.recognized}, operationType=${operationType}`);

    // 第二步：检查 dataPolicy 是否允许（含 allowedTxTypes 和 allowedOperations）
    const policyCheck = this.checkDataPolicy(dataPolicy, identification, operationType);
    if (!policyCheck.allowed) {
      throw new Error('DataPolicy check failed: ' + policyCheck.reason);
    }

    // 第二步半：检查 eip7702Policy（仅对 eip7702Auth/eip7702Tx 操作）
    const eip7702Policy = params.eip7702Policy;
    const eip7702Context = params.eip7702Context;
    const eip7702Check = this.checkEip7702Policy(eip7702Policy, operationType, eip7702Context);
    if (!eip7702Check.allowed) {
      throw new Error('EIP-7702 policy check failed: ' + eip7702Check.reason);
    }

    // 第三步：确定 chainId 用于查询钱包
    let effectiveChainId;
    if (identification.recognized) {
      effectiveChainId = identification.parsed.chainId;
    } else {
      effectiveChainId = params.chainId;
      if (!effectiveChainId) {
        throw new Error('chainId is required when rawTxHex is unrecognized arbitrary data');
      }
    }

    // 第四步：从数据库取私钥
    const walletInfo = await this._walletManager.getWalletByAddress(
      userId,
      effectiveChainId,
      walletAddress
    );
    if (!walletInfo) {
      throw new Error(`Wallet not found: userId=${userId}, chainId=${effectiveChainId}, address=${walletAddress}`);
    }

    const privateKey = walletInfo.privateKey.startsWith('0x')
      ? walletInfo.privateKey
      : '0x' + walletInfo.privateKey;

    // 第五步：执行签名
    let result;
    try {
      if (identification.recognized) {
        // 模式二：已识别的交易类型，对预构造的字节直接签名
        const rawResult = this.signRawBytes(rawTxHex, privateKey);
        result = {
          signedTransaction: rawResult.signedTransaction,
          txHash: rawResult.txHash,
        };
      } else {
        // 模式三：不可识别的任意二进制数据，做以太坊格式签名
        result = this.signArbitraryData(rawTxHex, privateKey);
      }
    } catch (err) {
      throw new Error('Transaction signing failed: ' + err.message);
    }

    // 第六步：签名成功后递增累计值
    // 重要：必须使用从 raw bytes 解析/推导出的 tokenAddress 和 amount，不信任平台显式传入的值
    if (params._tokenInfo) {
      // rawTxHex 模式：由 API 层从 raw bytes 推导的 tokenInfo
      if (params._tokenInfo.tokens && Array.isArray(params._tokenInfo.tokens)) {
        // 处理多token的复合交易
        console.log(`[TransactionSigner] signAndUpdate: processing ${params._tokenInfo.tokens.length} tokens from complex transaction`);
        
        // 为每个识别出的token分别更新状态
        for (const token of params._tokenInfo.tokens) {
          console.log(`[TransactionSigner] signAndUpdate: incrementing usage for token: tokenAddress=${token.tokenAddress}, amount=${token.amount}`);
          await this._stateManager.incrementUsage(
            authorizationId,
            token.amount,
            effectiveChainId,
            token.tokenAddress
          );
        }
      } else {
        // 不应该到达这里，因为我们的实现总是返回tokens数组
        throw new Error('Invalid tokenInfo structure: missing tokens array');
      }
    } else {
      // 模式一：结构化参数（仅基本转账）
      if (tokenAddress === undefined || tokenAddress === null) {
        throw new Error('tokenAddress is required: must be explicitly provided by the requester');
      }
      const effectiveTokenAddress = tokenAddress;
      const effectiveAmount = identification.parsed?.value || '0';
      console.log(`[TransactionSigner] signAndUpdate: using platform-provided tokenInfo for incrementUsage: tokenAddress=${effectiveTokenAddress}, amount=${effectiveAmount}`);
      await this._stateManager.incrementUsage(
        authorizationId,
        effectiveAmount,
        effectiveChainId,
        effectiveTokenAddress
      );
    }

    console.log(`[TransactionSigner] signAndUpdate: mode=rawTxHex complete, operationType=${operationType}, txHash=${result.txHash || 'N/A'}`);
    return result;
  }
}
