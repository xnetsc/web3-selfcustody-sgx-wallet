// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/P256.sol";

/**
 * @title WalletTrustContract
 * @dev 去中心化信任锚点合约，部署在区块链上，承担配置公示、白名单管理和授权撤销功能。
 *      任何人均可查验合约数据，确保系统的透明性和可验证性。
 *
 *      平台白名单由 Owner 维护写权限，其他人只可读取。
 */
contract WalletTrustContract is Ownable {

    // ============ 数据结构 ============

    /// @dev Enclave 白名单条目（用于 RA-TLS 互验，支持多版本共存和滚动升级）
    struct EnclaveIdentity {
        bytes32 mrenclave;
        bytes32 mrsigner;
        uint16 isvprodid;
        uint16 isvsvn;
        string description;
    }

    /// @dev 撤销记录
    struct RevocationRecord {
        string authorizationId;
        address grantee;
        bytes32 passkeyPubKeyX;
        bytes32 passkeyPubKeyY;
        uint256 revokedAt;
    }

    /// @dev Passkey 恢复条目（Owner 授权用户通过新 Passkey 找回账户）
    struct PasskeyRecovery {
        bytes32 oldPubKeyHash;    // SHA256(旧 Passkey 的 COSE 公钥)，用于在 SGX 端匹配现有 Passkey
        string uuid;              // 唯一标识符，防止混淆不同的恢复请求
        string memo;              // 备注（如线下验证记录）
        uint256 createdAt;        // 创建时间戳
    }

    // ============ 配置存储 ============

    /// @dev 代码仓库链接
    string public codeRepository;

    /// @dev 程序运行参数（JSON 字符串格式）
    string public runtimeParams;

    // ============ RPC TLS CA 证书 ============

    /// @dev RPC 服务器的 TLS CA 证书（base64 编码），用于验证 RPC 连接的 TLS 证书链
    string public rpcTlsCaCert;

    // ============ 合约迁移目标（Owner 设置，无需鉴权即可读取） ============

    /// @dev 迁移目标 RPC URL（空字符串表示无迁移）
    string public migrationRpcUrl;
    /// @dev 迁移目标合约地址（空字符串表示无迁移）
    string public migrationContractAddress;
    /// @dev 迁移目标链 ID（0 表示无迁移）
    uint256 public migrationChainId;
    /// @dev 迁移目标 RPC TLS CA 证书（base64 编码，空字符串表示无迁移）
    string public migrationRpcTlsCaCert;

    // ============ Enclave 白名单（RA-TLS 验证用） ============

    EnclaveIdentity[] internal _enclaveWhitelist;
    /// @dev mrenclave => 是否在白名单
    mapping(bytes32 => bool) public enclaveWhitelistByMrenclave;
    /// @dev mrenclave => 在数组中的索引
    mapping(bytes32 => uint256) internal _enclaveWhitelistIndex;

    // ============ 平台白名单 ============

    /// @dev 平台公钥白名单（secp256k1 地址格式）
    mapping(address => bool) public platformWhitelist;
    address[] internal _platformWhitelistArray;
    /// @dev 平台地址在数组中的索引（用于高效删除）
    mapping(address => uint256) internal _platformWhitelistIndex;

    // ============ 授权撤销 ============

    /// @dev user_id => RevocationRecord[]
    mapping(string => RevocationRecord[]) internal _revokedAuthorizations;
    /// @dev user_id => authorization_id => 是否已撤销
    mapping(string => mapping(string => bool)) internal _isRevoked;

    // ============ Passkey 恢复（Owner 授权用户找回账户） ============

    /// @dev userId => newPubKeyHash => PasskeyRecovery
    mapping(string => mapping(bytes32 => PasskeyRecovery)) internal _passkeyRecoveries;
    /// @dev userId => newPubKeyHash => 是否存在
    mapping(string => mapping(bytes32 => bool)) public passkeyRecoveryExists;

    // ============ 事件 ============

    event CodeRepositoryUpdated(string codeRepository);
    event RuntimeParamsUpdated(string runtimeParams);
    event PlatformAddressAdded(address indexed addr);
    event PlatformAddressRemoved(address indexed addr);
    event EnclaveIdentityAdded(bytes32 mrenclave, bytes32 mrsigner, string description);
    event EnclaveIdentityRemoved(bytes32 mrenclave);
    event AuthorizationRevoked(
        string userId,
        string authorizationId,
        address grantee,
        bytes32 passkeyPubKeyX,
        bytes32 passkeyPubKeyY
    );
    event PasskeyRecoverySet(string userId, bytes32 newPubKeyHash, bytes32 oldPubKeyHash, string uuid, string memo);
    event PasskeyRecoveryRemoved(string userId, bytes32 newPubKeyHash);
    event RpcTlsCaCertUpdated(string caCert);
    event MigrationTargetUpdated(string rpcUrl, string contractAddress, uint256 chainId, string rpcTlsCaCert);
    event MigrationTargetCleared();

    // ============ 构造函数 ============

    constructor() Ownable(msg.sender) {}

    // ============ 配置管理（Owner 权限） ============

    /// @dev 更新代码仓库链接
    function updateCodeRepository(string calldata _codeRepository) external onlyOwner {
        codeRepository = _codeRepository;
        emit CodeRepositoryUpdated(_codeRepository);
    }

    /// @dev 更新运行参数
    function updateRuntimeParams(string calldata _runtimeParams) external onlyOwner {
        runtimeParams = _runtimeParams;
        emit RuntimeParamsUpdated(_runtimeParams);
    }

    // ============ RPC TLS CA 证书管理（Owner 权限） ============

    /// @dev 设置 RPC TLS CA 证书（base64 编码）
    function setRpcTlsCaCert(string calldata _caCert) external onlyOwner {
        rpcTlsCaCert = _caCert;
        emit RpcTlsCaCertUpdated(_caCert);
    }

    /// @dev 查询 RPC TLS CA 证书
    function getRpcTlsCaCert() external view returns (string memory) {
        return rpcTlsCaCert;
    }

    // ============ 合约迁移目标管理（Owner 权限） ============

    /// @dev 设置迁移目标（Owner 调用，所有节点读到后将切换到新合约）
    function setMigrationTarget(string calldata _rpcUrl, string calldata _contractAddress, uint256 _chainId, string calldata _rpcTlsCaCert) external onlyOwner {
        require(bytes(_rpcUrl).length > 0, "Empty rpcUrl");
        require(bytes(_contractAddress).length > 0, "Empty contractAddress");
        require(_chainId > 0, "Invalid chainId");
        migrationRpcUrl = _rpcUrl;
        migrationContractAddress = _contractAddress;
        migrationChainId = _chainId;
        migrationRpcTlsCaCert = _rpcTlsCaCert;
        emit MigrationTargetUpdated(_rpcUrl, _contractAddress, _chainId, _rpcTlsCaCert);
    }

    /// @dev 清除迁移目标（迁移完成后 Owner 调用）
    function clearMigrationTarget() external onlyOwner {
        migrationRpcUrl = "";
        migrationContractAddress = "";
        migrationChainId = 0;
        migrationRpcTlsCaCert = "";
        emit MigrationTargetCleared();
    }

    /// @dev 查询迁移目标（任何人可调用，无需鉴权）
    function getMigrationTarget() external view returns (string memory rpcUrl_, string memory contractAddress_, uint256 chainId_, string memory rpcTlsCaCert_) {
        return (migrationRpcUrl, migrationContractAddress, migrationChainId, migrationRpcTlsCaCert);
    }

    // ============ Enclave 白名单管理（Owner 权限，RA-TLS 验证用） ============

    /// @dev 添加 Enclave 身份到白名单（滚动升级时可同时添加新旧版本）
    function addEnclaveIdentity(
        bytes32 _mrenclave,
        bytes32 _mrsigner,
        uint16 _isvprodid,
        uint16 _isvsvn,
        string calldata _description
    ) external onlyOwner {
        require(_mrenclave != bytes32(0), "Invalid _mrenclave");
        require(!enclaveWhitelistByMrenclave[_mrenclave], "Already whitelisted");

        enclaveWhitelistByMrenclave[_mrenclave] = true;
        _enclaveWhitelistIndex[_mrenclave] = _enclaveWhitelist.length;
        _enclaveWhitelist.push(EnclaveIdentity({
            mrenclave: _mrenclave,
            mrsigner: _mrsigner,
            isvprodid: _isvprodid,
            isvsvn: _isvsvn,
            description: _description
        }));

        emit EnclaveIdentityAdded(_mrenclave, _mrsigner, _description);
    }

    /// @dev 从白名单移除 Enclave 身份（升级完成后移除旧版本）
    function removeEnclaveIdentity(bytes32 _mrenclave) external onlyOwner {
        require(enclaveWhitelistByMrenclave[_mrenclave], "Not whitelisted");

        enclaveWhitelistByMrenclave[_mrenclave] = false;

        uint256 index = _enclaveWhitelistIndex[_mrenclave];
        uint256 lastIndex = _enclaveWhitelist.length - 1;
        if (index != lastIndex) {
            EnclaveIdentity memory lastItem = _enclaveWhitelist[lastIndex];
            _enclaveWhitelist[index] = lastItem;
            _enclaveWhitelistIndex[lastItem.mrenclave] = index;
        }
        _enclaveWhitelist.pop();
        delete _enclaveWhitelistIndex[_mrenclave];

        emit EnclaveIdentityRemoved(_mrenclave);
    }

    /// @dev 查询 Enclave 是否在白名单
    function isEnclaveWhitelisted(bytes32 _mrenclave) external view returns (bool) {
        return enclaveWhitelistByMrenclave[_mrenclave];
    }

    /// @dev 获取所有 Enclave 白名单
    function getEnclaveWhitelist() external view returns (EnclaveIdentity[] memory) {
        return _enclaveWhitelist;
    }

    // ============ 平台白名单管理（Owner 权限） ============

    /// @dev 添加平台公钥到白名单
    function addPlatformAddress(address _addr) external onlyOwner {
        require(_addr != address(0), "Invalid address");
        require(!platformWhitelist[_addr], "Already whitelisted");

        platformWhitelist[_addr] = true;
        _platformWhitelistIndex[_addr] = _platformWhitelistArray.length;
        _platformWhitelistArray.push(_addr);

        emit PlatformAddressAdded(_addr);
    }

    /// @dev 从白名单移除平台公钥
    function removePlatformAddress(address _addr) external onlyOwner {
        require(platformWhitelist[_addr], "Not whitelisted");

        platformWhitelist[_addr] = false;

        // 用最后一个元素覆盖被删除位置，然后 pop
        uint256 index = _platformWhitelistIndex[_addr];
        uint256 lastIndex = _platformWhitelistArray.length - 1;
        if (index != lastIndex) {
            address lastAddr = _platformWhitelistArray[lastIndex];
            _platformWhitelistArray[index] = lastAddr;
            _platformWhitelistIndex[lastAddr] = index;
        }
        _platformWhitelistArray.pop();
        delete _platformWhitelistIndex[_addr];

        emit PlatformAddressRemoved(_addr);
    }

    /// @dev 查询平台地址是否在白名单
    function isPlatformWhitelisted(address _addr) external view returns (bool) {
        return platformWhitelist[_addr];
    }

    /// @dev 获取所有平台白名单地址
    function getPlatformWhitelist() external view returns (address[] memory) {
        return _platformWhitelistArray;
    }

    // ============ 公示查询（任何人可调用） ============

    /// @dev 获取代码仓库链接
    function getCodeRepository() external view returns (string memory) {
        return codeRepository;
    }

    /// @dev 获取运行参数
    function getRuntimeParams() external view returns (string memory) {
        return runtimeParams;
    }

    /// @dev 获取所有公示信息
    function getPublicInfo() external view returns (
        string memory codeRepository_,
        string memory runtimeParams_,
        EnclaveIdentity[] memory enclaveWhitelist_
    ) {
        return (codeRepository, runtimeParams, _enclaveWhitelist);
    }

    // ============ 授权撤销（完整实现） ============

    /**
     * @dev 撤销授权 - 用户直接调用，需提供 Passkey P256 签名
     *      合约内部使用 sha256(abi.encodePacked(userId, authorizationId, grantee)) 作为签名消息摘要，
     *      与 P256/WebAuthn 生态的 SHA-256 标准一致。
     * @param _userId 用户 ID
     * @param _authorizationId 要撤销的授权 ID
     * @param _grantee 被授权的平台地址（授权给谁）
     * @param _passkeyPubKeyX Passkey P256 公钥 X 坐标
     * @param _passkeyPubKeyY Passkey P256 公钥 Y 坐标
     * @param _signatureR P256 签名 R 值
     * @param _signatureS P256 签名 S 值
     */
    function revokeAuthorization(
        string calldata _userId,
        string calldata _authorizationId,
        address _grantee,
        bytes32 _passkeyPubKeyX,
        bytes32 _passkeyPubKeyY,
        bytes32 _signatureR,
        bytes32 _signatureS
    ) external {
        // 1. 基本参数校验
        require(bytes(_userId).length > 0, "Empty userId");
        require(bytes(_authorizationId).length > 0, "Empty authorizationId");
        require(_grantee != address(0), "Empty grantee");
        require(!_isRevoked[_userId][_authorizationId], "Already revoked");

        // 2. 合约内部计算消息哈希（使用 SHA-256，与 P256/WebAuthn 生态一致）
        //    签名消息包含 grantee，确保撤销操作明确关联被授权方
        bytes32 messageHash = sha256(abi.encodePacked(_userId, _authorizationId, _grantee));

        // 3. 调用 P256 验证签名（使用 OpenZeppelin P256 库，自动 fallback 到纯 Solidity 实现）
        bool valid = P256.verify(
            messageHash,
            _signatureR,
            _signatureS,
            _passkeyPubKeyX,
            _passkeyPubKeyY
        );
        require(valid, "Invalid P256 signature");

        // 4. 写入撤销列表
        _isRevoked[_userId][_authorizationId] = true;
        _revokedAuthorizations[_userId].push(RevocationRecord({
            authorizationId: _authorizationId,
            grantee: _grantee,
            passkeyPubKeyX: _passkeyPubKeyX,
            passkeyPubKeyY: _passkeyPubKeyY,
            revokedAt: block.timestamp
        }));

        emit AuthorizationRevoked(_userId, _authorizationId, _grantee, _passkeyPubKeyX, _passkeyPubKeyY);
    }

    /// @dev 检查授权是否被撤销
    function isAuthorizationRevoked(
        string calldata _userId,
        string calldata _authorizationId
    ) external view returns (bool) {
        return _isRevoked[_userId][_authorizationId];
    }

    /// @dev 获取用户所有撤销记录（含 Passkey 公钥信息，供 SGX 端验证）
    function getRevokedAuthorizations(
        string calldata _userId
    ) external view returns (RevocationRecord[] memory) {
        return _revokedAuthorizations[_userId];
    }

    // ============ Passkey 恢复管理（Owner 权限） ============

    /**
     * @dev 设置 Passkey 恢复条目 - 允许用户通过新 Passkey 找回账户
     *      Owner 通过线下验证确认用户身份后调用，授权指定用户使用新 Passkey 替换旧 Passkey。
     *      SGX 端注册时查询此条目，验证旧 Passkey 哈希匹配后执行恢复。
     * @param _userId 用户 ID
     * @param _newPubKeyHash SHA256(新 Passkey 的 COSE 公钥)
     * @param _oldPubKeyHash SHA256(旧 Passkey 的 COSE 公钥)，SGX 端用于匹配现有 Passkey
     * @param _uuid 唯一标识符（防止混淆不同恢复请求）
     * @param _memo 备注（如线下验证记录、工单号等）
     */
    function setPasskeyRecovery(
        string calldata _userId,
        bytes32 _newPubKeyHash,
        bytes32 _oldPubKeyHash,
        string calldata _uuid,
        string calldata _memo
    ) external onlyOwner {
        require(bytes(_userId).length > 0, "Empty userId");
        require(_newPubKeyHash != bytes32(0), "Invalid newPubKeyHash");
        require(_oldPubKeyHash != bytes32(0), "Invalid oldPubKeyHash");
        require(bytes(_uuid).length > 0, "Empty uuid");

        _passkeyRecoveries[_userId][_newPubKeyHash] = PasskeyRecovery({
            oldPubKeyHash: _oldPubKeyHash,
            uuid: _uuid,
            memo: _memo,
            createdAt: block.timestamp
        });
        passkeyRecoveryExists[_userId][_newPubKeyHash] = true;

        emit PasskeyRecoverySet(_userId, _newPubKeyHash, _oldPubKeyHash, _uuid, _memo);
    }

    /**
     * @dev 移除 Passkey 恢复条目（恢复完成后清理，或取消恢复授权）
     * @param _userId 用户 ID
     * @param _newPubKeyHash SHA256(新 Passkey 的 COSE 公钥)
     */
    function removePasskeyRecovery(
        string calldata _userId,
        bytes32 _newPubKeyHash
    ) external onlyOwner {
        require(passkeyRecoveryExists[_userId][_newPubKeyHash], "Recovery not found");

        delete _passkeyRecoveries[_userId][_newPubKeyHash];
        passkeyRecoveryExists[_userId][_newPubKeyHash] = false;

        emit PasskeyRecoveryRemoved(_userId, _newPubKeyHash);
    }

    /**
     * @dev 查询 Passkey 恢复条目（SGX 端注册时调用）
     * @param _userId 用户 ID
     * @param _newPubKeyHash SHA256(新 Passkey 的 COSE 公钥)
     * @return oldPubKeyHash SHA256(旧 Passkey 的 COSE 公钥)
     * @return uuid 唯一标识符
     * @return memo 备注
     * @return createdAt 创建时间戳
     */
    function getPasskeyRecovery(
        string calldata _userId,
        bytes32 _newPubKeyHash
    ) external view returns (bytes32 oldPubKeyHash, string memory uuid, string memory memo, uint256 createdAt) {
        require(passkeyRecoveryExists[_userId][_newPubKeyHash], "Recovery not found");
        PasskeyRecovery memory recovery = _passkeyRecoveries[_userId][_newPubKeyHash];
        return (recovery.oldPubKeyHash, recovery.uuid, recovery.memo, recovery.createdAt);
    }
}
