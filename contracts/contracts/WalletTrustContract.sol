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

    // ============ 治理 Passkey 指定（运营方应急授权用） ============

    /// @dev 治理 Passkey 指定：userId => 公钥哈希(SHA256(COSE 公钥)) => 是否指定
    ///      治理 Passkey 本身就是普通钱包账户的 Passkey（在 SGX 端按普通流程注册），
    ///      合约不存公钥本体，只公开指定“哪个普通账户的哪一把 Passkey 具备治理身份”。
    ///      SGX 每次执行应急授权时都实时查询此指定，指定被移除即刻失效。
    mapping(string => mapping(bytes32 => bool)) internal _governancePasskeys;

    event GovernancePasskeyDesignated(string userId, bytes32 pubKeyHash);
    event GovernancePasskeyRemoved(string userId, bytes32 pubKeyHash);

    /// @dev 指定一把普通账户 Passkey 为治理 Passkey（Owner 权限）
    function designateGovernancePasskey(string calldata _userId, bytes32 _pubKeyHash) external onlyOwner {
        require(bytes(_userId).length > 0, "Empty userId");
        require(_pubKeyHash != bytes32(0), "Invalid pubKeyHash");
        require(!_governancePasskeys[_userId][_pubKeyHash], "Already designated");

        _governancePasskeys[_userId][_pubKeyHash] = true;

        emit GovernancePasskeyDesignated(_userId, _pubKeyHash);
    }

    /// @dev 移除治理 Passkey 指定（Owner 权限）；移除后该钥匙签发的应急授权立即不可执行
    function removeGovernancePasskey(string calldata _userId, bytes32 _pubKeyHash) external onlyOwner {
        require(_governancePasskeys[_userId][_pubKeyHash], "Not designated");

        _governancePasskeys[_userId][_pubKeyHash] = false;

        emit GovernancePasskeyRemoved(_userId, _pubKeyHash);
    }

    /// @dev 查询某账户的某把 Passkey 是否为当前指定的治理 Passkey（SGX 每次执行时实时调用）
    function isGovernancePasskey(string calldata _userId, bytes32 _pubKeyHash) external view returns (bool) {
        return _governancePasskeys[_userId][_pubKeyHash];
    }

    // ============ 应急授权（运营方治理，面向他人钱包的全量操作授权） ============

    /// @dev 应急授权记录：合约只存授权 JSON 的哈希与核查元数据，不存全文；
    ///      授权全文由执行方递进 SGX，SGX 对递进文本算 sha256 与本记录比对
    struct EmergencyAuthorization {
        bytes32 authHash;           // sha256(授权 JSON 全文)，写入时由 Owner 随记录提交
        string operatorUserId;      // 治理方（运营方）userId
        bytes32 operatorPubKeyHash; // 治理 Passkey 公钥哈希（写入时必须为已指定治理 Passkey）
        address grantee;            // 唯一允许执行本次授权的服务器平台地址
        uint256 createdAt;          // 写入时间戳
        uint256 expiresAt;          // 链上到期时间（unix 秒）
        bool revoked;               // 是否已被 Owner 撤销（撤销为终态）
    }

    /// @dev authorizationId => 应急授权记录
    mapping(string => EmergencyAuthorization) internal _emergencyAuthorizations;
    /// @dev authorizationId 是否曾经写入过：只写一次、永不复用（撤销/过期后同样不可再用）
    mapping(string => bool) public emergencyAuthorizationExists;

    event EmergencyAuthorizationSet(
        string authorizationId,
        bytes32 authHash,
        string operatorUserId,
        bytes32 operatorPubKeyHash,
        address grantee,
        uint256 expiresAt
    );
    event EmergencyAuthorizationRevoked(string authorizationId);

    /**
     * @dev 写入一份应急授权（Owner 权限）
     *      前置条件：签名钥匙必须已被指定为治理 Passkey；authorizationId 全局唯一且永不复用。
     *      合约只存授权 JSON 的哈希：_authHash 须为 sha256(授权 JSON 全文)，由写入方
     *      在链下对原文计算；SGX 执行时对递进文本重算哈希与记录比对，不一致即拒绝。
     * @param _authorizationId 全局唯一授权 ID（写入授权 JSON 原文内）
     * @param _authHash 授权 JSON 全文的 sha256 哈希
     * @param _operatorUserId 治理方 userId
     * @param _operatorPubKeyHash 治理 Passkey 公钥哈希
     * @param _grantee 唯一允许执行的平台地址
     * @param _expiresAt 到期时间（unix 秒，必须在未来）
     */
    function setEmergencyAuthorization(
        string calldata _authorizationId,
        bytes32 _authHash,
        string calldata _operatorUserId,
        bytes32 _operatorPubKeyHash,
        address _grantee,
        uint256 _expiresAt
    ) external onlyOwner {
        require(bytes(_authorizationId).length > 0, "Empty authorizationId");
        require(!emergencyAuthorizationExists[_authorizationId], "Authorization id already used");
        require(_authHash != bytes32(0), "Empty authHash");
        require(_governancePasskeys[_operatorUserId][_operatorPubKeyHash], "Passkey not designated as governance");
        require(_grantee != address(0), "Invalid grantee");
        require(_expiresAt > block.timestamp, "Authorization already expired");

        bytes32 authHash = _authHash;

        _emergencyAuthorizations[_authorizationId] = EmergencyAuthorization({
            authHash: authHash,
            operatorUserId: _operatorUserId,
            operatorPubKeyHash: _operatorPubKeyHash,
            grantee: _grantee,
            createdAt: block.timestamp,
            expiresAt: _expiresAt,
            revoked: false
        });
        emergencyAuthorizationExists[_authorizationId] = true;

        emit EmergencyAuthorizationSet(_authorizationId, authHash, _operatorUserId, _operatorPubKeyHash, _grantee, _expiresAt);
    }

    /// @dev 撤销一份应急授权（Owner 权限，终态）；SGX 每次执行实时查合约，撤销在下一次执行尝试时即刻生效
    function revokeEmergencyAuthorization(string calldata _authorizationId) external onlyOwner {
        require(emergencyAuthorizationExists[_authorizationId], "Authorization not found");
        require(!_emergencyAuthorizations[_authorizationId].revoked, "Already revoked");

        _emergencyAuthorizations[_authorizationId].revoked = true;

        emit EmergencyAuthorizationRevoked(_authorizationId);
    }

    /**
     * @dev 查询应急授权记录（任何人可调用；SGX 每次执行应急授权时实时调用，
     *      以链上记录判定有效性：存在、未撤销、未过期、递进文本的 sha256 与记录 authHash 一致）
     */
    function getEmergencyAuthorization(
        string calldata _authorizationId
    ) external view returns (
        bytes32 authHash,
        string memory operatorUserId,
        bytes32 operatorPubKeyHash,
        address grantee,
        uint256 createdAt,
        uint256 expiresAt,
        bool revoked,
        bool exists
    ) {
        exists = emergencyAuthorizationExists[_authorizationId];
        if (!exists) {
            return (bytes32(0), "", bytes32(0), address(0), 0, 0, false, false);
        }
        EmergencyAuthorization memory record = _emergencyAuthorizations[_authorizationId];
        return (
            record.authHash,
            record.operatorUserId,
            record.operatorPubKeyHash,
            record.grantee,
            record.createdAt,
            record.expiresAt,
            record.revoked,
            true
        );
    }

    // ============ 账本指定（多账本：所有权人与归集地址集由合约指定） ============

    /// @dev 账本指定信息：所有权人（普通钱包账户）
    struct LedgerDesignation {
        string ownerUserId;         // 所有权人 userId
        bytes32 ownerPubKeyHash;    // 所有权人 Passkey 公钥哈希
        bool enabled;               // 是否启用
        bool exists;                // 是否已登记
    }

    /// @dev ledgerId => 账本指定
    mapping(string => LedgerDesignation) internal _ledgers;

    /// @dev 可归集资产登记：(ledgerId, chainId, 资产地址) => 归集地址集。
    ///      资产地址 address(0) 表示该链原生币。登记按（链，币种）逐项进行，
    ///      每一项登记对应账本里同（链，币种）的一份资产：账本资产与可归集
    ///      资产一一对应。同一地址可登记为多个账本、多个（链，币种）的归集地址。
    mapping(string => mapping(uint256 => mapping(address => address[]))) internal _ledgerPoolSets;

    /// @dev 地址被登记为归集地址的总份数（跨账本、跨链、跨币种累计）。
    ///      大于 0 即该地址托管着某个账本的可归集资产（SGX 导出锁判定用）。
    mapping(address => uint256) internal _collectionRefCount;

    event LedgerRegistered(string ledgerId, string ownerUserId, bytes32 ownerPubKeyHash);
    event LedgerOwnerChanged(string ledgerId, string ownerUserId, bytes32 ownerPubKeyHash);
    event LedgerPoolAddressesUpdated(string ledgerId, uint256 chainId, address asset);
    event LedgerEnabledChanged(string ledgerId, bool enabled);

    /**
     * @dev 登记一个账本（Owner 权限）。登记只是指定：账本还须由所有权人持指定
     *      Passkey 在 SGX 内创建才存在（SGX 侧逻辑，合约只保存指定事实）。
     */
    function registerLedger(
        string calldata _ledgerId,
        string calldata _ownerUserId,
        bytes32 _ownerPubKeyHash
    ) external onlyOwner {
        require(bytes(_ledgerId).length > 0, "Empty ledgerId");
        require(!_ledgers[_ledgerId].exists, "Ledger already registered");
        require(bytes(_ownerUserId).length > 0, "Empty ownerUserId");
        require(_ownerPubKeyHash != bytes32(0), "Empty ownerPubKeyHash");

        LedgerDesignation storage ledger = _ledgers[_ledgerId];
        ledger.ownerUserId = _ownerUserId;
        ledger.ownerPubKeyHash = _ownerPubKeyHash;
        ledger.enabled = true;
        ledger.exists = true;

        emit LedgerRegistered(_ledgerId, _ownerUserId, _ownerPubKeyHash);
    }

    /// @dev 变更账本所有权人（Owner 权限）；SGX 每次敏感操作实时查本记录，变更即时生效
    function setLedgerOwner(
        string calldata _ledgerId,
        string calldata _ownerUserId,
        bytes32 _ownerPubKeyHash
    ) external onlyOwner {
        require(_ledgers[_ledgerId].exists, "Ledger not found");
        require(bytes(_ownerUserId).length > 0, "Empty ownerUserId");
        require(_ownerPubKeyHash != bytes32(0), "Empty ownerPubKeyHash");

        _ledgers[_ledgerId].ownerUserId = _ownerUserId;
        _ledgers[_ledgerId].ownerPubKeyHash = _ownerPubKeyHash;

        emit LedgerOwnerChanged(_ledgerId, _ownerUserId, _ownerPubKeyHash);
    }

    /**
     * @dev 整体替换某账本在某（链，币种）下的归集地址集（Owner 权限）。
     *      同步维护每个地址的登记计数：离开集合减一、进入集合加一（同一地址
     *      在新旧集合中同时出现时增减相抵）。
     */
    function setLedgerPoolAddresses(
        string calldata _ledgerId,
        uint256 _chainId,
        address _asset,
        address[] calldata _poolAddresses
    ) external onlyOwner {
        require(_ledgers[_ledgerId].exists, "Ledger not found");

        address[] storage current = _ledgerPoolSets[_ledgerId][_chainId][_asset];
        for (uint256 i = 0; i < current.length; i++) {
            _collectionRefCount[current[i]] -= 1;
        }
        delete _ledgerPoolSets[_ledgerId][_chainId][_asset];
        for (uint256 i = 0; i < _poolAddresses.length; i++) {
            require(_poolAddresses[i] != address(0), "Invalid pool address");
            for (uint256 j = 0; j < i; j++) {
                require(_poolAddresses[j] != _poolAddresses[i], "Duplicate pool address");
            }
            _ledgerPoolSets[_ledgerId][_chainId][_asset].push(_poolAddresses[i]);
            _collectionRefCount[_poolAddresses[i]] += 1;
        }

        emit LedgerPoolAddressesUpdated(_ledgerId, _chainId, _asset);
    }

    /// @dev 查询某账本在某（链，币种）下的归集地址集（任何人可调用；SGX 实时调用）
    function getLedgerPoolAddresses(
        string calldata _ledgerId,
        uint256 _chainId,
        address _asset
    ) external view returns (address[] memory) {
        return _ledgerPoolSets[_ledgerId][_chainId][_asset];
    }

    /// @dev 某地址是否被登记为任一账本任一（链，币种）的归集地址（SGX 导出锁判定用）
    function isCollectionAddress(address _addr) external view returns (bool) {
        return _collectionRefCount[_addr] > 0;
    }

    /// @dev 启用/停用账本（Owner 权限）；停用后 SGX 拒绝该账本的一切敏感操作与入账
    function setLedgerEnabled(string calldata _ledgerId, bool _enabled) external onlyOwner {
        require(_ledgers[_ledgerId].exists, "Ledger not found");
        _ledgers[_ledgerId].enabled = _enabled;
        emit LedgerEnabledChanged(_ledgerId, _enabled);
    }

    /// @dev 查询账本指定（任何人可调用；SGX 实时调用核对所有权）
    function getLedger(
        string calldata _ledgerId
    ) external view returns (
        string memory ownerUserId,
        bytes32 ownerPubKeyHash,
        bool enabled,
        bool exists
    ) {
        LedgerDesignation storage ledger = _ledgers[_ledgerId];
        if (!ledger.exists) {
            return ("", bytes32(0), false, false);
        }
        return (ledger.ownerUserId, ledger.ownerPubKeyHash, ledger.enabled, true);
    }

    // ============ 账本提现风控规则（单笔/日累计限额，SGX 强制执行） ============

    /// @dev (ledgerId, 资产地址) => 提现限额；资产地址 address(0) 表示原生币，0 表示该项不限
    struct WithdrawalPolicy {
        uint256 maxSingleAmount;
        uint256 maxDailyAmount;
        bool exists;
    }

    mapping(string => mapping(address => WithdrawalPolicy)) internal _withdrawalPolicies;

    event LedgerWithdrawalPolicyUpdated(string ledgerId, address asset);

    /// @dev 设置某账本某资产的提现风控规则（Owner 权限，整体替换）
    function setLedgerWithdrawalPolicy(
        string calldata _ledgerId,
        address _asset,
        uint256 _maxSingleAmount,
        uint256 _maxDailyAmount
    ) external onlyOwner {
        require(_ledgers[_ledgerId].exists, "Ledger not found");
        WithdrawalPolicy storage policy = _withdrawalPolicies[_ledgerId][_asset];
        policy.maxSingleAmount = _maxSingleAmount;
        policy.maxDailyAmount = _maxDailyAmount;
        policy.exists = true;
        emit LedgerWithdrawalPolicyUpdated(_ledgerId, _asset);
    }

    /// @dev 查询某账本某资产的提现风控规则（任何人可调用；SGX 提现申请时实时调用）
    function getLedgerWithdrawalPolicy(
        string calldata _ledgerId,
        address _asset
    ) external view returns (uint256 maxSingleAmount, uint256 maxDailyAmount, bool exists) {
        WithdrawalPolicy storage policy = _withdrawalPolicies[_ledgerId][_asset];
        if (!policy.exists) return (0, 0, false);
        return (policy.maxSingleAmount, policy.maxDailyAmount, true);
    }

    // ============ 归集地址出金目标配置（每个归集地址各自可出金到哪里） ============

    /// @dev (ledgerId, chainId, 资产地址, 归集地址) => 允许出金到的目标地址集；未配置即不许出金（默认拒绝）
    mapping(string => mapping(uint256 => mapping(address => mapping(address => address[])))) internal _collectionPayoutTargets;

    event CollectionPayoutTargetsUpdated(string ledgerId, uint256 chainId, address asset, address source);

    /**
     * @dev 设置某账本在某（链，币种）下某个归集地址可出金到的目标地址集（Owner 权限，整体替换）。
     *      源地址必须是该账本在该（链，币种）下已登记的归集地址。账本所有权人从
     *      归集地址出金时，SGX 实时读本配置检查目标地址，不在集内即拒绝签名。
     */
    function setCollectionPayoutTargets(
        string calldata _ledgerId,
        uint256 _chainId,
        address _asset,
        address _source,
        address[] calldata _targets
    ) external onlyOwner {
        require(_ledgers[_ledgerId].exists, "Ledger not found");
        bool isPool = false;
        address[] storage pool = _ledgerPoolSets[_ledgerId][_chainId][_asset];
        for (uint256 i = 0; i < pool.length; i++) {
            if (pool[i] == _source) { isPool = true; break; }
        }
        require(isPool, "Source is not a collection address of this ledger for this chain and asset");

        delete _collectionPayoutTargets[_ledgerId][_chainId][_asset][_source];
        for (uint256 i = 0; i < _targets.length; i++) {
            require(_targets[i] != address(0), "Invalid target address");
            _collectionPayoutTargets[_ledgerId][_chainId][_asset][_source].push(_targets[i]);
        }

        emit CollectionPayoutTargetsUpdated(_ledgerId, _chainId, _asset, _source);
    }

    /// @dev 查询某账本在某（链，币种）下某归集地址可出金到的目标地址集（任何人可调用；SGX 出金时实时调用）
    function getCollectionPayoutTargets(
        string calldata _ledgerId,
        uint256 _chainId,
        address _asset,
        address _source
    ) external view returns (address[] memory) {
        return _collectionPayoutTargets[_ledgerId][_chainId][_asset][_source];
    }

    // ============ 链读链配置（资产读链专用，与操作合约的 RPC 分开） ============

    /// @dev 单条链的读链配置：以 (chainName, chainId) 标识，RPC 地址集 + 对应 TLS CA + 入账确认数
    struct ChainRpcConfig {
        string chainName;
        string[] rpcUrls;       // RPC 地址集（必须全部为 https，SGX 侧强制校验）
        string[] caCerts;       // 与 rpcUrls 一一对应的 TLS CA 证书（PEM 文本，无则空字符串）
        uint256 confirmations;  // 入账所需确认数
        bool exists;
    }

    /// @dev chainId => 链读链配置
    mapping(uint256 => ChainRpcConfig) internal _chainRpcConfigs;

    event ChainRpcConfigUpdated(uint256 chainId, string chainName);

    /**
     * @dev 设置一条链的读链配置（Owner 权限，整体替换）。
     *      SGX 每次入账核验前实时读本配置，不用缓存；端点须为 https（SGX 侧拒绝 http）。
     */
    function setChainRpcConfig(
        string calldata _chainName,
        uint256 _chainId,
        string[] calldata _rpcUrls,
        string[] calldata _caCerts,
        uint256 _confirmations
    ) external onlyOwner {
        require(bytes(_chainName).length > 0, "Empty chainName");
        require(_chainId > 0, "Invalid chainId");
        require(_rpcUrls.length > 0, "Empty rpcUrls");
        require(_rpcUrls.length == _caCerts.length, "rpcUrls/caCerts length mismatch");

        ChainRpcConfig storage config = _chainRpcConfigs[_chainId];
        config.chainName = _chainName;
        delete config.rpcUrls;
        delete config.caCerts;
        for (uint256 i = 0; i < _rpcUrls.length; i++) {
            config.rpcUrls.push(_rpcUrls[i]);
            config.caCerts.push(_caCerts[i]);
        }
        config.confirmations = _confirmations;
        config.exists = true;

        emit ChainRpcConfigUpdated(_chainId, _chainName);
    }

    /// @dev 查询链读链配置（任何人可调用；SGX 入账核验前实时调用）
    function getChainRpcConfig(
        uint256 _chainId
    ) external view returns (
        string memory chainName,
        string[] memory rpcUrls,
        string[] memory caCerts,
        uint256 confirmations,
        bool exists
    ) {
        ChainRpcConfig storage config = _chainRpcConfigs[_chainId];
        if (!config.exists) {
            return ("", new string[](0), new string[](0), 0, false);
        }
        return (config.chainName, config.rpcUrls, config.caCerts, config.confirmations, true);
    }
}
