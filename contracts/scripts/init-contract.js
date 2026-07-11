/**
 * 初始化已部署的合约：设置 runtimeParams、平台白名单
 *
 * 环境变量：
 *   CONTRACT_ADDRESS  — 已部署的合约地址
 *
 * 用法：
 *   CONTRACT_ADDRESS=0x... npx hardhat run scripts/init-contract.js --network localhost
 */

import pkg from "hardhat";
const { ethers } = pkg;

async function main() {
  const contractAddress = process.env.CONTRACT_ADDRESS;
  if (!contractAddress) {
    throw new Error("CONTRACT_ADDRESS environment variable is required");
  }

  const [owner] = await ethers.getSigners();
  console.log("Owner account:", owner.address);
  console.log("Owner private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

  const contract = await ethers.getContractAt("WalletTrustContract", contractAddress);

  // 1. 设置 runtimeParams
  //    新增字段（以前由 env 提供，现在由合约统一管理）：
  //      attestation.allowNonRaTls        — direct/sim 测试模式必需（生产部署必须为 false）
  //      sync.numShards / sync.minQuorum  — 共识/分片参数（之前 NUM_SHARDS / MIN_QUORUM）
  //      security.freezeDurationSeconds   — 账户冻结时长（之前 FREEZE_DURATION_SECONDS）
  //      security.ntpServers              — NTP 时间源列表，用于校正单调时钟锚点，确保跨节点时间一致
  const runtimeParams = JSON.stringify({
    session: { importTtlSeconds: 300, exportTtlSeconds: 86400 },
    cache: { refreshInterval: 600000 },
    attestation: { allowNonRaTls: true },
    sync: { numShards: 16, minQuorum: 1 },
    security: { freezeDurationSeconds: 259200, ntpServers: ['pool.ntp.org', 'time.google.com', 'time.cloudflare.com'] },
  });

  const tx1 = await contract.updateRuntimeParams(runtimeParams);
  await tx1.wait();
  console.log("runtimeParams set");

  // 2. 将 Owner 地址加入平台白名单
  const tx2 = await contract.addPlatformAddress(owner.address);
  await tx2.wait();
  console.log("Platform address added:", owner.address);

  // 3. 添加示例 Enclave Identity（实际部署时替换为真实值）
  const enclaveV1Mrenclave = ethers.encodeBytes32String("enclave-v1.0");
  const enclaveV1Mrsigner = ethers.encodeBytes32String("enclave-signer");
  const tx3 = await contract.addEnclaveIdentity(enclaveV1Mrenclave, enclaveV1Mrsigner, 0, 0, "SGX Wallet Enclave v1.0");
  await tx3.wait();
  console.log("Enclave identity added: v1.0");

  // 4. 验证
  const params = await contract.getRuntimeParams();
  const parsed = JSON.parse(params);
  console.log("Verified runtimeParams: session=" + (parsed.session ? "OK" : "FAILED"));

  const whitelist = await contract.getPlatformWhitelist();
  console.log("Verified platform whitelist:", whitelist.length, "entries");

  const enclaveWhitelist = await contract.getEnclaveWhitelist();
  console.log("Verified enclave whitelist:", enclaveWhitelist.length, "entries");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
