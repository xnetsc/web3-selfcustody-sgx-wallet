import pkg from "hardhat";
const { ethers } = pkg;
import { expect } from "chai";

describe("Ledger designation & chain RPC config", function () {
  let contract, owner, addr1, addr2;

  const OWNER_USER_ID = "ops-owner";
  const PUBKEY_HASH = ethers.keccak256(ethers.toUtf8Bytes("owner-pubkey"));
  const USDT_MAINNET = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
  const USDT_POLYGON = "0xc2132D05D31c914a87C6611C10748AEb04B58e8F";
  const ZERO = ethers.ZeroAddress;

  beforeEach(async function () {
    [owner, addr1, addr2] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("WalletTrustContract");
    contract = await Factory.deploy();
    await contract.waitForDeployment();
  });

  describe("Ledger designation", function () {
    it("registers a ledger and reads it back", async function () {
      await expect(contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH))
        .to.emit(contract, "LedgerRegistered")
        .withArgs("ledger-a", OWNER_USER_ID, PUBKEY_HASH);

      const l = await contract.getLedger("ledger-a");
      expect(l.ownerUserId).to.equal(OWNER_USER_ID);
      expect(l.ownerPubKeyHash).to.equal(PUBKEY_HASH);
      expect(l.enabled).to.equal(true);
      expect(l.exists).to.equal(true);
    });

    it("unknown ledger reads as non-existent", async function () {
      const l = await contract.getLedger("nope");
      expect(l.exists).to.equal(false);
      expect(l.ownerUserId).to.equal("");
    });

    it("rejects duplicate registration and non-owner calls", async function () {
      await contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH);
      await expect(contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH))
        .to.be.revertedWith("Ledger already registered");
      await expect(contract.connect(addr1).registerLedger("ledger-b", OWNER_USER_ID, PUBKEY_HASH))
        .to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("owner can change owner and enabled flag", async function () {
      await contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH);
      const newHash = ethers.keccak256(ethers.toUtf8Bytes("new-pubkey"));
      await contract.setLedgerOwner("ledger-a", "ops-owner-2", newHash);
      await contract.setLedgerEnabled("ledger-a", false);

      const l = await contract.getLedger("ledger-a");
      expect(l.ownerUserId).to.equal("ops-owner-2");
      expect(l.ownerPubKeyHash).to.equal(newHash);
      expect(l.enabled).to.equal(false);
    });

    it("setters reject unknown ledgers", async function () {
      await expect(contract.setLedgerOwner("ghost", "x", PUBKEY_HASH)).to.be.revertedWith("Ledger not found");
      await expect(contract.setLedgerPoolAddresses("ghost", 1, USDT_MAINNET, [])).to.be.revertedWith("Ledger not found");
      await expect(contract.setLedgerEnabled("ghost", true)).to.be.revertedWith("Ledger not found");
    });
  });

  describe("Collection registration per (chain, asset)", function () {
    beforeEach(async function () {
      await contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH);
      await contract.registerLedger("ledger-b", OWNER_USER_ID, PUBKEY_HASH);
    });

    it("registers pool addresses per chain and asset independently", async function () {
      // 同名 USDT 在不同链是不同资产：登记按（链，合约地址）逐项独立
      await contract.setLedgerPoolAddresses("ledger-a", 1, USDT_MAINNET, [addr1.address]);
      await contract.setLedgerPoolAddresses("ledger-a", 137, USDT_POLYGON, [addr2.address]);

      expect(await contract.getLedgerPoolAddresses("ledger-a", 1, USDT_MAINNET)).to.deep.equal([addr1.address]);
      expect(await contract.getLedgerPoolAddresses("ledger-a", 137, USDT_POLYGON)).to.deep.equal([addr2.address]);
      expect(await contract.getLedgerPoolAddresses("ledger-a", 1, USDT_POLYGON)).to.deep.equal([]);
      expect(await contract.getLedgerPoolAddresses("ledger-a", 137, USDT_MAINNET)).to.deep.equal([]);
      // 原生币（零地址）是独立的一项登记
      expect(await contract.getLedgerPoolAddresses("ledger-a", 1, ZERO)).to.deep.equal([]);
    });

    it("one address can serve multiple ledgers; registration count tracks every membership", async function () {
      await contract.setLedgerPoolAddresses("ledger-a", 1, USDT_MAINNET, [addr1.address]);
      await contract.setLedgerPoolAddresses("ledger-b", 1, USDT_MAINNET, [addr1.address]);
      await contract.setLedgerPoolAddresses("ledger-b", 1, ZERO, [addr1.address]);
      expect(await contract.isCollectionAddress(addr1.address)).to.equal(true);
      expect(await contract.isCollectionAddress(addr2.address)).to.equal(false);

      // 移出一个账本的一项登记，仍有其它登记在：仍然是归集地址
      await contract.setLedgerPoolAddresses("ledger-a", 1, USDT_MAINNET, []);
      expect(await contract.isCollectionAddress(addr1.address)).to.equal(true);
      // 全部移出后才解除
      await contract.setLedgerPoolAddresses("ledger-b", 1, USDT_MAINNET, []);
      await contract.setLedgerPoolAddresses("ledger-b", 1, ZERO, []);
      expect(await contract.isCollectionAddress(addr1.address)).to.equal(false);
    });

    it("re-setting the same set keeps the count stable; duplicates are rejected", async function () {
      await contract.setLedgerPoolAddresses("ledger-a", 1, USDT_MAINNET, [addr1.address, addr2.address]);
      await contract.setLedgerPoolAddresses("ledger-a", 1, USDT_MAINNET, [addr1.address, addr2.address]);
      await contract.setLedgerPoolAddresses("ledger-a", 1, USDT_MAINNET, []);
      // 若计数被重复累加，清空后这里仍会是 true
      expect(await contract.isCollectionAddress(addr1.address)).to.equal(false);
      expect(await contract.isCollectionAddress(addr2.address)).to.equal(false);
      await expect(contract.setLedgerPoolAddresses("ledger-a", 1, USDT_MAINNET, [addr1.address, addr1.address]))
        .to.be.revertedWith("Duplicate pool address");
    });
  });

  describe("Collection payout targets", function () {
    beforeEach(async function () {
      await contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH);
      await contract.setLedgerPoolAddresses("ledger-a", 1, USDT_MAINNET, [addr1.address, addr2.address]);
    });

    it("sets and reads back payout targets for a (chain, asset, source)", async function () {
      await expect(contract.setCollectionPayoutTargets("ledger-a", 1, USDT_MAINNET, addr1.address, [addr2.address]))
        .to.emit(contract, "CollectionPayoutTargetsUpdated")
        .withArgs("ledger-a", 1, USDT_MAINNET, addr1.address);
      expect(await contract.getCollectionPayoutTargets("ledger-a", 1, USDT_MAINNET, addr1.address)).to.deep.equal([addr2.address]);
      // 未配置的源地址读到空集（默认不许出金）；换一条链即是另一份配置
      expect(await contract.getCollectionPayoutTargets("ledger-a", 1, USDT_MAINNET, addr2.address)).to.deep.equal([]);
      expect(await contract.getCollectionPayoutTargets("ledger-a", 137, USDT_MAINNET, addr1.address)).to.deep.equal([]);
    });

    it("replaces the whole target set on re-set", async function () {
      await contract.setCollectionPayoutTargets("ledger-a", 1, USDT_MAINNET, addr1.address, [addr2.address]);
      await contract.setCollectionPayoutTargets("ledger-a", 1, USDT_MAINNET, addr1.address, []);
      expect(await contract.getCollectionPayoutTargets("ledger-a", 1, USDT_MAINNET, addr1.address)).to.deep.equal([]);
    });

    it("rejects sources not registered for that chain and asset", async function () {
      const [, , , outsider] = await ethers.getSigners();
      await expect(contract.setCollectionPayoutTargets("ledger-a", 1, USDT_MAINNET, outsider.address, [addr2.address]))
        .to.be.revertedWith("Source is not a collection address of this ledger for this chain and asset");
      // 源地址登记在链 1 的 USDT 下，拿到链 137 的 USDT 配置里同样被拒
      await expect(contract.setCollectionPayoutTargets("ledger-a", 137, USDT_POLYGON, addr1.address, [addr2.address]))
        .to.be.revertedWith("Source is not a collection address of this ledger for this chain and asset");
      await expect(contract.setCollectionPayoutTargets("ghost", 1, USDT_MAINNET, addr1.address, []))
        .to.be.revertedWith("Ledger not found");
    });
  });

  describe("Ledger withdrawal policy", function () {
    it("sets and reads back per-asset limits; unset reads as non-existent", async function () {
      await contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH);
      await expect(contract.setLedgerWithdrawalPolicy("ledger-a", addr2.address, 1000, 5000))
        .to.emit(contract, "LedgerWithdrawalPolicyUpdated")
        .withArgs("ledger-a", addr2.address);
      const p = await contract.getLedgerWithdrawalPolicy("ledger-a", addr2.address);
      expect(p.maxSingleAmount).to.equal(1000n);
      expect(p.maxDailyAmount).to.equal(5000n);
      expect(p.exists).to.equal(true);

      const unset = await contract.getLedgerWithdrawalPolicy("ledger-a", addr1.address);
      expect(unset.exists).to.equal(false);
      await expect(contract.setLedgerWithdrawalPolicy("ghost", addr2.address, 1, 1))
        .to.be.revertedWith("Ledger not found");
    });
  });

  describe("Chain RPC config", function () {
    it("sets and reads back a chain config", async function () {
      await expect(contract.setChainRpcConfig("ethereum", 1, ["https://rpc1.example", "https://rpc2.example"], ["", "CERT"], 12))
        .to.emit(contract, "ChainRpcConfigUpdated")
        .withArgs(1, "ethereum");

      const c = await contract.getChainRpcConfig(1);
      expect(c.chainName).to.equal("ethereum");
      expect(c.rpcUrls).to.deep.equal(["https://rpc1.example", "https://rpc2.example"]);
      expect(c.caCerts).to.deep.equal(["", "CERT"]);
      expect(c.confirmations).to.equal(12n);
      expect(c.exists).to.equal(true);
    });

    it("replaces the whole config on re-set; unknown chain reads as non-existent", async function () {
      await contract.setChainRpcConfig("ethereum", 1, ["https://a.example"], [""], 12);
      await contract.setChainRpcConfig("ethereum", 1, ["https://b.example", "https://c.example"], ["", ""], 6);
      const c = await contract.getChainRpcConfig(1);
      expect(c.rpcUrls).to.deep.equal(["https://b.example", "https://c.example"]);
      expect(c.confirmations).to.equal(6n);

      const missing = await contract.getChainRpcConfig(999);
      expect(missing.exists).to.equal(false);
    });

    it("rejects mismatched caCerts length and non-owner calls", async function () {
      await expect(contract.setChainRpcConfig("ethereum", 1, ["https://a.example"], [], 12))
        .to.be.revertedWith("rpcUrls/caCerts length mismatch");
      await expect(contract.connect(addr1).setChainRpcConfig("ethereum", 1, ["https://a.example"], [""], 12))
        .to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });
  });
});
