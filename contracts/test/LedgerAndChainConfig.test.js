import pkg from "hardhat";
const { ethers } = pkg;
import { expect } from "chai";

describe("Ledger designation & chain RPC config", function () {
  let contract, owner, addr1, addr2;

  const OWNER_USER_ID = "ops-owner";
  const PUBKEY_HASH = ethers.keccak256(ethers.toUtf8Bytes("owner-pubkey"));

  beforeEach(async function () {
    [owner, addr1, addr2] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("WalletTrustContract");
    contract = await Factory.deploy();
    await contract.waitForDeployment();
  });

  describe("Ledger designation", function () {
    it("registers a ledger and reads it back", async function () {
      await expect(contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH, [addr1.address, addr2.address]))
        .to.emit(contract, "LedgerRegistered")
        .withArgs("ledger-a", OWNER_USER_ID, PUBKEY_HASH);

      const l = await contract.getLedger("ledger-a");
      expect(l.ownerUserId).to.equal(OWNER_USER_ID);
      expect(l.ownerPubKeyHash).to.equal(PUBKEY_HASH);
      expect(l.poolAddresses).to.deep.equal([addr1.address, addr2.address]);
      expect(l.enabled).to.equal(true);
      expect(l.exists).to.equal(true);
    });

    it("unknown ledger reads as non-existent", async function () {
      const l = await contract.getLedger("nope");
      expect(l.exists).to.equal(false);
      expect(l.ownerUserId).to.equal("");
      expect(l.poolAddresses.length).to.equal(0);
    });

    it("rejects duplicate registration and non-owner calls", async function () {
      await contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH, []);
      await expect(contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH, []))
        .to.be.revertedWith("Ledger already registered");
      await expect(contract.connect(addr1).registerLedger("ledger-b", OWNER_USER_ID, PUBKEY_HASH, []))
        .to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("owner can change owner, pool addresses and enabled flag", async function () {
      await contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH, [addr1.address]);
      const newHash = ethers.keccak256(ethers.toUtf8Bytes("new-pubkey"));
      await contract.setLedgerOwner("ledger-a", "ops-owner-2", newHash);
      await contract.setLedgerPoolAddresses("ledger-a", [addr2.address]);
      await contract.setLedgerEnabled("ledger-a", false);

      const l = await contract.getLedger("ledger-a");
      expect(l.ownerUserId).to.equal("ops-owner-2");
      expect(l.ownerPubKeyHash).to.equal(newHash);
      expect(l.poolAddresses).to.deep.equal([addr2.address]);
      expect(l.enabled).to.equal(false);
    });

    it("setters reject unknown ledgers", async function () {
      await expect(contract.setLedgerOwner("ghost", "x", PUBKEY_HASH)).to.be.revertedWith("Ledger not found");
      await expect(contract.setLedgerPoolAddresses("ghost", [])).to.be.revertedWith("Ledger not found");
      await expect(contract.setLedgerEnabled("ghost", true)).to.be.revertedWith("Ledger not found");
    });
  });

  describe("Collection payout targets", function () {
    beforeEach(async function () {
      await contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH, [addr1.address, addr2.address]);
    });

    it("sets and reads back payout targets for a collection address", async function () {
      await expect(contract.setCollectionPayoutTargets("ledger-a", addr1.address, [addr2.address]))
        .to.emit(contract, "CollectionPayoutTargetsUpdated")
        .withArgs("ledger-a", addr1.address);
      expect(await contract.getCollectionPayoutTargets("ledger-a", addr1.address)).to.deep.equal([addr2.address]);
      // 未配置的源地址读到空集（默认不许出金）
      expect(await contract.getCollectionPayoutTargets("ledger-a", addr2.address)).to.deep.equal([]);
    });

    it("replaces the whole target set on re-set", async function () {
      await contract.setCollectionPayoutTargets("ledger-a", addr1.address, [addr2.address]);
      await contract.setCollectionPayoutTargets("ledger-a", addr1.address, []);
      expect(await contract.getCollectionPayoutTargets("ledger-a", addr1.address)).to.deep.equal([]);
    });

    it("rejects sources that are not collection addresses of the ledger", async function () {
      const [, , , outsider] = await ethers.getSigners();
      await expect(contract.setCollectionPayoutTargets("ledger-a", outsider.address, [addr2.address]))
        .to.be.revertedWith("Source is not a collection address of this ledger");
      await expect(contract.setCollectionPayoutTargets("ghost", addr1.address, []))
        .to.be.revertedWith("Ledger not found");
    });
  });

  describe("Ledger withdrawal policy", function () {
    it("sets and reads back per-asset limits; unset reads as non-existent", async function () {
      await contract.registerLedger("ledger-a", OWNER_USER_ID, PUBKEY_HASH, [addr1.address]);
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
