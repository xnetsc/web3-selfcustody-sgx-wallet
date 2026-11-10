import pkg from "hardhat";
const { ethers } = pkg;
import { expect } from "chai";
import crypto from "crypto";

/**
 * 应急授权（运营方治理）合约测试
 *
 * 覆盖：
 *  - 治理 Passkey 指定/移除（onlyOwner、重复指定、移除未指定）
 *  - 应急授权写入（全文存储、authHash 合约自算、只写一次、未指定治理钥匙拒绝、
 *    过期时间必须在未来、grantee 非零、事件）
 *  - 查询全文与写入一致
 *  - 撤销（onlyOwner、终态、重复撤销拒绝、不存在拒绝）
 *  - 精确匹配：多份记录并存时按 authorizationId 各自命中
 */

function sha256Hex(str) {
  return "0x" + crypto.createHash("sha256").update(str, "utf8").digest("hex");
}

describe("WalletTrustContract - Emergency Authorization", function () {
  let contract;
  let owner;
  let addr1;
  let addr2;

  const OPERATOR_USER_ID = "operator-user-1";
  const PUBKEY_HASH = "0x" + "ab".repeat(32);
  const PUBKEY_HASH_2 = "0x" + "cd".repeat(32);

  const AUTH_JSON = JSON.stringify({
    authorizationId: "emg-2026-0001",
    type: "emergency",
    operatorUserId: OPERATOR_USER_ID,
    operatorCredentialId: "cred-op-1",
    grantee: "0x1111111111111111111111111111111111111111",
    wallets: [
      {
        userId: "user-alice",
        policy: {
          operations: {
            tx_sign: { targetAddresses: [{ chainId: 1, address: "*" }] },
            passkey_bind: { newPubKeyHash: "0x" + "ef".repeat(32) },
          },
        },
      },
    ],
    timePolicy: { deadline: "2027-01-01T00:00:00.000Z" },
    createdAt: "2026-11-10T00:00:00.000Z",
  });
  const SIGNATURE_JSON = JSON.stringify({ response: { authenticatorData: "aa", clientDataJSON: "bb", signature: "cc" } });

  async function futureTimestamp(offsetSeconds = 7 * 24 * 3600) {
    const block = await ethers.provider.getBlock("latest");
    return Number(block.timestamp) + offsetSeconds;
  }

  beforeEach(async function () {
    [owner, addr1, addr2] = await ethers.getSigners();
    const WalletTrustContract = await ethers.getContractFactory("WalletTrustContract");
    contract = await WalletTrustContract.deploy();
    await contract.waitForDeployment();
  });

  async function designate(hash = PUBKEY_HASH) {
    return contract.designateGovernancePasskey(OPERATOR_USER_ID, hash);
  }

  async function setAuth(id = "emg-2026-0001", overrides = {}) {
    const args = {
      authorizationId: id,
      authorizationJson: AUTH_JSON,
      signatureJson: SIGNATURE_JSON,
      operatorUserId: OPERATOR_USER_ID,
      operatorPubKeyHash: PUBKEY_HASH,
      grantee: addr1.address,
      expiresAt: await futureTimestamp(),
      ...overrides,
    };
    return contract.setEmergencyAuthorization(
      args.authorizationId,
      args.authorizationJson,
      args.signatureJson,
      args.operatorUserId,
      args.operatorPubKeyHash,
      args.grantee,
      args.expiresAt
    );
  }

  describe("Governance passkey designation", function () {
    it("Owner can designate a governance passkey", async function () {
      await expect(designate()).to.emit(contract, "GovernancePasskeyDesignated").withArgs(OPERATOR_USER_ID, PUBKEY_HASH);
      expect(await contract.isGovernancePasskey(OPERATOR_USER_ID, PUBKEY_HASH)).to.equal(true);
    });

    it("Non-owner cannot designate", async function () {
      await expect(
        contract.connect(addr1).designateGovernancePasskey(OPERATOR_USER_ID, PUBKEY_HASH)
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("Duplicate designation is rejected", async function () {
      await designate();
      await expect(designate()).to.be.revertedWith("Already designated");
    });

    it("Owner can remove a designation and it stops being governance", async function () {
      await designate();
      await expect(contract.removeGovernancePasskey(OPERATOR_USER_ID, PUBKEY_HASH))
        .to.emit(contract, "GovernancePasskeyRemoved")
        .withArgs(OPERATOR_USER_ID, PUBKEY_HASH);
      expect(await contract.isGovernancePasskey(OPERATOR_USER_ID, PUBKEY_HASH)).to.equal(false);
    });

    it("Removing a non-designated passkey is rejected", async function () {
      await expect(contract.removeGovernancePasskey(OPERATOR_USER_ID, PUBKEY_HASH)).to.be.revertedWith("Not designated");
    });

    it("Designation is scoped to (userId, pubKeyHash) pair", async function () {
      await designate();
      expect(await contract.isGovernancePasskey("someone-else", PUBKEY_HASH)).to.equal(false);
      expect(await contract.isGovernancePasskey(OPERATOR_USER_ID, PUBKEY_HASH_2)).to.equal(false);
    });
  });

  describe("Setting emergency authorizations", function () {
    beforeEach(async function () {
      await designate();
    });

    it("Stores the full record and computes authHash on-chain", async function () {
      const expiresAt = await futureTimestamp();
      await expect(setAuth("emg-2026-0001", { expiresAt }))
        .to.emit(contract, "EmergencyAuthorizationSet")
        .withArgs("emg-2026-0001", sha256Hex(AUTH_JSON), OPERATOR_USER_ID, PUBKEY_HASH, addr1.address, expiresAt);

      const rec = await contract.getEmergencyAuthorization("emg-2026-0001");
      expect(rec.authorizationJson).to.equal(AUTH_JSON);
      expect(rec.signatureJson).to.equal(SIGNATURE_JSON);
      expect(rec.authHash).to.equal(sha256Hex(AUTH_JSON));
      expect(rec.operatorUserId).to.equal(OPERATOR_USER_ID);
      expect(rec.operatorPubKeyHash).to.equal(PUBKEY_HASH);
      expect(rec.grantee).to.equal(addr1.address);
      expect(rec.expiresAt).to.equal(BigInt(expiresAt));
      expect(rec.revoked).to.equal(false);
      expect(rec.exists).to.equal(true);
      expect(rec.createdAt).to.be.greaterThan(0n);
    });

    it("Same authorizationId can never be written twice", async function () {
      await setAuth();
      await expect(setAuth()).to.be.revertedWith("Authorization id already used");
    });

    it("Id stays burned after revocation", async function () {
      await setAuth();
      await contract.revokeEmergencyAuthorization("emg-2026-0001");
      await expect(setAuth()).to.be.revertedWith("Authorization id already used");
    });

    it("Rejects when the signing passkey is not designated governance", async function () {
      await expect(setAuth("emg-x", { operatorPubKeyHash: PUBKEY_HASH_2 }))
        .to.be.revertedWith("Passkey not designated as governance");
    });

    it("Rejects an already-expired authorization", async function () {
      const block = await ethers.provider.getBlock("latest");
      await expect(setAuth("emg-x", { expiresAt: Number(block.timestamp) - 10 }))
        .to.be.revertedWith("Authorization already expired");
    });

    it("Rejects zero grantee", async function () {
      await expect(setAuth("emg-x", { grantee: ethers.ZeroAddress })).to.be.revertedWith("Invalid grantee");
    });

    it("Non-owner cannot set an authorization", async function () {
      const expiresAt = await futureTimestamp();
      await expect(
        contract.connect(addr1).setEmergencyAuthorization("emg-x", AUTH_JSON, SIGNATURE_JSON, OPERATOR_USER_ID, PUBKEY_HASH, addr1.address, expiresAt)
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("Multiple records coexist and match precisely by id", async function () {
      await setAuth("emg-2026-0001");
      const json2 = AUTH_JSON.replace("emg-2026-0001", "emg-2026-0002");
      await setAuth("emg-2026-0002", { authorizationJson: json2 });

      const rec1 = await contract.getEmergencyAuthorization("emg-2026-0001");
      const rec2 = await contract.getEmergencyAuthorization("emg-2026-0002");
      expect(rec1.authorizationJson).to.equal(AUTH_JSON);
      expect(rec2.authorizationJson).to.equal(json2);
      expect(rec1.authHash).to.not.equal(rec2.authHash);

      const missing = await contract.getEmergencyAuthorization("emg-does-not-exist");
      expect(missing.exists).to.equal(false);
      expect(missing.authorizationJson).to.equal("");
    });
  });

  describe("Revocation", function () {
    beforeEach(async function () {
      await designate();
      await setAuth();
    });

    it("Owner can revoke and the record shows revoked", async function () {
      await expect(contract.revokeEmergencyAuthorization("emg-2026-0001"))
        .to.emit(contract, "EmergencyAuthorizationRevoked")
        .withArgs("emg-2026-0001");
      const rec = await contract.getEmergencyAuthorization("emg-2026-0001");
      expect(rec.revoked).to.equal(true);
      // 全文仍在，事后可审计当时授权了什么
      expect(rec.authorizationJson).to.equal(AUTH_JSON);
    });

    it("Revoking twice is rejected", async function () {
      await contract.revokeEmergencyAuthorization("emg-2026-0001");
      await expect(contract.revokeEmergencyAuthorization("emg-2026-0001")).to.be.revertedWith("Already revoked");
    });

    it("Revoking a non-existent authorization is rejected", async function () {
      await expect(contract.revokeEmergencyAuthorization("emg-nope")).to.be.revertedWith("Authorization not found");
    });

    it("Non-owner cannot revoke", async function () {
      await expect(
        contract.connect(addr2).revokeEmergencyAuthorization("emg-2026-0001")
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });
  });
});
