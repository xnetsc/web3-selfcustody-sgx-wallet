import pkg from "hardhat";
const { ethers } = pkg;
import { expect } from "chai";
import crypto from "crypto";

function generateP256KeyPair() {
  const keyPair = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
  const pubKeyDer = keyPair.publicKey;
  const uncompressedKey = pubKeyDer.subarray(pubKeyDer.length - 65);
  const pubKeyX = "0x" + uncompressedKey.subarray(1, 33).toString("hex");
  const pubKeyY = "0x" + uncompressedKey.subarray(33, 65).toString("hex");
  return {
    privateKeyDer: keyPair.privateKey,
    publicKeyDer: keyPair.publicKey,
    pubKeyX,
    pubKeyY,
  };
}

function signP256Message(privateKeyDer, messageBytes) {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(privateKeyDer),
    format: "der",
    type: "pkcs8",
  });
  const signer = crypto.createSign("SHA256");
  signer.update(messageBytes);
  const signature = signer.sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
  const r = "0x" + signature.subarray(0, 32).toString("hex");
  const s = "0x" + signature.subarray(32, 64).toString("hex");
  const N = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
  const HALF_N = N / 2n;
  let sBig = BigInt(s);
  if (sBig > HALF_N) {
    sBig = N - sBig;
  }
  const sNormalized = "0x" + sBig.toString(16).padStart(64, "0");
  return { r, s: sNormalized };
}

function packRevocationMessage(userId, authorizationId, grantee) {
  const packed = ethers.solidityPacked(["string", "string", "address"], [userId, authorizationId, grantee]);
  return Buffer.from(ethers.getBytes(packed));
}

describe("WalletTrustContract", function () {
  let contract;
  let owner;
  let addr1;
  let addr2;

  beforeEach(async function () {
    [owner, addr1, addr2] = await ethers.getSigners();
    const WalletTrustContract = await ethers.getContractFactory("WalletTrustContract");
    contract = await WalletTrustContract.deploy();
    await contract.waitForDeployment();
  });

  describe("Configuration Management", function () {
    it("Owner can update code repository", async function () {
      const repo = "https://github.com/example/sgx-wallet";
      const tx = await contract.updateCodeRepository(repo);
      await expect(tx).to.emit(contract, "CodeRepositoryUpdated").withArgs(repo);
      expect(await contract.getCodeRepository()).to.equal(repo);
    });

    it("Non-owner cannot update code repository", async function () {
      await expect(
        contract.connect(addr1).updateCodeRepository("https://evil.com")
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("Owner can update runtime params with config structure", async function () {
      const params = JSON.stringify({
        session: { importTtlSeconds: 300, exportTtlSeconds: 86400 },
        cache: { refreshInterval: 60000 },
      });
      const tx = await contract.updateRuntimeParams(params);
      await expect(tx).to.emit(contract, "RuntimeParamsUpdated").withArgs(params);
      const stored = await contract.getRuntimeParams();
      expect(stored).to.equal(params);
      const parsed = JSON.parse(stored);
      expect(parsed.session.importTtlSeconds).to.equal(300);
      expect(parsed.cache.refreshInterval).to.equal(60000);
    });

    it("Owner can update runtime params with ntpServers in security config", async function () {
      const ntpServers = ['pool.ntp.org', 'time.google.com', 'time.cloudflare.com'];
      const params = JSON.stringify({
        session: { importTtlSeconds: 300, exportTtlSeconds: 86400 },
        cache: { refreshInterval: 60000 },
        security: { freezeDurationSeconds: 259200, ntpServers },
      });
      const tx = await contract.updateRuntimeParams(params);
      await expect(tx).to.emit(contract, "RuntimeParamsUpdated").withArgs(params);
      const stored = await contract.getRuntimeParams();
      expect(stored).to.equal(params);
      const parsed = JSON.parse(stored);
      expect(parsed.security.freezeDurationSeconds).to.equal(259200);
      expect(parsed.security.ntpServers).to.deep.equal(ntpServers);
      expect(parsed.security.ntpServers).to.have.lengthOf(3);
    });

    it("Owner can update ntpServers without losing other security fields", async function () {
      // 先设置初始配置
      const initialParams = JSON.stringify({
        security: { freezeDurationSeconds: 259200, ntpServers: ['pool.ntp.org'] },
      });
      await contract.updateRuntimeParams(initialParams);

      // 更新 ntpServers
      const updatedParams = JSON.stringify({
        security: { freezeDurationSeconds: 259200, ntpServers: ['time.google.com', 'time.cloudflare.com', 'time.apple.com'] },
      });
      await contract.updateRuntimeParams(updatedParams);
      const stored = await contract.getRuntimeParams();
      const parsed = JSON.parse(stored);
      expect(parsed.security.ntpServers).to.deep.equal(['time.google.com', 'time.cloudflare.com', 'time.apple.com']);
      expect(parsed.security.freezeDurationSeconds).to.equal(259200);
    });

    it("Non-owner cannot update runtime params", async function () {
      await expect(
        contract.connect(addr1).updateRuntimeParams("{}")
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });
  });

  describe("Platform Whitelist", function () {
    it("Owner can add platform address", async function () {
      const tx = await contract.addPlatformAddress(addr1.address);
      await expect(tx).to.emit(contract, "PlatformAddressAdded").withArgs(addr1.address);
      expect(await contract.isPlatformWhitelisted(addr1.address)).to.be.true;
    });

    it("Cannot add zero address", async function () {
      await expect(
        contract.addPlatformAddress(ethers.ZeroAddress)
      ).to.be.revertedWith("Invalid address");
    });

    it("Cannot add duplicate address", async function () {
      await contract.addPlatformAddress(addr1.address);
      await expect(
        contract.addPlatformAddress(addr1.address)
      ).to.be.revertedWith("Already whitelisted");
    });

    it("Owner can remove platform address", async function () {
      await contract.addPlatformAddress(addr1.address);
      const tx = await contract.removePlatformAddress(addr1.address);
      await expect(tx).to.emit(contract, "PlatformAddressRemoved").withArgs(addr1.address);
      expect(await contract.isPlatformWhitelisted(addr1.address)).to.be.false;
    });

    it("Cannot remove non-existent address", async function () {
      await expect(
        contract.removePlatformAddress(addr1.address)
      ).to.be.revertedWith("Not whitelisted");
    });

    it("Non-owner cannot add platform address", async function () {
      await expect(
        contract.connect(addr1).addPlatformAddress(addr2.address)
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("Non-owner cannot remove platform address", async function () {
      await contract.addPlatformAddress(addr1.address);
      await expect(
        contract.connect(addr1).removePlatformAddress(addr1.address)
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("Can get all whitelisted addresses", async function () {
      await contract.addPlatformAddress(addr1.address);
      await contract.addPlatformAddress(addr2.address);
      const whitelist = await contract.getPlatformWhitelist();
      expect(whitelist.length).to.equal(2);
      expect(whitelist).to.include(addr1.address);
      expect(whitelist).to.include(addr2.address);
    });

    it("Array updates correctly after middle element removal", async function () {
      const signers = await ethers.getSigners();
      await contract.addPlatformAddress(signers[1].address);
      await contract.addPlatformAddress(signers[2].address);
      await contract.addPlatformAddress(signers[3].address);
      await contract.removePlatformAddress(signers[1].address);
      const whitelist = await contract.getPlatformWhitelist();
      expect(whitelist.length).to.equal(2);
      expect(await contract.isPlatformWhitelisted(signers[1].address)).to.be.false;
      expect(await contract.isPlatformWhitelisted(signers[2].address)).to.be.true;
      expect(await contract.isPlatformWhitelisted(signers[3].address)).to.be.true;
    });
  });

  describe("Public Queries", function () {
    it("Anyone can query public info", async function () {
      const repo = "https://github.com/example/sgx";
      const params = '{"session":{"importTtlSeconds":300}}';
      await contract.updateCodeRepository(repo);
      await contract.updateRuntimeParams(params);
      const mrenclave = ethers.encodeBytes32String("test-mrenclave");
      const mrsigner = ethers.encodeBytes32String("test-mrsigner");
      await contract.addEnclaveIdentity(mrenclave, mrsigner, 1, 2, "Test Enclave v1");
      const info = await contract.connect(addr1).getPublicInfo();
      expect(info[0]).to.equal(repo);
      expect(info[1]).to.equal(params);
      expect(info[2].length).to.equal(1);
      expect(info[2][0].mrenclave).to.equal(mrenclave);
      expect(info[2][0].mrsigner).to.equal(mrsigner);
      expect(info[2][0].isvprodid).to.equal(1);
      expect(info[2][0].isvsvn).to.equal(2);
    });

    it("Initial state returns empty values", async function () {
      expect(await contract.getCodeRepository()).to.equal("");
      expect(await contract.getRuntimeParams()).to.equal("");
      const whitelist = await contract.getEnclaveWhitelist();
      expect(whitelist.length).to.equal(0);
    });
  });

  describe("Authorization Revocation", function () {
    it("Valid P256 signature can revoke authorization", async function () {
      const userId = "user-001";
      const authorizationId = "auth-001";
      const grantee = addr1.address;
      const keyPair = generateP256KeyPair();
      const msgBytes = packRevocationMessage(userId, authorizationId, grantee);
      const { r, s } = signP256Message(keyPair.privateKeyDer, msgBytes);
      const tx = await contract.revokeAuthorization(
        userId, authorizationId, grantee,
        keyPair.pubKeyX, keyPair.pubKeyY,
        r, s
      );
      await expect(tx)
        .to.emit(contract, "AuthorizationRevoked")
        .withArgs(userId, authorizationId, grantee, keyPair.pubKeyX, keyPair.pubKeyY);
      expect(await contract.isAuthorizationRevoked(userId, authorizationId)).to.be.true;
    });

    it("Cannot revoke same authorization twice", async function () {
      const userId = "user-002";
      const authorizationId = "auth-002";
      const grantee = addr1.address;
      const keyPair = generateP256KeyPair();
      const msgBytes = packRevocationMessage(userId, authorizationId, grantee);
      const { r, s } = signP256Message(keyPair.privateKeyDer, msgBytes);
      await contract.revokeAuthorization(
        userId, authorizationId, grantee,
        keyPair.pubKeyX, keyPair.pubKeyY, r, s
      );
      await expect(
        contract.revokeAuthorization(
          userId, authorizationId, grantee,
          keyPair.pubKeyX, keyPair.pubKeyY, r, s
        )
      ).to.be.revertedWith("Already revoked");
    });

    it("Rejects signature with wrong key pair", async function () {
      const userId = "user-004";
      const authorizationId = "auth-004";
      const grantee = addr1.address;
      const keyPair = generateP256KeyPair();
      const msgBytes = packRevocationMessage(userId, authorizationId, grantee);
      const wrongKeyPair = generateP256KeyPair();
      const { r, s } = signP256Message(wrongKeyPair.privateKeyDer, msgBytes);
      await expect(
        contract.revokeAuthorization(
          userId, authorizationId, grantee,
          keyPair.pubKeyX, keyPair.pubKeyY,
          r, s
        )
      ).to.be.revertedWith("Invalid P256 signature");
    });

    it("Rejects signature with wrong message content", async function () {
      const userId = "user-005";
      const authorizationId = "auth-005";
      const grantee = addr1.address;
      const keyPair = generateP256KeyPair();
      const wrongMsgBytes = packRevocationMessage("wrong-user", "wrong-auth", grantee);
      const { r, s } = signP256Message(keyPair.privateKeyDer, wrongMsgBytes);
      await expect(
        contract.revokeAuthorization(
          userId, authorizationId, grantee,
          keyPair.pubKeyX, keyPair.pubKeyY, r, s
        )
      ).to.be.revertedWith("Invalid P256 signature");
    });

    it("Rejects empty userId", async function () {
      const grantee = addr1.address;
      const keyPair = generateP256KeyPair();
      const msgBytes = packRevocationMessage("", "auth-006", grantee);
      const { r, s } = signP256Message(keyPair.privateKeyDer, msgBytes);
      await expect(
        contract.revokeAuthorization(
          "", "auth-006", grantee,
          keyPair.pubKeyX, keyPair.pubKeyY, r, s
        )
      ).to.be.revertedWith("Empty userId");
    });

    it("Rejects empty authorizationId", async function () {
      const grantee = addr1.address;
      const keyPair = generateP256KeyPair();
      const msgBytes = packRevocationMessage("user-007", "", grantee);
      const { r, s } = signP256Message(keyPair.privateKeyDer, msgBytes);
      await expect(
        contract.revokeAuthorization(
          "user-007", "", grantee,
          keyPair.pubKeyX, keyPair.pubKeyY, r, s
        )
      ).to.be.revertedWith("Empty authorizationId");
    });

    it("Rejects zero address grantee", async function () {
      const keyPair = generateP256KeyPair();
      const msgBytes = packRevocationMessage("user-011", "auth-011", ethers.ZeroAddress);
      const { r, s } = signP256Message(keyPair.privateKeyDer, msgBytes);
      await expect(
        contract.revokeAuthorization(
          "user-011", "auth-011", ethers.ZeroAddress,
          keyPair.pubKeyX, keyPair.pubKeyY, r, s
        )
      ).to.be.revertedWith("Empty grantee");
    });

    it("Signature for different grantee is rejected", async function () {
      const userId = "user-012";
      const authorizationId = "auth-012";
      const keyPair = generateP256KeyPair();
      // Sign for addr1 but try to revoke for addr2
      const msgBytes = packRevocationMessage(userId, authorizationId, addr1.address);
      const { r, s } = signP256Message(keyPair.privateKeyDer, msgBytes);
      await expect(
        contract.revokeAuthorization(
          userId, authorizationId, addr2.address,
          keyPair.pubKeyX, keyPair.pubKeyY, r, s
        )
      ).to.be.revertedWith("Invalid P256 signature");
    });

    it("Can retrieve all revocation records for a user", async function () {
      const userId = "user-008";
      const grantee = addr1.address;
      const keyPair = generateP256KeyPair();
      for (const authId of ["auth-A", "auth-B"]) {
        const msgBytes = packRevocationMessage(userId, authId, grantee);
        const { r, s } = signP256Message(keyPair.privateKeyDer, msgBytes);
        await contract.revokeAuthorization(
          userId, authId, grantee,
          keyPair.pubKeyX, keyPair.pubKeyY, r, s
        );
      }
      const records = await contract.getRevokedAuthorizations(userId);
      expect(records.length).to.equal(2);
      expect(records[0].authorizationId).to.equal("auth-A");
      expect(records[0].grantee).to.equal(grantee);
      expect(records[0].passkeyPubKeyX).to.equal(keyPair.pubKeyX);
      expect(records[0].passkeyPubKeyY).to.equal(keyPair.pubKeyY);
      expect(records[1].authorizationId).to.equal("auth-B");
      expect(records[1].grantee).to.equal(grantee);
    });

    it("Non-revoked authorization returns false", async function () {
      expect(
        await contract.isAuthorizationRevoked("user-009", "auth-nonexistent")
      ).to.be.false;
    });

    it("Different users have independent revocation records", async function () {
      const grantee = addr1.address;
      const keyPair1 = generateP256KeyPair();
      const msgBytes1 = packRevocationMessage("user-A", "auth-001", grantee);
      const sig1 = signP256Message(keyPair1.privateKeyDer, msgBytes1);
      await contract.revokeAuthorization(
        "user-A", "auth-001", grantee,
        keyPair1.pubKeyX, keyPair1.pubKeyY,
        sig1.r, sig1.s
      );
      expect(await contract.isAuthorizationRevoked("user-A", "auth-001")).to.be.true;
      expect(await contract.isAuthorizationRevoked("user-B", "auth-001")).to.be.false;
      const records = await contract.getRevokedAuthorizations("user-B");
      expect(records.length).to.equal(0);
    });

    it("Any account can invoke revocation (not owner-restricted)", async function () {
      const userId = "user-010";
      const authorizationId = "auth-010";
      const grantee = addr2.address;
      const keyPair = generateP256KeyPair();
      const msgBytes = packRevocationMessage(userId, authorizationId, grantee);
      const { r, s } = signP256Message(keyPair.privateKeyDer, msgBytes);
      const tx = await contract.connect(addr1).revokeAuthorization(
        userId, authorizationId, grantee,
        keyPair.pubKeyX, keyPair.pubKeyY, r, s
      );
      await expect(tx)
        .to.emit(contract, "AuthorizationRevoked")
        .withArgs(userId, authorizationId, grantee, keyPair.pubKeyX, keyPair.pubKeyY);
      expect(await contract.isAuthorizationRevoked(userId, authorizationId)).to.be.true;
    });
  });

  describe("Enclave Whitelist", function () {
    it("Owner can add enclave identity", async function () {
      const mrenclave = ethers.encodeBytes32String("enclave-v1");
      const mrsigner = ethers.encodeBytes32String("signer-v1");
      const tx = await contract.addEnclaveIdentity(mrenclave, mrsigner, 1, 0, "Enclave v1.0");
      await expect(tx).to.emit(contract, "EnclaveIdentityAdded").withArgs(mrenclave, mrsigner, "Enclave v1.0");
      expect(await contract.isEnclaveWhitelisted(mrenclave)).to.be.true;
    });

    it("Cannot add zero mrenclave", async function () {
      const mrsigner = ethers.encodeBytes32String("signer");
      await expect(
        contract.addEnclaveIdentity(ethers.ZeroHash, mrsigner, 0, 0, "bad")
      ).to.be.revertedWith("Invalid _mrenclave");
    });

    it("Cannot add duplicate mrenclave", async function () {
      const mrenclave = ethers.encodeBytes32String("enclave-dup");
      const mrsigner = ethers.encodeBytes32String("signer-dup");
      await contract.addEnclaveIdentity(mrenclave, mrsigner, 0, 0, "first");
      await expect(
        contract.addEnclaveIdentity(mrenclave, mrsigner, 0, 0, "second")
      ).to.be.revertedWith("Already whitelisted");
    });

    it("Owner can remove enclave identity", async function () {
      const mrenclave = ethers.encodeBytes32String("enclave-rm");
      const mrsigner = ethers.encodeBytes32String("signer-rm");
      await contract.addEnclaveIdentity(mrenclave, mrsigner, 1, 0, "to remove");
      const tx = await contract.removeEnclaveIdentity(mrenclave);
      await expect(tx).to.emit(contract, "EnclaveIdentityRemoved").withArgs(mrenclave);
      expect(await contract.isEnclaveWhitelisted(mrenclave)).to.be.false;
    });

    it("Cannot remove non-existent enclave identity", async function () {
      const mrenclave = ethers.encodeBytes32String("nonexist");
      await expect(
        contract.removeEnclaveIdentity(mrenclave)
      ).to.be.revertedWith("Not whitelisted");
    });

    it("Non-owner cannot add enclave identity", async function () {
      const mrenclave = ethers.encodeBytes32String("enc");
      const mrsigner = ethers.encodeBytes32String("sig");
      await expect(
        contract.connect(addr1).addEnclaveIdentity(mrenclave, mrsigner, 0, 0, "bad")
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("Non-owner cannot remove enclave identity", async function () {
      const mrenclave = ethers.encodeBytes32String("enc2");
      const mrsigner = ethers.encodeBytes32String("sig2");
      await contract.addEnclaveIdentity(mrenclave, mrsigner, 0, 0, "ok");
      await expect(
        contract.connect(addr1).removeEnclaveIdentity(mrenclave)
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("Can get all whitelisted enclave identities", async function () {
      const mr1 = ethers.encodeBytes32String("enc-a");
      const ms1 = ethers.encodeBytes32String("sig-a");
      const mr2 = ethers.encodeBytes32String("enc-b");
      const ms2 = ethers.encodeBytes32String("sig-b");
      await contract.addEnclaveIdentity(mr1, ms1, 1, 0, "Enclave A");
      await contract.addEnclaveIdentity(mr2, ms2, 2, 1, "Enclave B");
      const whitelist = await contract.getEnclaveWhitelist();
      expect(whitelist.length).to.equal(2);
      expect(whitelist[0].mrenclave).to.equal(mr1);
      expect(whitelist[0].mrsigner).to.equal(ms1);
      expect(whitelist[0].isvprodid).to.equal(1);
      expect(whitelist[0].isvsvn).to.equal(0);
      expect(whitelist[0].description).to.equal("Enclave A");
      expect(whitelist[1].mrenclave).to.equal(mr2);
      expect(whitelist[1].mrsigner).to.equal(ms2);
      expect(whitelist[1].isvprodid).to.equal(2);
      expect(whitelist[1].isvsvn).to.equal(1);
      expect(whitelist[1].description).to.equal("Enclave B");
    });

    it("Array updates correctly after middle element removal", async function () {
      const mr1 = ethers.encodeBytes32String("enc-1");
      const ms1 = ethers.encodeBytes32String("sig-1");
      const mr2 = ethers.encodeBytes32String("enc-2");
      const ms2 = ethers.encodeBytes32String("sig-2");
      const mr3 = ethers.encodeBytes32String("enc-3");
      const ms3 = ethers.encodeBytes32String("sig-3");
      await contract.addEnclaveIdentity(mr1, ms1, 0, 0, "v1");
      await contract.addEnclaveIdentity(mr2, ms2, 0, 0, "v2");
      await contract.addEnclaveIdentity(mr3, ms3, 0, 0, "v3");
      await contract.removeEnclaveIdentity(mr1);
      const whitelist = await contract.getEnclaveWhitelist();
      expect(whitelist.length).to.equal(2);
      expect(await contract.isEnclaveWhitelisted(mr1)).to.be.false;
      expect(await contract.isEnclaveWhitelisted(mr2)).to.be.true;
      expect(await contract.isEnclaveWhitelisted(mr3)).to.be.true;
    });

    it("Initial enclave whitelist is empty", async function () {
      const whitelist = await contract.getEnclaveWhitelist();
      expect(whitelist.length).to.equal(0);
    });
  });

  describe("Passkey Recovery", function () {
    const userId = "user-recovery-001";
    const newPubKeyHash = ethers.keccak256(ethers.toUtf8Bytes("new-passkey-cose-pubkey"));
    const oldPubKeyHash = ethers.keccak256(ethers.toUtf8Bytes("old-passkey-cose-pubkey"));
    const uuid = "recovery-uuid-001";
    const memo = "Verified via video call 2026-04-16";

    it("Owner can set passkey recovery entry", async function () {
      const tx = await contract.setPasskeyRecovery(userId, newPubKeyHash, oldPubKeyHash, uuid, memo);
      await expect(tx)
        .to.emit(contract, "PasskeyRecoverySet")
        .withArgs(userId, newPubKeyHash, oldPubKeyHash, uuid, memo);
      expect(await contract.passkeyRecoveryExists(userId, newPubKeyHash)).to.be.true;
    });

    it("Can query passkey recovery entry", async function () {
      await contract.setPasskeyRecovery(userId, newPubKeyHash, oldPubKeyHash, uuid, memo);
      const result = await contract.getPasskeyRecovery(userId, newPubKeyHash);
      expect(result.oldPubKeyHash).to.equal(oldPubKeyHash);
      expect(result.uuid).to.equal(uuid);
      expect(result.memo).to.equal(memo);
      expect(result.createdAt).to.be.gt(0);
    });

    it("Query non-existent recovery entry reverts", async function () {
      const fakeHash = ethers.keccak256(ethers.toUtf8Bytes("nonexistent"));
      await expect(
        contract.getPasskeyRecovery(userId, fakeHash)
      ).to.be.revertedWith("Recovery not found");
    });

    it("Owner can remove passkey recovery entry", async function () {
      await contract.setPasskeyRecovery(userId, newPubKeyHash, oldPubKeyHash, uuid, memo);
      const tx = await contract.removePasskeyRecovery(userId, newPubKeyHash);
      await expect(tx)
        .to.emit(contract, "PasskeyRecoveryRemoved")
        .withArgs(userId, newPubKeyHash);
      expect(await contract.passkeyRecoveryExists(userId, newPubKeyHash)).to.be.false;
    });

    it("Cannot remove non-existent recovery entry", async function () {
      const fakeHash = ethers.keccak256(ethers.toUtf8Bytes("nonexistent"));
      await expect(
        contract.removePasskeyRecovery(userId, fakeHash)
      ).to.be.revertedWith("Recovery not found");
    });

    it("Non-owner cannot set passkey recovery", async function () {
      await expect(
        contract.connect(addr1).setPasskeyRecovery(userId, newPubKeyHash, oldPubKeyHash, uuid, memo)
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("Non-owner cannot remove passkey recovery", async function () {
      await contract.setPasskeyRecovery(userId, newPubKeyHash, oldPubKeyHash, uuid, memo);
      await expect(
        contract.connect(addr1).removePasskeyRecovery(userId, newPubKeyHash)
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("Rejects empty userId", async function () {
      await expect(
        contract.setPasskeyRecovery("", newPubKeyHash, oldPubKeyHash, uuid, memo)
      ).to.be.revertedWith("Empty userId");
    });

    it("Rejects zero newPubKeyHash", async function () {
      await expect(
        contract.setPasskeyRecovery(userId, ethers.ZeroHash, oldPubKeyHash, uuid, memo)
      ).to.be.revertedWith("Invalid newPubKeyHash");
    });

    it("Rejects zero oldPubKeyHash", async function () {
      await expect(
        contract.setPasskeyRecovery(userId, newPubKeyHash, ethers.ZeroHash, uuid, memo)
      ).to.be.revertedWith("Invalid oldPubKeyHash");
    });

    it("Rejects empty uuid", async function () {
      await expect(
        contract.setPasskeyRecovery(userId, newPubKeyHash, oldPubKeyHash, "", memo)
      ).to.be.revertedWith("Empty uuid");
    });

    it("Can overwrite existing recovery entry", async function () {
      await contract.setPasskeyRecovery(userId, newPubKeyHash, oldPubKeyHash, uuid, memo);
      const newOldHash = ethers.keccak256(ethers.toUtf8Bytes("different-old-key"));
      await contract.setPasskeyRecovery(userId, newPubKeyHash, newOldHash, "uuid-002", "Updated");
      const result = await contract.getPasskeyRecovery(userId, newPubKeyHash);
      expect(result.oldPubKeyHash).to.equal(newOldHash);
      expect(result.uuid).to.equal("uuid-002");
      expect(result.memo).to.equal("Updated");
    });

    it("Different users have independent recovery entries", async function () {
      const newPubKeyHash2 = ethers.keccak256(ethers.toUtf8Bytes("user-b-new-key"));
      const oldPubKeyHash2 = ethers.keccak256(ethers.toUtf8Bytes("user-b-old-key"));
      await contract.setPasskeyRecovery("user-A", newPubKeyHash, oldPubKeyHash, "uuid-A", "memo-A");
      await contract.setPasskeyRecovery("user-B", newPubKeyHash2, oldPubKeyHash2, "uuid-B", "memo-B");
      const resultA = await contract.getPasskeyRecovery("user-A", newPubKeyHash);
      const resultB = await contract.getPasskeyRecovery("user-B", newPubKeyHash2);
      expect(resultA.uuid).to.equal("uuid-A");
      expect(resultB.uuid).to.equal("uuid-B");
      expect(await contract.passkeyRecoveryExists("user-A", newPubKeyHash2)).to.be.false;
    });
  });

  describe("Deployment", function () {
    it("Deployer is owner", async function () {
      expect(await contract.owner()).to.equal(owner.address);
    });

    it("Contract address is non-zero", async function () {
      const addr = await contract.getAddress();
      expect(addr).to.not.equal(ethers.ZeroAddress);
    });
  });
});
