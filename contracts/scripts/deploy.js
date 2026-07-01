import pkg from "hardhat";
const { ethers } = pkg;

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying WalletTrustContract with account:", deployer.address);

  const WalletTrustContract = await ethers.getContractFactory("WalletTrustContract");
  const contract = await WalletTrustContract.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log("WalletTrustContract deployed to:", address);

  return address;
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
