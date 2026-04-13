/**
 * deploy.js - Deployment Script for IAM dApp Smart Contracts
 *
 * Deployment Order:
 *   1. DIDRegistry    — No dependencies; deployed first.
 *   2. CredentialStatus — No dependencies; deployed second.
 *   3. AccessControl  — Depends on DIDRegistry and CredentialStatus addresses.
 *
 * Usage:
 *   npx hardhat run scripts/deploy.js --network hardhat       (local)
 *   npx hardhat run scripts/deploy.js --network sepolia       (Ethereum testnet)
 *   npx hardhat run scripts/deploy.js --network mumbai        (Polygon testnet)
 */

const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);
  console.log("Account balance:", (await deployer.provider.getBalance(deployer.address)).toString());

  // --- Step 1: Deploy DIDRegistry ---
  console.log("\n[1/3] Deploying DIDRegistry...");
  const DIDRegistry = await ethers.getContractFactory("DIDRegistry");
  const didRegistry = await DIDRegistry.deploy();
  await didRegistry.waitForDeployment();
  const didRegistryAddress = await didRegistry.getAddress();
  console.log("DIDRegistry deployed to:", didRegistryAddress);

  // --- Step 2: Deploy CredentialStatus ---
  console.log("\n[2/3] Deploying CredentialStatus...");
  const CredentialStatus = await ethers.getContractFactory("CredentialStatus");
  const credentialStatus = await CredentialStatus.deploy();
  await credentialStatus.waitForDeployment();
  const credentialStatusAddress = await credentialStatus.getAddress();
  console.log("CredentialStatus deployed to:", credentialStatusAddress);

  // --- Step 3: Deploy AccessControl (depends on the above two) ---
  console.log("\n[3/3] Deploying AccessControl...");
  const AccessControl = await ethers.getContractFactory("AccessControl");
  const accessControl = await AccessControl.deploy(didRegistryAddress, credentialStatusAddress);
  await accessControl.waitForDeployment();
  const accessControlAddress = await accessControl.getAddress();
  console.log("AccessControl deployed to:", accessControlAddress);

  // --- Summary ---
  console.log("\n=== Deployment Summary ===");
  console.log("DIDRegistry:      ", didRegistryAddress);
  console.log("CredentialStatus: ", credentialStatusAddress);
  console.log("AccessControl:    ", accessControlAddress);
  console.log("==========================\n");

  // TODO (Phase 3): Write deployed addresses to a deployments.json for frontend integration
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
