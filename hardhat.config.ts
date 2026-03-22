import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-gas-reporter";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.20",
    settings: {
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  paths: {
    sources: "./contracts/src"
  },
  networks: {
    hardhat: {},
    sepolia: {
      url: process.env["SEPOLIA_RPC_URL"] ?? "",
      accounts: process.env["PRIVATE_KEY"] ? [process.env["PRIVATE_KEY"]] : []
    },
    // OP Sepolia — Optimism testnet
    opSepolia: {
      url: process.env["OP_SEPOLIA_RPC_URL"] ?? "",
      accounts: process.env["PRIVATE_KEY"] ? [process.env["PRIVATE_KEY"]] : [],
      chainId: 11155420
    },
    // Arbitrum Sepolia
    arbitrumSepolia: {
      url: process.env["ARBITRUM_SEPOLIA_RPC_URL"] ?? "",
      accounts: process.env["PRIVATE_KEY"] ? [process.env["PRIVATE_KEY"]] : [],
      chainId: 421614
    }
  },
  gasReporter: {
    enabled: process.env["REPORT_GAS"] !== undefined,
    currency: "USD"
  },
  mocha: {
    timeout: 120000
  }
};

export default config;
