import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-gas-reporter";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.34",
    settings: {
      viaIR: true,
      evmVersion: "cancun",
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
    hardhat: {
      forking: {
        url: process.env["MAINNET_RPC_URL"] || "https://ethereum-rpc.publicnode.com",
        enabled: false
      }
    },
    sepolia: {
      url: process.env["SEPOLIA_RPC_URL"] || "https://sepolia-rpc.publicnode.com",
      accounts: process.env["DEPLOYER_PRIVATE_KEY"] ? [process.env["DEPLOYER_PRIVATE_KEY"]] : [],
      chainId: 11155111,
    },
    holesky: {
      url: process.env["HOLESKY_RPC_URL"] ?? "",
      accounts: process.env["PRIVATE_KEY"] ? [process.env["PRIVATE_KEY"]] : [],
      chainId: 17000
    }
  },
  gasReporter: {
    enabled: process.env["REPORT_GAS"] !== undefined,
    outputFile: "gas-report.txt",
    noColors: true,
    currency: "USD",
    coinmarketcap: process.env["CMC_API_KEY"] ?? undefined
  },
  mocha: {
    timeout: 120000
  }
};

export default config;
