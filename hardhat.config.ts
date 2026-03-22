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
    goerli: {
      url: process.env["GOERLI_RPC_URL"] ?? "",
      accounts: process.env["PRIVATE_KEY"] ? [process.env["PRIVATE_KEY"]] : []
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
