import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import path from "path";

const ROOT = path.resolve(__dirname, "..");

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
    root: ROOT,
    sources: path.join(ROOT, "contracts/src"),
    tests: path.join(ROOT, "test"),
    artifacts: path.join(ROOT, "artifacts"),
    cache: path.join(ROOT, "cache")
  },
  networks: {
    hardhat: {
      chainId: 31337,
      mining: {
        auto: true
      },
      blockGasLimit: 30_000_000,
      accounts: {
        count: 10,
        accountsBalance: "10000000000000000000000" // 10000 ETH each
      }
    },
    localhost: {
      url: "http://localhost:8545",
      chainId: 31337
    }
  },
  mocha: {
    timeout: 120000
  }
};

export default config;
