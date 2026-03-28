export const FORK_CONFIG = {
  rpcUrl: process.env.MAINNET_RPC_URL || "https://ethereum-rpc.publicnode.com",
  fallbackRpcUrl: "https://eth.llamarpc.com",
  blockNumber: "latest",
  chainId: 1,
  gasLimit: 30_000_000,
  accounts: 5
};
