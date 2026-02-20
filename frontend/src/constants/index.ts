export const STORAGE_KEY_PREFIX = 'consent-vault.encrypted-v1'
export const GUEST_PROFILE_ID = 'guest'
export const PBKDF2_ITERATIONS = 240_000
export const CONSENT_VAULT_REGISTRY_ADDRESS = '0x6D438d562900Fd8e71950776F70DAE52e850306C'
export const WALLET_CALL_TIMEOUT_MS = 30_000

export const POLKADOT_HUB_TESTNET = {
  name: 'polkadot-hub-testnet',
  chainId: 420420417,
  chainIdHex: '0x190f1b41',
  rpcUrl: 'https://services.polkadothub-rpc.com/testnet',
  blockExplorerUrl: 'https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fpas-rpc.stakeworld.io%2Fassethub#/explorer',
}

export const CONSENT_VAULT_ABI = [
  'event HashNotarized(bytes32 indexed hash, address indexed submitter, uint64 timestamp, string label)',
  'function notarize(bytes32 hash, string calldata label) external',
  'function getRecords(bytes32 hash) external view returns ((address submitter, uint64 timestamp, string label)[])',
  'function isNotarized(bytes32 hash) external view returns (bool)',
] as const
