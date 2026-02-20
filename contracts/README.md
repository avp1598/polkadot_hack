# Consent Vault Contract

`ConsentVaultRegistry.sol` is the on-chain trust layer for the prototype.

It stores only:
- `hash` (SHA-256 of file bytes)
- `label` (human-readable)
- wallet `submitter`
- block `timestamp`

It never stores file contents.

## Deploy Quickly (Remix)

1. Open `https://remix.polkadot.io/`.
2. Create `contracts/ConsentVaultRegistry.sol` and paste the contract.
3. Compile with Solidity `0.8.28` (or compatible `0.8.x`).
4. In **Deploy & Run Transactions**:
   - Environment: `Injected Provider - MetaMask`
   - Wallet network: Polkadot Hub TestNet
5. Deploy and copy the contract address.
6. Paste the address in the app's **Registry contract address** field.

## Polkadot Hub TestNet Network Config

These values are pulled from Polkadot docs resources used by this prototype:

- RPC URL: `https://services.polkadothub-rpc.com/testnet`
- Chain ID (decimal): `420420417`
- Chain ID (hex): `0x190f1b41`
- Chain name: `polkadot-hub-testnet`

## Suggested Demo Script

1. Add a file locally and show generated hash.
2. Click **Notarize Hash** and approve consent + wallet tx.
3. Click **Verify On-Chain** to show matching record count.
4. Modify file bytes and re-import as a new entry.
5. Verify modified file hash has no matching record (integrity proof).
