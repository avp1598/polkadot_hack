# Consent Vault Frontend

Local-first dApp UI for PromptOff.

## Features

- Encrypted local vault (AES-GCM at rest in browser storage)
- Explicit consent modal before every outside interaction
- Hash notarization to Polkadot Hub TestNet
- On-chain verification of stored file hashes
- Encrypted vault export/import for portability

## Stack

- React + TypeScript + Vite
- Bun for package management and scripts
- `ethers` for wallet + contract interactions

## Run

```bash
bun install
bun run dev
```

## Build

```bash
bun run build
```

## Contract Setup

1. Deploy `contracts/ConsentVaultRegistry.sol` (see `../contracts/README.md`)
2. Copy deployed address
3. Paste address into **Registry contract address** inside the app
