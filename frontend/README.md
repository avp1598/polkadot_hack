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

The app is hardcoded to this deployed registry:

`0x6D438d562900Fd8e71950776F70DAE52e850306C`

If you want to switch contracts, edit `src/App.tsx`.
