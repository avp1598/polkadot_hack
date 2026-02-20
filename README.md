# Consent Vault (PromptOff Prototype)

Local-first security app for sensitive documents:

- Files stay encrypted in browser storage by default
- Every outside interaction requires explicit approval
- Polkadot Hub TestNet stores hash proofs for verification

## Project Structure

- `frontend/` React + TypeScript UI
- `contracts/` Solidity trust-layer contract
- `docs/polkadot-ai/` ingested Polkadot AI resource bundles used for implementation

## Polkadot Config Used

- RPC URL: `https://services.polkadothub-rpc.com/testnet`
- Chain ID: `420420417` (`0x190f1b41`)
- Chain name: `polkadot-hub-testnet`

## Run Frontend

```bash
cd frontend
bun install
bun run dev
```

## Deploy Contract

See `contracts/README.md`.

App is hardcoded to:

`0x6D438d562900Fd8e71950776F70DAE52e850306C`

If you redeploy the contract, update `frontend/src/App.tsx`.

## Demo Flow

1. Create vault passphrase and unlock.
2. Add a document and show local SHA-256 hash.
3. Approve consent + notarize hash on-chain.
4. Verify on-chain and show matching records.
5. Export encrypted vault JSON to prove ownership/portability.
