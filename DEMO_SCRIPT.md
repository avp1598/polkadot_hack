# TruthMark — Demo Script

## Pre-Demo Setup

```
cd frontend && bun run dev
```

- MetaMask/SubWallet installed, funded with test DOT on Polkadot Hub TestNet
- Prepare a file: short MP4, or a `official-statement.txt` with a few sentences
- App open, vault already **created and unlocked**

---

## The Hook (say this out loud)

> *"It's 2026. You're a public figure. You just recorded your official statement on a breaking story. 72 hours later, a deepfake surfaces — showing you saying the exact opposite. How do you prove what was real?"*

---

## Step 1 — Vault is local, nothing leaves your machine

- Point to the status panel
- "No server. No upload. Files stay encrypted on your device."

---

## Step 2 — Add your authentic content

- Content type: **Statement** (or Video if you have an MP4)
- Choose file: `official-statement.txt`
- Label: `Official Statement — Feb 20 2026`
- Click **Save To Vault**

> *"The SHA-256 hash is computed in your browser. The file never leaves. Change one character — the hash changes completely."*

Point to the hash. Show the **UNVERIFIED** badge.

---

## Step 3 — Notarize it on Polkadot

- Click **Notarize Hash** on the entry card
- Walk through the **AUTHORIZATION REQUIRED** modal
- Click **Approve Once** → sign in wallet → wait ~5s

> *"That hash just got written to Polkadot Hub with a timestamp. Immutable. Permanent. Costs fractions of a cent."*

Badge is now **ON-CHAIN PENDING**.

---

## Step 4 — Verify (the kill shot)

- Click **Verify On-Chain** → approve → badge flips to **AUTHENTIC** ✅

Then scroll to **Public Hash Verifier**:

- Click **COPY** on the hash (shows "COPIED" for 2s)
- Paste into the Public Hash Verifier input
- Click **Verify Hash** — no wallet, no vault, no login needed

> *"This is what a journalist does. A court. A fact-checker. They paste the hash of the disputed content and see: notarized February 20th 2026, by wallet 0xabc... That timestamp was on-chain BEFORE the deepfake. Case closed."*

---

## The Close

| What they see | What it means |
|---|---|
| AUTHENTIC badge, green border | Hash verified on-chain with records |
| Timestamp in verification block | Proof of existence before any dispute |
| Public verifier, no wallet needed | Zero barrier for journalists and courts |
| No file uploaded anywhere | Only the hash is public — file stays private |

> *"TruthMark doesn't fight deepfakes with AI. It fights them with cryptographic proof that pre-dates them."*

---

## If Something Goes Wrong

| Problem | Fix |
|---|---|
| Wallet won't connect | Use Public Hash Verifier only — paste a pre-notarized hash |
| RPC timeout | Reload and retry verify — it's read-only |
| TX fails | Show the entry card with a real tx hash you pre-notarized |

**Pro tip:** Notarize a hash the night before. Keep that tx hash ready. The public verifier with a real on-chain record is your strongest moment anyway.
