import { type ChangeEvent, useState } from 'react'
import {
  BrowserProvider,
  Contract,
  JsonRpcProvider,
  type ContractRunner,
  type Eip1193Provider,
} from 'ethers'

const STORAGE_KEY_PREFIX = 'consent-vault.encrypted-v1'
const GUEST_PROFILE_ID = 'guest'
const PBKDF2_ITERATIONS = 240_000
const CONSENT_VAULT_REGISTRY_ADDRESS = '0x6D438d562900Fd8e71950776F70DAE52e850306C'
const WALLET_CALL_TIMEOUT_MS = 30_000

const POLKADOT_HUB_TESTNET = {
  name: 'polkadot-hub-testnet',
  chainId: 420420417,
  chainIdHex: '0x190f1b41',
  rpcUrl: 'https://services.polkadothub-rpc.com/testnet',
  blockExplorerUrl: 'https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fpas-rpc.stakeworld.io%2Fassethub#/explorer',
}

const CONSENT_VAULT_ABI = [
  'event HashNotarized(bytes32 indexed hash, address indexed submitter, uint64 timestamp, string label)',
  'function notarize(bytes32 hash, string calldata label) external',
  'function getRecords(bytes32 hash) external view returns ((address submitter, uint64 timestamp, string label)[])',
  'function isNotarized(bytes32 hash) external view returns (bool)',
] as const

type VaultEntry = {
  id: string
  label: string
  originalFilename: string
  mimeType: string
  byteSize: number
  hashHex: string
  notes: string
  contentBase64: string
  createdAt: string
  lastNotarizedTx?: string
  lastNotarizedAt?: string
}

type VaultPayload = {
  version: 1
  entries: VaultEntry[]
}

type EncryptedVaultEnvelope = {
  version: 1
  iterations: number
  salt: string
  iv: string
  ciphertext: string
  updatedAt: string
}

type PendingConsent = {
  title: string
  details: string[]
  run: () => Promise<void>
}

type VerificationRecord = {
  submitter: string
  timestamp: number
  label: string
}

type VerificationResult = {
  checkedAt: string
  records: VerificationRecord[]
}

declare global {
  interface Window {
    ethereum?: Eip1193Provider
  }
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

const bytesToBase64 = (bytes: Uint8Array): string => {
  let binary = ''
  const block = 0x8000
  for (let index = 0; index < bytes.length; index += block) {
    binary += String.fromCharCode(...bytes.subarray(index, index + block))
  }
  return btoa(binary)
}

const base64ToBytes = (base64: string): Uint8Array => {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes
}

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

const toHex = (bytes: Uint8Array): string =>
  `0x${Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`

const formatBytes = (value: number): string => {
  if (value < 1024) return `${value} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / 1024 ** 2).toFixed(2)} MB`
}

const formatDateTime = (isoDate: string): string =>
  new Date(isoDate).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })

const normalizeProfileId = (address: string | null): string =>
  address ? address.toLowerCase() : GUEST_PROFILE_ID

const getStorageKey = (profileId: string): string =>
  `${STORAGE_KEY_PREFIX}:${profileId}`

const deriveAesKey = async (
  passphrase: string,
  salt: Uint8Array,
): Promise<CryptoKey> => {
  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  )

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toArrayBuffer(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    passphraseKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt'],
  )
}

const encryptVault = async (
  payload: VaultPayload,
  passphrase: string,
): Promise<EncryptedVaultEnvelope> => {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveAesKey(passphrase, salt)
  const plaintext = encoder.encode(JSON.stringify(payload))
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    key,
    plaintext,
  )

  return {
    version: 1,
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertextBuffer)),
    updatedAt: new Date().toISOString(),
  }
}

const decryptVault = async (
  envelope: EncryptedVaultEnvelope,
  passphrase: string,
): Promise<VaultPayload> => {
  const salt = base64ToBytes(envelope.salt)
  const iv = base64ToBytes(envelope.iv)
  const ciphertext = base64ToBytes(envelope.ciphertext)
  const key = await deriveAesKey(passphrase, salt)

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(ciphertext),
  )

  const parsed = JSON.parse(decoder.decode(plaintext)) as VaultPayload
  if (parsed.version !== 1 || !Array.isArray(parsed.entries)) {
    throw new Error('Encrypted vault has an unsupported format.')
  }
  return parsed
}

const hashFileContents = async (contents: ArrayBuffer): Promise<string> => {
  const digest = await crypto.subtle.digest('SHA-256', contents)
  return toHex(new Uint8Array(digest))
}

const saveFile = (fileName: string, content: BlobPart, mimeType: string): void => {
  const blob = new Blob([content], { type: mimeType })
  const objectUrl = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = objectUrl
  anchor.download = fileName
  document.body.append(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(objectUrl)
}

const isValidEnvelope = (value: unknown): value is EncryptedVaultEnvelope => {
  if (typeof value !== 'object' || value === null) return false
  const candidate = value as Partial<EncryptedVaultEnvelope>
  return (
    candidate.version === 1 &&
    typeof candidate.salt === 'string' &&
    typeof candidate.iv === 'string' &&
    typeof candidate.ciphertext === 'string'
  )
}

const withTimeout = async <T,>(
  promise: Promise<T>,
  timeoutMessage: string,
  timeoutMs = WALLET_CALL_TIMEOUT_MS,
): Promise<T> => {
  let timeoutId: number | null = null

  const timeoutPromise = new Promise<T>((_, reject) => {
    timeoutId = window.setTimeout(() => {
      reject(new Error(timeoutMessage))
    }, timeoutMs)
  })

  try {
    return await Promise.race([promise, timeoutPromise])
  } finally {
    if (timeoutId !== null) {
      window.clearTimeout(timeoutId)
    }
  }
}

const getProviderErrorCode = (error: unknown): number | null => {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = (error as { code?: unknown }).code
    if (typeof code === 'number') {
      return code
    }
  }
  return null
}

const tryPromptAccountSelection = async (
  ethereum: Eip1193Provider,
): Promise<void> => {
  try {
    await withTimeout(
      ethereum.request({
        method: 'wallet_requestPermissions',
        params: [{ eth_accounts: {} }],
      }),
      'Timed out while opening wallet account permissions.',
      15_000,
    )
  } catch (error) {
    const code = getProviderErrorCode(error)
    // Unsupported method or user skip: continue with eth_requestAccounts fallback.
    if (code === -32601 || code === 4001) {
      return
    }
  }
}

const ensureHubNetwork = async (ethereum: Eip1193Provider): Promise<void> => {
  try {
    await withTimeout(
      ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: POLKADOT_HUB_TESTNET.chainIdHex }],
      }),
      'Timed out while switching wallet network.',
    )
  } catch (switchError) {
    const code = getProviderErrorCode(switchError)
    const switchMessage =
      switchError instanceof Error ? switchError.message.toLowerCase() : ''
    const shouldTryAddChain =
      code === 4902 ||
      switchMessage.includes('unrecognized chain') ||
      switchMessage.includes('unknown chain')

    if (!shouldTryAddChain) {
      throw switchError
    }

    await withTimeout(
      ethereum.request({
        method: 'wallet_addEthereumChain',
        params: [
          {
            chainId: POLKADOT_HUB_TESTNET.chainIdHex,
            chainName: POLKADOT_HUB_TESTNET.name,
            rpcUrls: [POLKADOT_HUB_TESTNET.rpcUrl],
            nativeCurrency: {
              name: 'DOT',
              symbol: 'DOT',
              decimals: 18,
            },
            blockExplorerUrls: [POLKADOT_HUB_TESTNET.blockExplorerUrl],
          },
        ],
      }),
      'Timed out while adding Polkadot Hub TestNet to wallet.',
    )
  }
}

const getEthereumProvider = (): Eip1193Provider => {
  if (!window.ethereum) {
    throw new Error('No injected wallet found. Install MetaMask, SubWallet, or Talisman.')
  }
  return window.ethereum
}

const getRegistryContract = (
  contractAddress: string,
  runner: ContractRunner,
): Contract => new Contract(contractAddress, CONSENT_VAULT_ABI, runner)

function App() {
  const [vault, setVault] = useState<VaultPayload | null>(null)
  const [sessionPassphrase, setSessionPassphrase] = useState('')
  const [unlockPassphrase, setUnlockPassphrase] = useState('')
  const [createPassphrase, setCreatePassphrase] = useState('')
  const [confirmCreatePassphrase, setConfirmCreatePassphrase] = useState('')
  const [statusMessage, setStatusMessage] = useState('Vault is locked.')
  const [isBusy, setIsBusy] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [labelInput, setLabelInput] = useState('')
  const [pendingConsent, setPendingConsent] = useState<PendingConsent | null>(null)
  const [isConsentBusy, setIsConsentBusy] = useState(false)
  const [walletAddress, setWalletAddress] = useState<string | null>(null)
  const [activeProfileId, setActiveProfileId] = useState<string>(GUEST_PROFILE_ID)
  const [verificationMap, setVerificationMap] = useState<
    Record<string, VerificationResult>
  >({})
  const [hasEncryptedVault, setHasEncryptedVault] = useState(
    () => localStorage.getItem(getStorageKey(GUEST_PROFILE_ID)) !== null,
  )
  const activeStorageKey = getStorageKey(activeProfileId)

  const resetUnlockedSession = (): void => {
    setVault(null)
    setSessionPassphrase('')
    setUnlockPassphrase('')
    setVerificationMap({})
  }

  const switchProfile = (profileId: string, message: string): void => {
    const storageKey = getStorageKey(profileId)
    const hasVault = localStorage.getItem(storageKey) !== null
    setActiveProfileId(profileId)
    resetUnlockedSession()
    setHasEncryptedVault(hasVault)
    setStatusMessage(
      `${message} ${
        hasVault
          ? 'Vault found for this profile. Unlock it with that profile passphrase.'
          : 'No vault for this profile yet. Create one.'
      }`,
    )
  }

  const persistVault = async (nextVault: VaultPayload): Promise<void> => {
    if (!sessionPassphrase) {
      throw new Error('Vault is locked. Unlock it before saving.')
    }
    const encrypted = await encryptVault(nextVault, sessionPassphrase)
    localStorage.setItem(activeStorageKey, JSON.stringify(encrypted))
    setHasEncryptedVault(true)
    setVault(nextVault)
  }

  const lockVault = (): void => {
    resetUnlockedSession()
    setHasEncryptedVault(localStorage.getItem(activeStorageKey) !== null)
    setStatusMessage('Vault locked. Data remains encrypted at rest.')
  }

  const createVault = async (): Promise<void> => {
    if (!createPassphrase || createPassphrase.length < 8) {
      setStatusMessage('Choose a passphrase with at least 8 characters.')
      return
    }
    if (createPassphrase !== confirmCreatePassphrase) {
      setStatusMessage('Passphrases do not match.')
      return
    }

    setIsBusy(true)
    try {
      const freshVault: VaultPayload = { version: 1, entries: [] }
      const encrypted = await encryptVault(freshVault, createPassphrase)
      localStorage.setItem(activeStorageKey, JSON.stringify(encrypted))
      setVault(freshVault)
      setHasEncryptedVault(true)
      setSessionPassphrase(createPassphrase)
      setCreatePassphrase('')
      setConfirmCreatePassphrase('')
      setStatusMessage('Vault created and unlocked. Nothing leaves your machine by default.')
    } catch (error) {
      setStatusMessage(
        `Vault creation failed: ${
          error instanceof Error ? error.message : 'Unknown error'
        }`,
      )
    } finally {
      setIsBusy(false)
    }
  }

  const unlockVault = async (): Promise<void> => {
    const rawEncrypted = localStorage.getItem(activeStorageKey)
    if (!rawEncrypted) {
      setStatusMessage('No encrypted vault found. Create one first.')
      return
    }
    if (!unlockPassphrase) {
      setStatusMessage('Enter your passphrase to unlock.')
      return
    }

    setIsBusy(true)
    try {
      const parsed = JSON.parse(rawEncrypted) as unknown
      if (!isValidEnvelope(parsed)) {
        throw new Error('Stored vault format is invalid.')
      }
      const decrypted = await decryptVault(parsed, unlockPassphrase)
      setVault(decrypted)
      setSessionPassphrase(unlockPassphrase)
      setUnlockPassphrase('')
      setStatusMessage(`Vault unlocked. ${decrypted.entries.length} item(s) loaded locally.`)
    } catch (error) {
      setStatusMessage(
        `Unlock failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      )
    } finally {
      setIsBusy(false)
    }
  }

  const addEntry = async (): Promise<void> => {
    if (!vault) {
      setStatusMessage('Unlock the vault first.')
      return
    }
    if (!selectedFile) {
      setStatusMessage('Select a file to add to your vault.')
      return
    }

    setIsBusy(true)
    try {
      const contents = await selectedFile.arrayBuffer()
      const contentBytes = new Uint8Array(contents)
      const entry: VaultEntry = {
        id: crypto.randomUUID(),
        label: labelInput.trim() || selectedFile.name,
        originalFilename: selectedFile.name,
        mimeType: selectedFile.type || 'application/octet-stream',
        byteSize: selectedFile.size,
        hashHex: await hashFileContents(contents),
        notes: '',
        contentBase64: bytesToBase64(contentBytes),
        createdAt: new Date().toISOString(),
      }

      const nextVault: VaultPayload = {
        ...vault,
        entries: [entry, ...vault.entries],
      }
      await persistVault(nextVault)
      setSelectedFile(null)
      setLabelInput('')
      setStatusMessage(
        `Saved "${entry.label}" locally. Hash ${entry.hashHex.slice(0, 12)}... is ready for optional notarization.`,
      )
    } catch (error) {
      setStatusMessage(
        `Unable to save file locally: ${
          error instanceof Error ? error.message : 'Unknown error'
        }`,
      )
    } finally {
      setIsBusy(false)
    }
  }

  const removeEntry = async (entryId: string): Promise<void> => {
    if (!vault) return
    const nextVault: VaultPayload = {
      ...vault,
      entries: vault.entries.filter((entry) => entry.id !== entryId),
    }
    setIsBusy(true)
    try {
      await persistVault(nextVault)
      setStatusMessage('Entry removed from local encrypted vault.')
    } catch (error) {
      setStatusMessage(
        `Unable to delete entry: ${
          error instanceof Error ? error.message : 'Unknown error'
        }`,
      )
    } finally {
      setIsBusy(false)
    }
  }

  const exportVault = (): void => {
    const rawEncrypted = localStorage.getItem(activeStorageKey)
    if (!rawEncrypted) {
      setStatusMessage('No vault data to export.')
      return
    }
    saveFile(
      `consent-vault-export-${new Date().toISOString().slice(0, 19)}.json`,
      rawEncrypted,
      'application/json',
    )
    setStatusMessage('Exported encrypted vault JSON. It remains unreadable without your passphrase.')
  }

  const importVault = async (event: ChangeEvent<HTMLInputElement>): Promise<void> => {
    const file = event.target.files?.[0]
    if (!file) return

    setIsBusy(true)
    try {
      const rawText = await file.text()
      const parsed = JSON.parse(rawText) as unknown
      if (!isValidEnvelope(parsed)) {
        throw new Error('Imported file is not a valid encrypted vault export.')
      }
      localStorage.setItem(activeStorageKey, JSON.stringify(parsed))
      setHasEncryptedVault(true)
      resetUnlockedSession()
      setStatusMessage('Encrypted vault imported. Unlock it with its passphrase.')
    } catch (error) {
      setStatusMessage(
        `Import failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      )
    } finally {
      event.target.value = ''
      setIsBusy(false)
    }
  }

  const requestConsent = (request: PendingConsent): void => {
    if (isConsentBusy) {
      setStatusMessage('Please finish the current external action first.')
      return
    }
    setPendingConsent(request)
  }

  const disconnectWallet = (): void => {
    if (!walletAddress) return
    setWalletAddress(null)
    switchProfile(
      GUEST_PROFILE_ID,
      'Wallet disconnected. Switched to guest vault profile.',
    )
  }

  const approveConsent = (): void => {
    if (!pendingConsent || isConsentBusy) return
    const approvedRequest = pendingConsent
    setPendingConsent(null)
    setIsConsentBusy(true)
    setStatusMessage('Executing approved external action...')
    void (async () => {
      try {
        await approvedRequest.run()
      } catch (error) {
        setStatusMessage(
          `External action failed: ${
            error instanceof Error ? error.message : 'Unknown error'
          }`,
        )
      } finally {
        setIsConsentBusy(false)
      }
    })()
  }

  const connectWallet = (): void => {
    requestConsent({
      title: 'Connect your wallet',
      details: [
        'Request account access from your wallet extension.',
        'Switch to Polkadot Hub TestNet (chainId 420420417).',
        'No local file contents will be sent.',
      ],
      run: async () => {
        const ethereum = getEthereumProvider()
        const browserProvider = new BrowserProvider(ethereum)
        await tryPromptAccountSelection(ethereum)
        setStatusMessage('Waiting for wallet account approval...')
        await withTimeout(
          browserProvider.send('eth_requestAccounts', []),
          'Wallet connect request timed out. Check your wallet pop-up.',
        )
        setStatusMessage('Ensuring Polkadot Hub TestNet in wallet...')
        await ensureHubNetwork(ethereum)
        const signer = await browserProvider.getSigner()
        const address = await signer.getAddress()
        setWalletAddress(address)
        const profileId = normalizeProfileId(address)
        if (profileId === activeProfileId) {
          setHasEncryptedVault(localStorage.getItem(getStorageKey(profileId)) !== null)
          setStatusMessage(`Wallet connected: ${address}`)
          return
        }
        switchProfile(profileId, `Wallet connected: ${address}. Switched to wallet vault profile.`)
      },
    })
  }

  const notarizeEntry = (entry: VaultEntry): void => {
    requestConsent({
      title: 'Notarize file hash on Polkadot Hub',
      details: [
        `Hash to send: ${entry.hashHex}`,
        `Label to send: ${entry.label}`,
        'This creates an on-chain transaction signed by your wallet.',
      ],
      run: async () => {
        if (!vault) throw new Error('Unlock the vault first.')

        const ethereum = getEthereumProvider()
        await ensureHubNetwork(ethereum)
        const browserProvider = new BrowserProvider(ethereum)
        const signer = await browserProvider.getSigner()

        const registry = getRegistryContract(CONSENT_VAULT_REGISTRY_ADDRESS, signer)
        const tx = await registry.notarize(entry.hashHex, entry.label)
        setStatusMessage(`Transaction submitted: ${tx.hash}`)
        const receipt = await tx.wait()

        const nextVault: VaultPayload = {
          ...vault,
          entries: vault.entries.map((candidate) =>
            candidate.id === entry.id
              ? {
                  ...candidate,
                  lastNotarizedTx: receipt?.hash ?? tx.hash,
                  lastNotarizedAt: new Date().toISOString(),
                }
              : candidate,
          ),
        }
        await persistVault(nextVault)
        setStatusMessage(`Notarized ${entry.label}. Final tx hash: ${receipt?.hash ?? tx.hash}`)
      },
    })
  }

  const verifyEntry = (entry: VaultEntry): void => {
    requestConsent({
      title: 'Verify hash from Polkadot Hub',
      details: [
        `Query hash: ${entry.hashHex}`,
        `Contract: ${CONSENT_VAULT_REGISTRY_ADDRESS}`,
        'This performs a read-only RPC call to Polkadot Hub TestNet.',
      ],
      run: async () => {
        const provider = new JsonRpcProvider(POLKADOT_HUB_TESTNET.rpcUrl, {
          chainId: POLKADOT_HUB_TESTNET.chainId,
          name: POLKADOT_HUB_TESTNET.name,
        })

        const registry = getRegistryContract(CONSENT_VAULT_REGISTRY_ADDRESS, provider)
        const recordsRaw = await registry.getRecords(entry.hashHex)
        const records: VerificationRecord[] = recordsRaw.map(
          (record: { submitter: string; timestamp: bigint; label: string }) => ({
            submitter: record.submitter,
            timestamp: Number(record.timestamp),
            label: record.label,
          }),
        )

        setVerificationMap((previous) => ({
          ...previous,
          [entry.id]: {
            checkedAt: new Date().toISOString(),
            records,
          },
        }))

        setStatusMessage(
          records.length > 0
            ? `Verification passed. ${records.length} notarization record(s) found.`
            : 'No notarization records found for this hash yet.',
        )
      },
    })
  }

  const downloadEntry = (entry: VaultEntry): void => {
    saveFile(
      entry.originalFilename,
      toArrayBuffer(base64ToBytes(entry.contentBase64)),
      entry.mimeType,
    )
    setStatusMessage(`Downloaded local copy of ${entry.originalFilename}.`)
  }

  const renderVaultControls = () => (
    <section className="panel">
      <h2>Vault Access</h2>
      <p className="helper">
        Files are encrypted locally with AES-GCM. We never store passphrases or upload
        documents automatically.
        <br />
        Active profile: <code>{activeProfileId}</code>
      </p>

      {hasEncryptedVault ? (
        <div className="field-grid">
          <label className="field">
            <span>Passphrase</span>
            <input
              type="password"
              value={unlockPassphrase}
              onChange={(event) => setUnlockPassphrase(event.target.value)}
              placeholder="Unlock existing vault"
            />
          </label>
          <button className="btn-strong" disabled={isBusy} onClick={() => void unlockVault()}>
            Unlock Vault
          </button>
        </div>
      ) : (
        <div className="field-grid">
          <label className="field">
            <span>Create passphrase</span>
            <input
              type="password"
              value={createPassphrase}
              onChange={(event) => setCreatePassphrase(event.target.value)}
              placeholder="At least 8 characters"
            />
          </label>
          <label className="field">
            <span>Confirm passphrase</span>
            <input
              type="password"
              value={confirmCreatePassphrase}
              onChange={(event) => setConfirmCreatePassphrase(event.target.value)}
              placeholder="Repeat passphrase"
            />
          </label>
          <button className="btn-strong" disabled={isBusy} onClick={() => void createVault()}>
            Create Vault
          </button>
        </div>
      )}
    </section>
  )

  return (
    <div className="app">
      <div className="background-shape background-shape-one" />
      <div className="background-shape background-shape-two" />

      <header className="hero">
        <p className="eyebrow">PromptOff Prototype · Survival & Security</p>
        <h1>Consent Vault</h1>
        <p className="subtitle">
          Local-first encrypted document vault with explicit consent for every outside
          interaction. Polkadot Hub anchors authenticity with on-chain hash notarization.
        </p>
        <div className="inline-badges">
          <span>Private by default</span>
          <span>User-approved network calls</span>
          <span>Owned and portable</span>
        </div>
      </header>

      <main className="layout">
        <section className="panel status-panel">
          <h2>Runtime Status</h2>
          <p>{statusMessage}</p>
          <p className="helper">
            Registry: <code>{CONSENT_VAULT_REGISTRY_ADDRESS}</code>
            <br />
            Wallet:{' '}
            <strong>{walletAddress ?? 'not connected'}</strong>
            <br />
            Profile: <code>{activeProfileId}</code>
          </p>
          <div className="status-actions">
            <button onClick={connectWallet}>
              {walletAddress ? 'Switch Wallet' : 'Connect Wallet'}
            </button>
            <button onClick={disconnectWallet} disabled={!walletAddress}>
              Disconnect Wallet
            </button>
            <button onClick={lockVault} disabled={!vault}>
              Lock
            </button>
            <button onClick={exportVault} disabled={!vault}>
              Export Encrypted Vault
            </button>
            <label className="import-btn">
              Import Encrypted Vault
              <input type="file" accept="application/json" onChange={(event) => void importVault(event)} />
            </label>
          </div>
        </section>

        {!vault && renderVaultControls()}

        {vault && (
          <>
            <section className="panel">
              <h2>Add Document</h2>
              <p className="helper">
                Wallet: <strong>{walletAddress ?? 'not connected yet'}</strong>
                <br />
                Network: <code>{POLKADOT_HUB_TESTNET.name}</code> (
                <code>{POLKADOT_HUB_TESTNET.chainId}</code>)
              </p>
              <div className="field-grid">
                <label className="field">
                  <span>Choose file</span>
                  <input
                    type="file"
                    onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
                  />
                </label>
                <label className="field">
                  <span>Display label</span>
                  <input
                    type="text"
                    value={labelInput}
                    onChange={(event) => setLabelInput(event.target.value)}
                    placeholder="Vaccination proof, ID, invoice..."
                  />
                </label>
                <button className="btn-strong" disabled={isBusy} onClick={() => void addEntry()}>
                  Save To Vault
                </button>
              </div>
            </section>

            <section className="panel">
              <h2>Vault Entries ({vault.entries.length})</h2>
              {vault.entries.length === 0 ? (
                <p className="helper">No entries yet. Add a document to begin.</p>
              ) : (
                <div className="entry-grid">
                  {vault.entries.map((entry) => {
                    const verification = verificationMap[entry.id]
                    return (
                      <article key={entry.id} className="entry-card">
                        <h3>{entry.label}</h3>
                        <p className="entry-meta">
                          {entry.originalFilename} · {formatBytes(entry.byteSize)} ·{' '}
                          {formatDateTime(entry.createdAt)}
                        </p>
                        <p className="entry-hash">
                          <span>SHA-256</span>
                          <code>{entry.hashHex}</code>
                        </p>
                        {entry.notes ? <p className="entry-notes">{entry.notes}</p> : null}

                        <div className="entry-actions">
                          <button onClick={() => downloadEntry(entry)}>Download Local Copy</button>
                          <button onClick={() => verifyEntry(entry)}>Verify On-Chain</button>
                          <button className="btn-strong" onClick={() => notarizeEntry(entry)}>
                            Notarize Hash
                          </button>
                          <button className="btn-danger" onClick={() => void removeEntry(entry.id)}>
                            Delete
                          </button>
                        </div>

                        {entry.lastNotarizedTx ? (
                          <p className="entry-proof">
                            Last notarized {entry.lastNotarizedAt ? formatDateTime(entry.lastNotarizedAt) : ''}
                            {' · '}
                            <code>{entry.lastNotarizedTx}</code>
                          </p>
                        ) : null}

                        {verification ? (
                          <div className="verification-block">
                            <p>
                              Checked {formatDateTime(verification.checkedAt)} ·{' '}
                              {verification.records.length} record(s)
                            </p>
                            {verification.records.map((record, index) => (
                              <p key={`${record.submitter}-${record.timestamp}-${index}`}>
                                {record.label || '(no label)'} · {record.submitter} ·{' '}
                                {new Date(record.timestamp * 1000).toLocaleString()}
                              </p>
                            ))}
                          </div>
                        ) : null}
                      </article>
                    )
                  })}
                </div>
              )}
            </section>
          </>
        )}
      </main>

      {pendingConsent ? (
        <div className="consent-backdrop">
          <div className="consent-modal">
            <p className="eyebrow">External Interaction Request</p>
            <h3>{pendingConsent.title}</h3>
            <ul>
              {pendingConsent.details.map((detail) => (
                <li key={detail}>{detail}</li>
              ))}
            </ul>
            <div className="consent-actions">
              <button onClick={() => setPendingConsent(null)}>
                Decline
              </button>
              <button
                className="btn-strong"
                onClick={() => void approveConsent()}
                disabled={isConsentBusy}
              >
                Approve Once
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}

export default App
