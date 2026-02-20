import { useState, type ChangeEvent } from 'react'
import { BrowserProvider, JsonRpcProvider } from 'ethers'
import { toast } from 'sonner'
import {
  GUEST_PROFILE_ID,
  POLKADOT_HUB_TESTNET,
  CONSENT_VAULT_REGISTRY_ADDRESS,
} from '../constants'
import type {
  VaultPayload,
  PendingConsent,
  VerificationResult,
  ContentType,
  VaultEntry,
  VerificationRecord,
} from '../types'
import {
  getStorageKey,
  encryptVault,
  decryptVault,
  isValidEnvelope,
  hashFileContents,
  bytesToBase64,
  base64ToBytes,
  toArrayBuffer,
  saveFile,
  getEthereumProvider,
  tryPromptAccountSelection,
  ensureHubNetwork,
  withTimeout,
  normalizeProfileId,
  getRegistryContract,
} from '../utils'
import { hexHashSchema } from '../types'

export function useTruthMark() {
  const [vault, setVault] = useState<VaultPayload | null>(null)
  const [sessionPassphrase, setSessionPassphrase] = useState('')
  const [unlockPassphrase, setUnlockPassphrase] = useState('')
  const [createPassphrase, setCreatePassphrase] = useState('')
  const [confirmCreatePassphrase, setConfirmCreatePassphrase] = useState('')
  const [isBusy, setIsBusy] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [labelInput, setLabelInput] = useState('')
  const [contentTypeInput, setContentTypeInput] = useState<ContentType>('document')
  const [pendingConsent, setPendingConsent] = useState<PendingConsent | null>(null)
  const [isConsentBusy, setIsConsentBusy] = useState(false)
  const [walletAddress, setWalletAddress] = useState<string | null>(null)
  const [activeProfileId, setActiveProfileId] = useState<string>(GUEST_PROFILE_ID)
  const [verificationMap, setVerificationMap] = useState<Record<string, VerificationResult>>({})
  const [hasEncryptedVault, setHasEncryptedVault] = useState(
    () => localStorage.getItem(getStorageKey(GUEST_PROFILE_ID)) !== null,
  )
  const [publicVerifierHash, setPublicVerifierHash] = useState('')
  const [publicVerifierResult, setPublicVerifierResult] = useState<VerificationResult | null>(null)
  const [isPublicVerifying, setIsPublicVerifying] = useState(false)
  const [copiedEntryId, setCopiedEntryId] = useState<string | null>(null)

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
    toast.info(message, {
      description: hasVault
        ? 'Vault found for this profile. Unlock it with that profile passphrase.'
        : 'No vault for this profile yet. Create one.',
    })
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
    toast.success('Vault locked', {
      description: 'Data remains encrypted at rest.',
    })
  }

  const createVault = async (): Promise<void> => {
    if (!createPassphrase || createPassphrase.length < 8) {
      toast.error('Choose a passphrase with at least 8 characters.')
      return
    }
    if (createPassphrase !== confirmCreatePassphrase) {
      toast.error('Passphrases do not match.')
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
      toast.success('Vault created and unlocked', {
        description: 'Nothing leaves your machine by default.',
      })
    } catch (error) {
      toast.error('Vault creation failed', {
        description: error instanceof Error ? error.message : 'Unknown error',
      })
    } finally {
      setIsBusy(false)
    }
  }

  const unlockVault = async (): Promise<void> => {
    const rawEncrypted = localStorage.getItem(activeStorageKey)
    if (!rawEncrypted) {
      toast.error('No encrypted vault found. Create one first.')
      return
    }
    if (!unlockPassphrase) {
      toast.error('Enter your passphrase to unlock.')
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
      toast.success('Vault unlocked', {
        description: `${decrypted.entries.length} item(s) loaded locally.`,
      })
    } catch (error) {
      toast.error('Unlock failed', {
        description: error instanceof Error ? error.message : 'Unknown error',
      })
    } finally {
      setIsBusy(false)
    }
  }

  const addEntry = async (): Promise<void> => {
    if (!vault) {
      toast.error('Unlock the vault first.')
      return
    }
    if (!selectedFile) {
      toast.error('Select a file to add to your vault.')
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
        contentType: contentTypeInput,
      }

      const nextVault: VaultPayload = {
        ...vault,
        entries: [entry, ...vault.entries],
      }
      await persistVault(nextVault)
      setSelectedFile(null)
      setLabelInput('')
      setContentTypeInput('document')
      toast.success('Saved locally', {
        description: `"${entry.label}" is ready for optional notarization. Hash: ${entry.hashHex.slice(0, 12)}...`,
      })
    } catch (error) {
      toast.error('Unable to save file locally', {
        description: error instanceof Error ? error.message : 'Unknown error',
      })
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
      toast.success('Entry removed from local encrypted vault.')
    } catch (error) {
      toast.error('Unable to delete entry', {
        description: error instanceof Error ? error.message : 'Unknown error',
      })
    } finally {
      setIsBusy(false)
    }
  }

  const exportVault = (): void => {
    const rawEncrypted = localStorage.getItem(activeStorageKey)
    if (!rawEncrypted) {
      toast.error('No vault data to export.')
      return
    }
    saveFile(
      `consent-vault-export-${new Date().toISOString().slice(0, 19)}.json`,
      rawEncrypted,
      'application/json',
    )
    toast.success('Exported encrypted vault JSON', {
      description: 'It remains unreadable without your passphrase.',
    })
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
      toast.success('Encrypted vault imported', {
        description: 'Unlock it with its passphrase.',
      })
    } catch (error) {
      toast.error('Import failed', {
        description: error instanceof Error ? error.message : 'Unknown error',
      })
    } finally {
      event.target.value = ''
      setIsBusy(false)
    }
  }

  const requestConsent = (request: PendingConsent): void => {
    if (isConsentBusy) {
      toast.warning('Please finish the current external action first.')
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
    toast.loading('Executing approved external action...', { id: 'consent-action' })
    void (async () => {
      try {
        await approvedRequest.run()
        toast.dismiss('consent-action')
      } catch (error) {
        toast.error('External action failed', {
          id: 'consent-action',
          description: error instanceof Error ? error.message : 'Unknown error',
        })
      } finally {
        setIsConsentBusy(false)
      }
    })()
  }

  const declineConsent = (): void => {
    setPendingConsent(null)
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
        toast.loading('Waiting for wallet account approval...', { id: 'wallet-connect' })
        await withTimeout(
          browserProvider.send('eth_requestAccounts', []),
          'Wallet connect request timed out. Check your wallet pop-up.',
        )
        toast.loading('Ensuring Polkadot Hub TestNet in wallet...', { id: 'wallet-connect' })
        await ensureHubNetwork(ethereum)
        const signer = await browserProvider.getSigner()
        const address = await signer.getAddress()
        setWalletAddress(address)
        const profileId = normalizeProfileId(address)
        toast.dismiss('wallet-connect')
        if (profileId === activeProfileId) {
          setHasEncryptedVault(localStorage.getItem(getStorageKey(profileId)) !== null)
          toast.success(`Wallet connected: ${address}`)
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
        toast.info(`Transaction submitted`, { description: tx.hash })
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
        toast.success(`Notarized ${entry.label}`, {
          description: `Final tx hash: ${receipt?.hash ?? tx.hash}`,
        })
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

        if (records.length > 0) {
          toast.success(`Verification passed`, {
            description: `${records.length} notarization record(s) found.`,
          })
        } else {
          toast.warning('No notarization records found for this hash yet.')
        }
      },
    })
  }

  const verifyPublicHash = async (): Promise<void> => {
    const parseResult = hexHashSchema.safeParse(publicVerifierHash.trim())
    if (!parseResult.success) {
      toast.error(`Invalid hash: ${parseResult.error.issues[0]?.message ?? 'Invalid format'}`)
      return
    }

    setIsPublicVerifying(true)
    try {
      const provider = new JsonRpcProvider(POLKADOT_HUB_TESTNET.rpcUrl, {
        chainId: POLKADOT_HUB_TESTNET.chainId,
        name: POLKADOT_HUB_TESTNET.name,
      })

      const registry = getRegistryContract(CONSENT_VAULT_REGISTRY_ADDRESS, provider)
      const recordsRaw = await registry.getRecords(parseResult.data)
      const records: VerificationRecord[] = recordsRaw.map(
        (record: { submitter: string; timestamp: bigint; label: string }) => ({
          submitter: record.submitter,
          timestamp: Number(record.timestamp),
          label: record.label,
        }),
      )

      setPublicVerifierResult({
        checkedAt: new Date().toISOString(),
        records,
      })

      if (records.length > 0) {
        toast.success(`Public verification`, {
          description: `${records.length} record(s) found on-chain.`,
        })
      } else {
        toast.warning('Public verification', {
          description: 'No on-chain records found for this hash.',
        })
      }
    } catch (error) {
      toast.error('Verification failed', {
        description: error instanceof Error ? error.message : 'Unknown error',
      })
    } finally {
      setIsPublicVerifying(false)
    }
  }

  const copyHash = (entry: VaultEntry): void => {
    void navigator.clipboard.writeText(entry.hashHex)
    setCopiedEntryId(entry.id)
    setTimeout(() => setCopiedEntryId(null), 2000)
    toast.success('Copied to clipboard')
  }

  const downloadEntry = (entry: VaultEntry): void => {
    saveFile(
      entry.originalFilename,
      toArrayBuffer(base64ToBytes(entry.contentBase64)),
      entry.mimeType,
    )
    toast.success(`Downloaded local copy of ${entry.originalFilename}.`)
  }

  return {
    vault,
    sessionPassphrase,
    unlockPassphrase,
    setUnlockPassphrase,
    createPassphrase,
    setCreatePassphrase,
    confirmCreatePassphrase,
    setConfirmCreatePassphrase,
    isBusy,
    selectedFile,
    setSelectedFile,
    labelInput,
    setLabelInput,
    contentTypeInput,
    setContentTypeInput,
    pendingConsent,
    isConsentBusy,
    walletAddress,
    activeProfileId,
    verificationMap,
    hasEncryptedVault,
    publicVerifierHash,
    setPublicVerifierHash,
    publicVerifierResult,
    isPublicVerifying,
    copiedEntryId,
    
    lockVault,
    createVault,
    unlockVault,
    addEntry,
    removeEntry,
    exportVault,
    importVault,
    disconnectWallet,
    approveConsent,
    declineConsent,
    connectWallet,
    notarizeEntry,
    verifyEntry,
    verifyPublicHash,
    copyHash,
    downloadEntry,
  }
}
