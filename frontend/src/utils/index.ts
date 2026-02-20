import { Contract, type ContractRunner, type Eip1193Provider } from 'ethers'
import {
  PBKDF2_ITERATIONS,
  GUEST_PROFILE_ID,
  STORAGE_KEY_PREFIX,
  WALLET_CALL_TIMEOUT_MS,
  POLKADOT_HUB_TESTNET,
  CONSENT_VAULT_ABI,
} from '../constants'
import type { EncryptedVaultEnvelope, VaultPayload, ContentType } from '../types'

declare global {
  interface Window {
    ethereum?: Eip1193Provider
  }
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export const bytesToBase64 = (bytes: Uint8Array): string => {
  let binary = ''
  const block = 0x8000
  for (let index = 0; index < bytes.length; index += block) {
    binary += String.fromCharCode(...bytes.subarray(index, index + block))
  }
  return btoa(binary)
}

export const base64ToBytes = (base64: string): Uint8Array => {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes
}

export const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

export const toHex = (bytes: Uint8Array): string =>
  `0x${Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`

export const formatBytes = (value: number): string => {
  if (value < 1024) return `${value} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / 1024 ** 2).toFixed(2)} MB`
}

export const formatDateTime = (isoDate: string): string =>
  new Date(isoDate).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })

export const normalizeProfileId = (address: string | null): string =>
  address ? address.toLowerCase() : GUEST_PROFILE_ID

export const getStorageKey = (profileId: string): string =>
  `${STORAGE_KEY_PREFIX}:${profileId}`

export const deriveAesKey = async (
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

export const encryptVault = async (
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

export const decryptVault = async (
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

export const hashFileContents = async (contents: ArrayBuffer): Promise<string> => {
  const digest = await crypto.subtle.digest('SHA-256', contents)
  return toHex(new Uint8Array(digest))
}

export const saveFile = (fileName: string, content: BlobPart, mimeType: string): void => {
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

export const isValidEnvelope = (value: unknown): value is EncryptedVaultEnvelope => {
  if (typeof value !== 'object' || value === null) return false
  const candidate = value as Partial<EncryptedVaultEnvelope>
  return (
    candidate.version === 1 &&
    typeof candidate.salt === 'string' &&
    typeof candidate.iv === 'string' &&
    typeof candidate.ciphertext === 'string'
  )
}

export const withTimeout = async <T,>(
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

export const getProviderErrorCode = (error: unknown): number | null => {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = (error as { code?: unknown }).code
    if (typeof code === 'number') {
      return code
    }
  }
  return null
}

export const tryPromptAccountSelection = async (
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
    if (code === -32601 || code === 4001) {
      return
    }
  }
}

export const ensureHubNetwork = async (ethereum: Eip1193Provider): Promise<void> => {
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

export const getEthereumProvider = (): Eip1193Provider => {
  if (!window.ethereum) {
    throw new Error('No injected wallet found. Install MetaMask, SubWallet, or Talisman.')
  }
  return window.ethereum
}

export const getRegistryContract = (
  contractAddress: string,
  runner: ContractRunner,
): Contract => new Contract(contractAddress, CONSENT_VAULT_ABI, runner)

export const getContentTypeBadgeClass = (type: ContentType): string => {
  const map: Record<ContentType, string> = {
    video: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
    audio: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
    image: 'bg-green-500/10 text-green-500 border-green-500/20',
    document: 'bg-amber-500/10 text-amber-500 border-amber-500/20',
    statement: 'bg-red-500/10 text-red-500 border-red-500/20',
  }
  return map[type]
}

export function cn(...classes: (string | undefined | null | false)[]) {
  return classes.filter(Boolean).join(' ')
}
