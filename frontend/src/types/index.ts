import { z } from 'zod'

export const contentTypeSchema = z.enum(['video', 'audio', 'image', 'document', 'statement'])
export type ContentType = z.infer<typeof contentTypeSchema>

export const hexHashSchema = z
  .string()
  .regex(/^0x[\da-fA-F]{64}$/, 'Must be a 0x-prefixed 64-hex-character hash (66 chars total)')

export type VaultEntry = {
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
  contentType?: ContentType
}

export type VaultPayload = {
  version: 1
  entries: VaultEntry[]
}

export type EncryptedVaultEnvelope = {
  version: 1
  iterations: number
  salt: string
  iv: string
  ciphertext: string
  updatedAt: string
}

export type PendingConsent = {
  title: string
  details: string[]
  run: () => Promise<void>
}

export type VerificationRecord = {
  submitter: string
  timestamp: number
  label: string
}

export type VerificationResult = {
  checkedAt: string
  records: VerificationRecord[]
}
