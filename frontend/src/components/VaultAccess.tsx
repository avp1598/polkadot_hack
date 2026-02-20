import { motion } from 'framer-motion'
import { LockKeyhole, KeyRound } from 'lucide-react'
import type { ChangeEvent } from 'react'

interface VaultAccessProps {
  hasEncryptedVault: boolean
  unlockPassphrase: string
  setUnlockPassphrase: (value: string) => void
  createPassphrase: string
  setCreatePassphrase: (value: string) => void
  confirmCreatePassphrase: string
  setConfirmCreatePassphrase: (value: string) => void
  isBusy: boolean
  onUnlockVault: () => void
  onCreateVault: () => void
  onImportVault: (e: ChangeEvent<HTMLInputElement>) => void
}

export function VaultAccess({
  hasEncryptedVault,
  unlockPassphrase,
  setUnlockPassphrase,
  createPassphrase,
  setCreatePassphrase,
  confirmCreatePassphrase,
  setConfirmCreatePassphrase,
  isBusy,
  onUnlockVault,
  onCreateVault,
  onImportVault,
}: VaultAccessProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-md mx-auto mt-16 p-6 sm:p-8 rounded-2xl bg-zinc-900 border border-white/10 shadow-2xl"
    >
      <div className="flex justify-center mb-6">
        <div className="p-4 bg-emerald-500/10 rounded-full">
          {hasEncryptedVault ? (
            <KeyRound className="w-8 h-8 text-emerald-400" />
          ) : (
            <LockKeyhole className="w-8 h-8 text-emerald-400" />
          )}
        </div>
      </div>

      <div className="text-center mb-8">
        <h2 className="text-2xl font-serif text-zinc-100 mb-2">
          {hasEncryptedVault ? 'Unlock Secure Vault' : 'Create Secure Vault'}
        </h2>
        <p className="text-sm text-zinc-400">
          Files are encrypted locally with AES-GCM. Nothing leaves your machine.
        </p>
      </div>

      {hasEncryptedVault ? (
        <div className="space-y-4">
          <div className="space-y-1">
            <label className="text-xs font-mono uppercase tracking-wider text-zinc-500">Passphrase</label>
            <input
              type="password"
              value={unlockPassphrase}
              onChange={(e) => setUnlockPassphrase(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && onUnlockVault()}
              placeholder="Enter your vault passphrase"
              className="w-full px-4 py-3 bg-zinc-950 border border-white/10 rounded-lg focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/50 transition-all font-mono text-zinc-100"
            />
          </div>
          <button
            onClick={onUnlockVault}
            disabled={isBusy || !unlockPassphrase}
            className="w-full py-3 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-lg font-medium hover:bg-emerald-500/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isBusy ? 'Unlocking...' : 'Unlock Vault'}
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="space-y-1">
            <label className="text-xs font-mono uppercase tracking-wider text-zinc-500">Create Passphrase</label>
            <input
              type="password"
              value={createPassphrase}
              onChange={(e) => setCreatePassphrase(e.target.value)}
              placeholder="At least 8 characters"
              className="w-full px-4 py-3 bg-zinc-950 border border-white/10 rounded-lg focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/50 transition-all font-mono text-zinc-100"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-mono uppercase tracking-wider text-zinc-500">Confirm Passphrase</label>
            <input
              type="password"
              value={confirmCreatePassphrase}
              onChange={(e) => setConfirmCreatePassphrase(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && onCreateVault()}
              placeholder="Repeat passphrase"
              className="w-full px-4 py-3 bg-zinc-950 border border-white/10 rounded-lg focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/50 transition-all font-mono text-zinc-100"
            />
          </div>
          <button
            onClick={onCreateVault}
            disabled={isBusy || !createPassphrase || !confirmCreatePassphrase}
            className="w-full py-3 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-lg font-medium hover:bg-emerald-500/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isBusy ? 'Creating...' : 'Create Vault'}
          </button>
        </div>
      )}

      <div className="mt-8 text-center">
        <label className="text-sm text-zinc-500 hover:text-zinc-300 cursor-pointer transition-colors underline underline-offset-4 decoration-white/20 hover:decoration-white/50">
          Import Encrypted Vault
          <input type="file" accept="application/json" onChange={onImportVault} className="hidden" />
        </label>
      </div>
    </motion.div>
  )
}
