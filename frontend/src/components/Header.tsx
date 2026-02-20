import { Wallet, LogOut, Lock, Shield } from 'lucide-react'
import { GUEST_PROFILE_ID } from '../constants'

interface HeaderProps {
  walletAddress: string | null
  activeProfileId: string
  vaultUnlocked: boolean
  onConnectWallet: () => void
  onDisconnectWallet: () => void
  onLockVault: () => void
}

export function Header({
  walletAddress,
  activeProfileId,
  vaultUnlocked,
  onConnectWallet,
  onDisconnectWallet,
  onLockVault,
}: HeaderProps) {
  return (
    <header className="sticky top-0 z-40 w-full backdrop-blur-md bg-zinc-950/80 border-b border-white/10">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-emerald-400" />
          <h1 className="font-serif text-xl font-medium tracking-tight text-zinc-100">TruthMark</h1>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 mr-2">
            <span className="text-xs font-mono uppercase tracking-wider text-zinc-500">Profile</span>
            <span className="text-xs font-mono px-2 py-1 rounded-full bg-zinc-800/50 text-zinc-300 border border-white/5">
              {activeProfileId === GUEST_PROFILE_ID ? 'Guest' : `${activeProfileId.slice(0, 6)}...${activeProfileId.slice(-4)}`}
            </span>
          </div>

          {walletAddress ? (
            <button
              onClick={onDisconnectWallet}
              className="flex items-center gap-2 text-sm px-3 py-1.5 rounded-lg border border-white/10 hover:bg-white/5 transition-colors text-zinc-300"
            >
              <LogOut className="w-4 h-4" />
              <span className="hidden sm:inline">Disconnect</span>
            </button>
          ) : (
            <button
              onClick={onConnectWallet}
              className="flex items-center gap-2 text-sm px-3 py-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/20 transition-colors"
            >
              <Wallet className="w-4 h-4" />
              <span>Connect Wallet</span>
            </button>
          )}

          {vaultUnlocked && (
            <button
              onClick={onLockVault}
              className="flex items-center gap-2 text-sm px-3 py-1.5 rounded-lg border border-red-500/20 text-red-400 hover:bg-red-500/10 transition-colors"
            >
              <Lock className="w-4 h-4" />
              <span className="hidden sm:inline">Lock Vault</span>
            </button>
          )}
        </div>
      </div>
    </header>
  )
}
