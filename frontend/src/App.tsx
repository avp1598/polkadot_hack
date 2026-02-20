import { Toaster } from 'sonner'
import { useTruthMark } from './hooks/useTruthMark'
import { Header } from './components/Header'
import { VaultAccess } from './components/VaultAccess'
import { Dashboard } from './components/Dashboard'
import { ConsentModal } from './components/ConsentModal'

export default function App() {
  const truthMark = useTruthMark()

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 font-serif selection:bg-emerald-500/30 font-sans">
      <Toaster 
        theme="dark" 
        position="bottom-right" 
        toastOptions={{
          style: { background: '#09090b', border: '1px solid rgba(255,255,255,0.1)' }
        }} 
      />
      
      {/* Background gradients */}
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        <div className="absolute top-[-20%] left-1/2 -translate-x-1/2 w-[80rem] h-[48rem] bg-[radial-gradient(ellipse_at_top,rgba(16,185,129,0.06)_0%,transparent_70%)]" />
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxmaWx0ZXIgaWQ9Im4iPjxmZVR1cmJ1bGVuY2UgdHlwZT0iZnJhY3RhbE5vaXNlIiBiYXNlRnJlcXVlbmN5PSIwLjY1IiBudW1PY3RhdmVzPSIzIiBzdGl0Y2hUaWxlcz0ic3RpdGNoIi8+PC9maWx0ZXI+PHJlY3Qgd2lkdGg9IjEwMCUiIGhlaWdodD0iMTAwJSIgZmlsdGVyPSJ1cmwoI24pIiBvcGFjaXR5PSIwLjAzIi8+PC9zdmc+')] opacity-20 mix-blend-overlay" />
      </div>

      <Header
        walletAddress={truthMark.walletAddress}
        activeProfileId={truthMark.activeProfileId}
        vaultUnlocked={!!truthMark.vault}
        onConnectWallet={truthMark.connectWallet}
        onDisconnectWallet={truthMark.disconnectWallet}
        onLockVault={truthMark.lockVault}
      />

      <main className="relative z-10 max-w-5xl mx-auto px-4 sm:px-6 py-12">
        <div className="text-center mb-16 animate-in fade-in slide-in-from-bottom-4 duration-700">
          <p className="text-xs font-mono uppercase tracking-widest text-zinc-500 mb-4">AI Content Provenance</p>
          <h1 className="text-5xl sm:text-7xl font-serif text-zinc-100 mb-6 tracking-tight">TruthMark</h1>
          <p className="text-lg text-zinc-400 max-w-2xl mx-auto leading-relaxed">
            Pre-notarize authentic video, audio, images, and statements on Polkadot.
            If a deepfake surfaces, the on-chain timestamp proves the real content existed first.
          </p>
        </div>

        {!truthMark.vault ? (
          <VaultAccess 
            hasEncryptedVault={truthMark.hasEncryptedVault}
            unlockPassphrase={truthMark.unlockPassphrase}
            setUnlockPassphrase={truthMark.setUnlockPassphrase}
            createPassphrase={truthMark.createPassphrase}
            setCreatePassphrase={truthMark.setCreatePassphrase}
            confirmCreatePassphrase={truthMark.confirmCreatePassphrase}
            setConfirmCreatePassphrase={truthMark.setConfirmCreatePassphrase}
            isBusy={truthMark.isBusy}
            onUnlockVault={truthMark.unlockVault}
            onCreateVault={truthMark.createVault}
            onImportVault={truthMark.importVault}
          />
        ) : (
          <Dashboard 
            vault={truthMark.vault}
            isBusy={truthMark.isBusy}
            contentTypeInput={truthMark.contentTypeInput}
            setContentTypeInput={truthMark.setContentTypeInput}
            selectedFile={truthMark.selectedFile}
            setSelectedFile={truthMark.setSelectedFile}
            labelInput={truthMark.labelInput}
            setLabelInput={truthMark.setLabelInput}
            onAddEntry={truthMark.addEntry}
            verificationMap={truthMark.verificationMap}
            copiedEntryId={truthMark.copiedEntryId}
            onVerifyEntry={truthMark.verifyEntry}
            onNotarizeEntry={truthMark.notarizeEntry}
            onRemoveEntry={truthMark.removeEntry}
            onCopyHash={truthMark.copyHash}
            onDownloadEntry={truthMark.downloadEntry}
            publicVerifierHash={truthMark.publicVerifierHash}
            setPublicVerifierHash={truthMark.setPublicVerifierHash}
            isPublicVerifying={truthMark.isPublicVerifying}
            onVerifyPublicHash={truthMark.verifyPublicHash}
            publicVerifierResult={truthMark.publicVerifierResult}
          />
        )}
      </main>

      <ConsentModal 
        pendingConsent={truthMark.pendingConsent}
        isConsentBusy={truthMark.isConsentBusy}
        onApprove={truthMark.approveConsent}
        onDecline={truthMark.declineConsent}
      />
    </div>
  )
}
