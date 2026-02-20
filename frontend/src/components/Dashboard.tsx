import { motion, AnimatePresence } from 'framer-motion'
import { Plus, Search, FileText, LayoutGrid } from 'lucide-react'
import { EntryCard } from './EntryCard'
import type { VaultPayload, ContentType, VerificationResult, VaultEntry } from '../types'
import { contentTypeSchema } from '../types'
import { POLKADOT_HUB_TESTNET } from '../constants'
import { formatDateTime } from '../utils'

interface DashboardProps {
  vault: VaultPayload
  isBusy: boolean
  contentTypeInput: ContentType
  setContentTypeInput: (val: ContentType) => void
  selectedFile: File | null
  setSelectedFile: (file: File | null) => void
  labelInput: string
  setLabelInput: (val: string) => void
  onAddEntry: () => void
  verificationMap: Record<string, VerificationResult>
  copiedEntryId: string | null
  onVerifyEntry: (entry: VaultEntry) => void
  onNotarizeEntry: (entry: VaultEntry) => void
  onRemoveEntry: (id: string) => void
  onCopyHash: (entry: VaultEntry) => void
  onDownloadEntry: (entry: VaultEntry) => void
  publicVerifierHash: string
  setPublicVerifierHash: (val: string) => void
  isPublicVerifying: boolean
  onVerifyPublicHash: () => void
  publicVerifierResult: VerificationResult | null
}

export function Dashboard({
  vault,
  isBusy,
  contentTypeInput,
  setContentTypeInput,
  selectedFile,
  setSelectedFile,
  labelInput,
  setLabelInput,
  onAddEntry,
  verificationMap,
  copiedEntryId,
  onVerifyEntry,
  onNotarizeEntry,
  onRemoveEntry,
  onCopyHash,
  onDownloadEntry,
  publicVerifierHash,
  setPublicVerifierHash,
  isPublicVerifying,
  onVerifyPublicHash,
  publicVerifierResult,
}: DashboardProps) {
  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700 mt-8">
      {/* Add Document Section */}
      <section className="bg-zinc-900 border border-white/10 rounded-2xl p-6 sm:p-8 relative overflow-hidden">
        <div className="absolute top-0 right-0 p-32 bg-emerald-500/5 rounded-full blur-[100px] pointer-events-none" />
        
        <div className="flex items-center gap-3 mb-6 relative z-10">
          <div className="p-2 bg-zinc-800 rounded-lg">
            <Plus className="w-5 h-5 text-zinc-300" />
          </div>
          <div>
            <h2 className="text-xl font-serif text-zinc-100">Add to Secure Vault</h2>
            <p className="text-sm text-zinc-400 font-mono mt-1">
              Network: <span className="text-emerald-400">{POLKADOT_HUB_TESTNET.name}</span>
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-5 relative z-10">
          <div className="space-y-1.5">
            <label className="text-xs font-mono uppercase tracking-wider text-zinc-500">Content Type</label>
            <select
              value={contentTypeInput}
              onChange={(e) => {
                const parsed = contentTypeSchema.safeParse(e.target.value)
                if (parsed.success) setContentTypeInput(parsed.data)
              }}
              className="w-full px-4 py-2.5 bg-zinc-950 border border-white/10 rounded-lg focus:outline-none focus:border-emerald-500 text-sm text-zinc-300 transition-colors"
            >
              <option value="video">Video</option>
              <option value="audio">Audio</option>
              <option value="image">Image</option>
              <option value="document">Document</option>
              <option value="statement">Statement</option>
            </select>
          </div>
          
          <div className="space-y-1.5">
            <label className="text-xs font-mono uppercase tracking-wider text-zinc-500">Choose File</label>
            <input
              type="file"
              onChange={(e) => setSelectedFile(e.target.files?.[0] ?? null)}
              className="w-full px-4 py-2 bg-zinc-950 border border-white/10 rounded-lg text-sm text-zinc-300 file:mr-4 file:py-1 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-medium file:bg-emerald-500/10 file:text-emerald-400 hover:file:bg-emerald-500/20 cursor-pointer"
            />
          </div>

          <div className="space-y-1.5 sm:col-span-2">
            <label className="text-xs font-mono uppercase tracking-wider text-zinc-500">Display Label</label>
            <input
              type="text"
              value={labelInput}
              onChange={(e) => setLabelInput(e.target.value)}
              placeholder="e.g. Interview footage, press statement..."
              className="w-full px-4 py-2.5 bg-zinc-950 border border-white/10 rounded-lg focus:outline-none focus:border-emerald-500 text-sm text-zinc-300 transition-colors"
            />
          </div>
        </div>

        <div className="mt-6 flex justify-end relative z-10">
          <button
            onClick={onAddEntry}
            disabled={isBusy || !selectedFile}
            className="flex items-center gap-2 px-6 py-2.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-lg font-medium hover:bg-emerald-500/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <FileText className="w-4 h-4" />
            {isBusy ? 'Saving...' : 'Save to Vault'}
          </button>
        </div>
      </section>

      {/* Vault Entries */}
      <section>
        <div className="flex items-center justify-between mb-6 px-1">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-zinc-900 rounded-lg border border-white/5">
              <LayoutGrid className="w-5 h-5 text-zinc-400" />
            </div>
            <h2 className="text-xl font-serif text-zinc-100">
              Vault Entries <span className="text-zinc-500 font-mono text-sm ml-2">({vault.entries.length})</span>
            </h2>
          </div>
        </div>

        {vault.entries.length === 0 ? (
          <div className="p-12 text-center border border-dashed border-white/10 rounded-2xl bg-zinc-900/50">
            <FileText className="w-12 h-12 text-zinc-600 mx-auto mb-4" />
            <p className="text-zinc-400">No entries yet. Add a document above to begin.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <AnimatePresence>
              {vault.entries.map((entry) => (
                <EntryCard
                  key={entry.id}
                  entry={entry}
                  verificationRecords={verificationMap[entry.id]?.records}
                  checkedAt={verificationMap[entry.id]?.checkedAt}
                  copiedEntryId={copiedEntryId}
                  onVerify={() => onVerifyEntry(entry)}
                  onNotarize={() => onNotarizeEntry(entry)}
                  onRemove={() => onRemoveEntry(entry.id)}
                  onCopyHash={() => onCopyHash(entry)}
                  onDownload={() => onDownloadEntry(entry)}
                />
              ))}
            </AnimatePresence>
          </div>
        )}
      </section>

      {/* Public Hash Verifier */}
      <section className="bg-zinc-900 border border-white/10 rounded-2xl p-6 sm:p-8">
        <div className="flex flex-col md:flex-row gap-8">
          <div className="md:w-1/3">
            <div className="flex items-center gap-3 mb-3">
              <div className="p-2 bg-zinc-800 rounded-lg">
                <Search className="w-5 h-5 text-zinc-300" />
              </div>
              <h2 className="text-xl font-serif text-zinc-100">Public Verifier</h2>
            </div>
            <p className="text-sm text-zinc-400 leading-relaxed">
              Verify any content hash on-chain. No wallet required. This checks the Polkadot Hub registry for notarization records matching the exact SHA-256 hash.
            </p>
          </div>
          
          <div className="md:w-2/3 space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-mono uppercase tracking-wider text-zinc-500">Content Hash (0x...)</label>
              <div className="flex gap-3">
                <input
                  type="text"
                  placeholder="0x..."
                  value={publicVerifierHash}
                  onChange={(e) => setPublicVerifierHash(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && onVerifyPublicHash()}
                  className="flex-1 px-4 py-2.5 bg-zinc-950 border border-white/10 rounded-lg focus:outline-none focus:border-emerald-500 text-sm font-mono text-zinc-300 transition-colors"
                />
                <button
                  onClick={onVerifyPublicHash}
                  disabled={isPublicVerifying || !publicVerifierHash}
                  className="px-5 py-2.5 bg-zinc-800 text-zinc-200 border border-white/10 rounded-lg font-medium hover:bg-zinc-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
                >
                  {isPublicVerifying ? 'Verifying...' : 'Verify'}
                </button>
              </div>
            </div>

            {publicVerifierResult && (
              <motion.div 
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                className="overflow-hidden"
              >
                <div className={`p-4 border rounded-xl ${publicVerifierResult.records.length > 0 ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-zinc-950/50 border-white/5'}`}>
                  <div className="text-xs font-mono text-zinc-400 mb-3">
                    Checked: {formatDateTime(publicVerifierResult.checkedAt)} • {publicVerifierResult.records.length} record(s)
                  </div>
                  
                  {publicVerifierResult.records.length === 0 ? (
                    <p className="text-sm text-zinc-400">No on-chain records found for this hash.</p>
                  ) : (
                    <div className="space-y-3">
                      {publicVerifierResult.records.map((record, idx) => (
                        <div key={`${record.submitter}-${record.timestamp}-${idx}`} className="text-sm bg-zinc-950/50 p-3 rounded-lg border border-white/5">
                          <div className="flex justify-between items-start mb-1">
                            <span className="font-medium text-emerald-400">{record.label || '(no label)'}</span>
                            <span className="text-xs font-mono text-zinc-500">{new Date(record.timestamp * 1000).toLocaleString()}</span>
                          </div>
                          <div className="text-xs font-mono text-zinc-400 break-all">
                            By: {record.submitter}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </motion.div>
            )}
          </div>
        </div>
      </section>
    </div>
  )
}
