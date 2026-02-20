import { motion } from 'framer-motion'
import { Copy, Download, Trash2, CheckCircle2, ShieldAlert, Clock, Info } from 'lucide-react'
import type { VaultEntry, VerificationRecord } from '../types'
import { getContentTypeBadgeClass, formatBytes, formatDateTime } from '../utils'

interface EntryCardProps {
  entry: VaultEntry
  verificationRecords?: VerificationRecord[]
  checkedAt?: string
  copiedEntryId: string | null
  onVerify: () => void
  onNotarize: () => void
  onRemove: () => void
  onCopyHash: () => void
  onDownload: () => void
}

export function EntryCard({
  entry,
  verificationRecords,
  checkedAt,
  copiedEntryId,
  onVerify,
  onNotarize,
  onRemove,
  onCopyHash,
  onDownload,
}: EntryCardProps) {
  const isNotarized = Boolean(entry.lastNotarizedTx)
  const isVerified = Boolean(checkedAt)
  const hasRecords = isVerified && (verificationRecords?.length ?? 0) > 0

  let borderColorClass = 'border-l-zinc-500'
  if (!isNotarized) {
    borderColorClass = 'border-l-zinc-500'
  } else if (isVerified && hasRecords) {
    borderColorClass = 'border-l-emerald-500'
  } else {
    borderColorClass = 'border-l-amber-500'
  }

  let StatusIcon = Clock
  let statusBadgeClass = 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20'
  let statusText = 'UNVERIFIED'

  if (isNotarized && isVerified && hasRecords) {
    StatusIcon = CheckCircle2
    statusBadgeClass = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
    statusText = 'AUTHENTIC'
  } else if (isVerified && !hasRecords) {
    StatusIcon = ShieldAlert
    statusBadgeClass = 'bg-red-500/10 text-red-400 border-red-500/20'
    statusText = 'NO RECORD'
  } else if (isNotarized) {
    StatusIcon = Info
    statusBadgeClass = 'bg-amber-500/10 text-amber-500 border-amber-500/20'
    statusText = 'ON-CHAIN PENDING'
  }

  const contentType = entry.contentType ?? 'document'

  return (
    <motion.article
      layout
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.95 }}
      className={`relative flex flex-col p-5 bg-zinc-900 border-y border-r border-white/5 border-l-[3px] rounded-xl shadow-lg ${borderColorClass} transition-colors`}
    >
      <div className="flex flex-col sm:flex-row justify-between items-start gap-4 mb-4">
        <div>
          <h3 className="font-serif text-lg font-medium text-zinc-100 line-clamp-1" title={entry.label}>
            {entry.label}
          </h3>
          <p className="text-xs font-mono text-zinc-400 mt-1 flex flex-wrap gap-2 items-center">
            <span className="truncate max-w-[200px]" title={entry.originalFilename}>{entry.originalFilename}</span>
            <span className="opacity-50">•</span>
            <span>{formatBytes(entry.byteSize)}</span>
            <span className="opacity-50">•</span>
            <span>{formatDateTime(entry.createdAt)}</span>
          </p>
        </div>
        <div className="flex flex-wrap gap-2 flex-shrink-0">
          <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-mono font-medium border ${getContentTypeBadgeClass(contentType)} uppercase tracking-wider`}>
            {contentType}
          </span>
          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] font-mono font-medium border ${statusBadgeClass} uppercase tracking-wider`}>
            <StatusIcon className="w-3 h-3" />
            {statusText}
          </span>
        </div>
      </div>

      <div className="flex-1 space-y-4">
        <div className="bg-zinc-950/50 p-3 rounded-lg border border-white/5">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] font-mono uppercase tracking-widest text-zinc-500">SHA-256 Hash</span>
            <button
              onClick={onCopyHash}
              className="flex items-center gap-1 text-[10px] font-mono uppercase tracking-wider text-zinc-400 hover:text-emerald-400 transition-colors"
            >
              {copiedEntryId === entry.id ? 'Copied!' : (
                <>
                  <Copy className="w-3 h-3" />
                  <span>Copy</span>
                </>
              )}
            </button>
          </div>
          <code className="block text-xs text-emerald-400/90 break-all select-all">
            {entry.hashHex}
          </code>
        </div>

        {entry.lastNotarizedTx && (
          <div className="text-xs font-mono text-zinc-500 border-l border-zinc-700 pl-3 py-1">
            <div className="mb-1">
              <span className="text-zinc-400">Notarized: </span>
              {entry.lastNotarizedAt ? formatDateTime(entry.lastNotarizedAt) : ''}
            </div>
            <a 
              href={`https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Fpas-rpc.stakeworld.io%2Fassethub#/explorer/query/${entry.lastNotarizedTx}`}
              target="_blank"
              rel="noreferrer"
              className="block truncate text-amber-500/70 hover:text-amber-400 transition-colors"
              title="View on Explorer"
            >
              {entry.lastNotarizedTx}
            </a>
          </div>
        )}

        {checkedAt && (
          <div className={`text-xs font-mono border-l pl-3 py-1 ${hasRecords ? 'border-emerald-500/30' : 'border-red-500/30'}`}>
            <div className="mb-1 text-zinc-400">
              Checked: {formatDateTime(checkedAt)}
            </div>
            {hasRecords ? (
              <div className="space-y-1">
                {verificationRecords!.map((record, idx) => (
                  <div key={idx} className="text-emerald-400/80">
                    <span className="text-zinc-500 block">Record {idx + 1}:</span>
                    {record.submitter.slice(0, 8)}...{record.submitter.slice(-6)} • {new Date(record.timestamp * 1000).toLocaleString()}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-red-400/80">
                No matching on-chain records found.
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2 mt-5 pt-4 border-t border-white/5">
        <button
          onClick={onNotarize}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/20 transition-colors"
        >
          Notarize Hash
        </button>
        <button
          onClick={onVerify}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded bg-zinc-800 text-zinc-300 hover:bg-zinc-700 border border-white/5 transition-colors"
        >
          Verify on Polkadot
        </button>
        <div className="flex-1" />
        <button
          onClick={onDownload}
          className="p-1.5 text-zinc-400 hover:text-blue-400 hover:bg-blue-500/10 rounded transition-colors"
          title="Download File"
        >
          <Download className="w-4 h-4" />
        </button>
        <button
          onClick={onRemove}
          className="p-1.5 text-zinc-400 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
          title="Delete Entry"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
    </motion.article>
  )
}
