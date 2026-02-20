import { motion, AnimatePresence } from 'framer-motion'
import { ShieldAlert, X } from 'lucide-react'
import type { PendingConsent } from '../types'

interface ConsentModalProps {
  pendingConsent: PendingConsent | null
  isConsentBusy: boolean
  onApprove: () => void
  onDecline: () => void
}

export function ConsentModal({
  pendingConsent,
  isConsentBusy,
  onApprove,
  onDecline,
}: ConsentModalProps) {
  return (
    <AnimatePresence>
      {pendingConsent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-zinc-950/80 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            className="w-full max-w-lg bg-zinc-900 border border-red-500/20 rounded-2xl shadow-2xl overflow-hidden relative"
          >
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-red-500/50 to-amber-500/50" />
            
            <div className="p-6 sm:p-8">
              <div className="flex items-start justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-red-500/10 rounded-full text-red-400">
                    <ShieldAlert className="w-6 h-6" />
                  </div>
                  <div>
                    <h2 className="text-xs font-mono uppercase tracking-widest text-red-400/80 mb-1">Authorization Required</h2>
                    <h3 className="font-serif text-xl font-medium text-zinc-100">{pendingConsent.title}</h3>
                  </div>
                </div>
                <button
                  onClick={onDecline}
                  disabled={isConsentBusy}
                  className="p-2 text-zinc-500 hover:text-zinc-300 hover:bg-white/5 rounded-full transition-colors disabled:opacity-50"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="bg-zinc-950/50 border border-white/5 rounded-xl p-5 mb-8">
                <ul className="space-y-3">
                  {pendingConsent.details.map((detail, idx) => (
                    <li key={idx} className="flex items-start gap-3 text-sm text-zinc-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500/50 mt-2 flex-shrink-0" />
                      <span className="leading-relaxed">{detail}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="flex flex-col-reverse sm:flex-row justify-end gap-3">
                <button
                  onClick={onDecline}
                  disabled={isConsentBusy}
                  className="px-6 py-2.5 rounded-lg border border-white/10 text-zinc-300 hover:bg-white/5 font-medium transition-colors disabled:opacity-50"
                >
                  Decline
                </button>
                <button
                  onClick={onApprove}
                  disabled={isConsentBusy}
                  className="px-6 py-2.5 rounded-lg bg-red-500 text-zinc-950 font-medium hover:bg-red-400 transition-colors disabled:opacity-50 flex items-center justify-center min-w-[140px]"
                >
                  {isConsentBusy ? (
                    <span className="flex items-center gap-2">
                      <span className="w-4 h-4 rounded-full border-2 border-zinc-950/20 border-t-zinc-950 animate-spin" />
                      Approving...
                    </span>
                  ) : (
                    'Approve Once'
                  )}
                </button>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  )
}
