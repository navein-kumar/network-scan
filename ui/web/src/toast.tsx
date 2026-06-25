// Lightweight toast system: a provider that renders a fixed bottom-right stack
// and a useToast() hook with success / error / info helpers. Toasts auto-dismiss
// after 5 seconds.
import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react'
import { CircleCheck, TriangleAlert, Info, X } from 'lucide-react'

type ToastKind = 'success' | 'error' | 'info'

interface ToastItem {
  id: number
  kind: ToastKind
  message: string
}

interface ToastApi {
  push: (kind: ToastKind, message: string) => void
  success: (message: string) => void
  error: (message: string) => void
  info: (message: string) => void
}

const ToastContext = createContext<ToastApi | null>(null)

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}

const VARIANTS: Record<ToastKind, { icon: ReactNode; classes: string }> = {
  success: {
    icon: <CircleCheck size={18} className="text-emerald-400" />,
    classes: 'border-emerald-500/40',
  },
  error: {
    icon: <TriangleAlert size={18} className="text-red-400" />,
    classes: 'border-red-500/40',
  },
  info: {
    icon: <Info size={18} className="text-blue-400" />,
    classes: 'border-blue-500/40',
  },
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const counter = useRef(0)

  const remove = useCallback((id: number) => {
    setToasts((list) => list.filter((t) => t.id !== id))
  }, [])

  const push = useCallback(
    (kind: ToastKind, message: string) => {
      const id = ++counter.current
      setToasts((list) => [...list, { id, kind, message }])
      window.setTimeout(() => remove(id), 5000)
    },
    [remove],
  )

  const api: ToastApi = {
    push,
    success: (m) => push('success', m),
    error: (m) => push('error', m),
    info: (m) => push('info', m),
  }

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-full max-w-sm flex-col gap-2">
        {toasts.map((t) => {
          const variant = VARIANTS[t.kind]
          return (
            <div
              key={t.id}
              className={`pointer-events-auto flex items-start gap-3 rounded-lg border bg-surface-raised px-4 py-3 shadow-card ${variant.classes}`}
            >
              <div className="mt-0.5 shrink-0">{variant.icon}</div>
              <p className="flex-1 text-sm text-slate-200">{t.message}</p>
              <button
                onClick={() => remove(t.id)}
                className="shrink-0 text-slate-500 hover:text-slate-300"
                aria-label="Dismiss"
              >
                <X size={16} />
              </button>
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}
