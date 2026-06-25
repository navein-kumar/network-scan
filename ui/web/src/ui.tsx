// Shared presentational primitives used across every page: cards, badges,
// progress/severity bars, skeletons, and empty/error states. Markup and class
// names match the running UI.
import type { ReactNode } from 'react'
import { classNames, SEVERITY_COLORS, SEVERITY_LABEL, severityTotal } from './lib'
import { SEVERITY_ORDER } from './types'
import type { ScanStatus, Severity, SeverityCounts } from './types'

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={classNames(
        'rounded-lg border border-surface-border bg-surface-card shadow-card',
        className,
      )}
    >
      {children}
    </div>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={classNames('skeleton', className)} />
}

export function ProgressBar({
  value,
  className,
  color = '#3b82f6',
}: {
  value: number
  className?: string
  color?: string
}) {
  const pct = Math.max(0, Math.min(100, Math.round(value)))
  return (
    <div
      className={classNames('h-2 w-full overflow-hidden rounded-full bg-surface-raised', className)}
    >
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${pct}%`, backgroundColor: color }}
      />
    </div>
  )
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const color = SEVERITY_COLORS[severity]
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-semibold uppercase tracking-wide"
      style={{ color, backgroundColor: `${color}1f`, border: `1px solid ${color}55` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
      {SEVERITY_LABEL[severity]}
    </span>
  )
}

// Stacked horizontal severity bar (proportional widths). Empty -> flat track.
export function SeverityMiniBar({ severity }: { severity: SeverityCounts }) {
  const total = severityTotal(severity)
  if (total === 0) {
    return <div className="h-1.5 w-full rounded-full bg-surface-raised" />
  }
  return (
    <div
      className="flex h-1.5 w-full overflow-hidden rounded-full bg-surface-raised"
      title={`${total} findings`}
    >
      {SEVERITY_ORDER.map((s) => {
        const v = severity[s] || 0
        if (v === 0) return null
        return (
          <div
            key={s}
            style={{ width: `${(v / total) * 100}%`, backgroundColor: SEVERITY_COLORS[s] }}
            title={`${SEVERITY_LABEL[s]}: ${v}`}
          />
        )
      })}
    </div>
  )
}

const STATUS_META: Record<ScanStatus, { label: string; classes: string; dot: string }> = {
  running: {
    label: 'Running',
    classes: 'bg-blue-500/10 text-blue-300 border border-blue-500/30',
    dot: 'bg-blue-400',
  },
  done: {
    label: 'Done',
    classes: 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30',
    dot: 'bg-emerald-400',
  },
  failed: {
    label: 'Failed',
    classes: 'bg-red-500/10 text-red-300 border border-red-500/30',
    dot: 'bg-red-400',
  },
  error: {
    label: 'Failed',
    classes: 'bg-red-500/10 text-red-300 border border-red-500/30',
    dot: 'bg-red-400',
  },
  paused: {
    label: 'Paused',
    classes: 'bg-amber-500/10 text-amber-300 border border-amber-500/30',
    dot: 'bg-amber-400',
  },
  stopped: {
    label: 'Stopped',
    classes: 'bg-slate-500/10 text-slate-400 border border-slate-500/30',
    dot: 'bg-slate-500',
  },
}

export function StatusBadge({ status }: { status: ScanStatus }) {
  const meta = STATUS_META[status] ?? STATUS_META.failed
  return (
    <span
      className={classNames(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium',
        meta.classes,
      )}
    >
      <span
        className={classNames(
          'h-1.5 w-1.5 rounded-full',
          meta.dot,
          status === 'running' && 'animate-pulse',
        )}
      />
      {meta.label}
    </span>
  )
}

export function EmptyState({
  icon,
  title,
  message,
  action,
}: {
  icon?: ReactNode
  title: string
  message?: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      {icon && <div className="text-slate-500">{icon}</div>}
      <h3 className="text-base font-semibold text-slate-200">{title}</h3>
      {message && <p className="max-w-md text-sm text-slate-400">{message}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}

export function ErrorState({
  title = 'Something went wrong',
  message,
  onRetry,
}: {
  title?: string
  message?: string
  onRetry?: () => void
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-16 text-center">
      <h3 className="text-base font-semibold text-red-300">{title}</h3>
      {message && <p className="max-w-md text-sm text-slate-400">{message}</p>}
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-2 rounded-md border border-surface-border bg-surface-raised px-3 py-1.5 text-sm font-medium text-slate-200 hover:bg-surface-hover"
        >
          Retry
        </button>
      )}
    </div>
  )
}
