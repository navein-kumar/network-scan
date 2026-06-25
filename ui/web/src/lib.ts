// Shared helpers: class merging, date/duration formatting, severity utilities.
import { SEVERITY_ORDER, emptySeverity } from './types'
import type { Severity, SeverityCounts } from './types'

export function classNames(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ')
}

// Severity palette and labels, mined to match the running UI exactly.
export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#b91c1c',
  high: '#ea580c',
  medium: '#d97706',
  low: '#65a30d',
  info: '#6b7280',
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

// Lower rank = more severe (used to sort findings critical-first).
export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s)
}

// Total finding count across all severities.
export function severityTotal(counts?: SeverityCounts | null): number {
  if (!counts) return 0
  return SEVERITY_ORDER.reduce((sum, s) => sum + (counts[s] || 0), 0)
}

// Sum any number of severity-count objects into one.
export function sumSeverity(list: Array<SeverityCounts | null | undefined>): SeverityCounts {
  const out = emptySeverity()
  for (const c of list) {
    if (!c) continue
    for (const s of SEVERITY_ORDER) out[s] += c[s] || 0
  }
  return out
}

export function formatDate(value?: string | null): string {
  if (!value) return '-'
  const d = new Date(value)
  if (isNaN(d.getTime())) return '-'
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

// Human-friendly elapsed time between two timestamps. If finished is null,
// the duration runs up to now (a still-running scan).
export function durationBetween(started?: string | null, finished?: string | null): string {
  if (!started) return '-'
  const start = new Date(started).getTime()
  const end = finished ? new Date(finished).getTime() : Date.now()
  if (isNaN(start) || isNaN(end) || end < start) return '-'
  const secs = Math.round((end - start) / 1000)
  if (secs < 60) return `${secs}s`
  const mins = Math.floor(secs / 60)
  const remSecs = secs % 60
  if (mins < 60) return `${mins}m ${remSecs}s`
  return `${Math.floor(mins / 60)}h ${mins % 60}m`
}
