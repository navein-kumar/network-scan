import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  ArrowLeft,
  FileSpreadsheet,
  Archive,
  Search,
  ChevronRight,
  ChevronDown,
  Server,
  Terminal,
  Loader2,
  GitCompare,
  CheckCircle2,
  AlertCircle,
  PlusCircle,
} from 'lucide-react'
import { api } from '../api'
import type {
  DiffFinding,
  Finding,
  HostInfo,
  ScanDetail as ScanDetailType,
  ScanDiff,
  ScanSummary,
  Severity,
} from '../types'
import { SEVERITY_ORDER, emptySeverity } from '../types'
import { usePolling } from '../hooks'
import { useScanStream } from '../useScanStream'
import {
  classNames,
  formatDate,
  durationBetween,
  severityRank,
  SEVERITY_COLORS,
  SEVERITY_LABEL,
} from '../lib'
import { TopBar } from '../Layout'
import {
  Card,
  EmptyState,
  ErrorState,
  Skeleton,
  StatusBadge,
  SeverityBadge,
  ProgressBar,
} from '../ui'
import { SeverityDonut, SeverityLegend } from '../charts'
import { useToast } from '../toast'

// ---------- Finding grouping ----------

type DisplayFinding = Finding & { _group?: Finding[] }

// cleanId strips any vendor prefix so it never appears in the UI.
const cleanId = (id: string) => id.replace(/^nessus-/, '')

function extractProduct(title: string): string {
  return title.split(/\s+/)[0] || 'Unknown'
}

function highestSeverity(group: Finding[]): Severity {
  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  return group.reduce((best, f) => rank[f.severity] < rank[best.severity] ? f : best, group[0]).severity
}

// A "nessus-style" rule has an ID ending in a 4-6 digit plugin number,
// with or without the legacy "nessus-" prefix (stripped at engine level for new scans).
const isNessusRule = (id: string) => /^(nessus-)?[a-z]+-\d{4,6}$/.test(id)

function groupFindings(findings: Finding[]): DisplayFinding[] {
  const buckets = new Map<string, Finding[]>()
  const ungrouped: DisplayFinding[] = []

  for (const f of findings) {
    if (!isNessusRule(f.rule_id)) {
      ungrouped.push(f)
      continue
    }
    const product = extractProduct(f.title)
    const key = `${f.host}\x00${f.port}\x00${product}`
    const existing = buckets.get(key)
    if (existing) {
      existing.push(f)
    } else {
      buckets.set(key, [f])
    }
  }

  const grouped: DisplayFinding[] = []
  for (const [, grp] of buckets) {
    if (grp.length === 1) {
      grouped.push(grp[0])
    } else {
      const first = grp[0]
      const product = extractProduct(first.title)
      grouped.push({
        ...first,
        severity: highestSeverity(grp),
        rule_id: `grouped:${first.host}:${first.port}:${product}`,
        title: `${product} Multiple CVE Vulnerabilities (${grp.length} affected)`,
        evidence: grp.map(f => `[${cleanId(f.rule_id)}] ${f.title}`).join('\n'),
        _group: grp,
      })
    }
  }

  return [...ungrouped, ...grouped]
}

// ---------- Pagination helpers ----------

const PAGE_SIZES = [10, 25, 50, 100, 0] as const
const PAGE_LABELS: Record<number, string> = { 10: '10', 25: '25', 50: '50', 100: '100', 0: 'All' }

function usePagination<T>(items: T[], pageSize: number) {
  const [page, setPage] = useState(1)
  useEffect(() => { setPage(1) }, [pageSize])
  const totalPages = pageSize === 0 ? 1 : Math.max(1, Math.ceil(items.length / pageSize))
  const clampedPage = Math.min(page, totalPages)
  const start = pageSize === 0 ? 0 : (clampedPage - 1) * pageSize
  const sliced = pageSize === 0 ? items : items.slice(start, start + pageSize)
  const end = Math.min(start + (pageSize === 0 ? items.length : pageSize), items.length)
  return { paged: sliced, page: clampedPage, setPage, totalPages, start, end }
}

function PageBar({
  total, pageSize, onPageSize,
  page, totalPages, onPage,
  start, end,
}: {
  total: number; pageSize: number; onPageSize: (n: number) => void
  page: number; totalPages: number; onPage: (n: number) => void
  start: number; end: number
}) {
  if (total <= 10) return null
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-surface-border px-5 py-2.5">
      <span className="text-xs text-slate-500">
        {pageSize === 0 ? `All ${total}` : `${start + 1}–${end} of ${total}`}
      </span>
      <div className="flex items-center gap-1">
        <span className="mr-1 text-xs text-slate-500">Show</span>
        {PAGE_SIZES.map((n) => (
          <button
            key={n}
            onClick={() => { onPageSize(n); onPage(1) }}
            className={classNames(
              'rounded px-2 py-0.5 text-xs font-medium transition-colors',
              pageSize === n ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200',
            )}
          >{PAGE_LABELS[n]}</button>
        ))}
        {pageSize !== 0 && totalPages > 1 && (
          <>
            <button disabled={page <= 1} onClick={() => onPage(page - 1)}
              className="ml-2 rounded px-1.5 py-0.5 text-xs text-slate-400 hover:text-slate-200 disabled:opacity-30">‹</button>
            <span className="text-xs text-slate-500">{page}/{totalPages}</span>
            <button disabled={page >= totalPages} onClick={() => onPage(page + 1)}
              className="rounded px-1.5 py-0.5 text-xs text-slate-400 hover:text-slate-200 disabled:opacity-30">›</button>
          </>
        )}
      </div>
    </div>
  )
}

// ---------- Running view ----------

const HOST_STATUS_META: Record<string, { label: string; classes: string }> = {
  running: { label: 'Running', classes: 'bg-blue-500/10 text-blue-300' },
  done: { label: 'Done', classes: 'bg-emerald-500/10 text-emerald-300' },
  lost: { label: 'Lost', classes: 'bg-red-500/10 text-red-300' },
}

function RunningView({ id }: { id: string }) {
  const stream = useScanStream(id, true)
  const logRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const [logOpen, setLogOpen] = useState(false)
  const [hostsOpen, setHostsOpen] = useState(true)
  const [hostsPageSize, setHostsPageSize] = useState<number>(25)
  const [logPageSize, setLogPageSize] = useState<number>(100)

  const hostsPagination = usePagination(stream.hosts, hostsPageSize)

  // For log: show last N lines
  const logLines = logPageSize === 0 ? stream.logs : stream.logs.slice(-logPageSize)

  useEffect(() => {
    if (autoScroll && logRef.current && logOpen) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [stream.logs, autoScroll, logOpen])

  return (
    <div className="space-y-6">
      {/* Overall progress */}
      <Card className="p-6">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold text-slate-200">Overall Progress</h2>
            <span
              className={classNames(
                'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium',
                stream.connected
                  ? 'bg-emerald-500/10 text-emerald-300'
                  : 'bg-amber-500/10 text-amber-300',
              )}
            >
              <span
                className={classNames(
                  'h-1.5 w-1.5 rounded-full',
                  stream.connected ? 'bg-emerald-400' : 'bg-amber-400 animate-pulse',
                )}
              />
              {stream.connected ? 'Live' : 'Reconnecting'}
            </span>
          </div>
          <span className="text-sm tabular-nums text-slate-400">
            {stream.hostsDone} / {stream.hostsTotal || '?'} hosts
          </span>
        </div>
        <div className="flex items-center gap-3">
          <ProgressBar value={stream.overall} className="h-3" />
          <span className="w-12 text-right text-lg font-bold tabular-nums text-white">
            {Math.round(stream.overall)}%
          </span>
        </div>
        {stream.liveFindingCount > 0 && (
          <p className="mt-3 text-xs text-slate-400">
            {stream.liveFindingCount} findings reported so far
          </p>
        )}
      </Card>

      {/* Hosts — collapsible */}
      <Card className="overflow-hidden">
        <button
          onClick={() => setHostsOpen((o) => !o)}
          className="flex w-full items-center justify-between border-b border-surface-border px-5 py-3.5 hover:bg-surface-hover/30 transition-colors"
        >
          <div className="flex items-center gap-2">
            {hostsOpen ? <ChevronDown size={15} className="text-slate-400" /> : <ChevronRight size={15} className="text-slate-400" />}
            <h2 className="text-sm font-semibold text-slate-200">Hosts</h2>
            {stream.hosts.length > 0 && (
              <span className="rounded-full bg-slate-700/60 px-2 py-0.5 text-xs text-slate-400">
                {stream.hosts.filter(h => h.status === 'done').length}/{stream.hosts.length}
              </span>
            )}
          </div>
        </button>
        {hostsOpen && (
          <>
            {stream.hosts.length === 0 ? (
              <div className="px-5 py-10 text-center text-sm text-slate-500">
                Waiting for host progress...
              </div>
            ) : (
              <>
                <div className="divide-y divide-surface-border/60">
                  {hostsPagination.paged.map((h) => {
                    const meta = HOST_STATUS_META[h.status] ?? HOST_STATUS_META.running
                    return (
                      <div key={h.host} className="flex items-center gap-4 px-5 py-3">
                        <div className="w-44 shrink-0 truncate font-mono text-sm text-slate-200" title={h.host}>{h.host}</div>
                        <div className="w-20 shrink-0 text-xs text-slate-500">phase {h.phase}</div>
                        <div className="flex flex-1 items-center gap-3">
                          <ProgressBar value={h.percent} />
                          <span className="w-9 text-right text-xs tabular-nums text-slate-400">
                            {Math.round(h.percent)}%
                          </span>
                        </div>
                        <span className={classNames('inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-xs font-medium', meta.classes)}>
                          {meta.label}
                        </span>
                      </div>
                    )
                  })}
                </div>
                <PageBar
                  total={stream.hosts.length} pageSize={hostsPageSize} onPageSize={setHostsPageSize}
                  page={hostsPagination.page} totalPages={hostsPagination.totalPages} onPage={hostsPagination.setPage}
                  start={hostsPagination.start} end={hostsPagination.end}
                />
              </>
            )}
          </>
        )}
      </Card>

      {/* Live Findings — collapsible panel handles its own state */}
      <LiveFindingsPanel id={id} />

      {/* Live Log — collapsible + last-N pagination */}
      <Card className="overflow-hidden">
        <button
          onClick={() => setLogOpen((o) => !o)}
          className="flex w-full items-center justify-between border-b border-surface-border px-5 py-3.5 hover:bg-surface-hover/30 transition-colors"
        >
          <div className="flex items-center gap-2">
            {logOpen ? <ChevronDown size={15} className="text-slate-400" /> : <ChevronRight size={15} className="text-slate-400" />}
            <Terminal size={15} className="text-slate-400" />
            <h2 className="text-sm font-semibold text-slate-200">Live Log</h2>
            {stream.logs.length > 0 && (
              <span className="rounded-full bg-slate-700/60 px-2 py-0.5 text-xs text-slate-400">
                {stream.logs.length} lines
              </span>
            )}
          </div>
          {logOpen && (
            <label className="flex cursor-pointer items-center gap-1.5 text-xs text-slate-400" onClick={(e) => e.stopPropagation()}>
              <input type="checkbox" checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} className="accent-blue-600" />
              Auto-scroll
            </label>
          )}
        </button>
        {logOpen && (
          <>
            <div
              ref={logRef}
              className="h-72 overflow-y-auto bg-[#0a0d14] px-4 py-3 font-mono text-xs leading-relaxed"
            >
              {logLines.length === 0 ? (
                <span className="text-slate-600">Waiting for log output...</span>
              ) : (
                logLines.map((line, i) => (
                  <div key={i} className="whitespace-pre-wrap break-all text-slate-400">{line}</div>
                ))
              )}
            </div>
            {/* Log page size: show last N lines */}
            {stream.logs.length > 50 && (
              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-surface-border px-5 py-2.5">
                <span className="text-xs text-slate-500">
                  Showing last {logPageSize === 0 ? stream.logs.length : Math.min(logPageSize, stream.logs.length)} of {stream.logs.length} lines
                </span>
                <div className="flex items-center gap-1">
                  <span className="mr-1 text-xs text-slate-500">Show last</span>
                  {([50, 100, 200, 500, 0] as const).map((n) => (
                    <button key={n} onClick={() => setLogPageSize(n)}
                      className={classNames('rounded px-2 py-0.5 text-xs font-medium transition-colors',
                        logPageSize === n ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
                      )}>
                      {n === 0 ? 'All' : String(n)}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </Card>
    </div>
  )
}

// ---------- Findings table ----------

function FindingsTable({ id }: { id: string }) {
  const { data, loading, error, reload } = usePolling<Finding[]>(() => api.getFindings(id), undefined, [id])
  const [sevFilter, setSevFilter] = useState<Severity | 'all'>('all')
  const [hostFilter, setHostFilter] = useState<string>('all')
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState<number | null>(null)

  const findings = data ?? []

  const hosts = useMemo(() => {
    const set = new Set<string>()
    findings.forEach((f) => f.host && set.add(f.host))
    return Array.from(set).sort()
  }, [findings])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return findings
      .filter((f) => sevFilter === 'all' || f.severity === sevFilter)
      .filter((f) => hostFilter === 'all' || f.host === hostFilter)
      .filter(
        (f) =>
          q === '' ||
          f.title.toLowerCase().includes(q) ||
          f.rule_id.toLowerCase().includes(q) ||
          (f.evidence || '').toLowerCase().includes(q) ||
          f.host.toLowerCase().includes(q),
      )
      .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
  }, [findings, sevFilter, hostFilter, query])

  const displayed = useMemo(() => groupFindings(filtered), [filtered])

  if (loading && !data) {
    return (
      <Card>
        <div className="space-y-2 p-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12" />
          ))}
        </div>
      </Card>
    )
  }

  if (error && !data) {
    return (
      <Card>
        <ErrorState title="Could not load findings" message={error} onRetry={reload} />
      </Card>
    )
  }

  return (
    <Card>
      <div className="flex flex-wrap items-center gap-3 border-b border-surface-border px-5 py-4">
        <h2 className="mr-auto text-sm font-semibold text-slate-200">
          Findings
          <span className="ml-2 text-xs font-normal text-slate-500">
            {displayed.length} shown
            {displayed.length < filtered.length && (
              <span className="ml-1 text-slate-600">({filtered.length} total, grouped by service)</span>
            )}
          </span>
        </h2>
        <div className="relative">
          <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search findings"
            className="w-52 rounded-md border border-surface-border bg-surface-base py-1.5 pl-8 pr-3 text-sm text-slate-100 placeholder:text-slate-600 focus:border-blue-500 focus:outline-none"
          />
        </div>
        <select
          value={sevFilter}
          onChange={(e) => setSevFilter(e.target.value as Severity | 'all')}
          className="rounded-md border border-surface-border bg-surface-base px-2.5 py-1.5 text-sm text-slate-200 focus:border-blue-500 focus:outline-none"
        >
          <option value="all">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABEL[s]}
            </option>
          ))}
        </select>
        <select
          value={hostFilter}
          onChange={(e) => setHostFilter(e.target.value)}
          className="max-w-[12rem] rounded-md border border-surface-border bg-surface-base px-2.5 py-1.5 text-sm text-slate-200 focus:border-blue-500 focus:outline-none"
        >
          <option value="all">All hosts</option>
          {hosts.map((h) => (
            <option key={h} value={h}>
              {h}
            </option>
          ))}
        </select>
      </div>

      {findings.length === 0 ? (
        <EmptyState title="No findings" message="This scan did not report any findings." />
      ) : displayed.length === 0 ? (
        <EmptyState title="No matches" message="No findings match the current filters." />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-border text-left text-xs uppercase tracking-wide text-slate-500">
                <th className="w-8 px-3 py-3" />
                <th className="px-3 py-3 font-medium">Severity</th>
                <th className="px-3 py-3 font-medium">Title</th>
                <th className="px-3 py-3 font-medium">Host</th>
                <th className="px-3 py-3 font-medium">Port</th>
                <th className="px-3 py-3 font-medium">Source</th>
              </tr>
            </thead>
            <tbody>
              {displayed.map((f, idx) => {
                const isOpen = expanded === idx
                return (
                  <FindingRow
                    key={`${f.rule_id}-${f.host}-${f.port}-${idx}`}
                    scanId={id}
                    finding={f}
                    group={f._group}
                    isOpen={isOpen}
                    onToggle={() => setExpanded(isOpen ? null : idx)}
                  />
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

function FindingRow({
  scanId,
  finding,
  group,
  isOpen,
  onToggle,
}: {
  scanId: string
  finding: Finding
  group?: Finding[]
  isOpen: boolean
  onToggle: () => void
}) {
  const [evidence, setEvidence] = useState<string | null>(null)
  const [eviLoading, setEviLoading] = useState(false)
  useEffect(() => {
    if (group || !isOpen || evidence !== null) return
    let active = true
    setEviLoading(true)
    api
      .getEvidence(scanId, finding.rule_id)
      .then((t) => active && setEvidence(t))
      .catch(() => active && setEvidence(finding.evidence || ""))
      .finally(() => active && setEviLoading(false))
    return () => {
      active = false
    }
  }, [group, isOpen, scanId, finding.rule_id, finding.evidence, evidence])
  const eviText = evidence ?? finding.evidence ?? ""
  return (
    <>
      <tr
        onClick={onToggle}
        className="cursor-pointer border-b border-surface-border/60 hover:bg-surface-hover/40"
      >
        <td className="px-3 py-3 text-slate-500">
          {isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        </td>
        <td className="px-3 py-3">
          <SeverityBadge severity={finding.severity} />
        </td>
        <td className="px-3 py-3">
          <div className="font-medium text-slate-100">{finding.title || cleanId(finding.rule_id)}</div>
          {group ? (
            <div className="mt-0.5 text-[11px] text-amber-500/70">{group.length} CVEs grouped — click to expand</div>
          ) : (
            <div className="font-mono text-[11px] text-slate-600">{cleanId(finding.rule_id)}</div>
          )}
        </td>
        <td className="px-3 py-3 font-mono text-xs text-slate-300">{finding.host || '-'}</td>
        <td className="px-3 py-3 tabular-nums text-slate-300">{finding.port || '-'}</td>
        <td className="px-3 py-3 text-slate-400">{finding.source || '-'}</td>
      </tr>
      {isOpen && (
        <tr className="border-b border-surface-border/60 bg-surface-base/40">
          <td />
          <td colSpan={5} className="px-3 py-4">
            {group ? (
              <div className="space-y-3">
                <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Affected CVEs ({group.length})
                </div>
                <div className="overflow-hidden rounded-md border border-surface-border">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-surface-border bg-surface-raised text-left text-[11px] uppercase tracking-wide text-slate-500">
                        <th className="px-3 py-2 font-medium">Severity</th>
                        <th className="px-3 py-2 font-medium">Vulnerability</th>
                        <th className="px-3 py-2 font-medium">Rule ID</th>
                      </tr>
                    </thead>
                    <tbody>
                      {group.map((item) => (
                        <tr key={item.rule_id} className="border-b border-surface-border/50 last:border-0">
                          <td className="px-3 py-2">
                            <SeverityBadge severity={item.severity} />
                          </td>
                          <td className="px-3 py-2 text-slate-200">{item.title}</td>
                          <td className="px-3 py-2 font-mono text-slate-500">{cleanId(item.rule_id)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Evidence
                </div>
                {eviLoading && evidence === null ? (
                  <p className="text-sm text-slate-500">Loading evidence...</p>
                ) : eviText ? (
                  <pre className="max-h-96 overflow-auto whitespace-pre rounded-md border border-surface-border bg-[#0a0d14] p-3 font-mono text-xs leading-relaxed text-slate-300">
                    {eviText}
                  </pre>
                ) : (
                  <p className="text-sm text-slate-500">No evidence captured for this finding.</p>
                )}
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

type SortCol = 'severity' | 'title' | 'host' | 'port' | 'source'

function LiveFindingsPanel({ id }: { id: string }) {
  const { data } = usePolling<Finding[]>(() => api.getFindings(id), 8000, [id])
  const [open, setOpen] = useState(true)
  const [expanded, setExpanded] = useState<number | null>(null)
  const [sortCol, setSortCol] = useState<SortCol>('severity')
  const [sortAsc, setSortAsc] = useState(true)
  const [pageSize, setPageSize] = useState(25)

  const grouped = useMemo(() => groupFindings(data ?? []), [data])

  const displayed = useMemo(() => {
    return [...grouped].sort((a, b) => {
      let cmp = 0
      if (sortCol === 'severity') cmp = severityRank(a.severity) - severityRank(b.severity)
      else if (sortCol === 'title') cmp = a.title.localeCompare(b.title)
      else if (sortCol === 'host') cmp = a.host.localeCompare(b.host)
      else if (sortCol === 'port') cmp = (a.port ?? 0) - (b.port ?? 0)
      else if (sortCol === 'source') cmp = (a.source ?? '').localeCompare(b.source ?? '')
      return sortAsc ? cmp : -cmp
    })
  }, [grouped, sortCol, sortAsc])

  const pagination = usePagination(displayed, pageSize)

  const handleSort = (col: SortCol) => {
    if (sortCol === col) setSortAsc(a => !a)
    else { setSortCol(col); setSortAsc(true) }
    setExpanded(null)
  }

  const SortIcon = ({ col }: { col: SortCol }) => {
    if (sortCol !== col) return <span className="ml-1 opacity-30">↕</span>
    return <span className="ml-1 text-blue-400">{sortAsc ? '↑' : '↓'}</span>
  }

  if (displayed.length === 0 && (data ?? []).length === 0) return null
  return (
    <Card className="overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between border-b border-surface-border px-5 py-3.5 hover:bg-surface-hover/30 transition-colors"
      >
        <div className="flex items-center gap-2">
          {open ? <ChevronDown size={15} className="text-slate-400" /> : <ChevronRight size={15} className="text-slate-400" />}
          <h2 className="text-sm font-semibold text-slate-200">Live Findings</h2>
          <span className="rounded-full bg-blue-500/20 px-2 py-0.5 text-xs font-medium text-blue-300 tabular-nums">
            {displayed.length}
          </span>
        </div>
        <span className="text-xs text-slate-500">Refreshes every 8 s</span>
      </button>
      {open && (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-border text-left text-xs uppercase tracking-wide text-slate-500">
                  <th className="w-8 px-3 py-3" />
                  <th className="cursor-pointer select-none px-3 py-3 font-medium hover:text-slate-300" onClick={() => handleSort('severity')}>
                    Severity<SortIcon col="severity" />
                  </th>
                  <th className="cursor-pointer select-none px-3 py-3 font-medium hover:text-slate-300" onClick={() => handleSort('title')}>
                    Title<SortIcon col="title" />
                  </th>
                  <th className="cursor-pointer select-none px-3 py-3 font-medium hover:text-slate-300" onClick={() => handleSort('host')}>
                    Host<SortIcon col="host" />
                  </th>
                  <th className="cursor-pointer select-none px-3 py-3 font-medium hover:text-slate-300" onClick={() => handleSort('port')}>
                    Port<SortIcon col="port" />
                  </th>
                  <th className="cursor-pointer select-none px-3 py-3 font-medium hover:text-slate-300" onClick={() => handleSort('source')}>
                    Source<SortIcon col="source" />
                  </th>
                </tr>
              </thead>
              <tbody>
                {pagination.paged.map((f, idx) => {
                  const absIdx = pagination.start + idx
                  const isOpen = expanded === absIdx
                  return (
                    <FindingRow
                      key={`${f.rule_id}-${f.host}-${f.port}-${absIdx}`}
                      scanId={id}
                      finding={f}
                      group={f._group}
                      isOpen={isOpen}
                      onToggle={() => setExpanded(isOpen ? null : absIdx)}
                    />
                  )
                })}
              </tbody>
            </table>
          </div>
          <PageBar
            total={displayed.length} pageSize={pageSize} onPageSize={setPageSize}
            page={pagination.page} totalPages={pagination.totalPages} onPage={pagination.setPage}
            start={pagination.start} end={pagination.end}
          />
        </>
      )}
    </Card>
  )
}

// ---------- Hosts table ----------

function HostsTable({ id }: { id: string }) {
  const { data, loading, error, reload } = usePolling<HostInfo[]>(() => api.getHosts(id), undefined, [id])
  const [open, setOpen] = useState<string | null>(null)
  const hosts = useMemo(() => {
    const arr = data ?? []
    const weight = (h: HostInfo) =>
      (h.severity?.critical || 0) * 1e6 +
      (h.severity?.high || 0) * 1e4 +
      (h.severity?.medium || 0) * 1e2 +
      (h.severity?.low || 0) +
      (h.severity?.info || 0) * 0.001
    return [...arr].sort((a, b) => weight(b) - weight(a))
  }, [data])

  if (loading && !data) {
    return (
      <Card>
        <div className="space-y-2 p-5">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-12" />
          ))}
        </div>
      </Card>
    )
  }

  if (error && !data) {
    return (
      <Card>
        <ErrorState title="Could not load hosts" message={error} onRetry={reload} />
      </Card>
    )
  }

  return (
    <Card>
      <div className="border-b border-surface-border px-5 py-4">
        <h2 className="text-sm font-semibold text-slate-200">
          Hosts
          <span className="ml-2 text-xs font-normal text-slate-500">{hosts.length}</span>
        </h2>
      </div>
      {hosts.length === 0 ? (
        <EmptyState
          icon={<Server size={32} />}
          title="No hosts"
          message="No host data is available for this scan."
        />
      ) : (
        <div className="divide-y divide-surface-border/60">
          {hosts.map((h) => {
            const isOpen = open === h.host
            return (
              <div key={h.host}>
                <button
                  onClick={() => setOpen(isOpen ? null : h.host)}
                  className="flex w-full items-center gap-4 px-5 py-3 text-left hover:bg-surface-hover/40"
                >
                  <span className="text-slate-500">
                    {isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                  </span>
                  <span className="w-40 shrink-0 truncate font-mono text-sm text-slate-100" title={h.host}>{h.host}</span>
                  <span className="w-20 shrink-0 text-xs text-slate-500">
                    {h.ports?.length || 0} ports
                  </span>
                  <div className="flex h-2.5 flex-1 overflow-hidden rounded-full bg-surface-raised">
                    {SEVERITY_ORDER.map((s) => {
                      const v = h.severity?.[s] || 0
                      if (v <= 0) return null
                      const total = h.finding_count || 1
                      return (
                        <div
                          key={s}
                          style={{
                            width: `${(v / total) * 100}%`,
                            backgroundColor: SEVERITY_COLORS[s],
                          }}
                          title={`${SEVERITY_LABEL[s]}: ${v}`}
                        />
                      )
                    })}
                  </div>
                  <div className="flex shrink-0 items-center gap-1.5">
                    {SEVERITY_ORDER.filter((s) => (h.severity?.[s] || 0) > 0).map((s) => (
                      <span
                        key={s}
                        className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-semibold tabular-nums"
                        style={{
                          color: SEVERITY_COLORS[s],
                          backgroundColor: `${SEVERITY_COLORS[s]}1a`,
                        }}
                        title={SEVERITY_LABEL[s]}
                      >
                        {h.severity[s]}
                      </span>
                    ))}
                    <span className="ml-1 text-xs tabular-nums text-slate-400">
                      {h.finding_count} findings
                    </span>
                  </div>
                </button>
                {isOpen && (
                  <div className="border-t border-surface-border/60 bg-surface-base/40 px-5 py-4">
                    {h.ports && h.ports.length > 0 ? (
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="text-left text-xs uppercase tracking-wide text-slate-500">
                            <th className="py-2 pr-4 font-medium">Port</th>
                            <th className="py-2 pr-4 font-medium">Proto</th>
                            <th className="py-2 pr-4 font-medium">Service</th>
                            <th className="py-2 font-medium">Version</th>
                          </tr>
                        </thead>
                        <tbody>
                          {h.ports.map((p, i) => (
                            <tr key={`${p.port}-${p.proto}-${i}`} className="text-slate-300">
                              <td className="py-1.5 pr-4 font-mono tabular-nums">{p.port}</td>
                              <td className="py-1.5 pr-4 uppercase text-slate-400">{p.proto}</td>
                              <td className="py-1.5 pr-4">{p.service || '-'}</td>
                              <td className="py-1.5 text-slate-400">{p.version || '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <p className="text-sm text-slate-500">No open ports recorded.</p>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </Card>
  )
}

// ---------- Compare / rescan diff ----------

// One diff bucket (Fixed / Still-open / New) with accent color and finding list.
const DIFF_BUCKETS = [
  {
    key: 'fixed' as const,
    label: 'Fixed',
    help: 'In baseline, gone in this rescan',
    icon: CheckCircle2,
    accent: '#10b981',
    classes: 'border-emerald-500/30 bg-emerald-500/5',
    text: 'text-emerald-300',
  },
  {
    key: 'still_open' as const,
    label: 'Still open',
    help: 'Present in both scans',
    icon: AlertCircle,
    accent: '#f97316',
    classes: 'border-orange-500/30 bg-orange-500/5',
    text: 'text-orange-300',
  },
  {
    key: 'new' as const,
    label: 'New',
    help: 'Not in baseline, found in this rescan',
    icon: PlusCircle,
    accent: '#3b82f6',
    classes: 'border-blue-500/30 bg-blue-500/5',
    text: 'text-blue-300',
  },
]

function DiffFindingList({ items }: { items: DiffFinding[] }) {
  if (items.length === 0) {
    return <p className="px-5 py-6 text-center text-sm text-slate-500">No findings in this bucket.</p>
  }
  const sorted = [...items].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
  return (
    <ul className="divide-y divide-surface-border/60">
      {sorted.map((f, i) => (
        <li key={`${f.rule_id}-${f.host}-${f.port}-${i}`} className="flex items-center gap-3 px-5 py-3">
          <SeverityBadge severity={f.severity} />
          <div className="min-w-0 flex-1">
            <div className="truncate font-medium text-slate-100">{f.title || cleanId(f.rule_id)}</div>
            <div className="font-mono text-[11px] text-slate-600">{cleanId(f.rule_id)}</div>
          </div>
          <span className="shrink-0 font-mono text-xs text-slate-400">
            {f.host || '-'}
            {f.port ? `:${f.port}` : ''}
          </span>
        </li>
      ))}
    </ul>
  )
}

function DiffBucket({
  meta,
  count,
  items,
}: {
  meta: (typeof DIFF_BUCKETS)[number]
  count: number
  items: DiffFinding[]
}) {
  const Icon = meta.icon
  return (
    <Card className={classNames('overflow-hidden', meta.classes)}>
      <div className="flex items-center gap-2 border-b border-surface-border/60 px-5 py-3.5">
        <Icon size={16} style={{ color: meta.accent }} />
        <h3 className={classNames('text-sm font-semibold', meta.text)}>{meta.label}</h3>
        <span className="text-2xl font-bold tabular-nums" style={{ color: meta.accent }}>
          {count}
        </span>
        <span className="ml-auto text-xs text-slate-500">{meta.help}</span>
      </div>
      <DiffFindingList items={items} />
    </Card>
  )
}

function CompareView({ scan }: { scan: ScanDetailType }) {
  const { data: scans } = usePolling<ScanSummary[]>(() => api.listScans(), undefined, [scan.id])
  const [baselineId, setBaselineId] = useState('')
  const [diff, setDiff] = useState<ScanDiff | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Baselines = every other scan, newest-first (the list is already sorted).
  const baselines = useMemo(
    () => (scans ?? []).filter((s) => s.id !== scan.id),
    [scans, scan.id],
  )

  useEffect(() => {
    if (!baselineId) {
      setDiff(null)
      setError(null)
      return
    }
    let active = true
    setLoading(true)
    setError(null)
    api
      .getDiff(scan.id, baselineId)
      .then((d) => active && setDiff(d))
      .catch((e) => active && setError(e instanceof Error ? e.message : 'Could not load diff.'))
      .finally(() => active && setLoading(false))
    return () => {
      active = false
    }
  }, [scan.id, baselineId])

  return (
    <div className="space-y-6">
      <Card className="p-5">
        <div className="flex flex-wrap items-center gap-3">
          <GitCompare size={16} className="text-slate-400" />
          <h2 className="text-sm font-semibold text-slate-200">Compare against a baseline</h2>
          <p className="w-full text-xs text-slate-500 sm:w-auto sm:flex-1">
            Pick an earlier scan of the same targets to see what was fixed, what is still open, and
            what is new in this rescan.
          </p>
          <select
            value={baselineId}
            onChange={(e) => setBaselineId(e.target.value)}
            className="min-w-[16rem] rounded-md border border-surface-border bg-surface-base px-2.5 py-1.5 text-sm text-slate-200 focus:border-blue-500 focus:outline-none"
          >
            <option value="">Select baseline scan...</option>
            {baselines.map((s) => (
              <option key={s.id} value={s.id}>
                {(s.name || s.id) + ' (' + formatDate(s.started) + ')'}
              </option>
            ))}
          </select>
        </div>
      </Card>

      {!baselineId ? (
        <Card>
          <EmptyState
            icon={<GitCompare size={32} />}
            title="No baseline selected"
            message="Choose a baseline scan above to compare it against this rescan."
          />
        </Card>
      ) : loading && !diff ? (
        <div className="space-y-4">
          <Skeleton className="h-16" />
          <Skeleton className="h-48" />
        </div>
      ) : error ? (
        <Card>
          <ErrorState title="Could not compare scans" message={error} onRetry={() => setBaselineId(baselineId)} />
        </Card>
      ) : diff ? (
        <>
          <Card className="p-5">
            <p className="text-sm text-slate-400">
              <span className="font-medium text-slate-200">{diff.rescan_name || diff.rescan_id}</span>
              {' vs baseline '}
              <span className="font-medium text-slate-200">
                {diff.baseline_name || diff.baseline_id}
              </span>
            </p>
            <p className="mt-2 text-lg font-semibold text-slate-100">
              <span className="text-emerald-400">{diff.counts.fixed} fixed</span>
              <span className="text-slate-600">{' · '}</span>
              <span className="text-orange-400">{diff.counts.still_open} still open</span>
              <span className="text-slate-600">{' · '}</span>
              <span className="text-blue-400">{diff.counts.new} new</span>
            </p>
          </Card>
          <div className="space-y-4">
            {DIFF_BUCKETS.map((meta) => (
              <DiffBucket
                key={meta.key}
                meta={meta}
                count={diff.counts[meta.key]}
                items={diff[meta.key]}
              />
            ))}
          </div>
        </>
      ) : null}
    </div>
  )
}

// ---------- Done view ----------

function ExportButtons({ id }: { id: string }) {
  const toast = useToast()
  const [busy, setBusy] = useState<string | null>(null)

  async function handleExport(format: 'xlsx' | 'evidence') {
    setBusy(format)
    try {
      const res = await fetch(api.exportUrl(id, format))
      if (!res.ok) {
        let msg = `Export failed (${res.status})`
        try {
          const body = await res.json()
          if (body?.error) msg = body.error
        } catch {
          // keep generic message
        }
        toast.error(msg)
        return
      }
      const blob = await res.blob()
      const disposition = res.headers.get('Content-Disposition') || ''
      const match = disposition.match(/filename="?([^"]+)"?/)
      const filename = match ? match[1] : `${id}-${format}`
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      toast.success('Export downloaded.')
    } catch {
      toast.error('Export failed: could not reach the server.')
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="flex items-center gap-2">
      <button
        onClick={() => handleExport('xlsx')}
        disabled={busy !== null}
        className="inline-flex items-center gap-2 rounded-md border border-surface-border bg-surface-raised px-3 py-2 text-sm font-medium text-slate-200 hover:bg-surface-hover disabled:opacity-50"
      >
        {busy === 'xlsx' ? (
          <Loader2 size={15} className="animate-spin" />
        ) : (
          <FileSpreadsheet size={15} />
        )}
        Export XLSX
      </button>
      <button
        onClick={() => handleExport('evidence')}
        disabled={busy !== null}
        className="inline-flex items-center gap-2 rounded-md border border-surface-border bg-surface-raised px-3 py-2 text-sm font-medium text-slate-200 hover:bg-surface-hover disabled:opacity-50"
      >
        {busy === 'evidence' ? (
          <Loader2 size={15} className="animate-spin" />
        ) : (
          <Archive size={15} />
        )}
        Export Evidence
      </button>
    </div>
  )
}

function SummaryCard({ severity, count }: { severity: Severity; count: number }) {
  return (
    <Card className="p-4">
      <div className="flex items-center gap-2">
        <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: SEVERITY_COLORS[severity] }} />
        <span className="text-xs font-medium uppercase tracking-wide text-slate-500">
          {SEVERITY_LABEL[severity]}
        </span>
      </div>
      <p className="mt-2 text-2xl font-bold tabular-nums" style={{ color: SEVERITY_COLORS[severity] }}>
        {count}
      </p>
    </Card>
  )
}

function DoneView({ scan }: { scan: ScanDetailType }) {
  const severity = scan.severity ?? emptySeverity()
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
        {SEVERITY_ORDER.map((s) => (
          <SummaryCard key={s} severity={s} count={severity[s] || 0} />
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="p-5">
          <h2 className="mb-4 text-sm font-semibold text-slate-200">Severity Breakdown</h2>
          <SeverityDonut severity={severity} />
          <div className="mt-4 border-t border-surface-border pt-4">
            <SeverityLegend severity={severity} />
          </div>
        </Card>
        <Card className="p-5 lg:col-span-2">
          <h2 className="mb-4 text-sm font-semibold text-slate-200">Scan Summary</h2>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <SummaryRow label="Status" value={<StatusBadge status={scan.status} />} />
            <SummaryRow label="Template" value={scan.config?.template ?? '-'} />
            <SummaryRow label="Rules Fired" value={scan.rules_fired ? String(scan.rules_fired) : '-'} />
            <SummaryRow label="Hosts" value={String(scan.host_count)} />
            <SummaryRow label="Findings" value={String(scan.finding_count)} />
            <SummaryRow label="Started" value={formatDate(scan.started)} />
            <SummaryRow
              label="Duration"
              value={durationBetween(scan.started, scan.finished)}
            />
            <SummaryRow
              label="Targets"
              value={
                <span className="font-mono text-xs text-slate-300">
                  {scan.config?.targets?.split(/[\n,]/).map((t) => t.trim()).filter(Boolean).join(', ') || '-'}
                </span>
              }
              full
            />
          </dl>
        </Card>
      </div>

      <ResultsTabs scan={scan} />
    </div>
  )
}

function ResultsTabs({ scan }: { scan: ScanDetailType }) {
  const [tab, setTab] = useState<"findings" | "hosts" | "compare">("findings")
  const tabBtn = (key: "findings" | "hosts" | "compare", label: string) => (
    <button
      onClick={() => setTab(key)}
      className={classNames(
        "-mb-px border-b-2 px-4 py-2 text-sm font-medium transition-colors",
        tab === key
          ? "border-blue-500 text-slate-100"
          : "border-transparent text-slate-500 hover:text-slate-300",
      )}
    >
      {label}
    </button>
  )
  return (
    <div className="space-y-4">
      <div className="flex gap-1 border-b border-surface-border">
        {tabBtn("findings", "Findings")}
        {tabBtn("hosts", "Hosts")}
        {tabBtn("compare", "Compare")}
      </div>
      {tab === "findings" ? (
        <FindingsTable id={scan.id} />
      ) : tab === "hosts" ? (
        <HostsTable id={scan.id} />
      ) : (
        <CompareView scan={scan} />
      )}
    </div>
  )
}

function SummaryRow({
  label,
  value,
  full,
}: {
  label: string
  value: React.ReactNode
  full?: boolean
}) {
  return (
    <div className={classNames(full && 'col-span-2')}>
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-0.5 text-slate-200">{value}</dd>
    </div>
  )
}

// ---------- Page ----------

export default function ScanDetail() {
  const { id = '' } = useParams()
  // Poll the scan record so we know when a running scan flips to done/failed.
  const { data, loading, error, reload } = usePolling<ScanDetailType>(
    () => api.getScan(id),
    5000,
    [id],
  )

  const isRunning = data?.status === 'running'

  return (
    <>
      <TopBar
        title={data?.name || 'Scan Detail'}
        subtitle={id}
        action={
          <div className="flex items-center gap-2">
            {data && data.status !== 'running' && <ExportButtons id={id} />}
            <Link
              to="/scans"
              className="inline-flex items-center gap-2 rounded-md border border-surface-border bg-surface-raised px-3 py-2 text-sm font-medium text-slate-300 hover:bg-surface-hover"
            >
              <ArrowLeft size={15} />
              Back
            </Link>
          </div>
        }
      />
      <main className="p-8">
        {loading && !data ? (
          <div className="space-y-6">
            <Skeleton className="h-24" />
            <Skeleton className="h-48" />
            <Skeleton className="h-64" />
          </div>
        ) : error && !data ? (
          <Card>
            <ErrorState title="Could not load scan" message={error} onRetry={reload} />
          </Card>
        ) : !data ? (
          <Card>
            <EmptyState title="Scan not found" message="This scan does not exist." />
          </Card>
        ) : (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center gap-3">
              <StatusBadge status={data.status} />
              <span className="text-sm text-slate-400">
                Started {formatDate(data.started)}
              </span>
              {data.status !== 'running' && (
                <span className="text-sm text-slate-400">
                  Duration {durationBetween(data.started, data.finished)}
                </span>
              )}
            </div>
            {isRunning ? <RunningView id={id} /> : <DoneView scan={data} />}
            {data.status === 'failed' && (
              <Card className="border-red-500/30 bg-red-500/5 p-4">
                <p className="text-sm text-red-300">
                  This scan failed. Review the scan engine logs on the server for details.
                </p>
              </Card>
            )}
          </div>
        )}
      </main>
    </>
  )
}
