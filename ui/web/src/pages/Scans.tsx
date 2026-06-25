import { useRef, useState, type ChangeEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Upload, RefreshCw, Eye, Repeat, Download, Trash2, Loader2, Radar, Square, Pause, Play } from 'lucide-react'
import { api, ApiError } from '../api'
import type { ScanSummary } from '../types'
import { usePolling } from '../hooks'
import { classNames, formatDate } from '../lib'
import { TopBar, NewScanButton } from '../Layout'
import { Card, EmptyState, ErrorState, Skeleton, StatusBadge, ProgressBar, SeverityMiniBar } from '../ui'
import { useToast } from '../toast'

function ScansSkeleton() {
  return (
    <div className="space-y-2 p-5">
      {Array.from({ length: 6 }).map((_, i) => (
        <Skeleton key={i} className="h-12" />
      ))}
    </div>
  )
}

export default function Scans() {
  const navigate = useNavigate()
  const toast = useToast()
  const { data, loading, error, reload } = usePolling<ScanSummary[]>(() => api.listScans(), 5000)
  const [deleting, setDeleting] = useState<string | null>(null)
  const [exporting, setExporting] = useState<string | null>(null)
  const [importing, setImporting] = useState(false)
  const [rescanning, setRescanning] = useState<string | null>(null)
  const [stopping, setStopping] = useState<string | null>(null)
  const [pausing, setPausing] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const scans = data ?? []

  async function handleImport(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    setImporting(true)
    try {
      const res = await api.importScan(file)
      toast.success('Scan imported.')
      reload()
      navigate(`/scan/${res.id}`)
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Failed to import scan.')
    } finally {
      setImporting(false)
    }
  }

  async function handleExport(id: string) {
    setExporting(id)
    try {
      const res = await fetch(api.exportUrl(id, 'bundle'))
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
      const filename = match ? match[1] : `${id}.fsbundle.zip`
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      toast.success('Bundle downloaded.')
    } catch {
      toast.error('Export failed: could not reach the server.')
    } finally {
      setExporting(null)
    }
  }

  async function handleRescan(id: string) {
    setRescanning(id)
    try {
      const res = await api.rescan(id)
      toast.success(
        'Rescan started. When it finishes, open the Compare tab to see fixed vs still-open.',
      )
      reload()
      navigate(`/scan/${res.id}`)
    } catch {
      toast.error('Rescan failed: could not start the scan.')
    } finally {
      setRescanning(null)
    }
  }

  async function handleStop(id: string) {
    setStopping(id)
    try {
      await api.stopScan(id)
      toast.success('Scan stopped.')
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Failed to stop scan.')
    } finally {
      setStopping(null)
    }
  }

  async function handlePause(id: string) {
    setPausing(id)
    try {
      await api.pauseScan(id)
      toast.success('Scan paused.')
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Failed to pause scan.')
    } finally {
      setPausing(null)
    }
  }

  async function handleResume(id: string) {
    setPausing(id)
    try {
      await api.resumeScan(id)
      toast.success('Scan resumed.')
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Failed to resume scan.')
    } finally {
      setPausing(null)
    }
  }

  async function handleDelete(id: string, name: string) {
    if (!window.confirm(`Delete scan "${name || id}"? This cannot be undone.`)) return
    setDeleting(id)
    try {
      await api.deleteScan(id)
      toast.success('Scan deleted.')
      reload()
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Failed to delete scan.')
    } finally {
      setDeleting(null)
    }
  }

  return (
    <>
      <TopBar
        title="Scans"
        subtitle="All vulnerability scans"
        action={
          <div className="flex items-center gap-2">
            <input
              ref={fileRef}
              type="file"
              accept=".zip,application/zip"
              className="hidden"
              onChange={handleImport}
            />
            <button
              onClick={() => fileRef.current?.click()}
              disabled={importing}
              className="inline-flex items-center gap-2 rounded-md border border-surface-border bg-surface-raised px-3 py-2 text-sm font-medium text-slate-300 hover:bg-surface-hover disabled:opacity-50"
            >
              {importing ? (
                <Loader2 size={15} className="animate-spin" />
              ) : (
                <Upload size={15} />
              )}
              Import scan
            </button>
            <button
              onClick={reload}
              className="inline-flex items-center gap-2 rounded-md border border-surface-border bg-surface-raised px-3 py-2 text-sm font-medium text-slate-300 hover:bg-surface-hover"
            >
              <RefreshCw size={15} />
              Refresh
            </button>
            <NewScanButton />
          </div>
        }
      />
      <main className="p-8">
        <Card>
          {loading && !data ? (
            <ScansSkeleton />
          ) : error && !data ? (
            <ErrorState title="Could not load scans" message={error} onRetry={reload} />
          ) : scans.length === 0 ? (
            <EmptyState
              icon={<Radar size={36} />}
              title="No scans yet"
              message="Launch your first scan to begin assessing your network."
              action={
                <Link
                  to="/scan/new"
                  className="rounded-md bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500"
                >
                  New Scan
                </Link>
              }
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-surface-border text-left text-xs uppercase tracking-wide text-slate-500">
                    <th className="px-5 py-3 font-medium">Name</th>
                    <th className="px-5 py-3 font-medium">Status</th>
                    <th className="px-5 py-3 font-medium">Progress</th>
                    <th className="px-5 py-3 font-medium">Started</th>
                    <th className="px-5 py-3 font-medium">Hosts</th>
                    <th className="px-5 py-3 font-medium">Findings</th>
                    <th className="px-5 py-3 text-right font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((s) => (
                    <tr
                      key={s.id}
                      className="border-b border-surface-border/60 last:border-0 hover:bg-surface-hover/40"
                    >
                      <td className="px-5 py-3">
                        <Link
                          to={`/scan/${s.id}`}
                          className="font-medium text-slate-100 hover:text-blue-300"
                        >
                          {s.name || s.id}
                        </Link>
                        <div className="font-mono text-[11px] text-slate-600">{s.id}</div>
                      </td>
                      <td className="px-5 py-3">
                        <StatusBadge status={s.status} />
                      </td>
                      <td className="px-5 py-3">
                        <div className="flex w-36 items-center gap-2">
                          <ProgressBar value={s.status === 'done' ? 100 : s.progress} />
                          <span className="w-9 text-right text-xs tabular-nums text-slate-400">
                            {s.status === 'done' ? 100 : Math.round(s.progress)}%
                          </span>
                        </div>
                      </td>
                      <td className="whitespace-nowrap px-5 py-3 text-slate-400">
                        {formatDate(s.started)}
                      </td>
                      <td className="px-5 py-3 tabular-nums text-slate-300">{s.host_count}</td>
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-3">
                          <span
                            className={classNames(
                              'font-semibold tabular-nums',
                              s.finding_count > 0 ? 'text-slate-100' : 'text-slate-500',
                            )}
                          >
                            {s.finding_count}
                          </span>
                          <div className="w-24">
                            <SeverityMiniBar severity={s.severity} />
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-3">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => navigate(`/scan/${s.id}`)}
                            title="View"
                            className="rounded-md p-1.5 text-slate-400 hover:bg-surface-hover hover:text-slate-200"
                          >
                            <Eye size={16} />
                          </button>
                          {s.status === 'running' && (
                            <>
                              <button
                                onClick={() => handlePause(s.id)}
                                disabled={pausing === s.id}
                                title="Pause scan"
                                className="rounded-md p-1.5 text-slate-400 hover:bg-surface-hover hover:text-amber-300 disabled:opacity-50"
                              >
                                {pausing === s.id ? <Loader2 size={16} className="animate-spin" /> : <Pause size={16} />}
                              </button>
                              <button
                                onClick={() => handleStop(s.id)}
                                disabled={stopping === s.id}
                                title="Stop scan"
                                className="rounded-md p-1.5 text-slate-400 hover:bg-red-500/10 hover:text-red-300 disabled:opacity-50"
                              >
                                {stopping === s.id ? <Loader2 size={16} className="animate-spin" /> : <Square size={16} />}
                              </button>
                            </>
                          )}
                          {s.status === 'paused' && (
                            <>
                              <button
                                onClick={() => handleResume(s.id)}
                                disabled={pausing === s.id}
                                title="Resume scan"
                                className="rounded-md p-1.5 text-slate-400 hover:bg-surface-hover hover:text-green-300 disabled:opacity-50"
                              >
                                {pausing === s.id ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
                              </button>
                              <button
                                onClick={() => handleStop(s.id)}
                                disabled={stopping === s.id}
                                title="Stop scan"
                                className="rounded-md p-1.5 text-slate-400 hover:bg-red-500/10 hover:text-red-300 disabled:opacity-50"
                              >
                                {stopping === s.id ? <Loader2 size={16} className="animate-spin" /> : <Square size={16} />}
                              </button>
                            </>
                          )}
                          {(s.status === 'done' || s.status === 'stopped' || s.status === 'error') && (
                            <button
                              onClick={() => handleRescan(s.id)}
                              disabled={rescanning === s.id}
                              title="Rescan (re-run with same config)"
                              className="rounded-md p-1.5 text-slate-400 hover:bg-surface-hover hover:text-sky-300 disabled:opacity-50"
                            >
                              {rescanning === s.id ? <Loader2 size={16} className="animate-spin" /> : <Repeat size={16} />}
                            </button>
                          )}
                          <button
                            onClick={() => handleExport(s.id)}
                            disabled={exporting === s.id}
                            title="Export bundle"
                            className="rounded-md p-1.5 text-slate-400 hover:bg-surface-hover hover:text-slate-200 disabled:opacity-50"
                          >
                            {exporting === s.id ? <Loader2 size={16} className="animate-spin" /> : <Download size={16} />}
                          </button>
                          <button
                            onClick={() => handleDelete(s.id, s.name)}
                            disabled={deleting === s.id}
                            title="Delete"
                            className="rounded-md p-1.5 text-slate-400 hover:bg-red-500/10 hover:text-red-300 disabled:opacity-50"
                          >
                            {deleting === s.id ? <Loader2 size={16} className="animate-spin" /> : <Trash2 size={16} />}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </main>
    </>
  )
}
