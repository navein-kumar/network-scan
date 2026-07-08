import { useRef, useState, type ChangeEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Upload, RefreshCw, Eye, Repeat, Download, Trash2, Loader2, Radar,
  Square, Pause, Play, FolderPlus, Folder, FolderOpen, X, Check, ChevronDown,
} from 'lucide-react'
import { api, ApiError } from '../api'
import type { Folder as FolderType, ScanSummary } from '../types'
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
  const { data: folders, reload: reloadFolders } = usePolling<FolderType[]>(() => api.listFolders(), 30000)

  const [deleting, setDeleting] = useState<string | null>(null)
  const [exporting, setExporting] = useState<string | null>(null)
  const [importing, setImporting] = useState(false)
  const [rescanning, setRescanning] = useState<string | null>(null)
  const [stopping, setStopping] = useState<string | null>(null)
  const [pausing, setPausing] = useState<string | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [bulkDeleting, setBulkDeleting] = useState(false)
  const [activeFolderID, setActiveFolderID] = useState<string | null>(null)
  const [creatingFolder, setCreatingFolder] = useState(false)
  const [newFolderName, setNewFolderName] = useState('')
  const [moveMenuID, setMoveMenuID] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const scans = data ?? []
  const folderList = folders ?? []

  const visibleScans = activeFolderID
    ? scans.filter((s) => (s.folder_id || 'default') === activeFolderID)
    : scans

  const allSelected = visibleScans.length > 0 && visibleScans.every((s) => selected.has(s.id))
  const someSelected = visibleScans.some((s) => selected.has(s.id))
  const selectedCount = visibleScans.filter((s) => selected.has(s.id)).length

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function toggleAll() {
    if (allSelected) {
      setSelected((prev) => {
        const next = new Set(prev)
        visibleScans.forEach((s) => next.delete(s.id))
        return next
      })
    } else {
      setSelected((prev) => {
        const next = new Set(prev)
        visibleScans.forEach((s) => next.add(s.id))
        return next
      })
    }
  }

  async function handleBulkDelete() {
    const ids = [...selected].filter((id) => visibleScans.some((s) => s.id === id))
    if (ids.length === 0) return
    if (!window.confirm(`Delete ${ids.length} scan(s)? This cannot be undone.`)) return
    setBulkDeleting(true)
    try {
      const res = await api.bulkDelete(ids)
      toast.success(`Deleted ${res.deleted} scan(s).`)
      setSelected(new Set())
      reload()
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Bulk delete failed.')
    } finally {
      setBulkDeleting(false)
    }
  }

  async function handleCreateFolder() {
    const name = newFolderName.trim()
    if (!name) return
    try {
      await api.createFolder(name)
      setNewFolderName('')
      setCreatingFolder(false)
      reloadFolders()
      toast.success(`Folder "${name}" created.`)
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Failed to create folder.')
    }
  }

  async function handleDeleteFolder(id: string, name: string) {
    if (id === 'default') return
    if (!window.confirm(`Delete folder "${name}"? Scans will be moved to Default.`)) return
    try {
      await api.deleteFolder(id)
      if (activeFolderID === id) setActiveFolderID(null)
      reloadFolders()
      reload()
      toast.success('Folder deleted.')
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Failed to delete folder.')
    }
  }

  async function handleMoveToFolder(scanID: string, folderID: string) {
    setMoveMenuID(null)
    try {
      await api.moveScan(scanID, folderID)
      reload()
      toast.success('Scan moved.')
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Failed to move scan.')
    }
  }

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
        try { const b = await res.json(); if (b?.error) msg = b.error } catch {}
        toast.error(msg)
        return
      }
      const blob = await res.blob()
      const disposition = res.headers.get('Content-Disposition') || ''
      const match = disposition.match(/filename="?([^"]+)"?/)
      const filename = match ? match[1] : `${id}.fsbundle.zip`
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = filename
      document.body.appendChild(a); a.click(); a.remove()
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
      toast.success('Rescan started. When it finishes, open the Compare tab to see fixed vs still-open.')
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
      setSelected((prev) => { const n = new Set(prev); n.delete(id); return n })
      reload()
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Failed to delete scan.')
    } finally {
      setDeleting(null)
    }
  }

  const activeName = activeFolderID
    ? (folderList.find((f) => f.id === activeFolderID)?.name ?? 'Folder')
    : 'All Scans'

  return (
    <>
      <TopBar
        title={activeName}
        subtitle={activeFolderID ? 'Filtered by folder' : 'All vulnerability scans'}
        action={
          <div className="flex items-center gap-2">
            <input ref={fileRef} type="file" accept=".zip,application/zip" className="hidden" onChange={handleImport} />
            {someSelected && (
              <button
                onClick={handleBulkDelete}
                disabled={bulkDeleting}
                className="inline-flex items-center gap-2 rounded-md border border-red-700 bg-red-900/30 px-3 py-2 text-sm font-medium text-red-300 hover:bg-red-900/60 disabled:opacity-50"
              >
                {bulkDeleting ? <Loader2 size={15} className="animate-spin" /> : <Trash2 size={15} />}
                Delete {selectedCount}
              </button>
            )}
            <button
              onClick={() => fileRef.current?.click()}
              disabled={importing}
              className="inline-flex items-center gap-2 rounded-md border border-surface-border bg-surface-raised px-3 py-2 text-sm font-medium text-slate-300 hover:bg-surface-hover disabled:opacity-50"
            >
              {importing ? <Loader2 size={15} className="animate-spin" /> : <Upload size={15} />}
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
      <main className="flex gap-0">
        {/* Folder Sidebar */}
        <aside className="w-52 shrink-0 border-r border-surface-border min-h-[calc(100vh-4rem)] p-3">
          <p className="mb-2 px-2 text-[10px] font-semibold uppercase tracking-widest text-slate-500">Projects</p>
          <button
            onClick={() => setActiveFolderID(null)}
            className={classNames(
              'flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors',
              activeFolderID === null
                ? 'bg-blue-600/15 text-blue-300'
                : 'text-slate-400 hover:bg-surface-hover hover:text-slate-200',
            )}
          >
            <FolderOpen size={15} />
            All Scans
            <span className="ml-auto text-xs tabular-nums opacity-60">{scans.length}</span>
          </button>
          {folderList.map((folder) => {
            const count = scans.filter((s) => (s.folder_id || 'default') === folder.id).length
            return (
              <div key={folder.id} className="group relative">
                <button
                  onClick={() => setActiveFolderID(folder.id)}
                  className={classNames(
                    'flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors',
                    activeFolderID === folder.id
                      ? 'bg-blue-600/15 text-blue-300'
                      : 'text-slate-400 hover:bg-surface-hover hover:text-slate-200',
                  )}
                >
                  <Folder size={15} />
                  <span className="flex-1 truncate text-left">{folder.name}</span>
                  <span className="text-xs tabular-nums opacity-60">{count}</span>
                </button>
                {folder.id !== 'default' && (
                  <button
                    onClick={() => handleDeleteFolder(folder.id, folder.name)}
                    className="absolute right-1 top-1 hidden rounded p-0.5 text-slate-600 hover:text-red-400 group-hover:block"
                    title="Delete folder"
                  >
                    <X size={12} />
                  </button>
                )}
              </div>
            )
          })}
          <div className="mt-3 border-t border-surface-border pt-3">
            {creatingFolder ? (
              <div className="space-y-1.5 px-1">
                <input
                  autoFocus
                  value={newFolderName}
                  onChange={(e) => setNewFolderName(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') handleCreateFolder(); if (e.key === 'Escape') { setCreatingFolder(false); setNewFolderName('') } }}
                  placeholder="Folder name"
                  className="w-full rounded border border-surface-border bg-surface-base px-2 py-1 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
                />
                <div className="flex gap-1">
                  <button onClick={handleCreateFolder} className="flex-1 rounded bg-blue-600 py-1 text-xs text-white hover:bg-blue-500">
                    <Check size={11} className="mx-auto" />
                  </button>
                  <button onClick={() => { setCreatingFolder(false); setNewFolderName('') }} className="flex-1 rounded bg-surface-raised py-1 text-xs text-slate-400 hover:text-slate-200">
                    <X size={11} className="mx-auto" />
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={() => setCreatingFolder(true)}
                className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-xs text-slate-500 hover:bg-surface-hover hover:text-slate-300"
              >
                <FolderPlus size={13} />
                New folder
              </button>
            )}
          </div>
        </aside>

        {/* Scan Table */}
        <div className="flex-1 p-8">
          <Card>
            {loading && !data ? (
              <ScansSkeleton />
            ) : error && !data ? (
              <ErrorState title="Could not load scans" message={error} onRetry={reload} />
            ) : visibleScans.length === 0 ? (
              <EmptyState
                icon={<Radar size={36} />}
                title="No scans yet"
                message={activeFolderID ? 'No scans in this folder.' : 'Launch your first scan to begin assessing your network.'}
                action={
                  <Link to="/scan/new" className="rounded-md bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500">
                    New Scan
                  </Link>
                }
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-surface-border text-left text-xs uppercase tracking-wide text-slate-500">
                      <th className="px-3 py-3">
                        <input
                          type="checkbox"
                          checked={allSelected}
                          onChange={toggleAll}
                          className="accent-blue-500"
                          title="Select all"
                        />
                      </th>
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
                    {visibleScans.map((s) => (
                      <tr
                        key={s.id}
                        className={classNames(
                          'border-b border-surface-border/60 last:border-0 hover:bg-surface-hover/40',
                          selected.has(s.id) && 'bg-blue-600/5',
                        )}
                      >
                        <td className="px-3 py-3">
                          <input
                            type="checkbox"
                            checked={selected.has(s.id)}
                            onChange={() => toggleSelect(s.id)}
                            className="accent-blue-500"
                          />
                        </td>
                        <td className="px-5 py-3">
                          <Link to={`/scan/${s.id}`} className="font-medium text-slate-100 hover:text-blue-300">
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
                        <td className="whitespace-nowrap px-5 py-3 text-slate-400">{formatDate(s.started)}</td>
                        <td className="px-5 py-3 tabular-nums text-slate-300">{s.host_count}</td>
                        <td className="px-5 py-3">
                          <div className="flex items-center gap-3">
                            <span className={classNames('font-semibold tabular-nums', s.finding_count > 0 ? 'text-slate-100' : 'text-slate-500')}>
                              {s.finding_count}
                            </span>
                            <div className="w-24">
                              <SeverityMiniBar severity={s.severity} />
                            </div>
                          </div>
                        </td>
                        <td className="px-5 py-3">
                          <div className="flex items-center justify-end gap-1">
                            <button onClick={() => navigate(`/scan/${s.id}`)} title="View" className="rounded-md p-1.5 text-slate-400 hover:bg-surface-hover hover:text-slate-200">
                              <Eye size={16} />
                            </button>
                            {/* Move to folder */}
                            <div className="relative">
                              <button
                                onClick={() => setMoveMenuID(moveMenuID === s.id ? null : s.id)}
                                title="Move to folder"
                                className="rounded-md p-1.5 text-slate-400 hover:bg-surface-hover hover:text-slate-200"
                              >
                                <ChevronDown size={16} />
                              </button>
                              {moveMenuID === s.id && (
                                <div className="absolute right-0 top-full z-50 mt-1 min-w-[140px] rounded-md border border-surface-border bg-surface-panel py-1 shadow-lg">
                                  <p className="px-3 py-1 text-[10px] uppercase tracking-wide text-slate-500">Move to</p>
                                  {folderList.map((fl) => (
                                    <button
                                      key={fl.id}
                                      onClick={() => handleMoveToFolder(s.id, fl.id)}
                                      className={classNames(
                                        'flex w-full items-center gap-2 px-3 py-1.5 text-xs hover:bg-surface-hover',
                                        (s.folder_id || 'default') === fl.id ? 'text-blue-300' : 'text-slate-300',
                                      )}
                                    >
                                      <Folder size={12} />
                                      {fl.name}
                                    </button>
                                  ))}
                                </div>
                              )}
                            </div>
                            {s.status === 'running' && (
                              <>
                                <button onClick={() => handlePause(s.id)} disabled={pausing === s.id} title="Pause scan" className="rounded-md p-1.5 text-slate-400 hover:bg-surface-hover hover:text-amber-300 disabled:opacity-50">
                                  {pausing === s.id ? <Loader2 size={16} className="animate-spin" /> : <Pause size={16} />}
                                </button>
                                <button onClick={() => handleStop(s.id)} disabled={stopping === s.id} title="Stop scan" className="rounded-md p-1.5 text-slate-400 hover:bg-red-500/10 hover:text-red-300 disabled:opacity-50">
                                  {stopping === s.id ? <Loader2 size={16} className="animate-spin" /> : <Square size={16} />}
                                </button>
                              </>
                            )}
                            {s.status === 'paused' && (
                              <>
                                <button onClick={() => handleResume(s.id)} disabled={pausing === s.id} title="Resume scan" className="rounded-md p-1.5 text-slate-400 hover:bg-surface-hover hover:text-green-300 disabled:opacity-50">
                                  {pausing === s.id ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
                                </button>
                                <button onClick={() => handleStop(s.id)} disabled={stopping === s.id} title="Stop scan" className="rounded-md p-1.5 text-slate-400 hover:bg-red-500/10 hover:text-red-300 disabled:opacity-50">
                                  {stopping === s.id ? <Loader2 size={16} className="animate-spin" /> : <Square size={16} />}
                                </button>
                              </>
                            )}
                            {(s.status === 'done' || s.status === 'stopped' || s.status === 'error') && (
                              <button onClick={() => handleRescan(s.id)} disabled={rescanning === s.id} title="Rescan" className="rounded-md p-1.5 text-slate-400 hover:bg-surface-hover hover:text-sky-300 disabled:opacity-50">
                                {rescanning === s.id ? <Loader2 size={16} className="animate-spin" /> : <Repeat size={16} />}
                              </button>
                            )}
                            <button onClick={() => handleExport(s.id)} disabled={exporting === s.id} title="Export bundle" className="rounded-md p-1.5 text-slate-400 hover:bg-surface-hover hover:text-slate-200 disabled:opacity-50">
                              {exporting === s.id ? <Loader2 size={16} className="animate-spin" /> : <Download size={16} />}
                            </button>
                            <button onClick={() => handleDelete(s.id, s.name)} disabled={deleting === s.id} title="Delete" className="rounded-md p-1.5 text-slate-400 hover:bg-red-500/10 hover:text-red-300 disabled:opacity-50">
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
        </div>
      </main>
    </>
  )
}
