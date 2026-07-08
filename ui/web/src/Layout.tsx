// App shell: fixed left sidebar with logo + nav + folders, plus shared TopBar helpers.
import { useState, type ReactNode } from 'react'
import { NavLink, useNavigate, useSearchParams } from 'react-router-dom'
import {
  LayoutDashboard,
  Plus,
  ListChecks,
  Settings as SettingsIcon,
  ShieldCheck,
  User,
  Folder,
  FolderOpen,
  FolderPlus,
  X,
  Check,
} from 'lucide-react'
import { classNames } from './lib'
import { usePolling } from './hooks'
import { api } from './api'
import type { Folder as FolderType } from './types'
import { useToast } from './toast'

function FolderNav({ folders, onCreated }: { folders: FolderType[]; onCreated: () => void }) {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const toast = useToast()
  const [creating, setCreating] = useState(false)
  const [name, setName] = useState('')
  const active = params.get('folder')

  async function handleCreate() {
    const n = name.trim()
    if (!n) return
    try {
      await api.createFolder(n)
      setName('')
      setCreating(false)
      onCreated()
      toast.success(`Folder "${n}" created.`)
    } catch {
      toast.error('Failed to create folder.')
    }
  }

  async function handleDelete(id: string, folderName: string) {
    if (id === 'default') return
    if (!window.confirm(`Delete folder "${folderName}"? Scans will be moved to Default.`)) return
    try {
      await api.deleteFolder(id)
      onCreated() // reload
      if (active === id) navigate('/scans')
      toast.success('Folder deleted.')
    } catch {
      toast.error('Failed to delete folder.')
    }
  }

  return (
    <div className="mt-1">
      <p className="mb-1 px-3 pt-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600">
        Folders
      </p>
      {/* All Scans */}
      <NavLink
        to="/scans"
        end
        className={classNames(
          'flex items-center gap-2.5 rounded-md px-3 py-1.5 text-sm transition-colors',
          !active
            ? 'bg-blue-600/15 text-blue-300'
            : 'text-slate-400 hover:bg-surface-hover hover:text-slate-200',
        )}
      >
        <FolderOpen size={15} />
        <span className="flex-1">All Scans</span>
      </NavLink>

      {/* Per-folder links */}
      {folders.map((f) => {
        const isActive = active === f.id
        return (
          <div key={f.id} className="group relative">
            <NavLink
              to={`/scans?folder=${f.id}`}
              className={classNames(
                'flex items-center gap-2.5 rounded-md px-3 py-1.5 text-sm transition-colors',
                isActive
                  ? 'bg-blue-600/15 text-blue-300'
                  : 'text-slate-400 hover:bg-surface-hover hover:text-slate-200',
              )}
            >
              <Folder size={15} />
              <span className="flex-1 truncate">{f.name}</span>
            </NavLink>
            {f.id !== 'default' && (
              <button
                onClick={() => handleDelete(f.id, f.name)}
                className="absolute right-1.5 top-1/2 -translate-y-1/2 hidden rounded p-0.5 text-slate-600 hover:text-red-400 group-hover:block"
                title="Delete folder"
              >
                <X size={11} />
              </button>
            )}
          </div>
        )
      })}

      {/* New folder */}
      {creating ? (
        <div className="mx-2 mt-1 space-y-1">
          <input
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleCreate()
              if (e.key === 'Escape') { setCreating(false); setName('') }
            }}
            placeholder="Folder name"
            className="w-full rounded border border-surface-border bg-surface-base px-2 py-1 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
          />
          <div className="flex gap-1">
            <button onClick={handleCreate} className="flex flex-1 items-center justify-center rounded bg-blue-600 py-0.5 text-xs text-white hover:bg-blue-500">
              <Check size={11} />
            </button>
            <button onClick={() => { setCreating(false); setName('') }} className="flex flex-1 items-center justify-center rounded bg-surface-raised py-0.5 text-xs text-slate-400">
              <X size={11} />
            </button>
          </div>
        </div>
      ) : (
        <button
          onClick={() => setCreating(true)}
          className="flex w-full items-center gap-2.5 rounded-md px-3 py-1.5 text-xs text-slate-600 hover:bg-surface-hover hover:text-slate-400"
        >
          <FolderPlus size={14} />
          New Folder
        </button>
      )}
    </div>
  )
}

function Sidebar() {
  const meta = usePolling(() => api.getMeta(), 300_000, [])
  const { data: folders, reload: reloadFolders } = usePolling<FolderType[]>(
    () => api.listFolders(),
    30_000,
    [],
  )
  const navigate = useNavigate()

  return (
    <aside className="fixed inset-y-0 left-0 z-30 flex w-60 flex-col border-r border-surface-border bg-surface-panel">
      {/* Logo */}
      <div className="flex h-16 items-center gap-2.5 border-b border-surface-border px-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-blue-600/20 text-blue-400">
          <ShieldCheck size={20} />
        </div>
        <div className="leading-tight">
          <div className="text-base font-bold tracking-tight text-white">fastscan</div>
          <div className="text-[10px] font-medium uppercase tracking-widest text-slate-500">
            Vulnerability Scanner
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-3 py-4">
        {/* Top-level nav items */}
        {[
          { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
          { to: '/scan/new', label: 'New Scan', icon: Plus, end: false },
          { to: '/settings', label: 'Settings', icon: SettingsIcon, end: false },
        ].map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              classNames(
                'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-blue-600/15 text-blue-300'
                  : 'text-slate-400 hover:bg-surface-hover hover:text-slate-200',
              )
            }
          >
            <item.icon size={18} />
            {item.label}
          </NavLink>
        ))}

        {/* Scans section with folders */}
        <div className="mt-1">
          <button
            onClick={() => navigate('/scans')}
            className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-slate-400 hover:bg-surface-hover hover:text-slate-200"
          >
            <ListChecks size={18} />
            Scans
          </button>
          <FolderNav folders={folders ?? []} onCreated={reloadFolders} />
        </div>
      </nav>

      {/* Footer */}
      <div className="border-t border-surface-border px-5 py-4 space-y-1.5">
        {meta.data?.version && (
          <p className="text-[11px] font-mono text-slate-500">v{meta.data.version}</p>
        )}
        {meta.data?.user && (
          <div className="flex items-center gap-1.5">
            <User size={11} className="text-slate-500 shrink-0" />
            <p className="text-[11px] text-slate-400 truncate">{meta.data.user}</p>
          </div>
        )}
      </div>
    </aside>
  )
}

export function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-surface-base">
      <Sidebar />
      <div className="pl-60">{children}</div>
    </div>
  )
}

export function TopBar({
  title,
  subtitle,
  action,
}: {
  title: string
  subtitle?: string
  action?: ReactNode
}) {
  return (
    <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-surface-border bg-surface-base/80 px-8 backdrop-blur">
      <div>
        <h1 className="text-lg font-semibold text-white">{title}</h1>
        {subtitle && <p className="text-xs text-slate-400">{subtitle}</p>}
      </div>
      {action}
    </header>
  )
}

export function PrimaryButton({
  children,
  onClick,
  type = 'button',
  disabled,
  icon,
}: {
  children: ReactNode
  onClick?: () => void
  type?: 'button' | 'submit'
  disabled?: boolean
  icon?: ReactNode
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className="inline-flex items-center gap-2 rounded-md bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
    >
      {icon}
      {children}
    </button>
  )
}

export function NewScanButton() {
  const navigate = useNavigate()
  return (
    <PrimaryButton icon={<Plus size={16} />} onClick={() => navigate('/scan/new')}>
      New Scan
    </PrimaryButton>
  )
}
