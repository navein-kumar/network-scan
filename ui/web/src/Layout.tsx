// App shell: fixed left sidebar with the logo + nav, plus the shared TopBar,
// PrimaryButton, and NewScanButton used by the pages.
import type { ReactNode } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  Plus,
  ListChecks,
  Settings as SettingsIcon,
  ShieldCheck,
  User,
  type LucideIcon,
} from 'lucide-react'
import { classNames } from './lib'
import { usePolling } from './hooks'
import { api } from './api'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  end: boolean
}

const NAV: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/scan/new', label: 'New Scan', icon: Plus, end: false },
  { to: '/scans', label: 'Scans', icon: ListChecks, end: false },
  { to: '/settings', label: 'Settings', icon: SettingsIcon, end: false },
]

function Sidebar() {
  const meta = usePolling(() => api.getMeta(), 300_000, [])

  return (
    <aside className="fixed inset-y-0 left-0 z-30 flex w-60 flex-col border-r border-surface-border bg-surface-panel">
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
      <nav className="flex-1 space-y-1 px-3 py-4">
        {NAV.map((item) => (
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
      </nav>
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
