import { useMemo, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Activity, Server, Bug, ShieldAlert, Radar, ArrowUpRight } from 'lucide-react'
import { api } from '../api'
import type { ScanSummary } from '../types'
import { usePolling } from '../hooks'
import { formatDate, classNames, sumSeverity } from '../lib'
import { TopBar, NewScanButton } from '../Layout'
import { Card, EmptyState, ErrorState, Skeleton, StatusBadge, ProgressBar, SeverityMiniBar } from '../ui'
import { SeverityDonut, SeverityBar, SeverityLegend } from '../charts'

function StatCard({
  label,
  value,
  icon,
  accent,
}: {
  label: string
  value: ReactNode
  icon: ReactNode
  accent: string
}) {
  return (
    <Card className="p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
          <p className="mt-2 text-3xl font-bold tabular-nums text-white">{value}</p>
        </div>
        <div
          className="flex h-10 w-10 items-center justify-center rounded-lg"
          style={{ backgroundColor: `${accent}1f`, color: accent }}
        >
          {icon}
        </div>
      </div>
    </Card>
  )
}

function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-28" />
        ))}
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Skeleton className="h-72" />
        <Skeleton className="h-72 lg:col-span-2" />
      </div>
      <Skeleton className="h-64" />
    </div>
  )
}

export default function Dashboard() {
  const { data, loading, error, reload } = usePolling<ScanSummary[]>(() => api.listScans(), 10000)
  const scans = data ?? []

  const stats = useMemo(() => {
    const totalScans = scans.length
    const hostsScanned = scans.reduce((sum, s) => sum + (s.host_count || 0), 0)
    const findingCount = scans.reduce((sum, s) => sum + (s.finding_count || 0), 0)
    const severity = sumSeverity(scans.map((s) => s.severity))
    return { totalScans, hostsScanned, findingCount, criticals: severity.critical, severity }
  }, [scans])

  const recent = useMemo(() => scans.slice(0, 8), [scans])

  return (
    <>
      <TopBar
        title="Dashboard"
        subtitle="Overview of scan activity and findings"
        action={<NewScanButton />}
      />
      <main className="p-8">
        {loading && !data ? (
          <DashboardSkeleton />
        ) : error && !data ? (
          <Card>
            <ErrorState title="Could not load dashboard" message={error} onRetry={reload} />
          </Card>
        ) : (
          <div className="space-y-6">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <StatCard
                label="Total Scans"
                value={stats.totalScans}
                icon={<Activity size={20} />}
                accent="#3b82f6"
              />
              <StatCard
                label="Hosts Scanned"
                value={stats.hostsScanned}
                icon={<Server size={20} />}
                accent="#0ea5e9"
              />
              <StatCard
                label="Total Findings"
                value={stats.findingCount}
                icon={<Bug size={20} />}
                accent="#d97706"
              />
              <StatCard
                label="Criticals"
                value={stats.criticals}
                icon={<ShieldAlert size={20} />}
                accent="#b91c1c"
              />
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card className="p-5 lg:col-span-1">
                <h2 className="mb-4 text-sm font-semibold text-slate-200">Findings by Severity</h2>
                <SeverityDonut severity={stats.severity} />
                <div className="mt-4 border-t border-surface-border pt-4">
                  <SeverityLegend severity={stats.severity} />
                </div>
              </Card>
              <Card className="p-5 lg:col-span-2">
                <h2 className="mb-4 text-sm font-semibold text-slate-200">Severity Distribution</h2>
                <SeverityBar severity={stats.severity} />
              </Card>
            </div>

            <Card>
              <div className="flex items-center justify-between border-b border-surface-border px-5 py-4">
                <h2 className="text-sm font-semibold text-slate-200">Recent Scans</h2>
                <Link
                  to="/scans"
                  className="inline-flex items-center gap-1 text-xs font-medium text-blue-400 hover:text-blue-300"
                >
                  View all
                  <ArrowUpRight size={14} />
                </Link>
              </div>
              {recent.length === 0 ? (
                <EmptyState
                  icon={<Radar size={36} />}
                  title="No scans yet"
                  message="Launch your first scan to start finding vulnerabilities across your network."
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
                        <th className="px-5 py-3 font-medium">Findings</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recent.map((s) => (
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
                          </td>
                          <td className="px-5 py-3">
                            <StatusBadge status={s.status} />
                          </td>
                          <td className="px-5 py-3">
                            <div className="flex w-40 items-center gap-2">
                              <ProgressBar value={s.status === 'done' ? 100 : s.progress} />
                              <span className="w-9 text-right text-xs tabular-nums text-slate-400">
                                {s.status === 'done' ? 100 : Math.round(s.progress)}%
                              </span>
                            </div>
                          </td>
                          <td className="whitespace-nowrap px-5 py-3 text-slate-400">
                            {formatDate(s.started)}
                          </td>
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
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          </div>
        )}
      </main>
    </>
  )
}
