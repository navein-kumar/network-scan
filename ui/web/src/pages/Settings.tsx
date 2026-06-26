import { useEffect, useState, type ReactNode } from 'react'
import {
  Cpu,
  Boxes,
  Layers,
  SlidersHorizontal,
  CircleCheck,
  CircleX,
  Save,
  Loader2,
  TriangleAlert,
  Wrench,
} from 'lucide-react'
import { api, ApiError } from '../api'
import type { DepInfo, Settings as SettingsType, Template } from '../types'
import { usePolling } from '../hooks'
import { classNames } from '../lib'
import { TopBar, PrimaryButton } from '../Layout'
import { Card, EmptyState, ErrorState, Skeleton } from '../ui'
import { useToast } from '../toast'

const INPUT_CLASS =
  'w-full rounded-md border border-surface-border bg-surface-base px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500'

const TEMPLATES: Array<{ value: Template; label: string }> = [
  { value: 'fast', label: 'Fast' },
  { value: 'standard', label: 'Standard' },
  { value: 'deep', label: 'Deep' },
]

function StatCard({
  icon,
  label,
  value,
  accent,
}: {
  icon: ReactNode
  label: string
  value: ReactNode
  accent: string
}) {
  return (
    <Card className="p-5">
      <div className="flex items-center gap-3">
        <div
          className="flex h-10 w-10 items-center justify-center rounded-lg"
          style={{ backgroundColor: `${accent}1f`, color: accent }}
        >
          {icon}
        </div>
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
          <p className="text-xl font-bold tabular-nums text-white">{value}</p>
        </div>
      </div>
    </Card>
  )
}

function DepsTable({ deps }: { deps: DepInfo[] }) {
  if (deps.length === 0) {
    return <EmptyState title="No dependencies reported" />
  }

  const missingRequired = deps.filter((d) => !d.present && d.required)
  const missingOptional = deps.filter((d) => !d.present && !d.required)

  return (
    <div>
      {missingRequired.length > 0 && (
        <div className="flex items-start gap-3 border-b border-red-500/20 bg-red-500/10 px-5 py-3.5">
          <TriangleAlert size={16} className="mt-0.5 shrink-0 text-red-400" />
          <div>
            <p className="text-sm font-semibold text-red-300">
              {missingRequired.length} required tool{missingRequired.length > 1 ? 's' : ''} missing
            </p>
            <p className="mt-0.5 text-xs text-red-400/80">
              {missingRequired.map((d) => d.name).join(', ')} — run{' '}
              <code className="font-mono">install-prereqs.sh</code> to install automatically
            </p>
          </div>
        </div>
      )}
      {missingOptional.length > 0 && missingRequired.length === 0 && (
        <div className="flex items-start gap-3 border-b border-amber-500/20 bg-amber-500/10 px-5 py-3.5">
          <TriangleAlert size={16} className="mt-0.5 shrink-0 text-amber-400" />
          <p className="text-xs text-amber-300">
            <span className="font-semibold">{missingOptional.length} optional tool{missingOptional.length > 1 ? 's' : ''} not installed</span>
            {' '}— {missingOptional.map((d) => d.name).join(', ')}. Some scan features will be skipped.
          </p>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-surface-border text-left text-xs uppercase tracking-wide text-slate-500">
              <th className="px-5 py-3 font-medium">Tool</th>
              <th className="px-5 py-3 font-medium">Role</th>
              <th className="px-5 py-3 font-medium">Status</th>
              <th className="px-5 py-3 font-medium">Path</th>
            </tr>
          </thead>
          <tbody>
            {deps.map((d) => (
              <tr
                key={d.name}
                className={classNames(
                  'border-b border-surface-border/60 last:border-0 hover:bg-surface-hover/40',
                  !d.present && d.required ? 'bg-red-500/5' : '',
                )}
              >
                <td className="px-5 py-3">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-semibold text-slate-100">{d.name}</span>
                    {d.required && (
                      <span className="rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide bg-blue-500/15 text-blue-400 border border-blue-500/20">
                        required
                      </span>
                    )}
                  </div>
                </td>
                <td className="px-5 py-3 text-xs text-slate-400 max-w-xs">{d.description || '-'}</td>
                <td className="px-5 py-3">
                  {d.present ? (
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-300">
                      <CircleCheck size={13} />
                      Present
                    </span>
                  ) : d.required ? (
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-red-500/40 bg-red-500/15 px-2.5 py-0.5 text-xs font-semibold text-red-300">
                      <TriangleAlert size={13} />
                      Missing
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-0.5 text-xs font-medium text-amber-400">
                      <CircleX size={13} />
                      Not installed
                    </span>
                  )}
                </td>
                <td className="px-5 py-3 font-mono text-xs text-slate-400">{d.path || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function DefaultsToggle({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
  hint?: string
}) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-4">
      <div>
        <div className="text-sm font-medium text-slate-300">{label}</div>
        {hint && <div className="text-xs text-slate-500">{hint}</div>}
      </div>
      <div className="inline-flex shrink-0 overflow-hidden rounded-md border border-slate-600 text-xs font-semibold">
        <button
          type="button"
          onClick={() => onChange(false)}
          className={classNames(
            'px-5 py-2 transition-colors',
            checked
              ? 'bg-transparent text-slate-500 hover:text-slate-300'
              : 'bg-slate-600 text-white',
          )}
        >
          Off
        </button>
        <button
          type="button"
          onClick={() => onChange(true)}
          className={classNames(
            'px-5 py-2 transition-colors',
            checked
              ? 'bg-emerald-500 text-white'
              : 'bg-transparent text-slate-500 hover:text-slate-300',
          )}
        >
          On
        </button>
      </div>
    </label>
  )
}

function ScanDefaultsForm() {
  const toast = useToast()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [ports, setPorts] = useState('')
  const [udpPorts, setUdpPorts] = useState('')
  const [skipUdp, setSkipUdp] = useState(false)
  const [skipNuclei, setSkipNuclei] = useState(false)
  const [maxHosts, setMaxHosts] = useState(0)
  const [template, setTemplate] = useState<Template>('standard')

  function apply(s: SettingsType) {
    setPorts(s.ports ?? '')
    setUdpPorts(s.udp_ports ?? '')
    setSkipUdp(!!s.skip_udp)
    setSkipNuclei(!!s.skip_nuclei)
    setMaxHosts(s.max_hosts ?? 0)
    setTemplate(s.template ?? 'standard')
  }

  function load() {
    setLoading(true)
    setError(null)
    api
      .getSettings()
      .then((s) => apply(s))
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load defaults'))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
  }, [])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const payload: SettingsType = {
      ports: ports.trim(),
      udp_ports: udpPorts.trim(),
      skip_udp: skipUdp,
      skip_nuclei: skipNuclei,
      max_hosts: Number.isFinite(maxHosts) ? Math.max(0, maxHosts) : 0,
      template,
    }
    setSaving(true)
    try {
      apply(await api.putSettings(payload))
      toast.success('Scan defaults saved.')
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Failed to save defaults.')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="space-y-3 p-5">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-10" />
        ))}
      </div>
    )
  }

  if (error) {
    return <ErrorState title="Could not load scan defaults" message={error} onRetry={load} />
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-5 p-5">
      <div>
        <label className="mb-1.5 block text-sm font-medium text-slate-300">Default ports</label>
        <input
          value={ports}
          onChange={(e) => setPorts(e.target.value)}
          placeholder="blank = top common ports, or e.g. 1-1000 / all"
          className={classNames(INPUT_CLASS, 'font-mono text-xs')}
        />
        <p className="mt-1 text-xs text-slate-500">
          Pre-fills the New Scan custom port range. Leave blank for the default port set.
        </p>
      </div>
      <div>
        <label className="mb-1.5 block text-sm font-medium text-slate-300">Default UDP ports</label>
        <input
          value={udpPorts}
          onChange={(e) => setUdpPorts(e.target.value)}
          placeholder="53,123,161"
          className={classNames(INPUT_CLASS, 'font-mono text-xs')}
        />
      </div>
      <div>
        <label className="mb-1.5 block text-sm font-medium text-slate-300">
          Default max concurrent hosts
        </label>
        <input
          type="number"
          min={0}
          value={maxHosts || ''}
          onChange={(e) => setMaxHosts(parseInt(e.target.value, 10) || 0)}
          placeholder="0 = auto"
          className={classNames(INPUT_CLASS, 'font-mono text-xs')}
        />
        <p className="mt-1 text-xs text-slate-500">
          0 = auto. Number of hosts to scan in parallel.
        </p>
      </div>
      <div>
        <label className="mb-1.5 block text-sm font-medium text-slate-300">Default template</label>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
          {TEMPLATES.map((t) => (
            <button
              key={t.value}
              type="button"
              onClick={() => setTemplate(t.value)}
              className={classNames(
                'rounded-md border px-3 py-2.5 text-center text-sm font-semibold transition-colors',
                template === t.value
                  ? 'border-blue-500 bg-blue-600/10 text-blue-300'
                  : 'border-surface-border bg-surface-base text-slate-200 hover:border-surface-hover',
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>
      <div className="space-y-4 border-t border-surface-border pt-4">
        <DefaultsToggle
          checked={skipUdp}
          onChange={setSkipUdp}
          label="Skip UDP by default"
          hint="Disable UDP scanning on new scans."
        />
        <DefaultsToggle
          checked={skipNuclei}
          onChange={setSkipNuclei}
          label="Skip nuclei by default"
          hint="Do not run the nuclei template engine on new scans."
        />
      </div>
      <div className="flex items-center justify-end border-t border-surface-border pt-4">
        <PrimaryButton
          type="submit"
          disabled={saving}
          icon={saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
        >
          {saving ? 'Saving...' : 'Save defaults'}
        </PrimaryButton>
      </div>
    </form>
  )
}

export default function Settings() {
  const meta = usePolling(() => api.getMeta(), undefined, [])
  const depsQuery = usePolling(() => api.getDeps(), undefined, [])
  const metaData = meta.data
  const deps = depsQuery.data ?? metaData?.deps ?? []

  const totalTools = deps.length
  const missingTools = deps.filter((d) => !d.present).length
  const missingRequired = deps.filter((d) => !d.present && d.required).length
  const toolsAccent = missingRequired > 0 ? '#ef4444' : missingTools > 0 ? '#f59e0b' : '#10b981'

  return (
    <>
      <TopBar title="Settings" subtitle="Engine capabilities and dependencies" />
      <main className="space-y-6 p-8">
        <section>
          <h2 className="mb-3 text-sm font-semibold text-slate-200">Engine</h2>
          {meta.loading && !metaData ? (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-20" />
              ))}
            </div>
          ) : meta.error && !metaData ? (
            <Card>
              <ErrorState
                title="Could not load engine metadata"
                message={meta.error}
                onRetry={meta.reload}
              />
            </Card>
          ) : (
            <>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
                <StatCard
                  icon={<Cpu size={20} />}
                  label="Drivers"
                  value={metaData?.driver_count ?? 0}
                  accent="#3b82f6"
                />
                <StatCard
                  icon={<Boxes size={20} />}
                  label="Plugins"
                  value={metaData?.plugin_count ?? 0}
                  accent="#0ea5e9"
                />
                <StatCard
                  icon={<Layers size={20} />}
                  label="Profiles"
                  value={metaData?.profiles?.length ?? 0}
                  accent="#8b5cf6"
                />
                <StatCard
                  icon={<Wrench size={20} />}
                  label={missingTools > 0 ? `Tools (${missingTools} missing)` : 'Tools'}
                  value={totalTools > 0 ? `${totalTools - missingTools} / ${totalTools}` : '—'}
                  accent={toolsAccent}
                />
              </div>
              {metaData?.profiles && metaData.profiles.length > 0 && (
                <div className="mt-4 flex flex-wrap items-center gap-2">
                  <span className="text-xs text-slate-500">Available profiles:</span>
                  {metaData.profiles.map((p) => (
                    <span
                      key={p}
                      className="rounded-md border border-surface-border bg-surface-raised px-2.5 py-1 font-mono text-xs text-slate-300"
                    >
                      {p}
                    </span>
                  ))}
                </div>
              )}
            </>
          )}
        </section>

        <section>
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-200">
            Dependencies
            {missingRequired > 0 && (
              <span className="inline-flex items-center gap-1 rounded-full border border-red-500/40 bg-red-500/15 px-2 py-0.5 text-[11px] font-semibold text-red-300">
                <TriangleAlert size={11} />
                {missingRequired} / {totalTools} required missing
              </span>
            )}
            {missingRequired === 0 && missingTools > 0 && (
              <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-400">
                <TriangleAlert size={11} />
                {missingTools} / {totalTools} not installed
              </span>
            )}
            {missingTools === 0 && totalTools > 0 && (
              <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-400">
                <CircleCheck size={11} />
                {totalTools} / {totalTools} present
              </span>
            )}
          </h2>
          <Card>
            {depsQuery.loading && !depsQuery.data && !metaData ? (
              <div className="space-y-2 p-5">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-10" />
                ))}
              </div>
            ) : depsQuery.error && deps.length === 0 ? (
              <ErrorState
                title="Could not load dependencies"
                message={depsQuery.error}
                onRetry={depsQuery.reload}
              />
            ) : (
              <DepsTable deps={deps} />
            )}
          </Card>
        </section>

        <section>
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-200">
            <SlidersHorizontal size={15} className="text-blue-400" />
            Scan defaults
          </h2>
          <p className="mb-3 text-xs text-slate-400">
            Default values used to pre-fill the New Scan form. You can still override them per scan.
          </p>
          <Card>
            <ScanDefaultsForm />
          </Card>
        </section>
      </main>
    </>
  )
}
