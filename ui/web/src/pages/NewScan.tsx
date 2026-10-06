import { useEffect, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Rocket,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  ChevronDown,
  Loader2,
} from 'lucide-react'
import { api, ApiError } from '../api'
import type { Folder, ScanConfig, Template } from '../types'
import { classNames } from '../lib'
import { TopBar, PrimaryButton } from '../Layout'
import { Card } from '../ui'
import { useToast } from '../toast'

type PortMode = 'default' | 'all' | 'custom'

const TEMPLATES: Array<{ value: Template; label: string; desc: string }> = [
  { value: 'fast', label: 'Fast', desc: 'Top ports, quick assessment' },
  { value: 'standard', label: 'Standard', desc: 'Balanced default coverage' },
  { value: 'deep', label: 'Deep', desc: 'Thorough, deep TLS, all checks' },
]

// Shared input class, mined from the running UI.
const INPUT_CLASS =
  'w-full rounded-md border border-surface-border bg-surface-base px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500'

function FormCard({
  icon,
  title,
  description,
  children,
}: {
  icon: ReactNode
  title: string
  description?: string
  children: ReactNode
}) {
  return (
    <Card className="overflow-hidden">
      <div className="flex items-start gap-3 border-b border-surface-border px-6 py-4">
        <div className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-md bg-blue-600/15 text-blue-400">
          {icon}
        </div>
        <div>
          <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
          {description && <p className="text-xs text-slate-400">{description}</p>}
        </div>
      </div>
      <div className="space-y-5 px-6 py-5">{children}</div>
    </Card>
  )
}

function Field({
  label,
  hint,
  children,
}: {
  label: string
  hint?: string
  children: ReactNode
}) {
  return (
    <div>
      <label className="mb-1.5 block text-sm font-medium text-slate-300">{label}</label>
      {children}
      {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
    </div>
  )
}

function Toggle({
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

export default function NewScan() {
  const navigate = useNavigate()
  const toast = useToast()
  const [name, setName] = useState('')
  const [targets, setTargets] = useState('')
  const [template, setTemplate] = useState<Template>('standard')
  const [portMode, setPortMode] = useState<PortMode>('default')
  const [customPorts, setCustomPorts] = useState('')
  const [udpPorts, setUdpPorts] = useState('')
  const [skipUdp, setSkipUdp] = useState(false)
  const [skipNuclei, setSkipNuclei] = useState(false)
  const [folderID, setFolderID] = useState('default')
  const [folders, setFolders] = useState<Folder[]>([])
  const [deepTls, setDeepTls] = useState(false)
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [maxHosts, setMaxHosts] = useState(0)
  const [nmapIntensity, setNmapIntensity] = useState(0)
  const [forceService, setForceService] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [nameError, setNameError] = useState(false)
  const [targetsError, setTargetsError] = useState(false)

  // Pre-fill from the saved scan defaults.
  useEffect(() => {
    let alive = true
    api
      .getSettings()
      .then((s) => {
        if (!alive) return
        setTemplate(s.template ?? 'standard')
        setUdpPorts(s.udp_ports ?? '')
        setSkipUdp(!!s.skip_udp)
        setSkipNuclei(!!s.skip_nuclei)
        setMaxHosts(s.max_hosts ?? 0)
        const ports = (s.ports ?? '').trim()
        if (ports === '') setPortMode('default')
        else if (ports === 'all') setPortMode('all')
        else {
          setPortMode('custom')
          setCustomPorts(ports)
        }
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [])

  useEffect(() => {
    api.listFolders().then(setFolders).catch(() => {})
  }, [])

  function resolvePorts(): string {
    if (portMode === 'all') return 'all'
    if (portMode === 'custom') return customPorts.trim()
    return ''
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const trimmedName = name.trim()
    const trimmedTargets = targets.trim()
    const noName = trimmedName.length === 0
    const noTargets = trimmedTargets.length === 0
    setNameError(noName)
    setTargetsError(noTargets)
    if (noName || noTargets) {
      toast.error('Name and targets are required.')
      return
    }
    const config: ScanConfig = {
      name: trimmedName,
      targets: trimmedTargets,
      template,
      ports: resolvePorts(),
      udp_ports: udpPorts.trim(),
      skip_udp: skipUdp,
      skip_nuclei: skipNuclei,
      deep_tls: deepTls,
      max_hosts: Number.isFinite(maxHosts) ? Math.max(0, maxHosts) : 0,
      nmap_intensity: Math.max(0, Math.min(9, nmapIntensity)),
      force_service: forceService.trim(),
      folder_id: folderID,
    }
    setSubmitting(true)
    try {
      const res = await api.createScan(config)
      toast.success('Scan launched.')
      navigate(`/scan/${res.id}`)
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Failed to launch scan.')
      setSubmitting(false)
    }
  }

  return (
    <>
      <TopBar title="New Scan" subtitle="Configure and launch a vulnerability scan" />
      <main className="p-8">
        <form onSubmit={handleSubmit} className="mx-auto max-w-3xl space-y-6">
          <FormCard icon={<Rocket size={16} />} title="Scan Details">
            <Field label="Name" hint="A label to identify this scan.">
              <input
                value={name}
                onChange={(e) => {
                  setName(e.target.value)
                  if (nameError) setNameError(false)
                }}
                placeholder="e.g. Q2 Perimeter Sweep"
                className={classNames(INPUT_CLASS, nameError && 'border-red-500 ring-1 ring-red-500')}
              />
            </Field>
            <Field
              label="Targets"
              hint="IPs, CIDRs or hostnames. One per line or comma separated."
            >
              <textarea
                value={targets}
                onChange={(e) => {
                  setTargets(e.target.value)
                  if (targetsError) setTargetsError(false)
                }}
                rows={4}
                placeholder={'10.0.0.0/24\n192.168.1.10\nexample.com'}
                className={classNames(
                  INPUT_CLASS,
                  'resize-y font-mono text-xs',
                  targetsError && 'border-red-500 ring-1 ring-red-500',
                )}
              />
            </Field>
            <Field label="Template">
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                {TEMPLATES.map((t) => (
                  <button
                    key={t.value}
                    type="button"
                    onClick={() => setTemplate(t.value)}
                    className={classNames(
                      'rounded-md border px-3 py-2.5 text-left transition-colors',
                      template === t.value
                        ? 'border-blue-500 bg-blue-600/10'
                        : 'border-surface-border bg-surface-base hover:border-surface-hover',
                    )}
                  >
                    <div
                      className={classNames(
                        'text-sm font-semibold',
                        template === t.value ? 'text-blue-300' : 'text-slate-200',
                      )}
                    >
                      {t.label}
                    </div>
                    <div className="text-xs text-slate-500">{t.desc}</div>
                  </button>
                ))}
              </div>
            </Field>
            {folders.length > 1 && (
              <Field label="Project Folder" hint="Organise this scan under a folder.">
                <select
                  value={folderID}
                  onChange={(e) => setFolderID(e.target.value)}
                  className="w-full rounded-md border border-surface-border bg-surface-base px-3 py-2 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  {folders.map((f) => (
                    <option key={f.id} value={f.id}>{f.name}</option>
                  ))}
                </select>
              </Field>
            )}
          </FormCard>

          <FormCard
            icon={<Search size={16} />}
            title="Discovery"
            description="Control how hosts and ports are discovered."
          >
            <Field label="Port range">
              <div className="space-y-2">
                {(
                  [
                    { v: 'default', label: 'Default', desc: 'Top common ports' },
                    { v: 'all', label: 'All ports', desc: '1 to 65535' },
                    { v: 'custom', label: 'Custom', desc: 'Specify a range' },
                  ] as Array<{ v: PortMode; label: string; desc: string }>
                ).map((opt) => (
                  <label
                    key={opt.v}
                    className={classNames(
                      'flex cursor-pointer items-center gap-3 rounded-md border px-3 py-2 transition-colors',
                      portMode === opt.v
                        ? 'border-blue-500 bg-blue-600/10'
                        : 'border-surface-border hover:border-surface-hover',
                    )}
                  >
                    <input
                      type="radio"
                      name="portMode"
                      checked={portMode === opt.v}
                      onChange={() => setPortMode(opt.v)}
                      className="accent-blue-600"
                    />
                    <span className="text-sm font-medium text-slate-200">{opt.label}</span>
                    <span className="text-xs text-slate-500">{opt.desc}</span>
                  </label>
                ))}
              </div>
              {portMode === 'custom' && (
                <input
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                  placeholder="21-80,443,8000-8100"
                  className={classNames(INPUT_CLASS, 'mt-2 font-mono text-xs')}
                />
              )}
            </Field>
            <Field label="UDP ports" hint="Leave blank for the default UDP port set.">
              <input
                value={udpPorts}
                onChange={(e) => setUdpPorts(e.target.value)}
                placeholder="53,123,161"
                disabled={skipUdp}
                className={classNames(
                  INPUT_CLASS,
                  'font-mono text-xs',
                  skipUdp && 'cursor-not-allowed opacity-50',
                )}
              />
            </Field>
            <Field
              label="Concurrent hosts (parallel)"
              hint="0 = auto (Fast profile scans 8 at once). Set a number to force how many hosts run in parallel."
            >
              <input
                type="number"
                min={0}
                value={maxHosts || ''}
                onChange={(e) => setMaxHosts(parseInt(e.target.value, 10) || 0)}
                placeholder="0 = auto"
                className={classNames(INPUT_CLASS, 'font-mono text-xs')}
              />
            </Field>
            <div className="border-t border-surface-border pt-4">
              <Toggle
                checked={skipUdp}
                onChange={setSkipUdp}
                label="Skip UDP"
                hint="Disable UDP scanning entirely."
              />
            </div>
          </FormCard>

          <FormCard
            icon={<ShieldCheck size={16} />}
            title="Assessment"
            description="Vulnerability checks to run against discovered services."
          >
            <Toggle
              checked={skipNuclei}
              onChange={setSkipNuclei}
              label="Skip nxc"
              hint="Do not run the nxc template engine."
            />
            <div className="border-t border-surface-border pt-4">
              <Toggle
                checked={deepTls}
                onChange={setDeepTls}
                label="Deep TLS / testssl"
                hint="Run an in-depth TLS configuration assessment."
              />
            </div>
          </FormCard>

          <Card className="overflow-hidden">
            <button
              type="button"
              onClick={() => setAdvancedOpen((v) => !v)}
              className="flex w-full items-center justify-between px-6 py-4 text-left"
            >
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-md bg-blue-600/15 text-blue-400">
                  <SlidersHorizontal size={16} />
                </div>
                <div>
                  <h2 className="text-sm font-semibold text-slate-100">Advanced</h2>
                  <p className="text-xs text-slate-400">Tuning and overrides (optional).</p>
                </div>
              </div>
              <ChevronDown
                size={18}
                className={classNames('text-slate-400 transition-transform', advancedOpen && 'rotate-180')}
              />
            </button>
            {advancedOpen && (
              <div className="space-y-5 border-t border-surface-border px-6 py-5">
                <Field label="Max hosts" hint="0 means no limit.">
                  <input
                    type="number"
                    min={0}
                    value={maxHosts}
                    onChange={(e) => setMaxHosts(parseInt(e.target.value, 10) || 0)}
                    className={INPUT_CLASS}
                  />
                </Field>
                <Field label={`Nmap intensity: ${nmapIntensity}`} hint="0 (default) to 9 (most aggressive).">
                  <input
                    type="range"
                    min={0}
                    max={9}
                    step={1}
                    value={nmapIntensity}
                    onChange={(e) => setNmapIntensity(parseInt(e.target.value, 10))}
                    className="w-full accent-blue-600"
                  />
                  <div className="mt-1 flex justify-between text-[10px] text-slate-600">
                    <span>0</span>
                    <span>9</span>
                  </div>
                </Field>
                <Field
                  label="Force service"
                  hint="Override service detection, e.g. 8888=ssh,55555=http"
                >
                  <input
                    value={forceService}
                    onChange={(e) => setForceService(e.target.value)}
                    placeholder="8888=ssh,55555=http"
                    className={classNames(INPUT_CLASS, 'font-mono text-xs')}
                  />
                </Field>
              </div>
            )}
          </Card>

          <div className="flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={() => navigate('/scans')}
              className="rounded-md border border-surface-border bg-surface-raised px-4 py-2 text-sm font-medium text-slate-300 hover:bg-surface-hover"
            >
              Cancel
            </button>
            <PrimaryButton
              type="submit"
              disabled={submitting}
              icon={
                submitting ? <Loader2 size={16} className="animate-spin" /> : <Rocket size={16} />
              }
            >
              {submitting ? 'Launching...' : 'Launch Scan'}
            </PrimaryButton>
          </div>
        </form>
      </main>
    </>
  )
}
