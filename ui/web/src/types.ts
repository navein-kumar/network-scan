// Types matching API_CONTRACT.md exactly.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export type SeverityCounts = Record<Severity, number>

export type ScanStatus = 'running' | 'done' | 'failed' | 'error' | 'paused' | 'stopped'

export type Template = 'fast' | 'standard' | 'deep'

export interface ScanConfig {
  name: string
  targets: string
  template: Template
  ports: string
  udp_ports: string
  skip_udp: boolean
  skip_nuclei: boolean
  deep_tls: boolean
  max_hosts: number
  nmap_intensity: number
  force_service: string
}

// Persisted scan defaults used to pre-fill the New Scan form
// (GET/PUT /api/settings).
export interface Settings {
  template: Template
  ports: string
  udp_ports: string
  skip_udp: boolean
  skip_nuclei: boolean
  max_hosts: number
}

export interface ScanSummary {
  id: string
  name: string
  status: ScanStatus
  progress: number
  started: string
  finished: string | null
  host_count: number
  finding_count: number
  severity: SeverityCounts
}

export interface ScanDetail extends ScanSummary {
  config: ScanConfig
  hosts_done: number
  hosts_total: number
}

export interface Finding {
  rule_id: string
  title: string
  severity: Severity
  host: string
  port: number
  source: string
  evidence: string
}

export interface DiffFinding {
  rule_id: string
  title: string
  severity: Severity
  host: string
  port: number
}

export interface ScanDiff {
  baseline_id: string
  rescan_id: string
  baseline_name: string
  rescan_name: string
  counts: {
    fixed: number
    still_open: number
    new: number
  }
  fixed: DiffFinding[]
  still_open: DiffFinding[]
  new: DiffFinding[]
}

export interface HostPort {
  port: number
  proto: string
  service: string
  version: string
}

export interface HostInfo {
  host: string
  ports: HostPort[]
  finding_count: number
  severity: SeverityCounts
}

export interface DepInfo {
  name: string
  present: boolean
  path?: string
}

export interface Meta {
  profiles: string[]
  driver_count: number
  plugin_count: number
  deps: DepInfo[]
}

export interface CreateScanResponse {
  id: string
  status: string
}

// SSE event payloads
export interface ProgressHost {
  host: string
  phase: string
  percent: number
  status: 'running' | 'done' | 'lost'
}

export interface ProgressEvent {
  overall: number
  hosts_done: number
  hosts_total: number
  hosts: ProgressHost[]
}

export interface FindingEvent {
  rule_id: string
  title: string
  severity: Severity
  host: string
  port: number
}

export interface LogEvent {
  line: string
}

export interface DoneEvent {
  status: ScanStatus
  severity: SeverityCounts
}

export function emptySeverity(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
}
