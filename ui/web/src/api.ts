// Typed fetch wrappers for every endpoint + an EventSource helper for the stream.
import type {
  CreateScanResponse,
  DepInfo,
  Finding,
  HostInfo,
  Meta,
  ScanConfig,
  ScanDetail,
  ScanDiff,
  ScanSummary,
  Settings,
} from './types'

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      headers: { 'Content-Type': 'application/json' },
      ...init,
    })
  } catch {
    throw new ApiError('Network error: could not reach the server.', 0)
  }
  if (!res.ok) {
    let msg = `Request failed (${res.status})`
    try {
      const body = await res.json()
      if (body && typeof body.error === 'string') msg = body.error
    } catch {
      // non-JSON error body, keep generic message
    }
    throw new ApiError(msg, res.status)
  }
  if (res.status === 204) return undefined as T
  const text = await res.text()
  if (!text) return undefined as T
  return JSON.parse(text) as T
}

export const api = {
  getMeta: () => request<Meta>('/api/meta'),
  getDeps: () => request<DepInfo[]>('/api/deps'),

  listScans: () => request<ScanSummary[]>('/api/scans'),
  getScan: (id: string) => request<ScanDetail>(`/api/scans/${encodeURIComponent(id)}`),
  getFindings: (id: string) =>
    request<Finding[]>(`/api/scans/${encodeURIComponent(id)}/findings`),
  getHosts: (id: string) => request<HostInfo[]>(`/api/scans/${encodeURIComponent(id)}/hosts`),
  getDiff: (id: string, baselineId: string) =>
    request<ScanDiff>(
      `/api/scans/${encodeURIComponent(id)}/diff?baseline=${encodeURIComponent(baselineId)}`,
    ),
  getEvidence: async (id: string, ruleId: string): Promise<string> => {
    const res = await fetch(
      `/api/scans/${encodeURIComponent(id)}/evidence/${encodeURIComponent(ruleId)}`,
    )
    if (!res.ok) throw new ApiError("evidence not available", res.status)
    return res.text()
  },

  createScan: (config: ScanConfig) =>
    request<CreateScanResponse>('/api/scans', {
      method: 'POST',
      body: JSON.stringify(config),
    }),

  deleteScan: (id: string) =>
    request<{ ok: boolean }>(`/api/scans/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  // Re-run a scan with the same config; the Compare tab can then diff the two.
  rescan: (id: string) =>
    request<CreateScanResponse>(`/api/scans/${encodeURIComponent(id)}/rescan`, {
      method: 'POST',
    }),

  // Upload an exported scan bundle (.fsbundle.zip). FormData sets its own
  // multipart boundary, so the JSON Content-Type header is cleared here.
  importScan: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return request<CreateScanResponse>('/api/scans/import', {
      method: 'POST',
      headers: {},
      body: form,
    })
  },

  getSettings: () => request<Settings>('/api/settings'),
  putSettings: (settings: Settings) =>
    request<Settings>('/api/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    }),

  stopScan: (id: string) =>
    request<{ status: string }>(`/api/scans/${encodeURIComponent(id)}/stop`, { method: 'POST' }),

  pauseScan: (id: string) =>
    request<{ status: string }>(`/api/scans/${encodeURIComponent(id)}/pause`, { method: 'POST' }),

  resumeScan: (id: string) =>
    request<{ status: string }>(`/api/scans/${encodeURIComponent(id)}/resume`, { method: 'POST' }),

  exportUrl: (id: string, format: 'xlsx' | 'docx' | 'evidence' | 'bundle') =>
    `/api/scans/${encodeURIComponent(id)}/export?format=${format}`,
}

// EventSource helper for the live scan stream. Reconnect is handled by the caller.
export interface StreamHandlers {
  onProgress?: (e: MessageEvent) => void
  onFinding?: (e: MessageEvent) => void
  onLog?: (e: MessageEvent) => void
  onDone?: (e: MessageEvent) => void
  onError?: (e: Event) => void
  onOpen?: (e: Event) => void
}

export function openScanStream(id: string, handlers: StreamHandlers): EventSource {
  const es = new EventSource(`/api/scans/${encodeURIComponent(id)}/stream`)
  if (handlers.onOpen) es.addEventListener('open', handlers.onOpen)
  if (handlers.onProgress) es.addEventListener('progress', handlers.onProgress as EventListener)
  if (handlers.onFinding) es.addEventListener('finding', handlers.onFinding as EventListener)
  if (handlers.onLog) es.addEventListener('log', handlers.onLog as EventListener)
  if (handlers.onDone) es.addEventListener('done', handlers.onDone as EventListener)
  if (handlers.onError) es.addEventListener('error', handlers.onError)
  return es
}
