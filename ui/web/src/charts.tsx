// Recharts-based severity visualizations: a donut (scan detail), a bar chart
// (dashboard), plus a plain legend grid. All share the same data builder and
// the dark custom tooltip.
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  CartesianGrid,
  XAxis,
  YAxis,
} from 'recharts'
import { SEVERITY_COLORS, SEVERITY_LABEL, severityTotal } from './lib'
import { SEVERITY_ORDER } from './types'
import type { Severity, SeverityCounts } from './types'

interface Datum {
  key: Severity
  name: string
  value: number
  color: string
}

function buildData(severity: SeverityCounts): Datum[] {
  return SEVERITY_ORDER.map((s) => ({
    key: s,
    name: SEVERITY_LABEL[s],
    value: severity[s] || 0,
    color: SEVERITY_COLORS[s],
  }))
}

interface TooltipProps {
  active?: boolean
  payload?: Array<{ value: number; payload: Datum }>
}

function ChartTooltip({ active, payload }: TooltipProps) {
  if (!active || !payload || payload.length === 0) return null
  const item = payload[0]
  return (
    <div className="rounded-md border border-surface-border bg-surface-raised px-3 py-1.5 text-xs shadow-card">
      <span className="font-medium text-slate-200">{item.payload.name}</span>
      <span className="ml-2 font-semibold tabular-nums" style={{ color: item.payload.color }}>
        {item.value}
      </span>
    </div>
  )
}

export function SeverityDonut({ severity }: { severity: SeverityCounts }) {
  const data = buildData(severity).filter((d) => d.value > 0)
  const total = severityTotal(severity)
  if (total === 0) {
    return (
      <div className="flex h-[220px] items-center justify-center text-sm text-slate-500">
        No findings to chart
      </div>
    )
  }
  return (
    <div className="relative h-[220px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius={62}
            outerRadius={92}
            paddingAngle={2}
            stroke="none"
          >
            {data.map((d) => (
              <Cell key={d.key} fill={d.color} />
            ))}
          </Pie>
          <Tooltip content={<ChartTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold tabular-nums text-white">{total}</span>
        <span className="text-xs uppercase tracking-wide text-slate-500">Findings</span>
      </div>
    </div>
  )
}

export function SeverityBar({ severity }: { severity: SeverityCounts }) {
  const data = buildData(severity)
  if (severityTotal(severity) === 0) {
    return (
      <div className="flex h-[220px] items-center justify-center text-sm text-slate-500">
        No findings to chart
      </div>
    )
  }
  return (
    <div className="h-[220px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#222c3d" vertical={false} />
          <XAxis
            dataKey="name"
            tick={{ fill: '#94a3b8', fontSize: 12 }}
            axisLine={{ stroke: '#222c3d' }}
            tickLine={false}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: '#94a3b8', fontSize: 12 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: '#ffffff08' }} />
          <Bar dataKey="value" radius={[4, 4, 0, 0]} maxBarSize={56}>
            {data.map((d) => (
              <Cell key={d.key} fill={d.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

export function SeverityLegend({ severity }: { severity: SeverityCounts }) {
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
      {SEVERITY_ORDER.map((s) => (
        <div key={s} className="flex items-center gap-2 text-sm">
          <span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: SEVERITY_COLORS[s] }} />
          <span className="text-slate-400">{SEVERITY_LABEL[s]}</span>
          <span className="ml-auto font-semibold tabular-nums text-slate-200">
            {severity[s] || 0}
          </span>
        </div>
      ))}
    </div>
  )
}
