import { useQuery } from '@tanstack/react-query'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, titleCase } from '../api'
import { ErrorState, LoadingState, MetricCard, PageHeader } from '../components/Ui'
import type { OverviewMetrics } from '../types'

const severityOrder = ['critical', 'high', 'medium', 'low', 'informational']

export function OverviewPage() {
  const query = useQuery({
    queryKey: ['overview'],
    queryFn: () => api<OverviewMetrics>('/overview'),
    refetchInterval: 30_000,
  })

  if (query.isLoading) return <LoadingState />
  if (query.error) return <ErrorState message={query.error.message} />
  if (!query.data) return null

  const data = query.data
  const severityData = severityOrder.map((severity) => ({
    severity: titleCase(severity),
    incidents: data.incidents_by_severity[severity] ?? 0,
  }))
  const incidentCount = Object.values(data.incidents_by_severity).reduce((sum, count) => sum + count, 0)

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Live local operations"
        title="SOC Overview"
        description="Synthetic signals moving through ingestion, detection, correlation, and investigation."
      />

      <section className="metric-grid" aria-label="SOC key metrics">
        <MetricCard label="Open incidents" value={data.open_incidents} detail={`${incidentCount} total correlated cases`} />
        <MetricCard label="Active alerts" value={data.total_alerts} detail={`${data.total_events} normalized events`} />
        <MetricCard
          label="Mean detection latency"
          value={`${data.mean_detection_latency_ms.toFixed(0)} ms`}
          detail="Local evaluator processing latency"
        />
        <MetricCard
          label="ATT&CK tactics observed"
          value={data.attack_tactics_observed.length}
          detail="Mapped from generated alerts"
        />
      </section>

      <div className="content-grid two-thirds">
        <section className="panel chart-panel" aria-labelledby="alerts-over-time-title">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">Signal volume</span>
              <h2 id="alerts-over-time-title">Alerts over time</h2>
            </div>
            <span className="panel-value">{data.total_alerts} total</span>
          </div>
          <p className="sr-only">
            {data.alerts_over_time.map((point) => `${point.date}: ${point.count} alerts`).join('; ')}
          </p>
          <div className="chart" aria-hidden="true">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.alerts_over_time} margin={{ top: 12, right: 12, left: -22, bottom: 0 }}>
                <defs>
                  <linearGradient id="alertFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#31d2b3" stopOpacity={0.38} />
                    <stop offset="100%" stopColor="#31d2b3" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#1b3043" strokeDasharray="3 4" vertical={false} />
                <XAxis dataKey="date" stroke="#7892a8" tickLine={false} axisLine={false} />
                <YAxis stroke="#7892a8" allowDecimals={false} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: '#0d1d2d', border: '1px solid #28435a', borderRadius: 8 }} />
                <Area type="monotone" dataKey="count" stroke="#31d2b3" strokeWidth={2} fill="url(#alertFill)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel chart-panel" aria-labelledby="severity-title">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">Case priority</span>
              <h2 id="severity-title">Incidents by severity</h2>
            </div>
          </div>
          <p className="sr-only">
            {severityData.map((point) => `${point.severity}: ${point.incidents}`).join('; ')}
          </p>
          <div className="chart" aria-hidden="true">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} layout="vertical" margin={{ top: 8, right: 10, left: 28, bottom: 0 }}>
                <CartesianGrid stroke="#1b3043" strokeDasharray="3 4" horizontal={false} />
                <XAxis type="number" allowDecimals={false} stroke="#7892a8" axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="severity" width={88} stroke="#a9bac8" axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: '#0d1d2d', border: '1px solid #28435a', borderRadius: 8 }} />
                <Bar dataKey="incidents" fill="#5e8bff" radius={[0, 5, 5, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
      </div>

      <div className="content-grid equal">
        <section className="panel" aria-labelledby="entities-title">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">Investigation focus</span>
              <h2 id="entities-title">Top entities</h2>
            </div>
          </div>
          <div className="compact-list">
            {data.top_entities.map((item, index) => (
              <div className="compact-row" key={item.entity}>
                <span className="rank">{String(index + 1).padStart(2, '0')}</span>
                <span className="entity-text">{item.entity}</span>
                <strong>{item.count}</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="panel" aria-labelledby="tactics-title">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">ATT&CK context</span>
              <h2 id="tactics-title">Tactics observed</h2>
            </div>
          </div>
          <div className="tactic-list">
            {data.attack_tactics_observed.map((item) => (
              <div className="tactic-row" key={item.tactic}>
                <span>{item.tactic}</span>
                <div className="progress-track" aria-hidden="true">
                  <span style={{ width: `${Math.min(100, item.count * 15)}%` }} />
                </div>
                <strong>{item.count}</strong>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  )
}

