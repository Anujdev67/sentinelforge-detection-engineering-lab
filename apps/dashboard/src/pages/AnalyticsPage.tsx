import { useQuery } from '@tanstack/react-query'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api, formatTimestamp, titleCase } from '../api'
import { ErrorState, LoadingState, MetricCard, PageHeader, SeverityBadge } from '../components/Ui'
import type { AnalyticsSnapshot, Severity } from '../types'

export function AnalyticsPage() {
  const query = useQuery({
    queryKey: ['analytics'],
    queryFn: () => api<AnalyticsSnapshot>('/analytics'),
    refetchInterval: 30_000,
  })
  if (query.isLoading) return <LoadingState label="Analyzing SOC operations" />
  if (query.error) return <ErrorState message={query.error.message} />
  if (!query.data) return null
  const data = query.data

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Operational data analysis"
        title="SOC Analytics"
        description="Analyze synthetic telemetry volume, detection yield, correlation, entity risk, and local processing performance."
        actions={<span className="result-count">Updated {formatTimestamp(data.generated_at)}</span>}
      />
      <section className="metric-grid" aria-label="Analysis summary">
        <MetricCard label="Normalized events" value={data.total_events} detail={String(data.event_sources.length) + ' event sources'} />
        <MetricCard label="Detection alerts" value={data.total_alerts} detail={String(data.rules.filter((rule) => rule.alert_count > 0).length) + ' rules fired'} />
        <MetricCard label="Correlated incidents" value={data.total_incidents} detail="Entity and correlation-ID grouping" />
        <MetricCard label="Alerts per incident" value={data.alert_to_incident_ratio.toFixed(2)} detail="Local correlation compression" />
      </section>

      <div className="content-grid equal">
        <section className="panel chart-panel" aria-labelledby="activity-analysis-title">
          <div className="panel-heading"><div><span className="eyebrow">Time series</span><h2 id="activity-analysis-title">Events, alerts, and incidents</h2></div></div>
          <div className="chart" aria-hidden="true">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.daily_activity} margin={{ top: 12, right: 12, left: -16, bottom: 0 }}>
                <CartesianGrid stroke="#1b3043" strokeDasharray="3 4" vertical={false} />
                <XAxis dataKey="date" stroke="#7892a8" tickLine={false} axisLine={false} />
                <YAxis stroke="#7892a8" allowDecimals={false} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: '#0d1d2d', border: '1px solid #28435a', borderRadius: 8 }} />
                <Legend />
                <Area type="monotone" dataKey="events" stroke="#6f96ff" fill="#6f96ff22" />
                <Area type="monotone" dataKey="alerts" stroke="#f5bd62" fill="#f5bd6222" />
                <Area type="monotone" dataKey="incidents" stroke="#31d2b3" fill="#31d2b322" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel chart-panel" aria-labelledby="source-analysis-title">
          <div className="panel-heading"><div><span className="eyebrow">Ingestion mix</span><h2 id="source-analysis-title">Events by source</h2></div></div>
          <div className="chart" aria-hidden="true">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.event_sources} layout="vertical" margin={{ top: 4, right: 12, left: 72, bottom: 0 }}>
                <CartesianGrid stroke="#1b3043" strokeDasharray="3 4" horizontal={false} />
                <XAxis type="number" stroke="#7892a8" allowDecimals={false} />
                <YAxis type="category" dataKey="label" stroke="#7892a8" width={110} />
                <Tooltip contentStyle={{ background: '#0d1d2d', border: '1px solid #28435a', borderRadius: 8 }} />
                <Bar dataKey="count" fill="#6f96ff" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
      </div>

      <section className="panel table-panel" aria-labelledby="rule-performance-title">
        <div className="panel-heading"><div><span className="eyebrow">Detection yield</span><h2 id="rule-performance-title">Rule performance</h2></div><span className="panel-value">{data.rules.length} rules</span></div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Rule</th><th>Severity</th><th>Alerts</th><th>Incidents</th><th>Mean latency</th><th>Yield</th></tr></thead>
            <tbody>
              {data.rules.map((rule) => (
                <tr key={rule.rule_id}>
                  <td><strong>{rule.rule_id}</strong><small className="table-subtext">{rule.title}</small></td>
                  <td><SeverityBadge severity={rule.severity as Severity} /></td>
                  <td>{rule.alert_count}</td>
                  <td>{rule.incident_count}</td>
                  <td>{rule.mean_latency_ms.toFixed(0)} ms</td>
                  <td>{rule.alert_count > 0 ? 'Triggered by demo fixture' : 'No current signal'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="content-grid equal">
        <section className="panel table-panel" aria-labelledby="entity-risk-title">
          <div className="panel-heading"><div><span className="eyebrow">Prioritization aid</span><h2 id="entity-risk-title">Entity risk ranking</h2></div></div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Entity</th><th>Type</th><th>Cases</th><th>Alerts</th><th>Risk</th></tr></thead>
              <tbody>
                {data.entity_risk.slice(0, 12).map((entity) => (
                  <tr key={entity.entity_type + ':' + entity.entity}>
                    <td><strong>{entity.entity}</strong></td>
                    <td>{titleCase(entity.entity_type)}</td>
                    <td>{entity.incident_count}</td>
                    <td>{entity.alert_count}</td>
                    <td><div className="risk-cell"><span style={{ width: String(entity.risk_score) + '%' }} /><strong>{entity.risk_score}</strong></div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="analysis-caveat">Risk is a transparent local prioritization score based on case severity and alert frequency, not a machine-learning prediction.</p>
        </section>

        <section className="panel" aria-labelledby="distribution-title">
          <div className="panel-heading"><div><span className="eyebrow">Workflow state</span><h2 id="distribution-title">Result distributions</h2></div></div>
          <div className="distribution-group">
            <h3>Event results</h3>
            {data.event_results.map((item) => (
              <div className="distribution-row" key={item.label}><span>{titleCase(item.label)}</span><strong>{item.count}</strong></div>
            ))}
          </div>
          <div className="distribution-group">
            <h3>Incident statuses</h3>
            {data.incident_statuses.map((item) => (
              <div className="distribution-row" key={item.label}><span>{titleCase(item.label)}</span><strong>{item.count}</strong></div>
            ))}
          </div>
        </section>
      </div>
    </div>
  )
}
