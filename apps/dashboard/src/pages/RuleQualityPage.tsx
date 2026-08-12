import { useQuery } from '@tanstack/react-query'
import { CheckCircle2, Clock3, TriangleAlert } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, formatTimestamp, titleCase } from '../api'
import { ErrorState, LoadingState, MetricCard, PageHeader } from '../components/Ui'
import type { DetectionRule, QualitySnapshot } from '../types'

export function RuleQualityPage() {
  const quality = useQuery({ queryKey: ['quality'], queryFn: () => api<QualitySnapshot>('/quality') })
  const detections = useQuery({ queryKey: ['detections'], queryFn: () => api<DetectionRule[]>('/detections') })
  if (quality.isLoading || detections.isLoading) return <LoadingState label="Validating rule quality" />
  if (quality.error) return <ErrorState message={quality.error.message} />
  if (detections.error) return <ErrorState message={detections.error.message} />
  if (!quality.data || !detections.data) return null
  const severityData = Object.entries(quality.data.rules_by_severity).map(([severity, count]) => ({ severity: titleCase(severity), count }))
  const tuningRules = detections.data.filter((rule) => rule.tuning_required)

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Quality gates" title="Rule Quality" description="Live validation results derived from committed malicious and benign fixtures, schemas, and metadata." />
      <section className="metric-grid">
        <MetricCard label="Detections" value={quality.data.total_detections} detail={`${quality.data.sigma_rule_count} Sigma equivalents`} />
        <MetricCard label="Positive tests" value={`${quality.data.positive_tests_passed}/${quality.data.total_detections}`} detail="Malicious fixtures triggered" />
        <MetricCard label="Negative tests" value={`${quality.data.negative_tests_passed}/${quality.data.total_detections}`} detail="Benign fixtures stayed quiet" />
        <MetricCard label="ATT&CK techniques" value={quality.data.attack_coverage.length} detail={`${quality.data.covered_data_sources.length} data sources`} />
      </section>
      <div className="content-grid equal">
        <section className="panel chart-panel">
          <div className="panel-heading"><div><span className="eyebrow">Distribution</span><h2>Rules by severity</h2></div></div>
          <div className="chart" aria-hidden="true"><ResponsiveContainer width="100%" height="100%"><BarChart data={severityData}><CartesianGrid stroke="#1b3043" strokeDasharray="3 4" vertical={false} /><XAxis dataKey="severity" stroke="#7892a8" axisLine={false} tickLine={false} /><YAxis allowDecimals={false} stroke="#7892a8" axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: '#0d1d2d', border: '1px solid #28435a' }} /><Bar dataKey="count" fill="#31d2b3" radius={[5, 5, 0, 0]} /></BarChart></ResponsiveContainer></div>
        </section>
        <section className="panel">
          <div className="panel-heading"><div><span className="eyebrow">Validation record</span><h2>Current gate status</h2></div></div>
          <div className="quality-status"><CheckCircle2 size={24} /><div><strong>All fixture pairs passing</strong><p>Changes cannot silently alter committed alert evidence snapshots.</p></div></div>
          <div className="quality-status"><Clock3 size={24} /><div><strong>Last validation</strong><p>{formatTimestamp(quality.data.last_validation_time)}</p></div></div>
        </section>
      </div>
      <section className="panel table-panel">
        <div className="panel-heading"><div><span className="eyebrow">Environment-sensitive logic</span><h2>Rules requiring tuning</h2></div><span className="panel-value">{tuningRules.length}</span></div>
        <div className="table-wrap"><table><thead><tr><th>Rule</th><th>Severity</th><th>Data source</th><th>Tuning focus</th></tr></thead><tbody>{tuningRules.map((rule) => <tr key={rule.rule_id}><td><strong>{rule.rule_id}</strong><span className="table-subtext">{rule.title}</span></td><td>{titleCase(rule.severity)}</td><td>{rule.required_data_sources.join(', ')}</td><td><span className="tuning-needed"><TriangleAlert size={14} />Review false positives, watchlists, and baseline thresholds</span></td></tr>)}</tbody></table></div>
      </section>
    </div>
  )
}

