import { useQuery } from '@tanstack/react-query'
import { CircleCheck, CircleDashed, Download, ExternalLink, ShieldCheck } from 'lucide-react'
import { api } from '../api'
import { ErrorState, LoadingState, MetricCard, PageHeader } from '../components/Ui'
import type { AttackCoverage } from '../types'

export function AttackCoveragePage() {
  const query = useQuery({
    queryKey: ['attack-coverage'],
    queryFn: () => api<AttackCoverage>('/attack-coverage'),
  })
  if (query.isLoading) return <LoadingState label="Mapping ATT&CK coverage" />
  if (query.error) return <ErrorState message={query.error.message} />
  if (!query.data) return null
  const data = query.data

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow={data.framework.name + ' v' + data.framework.version}
        title="ATT&CK Coverage"
        description="Version-pinned detection-to-technique relationships with validation context, data readiness, explicit gaps, and a Navigator-compatible export."
        actions={
          <a
            className="button secondary"
            href="/api/v1/attack-coverage/navigator-layer"
            download="sentinelforge-attack-navigator-layer.json"
          >
            <Download size={16} /> Export Navigator layer
          </a>
        }
      />

      <section className="metric-grid" aria-label="ATT&CK coverage summary">
        <MetricCard
          label="Tactic coverage"
          value={String(data.summary.coverage_percent) + '%'}
          detail={String(data.summary.covered_tactics) + ' of ' + String(data.summary.total_tactics) + ' Enterprise tactics'}
        />
        <MetricCard label="Mapped techniques" value={data.summary.mapped_techniques} detail="Unique techniques and sub-techniques" />
        <MetricCard label="Mapped detections" value={data.summary.mapped_rules} detail="Fixture-validated local rule mappings" />
        <MetricCard label="Pinned release" value={'v' + data.framework.version} detail={'Released ' + data.framework.release_date} />
      </section>

      <div className="notice-banner">
        <ShieldCheck size={18} aria-hidden="true" />
        <span>
          Coverage means a rule is mapped and its local positive/negative fixtures pass. It does not
          prove production efficacy, complete telemetry, or prevention. The snapshot is pinned and
          does not automatically synchronize with MITRE TAXII or STIX.
          {' '}
          <a href={data.framework.source} target="_blank" rel="noreferrer" className="inline-link">
            Official ATT&CK source <ExternalLink size={13} />
          </a>
        </span>
      </div>

      <section className="coverage-grid" aria-label="Enterprise ATT&CK tactic coverage">
        {data.tactics.map((tactic) => (
          <article className={'coverage-card ' + (tactic.covered ? 'covered' : 'gap')} key={tactic.tactic_id}>
            {tactic.covered ? <CircleCheck size={19} /> : <CircleDashed size={19} />}
            <div>
              <span>{tactic.tactic_id}</span>
              <strong>{tactic.tactic_name}</strong>
              <small>
                {tactic.covered
                  ? String(tactic.rule_ids.length) + ' mapped rule' + (tactic.rule_ids.length === 1 ? '' : 's')
                  : 'Coverage gap'}
              </small>
            </div>
          </article>
        ))}
      </section>

      <section className="panel table-panel">
        <div className="panel-heading">
          <div><span className="eyebrow">Detection relationships</span><h2>Technique-to-rule mapping</h2></div>
          <span className="panel-value">{data.techniques.length} techniques</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Technique</th><th>Tactic</th><th>Detection rules</th><th>Required telemetry</th><th>Validation</th></tr></thead>
            <tbody>
              {data.techniques.map((technique) => (
                <tr key={technique.technique_id}>
                  <td><strong>{technique.technique_id}</strong><small className="table-subtext">{technique.technique_name}</small></td>
                  <td>{technique.tactic_name}<small className="table-subtext">{technique.tactic_id}</small></td>
                  <td><div className="tag-row">{technique.rule_ids.map((rule) => <span className="tag" key={rule}>{rule}</span>)}</div></td>
                  <td>{technique.data_sources.join(' · ')}</td>
                  <td>{technique.validation}<small className="table-subtext">{technique.severities.join(' · ')} severity</small></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel" aria-labelledby="coverage-limitations-title">
        <div className="panel-heading"><div><span className="eyebrow">Interpretation</span><h2 id="coverage-limitations-title">Coverage limitations</h2></div></div>
        <ul className="plain-list">
          {data.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
        </ul>
      </section>
    </div>
  )
}
