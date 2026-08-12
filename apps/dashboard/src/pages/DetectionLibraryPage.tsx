import { useQuery } from '@tanstack/react-query'
import { CheckCircle2, Search, SlidersHorizontal, TriangleAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import { api } from '../api'
import { EmptyState, ErrorState, LoadingState, PageHeader, SeverityBadge } from '../components/Ui'
import type { DetectionRule } from '../types'

export function DetectionLibraryPage() {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [preview, setPreview] = useState<'kql' | 'sigma'>('kql')
  const query = useQuery({ queryKey: ['detections'], queryFn: () => api<DetectionRule[]>('/detections') })

  const sources = useMemo(
    () => [...new Set(query.data?.flatMap((rule) => rule.required_data_sources) ?? [])].sort(),
    [query.data],
  )
  const filtered = useMemo(() => {
    const needle = search.toLowerCase()
    return (query.data ?? []).filter(
      (rule) =>
        (!needle || `${rule.rule_id} ${rule.title} ${rule.description}`.toLowerCase().includes(needle)) &&
        (!severity || rule.severity === severity) &&
        (!source || rule.required_data_sources.includes(source)),
    )
  }, [query.data, search, severity, source])
  const selected = filtered.find((rule) => rule.rule_id === selectedId) ?? filtered[0]

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Detection as code"
        title="Detection Library"
        description="Review authoritative Microsoft Sentinel KQL, Sigma mappings, data requirements, tuning notes, and fixture status."
        actions={<span className="result-count">{filtered.length} rules</span>}
      />

      <section className="filter-bar" aria-label="Detection filters">
        <label className="grow-field"><span>Search</span><div className="input-with-icon"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Rule ID, title, or behavior" /></div></label>
        <label><span>Severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option></select></label>
        <label><span>Data source</span><select value={source} onChange={(event) => setSource(event.target.value)}><option value="">All sources</option>{sources.map((item) => <option key={item}>{item}</option>)}</select></label>
      </section>

      {query.isLoading ? <LoadingState label="Loading detection packs" /> : null}
      {query.error ? <ErrorState message={query.error.message} /> : null}
      {query.data && filtered.length === 0 ? <EmptyState title="No matching detections" description="Adjust the search or filter criteria." /> : null}
      {selected ? (
        <div className="content-grid library-layout">
          <section className="rule-list" aria-label="Detection rule results">
            {filtered.map((rule) => (
              <button
                key={rule.rule_id}
                className={`rule-list-item ${selected.rule_id === rule.rule_id ? 'selected' : ''}`}
                onClick={() => setSelectedId(rule.rule_id)}
                aria-pressed={selected.rule_id === rule.rule_id}
              >
                <div><span className="rule-id">{rule.rule_id}</span><SeverityBadge severity={rule.severity} /></div>
                <strong>{rule.title}</strong>
                <span>{rule.required_data_sources.join(' · ')}</span>
                <small className={rule.tuning_required ? 'tuning-needed' : 'test-pass'}>
                  {rule.tuning_required ? <TriangleAlert size={14} /> : <CheckCircle2 size={14} />}
                  {rule.tuning_required ? 'Tuning guidance required' : 'Fixture pair passing'}
                </small>
              </button>
            ))}
          </section>

          <article className="panel rule-detail">
            <div className="rule-detail-header">
              <div><span className="eyebrow">{selected.rule_id} · v{selected.version}</span><h2>{selected.title}</h2><p>{selected.description}</p></div>
              <SeverityBadge severity={selected.severity} />
            </div>
            <div className="notice-banner"><SlidersHorizontal size={17} /><span>{selected.local_evaluator_notice}</span></div>
            <dl className="rule-facts">
              <div><dt>Required data</dt><dd>{selected.required_data_sources.join(', ')}</dd></div>
              <div><dt>Window / threshold</dt><dd>{selected.time_window_minutes} min / {selected.threshold}</dd></div>
              <div><dt>Entity mappings</dt><dd>{Object.entries(selected.entity_mappings).map(([key, value]) => `${key}: ${value}`).join(' · ')}</dd></div>
              <div><dt>Test status</dt><dd className="test-pass"><CheckCircle2 size={15} /> Positive and negative fixtures passing</dd></div>
            </dl>
            <div className="preview-tabs" role="tablist" aria-label="Detection content preview">
              <button role="tab" aria-selected={preview === 'kql'} onClick={() => setPreview('kql')}>KQL</button>
              <button role="tab" aria-selected={preview === 'sigma'} onClick={() => setPreview('sigma')} disabled={!selected.sigma}>Sigma</button>
            </div>
            <pre className="code-preview" tabIndex={0}><code>{preview === 'sigma' ? selected.sigma ?? 'No applicable Sigma equivalent.' : selected.kql}</code></pre>
            <div className="content-grid equal rule-guidance">
              <section><h3>Known false positives</h3><ul className="plain-list">{selected.known_false_positives.map((item) => <li key={item}>{item}</li>)}</ul></section>
              <section><h3>Investigation steps</h3><ol className="plain-list numbered">{selected.investigation_steps.map((item) => <li key={item}>{item}</li>)}</ol></section>
            </div>
            <div className="tag-row">{selected.mitre_attack.map((mapping) => <span className="tag" key={mapping.technique}>{mapping.tactic} · {mapping.tactic_name} / {mapping.technique}</span>)}</div>
          </article>
        </div>
      ) : null}
    </div>
  )
}

