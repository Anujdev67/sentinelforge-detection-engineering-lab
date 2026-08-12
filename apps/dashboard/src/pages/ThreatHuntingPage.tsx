import { useMutation, useQuery } from '@tanstack/react-query'
import { Download, FlaskConical, Play } from 'lucide-react'
import { useState } from 'react'
import { api, formatTimestamp, titleCase } from '../api'
import { EmptyState, ErrorState, LoadingState, PageHeader } from '../components/Ui'
import type { HuntDefinition, HuntResult } from '../types'

export function ThreatHuntingPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [dataSource, setDataSource] = useState('')
  const hunts = useQuery({ queryKey: ['hunts'], queryFn: () => api<HuntDefinition[]>('/hunts') })
  const selected = hunts.data?.find((hunt) => hunt.hunt_id === selectedId) ?? hunts.data?.[0]
  const selectedHuntId = selected?.hunt_id ?? ''
  const activeSource = dataSource && selected?.data_sources.includes(dataSource) ? dataSource : (selected?.data_sources[0] ?? '')
  const run = useMutation({
    mutationFn: () =>
      api<HuntResult>(`/hunts/${selectedHuntId}/run`, {
        method: 'POST',
        body: JSON.stringify({ data_source: activeSource, limit: 100 }),
      }),
  })

  const exportNotes = () => {
    if (!run.data) return
    const blob = new Blob([run.data.investigation_notes], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${run.data.hunt.hunt_id}-investigation-notes.txt`
    link.click()
    URL.revokeObjectURL(url)
  }

  if (hunts.isLoading) return <LoadingState label="Loading hunt hypotheses" />
  if (hunts.error) return <ErrorState message={hunts.error.message} />
  if (!selected) return <EmptyState title="No hunts available" description="The API returned no hunt definitions." />

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Analyst exploration"
        title="Threat Hunting Lab"
        description="Test prebuilt hypotheses against normalized synthetic data and export a concise investigation note."
      />
      <div className="content-grid hunt-layout">
        <aside className="hunt-list" aria-label="Hunt hypotheses">
          {hunts.data?.map((hunt) => (
            <button key={hunt.hunt_id} className={`hunt-card ${selected.hunt_id === hunt.hunt_id ? 'selected' : ''}`} onClick={() => { setSelectedId(hunt.hunt_id); setDataSource(''); run.reset() }}>
              <FlaskConical size={19} /><span><strong>{hunt.title}</strong><small>{hunt.data_sources.join(' · ')}</small></span>
            </button>
          ))}
        </aside>
        <div className="page-stack">
          <section className="panel">
            <span className="eyebrow">Hunt hypothesis</span><h2>{selected.title}</h2><p className="lead-copy">{selected.hypothesis}</p>
            <div className="hunt-controls">
              <label><span>Data source</span><select value={activeSource} onChange={(event) => setDataSource(event.target.value)}>{selected.data_sources.map((source) => <option key={source}>{source}</option>)}</select></label>
              <button className="button primary" disabled={run.isPending} onClick={() => run.mutate()}><Play size={16} /> {run.isPending ? 'Running…' : 'Run local hunt'}</button>
            </div>
            <h3>Microsoft Sentinel query example</h3>
            <pre className="code-preview compact" tabIndex={0}><code>{selected.query_example}</code></pre>
            <p className="helper-text">The local hunt filters normalized events; it does not execute this KQL.</p>
          </section>
          {run.error ? <ErrorState message={run.error.message} /> : null}
          {run.data ? (
            <section className="panel table-panel">
              <div className="panel-heading"><div><span className="eyebrow">Hunt results</span><h2>{run.data.result_count} matching events</h2></div><button className="button secondary" onClick={exportNotes}><Download size={16} /> Export notes</button></div>
              <div className="notes-preview"><strong>Investigation note</strong><pre>{run.data.investigation_notes}</pre></div>
              <div className="table-wrap"><table><thead><tr><th>Time</th><th>Source</th><th>Event</th><th>User / host</th><th>Result</th></tr></thead><tbody>{run.data.results.map((event) => <tr key={event.event_id}><td>{formatTimestamp(event.timestamp)}</td><td>{event.event_source}</td><td>{titleCase(event.event_type)}<span className="table-subtext">{event.event_id}</span></td><td>{event.user}<span className="table-subtext">{event.host}</span></td><td>{titleCase(event.result)}</td></tr>)}</tbody></table></div>
            </section>
          ) : null}
        </div>
      </div>
    </div>
  )
}
