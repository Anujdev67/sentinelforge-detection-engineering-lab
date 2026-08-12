import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, CheckCheck, ClipboardCheck, FileClock, Search, ShieldAlert } from 'lucide-react'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, formatTimestamp, titleCase } from '../api'
import { ErrorState, LoadingState, PageHeader, SeverityBadge, StatusBadge } from '../components/Ui'
import type { AnalystNote, Incident, IncidentDetail, PlaybookDefinition, PlaybookRun } from '../types'

export function IncidentDetailPage() {
  const { incidentId } = useParams()
  const incidentKey = incidentId ?? ''
  const queryClient = useQueryClient()
  const [currentRun, setCurrentRun] = useState<PlaybookRun | null>(null)
  const detailQuery = useQuery({
    queryKey: ['incident', incidentKey],
    queryFn: () => api<IncidentDetail>(`/incidents/${incidentKey}`),
    enabled: Boolean(incidentId),
  })
  const playbookQuery = useQuery({
    queryKey: ['playbooks'],
    queryFn: () => api<PlaybookDefinition[]>('/playbooks'),
  })

  const refresh = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['incident', incidentKey] }),
      queryClient.invalidateQueries({ queryKey: ['incidents'] }),
      queryClient.invalidateQueries({ queryKey: ['overview'] }),
    ])
  }

  const updateMutation = useMutation({
    mutationFn: (payload: { status: string; assigned_to: string | null }) =>
      api<Incident>(`/incidents/${incidentKey}`, { method: 'PATCH', body: JSON.stringify(payload) }),
    onSuccess: refresh,
  })
  const noteMutation = useMutation({
    mutationFn: (payload: { author: string; body: string }) =>
      api<AnalystNote>(`/incidents/${incidentKey}/notes`, { method: 'POST', body: JSON.stringify(payload) }),
    onSuccess: refresh,
  })
  const requestMutation = useMutation({
    mutationFn: ({ playbookId, payload }: { playbookId: string; payload: Record<string, unknown> }) =>
      api<PlaybookRun>(`/incidents/${incidentKey}/playbooks/${playbookId}/request`, {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: async (run) => {
      setCurrentRun(run)
      await refresh()
    },
  })
  const approveMutation = useMutation({
    mutationFn: ({ runId, approvedBy }: { runId: string; approvedBy: string }) =>
      api<PlaybookRun>(`/playbook-runs/${runId}/approve`, {
        method: 'POST',
        body: JSON.stringify({ approved_by: approvedBy }),
      }),
    onSuccess: async (run) => {
      setCurrentRun(run)
      await refresh()
    },
  })
  const executeMutation = useMutation({
    mutationFn: ({ runId, executedBy }: { runId: string; executedBy: string }) =>
      api<PlaybookRun>(`/playbook-runs/${runId}/execute`, {
        method: 'POST',
        body: JSON.stringify({ executed_by: executedBy }),
      }),
    onSuccess: async (run) => {
      setCurrentRun(run)
      await refresh()
    },
  })

  if (!incidentId) return <ErrorState message="Incident identifier is missing." />
  if (detailQuery.isLoading) return <LoadingState label="Loading incident evidence" />
  if (detailQuery.error) return <ErrorState message={detailQuery.error.message} />
  if (!detailQuery.data) return null

  const detail = detailQuery.data
  const activeRun = currentRun ?? detail.playbook_runs[0] ?? null
  const intelligenceObservable = Object.entries(detail.incident.entities).find(([type]) =>
    type.toLowerCase().includes('ip'),
  )?.[1][0] ?? ''
  const automationError = requestMutation.error ?? approveMutation.error ?? executeMutation.error
  const field = (form: FormData, name: string) => {
    const value = form.get(name)
    return typeof value === 'string' ? value : ''
  }

  return (
    <div className="page-stack">
      <Link to="/incidents" className="back-link"><ArrowLeft size={16} /> Back to incident queue</Link>
      <PageHeader
        eyebrow={detail.incident.incident_id}
        title={detail.incident.title}
        description={detail.incident.executive_summary}
        actions={
          <div className="badge-row">
            <SeverityBadge severity={detail.incident.severity} />
            <StatusBadge status={detail.incident.status} />
          </div>
        }
      />

      <div className="content-grid incident-layout">
        <div className="page-stack">
          <section className="panel" aria-labelledby="evidence-title">
            <div className="panel-heading">
              <div><span className="eyebrow">Correlated signals</span><h2 id="evidence-title">Evidence</h2></div>
              <span className="panel-value">{detail.alerts.length} alerts</span>
            </div>
            <div className="alert-stack">
              {detail.alerts.map((alert) => (
                <article className="alert-card" key={alert.alert_id}>
                  <div className="alert-card-header">
                    <div><span className="rule-id">{alert.rule_id}</span><h3>{alert.title}</h3></div>
                    <SeverityBadge severity={alert.severity} />
                  </div>
                  <p>{alert.summary}</p>
                  <div className="meta-line">
                    <span>{alert.evidence_event_ids.length} evidence events</span>
                    <span>{alert.detection_latency_ms} ms latency</span>
                    <span>{alert.correlation_id}</span>
                  </div>
                  <div className="tag-row">
                    {alert.mitre_attack.map((mapping) => (
                      <span className="tag" key={`${alert.alert_id}-${mapping.technique}`}>
                        {mapping.technique} · {mapping.technique_name}
                      </span>
                    ))}
                  </div>
                </article>
              ))}
            </div>
          </section>

          <section className="panel" aria-labelledby="timeline-title">
            <div className="panel-heading">
              <div><span className="eyebrow">Entity chronology</span><h2 id="timeline-title">Entity timeline</h2></div>
            </div>
            <ol className="timeline">
              {detail.timeline.map((event) => (
                <li key={event.event_id}>
                  <span className="timeline-marker" aria-hidden="true" />
                  <time dateTime={event.timestamp}>{formatTimestamp(event.timestamp)}</time>
                  <div>
                    <strong>{titleCase(event.event_type)} · {event.result}</strong>
                    <p>{event.user} on {event.host}</p>
                    <small>{event.event_source} · {event.source_ip ?? 'No source IP'} · {event.event_id}</small>
                  </div>
                </li>
              ))}
            </ol>
          </section>

          <section className="panel" aria-labelledby="checklist-title">
            <div className="panel-heading">
              <div><span className="eyebrow">Analyst workflow</span><h2 id="checklist-title">Investigation checklist</h2></div>
            </div>
            <ul className="check-list">
              {detail.investigation_checklist.map((step) => (
                <li key={step}><ClipboardCheck size={17} aria-hidden="true" /><span>{step}</span></li>
              ))}
            </ul>
          </section>

          <section className="panel" aria-labelledby="notes-title">
            <div className="panel-heading">
              <div><span className="eyebrow">Case record</span><h2 id="notes-title">Analyst notes</h2></div>
            </div>
            <div className="notes-list">
              {detail.notes.length === 0 ? <p className="muted">No analyst notes yet.</p> : null}
              {detail.notes.map((note) => (
                <article key={note.note_id} className="note-card">
                  <div><strong>{note.author}</strong><time dateTime={note.created_at}>{formatTimestamp(note.created_at)}</time></div>
                  <p>{note.body}</p>
                </article>
              ))}
            </div>
            <form
              className="form-stack"
              onSubmit={(event) => {
                event.preventDefault()
                const form = new FormData(event.currentTarget)
                noteMutation.mutate({ author: field(form, 'author'), body: field(form, 'body') })
                event.currentTarget.reset()
              }}
            >
              <div className="form-row">
                <label><span>Analyst</span><input name="author" type="email" required defaultValue="analyst.one@example.test" /></label>
              </div>
              <label><span>Investigation note</span><textarea name="body" required minLength={3} rows={3} placeholder="Record evidence, scope, and decision rationale." /></label>
              <button className="button secondary" disabled={noteMutation.isPending}>Add note</button>
            </form>
          </section>
        </div>

        <aside className="page-stack incident-sidebar" aria-label="Incident controls">
          <section className="panel sticky-panel">
            <div className="panel-heading"><div><span className="eyebrow">Case ownership</span><h2>Assignment & status</h2></div></div>
            <form
              className="form-stack"
              key={`${detail.incident.incident_id}-${detail.incident.assigned_to}-${detail.incident.status}`}
              onSubmit={(event) => {
                event.preventDefault()
                const form = new FormData(event.currentTarget)
                const assigned = field(form, 'assigned_to').trim()
                updateMutation.mutate({ status: field(form, 'status'), assigned_to: assigned || null })
              }}
            >
              <label><span>Assigned analyst</span><input name="assigned_to" type="email" defaultValue={detail.incident.assigned_to ?? ''} placeholder="analyst@example.test" /></label>
              <label><span>Workflow status</span>
                <select name="status" defaultValue={detail.incident.status}>
                  <option value="new">New</option><option value="active">Active</option>
                  <option value="pending_approval">Pending approval</option>
                  <option value="contained_simulated">Contained · simulated</option><option value="closed">Closed</option>
                </select>
              </label>
              <button className="button secondary" disabled={updateMutation.isPending}>Save incident</button>
            </form>
          </section>

          <section className="panel danger-panel" aria-labelledby="soar-title">
            <div className="panel-heading"><div><span className="eyebrow">Approval-gated automation</span><h2 id="soar-title">Safe SOAR simulation</h2></div><ShieldAlert size={20} /></div>
            <p className="notice-text">Every playbook requires a second analyst's approval. Execution changes local records only.</p>
            <form
              className="form-stack"
              onSubmit={(event) => {
                event.preventDefault()
                const form = new FormData(event.currentTarget)
                const indicators = field(form, 'indicators').split(',').map((item) => item.trim()).filter(Boolean)
                requestMutation.mutate({
                  playbookId: field(form, 'playbook'),
                  payload: {
                    requested_by: field(form, 'requested_by'),
                    input_data: { indicators, simulate_containment: form.get('simulate_containment') === 'on' },
                  },
                })
              }}
            >
              <label><span>Playbook</span><select name="playbook" disabled={playbookQuery.isLoading}>
                {playbookQuery.data?.map((playbook) => <option value={playbook.playbook_id} key={playbook.playbook_id}>{playbook.title}</option>)}
              </select></label>
              <label><span>Requesting analyst</span><input name="requested_by" type="email" required defaultValue="analyst.one@example.test" /></label>
              <label><span>Indicators (comma-separated)</span><input name="indicators" defaultValue="198.51.100.44, synthetic-hash-001" /></label>
              <label className="checkbox-label"><input type="checkbox" name="simulate_containment" /><span>Set local incident to “contained · simulated” after approved execution</span></label>
              <button className="button danger" disabled={requestMutation.isPending || playbookQuery.isLoading}>Request approval</button>
            </form>

            {activeRun ? (
              <div className="approval-card" aria-live="polite">
                <div><strong>{titleCase(activeRun.playbook_id)}</strong><StatusBadge status={activeRun.status} /></div>
                <small>{activeRun.run_id}</small>
                {activeRun.status === 'pending_approval' ? (
                  <form
                    className="form-stack"
                    onSubmit={(event) => {
                      event.preventDefault()
                      const form = new FormData(event.currentTarget)
                      approveMutation.mutate({ runId: activeRun.run_id, approvedBy: field(form, 'approved_by') })
                    }}
                  >
                    <label><span>Second analyst approver</span><input name="approved_by" type="email" required defaultValue="analyst.two@example.test" /></label>
                    <button className="button approval" disabled={approveMutation.isPending}><CheckCheck size={16} /> Record approval</button>
                  </form>
                ) : null}
                {activeRun.status === 'approved' ? (
                  <button
                    className="button approval"
                    disabled={executeMutation.isPending}
                    onClick={() => executeMutation.mutate({ runId: activeRun.run_id, executedBy: activeRun.requested_by })}
                  ><FileClock size={16} /> Execute local simulation</button>
                ) : null}
                {activeRun.status === 'simulated_completed' ? (
                  <div className="simulation-result"><CheckCheck size={17} /><span>No external actions performed. Audit record complete.</span></div>
                ) : null}
              </div>
            ) : null}
            {automationError ? <p className="form-error" role="alert">{automationError.message}</p> : null}
          </section>

          <section className="panel">
            <div className="panel-heading"><div><span className="eyebrow">Recommended response</span><h2>Containment guidance</h2></div></div>
            <ul className="plain-list">{detail.recommended_containment.map((item) => <li key={item}>{item}</li>)}</ul>
          </section>

          <section className="panel">
            <div className="panel-heading"><div><span className="eyebrow">Entities</span><h2>Investigation scope</h2></div></div>
            <dl className="entity-dl">
              {Object.entries(detail.incident.entities).map(([type, values]) => (
                <div key={type}><dt>{titleCase(type)}</dt><dd>{values.join(', ')}</dd></div>
              ))}
            </dl>
            <Link
              className="button secondary"
              to={
                '/threat-intelligence?incident=' + encodeURIComponent(detail.incident.incident_id)
                + (intelligenceObservable ? '&observable=' + encodeURIComponent(intelligenceObservable) : '')
              }
            >
              <Search size={16} /> Check IP or domain reputation
            </Link>
          </section>
        </aside>
      </div>
    </div>
  )
}
