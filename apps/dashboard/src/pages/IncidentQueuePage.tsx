import { useQuery } from '@tanstack/react-query'
import { Filter, Search } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, formatTimestamp } from '../api'
import { EmptyState, ErrorState, LoadingState, PageHeader, SeverityBadge, StatusBadge } from '../components/Ui'
import type { Incident } from '../types'

export function IncidentQueuePage() {
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [rule, setRule] = useState('')
  const [entity, setEntity] = useState('')
  const parameters = new URLSearchParams()
  if (severity) parameters.set('severity', severity)
  if (status) parameters.set('status', status)
  if (rule) parameters.set('rule_id', rule)
  if (entity) parameters.set('entity', entity)

  const query = useQuery({
    queryKey: ['incidents', severity, status, rule, entity],
    queryFn: () => api<Incident[]>(`/incidents?${parameters.toString()}`),
  })

  const visibleCount = useMemo(() => query.data?.length ?? 0, [query.data])

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Triage workspace"
        title="Incident Queue"
        description="Prioritize correlated cases, review ownership, and move investigations through the local workflow."
        actions={<span className="result-count">{visibleCount} incidents</span>}
      />

      <section className="filter-bar" aria-label="Incident filters">
        <label>
          <span>Severity</span>
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </label>
        <label>
          <span>Status</span>
          <select value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="">All statuses</option>
            <option value="new">New</option>
            <option value="active">Active</option>
            <option value="pending_approval">Pending approval</option>
            <option value="contained_simulated">Contained · simulated</option>
            <option value="closed">Closed</option>
          </select>
        </label>
        <label>
          <span>Rule ID</span>
          <div className="input-with-icon">
            <Filter size={16} aria-hidden="true" />
            <input value={rule} onChange={(event) => setRule(event.target.value.toUpperCase())} placeholder="SF-005" />
          </div>
        </label>
        <label className="grow-field">
          <span>Entity</span>
          <div className="input-with-icon">
            <Search size={16} aria-hidden="true" />
            <input value={entity} onChange={(event) => setEntity(event.target.value)} placeholder="Account, host, or IP" />
          </div>
        </label>
      </section>

      {query.isLoading ? <LoadingState /> : null}
      {query.error ? <ErrorState message={query.error.message} /> : null}
      {query.data?.length === 0 ? (
        <EmptyState title="No incidents match these filters" description="Adjust the filter set or run the demo scenarios." />
      ) : null}
      {query.data && query.data.length > 0 ? (
        <section className="panel table-panel" aria-label="Incident queue results">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Incident</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Owner</th>
                  <th>Alerts</th>
                  <th>Observed</th>
                </tr>
              </thead>
              <tbody>
                {query.data.map((incident) => (
                  <tr key={incident.incident_id}>
                    <td>
                      <Link className="incident-link" to={`/incidents/${incident.incident_id}`}>
                        <span>{incident.title}</span>
                        <small>{incident.incident_id}</small>
                      </Link>
                    </td>
                    <td><SeverityBadge severity={incident.severity} /></td>
                    <td><StatusBadge status={incident.status} /></td>
                    <td>{incident.assigned_to ?? <span className="muted">Unassigned</span>}</td>
                    <td>{incident.alert_ids.length}</td>
                    <td>
                      <time dateTime={incident.first_observed}>{formatTimestamp(incident.first_observed)}</time>
                      <small className="table-subtext">to {formatTimestamp(incident.last_observed)}</small>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}
    </div>
  )
}

