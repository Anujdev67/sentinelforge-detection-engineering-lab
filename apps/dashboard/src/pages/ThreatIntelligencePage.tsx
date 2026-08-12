import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, Globe2, History, LockKeyhole, SearchCheck } from 'lucide-react'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, formatTimestamp, titleCase } from '../api'
import { ErrorState, LoadingState, PageHeader } from '../components/Ui'
import type {
  ObservableType,
  ReputationLookupResponse,
  ReputationProvider,
  ReputationResult,
} from '../types'

export function ThreatIntelligencePage() {
  const [params] = useSearchParams()
  const queryClient = useQueryClient()
  const [observable, setObservable] = useState(params.get('observable') ?? '203.0.113.77')
  const [observableType, setObservableType] = useState<ObservableType | ''>('')
  const [incidentId, setIncidentId] = useState(params.get('incident') ?? '')
  const [requestedBy, setRequestedBy] = useState('analyst.one@example.test')
  const [selectedProviders, setSelectedProviders] = useState<string[]>(['synthetic'])

  const providers = useQuery({
    queryKey: ['reputation-providers'],
    queryFn: () => api<ReputationProvider[]>('/reputation/providers'),
  })
  const history = useQuery({
    queryKey: ['reputation-history'],
    queryFn: () => api<ReputationResult[]>('/reputation/history?limit=100'),
  })
  const lookup = useMutation({
    mutationFn: () =>
      api<ReputationLookupResponse>('/reputation/lookup', {
        method: 'POST',
        body: JSON.stringify({
          observable,
          observable_type: observableType || null,
          providers: selectedProviders,
          requested_by: requestedBy,
          incident_id: incidentId.trim() || null,
          force_refresh: false,
        }),
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['reputation-history'] })
    },
  })

  const toggleProvider = (provider: string) => {
    setSelectedProviders((current) =>
      current.includes(provider)
        ? current.filter((item) => item !== provider)
        : [...current, provider],
    )
  }

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Read-only CTI enrichment"
        title="Threat Intelligence"
        description="Check an IP address or domain against deterministic local intelligence or explicitly enabled external reputation providers. Results add analyst context only."
      />

      <div className="notice-banner">
        <LockKeyhole size={18} aria-hidden="true" />
        <span>
          Live connectors are opt-in and use environment-only API keys. Reserved, private, local,
          and documentation observables are blocked from external sharing. No scan, submission, or
          containment action is performed.
        </span>
      </div>

      <div className="content-grid lookup-layout">
        <section className="panel" aria-labelledby="lookup-title">
          <div className="panel-heading">
            <div><span className="eyebrow">Observable lookup</span><h2 id="lookup-title">Reputation check</h2></div>
            <SearchCheck size={21} aria-hidden="true" />
          </div>
          <form
            className="form-stack"
            onSubmit={(event) => {
              event.preventDefault()
              lookup.mutate()
            }}
          >
            <label>
              <span>IP address or domain</span>
              <input
                value={observable}
                onChange={(event) => setObservable(event.target.value)}
                required
                placeholder="203.0.113.77 or suspicious.example"
                autoComplete="off"
              />
            </label>
            <div className="form-row">
              <label>
                <span>Type</span>
                <select
                  value={observableType}
                  onChange={(event) => setObservableType(event.target.value as ObservableType | '')}
                >
                  <option value="">Auto-detect</option>
                  <option value="ip">IP address</option>
                  <option value="domain">Domain</option>
                </select>
              </label>
              <label className="grow-field">
                <span>Link to incident (optional)</span>
                <input
                  value={incidentId}
                  onChange={(event) => setIncidentId(event.target.value)}
                  placeholder="inc-..."
                />
              </label>
            </div>
            <label>
              <span>Requesting analyst</span>
              <input
                type="email"
                value={requestedBy}
                onChange={(event) => setRequestedBy(event.target.value)}
                required
              />
            </label>

            <fieldset className="provider-fieldset">
              <legend>Providers</legend>
              {providers.isLoading ? <span className="muted">Loading connectors...</span> : null}
              {providers.data?.map((provider) => (
                <label className="provider-option" key={provider.provider}>
                  <input
                    type="checkbox"
                    checked={selectedProviders.includes(provider.provider)}
                    onChange={() => toggleProvider(provider.provider)}
                    disabled={!provider.enabled}
                  />
                  <span>
                    <strong>{provider.display_name}</strong>
                    <small>
                      {provider.live ? 'External' : 'Local'} · {titleCase(provider.status)}
                    </small>
                  </span>
                </label>
              ))}
            </fieldset>
            <button
              className="button primary"
              disabled={lookup.isPending || selectedProviders.length === 0}
            >
              {lookup.isPending ? 'Checking reputation...' : 'Check reputation'}
            </button>
            {lookup.error ? <p className="form-error" role="alert">{lookup.error.message}</p> : null}
          </form>
        </section>

        <section className="panel" aria-labelledby="provider-title">
          <div className="panel-heading">
            <div><span className="eyebrow">Connector health</span><h2 id="provider-title">Provider status</h2></div>
            <Globe2 size={21} aria-hidden="true" />
          </div>
          {providers.error ? <ErrorState message={providers.error.message} /> : null}
          <div className="provider-grid">
            {providers.data?.map((provider) => (
              <article className="provider-card" key={provider.provider}>
                <div>
                  <strong>{provider.display_name}</strong>
                  <span className={provider.enabled ? 'connector-ready' : 'connector-disabled'}>
                    {titleCase(provider.status)}
                  </span>
                </div>
                <small>{provider.supported_types.map(titleCase).join(' · ')}</small>
                <p>{provider.privacy_notice}</p>
              </article>
            ))}
          </div>
        </section>
      </div>

      {lookup.data ? (
        <section className="panel" aria-labelledby="result-title" aria-live="polite">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">Analyst context</span>
              <h2 id="result-title">{lookup.data.observable}</h2>
            </div>
            <div className="reputation-summary">
              <span className={'verdict verdict-' + lookup.data.overall_verdict}>
                {titleCase(lookup.data.overall_verdict)}
              </span>
              <strong>{lookup.data.risk_score}/100 risk</strong>
            </div>
          </div>
          <p className="notice-text">{lookup.data.analyst_notice}</p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Provider</th><th>Verdict</th><th>Confidence</th><th>Signals</th><th>Context</th><th>Source</th></tr>
              </thead>
              <tbody>
                {lookup.data.results.map((result) => (
                  <tr key={result.lookup_id}>
                    <td>
                      <strong>{titleCase(result.provider)}</strong>
                      <small className="table-subtext">
                        {result.cache_hit ? 'Cached' : result.live_lookup ? 'Live lookup' : 'Local lookup'}
                      </small>
                    </td>
                    <td><span className={'verdict verdict-' + result.verdict}>{titleCase(result.verdict)}</span></td>
                    <td>{result.confidence}%</td>
                    <td>{result.malicious_count} malicious · {result.suspicious_count} suspicious</td>
                    <td>{[result.country, result.as_owner, ...result.categories].filter(Boolean).join(' · ') || 'No additional context'}</td>
                    <td>
                      {result.reference_url ? (
                        <a href={result.reference_url} target="_blank" rel="noreferrer" className="inline-link">
                          Report <ExternalLink size={13} />
                        </a>
                      ) : 'Local'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      <section className="panel table-panel" aria-labelledby="history-title">
        <div className="panel-heading">
          <div><span className="eyebrow">Audit history</span><h2 id="history-title">Recent reputation lookups</h2></div>
          <History size={20} aria-hidden="true" />
        </div>
        {history.isLoading ? <LoadingState label="Loading lookup history" /> : null}
        {history.error ? <ErrorState message={history.error.message} /> : null}
        {history.data && history.data.length === 0 ? <p className="empty-copy">No lookups recorded yet.</p> : null}
        {history.data && history.data.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Observable</th><th>Provider</th><th>Verdict</th><th>Analyst</th><th>Incident</th><th>Time</th></tr></thead>
              <tbody>
                {history.data.map((result) => (
                  <tr key={result.lookup_id}>
                    <td><strong>{result.observable}</strong><small className="table-subtext">{titleCase(result.observable_type)}</small></td>
                    <td>{titleCase(result.provider)}</td>
                    <td><span className={'verdict verdict-' + result.verdict}>{titleCase(result.verdict)}</span></td>
                    <td>{result.requested_by}</td>
                    <td>{result.incident_id ?? 'Not linked'}</td>
                    <td>{formatTimestamp(result.queried_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </div>
  )
}
