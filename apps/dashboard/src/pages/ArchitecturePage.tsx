import { useEffect, useId, useState } from 'react'
import { ErrorState, PageHeader } from '../components/Ui'

const diagram = `flowchart LR
  G["Synthetic telemetry generator"] --> I["FastAPI ingestion"]
  I --> N["Schema normalization"]
  N --> P[("PostgreSQL event store")]
  P --> E["Python behavioral evaluators"]
  E --> A["Explainable alerts"]
  A --> C["Alert correlation"]
  C --> X["Incidents + entity timelines"]
  X --> D["React SOC dashboard"]
  X --> S["Human-approved SOAR simulation"]
  K["Authoritative Sentinel KQL + Sigma"] -. "contracts + tests" .-> E`

const mappings = [
  ['Synthetic generators', 'Lab data sources and connector test telemetry'],
  ['FastAPI ingestion + normalization', 'Data Collection Rules and ASIM normalization'],
  ['PostgreSQL event store', 'Log Analytics workspace tables'],
  ['Python behavioral evaluators', 'Microsoft Sentinel scheduled analytics rules in KQL'],
  ['Local correlation + incidents', 'Sentinel and Defender XDR incident correlation'],
  ['React investigation experience', 'Sentinel incidents, hunting, and workbooks'],
  ['Approval-gated local playbooks', 'Automation rules and Azure Logic Apps'],
]

export function ArchitecturePage() {
  const reactId = useId().replaceAll(':', '')
  const [svg, setSvg] = useState('')
  const [renderError, setRenderError] = useState('')

  useEffect(() => {
    let active = true
    void import('mermaid')
      .then(({ default: mermaid }) => {
        mermaid.initialize({
          startOnLoad: false,
          theme: 'base',
          securityLevel: 'strict',
          themeVariables: {
            background: '#0a1623',
            primaryColor: '#10283a',
            primaryTextColor: '#e7f1f7',
            primaryBorderColor: '#31d2b3',
            lineColor: '#5e8bff',
            secondaryColor: '#16263a',
            tertiaryColor: '#0d1d2d',
            fontFamily: 'Inter, system-ui, sans-serif',
          },
        })
        return mermaid.render(`sentinelforge-${reactId}`, diagram)
      })
      .then(({ svg: rendered }) => { if (active) setSvg(rendered) })
      .catch((error: unknown) => { if (active) setRenderError(error instanceof Error ? error.message : 'Diagram render failed') })
    return () => { active = false }
  }, [reactId])

  return (
    <div className="page-stack">
      <PageHeader eyebrow="System design" title="Architecture & Data Flow" description="A local-first defensive pipeline with explicit Microsoft Sentinel and Defender XDR mappings." />
      <section className="panel architecture-panel" aria-labelledby="data-flow-title">
        <div className="panel-heading"><div><span className="eyebrow">End-to-end pipeline</span><h2 id="data-flow-title">Local SOC data flow</h2></div></div>
        {renderError ? <ErrorState message={renderError} /> : null}
        {svg ? <div className="mermaid-output" aria-label="Synthetic telemetry flows through ingestion, normalization, PostgreSQL, detection evaluation, alert correlation, incidents, the dashboard, and approved SOAR simulation." dangerouslySetInnerHTML={{ __html: svg }} /> : null}
        <div className="notice-banner"><span><strong>Evaluator boundary:</strong> KQL files are authoritative Microsoft Sentinel examples. The local Python modules implement selected behavior only and are not a complete KQL engine.</span></div>
      </section>
      <section className="panel table-panel">
        <div className="panel-heading"><div><span className="eyebrow">Deployment translation</span><h2>Local versus Azure mapping</h2></div></div>
        <div className="table-wrap"><table><thead><tr><th>Local component</th><th>Microsoft cloud equivalent</th></tr></thead><tbody>{mappings.map(([local, cloud]) => <tr key={local}><td><strong>{local}</strong></td><td>{cloud}</td></tr>)}</tbody></table></div>
      </section>
      <section className="component-grid">
        <article className="panel"><span className="eyebrow">Detection content</span><h3>Portable and reviewable</h3><p>Each versioned pack binds metadata, KQL, optional Sigma, Python behavior, positive and negative fixtures, and expected evidence.</p></article>
        <article className="panel"><span className="eyebrow">Correlation</span><h3>Explainable grouping</h3><p>Alerts group by scenario correlation ID or overlapping account and host entities inside a bounded window.</p></article>
        <article className="panel"><span className="eyebrow">Automation safety</span><h3>Human approval required</h3><p>Local playbooks require a second analyst, emit immutable audit entries, and never call a real containment interface.</p></article>
      </section>
    </div>
  )
}
