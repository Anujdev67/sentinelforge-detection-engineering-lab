import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { expect, test, vi } from 'vitest'
import { AnalyticsPage } from '../pages/AnalyticsPage'
import { DetectionLibraryPage } from '../pages/DetectionLibraryPage'
import { OverviewPage } from '../pages/OverviewPage'
import { ThreatIntelligencePage } from '../pages/ThreatIntelligencePage'
import type { DetectionRule, OverviewMetrics } from '../types'

const overview: OverviewMetrics = {
  open_incidents: 3,
  incidents_by_severity: { critical: 1, high: 2 },
  alerts_over_time: [{ date: '2026-02-03', count: 12 }],
  top_entities: [{ entity: 'host:ws-417.sentinelforge.test', count: 3 }],
  attack_tactics_observed: [{ tactic: 'Credential Access', count: 4 }],
  mean_detection_latency_ms: 250,
  total_events: 84,
  total_alerts: 12,
}

const detection: DetectionRule = {
  rule_id: 'SF-005',
  title: 'Encoded or suspicious PowerShell execution',
  description: 'Detects encoded or suspicious synthetic PowerShell process telemetry for analyst review.',
  severity: 'high',
  status: 'stable',
  required_data_sources: ['DeviceProcessEvents'],
  kql_file: 'query.kql',
  sigma_file: 'rule.yml',
  evaluator: 'suspicious_powershell',
  mitre_attack: [
    { tactic: 'TA0002', tactic_name: 'Execution', technique: 'T1059.001', technique_name: 'PowerShell' },
  ],
  entity_mappings: { account: 'AccountUpn', host: 'DeviceName' },
  known_false_positives: ['Approved deployment scripts'],
  investigation_steps: ['Review process lineage', 'Validate the automation source'],
  containment_recommendations: ['Require human approval before endpoint isolation'],
  threshold: 1,
  time_window_minutes: 15,
  tuning_required: true,
  version: '1.0.0',
  kql: 'DeviceProcessEvents | where Timestamp > ago(15m)',
  sigma: 'title: Encoded or Suspicious PowerShell Execution',
  test_status: { rule_id: 'SF-005', positive_passed: true, negative_passed: true },
  local_evaluator_notice: 'Purpose-built Python behavioral counterpart; this is not a KQL execution engine.',
}

function json(value: unknown): Response {
  return new Response(JSON.stringify(value), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

function renderPage(page: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{page}</MemoryRouter>
    </QueryClientProvider>,
  )
}

test('renders live overview metrics', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.resolve(json(overview))),
  )
  renderPage(<OverviewPage />)

  expect(await screen.findByRole('heading', { name: 'SOC Overview' })).toBeInTheDocument()
  const incidentMetric = screen.getByText('Open incidents').closest('article')
  if (incidentMetric === null) {
    throw new Error('Open incidents metric card was not rendered')
  }
  expect(within(incidentMetric).getByText('3')).toBeInTheDocument()
  expect(screen.getByText('250 ms')).toBeInTheDocument()
})

test('switches between authoritative KQL and available Sigma content', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.resolve(json([detection]))),
  )
  renderPage(<DetectionLibraryPage />)

  expect(await screen.findByRole('heading', { name: detection.title })).toBeInTheDocument()
  expect(screen.getByText(/DeviceProcessEvents \| where Timestamp/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('tab', { name: 'Sigma' }))
  expect(screen.getByText(/title: Encoded or Suspicious PowerShell Execution/)).toBeInTheDocument()
  expect(screen.getByText(/not a KQL execution engine/)).toBeInTheDocument()
})


test('performs a deterministic local reputation lookup without live connectors', async () => {
  const providers = [
    {
      provider: 'synthetic',
      display_name: 'Deterministic Local Intelligence',
      supported_types: ['ip'],
      configured: true,
      live: false,
      enabled: true,
      status: 'ready',
      privacy_notice: 'The observable remains local.',
    },
  ]
  const result = {
    observable: '203.0.113.77',
    observable_type: 'ip',
    overall_verdict: 'unknown',
    risk_score: 15,
    live_connectors_used: false,
    analyst_notice: 'No containment action was performed.',
    results: [
      {
        lookup_id: 'rep-00000000000001',
        incident_id: null,
        observable: '203.0.113.77',
        observable_type: 'ip',
        provider: 'synthetic',
        verdict: 'unknown',
        confidence: 30,
        malicious_count: 0,
        suspicious_count: 0,
        total_sources: 0,
        categories: ['synthetic-simulation'],
        country: null,
        as_owner: null,
        reference_url: null,
        live_lookup: false,
        cache_hit: false,
        requested_by: 'analyst.one@example.test',
        queried_at: '2026-08-12T00:00:00Z',
        expires_at: '2026-08-12T01:00:00Z',
        error: null,
        details: { simulation: true },
      },
    ],
  }
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL, options?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      if (url.includes('/reputation/providers')) return Promise.resolve(json(providers))
      if (url.includes('/reputation/history')) return Promise.resolve(json([]))
      if (url.includes('/reputation/lookup') && options?.method === 'POST') {
        return Promise.resolve(json(result))
      }
      return Promise.resolve(new Response(null, { status: 404 }))
    }),
  )

  renderPage(<ThreatIntelligencePage />)
  expect(await screen.findByRole('heading', { name: 'Threat Intelligence' })).toBeInTheDocument()
  expect((await screen.findAllByText('Deterministic Local Intelligence')).length).toBe(2)
  fireEvent.click(screen.getByRole('button', { name: 'Check reputation' }))
  expect(await screen.findByText('15/100 risk')).toBeInTheDocument()
  expect(screen.getByText('No containment action was performed.')).toBeInTheDocument()
})

test('renders operational analytics and transparent entity risk', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve(
        json({
          generated_at: '2026-08-12T00:00:00Z',
          total_events: 80,
          total_alerts: 12,
          total_incidents: 10,
          alert_to_incident_ratio: 1.2,
          event_sources: [{ label: 'SigninLogs', count: 12 }],
          event_results: [{ label: 'success', count: 40 }],
          incident_statuses: [{ label: 'new', count: 10 }],
          rules: [
            {
              rule_id: 'SF-001',
              title: 'Password spray across multiple accounts',
              severity: 'high',
              alert_count: 1,
              incident_count: 1,
              mean_latency_ms: 250,
            },
          ],
          entity_risk: [
            {
              entity: 'analyst-target@example.test',
              entity_type: 'account',
              incident_count: 2,
              alert_count: 3,
              risk_score: 85,
            },
          ],
          daily_activity: [{ date: '2026-08-12', events: 80, alerts: 12, incidents: 10 }],
        }),
      ),
    ),
  )

  renderPage(<AnalyticsPage />)
  expect(await screen.findByRole('heading', { name: 'SOC Analytics' })).toBeInTheDocument()
  expect(screen.getByText('80')).toBeInTheDocument()
  expect(screen.getByText('analyst-target@example.test')).toBeInTheDocument()
  expect(screen.getByText(/not a machine-learning prediction/)).toBeInTheDocument()
})
