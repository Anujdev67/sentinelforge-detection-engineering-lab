export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical'
export type IncidentStatus = 'new' | 'active' | 'pending_approval' | 'contained_simulated' | 'closed'

export interface MitreMapping {
  tactic: string
  tactic_name: string
  technique: string
  technique_name: string
}

export interface Alert {
  alert_id: string
  rule_id: string
  title: string
  severity: Severity
  detected_at: string
  first_observed: string
  last_observed: string
  summary: string
  evidence_event_ids: string[]
  entities: Record<string, string[]>
  mitre_attack: MitreMapping[]
  correlation_id: string
  detection_latency_ms: number
}

export interface Incident {
  incident_id: string
  title: string
  severity: Severity
  status: IncidentStatus
  executive_summary: string
  alert_ids: string[]
  entities: Record<string, string[]>
  first_observed: string
  last_observed: string
  assigned_to: string | null
  created_at: string
}

export interface NormalizedEvent {
  event_id: string
  timestamp: string
  event_source: string
  event_type: string
  host: string
  user: string
  source_ip: string | null
  destination_ip: string | null
  action: string
  result: string
  correlation_id: string
  raw_event_ref: string
  normalized: Record<string, unknown>
}

export interface AnalystNote {
  note_id: number
  incident_id: string
  author: string
  body: string
  created_at: string
}

export interface PlaybookRun {
  run_id: string
  incident_id: string
  playbook_id: string
  status: string
  requires_approval: boolean
  requested_by: string
  approved_by: string | null
  created_at: string
  approved_at: string | null
  completed_at: string | null
  input_data: Record<string, unknown>
  output_data: Record<string, unknown>
}

export interface IncidentDetail {
  incident: Incident
  alerts: Alert[]
  timeline: NormalizedEvent[]
  notes: AnalystNote[]
  playbook_runs: PlaybookRun[]
  investigation_checklist: string[]
  recommended_containment: string[]
}

export interface OverviewMetrics {
  open_incidents: number
  incidents_by_severity: Record<string, number>
  alerts_over_time: Array<{ date: string; count: number }>
  top_entities: Array<{ entity: string; count: number }>
  attack_tactics_observed: Array<{ tactic: string; count: number }>
  mean_detection_latency_ms: number
  total_events: number
  total_alerts: number
}

export interface DetectionRule {
  rule_id: string
  title: string
  description: string
  severity: Severity
  status: string
  required_data_sources: string[]
  kql_file: string
  sigma_file: string | null
  evaluator: string
  mitre_attack: MitreMapping[]
  entity_mappings: Record<string, string>
  known_false_positives: string[]
  investigation_steps: string[]
  containment_recommendations: string[]
  threshold: number
  time_window_minutes: number
  tuning_required: boolean
  version: string
  kql: string
  sigma: string | null
  test_status: { rule_id: string; positive_passed: boolean; negative_passed: boolean }
  local_evaluator_notice: string
}

export interface QualitySnapshot {
  total_detections: number
  positive_tests_passed: number
  negative_tests_passed: number
  attack_coverage: string[]
  covered_data_sources: string[]
  rules_by_severity: Record<string, number>
  rules_requiring_tuning: number
  sigma_rule_count: number
  last_validation_time: string
}

export interface AttackCoverage {
  framework: {
    name: string
    version: string
    release_date: string
    source: string
    local_snapshot: boolean
  }
  summary: {
    covered_tactics: number
    total_tactics: number
    coverage_percent: number
    mapped_techniques: number
    mapped_rules: number
  }
  tactics: Array<{
    tactic_id: string
    tactic_name: string
    covered: boolean
    gap: boolean
    rule_ids: string[]
  }>
  techniques: Array<{
    technique_id: string
    technique_name: string
    tactic_id: string
    tactic_name: string
    rule_ids: string[]
    data_sources: string[]
    severities: string[]
    validation: string
  }>
  limitations: string[]
}

export interface HuntDefinition {
  hunt_id: string
  title: string
  hypothesis: string
  data_sources: string[]
  query_example: string
}

export interface HuntResult {
  hunt: HuntDefinition
  data_source: string
  result_count: number
  results: NormalizedEvent[]
  investigation_notes: string
}

export interface PlaybookDefinition {
  playbook_id: string
  title: string
  description: string
  requires_approval: boolean
  simulation_only: boolean
}


export type ObservableType = 'ip' | 'domain'
export type ReputationVerdict = 'benign' | 'unknown' | 'suspicious' | 'malicious' | 'error'

export interface ReputationProvider {
  provider: string
  display_name: string
  supported_types: ObservableType[]
  configured: boolean
  live: boolean
  enabled: boolean
  status: string
  privacy_notice: string
}

export interface ReputationResult {
  lookup_id: string
  incident_id: string | null
  observable: string
  observable_type: ObservableType
  provider: string
  verdict: ReputationVerdict
  confidence: number
  malicious_count: number
  suspicious_count: number
  total_sources: number
  categories: string[]
  country: string | null
  as_owner: string | null
  reference_url: string | null
  live_lookup: boolean
  cache_hit: boolean
  requested_by: string
  queried_at: string
  expires_at: string
  error: string | null
  details: Record<string, unknown>
}

export interface ReputationLookupResponse {
  observable: string
  observable_type: ObservableType
  overall_verdict: ReputationVerdict
  risk_score: number
  results: ReputationResult[]
  live_connectors_used: boolean
  analyst_notice: string
}

export interface AnalyticsSnapshot {
  generated_at: string
  total_events: number
  total_alerts: number
  total_incidents: number
  alert_to_incident_ratio: number
  event_sources: Array<{ label: string; count: number }>
  event_results: Array<{ label: string; count: number }>
  incident_statuses: Array<{ label: string; count: number }>
  rules: Array<{
    rule_id: string
    title: string
    severity: string
    alert_count: number
    incident_count: number
    mean_latency_ms: number
  }>
  entity_risk: Array<{
    entity: string
    entity_type: string
    incident_count: number
    alert_count: number
    risk_score: number
  }>
  daily_activity: Array<{ date: string; events: number; alerts: number; incidents: number }>
}
