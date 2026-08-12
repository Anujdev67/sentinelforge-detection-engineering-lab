import { AlertCircle, CheckCircle2, LoaderCircle } from 'lucide-react'
import type { ReactNode } from 'react'
import { titleCase } from '../api'
import type { Severity } from '../types'

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string
  title: string
  description: string
  actions?: ReactNode
}) {
  return (
    <header className="page-header">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  )
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge severity-${severity}`}>{titleCase(severity)}</span>
}

export function StatusBadge({ status }: { status: string }) {
  return <span className={`badge status-${status}`}>{titleCase(status)}</span>
}

export function LoadingState({ label = 'Loading operational data' }: { label?: string }) {
  return (
    <div className="state-panel" role="status">
      <LoaderCircle className="spin" size={24} aria-hidden="true" />
      <p>{label}…</p>
    </div>
  )
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="state-panel error-panel" role="alert">
      <AlertCircle size={24} aria-hidden="true" />
      <div>
        <strong>Unable to load data</strong>
        <p>{message}</p>
      </div>
    </div>
  )
}

export function EmptyState({ title, description }: { title: string; description: string }) {
  return (
    <div className="state-panel">
      <CheckCircle2 size={24} aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        <p>{description}</p>
      </div>
    </div>
  )
}

export function MetricCard({ label, value, detail }: { label: string; value: string | number; detail: string }) {
  return (
    <article className="metric-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  )
}

