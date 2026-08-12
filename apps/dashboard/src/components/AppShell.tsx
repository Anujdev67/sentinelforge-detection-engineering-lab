import {
  Activity,
  BadgeCheck,
  BellRing,
  Boxes,
  ChartNoAxesCombined,
  Crosshair,
  Globe2,
  Library,
  Menu,
  Radar,
  ShieldCheck,
  X,
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { api } from '../api'

const navigation = [
  { to: '/', label: 'SOC Overview', icon: Activity, end: true },
  { to: '/incidents', label: 'Incident Queue', icon: BellRing },
  { to: '/threat-intelligence', label: 'Threat Intelligence', icon: Globe2 },
  { to: '/analytics', label: 'SOC Analytics', icon: ChartNoAxesCombined },
  { to: '/detections', label: 'Detection Library', icon: Library },
  { to: '/rule-quality', label: 'Rule Quality', icon: BadgeCheck },
  { to: '/hunting', label: 'Threat Hunting', icon: Crosshair },
  { to: '/attack-coverage', label: 'ATT&CK Coverage', icon: Radar },
  { to: '/architecture', label: 'Architecture', icon: Boxes },
]

export function AppShell() {
  const [menuOpen, setMenuOpen] = useState(false)
  const health = useQuery({
    queryKey: ['health'],
    queryFn: () => api<{ status: string }>('/health'),
    refetchInterval: 30_000,
    retry: false,
  })
  const apiReady = health.data?.status === 'ok'

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <aside className={`sidebar ${menuOpen ? 'sidebar-open' : ''}`} aria-label="Primary navigation">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <ShieldCheck size={25} />
          </div>
          <div>
            <strong>SentinelForge</strong>
            <span>Local SOC Lab</span>
          </div>
          <button className="icon-button mobile-only" onClick={() => setMenuOpen(false)} aria-label="Close menu">
            <X size={20} />
          </button>
        </div>
        <nav>
          {navigation.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              onClick={() => setMenuOpen(false)}
              className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
            >
              <Icon size={18} aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="simulation-notice">
          <span className="status-dot" aria-hidden="true" />
          <div>
            <strong>Simulation mode</strong>
            <p>Synthetic telemetry. No real containment.</p>
          </div>
        </div>
      </aside>
      {menuOpen ? <button className="sidebar-scrim" onClick={() => setMenuOpen(false)} aria-label="Close menu" /> : null}
      <div className="app-body">
        <header className="topbar">
          <button className="icon-button mobile-only" onClick={() => setMenuOpen(true)} aria-label="Open menu">
            <Menu size={22} />
          </button>
          <div className="topbar-context">
            <span className="eyebrow">Detection engineering workspace</span>
            <span className="environment-chip">LOCAL · SYNTHETIC</span>
          </div>
          <div className="topbar-status">
            <span className={`status-dot ${health.isError ? 'offline' : ''}`} aria-hidden="true" />
            {health.isLoading ? 'Checking API' : apiReady ? 'API connected' : 'API unavailable'}
          </div>
        </header>
        <main id="main-content" className="main-content" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
