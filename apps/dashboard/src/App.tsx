import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { LoadingState } from './components/Ui'

const AnalyticsPage = lazy(() => import('./pages/AnalyticsPage').then((module) => ({ default: module.AnalyticsPage })))
const ArchitecturePage = lazy(() => import('./pages/ArchitecturePage').then((module) => ({ default: module.ArchitecturePage })))
const AttackCoveragePage = lazy(() => import('./pages/AttackCoveragePage').then((module) => ({ default: module.AttackCoveragePage })))
const DetectionLibraryPage = lazy(() => import('./pages/DetectionLibraryPage').then((module) => ({ default: module.DetectionLibraryPage })))
const IncidentDetailPage = lazy(() => import('./pages/IncidentDetailPage').then((module) => ({ default: module.IncidentDetailPage })))
const IncidentQueuePage = lazy(() => import('./pages/IncidentQueuePage').then((module) => ({ default: module.IncidentQueuePage })))
const OverviewPage = lazy(() => import('./pages/OverviewPage').then((module) => ({ default: module.OverviewPage })))
const RuleQualityPage = lazy(() => import('./pages/RuleQualityPage').then((module) => ({ default: module.RuleQualityPage })))
const ThreatHuntingPage = lazy(() => import('./pages/ThreatHuntingPage').then((module) => ({ default: module.ThreatHuntingPage })))
const ThreatIntelligencePage = lazy(() => import('./pages/ThreatIntelligencePage').then((module) => ({ default: module.ThreatIntelligencePage })))

export default function App() {
  return (
    <Suspense fallback={<LoadingState />}>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<OverviewPage />} />
          <Route path="incidents" element={<IncidentQueuePage />} />
          <Route path="incidents/:incidentId" element={<IncidentDetailPage />} />
          <Route path="threat-intelligence" element={<ThreatIntelligencePage />} />
          <Route path="analytics" element={<AnalyticsPage />} />
          <Route path="detections" element={<DetectionLibraryPage />} />
          <Route path="rule-quality" element={<RuleQualityPage />} />
          <Route path="hunting" element={<ThreatHuntingPage />} />
          <Route path="attack-coverage" element={<AttackCoveragePage />} />
          <Route path="architecture" element={<ArchitecturePage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  )
}
