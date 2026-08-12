import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

class ResizeObserverMock {
  observe() {
    // Recharts needs the browser API; layout behavior is covered by production build and browser QA.
  }

  unobserve() {
    // No-op in deterministic component tests.
  }

  disconnect() {
    // No-op in deterministic component tests.
  }
}

vi.stubGlobal('ResizeObserver', ResizeObserverMock)

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

