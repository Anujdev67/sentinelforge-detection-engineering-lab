const API_BASE = import.meta.env.VITE_API_URL ?? ''

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message)
  }
}

export async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const headers = new Headers(options?.headers)
  headers.set('Accept', 'application/json')
  if (options?.body) headers.set('Content-Type', 'application/json')
  const response = await fetch(`${API_BASE}/api/v1${path}`, {
    ...options,
    headers,
  })
  if (!response.ok) {
    const body = (await response.json().catch(() => ({ detail: response.statusText }))) as {
      detail?: string
    }
    throw new ApiError(body.detail ?? 'Request failed', response.status)
  }
  return (await response.json()) as T
}

export function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

export function titleCase(value: string): string {
  return value.replaceAll('_', ' ').replace(/\b\w/g, (character) => character.toUpperCase())
}
