import { iocsFrom } from '../iocs.ts'
import type { Finding, LogEvent } from '../types.ts'

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function isRootIdentity(event: LogEvent): boolean {
  if (event.source !== 'cloudtrail') return false
  const identity = asRecord(event.raw.userIdentity)
  if (!identity) return false
  const type = identity.type
  if (typeof type === 'string' && type.toLowerCase() === 'root') return true
  const userName = identity.userName
  if (typeof userName === 'string' && userName.toLowerCase() === 'root') return true
  const arn = identity.arn
  if (typeof arn === 'string' && /:root$/i.test(arn)) return true
  return false
}

export function detectRootLogin(events: LogEvent[]): Finding[] {
  const hits = events.filter(isRootIdentity)
  if (hits.length === 0) return []

  const users = [...new Set(hits.map((event) => event.user))].join(', ')
  return [
    {
      rule: 'root-login',
      severity: 'HIGH',
      title: 'Root account used',
      detail: `${hits.length} event(s) performed by the root account (${users}).`,
      nextStep: 'Confirm the action was intended, rotate root credentials, and enforce MFA on the root account.',
      events: hits,
      iocs: iocsFrom(hits),
    },
  ]
}

// Aliases for compatibility with alternate naming.
export const detectRootAccountUsage = detectRootLogin
export const detectRootAccount = detectRootLogin
export const detectRootAccountLogin = detectRootLogin