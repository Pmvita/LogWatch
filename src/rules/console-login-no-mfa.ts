import { iocsFrom } from '../iocs.ts'
import type { Finding, LogEvent } from '../types.ts'

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function isSuccess(event: LogEvent): boolean {
  const response = asRecord(event.raw.responseElements)
  const result = response?.ConsoleLogin
  return result === 'Success' || result == null
}

function mfaUsed(event: LogEvent): boolean {
  const extra = asRecord(event.raw.additionalEventData)
  const used = extra?.MFAUsed
  if (typeof used === 'string') return used.toLowerCase() === 'yes'
  const session = asRecord(asRecord(event.raw.userIdentity)?.sessionContext)
  const attrs = asRecord(session?.attributes)
  return attrs?.mfaAuthenticated === 'true' || attrs?.mfaAuthenticated === true
}

export function detectConsoleLoginNoMfa(events: LogEvent[]): Finding[] {
  const hits = events.filter(
    (event) =>
      event.source === 'cloudtrail' &&
      event.eventName === 'ConsoleLogin' &&
      isSuccess(event) &&
      !mfaUsed(event)
  )
  if (hits.length === 0) return []

  const users = [...new Set(hits.map((event) => event.user))].join(', ')
  return [
    {
      rule: 'console-login-no-mfa',
      severity: 'HIGH',
      title: 'Console login without MFA',
      detail: `${hits.length} successful console login(s) without MFA (${users}).`,
      nextStep: 'Disable the password-only session, require MFA on the user, and review CloudTrail for the same IP.',
      events: hits,
      iocs: iocsFrom(hits),
    },
  ]
}
