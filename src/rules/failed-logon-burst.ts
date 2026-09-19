import { iocsFrom } from '../iocs.ts'
import type { Finding, LogEvent } from '../types.ts'

const WINDOW_MS = 10 * 60 * 1000
const THRESHOLD = 5

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function isFailedLogon(event: LogEvent): boolean {
  if (event.source === 'windows' && event.eventName === '4625') return true
  if (event.source !== 'cloudtrail' || event.eventName !== 'ConsoleLogin') {
    return false
  }
  const response = asRecord(event.raw.responseElements)
  return response?.ConsoleLogin === 'Failure'
}

function keyFor(event: LogEvent): string {
  if (event.user !== 'unknown') return `user:${event.user}`
  return `ip:${event.sourceIp}`
}

export function detectFailedLogonBurst(events: LogEvent[]): Finding[] {
  const failures = events.filter(isFailedLogon)
  const groups = new Map<string, LogEvent[]>()
  for (const event of failures) {
    const key = keyFor(event)
    const list = groups.get(key) ?? []
    list.push(event)
    groups.set(key, list)
  }

  const findings: Finding[] = []
  for (const [key, group] of groups) {
    const ordered = [...group].sort((a, b) => a.timestampMs - b.timestampMs)
    for (let i = 0; i < ordered.length; i += 1) {
      const window = ordered.filter(
        (event) =>
          event.timestampMs >= ordered[i].timestampMs &&
          event.timestampMs - ordered[i].timestampMs <= WINDOW_MS
      )
      if (window.length >= THRESHOLD) {
        findings.push({
          rule: 'failed-logon-burst',
          severity: 'MEDIUM',
          title: 'Failed logon burst',
          detail: `${window.length} failed logons for ${key} inside 10 minutes.`,
          nextStep: 'Lock or reset the account, block the source IP if it is foreign to the user, and watch for a later success.',
          events: window,
          iocs: iocsFrom(window),
        })
        break
      }
    }
  }
  return findings
}
