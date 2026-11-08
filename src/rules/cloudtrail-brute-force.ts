import { iocsFrom } from '../iocs.ts'
import type { Finding, LogEvent } from '../types.ts'

const WINDOW_MS = 10 * 60 * 1000
const THRESHOLD = 5

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function isFailedCloudTrailLogin(event: LogEvent): boolean {
  if (event.source !== 'cloudtrail' || event.eventName !== 'ConsoleLogin') return false
  const response = asRecord(event.raw.responseElements)
  return response?.ConsoleLogin === 'Failure'
}

export function detectCloudtrailBruteForce(events: LogEvent[]): Finding[] {
  const failures = events.filter(isFailedCloudTrailLogin)
  const groups = new Map<string, LogEvent[]>()
  for (const event of failures) {
    const key = event.sourceIp !== 'unknown' ? `ip:${event.sourceIp}` : `user:${event.user}`
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
          rule: 'cloudtrail-brute-force',
          severity: 'MEDIUM',
          title: 'CloudTrail brute-force attempt',
          detail: `${window.length} failed console logins for ${key} inside 10 minutes.`,
          nextStep: 'Block or rate-limit the source, lock the targeted account, and review for a later successful login.',
          events: window,
          iocs: iocsFrom(window),
        })
        break
      }
    }
  }
  return findings
}

export const detectCloudTrailBruteForce = detectCloudtrailBruteForce
export const detectBruteForceCloudTrail = detectCloudtrailBruteForce
export const detectCloudtrailBruteforce = detectCloudtrailBruteForce