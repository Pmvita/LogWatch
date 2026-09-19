import { iocsFrom } from '../iocs.ts'
import type { Finding, LogEvent } from '../types.ts'

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function collectCidrs(value: unknown, into: string[]): void {
  if (typeof value === 'string') {
    into.push(value)
    return
  }
  if (Array.isArray(value)) {
    for (const item of value) collectCidrs(item, into)
    return
  }
  const record = asRecord(value)
  if (!record) return
  if (typeof record.cidrIp === 'string') into.push(record.cidrIp)
  if (typeof record.CidrIp === 'string') into.push(record.CidrIp)
  for (const nested of Object.values(record)) collectCidrs(nested, into)
}

function opensToWorld(event: LogEvent): boolean {
  const params = asRecord(event.raw.requestParameters)
  if (!params) return false
  const cidrs: string[] = []
  collectCidrs(params.ipPermissions ?? params.cidrIp ?? params.CidrIp, cidrs)
  if (typeof params.cidrIp === 'string') cidrs.push(params.cidrIp)
  return cidrs.includes('0.0.0.0/0')
}

export function detectSgOpenToWorld(events: LogEvent[]): Finding[] {
  const hits = events.filter(
    (event) =>
      event.source === 'cloudtrail' &&
      event.eventName === 'AuthorizeSecurityGroupIngress' &&
      opensToWorld(event)
  )
  if (hits.length === 0) return []

  const groups = [...new Set(hits.map((event) => event.resource))].join(', ')
  return [
    {
      rule: 'sg-open-to-world',
      severity: 'HIGH',
      title: 'Security group opened to the world',
      detail: `${hits.length} ingress change(s) allowed 0.0.0.0/0 (${groups}).`,
      nextStep: 'Revert the rule, restrict the CIDR, and check what used the group after the change.',
      events: hits,
      iocs: iocsFrom(hits),
    },
  ]
}
