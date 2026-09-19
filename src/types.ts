export type EventSource = 'cloudtrail' | 'windows' | 'unknown'

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH'

export type LogEvent = {
  id: string
  timestamp: string
  timestampMs: number
  source: EventSource
  eventName: string
  user: string
  sourceIp: string
  resource: string
  raw: Record<string, unknown>
}

export type Iocs = {
  users: string[]
  ips: string[]
  resources: string[]
}

export type Finding = {
  rule: string
  severity: Severity
  title: string
  detail: string
  nextStep: string
  events: LogEvent[]
  iocs: Iocs
}

export type IncidentNote = {
  eventCount: number
  sourceLabel: string
  findings: Finding[]
  timeline: LogEvent[]
  iocs: Iocs
  summary: string
}
