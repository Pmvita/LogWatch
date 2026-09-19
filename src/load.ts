import { readFileSync } from 'node:fs'
import type { LogEvent } from './types.ts'

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function text(value: unknown, fallback = 'unknown'): string {
  return typeof value === 'string' && value.length > 0 ? value : fallback
}

function parseTime(value: unknown): { iso: string; ms: number } {
  const raw = text(value, '')
  const ms = Date.parse(raw)
  if (Number.isFinite(ms)) {
    return { iso: new Date(ms).toISOString(), ms }
  }
  return { iso: new Date(0).toISOString(), ms: 0 }
}

function cloudTrailUser(raw: Record<string, unknown>): string {
  const identity = asRecord(raw.userIdentity)
  if (!identity) return 'unknown'
  return text(identity.userName, text(identity.principalId, text(identity.arn)))
}

function cloudTrailResource(raw: Record<string, unknown>): string {
  const params = asRecord(raw.requestParameters)
  if (!params) return 'unknown'
  const named = text(params.groupId, text(params.bucketName, ''))
  return named && named !== 'unknown' ? named : 'unknown'
}

function isCloudTrail(raw: Record<string, unknown>): boolean {
  return (
    typeof raw.eventName === 'string' ||
    typeof raw.eventSource === 'string' ||
    asRecord(raw.userIdentity) !== null
  )
}

function isWindows(raw: Record<string, unknown>): boolean {
  return typeof raw.EventID === 'number' || typeof raw.EventID === 'string'
}

function normalizeOne(raw: Record<string, unknown>, index: number): LogEvent {
  if (isWindows(raw)) {
    const time = parseTime(raw.TimeCreated ?? raw.timeCreated)
    return {
      id: text(raw.RecordId, `win-${index + 1}`),
      timestamp: time.iso,
      timestampMs: time.ms,
      source: 'windows',
      eventName: String(raw.EventID ?? 'unknown'),
      user: text(raw.TargetUserName, text(raw.SubjectUserName)),
      sourceIp: text(raw.IpAddress),
      resource: text(raw.WorkstationName, 'windows-host'),
      raw,
    }
  }

  if (isCloudTrail(raw)) {
    const time = parseTime(raw.eventTime)
    return {
      id: text(raw.eventID, `ct-${index + 1}`),
      timestamp: time.iso,
      timestampMs: time.ms,
      source: 'cloudtrail',
      eventName: text(raw.eventName),
      user: cloudTrailUser(raw),
      sourceIp: text(raw.sourceIPAddress),
      resource: cloudTrailResource(raw),
      raw,
    }
  }

  const time = parseTime(raw.timestamp ?? raw.eventTime ?? raw.TimeCreated)
  return {
    id: text(raw.id, `evt-${index + 1}`),
    timestamp: time.iso,
    timestampMs: time.ms,
    source: 'unknown',
    eventName: text(raw.eventName, text(raw.EventID)),
    user: text(raw.user),
    sourceIp: text(raw.sourceIp, text(raw.sourceIPAddress)),
    resource: text(raw.resource),
    raw,
  }
}

export function extractRawEvents(payload: unknown): Record<string, unknown>[] {
  if (Array.isArray(payload)) {
    return payload.map(asRecord).filter((item): item is Record<string, unknown> => item !== null)
  }
  const root = asRecord(payload)
  if (!root) return []
  if (Array.isArray(root.Records)) {
    return root.Records.map(asRecord).filter((item): item is Record<string, unknown> => item !== null)
  }
  if (Array.isArray(root.events)) {
    return root.events.map(asRecord).filter((item): item is Record<string, unknown> => item !== null)
  }
  return [root]
}

export function normalizeEvents(payload: unknown): LogEvent[] {
  return extractRawEvents(payload)
    .map((raw, index) => normalizeOne(raw, index))
    .sort((a, b) => a.timestampMs - b.timestampMs)
}

export function loadEventsFromFile(path: string): LogEvent[] {
  const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'))
  return normalizeEvents(parsed)
}

export function sourceLabel(events: LogEvent[]): string {
  const sources = new Set(events.map((event) => event.source))
  if (sources.size === 1) return [...sources][0]
  if (sources.size === 0) return 'empty'
  return 'mixed'
}
