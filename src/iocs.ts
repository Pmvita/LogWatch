import type { Iocs, LogEvent } from './types.ts'

function unique(values: string[]): string[] {
  return [...new Set(values.filter((value) => value && value !== 'unknown'))].sort()
}

export function iocsFrom(events: LogEvent[]): Iocs {
  return {
    users: unique(events.map((event) => event.user)),
    ips: unique(events.map((event) => event.sourceIp)),
    resources: unique(events.map((event) => event.resource)),
  }
}

export function mergeIocs(findingsIocs: Iocs[]): Iocs {
  return {
    users: unique(findingsIocs.flatMap((item) => item.users)),
    ips: unique(findingsIocs.flatMap((item) => item.ips)),
    resources: unique(findingsIocs.flatMap((item) => item.resources)),
  }
}
