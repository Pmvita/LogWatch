import { mergeIocs } from './iocs.ts'
import { sourceLabel } from './load.ts'
import { runRules } from './rules/index.ts'
import type { IncidentNote, LogEvent } from './types.ts'

export function triage(events: LogEvent[]): IncidentNote {
  const findings = runRules(events)
  const summary =
    findings.length === 0
      ? `Reviewed ${events.length} event(s). No detections crossed the thresholds.`
      : `Reviewed ${events.length} event(s). ${findings.length} finding(s) to follow up.`

  return {
    eventCount: events.length,
    sourceLabel: sourceLabel(events),
    findings,
    timeline: events,
    iocs: mergeIocs(findings.map((finding) => finding.iocs)),
    summary,
  }
}
