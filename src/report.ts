import type { IncidentNote } from './types.ts'

function listOrNone(values: string[]): string {
  return values.length === 0 ? '- none' : values.map((value) => `- ${value}`).join('\n')
}

export function formatIncidentNote(note: IncidentNote): string {
  const findingBlocks =
    note.findings.length === 0
      ? '- none'
      : note.findings
          .map((finding) =>
            [
              `### [${finding.severity}] ${finding.rule}`,
              '',
              finding.title,
              '',
              finding.detail,
              '',
              `Next: ${finding.nextStep}`,
            ].join('\n')
          )
          .join('\n\n')

  const timeline =
    note.timeline.length === 0
      ? '- none'
      : note.timeline
          .map(
            (event) =>
              `- ${event.timestamp} | ${event.eventName} | ${event.user} | ${event.sourceIp}`
          )
          .join('\n')

  return [
    '# Logwatch incident note',
    '',
    note.summary,
    '',
    `Source: ${note.sourceLabel}`,
    '',
    '## Findings',
    '',
    findingBlocks,
    '',
    '## Timeline',
    '',
    timeline,
    '',
    '## IOCs',
    '',
    'Users:',
    listOrNone(note.iocs.users),
    '',
    'IPs:',
    listOrNone(note.iocs.ips),
    '',
    'Resources:',
    listOrNone(note.iocs.resources),
    '',
  ].join('\n')
}
