import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { loadEventsFromFile } from '../src/load.ts'
import { formatIncidentNote } from '../src/report.ts'
import { triage } from '../src/triage.ts'

describe('incident note', () => {
  it('writes findings, timeline, and IOCs for the CloudTrail sample', () => {
    const events = loadEventsFromFile(resolve('samples/cloudtrail.json'))
    const text = formatIncidentNote(triage(events))
    expect(text).toContain('# Logwatch incident note')
    expect(text).toContain('## Findings')
    expect(text).toContain('## Timeline')
    expect(text).toContain('## IOCs')
    expect(text).toContain('console-login-no-mfa')
    expect(text).toContain('sg-open-to-world')
    expect(text).toContain('198.51.100.44')
  })

  it('flags the Windows failed-logon sample', () => {
    const events = loadEventsFromFile(resolve('samples/windows-security.json'))
    const text = formatIncidentNote(triage(events))
    expect(text).toContain('failed-logon-burst')
    expect(text).toContain('admin')
  })

  it('can parse the bundled sample files as JSON', () => {
    JSON.parse(readFileSync(resolve('samples/cloudtrail.json'), 'utf8'))
    JSON.parse(readFileSync(resolve('samples/windows-security.json'), 'utf8'))
  })
})
