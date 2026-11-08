import { describe, expect, it } from 'vitest'
import { normalizeEvents } from '../src/load.ts'
import { detectConsoleLoginNoMfa } from '../src/rules/console-login-no-mfa.ts'
import { detectFailedLogonBurst } from '../src/rules/failed-logon-burst.ts'
import { detectSgOpenToWorld } from '../src/rules/sg-open-to-world.ts'
import { detectRootLogin } from '../src/rules/root-login.ts'
import { detectSuspiciousIam } from '../src/rules/suspicious-iam.ts'
import { detectCloudtrailBruteForce } from '../src/rules/cloudtrail-brute-force.ts'
import { triage } from '../src/triage.ts'

const cloudtrail = {
  Records: [
    {
      eventTime: '2026-03-01T14:05:00Z',
      eventName: 'ConsoleLogin',
      eventID: 'no-mfa',
      sourceIPAddress: '198.51.100.44',
      userIdentity: { userName: 'alex' },
      responseElements: { ConsoleLogin: 'Success' },
      additionalEventData: { MFAUsed: 'No' },
    },
    {
      eventTime: '2026-03-01T14:12:00Z',
      eventName: 'AuthorizeSecurityGroupIngress',
      eventID: 'sg',
      sourceIPAddress: '198.51.100.44',
      userIdentity: { userName: 'alex' },
      requestParameters: {
        groupId: 'sg-0demo12',
        ipPermissions: { items: [{ ipRanges: { items: [{ cidrIp: '0.0.0.0/0' }] } }] },
      },
    },
  ],
}

describe('detections', () => {
  it('flags a console login without MFA', () => {
    const events = normalizeEvents(cloudtrail)
    const findings = detectConsoleLoginNoMfa(events)
    expect(findings[0]?.rule).toBe('console-login-no-mfa')
  })

  it('flags a security group opened to 0.0.0.0/0', () => {
    const events = normalizeEvents(cloudtrail)
    const findings = detectSgOpenToWorld(events)
    expect(findings[0]?.rule).toBe('sg-open-to-world')
    expect(findings[0]?.iocs.resources).toContain('sg-0demo12')
  })

  it('flags five failed Windows logons in ten minutes', () => {
    const events = normalizeEvents({
      events: Array.from({ length: 5 }, (_, i) => ({
        EventID: 4625,
        TimeCreated: `2026-03-01T15:0${i}:00Z`,
        TargetUserName: 'admin',
        IpAddress: '198.51.100.80',
      })),
    })
    const findings = detectFailedLogonBurst(events)
    expect(findings[0]?.rule).toBe('failed-logon-burst')
  })

  it('does not flag four failed logons', () => {
    const events = normalizeEvents({
      events: Array.from({ length: 4 }, (_, i) => ({
        EventID: 4625,
        TimeCreated: `2026-03-01T15:0${i}:00Z`,
        TargetUserName: 'admin',
        IpAddress: '198.51.100.80',
      })),
    })
    expect(detectFailedLogonBurst(events)).toHaveLength(0)
  })

  it('flags root account usage', () => {
    const events = normalizeEvents({
      Records: [
        {
          eventTime: '2026-03-02T09:00:00Z',
          eventName: 'ConsoleLogin',
          eventID: 'r1',
          userIdentity: { type: 'Root', arn: 'arn:aws:iam::123:root' },
          responseElements: { ConsoleLogin: 'Success' },
        },
      ],
    })
    expect(detectRootLogin(events)[0]?.rule).toBe('root-login')
  })

  it('flags suspicious IAM changes', () => {
    const events = normalizeEvents({
      Records: [
        {
          eventTime: '2026-03-02T09:05:00Z',
          eventName: 'CreateUser',
          eventID: 'i1',
          userIdentity: { type: 'IAMUser', userName: 'alex' },
          requestParameters: { userName: 'backdoor' },
        },
      ],
    })
    expect(detectSuspiciousIam(events)[0]?.rule).toBe('suspicious-iam')
  })

  it('flags a CloudTrail brute-force burst', () => {
    const events = normalizeEvents({
      Records: Array.from({ length: 5 }, (_, i) => ({
        eventTime: `2026-03-03T10:0${i}:00Z`,
        eventName: 'ConsoleLogin',
        eventID: `f${i}`,
        sourceIPAddress: '198.51.100.77',
        userIdentity: { type: 'IAMUser', userName: 'alice' },
        responseElements: { ConsoleLogin: 'Failure' },
      })),
    })
    expect(detectCloudtrailBruteForce(events)[0]?.rule).toBe('cloudtrail-brute-force')
  })

})
