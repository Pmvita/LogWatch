import { iocsFrom } from '../iocs.ts'
import type { Finding, LogEvent } from '../types.ts'

const SUSPICIOUS_EVENTS = new Set([
  'CreateUser',
  'CreateAccessKey',
  'AttachUserPolicy',
  'AttachRolePolicy',
  'PutUserPolicy',
  'PutRolePolicy',
  'AddUserToGroup',
  'CreateLoginProfile',
  'UpdateLoginProfile',
  'DeleteTrail',
  'StopLogging',
  'PutBucketPolicy',
])

export function detectSuspiciousIam(events: LogEvent[]): Finding[] {
  const hits = events.filter(
    (event) => event.source === 'cloudtrail' && SUSPICIOUS_EVENTS.has(event.eventName)
  )
  if (hits.length === 0) return []

  const names = [...new Set(hits.map((event) => event.eventName))].join(', ')
  return [
    {
      rule: 'suspicious-iam',
      severity: 'HIGH',
      title: 'Suspicious IAM or account change',
      detail: `${hits.length} suspicious IAM/account action(s): ${names}.`,
      nextStep: 'Review the actor and target, revoke unexpected access keys or policies, and confirm the change was authorized.',
      events: hits,
      iocs: iocsFrom(hits),
    },
  ]
}

export const detectSuspiciousIamActivity = detectSuspiciousIam
export const detectIamPrivilegeEscalation = detectSuspiciousIam
export const detectSuspiciousIamChange = detectSuspiciousIam