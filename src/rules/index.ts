import type { Finding, LogEvent } from '../types.ts'
import { detectConsoleLoginNoMfa } from './console-login-no-mfa.ts'
import { detectFailedLogonBurst } from './failed-logon-burst.ts'
import { detectSgOpenToWorld } from './sg-open-to-world.ts'
import { detectRootLogin } from './root-login.ts'
import { detectSuspiciousIam } from './suspicious-iam.ts'
import { detectCloudtrailBruteForce } from './cloudtrail-brute-force.ts'

const RULES = [
  detectConsoleLoginNoMfa,
  detectSgOpenToWorld,
  detectFailedLogonBurst,
  detectRootLogin,
  detectSuspiciousIam,
  detectCloudtrailBruteForce,
]

export function runRules(events: LogEvent[]): Finding[] {
  return RULES.flatMap((rule) => rule(events))
}
