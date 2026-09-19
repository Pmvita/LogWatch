import type { Finding, LogEvent } from '../types.ts'
import { detectConsoleLoginNoMfa } from './console-login-no-mfa.ts'
import { detectFailedLogonBurst } from './failed-logon-burst.ts'
import { detectSgOpenToWorld } from './sg-open-to-world.ts'

const RULES = [
  detectConsoleLoginNoMfa,
  detectSgOpenToWorld,
  detectFailedLogonBurst,
]

export function runRules(events: LogEvent[]): Finding[] {
  return RULES.flatMap((rule) => rule(events))
}
