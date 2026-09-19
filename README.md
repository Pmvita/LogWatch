# Logwatch

### Local log triage - findings become an incident note

Sample CloudTrail or Windows Security events in. A few detections fire. You get a markdown write-up: what happened, the timeline, and the IOCs.

![TypeScript](https://img.shields.io/badge/Runtime-TypeScript%20%2F%20Node-3178C6?logo=typescript&logoColor=white)
![Vitest](https://img.shields.io/badge/Tests-Vitest-6E9F18?logo=vitest&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

**Live:** [www.pierre-mvita.dev](https://www.pierre-mvita.dev)

---

**Spec version:** 1.0 - 2026-09-18 (same version as `[TODO.md](./TODO.md)`)

## Overview

A security lab for **triage**. Sample logs in, detections fire, markdown incident note out. No AWS account, no Npcap, no database. The demo is `npm run triage` against the bundled samples.

> **Built for:** a Security Analyst portfolio piece you can finish at $0 on Windows.



## Locked scope

- Inputs: CloudTrail `Records` JSON, or Windows Security events JSON
- Detections: console login without MFA, security group opened to `0.0.0.0/0`, failed-logon burst (5+ in 10 minutes)
- Output: markdown incident note (stdout, optional `--out`)
- Tests: Vitest, no live AWS
- No SIEM product, no auth, no auto-remediation



## Default cost

$0. All local.



## Tech stack


| Layer      | Technology                         | Purpose                                          |
| ---------- | ---------------------------------- | ------------------------------------------------ |
| Runtime    | Node.js + TypeScript               | Run detections and the CLI on Windows            |
| Runner     | tsx                                | `npm run triage` without a separate build        |
| Input      | CloudTrail / Windows Security JSON | Bundled samples in `samples/`                    |
| Detections | TypeScript rule functions          | No-MFA login, SG `0.0.0.0/0`, failed-logon burst |
| Output     | Markdown                           | Incident note to stdout or `--out`               |
| Tests      | Vitest                             | Rules + report, no live AWS                      |




## Flow

```
sample JSON ──► normalize ──► rules ──► incident note
```



## Detections


| Rule                   | Severity | Fires when                                                                                                  |
| ---------------------- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `console-login-no-mfa` | HIGH     | CloudTrail `ConsoleLogin` success and MFA was not used                                                      |
| `sg-open-to-world`     | HIGH     | `AuthorizeSecurityGroupIngress` allows `0.0.0.0/0`                                                          |
| `failed-logon-burst`   | MEDIUM   | 5+ failed logons (CloudTrail `ConsoleLogin` Failure or Windows 4625) from the same user or IP in 10 minutes |




## Getting started

```bash
cd Logwatch
npm install
npm test
npm run triage
npm run triage -- samples/windows-security.json --out reports/incident.md
```



## Project structure

```
samples/     bundled CloudTrail + Windows events
src/load.ts  normalize either format
src/rules/   the three detections
src/report.ts  markdown incident note
src/cli.ts   file in, note out
tests/       Vitest
```



## License

MIT. See [LICENSE](./LICENSE).