# Logwatch incident note

Reviewed 6 event(s). 1 finding(s) to follow up.

Source: windows

## Findings

### [MEDIUM] failed-logon-burst

Failed logon burst

5 failed logons for user:admin inside 10 minutes.

Next: Lock or reset the account, block the source IP if it is foreign to the user, and watch for a later success.

## Timeline

- 2026-03-01T15:00:00.000Z | 4624 | jordan | 203.0.113.10
- 2026-03-01T15:01:00.000Z | 4625 | admin | 198.51.100.80
- 2026-03-01T15:01:20.000Z | 4625 | admin | 198.51.100.80
- 2026-03-01T15:01:40.000Z | 4625 | admin | 198.51.100.80
- 2026-03-01T15:02:00.000Z | 4625 | admin | 198.51.100.80
- 2026-03-01T15:02:20.000Z | 4625 | admin | 198.51.100.80

## IOCs

Users:
- admin

IPs:
- 198.51.100.80

Resources:
- WS-01
