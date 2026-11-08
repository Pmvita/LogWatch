# Logwatch incident note

Reviewed 4 event(s). 2 finding(s) to follow up.

Source: cloudtrail

## Findings

### [HIGH] console-login-no-mfa

Console login without MFA

1 successful console login(s) without MFA (alex).

Next: Disable the password-only session, require MFA on the user, and review CloudTrail for the same IP.

### [HIGH] sg-open-to-world

Security group opened to the world

1 ingress change(s) allowed 0.0.0.0/0 (sg-0demo12).

Next: Revert the rule, restrict the CIDR, and check what used the group after the change.

## Timeline

- 2026-03-01T14:00:00.000Z | ConsoleLogin | jordan | 203.0.113.10
- 2026-03-01T14:05:00.000Z | ConsoleLogin | alex | 198.51.100.44
- 2026-03-01T14:12:00.000Z | AuthorizeSecurityGroupIngress | alex | 198.51.100.44
- 2026-03-01T14:20:00.000Z | GetObject | jordan | 203.0.113.10

## IOCs

Users:
- alex

IPs:
- 198.51.100.44

Resources:
- sg-0demo12
