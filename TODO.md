# ✅ Logwatch — TODO

**Spec version:** 1.0 — 2026-09-18 (same version as [`README.md`](./README.md))

This checklist **is** the whole project. README = design; this file = build list.

**Locked scope:**

- CloudTrail or Windows Security JSON in
- Six rules: no-MFA console login, SG `0.0.0.0/0`, failed-logon burst (Windows 4625 / CloudTrail failures), root login, suspicious IAM, CloudTrail brute-force
- Markdown incident note
- Vitest only — no live AWS

---

## 🏗️ Project setup

- [x] package.json + TypeScript + Vitest
- [x] MIT LICENSE
- [x] `.gitignore` (node_modules, generated reports)
- [x] `bin/logwatch.js` CLI entry + GitHub Actions CI

---

## 📥 Input

- [x] Load CloudTrail `{ Records: [...] }`
- [x] Load Windows `{ events: [...] }`
- [x] Normalize to one event shape

---

## 🔎 Rules

- [x] `console-login-no-mfa`
- [x] `sg-open-to-world`
- [x] `failed-logon-burst` (5 in 10 minutes; CloudTrail Failure or Windows 4625)
- [x] `root-login`
- [x] `suspicious-iam`
- [x] `cloudtrail-brute-force`

---

## 📝 Output

- [x] Markdown: summary, findings, timeline, IOCs, next steps
- [x] CLI: path in, stdout / `--out`
- [x] Example report under `reports/example-incident.md`

---

## 🧪 Tests

- [x] Each of the six rules
- [x] Report contains the sections a screener should see
