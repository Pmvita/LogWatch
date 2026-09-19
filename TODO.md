# ✅ Logwatch — TODO

**Spec version:** 1.0 — 2026-09-18 (same version as [`README.md`](./README.md))

This checklist **is** the whole project. README = design; this file = build list.

**Locked scope:**

- CloudTrail or Windows Security JSON in
- Three rules: no-MFA console login, SG `0.0.0.0/0`, failed-logon burst
- Markdown incident note
- Vitest only — no live AWS

---

## 🏗️ Project setup

- [x] package.json + TypeScript + Vitest
- [x] MIT LICENSE
- [x] `.gitignore` (node_modules, generated reports)

---

## 📥 Input

- [x] Load CloudTrail `{ Records: [...] }`
- [x] Load Windows `{ events: [...] }`
- [x] Normalize to one event shape

---

## 🔎 Rules

- [x] `console-login-no-mfa`
- [x] `sg-open-to-world`
- [x] `failed-logon-burst` (5 in 10 minutes)

---

## 📝 Output

- [x] Markdown: summary, findings, timeline, IOCs, next steps
- [x] CLI: path in, stdout / `--out`

---

## 🧪 Tests

- [x] Each rule
- [x] Report contains the three sections a screener should see
