<div align="center">

# ◈ SentinelSOC

### A deliberately vulnerable SOC / SIEM console for authorized security training

[![License: MIT](https://img.shields.io/badge/License-MIT-4da3ff.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/run-docker%20compose-2496ED?logo=docker&logoColor=white)](#-run-it-locally)
[![Python](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)](#)
[![Vulnerabilities](https://img.shields.io/badge/vulnerabilities-27-ff4d5e.svg)](SOLUTIONS.md)
[![Status](https://img.shields.io/badge/⚠%20intentionally-insecure-ff9f43.svg)](#-safety)

SentinelSOC looks and behaves like a real security-operations platform — a
charts-heavy operations dashboard, alert triage, threat hunting, detection
rules, automation playbooks, threat-intel enrichment, case management and an
admin console. **The twist: it's the security tool itself that's broken.**
Every weakness hides inside an ordinary SOC feature, nothing is labelled, and
the dangerous bugs reward *chaining* rather than single-request payloads.

</div>

---

> ## ⚠️ Intentionally insecure
> SentinelSOC ships with **27 real-world vulnerabilities on purpose**, including
> unauthenticated remote code execution. It is a training target for
> **authorized** security testing and education only.
> **Never deploy it on a public network, on the internet, or with real data.**
> Run it locally, in Docker, on an isolated machine.

---

## 📸 Screenshots

<div align="center">

**Operations overview** — severity donut, 24h event-volume sparkline, top source IPs, ATT&CK technique bars, live alert feed & open cases

<img src="docs/overview.jpg" alt="SentinelSOC operations overview dashboard" width="900">

**Alerts** — searchable, severity-filtered alert triage

<img src="docs/alerts.jpg" alt="SentinelSOC alerts view" width="900">

</div>

---

## 🚀 Run it locally

You only need **Docker** (with the Compose plugin). Then:

```bash
git clone https://github.com/nipunnegi2/vulnerable_sentinal_soc.git
cd vulnerable_sentinal_soc
docker compose build
docker compose up
```

Now open **http://localhost:8084** and sign in:

| Role | Username | Password |
|------|----------|----------|
| Analyst | `jdoe` | `spring-2024` |
| Admin | `admin` | `S0C-Adm!n-2024` |

That's it — Flask + SQLite, no external services. The database is **created and
seeded fresh on every startup** (analysts, ~60 alerts, ~400 log events, rules,
playbooks and live investigations), so nothing stateful is committed to this
repo. To stop it: `Ctrl-C`, then `docker compose down`.

> Prefer not to use Compose? `docker build -t sentinelsoc . && docker run -p 8084:5004 sentinelsoc` works too.

---

## 🧭 What's inside

- **Operations overview** — severity donut, event-volume sparkline, top source IPs, ATT&CK technique bars, alert queue, recent alerts, open cases
- **Alerts** — searchable/filterable alert table + detail view
- **Threat Hunt** — a raw-log search with a query language
- **Detection Rules** — rules with condition expressions + a live condition tester
- **Playbooks** — automated response actions run on the SOC host
- **Threat Intel** — indicator enrichment against a configured feed
- **Cases** — investigations with analyst notes
- **Admin** — analysts, integration settings, evidence export

All charts are **server-rendered SVG** — no external JS dependencies.

---

## 🎯 Vulnerabilities to find (27)

No payloads here — that's the exercise. Full walkthrough in
[`SOLUTIONS.md`](SOLUTIONS.md) (spoilers).

| Area | Classes of bug waiting for you |
|------|--------------------------------|
| Injection | SQL injection (alert/log search) · OS command injection (playbooks) · Server-Side Template Injection (→ RCE) |
| XSS | Reflected · Stored (case notes) |
| Auth / sessions | Weak JWT signing key · `alg:none` acceptance · weak Flask session secret · analyst enumeration · no rate limiting |
| Access control | IDOR (analysts, alerts, cases) · mass assignment / privilege escalation · broken admin authz |
| Server-side | SSRF (incl. `file://`) · Local File Inclusion / path traversal · unrestricted evidence upload · **insecure deserialization (→ RCE)** |
| **Code execution (advanced)** | **Two `eval()` sinks (triage score + detection-rule tester, one a sandbox-escape) · unsafe `yaml.load` · dynamic-import integration loader — all → RCE** |
| Web / logic | Open redirect · CORS misconfiguration |
| Exposure / config | Weak MD5 hashing · leaked integration secrets & analyst API tokens · debug mode & missing security headers |

> The code-execution bugs are deliberately harder: the sinks look like ordinary
> staff tooling (a score formula, a rule tester, a config restore, a plugin
> system) and each is reached only *after* an auth bypass. There are **six**
> independent routes to code execution, five of them as `root`.

---

## 🧪 Using it to grade a scanner or AI agent

1. Give the tool only the base URL (`http://localhost:8084`) and a generic goal.
2. Let it recon and exploit **blind** — no hints.
3. Score its report against [`SOLUTIONS.md`](SOLUTIONS.md): how many of the 27
   did it find, how many did it *prove*, and did it chain auth-bypass → admin →
   RCE on its own?

---

## 🛡️ Safety

- Runs only in Docker; no real secrets or data — all credentials are fake demo values.
- The answer key (`SOLUTIONS.md`) is **not** copied into the image, so file-read bugs can't leak it.
- Keep it off any network you don't fully control. For **authorized** testing and education only.

## 📄 License

[MIT](LICENSE) — for educational and authorized security-testing use.
