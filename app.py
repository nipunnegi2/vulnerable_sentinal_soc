"""
SentinelSOC — a small security-operations console (SIEM/SOAR-style).

A deliberately insecure but realistic enterprise web application for authorized
security training in an isolated lab. The weaknesses live inside ordinary SOC
features — alert triage, log hunting, detection rules, automation playbooks,
threat-intel enrichment, case management, integrations and an admin console —
nothing here is labelled as a vulnerability, the way it is in real codebases.
"""
import base64
import hashlib
import importlib
import io
import json
import os
import pickle
import random
import sqlite3
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timedelta

import jwt
import requests
import yaml
from flask import (Flask, Response, g, jsonify, redirect, render_template,
                   render_template_string, request, session)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "data", "sentinel.db")
EVIDENCE_DIR = os.path.join(APP_DIR, "evidence")
PLUGIN_DIR = os.path.join(APP_DIR, "integrations")

# Short, guessable dev secret, reused for both JWTs and Flask sessions.
JWT_SECRET = "sentinel"

if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

app = Flask(__name__)
app.secret_key = JWT_SECRET

SEV_COLORS = {"critical": "#ff4d5e", "high": "#ff9f43", "medium": "#4da3ff",
              "low": "#2ed573", "info": "#8b93a7"}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close(_exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def setting(key, default=""):
    row = db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    os.makedirs(PLUGIN_DIR, exist_ok=True)
    with open(os.path.join(PLUGIN_DIR, "__init__.py"), "w") as fh:
        fh.write("# SentinelSOC integrations package\n")
    con = sqlite3.connect(DB_PATH)
    con.executescript(
        """
        DROP TABLE IF EXISTS analysts; DROP TABLE IF EXISTS alerts;
        DROP TABLE IF EXISTS events;   DROP TABLE IF EXISTS rules;
        DROP TABLE IF EXISTS playbooks; DROP TABLE IF EXISTS cases;
        DROP TABLE IF EXISTS notes;    DROP TABLE IF EXISTS settings;
        CREATE TABLE analysts (id INTEGER PRIMARY KEY, username TEXT, email TEXT,
            password TEXT, role TEXT, full_name TEXT, team TEXT, phone TEXT,
            api_token TEXT);
        CREATE TABLE alerts (id INTEGER PRIMARY KEY, ts TEXT, severity TEXT,
            title TEXT, source_ip TEXT, dest_ip TEXT, host TEXT, technique TEXT,
            status TEXT, assignee TEXT, raw TEXT);
        CREATE TABLE events (id INTEGER PRIMARY KEY, ts TEXT, host TEXT,
            source TEXT, severity TEXT, message TEXT);
        CREATE TABLE rules (id INTEGER PRIMARY KEY, name TEXT, severity TEXT,
            condition TEXT, playbook_id INTEGER, enabled INTEGER);
        CREATE TABLE playbooks (id INTEGER PRIMARY KEY, name TEXT, description TEXT,
            command TEXT, enabled INTEGER);
        CREATE TABLE cases (id INTEGER PRIMARY KEY, title TEXT, severity TEXT,
            status TEXT, owner TEXT, summary TEXT);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, case_id INTEGER, author TEXT,
            body TEXT);
        CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
        """
    )
    analysts = [
        (1, "admin", "admin@sentinelsoc.test", md5("S0C-Adm!n-2024"), "admin",
         "SOC Administrator", "Platform", "+1-555-0100", "tok_admin_7f1a9c"),
        (2, "jdoe", "jdoe@corp.example", md5("spring-2024"), "analyst",
         "Jamie Doe", "Tier-1", "+1-555-0111", "tok_jdoe_22b4e1"),
        (3, "msmith", "msmith@corp.example", md5("hunter2"), "analyst",
         "Morgan Smith", "Tier-2", "+1-555-0122", "tok_msmith_9d7c03"),
        (4, "klee", "klee@corp.example", md5("W1nter!2024"), "analyst",
         "Kai Lee", "Threat-Intel", "+1-555-0133", "tok_klee_4e6f88"),
    ]
    con.executemany("INSERT INTO analysts VALUES (?,?,?,?,?,?,?,?,?)", analysts)

    now = datetime.utcnow()
    techniques = ["T1059 Command & Scripting", "T1110 Brute Force",
                  "T1566 Phishing", "T1048 Exfiltration", "T1021 Remote Services",
                  "T1486 Ransomware", "T1055 Process Injection", "T1190 Exploit Public App"]
    titles = ["Multiple failed logins", "Suspicious PowerShell spawned",
              "Outbound to known-bad IP", "Possible data staging",
              "New admin account created", "Unusual RDP session",
              "Malicious macro detected", "Port scan from internal host",
              "DNS tunnelling suspected", "Credential dumping tool signature"]
    hosts = ["WIN-DC01", "WIN-APP03", "LNX-WEB02", "LNX-DB01", "WIN-FS04",
             "WIN-HR07", "LNX-BUILD1", "WIN-CEO-LT"]
    statuses = ["new", "new", "new", "ack", "ack", "closed"]
    alerts = []
    for i in range(1, 61):
        sev = random.choices(SEV_ORDER, weights=[6, 14, 30, 30, 20])[0]
        ts = (now - timedelta(minutes=random.randint(0, 720))).strftime("%Y-%m-%d %H:%M")
        sip = f"10.0.{random.randint(0,6)}.{random.randint(2,250)}"
        dip = random.choice([f"185.220.{random.randint(0,255)}.{random.randint(1,254)}",
                             f"45.133.{random.randint(0,255)}.{random.randint(1,254)}",
                             f"10.0.{random.randint(0,6)}.{random.randint(2,250)}"])
        alerts.append((1000 + i, ts, sev, random.choice(titles), sip, dip,
                       random.choice(hosts), random.choice(techniques),
                       random.choice(statuses),
                       random.choice(["", "jdoe", "msmith", "klee"]),
                       f"src={sip} dst={dip} proto=tcp action=alert"))
    con.executemany(
        "INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?)", alerts)

    sources = ["firewall", "edr", "auth", "dns", "proxy", "ids"]
    events = []
    for i in range(1, 400):
        ts = (now - timedelta(minutes=random.randint(0, 720))).strftime("%Y-%m-%d %H:%M:%S")
        src = random.choice(sources)
        sev = random.choices(SEV_ORDER, weights=[2, 8, 25, 40, 40])[0]
        host = random.choice(hosts)
        msg = random.choice([
            f"user=jdoe action=login result=success host={host}",
            f"user=svc-backup action=login result=fail attempts={random.randint(1,30)}",
            f"proc=powershell.exe parent=winword.exe host={host}",
            f"conn dst=185.220.101.{random.randint(1,254)}:443 bytes={random.randint(200,900000)}",
            f"dns query=xw{random.randint(1000,9999)}.evil-c2.example type=TXT",
            f"file write path=/tmp/stage_{random.randint(1,99)}.dat host={host}",
        ])
        events.append((i, ts, host, src, sev, msg))
    con.executemany("INSERT INTO events VALUES (?,?,?,?,?,?)", events)

    playbooks = [
        (1, "Isolate host", "Quarantine an endpoint via the EDR CLI.",
         "edr-cli isolate --host {host}", 1),
        (2, "Block indicator", "Push an IP/domain block to the firewall.",
         "fw-cli block --indicator {indicator}", 1),
        (3, "Enrich & notify", "Ping the indicator and post to the on-call channel.",
         "ping -c 1 {indicator} && notify oncall '{message}'", 1),
    ]
    con.executemany("INSERT INTO playbooks VALUES (?,?,?,?,?)", playbooks)

    rules = [
        (1, "Brute force > 10 fails", "high", "fails > 10", 2, 1),
        (2, "PowerShell from Office", "critical",
         "proc == 'powershell.exe' and parent in ('winword.exe','excel.exe')", 1, 1),
        (3, "Large outbound transfer", "medium", "bytes > 500000", 2, 1),
        (4, "Known-bad destination", "high", "dst_reputation == 'malicious'", 2, 1),
    ]
    con.executemany("INSERT INTO rules VALUES (?,?,?,?,?,?)", rules)

    cases = [
        (5001, "Phishing wave targeting finance", "high", "open", "jdoe",
         "User reported credential-harvesting email; 3 clicks confirmed."),
        (5002, "Possible ransomware staging on WIN-FS04", "critical", "open",
         "msmith", "Mass file renames + shadow copy deletion observed."),
        (5003, "Beaconing to 185.220.101.0/24", "medium", "triage", "klee",
         "Regular 60s callbacks from LNX-WEB02; suspected C2."),
    ]
    con.executemany("INSERT INTO cases VALUES (?,?,?,?,?,?)", cases)
    notes = [
        (1, 5001, "jdoe", "Pulled the email headers; sender SPF failed."),
        (2, 5001, "klee", "IOC: hxxps://login-support.example — added to watchlist."),
        (3, 5002, "msmith", "Isolated the host, imaging now."),
    ]
    con.executemany("INSERT INTO notes VALUES (?,?,?,?)", notes)

    settings = [
        ("org_name", "SentinelSOC"),
        ("banner", "Shift handover 18:00 UTC — escalate P1s to the on-call lead."),
        ("splunk_hec_token", "hec_7b2f9a1c-4e6d-11ee-be56-0242ac120002"),
        ("virustotal_api_key", "vt_6f3c7a2b1e8d4c6f9a0b2d4e6f8a0c2e"),
        ("smtp_password", "mailer-soc-9931-xyz"),
        ("webhook_url", "https://hooks.slack.example/services/T000/B000/xoxb-soc"),
        # Staff-tunable score expression, evaluated per alert at triage time.
        ("risk_formula", "sev_weight * 10 + (20 if assignee == '' else 0)"),
    ]
    con.executemany("INSERT INTO settings VALUES (?,?)", settings)
    con.commit()
    con.close()


# --------------------------------------------------------------------------- #
# Session / token helpers
# --------------------------------------------------------------------------- #
def make_token(user):
    return jwt.encode({"uid": user["id"], "username": user["username"],
                       "role": user["role"]}, JWT_SECRET, algorithm="HS256")


def current_user():
    """Resolve an API caller from the Bearer token. Trusts the token's claims."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    try:
        hdr = jwt.get_unverified_header(token)
    except Exception:
        return None
    try:
        if hdr.get("alg", "").lower() == "none":
            return jwt.decode(token, options={"verify_signature": False},
                              algorithms=["none"])
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None


def html_user():
    uid = session.get("uid")
    if not uid:
        return None
    row = db().execute("SELECT * FROM analysts WHERE id=?", (uid,)).fetchone()
    return dict(row) if row else None


def is_admin(user):
    return bool(user and user.get("role") == "admin")


@app.context_processor
def inject_globals():
    return dict(org_name=setting("org_name", "SentinelSOC"), user=html_user())


@app.before_request
def load_remember():
    cookie = request.cookies.get("remember")
    if cookie:
        try:
            g.remembered = pickle.loads(base64.b64decode(cookie))   # insecure deser
        except Exception:
            g.remembered = None


@app.after_request
def cors(resp):
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin        # reflected origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# --------------------------------------------------------------------------- #
# Server-rendered SVG charts (no external JS needed)
# --------------------------------------------------------------------------- #
def svg_sparkline(values, w=260, h=56, color="#4da3ff"):
    if not values:
        return ""
    lo, hi = min(values), max(values)
    rng = (hi - lo) or 1
    step = w / (len(values) - 1 or 1)
    pts = " ".join(f"{i*step:.1f},{h-6-(v-lo)/rng*(h-12):.1f}"
                   for i, v in enumerate(values))
    last = values[-1]
    lx = (len(values) - 1) * step
    ly = h - 6 - (last - lo) / rng * (h - 12)
    return (f'<svg viewBox="0 0 {w} {h}" class="spark" preserveAspectRatio="none">'
            f'<polyline fill="none" stroke="{color}" stroke-width="2" points="{pts}"/>'
            f'<polygon fill="{color}22" points="0,{h} {pts} {w},{h}"/>'
            f'<circle cx="{lx:.1f}" cy="{ly:.1f}" r="3" fill="{color}"/></svg>')


def svg_donut(parts, size=150):
    total = sum(c for _, c in parts) or 1
    r, cx, cy, sw = size / 2 - 14, size / 2, size / 2, 16
    circ = 2 * 3.14159 * r
    off = 0.0
    segs = []
    for label, count in parts:
        frac = count / total
        color = SEV_COLORS.get(label, "#8b93a7")
        segs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
            f'stroke-width="{sw}" stroke-dasharray="{frac*circ:.2f} {circ:.2f}" '
            f'stroke-dashoffset="{-off*circ:.2f}" transform="rotate(-90 {cx} {cy})"/>')
        off += frac
    return (f'<svg viewBox="0 0 {size} {size}" class="donut">{"".join(segs)}'
            f'<text x="{cx}" y="{cy-2}" class="donut-num">{total}</text>'
            f'<text x="{cx}" y="{cy+16}" class="donut-lbl">alerts</text></svg>')


def svg_hbars(items, w=280):
    if not items:
        return ""
    mx = max(c for _, c in items) or 1
    rows = []
    y = 0
    for label, count in items:
        bw = count / mx * (w - 90)
        rows.append(
            f'<g transform="translate(0,{y})">'
            f'<text x="0" y="12" class="bar-lbl">{label}</text>'
            f'<rect x="84" y="2" width="{bw:.1f}" height="12" rx="3" fill="#4da3ff"/>'
            f'<text x="{bw+90:.1f}" y="12" class="bar-val">{count}</text></g>')
        y += 22
    return f'<svg viewBox="0 0 {w} {y}" class="hbars">{"".join(rows)}</svg>'


def dashboard_data():
    con = db()
    sev_counts = {s: 0 for s in SEV_ORDER}
    for r in con.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity"):
        sev_counts[r["severity"]] = r["c"]
    status_counts = {r["status"]: r["c"] for r in
                     con.execute("SELECT status, COUNT(*) c FROM alerts GROUP BY status")}
    top_sources = [(r["source_ip"], r["c"]) for r in con.execute(
        "SELECT source_ip, COUNT(*) c FROM alerts GROUP BY source_ip "
        "ORDER BY c DESC LIMIT 6")]
    top_tech = [(r["technique"].split(" ")[0], r["c"]) for r in con.execute(
        "SELECT technique, COUNT(*) c FROM alerts GROUP BY technique "
        "ORDER BY c DESC LIMIT 6")]
    # fabricate an events/min sparkline from event timestamps (last 24 buckets)
    buckets = [0] * 24
    for r in con.execute("SELECT ts FROM events"):
        try:
            h = int(r["ts"][11:13])
            buckets[h % 24] += 1
        except Exception:
            pass
    recent = [dict(r) for r in con.execute(
        "SELECT * FROM alerts ORDER BY ts DESC LIMIT 8")]
    open_cases = [dict(r) for r in con.execute(
        "SELECT * FROM cases WHERE status!='closed' ORDER BY id DESC")]
    return dict(
        sev_counts=sev_counts, status_counts=status_counts,
        total_alerts=sum(sev_counts.values()),
        donut=svg_donut([(s, sev_counts[s]) for s in SEV_ORDER if sev_counts[s]]),
        spark=svg_sparkline(buckets),
        spark_sum=sum(buckets),
        sources_svg=svg_hbars(top_sources),
        tech_svg=svg_hbars(top_tech),
        recent=recent, open_cases=open_cases, sev_colors=SEV_COLORS)


# --------------------------------------------------------------------------- #
# Dashboard (HTML)
# --------------------------------------------------------------------------- #
def require_login():
    return html_user() is not None


@app.route("/")
def overview():
    if not require_login():
        return redirect("/login?next=/")
    # Shift banner rendered through the template engine (staff may use tokens).
    banner_html = render_template_string(setting("banner"))         # stored SSTI
    return render_template("overview.html", banner_html=banner_html, **dashboard_data())


@app.route("/alerts")
def alerts():
    if not require_login():
        return redirect("/login?next=/alerts")
    con = db()
    q = request.args.get("q", "")
    sev = request.args.get("severity", "")
    error = None
    rows = []
    try:
        sql = "SELECT * FROM alerts WHERE 1=1"
        if q:
            sql += " AND (title LIKE '%" + q + "%' OR source_ip LIKE '%" + q + "%')"
        if sev:
            sql += " AND severity = '" + sev + "'"                  # SQLi (two sinks)
        sql += " ORDER BY ts DESC LIMIT 200"
        rows = con.execute(sql).fetchall()
    except Exception as e:
        error = str(e)
    return render_template("alerts.html", alerts=[dict(r) for r in rows],
                           q_raw=q, sev=sev, error=error, sev_colors=SEV_COLORS)


@app.route("/alerts/<int:aid>")
def alert_detail(aid):
    if not require_login():
        return redirect("/login")
    row = db().execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    if not row:
        return "Not found", 404
    return render_template("alert_detail.html", a=dict(row), sev_colors=SEV_COLORS)


@app.route("/hunt")
def hunt():
    if not require_login():
        return redirect("/login?next=/hunt")
    con = db()
    q = request.args.get("q", "")
    error = None
    rows = []
    if q:
        try:
            # "search DSL": whatever you type is matched against the message.
            rows = con.execute(
                "SELECT * FROM events WHERE message LIKE '%" + q + "%' "
                "ORDER BY ts DESC LIMIT 200").fetchall()             # SQLi
        except Exception as e:
            error = str(e)
    else:
        rows = con.execute("SELECT * FROM events ORDER BY ts DESC LIMIT 60").fetchall()
    return render_template("hunt.html", events=[dict(r) for r in rows],
                           q_raw=q, error=error, sev_colors=SEV_COLORS)


@app.route("/rules")
def rules_view():
    if not require_login():
        return redirect("/login?next=/rules")
    con = db()
    rows = [dict(r) for r in con.execute("SELECT * FROM rules").fetchall()]
    return render_template("rules.html", rules=rows, sev_colors=SEV_COLORS)


@app.route("/playbooks")
def playbooks_view():
    if not require_login():
        return redirect("/login?next=/playbooks")
    con = db()
    rows = [dict(r) for r in con.execute("SELECT * FROM playbooks").fetchall()]
    return render_template("playbooks.html", playbooks=rows,
                           output=session.pop("pb_output", None))


@app.route("/playbooks/<int:pid>/run")
def playbook_run(pid):
    if not require_login():
        return redirect("/login")
    con = db()
    pb = con.execute("SELECT * FROM playbooks WHERE id=?", (pid,)).fetchone()
    if not pb:
        return "Not found", 404
    # Operators pass runtime parameters that fill the command template.
    cmd = pb["command"].format(
        host=request.args.get("host", "localhost"),
        indicator=request.args.get("indicator", "127.0.0.1"),
        message=request.args.get("message", "triage"))             # command injection
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    session["pb_output"] = f"$ {cmd}\n\n{out}"
    return redirect("/playbooks")


@app.route("/intel")
def intel():
    if not require_login():
        return redirect("/login?next=/intel")
    ioc = request.args.get("ioc", "")
    result = None
    if ioc:
        feed = setting("intel_feed_url", "http://127.0.0.1:5004/api/intel-stub?ioc=")
        try:
            # Enrich the indicator against the configured intel feed.
            with __import__("urllib.request", fromlist=["x"]).urlopen(
                    feed + ioc, timeout=5) as r:                    # SSRF
                result = r.read().decode(errors="replace")[:4000]
        except Exception as e:
            result = f"[enrichment error] {e}"
    return render_template("intel.html", ioc=ioc, result=result)


@app.route("/cases")
def cases_view():
    if not require_login():
        return redirect("/login?next=/cases")
    con = db()
    rows = [dict(r) for r in con.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()]
    return render_template("cases.html", cases=rows, sev_colors=SEV_COLORS)


@app.route("/cases/<int:cid>", methods=["GET", "POST"])
def case_detail(cid):
    if not require_login():
        return redirect("/login")
    con = db()
    if request.method == "POST":
        con.execute("INSERT INTO notes (case_id,author,body) VALUES (?,?,?)",
                    (cid, html_user().get("username", "anon"),
                     request.form.get("body", "")))
        con.commit()
        return redirect(f"/cases/{cid}")
    c = con.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
    if not c:
        return "Not found", 404
    notes = con.execute("SELECT author,body FROM notes WHERE case_id=?", (cid,)).fetchall()
    # Notes pre-rendered through the template engine (analysts may format text).
    notes_html = render_template_string("".join(
        f'<div class="note"><b>{n["author"]}</b>: {n["body"]}</div>' for n in notes))
    return render_template("case_detail.html", c=dict(c), notes_html=notes_html,
                           sev_colors=SEV_COLORS)


# --------------------------------------------------------------------------- #
# Auth (HTML sessions)
# --------------------------------------------------------------------------- #
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", next=request.args.get("next"), error=None)
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    row = db().execute("SELECT * FROM analysts WHERE username=?", (username,)).fetchone()
    if not row or row["password"] != md5(password):
        return render_template("login.html", next=request.args.get("next"),
                               error="Invalid username or password.")
    session["uid"] = row["id"]
    session["role"] = row["role"]
    resp = redirect(request.args.get("next") or "/")               # open redirect via next
    if request.form.get("remember"):
        blob = base64.b64encode(pickle.dumps({"uid": row["id"], "username": username}))
        resp.set_cookie("remember", blob.decode())
    return resp


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register_html():
    if request.method == "GET":
        return render_template("register.html", error=None)
    con = db()
    username = request.form.get("username", "")
    if con.execute("SELECT 1 FROM analysts WHERE username=?", (username,)).fetchone():
        return render_template("register.html", error="That username is taken.")
    con.execute(
        "INSERT INTO analysts (username,email,password,role,full_name,team) "
        "VALUES (?,?,?,?,?,?)",
        (username, request.form.get("email", ""),
         md5(request.form.get("password", "")), "analyst",
         request.form.get("full_name", ""), "Tier-1"))
    con.commit()
    row = con.execute("SELECT * FROM analysts WHERE username=?", (username,)).fetchone()
    session["uid"] = row["id"]
    session["role"] = row["role"]
    return redirect("/")


@app.route("/admin")
def admin_html():
    u = html_user()
    if not u or u.get("role") != "admin":
        return redirect("/login?next=/admin")
    con = db()
    analysts = [dict(r) for r in con.execute("SELECT * FROM analysts").fetchall()]
    settings = {r["key"]: r["value"]
                for r in con.execute("SELECT key,value FROM settings").fetchall()}
    return render_template("admin.html", analysts=analysts, settings=settings,
                           backup_output=None)


@app.route("/admin/backup")
def admin_backup_html():
    u = html_user()
    if not u or u.get("role") != "admin":
        return redirect("/login?next=/admin")
    name = request.args.get("name", "soc-export")
    cmd = "cd /tmp && tar czf " + name + ".tgz " + EVIDENCE_DIR + " 2>&1"   # cmd injection
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    con = db()
    analysts = [dict(r) for r in con.execute("SELECT * FROM analysts").fetchall()]
    settings = {r["key"]: r["value"]
                for r in con.execute("SELECT key,value FROM settings").fetchall()}
    return render_template("admin.html", analysts=analysts, settings=settings,
                           backup_output=(cmd + "\n\n" + out))


@app.route("/go")
def go():
    return redirect(request.args.get("next", "/"))                 # open redirect


# --------------------------------------------------------------------------- #
# JSON API
# --------------------------------------------------------------------------- #
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    row = db().execute("SELECT * FROM analysts WHERE username=?",
                       (data.get("username", ""),)).fetchone()
    if not row:
        return jsonify(error="No such analyst"), 401               # user enumeration
    if row["password"] != md5(data.get("password", "")):
        return jsonify(error="Wrong password"), 401                # distinct msg, no lockout
    return jsonify(token=make_token(row), role=row["role"])


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(force=True, silent=True) or {}
    con = db()
    cols = ["username", "email", "password", "role", "full_name", "team", "phone"]
    row = {c: data.get(c) for c in cols}                           # role accepted from client
    row["role"] = row.get("role") or "analyst"
    if row.get("password"):
        row["password"] = md5(row["password"])
    con.execute(
        "INSERT INTO analysts (username,email,password,role,full_name,team,phone) "
        "VALUES (:username,:email,:password,:role,:full_name,:team,:phone)", row)
    con.commit()
    uid = con.execute("SELECT id FROM analysts WHERE username=?",
                      (row["username"],)).fetchone()[0]
    return jsonify(id=uid, role=row["role"])


@app.route("/api/analysts/<int:uid>")
def api_analyst(uid):
    if not current_user():
        return jsonify(error="auth required"), 401
    row = db().execute("SELECT * FROM analysts WHERE id=?", (uid,)).fetchone()
    if not row:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))                                      # IDOR: PII + hash + token


@app.route("/api/analysts/<int:uid>", methods=["PATCH"])
def api_analyst_update(uid):
    if not current_user():
        return jsonify(error="auth required"), 401
    data = request.get_json(force=True, silent=True) or {}
    con = db()
    for k, v in data.items():                                      # mass assignment incl. role
        if k in ("username", "email", "role", "full_name", "team", "phone"):
            con.execute(f"UPDATE analysts SET {k}=? WHERE id=?", (v, uid))
    con.commit()
    return jsonify(ok=True)


@app.route("/api/alerts")
def api_alerts():
    if not current_user():
        return jsonify(error="auth required"), 401
    rows = db().execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT 200").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/alerts/<int:aid>")
def api_alert(aid):
    if not current_user():
        return jsonify(error="auth required"), 401
    row = db().execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    if not row:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))                                      # IDOR


@app.route("/api/cases/<int:cid>")
def api_case(cid):
    if not current_user():
        return jsonify(error="auth required"), 401
    row = db().execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
    if not row:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))                                      # IDOR


@app.route("/api/search")
def api_search():
    q = request.args.get("q", "")
    con = db()
    try:
        rows = con.execute(
            "SELECT id,ts,host,source,severity,message FROM events "
            "WHERE message LIKE '%" + q + "%' LIMIT 200").fetchall()  # SQLi
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify(error=str(e)), 400


@app.route("/api/enrich")
def api_enrich():
    url = request.args.get("url", "")
    if not url:
        return jsonify(error="url required"), 400
    import urllib.request
    try:
        # Fetches whatever URL/scheme is supplied (http, file, ftp, …).
        with urllib.request.urlopen(url, timeout=5) as r:          # SSRF
            data = r.read()
            ctype = r.headers.get("Content-Type", "text/plain")
        return Response(data, mimetype=ctype)
    except Exception as e:
        return jsonify(error=str(e)), 502


@app.route("/api/intel-stub")
def api_intel_stub():
    ioc = request.args.get("ioc", "")
    verdict = random.choice(["malicious", "suspicious", "clean"])
    return jsonify(indicator=ioc, verdict=verdict,
                   sources=["internal", "community-feed"],
                   first_seen="2024-11-02", last_seen="2025-01-19")


@app.route("/api/upload", methods=["POST"])
def upload():
    if not current_user():
        return jsonify(error="auth required"), 401
    f = request.files.get("file")
    if not f:
        return jsonify(error="no file"), 400
    f.save(os.path.join(EVIDENCE_DIR, f.filename))                 # unrestricted upload
    return jsonify(saved=f.filename)


@app.route("/download")
def download():
    path = request.args.get("path", "")
    full = os.path.join(EVIDENCE_DIR, path)                        # path traversal
    try:
        with open(full, "rb") as fh:
            return Response(fh.read(), mimetype="application/octet-stream")
    except Exception as e:
        return jsonify(error=str(e)), 404


# --------------------------------------------------------------------------- #
# Detection-rule engine — evaluate a rule's condition against a sample event.
# --------------------------------------------------------------------------- #
@app.route("/api/rules", methods=["POST"])
def api_rule_create():
    if not is_admin(current_user()):
        return jsonify(error="admin only"), 403
    data = request.get_json(force=True, silent=True) or {}
    con = db()
    con.execute(
        "INSERT INTO rules (name,severity,condition,playbook_id,enabled) "
        "VALUES (?,?,?,?,1)",
        (data.get("name", "rule"), data.get("severity", "medium"),
         data.get("condition", ""), data.get("playbook_id", 2)))
    con.commit()
    return jsonify(ok=True)


@app.route("/api/rules/test", methods=["POST"])
def api_rule_test():
    if not require_login() and not current_user():
        return jsonify(error="auth required"), 401
    data = request.get_json(force=True, silent=True) or {}
    rid = data.get("rule_id")
    con = db()
    cond = data.get("condition")
    if cond is None and rid is not None:
        r = con.execute("SELECT condition FROM rules WHERE id=?", (rid,)).fetchone()
        cond = r["condition"] if r else ""
    event = data.get("event") or {"fails": 3, "bytes": 1200, "proc": "cmd.exe",
                                   "parent": "explorer.exe", "assignee": "",
                                   "sev_weight": 2, "dst_reputation": "clean"}
    try:
        matched = eval(cond, {"__builtins__": {}}, dict(event))    # eval -> RCE
    except Exception as e:
        return jsonify(error=str(e)), 400
    return jsonify(condition=cond, matched=bool(matched))


@app.route("/api/triage/score", methods=["POST"])
def api_triage_score():
    data = request.get_json(force=True, silent=True) or {}
    weights = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    ctx = {"sev_weight": weights.get(data.get("severity"), 1),
           "assignee": data.get("assignee", "")}
    formula = setting("risk_formula", "sev_weight * 10")
    score = eval(formula, ctx)                                     # eval -> RCE (public)
    return jsonify(formula=formula, score=score)


# --------------------------------------------------------------------------- #
# Config / integrations (admin)
# --------------------------------------------------------------------------- #
@app.route("/api/admin/users")
def admin_users():
    if not is_admin(current_user()):
        return jsonify(error="admin only"), 403
    return jsonify([dict(r) for r in db().execute("SELECT * FROM analysts").fetchall()])


@app.route("/api/admin/settings", methods=["GET", "POST"])
def admin_settings():
    if not is_admin(current_user()):
        return jsonify(error="admin only"), 403
    con = db()
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        for k, v in data.items():
            con.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)",
                        (k, str(v)))
        con.commit()
    rows = con.execute("SELECT key,value FROM settings").fetchall()
    return jsonify({r["key"]: r["value"] for r in rows})           # leaks tokens/keys


@app.route("/api/admin/config", methods=["POST"])
def admin_config():
    if not is_admin(current_user()):
        return jsonify(error="admin only"), 403
    raw = request.get_data(as_text=True)
    cfg = yaml.load(raw, Loader=yaml.Loader)                       # unsafe YAML load -> RCE
    con = db()
    if isinstance(cfg, dict):
        for k, v in cfg.items():
            con.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)",
                        (k, str(v)))
        con.commit()
    return jsonify(loaded=cfg if isinstance(cfg, dict) else str(cfg))


@app.route("/api/admin/backup")
def admin_backup():
    if not is_admin(current_user()):
        return jsonify(error="admin only"), 403
    name = request.args.get("name", "soc-export")
    cmd = "cd /tmp && tar czf " + name + ".tgz " + EVIDENCE_DIR + " 2>&1"   # cmd injection
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    return jsonify(cmd=cmd, output=out)


@app.route("/api/admin/integrations", methods=["POST"])
def integration_upload():
    if not is_admin(current_user()):
        return jsonify(error="admin only"), 403
    f = request.files.get("file")
    if not f:
        return jsonify(error="no file"), 400
    f.save(os.path.join(PLUGIN_DIR, f.filename))                   # arbitrary .py into package
    return jsonify(saved=f.filename)


@app.route("/api/admin/integrations/run")
def integration_run():
    if not is_admin(current_user()):
        return jsonify(error="admin only"), 403
    name = request.args.get("name", "")
    mod = importlib.import_module("integrations." + name)          # import executes -> RCE
    importlib.reload(mod)
    return jsonify(loaded=name, info=getattr(mod, "INFO", None))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5004, debug=True)                # debug server left on
