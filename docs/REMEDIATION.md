# Remediation

Fixes for each confirmed vulnerability in SentinelGrid, with code-level guidance and general hardening recommendations.

## 1. Priority Matrix

| # | Vulnerability | Severity | Priority | Target SLA |
|---|---------------|----------|----------|------------|
| 3 | SQL Injection (`/search`) | Critical | P1 | 0–7 days |
| 4 | SQL Injection (`/country`) | Critical | P1 | 0–7 days |
| 5 | Command Injection (`/admin/ping`) | Critical | P1 | 0–7 days |
| 1 | Reflected XSS (`/`) | High | P2 | 7–14 days |
| 2 | Reflected XSS (`/search`) | High | P2 | 7–14 days |
| 6 | SSRF (`/api/fetch`) | High | P2 | 7–14 days |
| 7 | IDOR (`/profile`) | High | P2 | 7–14 days |

## 2. Per-Finding Remediation

### 2.1 SQL Injection — `/search` and `/country`

**Root cause:** query strings built via string concatenation.

**Vulnerable (current):**

```python
query = f"SELECT * FROM regions WHERE name LIKE '%{q}%' OR code LIKE '%{q}%'"
results = conn.execute(query).fetchall()
Fixed (parameterized):

python
results = conn.execute(
    "SELECT * FROM regions WHERE name LIKE ? OR code LIKE ?",
    (f"%{q}%", f"%{q}%")
).fetchall()
For /country:

python
region = conn.execute(
    "SELECT * FROM regions WHERE code = ?",
    (code,)
).fetchone()
Why it works: the driver treats the parameter as data, not SQL. No payload can change the query structure.

Additional hardening:

Whitelist allowed characters for the code parameter (^[A-Z]{3}$)

Return a generic error message to the user; log the detailed error server-side

Enable SQLite's PRAGMA foreign_keys = ON (defence in depth)

2.2 Reflected XSS — / and /search
Root cause: user input rendered into the page without escaping.

Vulnerable (frontend, in index.html):

js
hit.innerHTML = term;
Vulnerable (backend, in templates/search.html):

html
<div class="search-echo">Showing results for: {{ q | safe }}</div>
Fixed (frontend — use textContent):

js
hit.textContent = term;
Fixed (backend — remove | safe):

html
<div class="search-echo">Showing results for: {{ q }}</div>
Jinja2 autoescapes by default when you do not use | safe. Flask ships with autoescaping enabled for .html templates, so removing the safe filter is sufficient.

Additional hardening:

Add a Content-Security-Policy header (default-src 'self'; script-src 'self') via after_request

Set X-Content-Type-Options: nosniff

Example:

python
@app.after_request
def add_security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp
2.3 Command Injection — /admin/ping
Root cause: shell=True with user-supplied host string.

Vulnerable (current):

python
result = subprocess.check_output(
    f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=10
)
Fixed (argument list, no shell):

python
import shlex
import re

# 1. Validate input
if not re.match(r"^[A-Za-z0-9.\-]{1,253}$", host):
    return render_template("admin_ping.html", host=host, output="Invalid host")

# 2. Use argument list, no shell
result = subprocess.check_output(
    ["ping", "-c", "1", host],
    stderr=subprocess.STDOUT,
    timeout=10,
)
Why it works: with shell=False and a list, subprocess does not invoke /bin/sh, so ;, |, && are treated as literal characters inside the argument.

Additional hardening:

Restrict the endpoint to authenticated admins

Rate-limit the endpoint per user

Consider removing the endpoint entirely if it is only a diagnostic convenience

2.4 SSRF — /api/fetch
Root cause: server fetches any URL supplied by the client.

Vulnerable (current):

python
r = requests.get(url, timeout=8, verify=False)
Fixed (allowlist + private-range block):

python
from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_HOSTS = {"api.trusted-provider.example"}

def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if parsed.hostname not in ALLOWED_HOSTS:
            return False
        # Resolve and check the destination is a public IP
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except Exception:
        return False

if not is_safe_url(url):
    return jsonify({"error": "URL not permitted"}), 400

r = requests.get(url, timeout=8, verify=True, allow_redirects=False)
Additional hardening:

Disable redirects (allow_redirects=False) — otherwise a safe initial URL can redirect to an internal one

Resolve DNS once and pin the resolved IP for the actual request

Block IPv6 and DNS rebinding by comparing the peer IP after connect

2.5 IDOR — /profile
Root cause: the endpoint returns any user record regardless of who is logged in.

Vulnerable (current):

python
user = conn.execute(f"SELECT * FROM users WHERE id = {uid}").fetchone()
Fixed (enforce ownership):

python
from flask import session, abort

requested_id = int(uid)
current_user_id = session.get("user_id")

# Only allow access to your own record, unless you are an admin
if current_user_id is None:
    abort(401)

if requested_id != current_user_id and session.get("role") != "admin":
    abort(403)

user = conn.execute(
    "SELECT id, username, role, email FROM users WHERE id = ?",
    (requested_id,)
).fetchone()
Two fixes in one:

Authorization check — only yourself or admins

Column selection — never return ssn or credit_card to the client

Additional hardening:

Use opaque identifiers (UUIDs) instead of sequential integers

Log authorization failures for monitoring

Add automated tests asserting 403 for cross-user access

3. General Hardening Recommendations
Not tied to any single finding, but worth adopting across the codebase:

Area	Recommendation
Input validation	Centralize validators; never trust client input
Output encoding	Rely on framework autoescaping; never use | safe on user data
Error handling	Return generic errors; log details server-side
Authentication	Replace stub login with real session management
Authorization	Enforce resource-level checks on every object access
Secrets	Move SECRET_KEY to environment variables
Dependencies	Pin versions, run pip-audit in CI
Headers	Set CSP, X-Content-Type-Options, Referrer-Policy
Logging	Log auth failures, injection attempts, and 4xx bursts
Transport	Enforce HTTPS in any non-local deployment
4. Verification After Fixes
Re-run SUDARSHAN against the patched application:

bash
cd sudarshan
python main.py --target http://localhost:3000/ --poc
Expected outcome:

Confirmed findings: 0

All previously confirmed findings should now appear as UNVERIFIED or be absent entirely

Any confirmed finding that remains indicates the fix was incomplete

Each fix should also be covered by an automated test, e.g.:

python
def test_search_rejects_sqli(client):
    r = client.get("/search?q=' OR '1'='1")
    assert b"SQL" not in r.data
    assert r.status_code == 200
5. Sign-off
Item	Value
Assessment target	SentinelGrid (World Monitor clone)
Assessment tool	SUDARSHAN
Total findings remediated	7
Verification method	Re-scan + PoC replay
Verified by	(assessment team)
Date	(fill in)
text

**Save and close.**

---

## You Now Have All Three `docs/` Files

| File | Status |
|------|--------|
| `docs/METHODOLOGY.md` | ✅ Created |
| `docs/FINDINGS.md` | ✅ Created |
| `docs/REMEDIATION.md` | ✅ Created |

---

## Full Staging Folder — Final Check

Run:

```bash
dir /s /b D:\upload-staging
