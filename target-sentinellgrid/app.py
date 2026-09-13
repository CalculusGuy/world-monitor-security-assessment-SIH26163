"""
World Monitor (Local Clone) — intentionally vulnerable DAST test target
=========================================================================
Built for local SUDARSHAN scanner testing / SIH demo purposes ONLY.

DO NOT deploy this application to any publicly reachable host, shared
network, or cloud VM. It contains deliberate, unauthenticated SQL
injection, command injection, SSRF, reflected XSS, and IDOR flaws by
design so a DAST scanner has real findings to detect. Run it only on
127.0.0.1 / localhost, on a machine you control, disconnected from
anything sensitive.

Run:
    python init_db.py
    python app.py
Then browse to http://localhost:3000
"""

import os
import sqlite3
import subprocess

import requests
from flask import Flask, request, jsonify, render_template, redirect, url_for

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "worldmonitor.db")

app = Flask(__name__)
app.secret_key = "dev-only-not-for-production"  # fine for a local demo target

# Pretend the "logged in" user is always id=1 (admin), to make the IDOR
# on /profile meaningful: any other user_id should NOT be viewable by
# this session, but the vulnerable handler doesn't check that.
CURRENT_SESSION_USER_ID = 1


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Dashboard / navigation (the "good" parts)
# ---------------------------------------------------------------------------

SITE_VARIANTS = {
    "world": "Geopolitical News",
    "tech": "Tech & Cyber",
    "finance": "Finance Radar",
    "energy": "Energy Watch",
}


@app.route("/")
def index():
    return redirect(url_for("site_variant", variant="world"))


@app.route("/<variant>")
def site_variant(variant):
    if variant not in SITE_VARIANTS:
        return redirect(url_for("site_variant", variant="world"))

    conn = get_db()
    news = conn.execute(
        "SELECT * FROM news WHERE category = ? ORDER BY published_at DESC",
        (variant,),
    ).fetchall()
    cii = conn.execute("SELECT * FROM cii ORDER BY score DESC").fetchall()
    finance = conn.execute("SELECT * FROM finance").fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        variant=variant,
        variants=SITE_VARIANTS,
        news=news,
        cii=cii,
        finance=finance,
    )


@app.route("/api/dashboard-data")
def api_dashboard_data():
    """Polled by the front-end setInterval loop to fake real-time updates."""
    variant = request.args.get("variant", "world")
    conn = get_db()
    news = conn.execute(
        "SELECT * FROM news WHERE category = ? ORDER BY published_at DESC LIMIT 5",
        (variant,),
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in news])


# ---------------------------------------------------------------------------
# VULNERABILITY 1: SQL Injection — /search?q=
# ---------------------------------------------------------------------------

@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()

    # INTENTIONALLY VULNERABLE: raw string concatenation into SQL.
    # Example payload: ' UNION SELECT id,username,email,role,internal_notes FROM users--
    query = f"SELECT * FROM news WHERE title LIKE '%{q}%';"
    try:
        cur.execute(query)
        rows = cur.fetchall()
        results = [dict(row) for row in rows]
        error = None
    except sqlite3.Error as e:
        results = []
        error = str(e)
    conn.close()

    return render_template("search.html", q=q, results=results, error=error, executed_sql=query)


# ---------------------------------------------------------------------------
# VULNERABILITY 2: Reflected / DOM XSS — /trending?topic=
# ---------------------------------------------------------------------------

@app.route("/trending")
def trending():
    conn = get_db()
    # A small fixed list of "trending" topics for the page to display by default.
    topics = conn.execute(
        "SELECT DISTINCT title FROM news ORDER BY published_at DESC LIMIT 8"
    ).fetchall()
    conn.close()
    # The template's JS reads ?topic= straight out of location.search and
    # writes it into innerHTML client-side — no sanitization anywhere.
    return render_template("trending.html", topics=topics)


# ---------------------------------------------------------------------------
# VULNERABILITY 3: OS Command Injection — /admin/ping?host=
# ---------------------------------------------------------------------------

@app.route("/admin/ping")
def admin_ping():
    host = request.args.get("host", "")
    output = None
    if host:
        # INTENTIONALLY VULNERABLE: unsanitized input handed to a shell.
        # Example payload: 8.8.8.8; cat /etc/passwd
        cmd = f"ping -c 3 {host}"
        try:
            output = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT, timeout=10
            ).decode(errors="replace")
        except subprocess.CalledProcessError as e:
            output = e.output.decode(errors="replace")
        except Exception as e:
            output = f"Error: {e}"
    return render_template("admin_ping.html", host=host, output=output)


# ---------------------------------------------------------------------------
# VULNERABILITY 4: SSRF — /api/fetch-news?url=
# ---------------------------------------------------------------------------

@app.route("/api/fetch-news")
def api_fetch_news():
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url parameter required"}), 400

    # INTENTIONALLY VULNERABLE: no scheme/host allow-list, no block on
    # internal ranges — the server will fetch whatever URL it's given.
    # Example payload: http://127.0.0.1:3000/admin/ping?host=localhost
    try:
        resp = requests.get(url, timeout=5)
        return jsonify(
            {
                "requested_url": url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:2000],
            }
        )
    except requests.RequestException as e:
        return jsonify({"requested_url": url, "error": str(e)}), 502


# ---------------------------------------------------------------------------
# VULNERABILITY 5: IDOR — /profile?user_id=
# ---------------------------------------------------------------------------

@app.route("/profile")
def profile():
    user_id = request.args.get("user_id", str(CURRENT_SESSION_USER_ID))

    conn = get_db()
    # INTENTIONALLY VULNERABLE: no check that user_id == the logged-in
    # session's own id, or that the session has admin rights to view others.
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    return render_template(
        "profile.html",
        session_user_id=CURRENT_SESSION_USER_ID,
        requested_id=user_id,
        user=dict(row) if row else None,
    )


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("Database not found — run `python init_db.py` first.")
    app.run(host="127.0.0.1", port=3000, debug=True)
