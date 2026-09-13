# Findings

Summary of every confirmed vulnerability from the final SUDARSHAN scan of SentinelGrid.

## 1. Executive Summary

| Metric | Count |
|--------|-------|
| Total raw findings | *fill from scan* |
| **Confirmed (reproducible)** | *fill from scan* |
| Unverified (detection only) | *fill from scan* |
| Errors | *fill from scan* |
| Unique vulnerability types | *fill from scan* |
| PoC scripts generated | *fill from scan* |

**Detection rate** = Confirmed ÷ Planted × 100%

SentinelGrid was built with **7 intentional vulnerabilities**. A successful scan should confirm all 7 (100% detection rate) with zero false positives among the confirmed set.

## 2. Planted Vulnerabilities

| # | Type | Endpoint | Parameter | Severity |
|---|------|----------|-----------|----------|
| 1 | Reflected XSS | `/` | `q` | High |
| 2 | Reflected XSS | `/search` | `q` | High |
| 3 | SQL Injection | `/search` | `q` | Critical |
| 4 | SQL Injection | `/country` | `code` | Critical |
| 5 | Command Injection | `/admin/ping` | `host` | Critical |
| 6 | SSRF | `/api/fetch` | `url` | High |
| 7 | IDOR | `/profile` | `id` | High |

## 3. Confirmed Findings

Fill this section from `reports/scan_report.json` — one block per confirmed finding.

### 3.1 Template

For each confirmed finding, record:

| Field | Value |
|-------|-------|
| **Vulnerability** | *e.g., Reflected XSS* |
| **Severity** | *Critical / High / Medium* |
| **Endpoint** | *e.g., `/search`* |
| **Parameter** | *e.g., `q`* |
| **Payload** | *e.g., `<script>alert(1)</script>`* |
| **Confidence** | *e.g., 95%* |
| **Evidence** | *validator evidence lines* |
| **PoC** | *e.g., `pocs/poc_DAST-002.py`* |

### 3.2 Known findings (based on prior scans)

**Finding 1 — Reflected XSS (`/`)**
- Payload: `<img src=x onerror=alert(1)>` injected via `?q=`
- Evidence: unique marker reflected unescaped in the page's search-echo element
- Impact: JavaScript execution in any victim's browser session

**Finding 2 — Reflected XSS (`/search`)**
- Same class, different endpoint
- Payload reflected via template `{{ q | safe }}`

**Finding 3 — SQL Injection (`/search`)**
- Payload: `' OR '1'='1`
- Evidence: application returns an unhandled SQLite error string, and `' OR '1'='1' --` bypasses the expected filtering

**Finding 4 — SQL Injection (`/country`)**
- Payload: `' OR '1'='1`
- Same class as #3, via the `code` parameter

**Finding 5 — Command Injection (`/admin/ping`)**
- Payload: `127.0.0.1; id`
- Evidence: OS command output appears in the response body (`uid=`, `gid=`, `groups=`)

**Finding 6 — SSRF (`/api/fetch`)**
- Payload: `http://localhost:3000/api/dashboard-data`
- Evidence: server-side fetch returns internal endpoint content to the client

**Finding 7 — IDOR (`/profile`)**
- Payload: `?id=2` while browsing as user `1`
- Evidence: profile page returns another user's record, including email, SSN, and credit card fields

## 4. Unverified Detections

The scan also produced a large number of detections that did **not** survive validation. These are typically caused by:

- A rule indicator (e.g., the substring `root`, `xml`, or `LDAP`) appearing in normal page content
- Baseline drift rather than an actual response change
- Payloads that were reflected but escaped by the framework

Full list is available in the `unverified` section of `reports/scan_report.json`.

## 5. False Negative Analysis

Any planted vulnerability that SUDARSHAN failed to confirm would be listed here. On the current SentinelGrid build, **all 7 planted vulnerabilities were confirmed** in prior runs.

## 6. Evidence Integrity

- Every confirmed finding has a matching PoC script under `pocs/`
- The scripts are non-destructive and can be re-run at any time
- The scan report carries the scan date and target URL in its header, so findings can be tied to a specific assessment run

## 7. Next Steps

1. Populate the summary table from the current `reports/scan_report.json`
2. For each confirmed finding, copy the exact payload and evidence lines
3. Cross-reference the finding to its PoC file under `pocs/`
4. Commit the finalised version of this document alongside the scan artifacts
