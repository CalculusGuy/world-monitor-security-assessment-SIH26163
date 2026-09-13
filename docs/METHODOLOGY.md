# Methodology

## 1. Objective

Perform a full Dynamic Application Security Testing (DAST) assessment of the **World Monitor** intelligence dashboard using an internally developed validation-aware scanner (SUDARSHAN), and report only vulnerabilities that can be reliably reproduced.

Because scanning a live third-party application without written authorization is not permissible, the assessment was performed against **SentinelGrid** — a functionally representative local clone of the World Monitor dashboard, built for this purpose with the same class of features (search, region lookups, ping utilities, profile pages, external fetches).

## 2. Scope

| Field | Value |
|-------|-------|
| Target application | SentinelGrid (local World Monitor clone) |
| Base URL | `http://localhost:3000` |
| Environment | Isolated localhost, no external network |
| Authorization | Self-authorized — application written by the assessment team |
| Assessment type | Black-box DAST |

### In scope

- All HTTP routes exposed by the application
- All GET/POST parameters accepted by those routes
- Cookies and headers as reachable from the crawler

### Out of scope

- Any host other than `localhost:3000`
- The real World Monitor production application
- Denial-of-service / load testing
- Social engineering

## 3. Phases

### 3.1 Reconnaissance

SUDARSHAN's BFS crawler starts from the root URL and discovers:

- Pages linked from the home page
- HTML forms and their input names
- Query-string parameters already present on any crawled URL
- API endpoints referenced in JavaScript

Each discovered URL and parameter becomes a test case.

### 3.2 Detection

Every discovered endpoint is fed through the rule engine, which loads 22 detection rules from `rules/dast_rules.json`. Each rule defines:

- A set of payloads
- An HTTP method
- A target parameter
- Response indicators

Payloads are injected and the responses are compared against the rule's indicators.

### 3.3 Validation

Detection alone produces false positives — a substring like `root` appearing in normal page content is not evidence of command injection.

The validator re-tests every detection with three requests:

1. **Baseline** — the endpoint called with a benign value
2. **Control** — the endpoint called with a random marker that should not trigger anything
3. **Attack** — the endpoint called with the actual payload

A finding is only promoted to **CONFIRMED** if:

- The attack response differs meaningfully from both baseline and control
- A rule-specific differential check passes (e.g., `{{7*7}}` returns `49`, an echoed marker appears unescaped, a SQL error string appears only in the attack response)

Every validator produces a numeric **confidence score** (0–100) and human-readable **evidence**.

### 3.4 Proof-of-Concept

Each CONFIRMED finding produces a standalone, runnable PoC script under `pocs/`. The script:

- Replays the exact request that triggered the finding
- Prints the response status and the relevant evidence
- Exits non-zero if the vulnerability is no longer reproducible

This makes every finding independently verifiable by a reviewer without rerunning SUDARSHAN.

### 3.5 Reporting

Two reports are produced:

- `reports/scan_report.json` — machine-readable, one object per finding, includes status, confidence, evidence, and remediation
- `reports/scan_report.html` — human-readable, dark-themed, color-coded by severity and status

Both classify findings as **CONFIRMED**, **UNVERIFIED**, or **ERROR**.

## 4. Tools

| Tool | Role |
|------|------|
| SUDARSHAN | DAST engine — crawler, rule engine, validator, PoC generator, reporter |
| Python 3.10+ | Runtime |
| Flask | Target framework (SentinelGrid) |
| SQLite | Target data store |
| requests / urllib3 | HTTP client used by both the scanner and validators |

## 5. Limitations

- Assessment was performed against a clone, not the production World Monitor. Findings are representative of *classes* of issues, not confirmed reports about the live application.
- Testing was unauthenticated. No test credentials were provided, so IDOR validation used object-id enumeration rather than role-based comparison.
- No active exploitation beyond the minimum needed to produce evidence was attempted.
- Rate limiting was not applied; the target is local and single-tenant, so this had no impact on third parties.

## 6. Ethics

- No third-party system was scanned.
- No real user data was accessed — the target's database is entirely mock data.
- All PoCs are non-destructive (read-only payloads; no dropped tables, no shells, no file writes).
- This document and all reports are intended for the SIH review panel only.
