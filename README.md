# SIH26163 — Security Assessment of the World Monitor Application

> **SIH 2026 · Problem Statement 26163 · Blockchain & Cybersecurity**

**Team:** Threat Lens
**Team Lead:** Nilanjan Chowdhury

A complete, evidence-driven **Dynamic Application Security Testing (DAST)** workflow designed to assess the security of the World Monitor application.

The project combines **SUDARSHAN**, a validation-aware DAST engine, with **SentinelGrid**, a safe local and intentionally vulnerable clone of the World Monitor dashboard used as the authorized assessment target.

---

## ⚠️ Legal & Safety Notice

**The real World Monitor production application was NOT scanned or tested.**

All security testing in this repository was performed exclusively against **SentinelGrid**, an intentionally vulnerable local clone running inside an isolated environment.

The vulnerabilities documented in this repository represent **security vulnerability classes demonstrated in the authorized test environment**. They must **not** be interpreted as confirmed vulnerabilities in the real World Monitor application.

> **SentinelGrid is intentionally vulnerable. Do not deploy it to a public or production environment.**

---

## 🎯 Project Objective

The objective of SIH26163 is to demonstrate a structured security-assessment workflow covering:

* Application discovery
* Attack-surface mapping
* Vulnerability detection
* Automated validation
* Proof-of-concept generation
* Evidence collection
* Risk classification
* Remediation guidance
* Re-testing after remediation

The central principle is:

```text
Detect → Validate → Prove → Report → Remediate → Re-test
```

A scanner alert alone is **not** considered a confirmed vulnerability.

---

## 🛡️ Architecture

```text
                    ┌──────────────────────────┐
                    │       Threat Lens        │
                    │       SIH 2026 Team      │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │        SUDARSHAN         │
                    │     DAST Validation      │
                    │         Engine           │
                    └────────────┬─────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
              ▼                  ▼                  ▼
          Discovery          Detection          Validation
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │       Evidence Layer     │
                    │   Findings + PoC + Logs  │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │       SentinelGrid        │
                    │ Authorized Local Target   │
                    │ Intentionally Vulnerable  │
                    └──────────────────────────┘
```

---

## 🔬 Components

### SUDARSHAN

A validation-aware **Dynamic Application Security Testing (DAST)** engine designed to reduce false positives through automated vulnerability confirmation.

Key capabilities include:

* Web application crawling
* Endpoint and parameter discovery
* Vulnerability detection
* Differential validation
* Baseline vs. attack comparison
* Confidence-based assessment
* Proof-of-concept generation
* JSON security reports
* HTML reports
* Modular vulnerability rules
* Reproducible testing workflow

SUDARSHAN follows an evidence-first approach:

```text
Recon
  ↓
Discover
  ↓
Detect
  ↓
Validate
  ↓
Prove
  ↓
Report
```

---

### SentinelGrid

**SentinelGrid** is a deliberately vulnerable, local application modeled after the functionality and attack surface of an intelligence-monitoring dashboard.

It exists exclusively as a **safe and authorized security-testing target**.

The application contains intentionally planted vulnerabilities so that the complete assessment workflow can be demonstrated without interacting with a real production system.

---

## 🧪 Planted Vulnerability Classes

|  # | Vulnerability     | Endpoint      | Parameter |
| -: | ----------------- | ------------- | --------- |
| 01 | Reflected XSS     | `/`           | `q`       |
| 02 | Reflected XSS     | `/search`     | `q`       |
| 03 | SQL Injection     | `/search`     | `q`       |
| 04 | SQL Injection     | `/country`    | `code`    |
| 05 | Command Injection | `/admin/ping` | `host`    |
| 06 | SSRF              | `/api/fetch`  | `url`     |
| 07 | IDOR              | `/profile`    | `id`      |

These vulnerabilities are **intentionally introduced into SentinelGrid** for controlled validation.

---

## ✅ Validation Model

SUDARSHAN does not treat every detection as a confirmed vulnerability.

Every finding is assigned one of three states:

### `CONFIRMED`

The vulnerability was successfully reproduced through differential or baseline validation.

A reproducible proof-of-concept is generated.

### `UNVERIFIED`

A detection signal was observed, but the vulnerability could not be conclusively proven.

The finding is **not treated as a confirmed vulnerability**.

### `ERROR`

The security test could not be executed successfully because of an execution or environmental failure.

---

## 📊 Assessment Philosophy

The project follows an **evidence-first security assessment model**:

```text
Detection
    │
    ▼
Validation
    │
    ├── Failed ──► UNVERIFIED
    │
    ▼
Confirmed
    │
    ▼
Proof of Concept
    │
    ▼
Evidence
    │
    ▼
Risk Assessment
    │
    ▼
Remediation
    │
    ▼
Re-test
```

Only findings reaching the **CONFIRMED** state are treated as actual vulnerabilities within the SentinelGrid assessment.

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/CalculusGuy/<repository-name>.git
cd <repository-name>
```

---

### 2. Start SentinelGrid

Open the first terminal:

```bash
cd target-sentinelgrid
pip install -r requirements.txt
python init_db.py
python app.py
```

The local target will be available at:

```text
http://localhost:3000
```

---

### 3. Run SUDARSHAN

Open a second terminal:

```bash
cd sudarshan
pip install -r requirements.txt
python main.py --target http://localhost:3000/ --poc
```

Generated assessment artifacts will appear under:

```text
reports/
pocs/
```

---

## 📁 Repository Structure

```text
world-monitor-security-assessment/
│
├── target-sentinelgrid/
│   ├── app.py
│   ├── init_db.py
│   ├── requirements.txt
│   └── ...
│
├── sudarshan/
│   ├── main.py
│   ├── rules/
│   ├── reports/
│   ├── pocs/
│   └── ...
│
├── docs/
│   ├── METHODOLOGY.md
│   ├── FINDINGS.md
│   └── REMEDIATION.md
│
├── README.md
├── LICENSE
└── .gitignore
```

---

## 📚 Documentation

| Document                                     | Description                                          |
| -------------------------------------------- | ---------------------------------------------------- |
| [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) | Security assessment methodology and testing workflow |
| [`docs/FINDINGS.md`](docs/FINDINGS.md)       | Confirmed SentinelGrid vulnerabilities and evidence  |
| [`docs/REMEDIATION.md`](docs/REMEDIATION.md) | Recommended fixes and security controls              |

---

## 🔐 Security Assessment Workflow

The complete workflow can be summarized as:

```text
┌─────────────┐
│  Discovery  │
└──────┬──────┘
       ↓
┌─────────────┐
│   Mapping   │
└──────┬──────┘
       ↓
┌─────────────┐
│  Detection  │
└──────┬──────┘
       ↓
┌─────────────┐
│ Validation  │
└──────┬──────┘
       ↓
┌─────────────┐
│   Evidence  │
└──────┬──────┘
       ↓
┌─────────────┐
│ Risk/Report │
└──────┬──────┘
       ↓
┌─────────────┐
│ Remediation │
└──────┬──────┘
       ↓
┌─────────────┐
│   Re-test   │
└─────────────┘
```

---

## 🧩 Security Domains Demonstrated

The assessment demonstrates controlled testing across multiple common web application vulnerability classes:

* Cross-Site Scripting (XSS)
* SQL Injection
* Command Injection
* Server-Side Request Forgery (SSRF)
* Insecure Direct Object Reference (IDOR)
* Input validation failures
* Access-control weaknesses
* Secure application testing methodology
* Automated vulnerability validation
* Security evidence generation

---

## 🏆 SIH 2026

**Problem Statement:** SIH26163
**Domain:** Blockchain & Cybersecurity
**Project:** Security Assessment of the World Monitor Application
**Team:** Threat Lens
**Team Lead:** Nilanjan Chowdhury

### Team Philosophy

> **Don't just detect vulnerabilities. Prove them. Document them. Fix them. Re-test them.**

---

## ⚖️ Responsible Testing

This repository is intended strictly for:

* Educational research
* Authorized security assessments
* Controlled laboratory environments
* Cybersecurity demonstrations
* SIH 2026 evaluation

Do not use SUDARSHAN or SentinelGrid against systems without explicit authorization.

---

## 📄 License

MIT License

For educational and authorized security testing purposes.
