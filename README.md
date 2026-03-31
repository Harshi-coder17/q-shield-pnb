<div align="center">

# 🛡️ Q-Shield
### Quantum-Proof Systems Scanner

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-4.2-092E20?style=flat-square&logo=django&logoColor=white)](https://www.djangoproject.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![NIST PQC](https://img.shields.io/badge/NIST-PQC%20Compliant-005A9C?style=flat-square)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![License](https://img.shields.io/badge/License-BSL-green?style=flat-square)](LICENSE)
[![PNB Hackathon](https://img.shields.io/badge/PNB%20Hackathon-2026-orange?style=flat-square)](https://github.com/Harshi-coder17/q-shield-pnb)

**"Quantum-Ready Cybersecurity for Future-Safe Banking"**

[Demo Video](https://drive.google.com/file/d/1lcj1HuAB5KF7iw0g4cD8YHRuOXhnWWQP/view?usp=drive_link) · [Report a Bug](https://github.com/Harshi-coder17/q-shield-pnb/issues)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [The Problem We Solve](#-the-problem-we-solve)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Quantum Safety Scoring Engine](#-quantum-safety-scoring-engine)
- [NIST PQC Algorithm Detection](#-nist-pqc-algorithm-detection)
- [Tech Stack](#-tech-stack)
- [Installation](#-installation)
- [Usage](#-usage)
- [API Reference](#-api-reference)
- [Security & Compliance](#-security--compliance)
- [Performance](#-performance)
- [Team](#-team)
- [Mentor](#-mentor)
- [License](#-license)

---

## 🔍 Overview

**Q-Shield** is a standalone, intranet-deployable **Quantum-Proof Systems Scanner** built for **Punjab National Bank's PSB Hackathon 2026**. It addresses the critical and growing threat of *Harvest Now, Decrypt Later (HNDL)* attacks — where adversaries intercept encrypted data today and decrypt it once cryptanalytically relevant quantum computers (CRQCs) emerge.

Q-Shield performs deep TLS inspection across public-facing banking infrastructure, generates a **Cryptographic Bill of Materials (CBOM)** compliant with Cert-In Annexure-A guidelines, and produces a quantitative **Quantum Safety Score** (0–100) for every scanned asset — all through a clean, enterprise-ready web dashboard.

> ⚠️ Q-Shield is **read-only and non-intrusive** — it never disrupts live banking services.

---

## 🎯 The Problem We Solve

Modern banking infrastructure relies heavily on classical cryptographic algorithms — RSA, ECDSA, ECDH — that are mathematically vulnerable to quantum computers. The **"Harvest Now, Decrypt Later"** threat means adversaries don't need to wait for quantum hardware; they are intercepting encrypted traffic *today* with the intent to decrypt it *tomorrow*.

Q-Shield gives PNB's cybersecurity and compliance teams a clear answer to: **"How quantum-safe are we — right now?"**

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔎 **Asset Discovery** | Automatically discovers domains, IPs, APIs, VPN endpoints, and TLS-enabled services |
| 🤝 **TLS Handshake Analysis** | Extracts TLS version, cipher suites, key exchange algorithms, and full X.509 certificate metadata |
| 🧮 **Quantum Safety Scoring** | Produces a 0–100 score across 7 weighted cryptographic dimensions per asset |
| 🏷️ **Label Assignment** | Auto-assigns: 🟢 Fully Quantum Safe / 🟡 PQC Ready / 🔴 Vulnerable / ⚫ Critical |
| 🔬 **NIST PQC Detection** | Detects ML-KEM, ML-DSA, SLH-DSA, and FALCON hybrid implementations |
| 📊 **Dependency Graph** | Visualizes cryptographic relationships between assets, certificates, CAs, and algorithms |
| ⚠️ **HNDL Exposure Analysis** | Assesses Harvest-Now-Decrypt-Later risk based on encryption strength and data lifetime |
| 🔁 **Certificate Reuse Detection** | Identifies shared TLS certificates across multiple systems and flags blast-radius risk |
| 📄 **CBOM Generation** | Produces Cert-In Annexure-A compliant reports in JSON, CSV, and PDF formats |
| 📅 **Scheduled Scanning** | Automated periodic scans with change detection alerts |
| 🖥️ **Enterprise Dashboard** | Role-based web GUI with real-time High/Medium/Low risk ratings, dark mode support |
| 🔒 **RBAC** | Admin, Checker, and Read-Only access roles with full audit logging |

---

## 🏗️ System Architecture

Q-Shield follows a **3-tier architecture** deployed entirely within PNB's intranet boundary:

```
┌─────────────────────────────────────────────────────────────────┐
│                     PNB INTRANET BOUNDARY                       │
│                                                                 │
│   ┌───────────────┐        ┌──────────────────────────────┐     │
│   │  DASHBOARD UI │ ◀────▶ │     DJANGO REST API SERVER    │     │
│   │  (Bootstrap 5)│        └───────────────┬──────────────┘     │
│   └───────────────┘                        │                    │
│                                            ▼                    │
│                               ┌────────────────────────┐        │
│                               │   ASSET DISCOVERY      │        │
│                               │       ENGINE           │        │
│                               └───────────┬────────────┘        │
│                                           │                     │
│                                           ▼                     │
│                               ┌────────────────────────┐        │
│                               │   TLS SCANNER ENGINE   │        │
│                               └───────────┬────────────┘        │
│                                           │                     │
│                                           ▼                     │
│                               ┌────────────────────────┐        │
│                               │  CRYPTOGRAPHIC ANALYSIS│        │
│                               │       ENGINE           │        │
│                               └──────┬────────┬────────┘        │
│                                      │        │                 │
│              ┌───────────────────────┘        └──────────────┐  │
│              ▼                                               ▼  │
│  ┌─────────────────────┐  ┌────────────────────┐  ┌────────────┐│
│  │  QUANTUM RISK       │  │  DEPENDENCY GRAPH  │  │  REPORT    ││
│  │  SCORING ENGINE     │  │  ENGINE            │  │  GENERATOR ││
│  └──────────┬──────────┘  └────────┬───────────┘  └─────┬──────┘│
│             │                      │                     │      │
│             └──────────────┬───────┘─────────────────────┘      │
│                            ▼                                    │
│               ┌──────────────────────────────┐                  │
│               │     PostgreSQL Database      │                  │
│               │  (Scan Results + CBOM Store) │                  │
│               └──────────────────────────────┘                  │
└──────────────────────────────┬──────────────────────────────────┘
                               │ (Outbound TLS only)
                               ▼
          ┌──────────────┬──────────────┬──────────────┐
          │  Web Server  │ API Gateway  │ VPN Endpoint │
          └──────────────┴──────────────┴──────────────┘
               PUBLIC-FACING INTERNET ENDPOINTS (SCAN TARGETS)
```

### Core Modules

1. **Asset Discovery Engine** — Discovers public-facing banking assets: domains, IP addresses, APIs, SSL certificates, and network services.
2. **TLS Scanner Engine** — Performs TLS handshake analysis to extract protocol versions, cipher suites, key exchange algorithms, and certificate data.
3. **Cryptographic Analysis Engine** — Parses X.509 certificates, identifies cryptographic algorithms, evaluates cipher strength, and detects vulnerable implementations.
4. **Quantum Risk Scoring Engine** — Calculates a 0–100 quantum safety score per asset across 7 weighted dimensions.
5. **Dependency Graph Engine** — Builds a visual graph of relationships between assets, certificates, CAs, and cryptographic algorithms.
6. **Dashboard & Visualization Engine** — Web-based GUI for enterprise-wide monitoring with PQC readiness posture and risk ratings.
7. **Report Generator** — Produces machine-readable CBOM reports in JSON, CSV, and PDF.

---

## 🧮 Quantum Safety Scoring Engine

Each scanned asset receives a **Quantum Safety Score (0–100)** across 7 dimensions:

| Dimension | Max Score | Criteria |
|---|---|---|
| TLS Version | 25 pts | TLS 1.3 = 25 · TLS 1.2 = 12 · TLS 1.1/1.0 = 0 |
| Cipher Suite | 20 pts | Strong AEAD (AES-GCM, ChaCha20) = 20 · Weak (CBC) = 10 · Deprecated = 0 |
| Key Exchange Algorithm | 20 pts | Forward secrecy enabled |
| Key Size | 10 pts | ≥ 2048-bit RSA or equivalent |
| Certificate Algorithm | 15 pts | ML-DSA = 15 · ECDSA = 2.5 · RSA = 0 |
| Certificate Validity | 5 pts | Valid >90 days = 5 · <30 days = 2.5 · Expired = 0 |
| Certificate Reuse Risk | 5 pts | Unique certificate per system |

### Label Decision Flow

```
Score ≥ 90  →  🟢  FULLY QUANTUM SAFE
Score ≥ 60  →  🟡  PQC READY
Score ≥ 30  →  🔴  QUANTUM VULNERABLE
Score < 30  →  ⚫  CRITICAL
```

---

## 🔬 NIST PQC Algorithm Detection

Q-Shield detects and validates the presence of NIST-standardized Post-Quantum Cryptography algorithms:

| Algorithm | Standard | Type | OID |
|---|---|---|---|
| ML-KEM (Kyber) | FIPS 203 | Key Exchange | `2.16.840.1.101.3.4.4.x` |
| ML-DSA (Dilithium) | FIPS 204 | Digital Signature | `2.16.840.1.101.3.4.3.17` |
| SLH-DSA (SPHINCS+) | FIPS 205 | Digital Signature | `2.16.840.1.101.3.4.3.20` |
| FALCON | NIST Round 4 | Digital Signature | `1.3.9999.3.x` |

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Backend | Python 3.11+ | Core scanner engine, PQC analysis |
| Backend | Django 4.2 | REST API and dashboard server |
| Backend | cryptography 42.0 | Deep X.509 certificate OID parsing |
| Backend | Django ORM | Database ORM abstraction |
| Frontend | HTML5 + Bootstrap 5 | Dashboard UI |
| Frontend | JavaScript ES6+ | Real-time scan results, charts |
| Database | SQLite | Local development |
| Database | PostgreSQL 15 | Production scan result storage |
| Security Tools | SSLyze + Nmap + OpenSSL | TLS analysis utilities |
| Reporting | ReportLab 4.1 | PDF CBOM report generation |
| Reporting | pandas 2.2 | CSV report generation |
| DevOps | Git + GitHub | Version control and collaboration |

---

## ⚙️ Installation

### Prerequisites

- Python 3.11+
- PostgreSQL 15 (production) or SQLite (development)
- Node.js (for frontend build, if applicable)

---

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/Harshi-coder17/q-shield-pnb.git
cd q-shield-pnb

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env

# Edit .env with your database URL and secret key

# 5. Apply database migrations
python manage.py migrate

# 6. Create superuser (for admin access)
python manage.py createsuperuser

# 7. Run the Django server
python manage.py runserver
```

The dashboard will be available at 
Frontend : `http://localhost:3000`
Backend (Django): `http://127.0.0.1:8000`
### Production Deployment

For production, configure PostgreSQL in `.env`:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/qshield
SECRET_KEY=your-secret-key
```

---

## 🚀 Usage

### Single URL Scan

```
POST /api/scan
Content-Type: application/json

{ "url": "https://target.example.com" }
```

### Batch Scan

Upload a `.txt` file containing one URL/IP per line via the dashboard's **Batch Scan** interface.

### Scan Workflow

```
1. Admin enters URL/IP or uploads batch .txt file
2. System validates URL format and reachability on port 443
3. Scanner initiates TLS handshake with target
4. TLS version, cipher suite, key exchange, and X.509 certificate extracted
5. Certificate parsed: subject, issuer, validity, signature algorithm OID, key size
6. OID mapped to algorithm name (RSA / ECDSA / ML-DSA / etc.)
7. Quantum Safety Score (0–100) calculated across 7 dimensions
8. Label assigned: Fully Quantum Safe / PQC Ready / Vulnerable / Critical
9. Actionable remediation steps generated for non-PQC assets
10. Scan result saved to database with timestamp
11. Cert-In Annexure-A compliant CBOM generated
12. Enterprise dashboard updated with risk rating
```

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Initiate a scan for a single URL or IP |
| `GET` | `/api/results` | Retrieve all stored scan results |
| `GET` | `/api/results/<id>` | Retrieve a specific scan result |
| `GET` | `/api/summary` | Get enterprise-wide risk summary |
| `GET` | `/api/cbom/<id>` | Get CBOM for a specific scan |
| `GET` | `/api/report/<id>?format=pdf\|csv\|json` | Export scan report |

All API endpoints are served over HTTPS and require authentication tokens.

---

## 🔐 Security & Compliance

- **NIST PQC Standards** — FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- **Cert-In Annexure-A** — Full coverage of all minimum CBOM elements
- **RBI IT Framework** — Compliant with Reserve Bank of India IT security guidelines
- **RBAC** — Admin (full access) · Checker (view + download) · Auditor (read-only)
- **MFA** — Multi-factor authentication for Admin users
- **Audit Logs** — All scan actions logged with user ID, timestamp, target, and result
- **TLS 1.3** — Dashboard and all API traffic served over TLS 1.3
- **Read-Only Scanner** — Only outbound TLS connections; no inbound ports exposed beyond dashboard HTTPS
- **Data Retention** — All scan data retained for minimum 1 year for audit compliance

---

## ⚡ Performance

| Metric | Target |
|---|---|
| Single endpoint scan | < 30 seconds |
| Batch scan (100 URLs) | < 30 minutes |
| Dashboard load (10,000 records) | < 3 seconds |
| Concurrent scans supported | 5 simultaneous |
| PDF report generation | < 10 seconds |
| System uptime | 99.5% |

---

## 👥 Team

**Team GarudaGrid** — B.Tech 2nd Year, Thapar Institute of Engineering and Technology (TIET), Patiala

| Member | Role |
|---|---|
| **Harshita** | Team Lead · Network & Frontend Engineer |
| **Adhiraj Singh Saini** | CBOM & FullStack Engineer |
| **Komal Kakkar** | Backend & Scoring Engine Engineer |
| **Antriksh** | Deployment & API Infrastructure |

---

## 🎓 Mentor

**Dr. Gurpal Singh Chhabra**
Assistant Professor, Thapar Institute of Engineering and Technology (TIET), Patiala

---

## 📺 Demo

Watch the full working demo of Q-Shield:
👉 [Demo Video on Google Drive](https://drive.google.com/file/d/1lcj1HuAB5KF7iw0g4cD8YHRuOXhnWWQP/view?usp=drive_link)

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<div align="center">

Built with ❤️ by Team GarudaGrid · PSB Hackathon 2026 · Punjab National Bank

</div>

