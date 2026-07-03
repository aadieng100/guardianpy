<div align="center">

<h1>🛡️ GuardianPy</h1>

<p><strong>Automated Policy-as-Code & Cloud Security Posture Management Engine</strong></p>

<p><em>Shift security left. Break the pipeline before breaches break production.</em></p>

<br/>

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/Security-SAST%20%7C%20CSPM-ef4444?style=for-the-badge&logo=shield&logoColor=white)]()
[![AWS](https://img.shields.io/badge/Cloud-AWS%20%28Mocked%29-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)](https://aws.amazon.com/)
[![ChatOps](https://img.shields.io/badge/ChatOps-Slack%20%7C%20Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)]()
[![CI/CD](https://img.shields.io/badge/CI%2FCD-Pipeline%20Gatekeeper-0ea5e9?style=for-the-badge&logo=githubactions&logoColor=white)]()

<br/>

> **GuardianPy** is a local-first, zero-cost DevSecOps compliance engine that acts as a security gatekeeper across both your infrastructure files (SAST) and simulated live AWS environments (CSPM)—with no cloud credentials, no external SDKs, and no hardcoded secrets.

</div>

---

## 📋 Table of Contents

- [Core Value Proposition](#-core-value-proposition)
- [System Architecture](#-system-architecture)
- [Compliance Rules Catalogue](#-compliance-rules-catalogue)
- [Quickstart & Installation](#-quickstart--installation)
- [Configuration Reference](#-configuration-reference)
- [Pipeline Integration](#-pipeline-integration)
- [Live Output Example](#-live-output-example)
- [Generated Security Artifact](#-generated-security-artifact)
- [ChatOps Alerting](#-chatops-alerting)
- [Project Structure](#-project-structure)
- [Design Philosophy](#-design-philosophy)
- [Roadmap](#-roadmap)

---

## 🚀 Core Value Proposition

| Pillar | Description |
|:---|:---|
| 🔀 **Shift-Left Enforcement** | Intercepts threats at the local development or pre-commit phase—before they reach staging or production environments. |
| 💸 **Zero-Cost Cloud Auditing** | Uses `moto` dependency injection to spin up a fully isolated, in-memory AWS environment. No cloud credentials. No accidental resource provisioning. No bill. |
| 🚦 **Automated Gatekeeping** | Strictly compliant with POSIX standards—emits `exit 1` on policy failures and `exit 0` on clean scans, enabling seamless integration with any CI/CD pipeline. |
| 📣 **ChatOps Integrated** | Dispatches real-time security summaries to Slack and Discord via native `urllib` HTTP—zero heavyweight SDK dependencies. |
| 🔌 **Modular Rule Engine** | Every scanner and reporter is a fully decoupled module. Adding new compliance rules requires no changes to the core orchestrator. |

---

## 🏗️ System Architecture

```
guardianpy/
│
├── targets/                        # 🧪 Intentionally vulnerable test suite laboratory
│   ├── Dockerfile.vuln             #    Anti-patterns: :latest, hardcoded secrets, root user
│   └── main.tf.vuln                #    Anti-patterns: public S3 ACL misconfiguration
│
└── guardianpy/                     # ⚙️  Core engine
    ├── main.py                     #    CLI Orchestrator, Moto environment seeder & Gatekeeper
    ├── config.py                   #    12-Factor App compliant environment variable manager
    │
    ├── scanners/                   # 🔍  Rule-engine analysis modules
    │   ├── static.py               #    SAST: Regex-driven Dockerfile & Terraform scanner
    │   └── aws_mock.py             #    CSPM: Mocked AWS S3 perimeter & IAM hardening auditor
    │
    └── reporters/                  # 📊  Output delivery interfaces
        ├── markdown.py             #    Generates immutable Markdown build artifacts
        └── notifier.py             #    Dispatches real-time Slack/Discord ChatOps alerts
```

### Component Stack

| Component | Technology | Security Goal |
|:---|:---|:---|
| **Static Engine (SAST)** | Python `re` (Regex) / Stream I/O | Identifies configuration drift, unpinned image versions, and leaked secrets in IaC files |
| **Cloud Simulation (CSPM)** | `boto3` / `moto` (In-Memory Sandbox) | Validates IAM hardening and data perimeter controls without any live AWS risk |
| **Orchestration** | Python Standard Library (`sys`, `os`) | Enforces pipeline automation blocking behavior via POSIX exit codes |
| **Reporting Suite** | `urllib` Native HTTP / Markdown | Generates immutable build artifacts and powers real-time Slack/Discord ChatOps alerts |

### Execution Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        python3 -m guardianpy.main               │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────▼───────────────┐
          │       Phase 1: SAST Scan      │
          │  Dockerfile.vuln + main.tf    │
          │  (Regex Rule Engine)          │
          └───────────────┬───────────────┘
                          │
          ┌───────────────▼───────────────┐
          │       Phase 2: CSPM Audit     │
          │  Moto In-Memory AWS Sandbox   │
          │  (S3 Perimeter + IAM MFA)     │
          └───────────────┬───────────────┘
                          │
          ┌───────────────▼───────────────┐
          │   Phase 3: Results & Reports  │
          │  Markdown Artifact + ChatOps  │
          └───────────────┬───────────────┘
                          │
          ┌───────────────▼───────────────┐
          │    Phase 4: Gatekeeper        │
          │  exit 1 (FAIL) / exit 0 (OK) │
          └───────────────────────────────┘
```

---

## 🔍 Compliance Rules Catalogue

### Phase 1 — Shift-Left Infrastructure Checks (SAST)

> Analyzes local IaC files **before** any deployment occurs.

#### 🐳 Dockerfile Rules

| ID | Severity | Rule | Rationale |
|:---|:---:|:---|:---|
| `DOCK-001` | 🟡 **MEDIUM** | Blocks `:latest` base image tags | Non-deterministic builds violate immutability principles and reproducibility. |
| `DOCK-002` | 🔴 **CRITICAL** | Detects hardcoded credentials in `ENV` statements | Plaintext secrets in image layers are permanently exposed via `docker history`. |
| `DOCK-003` | 🟠 **HIGH** | Flags missing `USER` directive | Containers without an explicit user run as `root` by default—a critical container escape vector. |

#### ☁️ Terraform Rules

| ID | Severity | Rule | Rationale |
|:---|:---:|:---|:---|
| `TF-001` | 🔴 **CRITICAL** | Flags `acl = "public-read"` on S3 resources | Public ACLs expose sensitive data to the open internet—a leading cause of cloud data breaches. |

---

### Phase 2 — Simulated Cloud Infrastructure Audit (CSPM)

> Provisions a fully isolated, in-memory AWS environment via `moto` and runs live-equivalent compliance checks.

| ID | Service | Severity | Rule | Standard Alignment |
|:---|:---:|:---:|:---|:---|
| `AWS-S3-001` | S3 | 🔴 **CRITICAL** | Detects buckets with `AllUsers` public ACL grants | CIS AWS Benchmark 2.1.2 |
| `AWS-IAM-001` | IAM | 🟠 **HIGH** | Audits IAM users without MFA devices enrolled | CIS AWS Benchmark 1.10 / AWS Well-Architected |

---

## ⚡ Quickstart & Installation

### Prerequisites

- Python `3.9` or higher
- `pip` package manager

### 1. Clone the Repository

```bash
git clone https://github.com/aadieng100/guardianpy.git
cd guardianpy
```

### 2. Initialize Your Isolated Workspace

```bash
# Create and activate a private virtual environment
python3 -m venv .venv
source .venv/bin/activate       # macOS / Linux
# .venv\Scripts\activate        # Windows

# Upgrade pip and install locked, production-ready dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Run the Compliance Scan

```bash
python3 -m guardianpy.main
```

That's it. No AWS credentials. No external accounts. No cloud costs.

---

## ⚙️ Configuration Reference

GuardianPy is fully configured through **environment variables**, following the [12-Factor App](https://12factor.net/config) methodology. Every setting has a safe default so it works out of the box.

| Variable | Default | Description |
|:---|:---|:---|
| `GUARDIAN_DOCKERFILE_PATH` | `targets/Dockerfile.vuln` | Path to the Dockerfile to be scanned by the SAST engine. |
| `GUARDIAN_TERRAFORM_PATH` | `targets/main.tf.vuln` | Path to the Terraform `.tf` file to be scanned. |
| `GUARDIAN_FAIL_ON_SEVERITY` | `HIGH` | Minimum severity level that triggers a pipeline failure (`CRITICAL`, `HIGH`, `MEDIUM`). |
| `GUARDIAN_SLACK_WEBHOOK` | *(empty)* | Optional. Full Slack Incoming Webhook URL for ChatOps alerts. |
| `GUARDIAN_DISCORD_WEBHOOK` | *(empty)* | Optional. Full Discord Webhook URL for ChatOps alerts. |

### Example: Scan Custom IaC Files

```bash
export GUARDIAN_DOCKERFILE_PATH="infra/production/Dockerfile"
export GUARDIAN_TERRAFORM_PATH="infra/terraform/s3.tf"
export GUARDIAN_FAIL_ON_SEVERITY="CRITICAL"

python3 -m guardianpy.main
```

---

## 🔗 Pipeline Integration

GuardianPy emits a standard POSIX exit code, making it compatible with **any** CI/CD platform.

| Exit Code | Meaning | Trigger Condition |
|:---:|:---|:---|
| `0` | ✅ **PASSED** | No findings at or above the configured severity threshold. |
| `1` | ❌ **BLOCKED** | One or more findings meet or exceed the configured severity threshold. |

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: GuardianPy Security Gate

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Run GuardianPy Compliance Scan
        env:
          GUARDIAN_FAIL_ON_SEVERITY: HIGH
          GUARDIAN_DISCORD_WEBHOOK: ${{ secrets.DISCORD_WEBHOOK }}
        run: python3 -m guardianpy.main

      - name: Upload Security Report Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: guardianpy-security-report
          path: guardianpy_report.md
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security:guardianpy:
  stage: test
  image: python:3.11-slim
  script:
    - pip install -r requirements.txt
    - python3 -m guardianpy.main
  artifacts:
    when: always
    paths:
      - guardianpy_report.md
  variables:
    GUARDIAN_FAIL_ON_SEVERITY: "HIGH"
```

---

## 📊 Live Output Example

Running against the bundled vulnerable test suite produces the following output:

```
============================================================
🛡️  GUARDIANPY: DevSecOps Static & Cloud Compliance Scanner 🛡️
============================================================

[+] Running Static Code Analysis (Shift-Left SAST)...
 -> Scanning Dockerfile: targets/Dockerfile.vuln
 -> Scanning Terraform: targets/main.tf.vuln

[+] Initializing Mock Cloud Environment & Running CSPM Audit...

============================================================
📊 SCAN RESULTS: Found 5 issues.
============================================================

[MEDIUM] File: targets/Dockerfile.vuln (Line 2)
      Issue: Usage of ':latest' tag detected. Prefer pinned versions or content hashes for immutability.

[CRITICAL] File: targets/Dockerfile.vuln (Line 5)
      Issue: Potential hardcoded secret or API key detected in environment variable.

[HIGH] File: targets/Dockerfile.vuln (Line Global)
      Issue: No 'USER' instruction detected. The container will run as root by default.

[CRITICAL] File: targets/main.tf.vuln (Line 17)
      Issue: S3 bucket configured with a public ACL ('public-read'). Major data leakage risk.

[CRITICAL] Resource: arn:aws:s3:::guardianpy-public-exposure-bucket (S3_Bucket)
      Issue: S3 Bucket 'guardianpy-public-exposure-bucket' has a public ACL configuration.

[HIGH] Resource: arn:aws:iam:::user/vulnerable-ci-user (IAM_User)
      Issue: IAM User 'vulnerable-ci-user' does not have Multi-Factor Authentication (MFA) enabled.

[+] Generating local security report...
 -> Markdown report successfully written to: /path/to/guardianpy_report.md

============================================================
❌ [GATEKEEPER BLOCKED] Critical/High vulnerabilities detected.
Stopping process execution with Exit Code 1.
============================================================
```

---

## 📄 Generated Security Artifact

Every scan automatically writes an immutable, structured Markdown report to `guardianpy_report.md`.

This artifact is designed to be:
- **Committed** to version control as a security audit trail.
- **Uploaded** as a CI/CD pipeline artifact for permanent build records.
- **Parsed** by downstream tooling for ticket creation or SIEM ingestion.

---

## 📣 ChatOps Alerting

GuardianPy can stream real-time security summaries to your team's communication channels with zero external SDK dependencies (uses Python's built-in `urllib` only).

### Enable Slack Alerts

```bash
export GUARDIAN_SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
python3 -m guardianpy.main
```

### Enable Discord Alerts

```bash
export GUARDIAN_DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
python3 -m guardianpy.main
```

Both can be active simultaneously. The alert payload looks like:

```
🚨 GuardianPy Security Alert 🚨
Scan completed with blocking issues found.
• Total Issues: 5
• 🔥 Critical: 3
• ⚠️  High: 1
Please check the generated Markdown artifact for full details.
```

> **Security Note:** Always pass webhook URLs via environment variables or CI/CD secrets management—never hardcode them in source files.

---

## 📁 Project Structure

```
guardianpy/
├── .gitignore
├── README.md
├── requirements.txt                   # Pinned production dependencies
│
├── targets/                           # Intentionally vulnerable IaC test suite
│   ├── Dockerfile.vuln                # Anti-patterns: :latest, root exec, hardcoded secrets
│   └── main.tf.vuln                   # Anti-patterns: public-read S3 ACL
│
└── guardianpy/                        # Core engine package
    ├── __init__.py
    ├── main.py                        # CLI orchestrator + Moto environment seeder
    ├── config.py                      # 12-Factor environment variable management
    │
    ├── scanners/
    │   ├── __init__.py
    │   ├── static.py                  # SAST: Dockerfile & Terraform regex rule engine
    │   └── aws_mock.py                # CSPM: Mocked AWS S3 & IAM compliance auditor
    │
    └── reporters/
        ├── __init__.py
        ├── markdown.py                # Generates structured Markdown security reports
        └── notifier.py               # ChatOps: native Slack & Discord webhook dispatcher
```

---

## 🧠 Design Philosophy

GuardianPy was engineered around three core principles:

**1. Zero External Friction**
The entire tool runs on a single `pip install -r requirements.txt`. No AWS credentials are needed. No external accounts. No paid tiers. The CSPM engine uses `moto` to provision a fully isolated, in-memory AWS runtime that is completely destroyed after each scan.

**2. Strict Separation of Concerns**
Each module has a single, clearly defined responsibility. The `scanners/` layer performs detection only. The `reporters/` layer handles presentation only. The `config.py` layer manages environment state only. The `main.py` orchestrator wires them together without embedding business logic. This architecture makes adding new compliance rules a matter of editing one file.

**3. Production-Grade Security by Default**
GuardianPy is designed to follow the same security standards it enforces. Secrets are loaded from the environment, never from source. The HTTP client uses Python's built-in `urllib` to avoid supply-chain risk from third-party HTTP libraries. Pipeline exits are deterministic and testable.

---

## 🛣️ Roadmap

- [ ] **JSON / SARIF Report Output** — Structured machine-readable reports for SIEM ingestion and GitHub Code Scanning integration.
- [ ] **Pre-Commit Hook** — Native `pre-commit` framework integration for zero-friction developer adoption.
- [ ] **Extended SAST Rules** — Support for `docker-compose.yml`, Kubernetes manifests, and Helm charts.
- [ ] **Extended CSPM Rules** — AWS Security Groups, CloudTrail logging compliance, and S3 public access block validation.
- [ ] **Configurable Rule Sets** — YAML-driven rule definitions to allow teams to author and share custom policies.
- [ ] **Multi-Cloud Support** — Azure and GCP CSPM modules using equivalent mock libraries.

---

## 📦 Dependencies

| Package | Version | Purpose |
|:---|:---|:---|
| `boto3` | `1.34.131` | AWS SDK — client interface for CSPM module |
| `moto[s3,iam]` | `5.0.10` | In-memory AWS mock framework for zero-cost cloud simulation |

All other functionality relies exclusively on the **Python Standard Library** (`re`, `os`, `sys`, `json`, `urllib`, `datetime`).

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built as a demonstration of advanced DevSecOps engineering principles.**
*Shifting security to the earliest layers of development—efficiently, securely, and at zero cost.*

</div>
