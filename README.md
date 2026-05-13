# Shift-Left Security in CI/CD Pipelines

**Bachelor Thesis** · Westfälische Hochschule Gelsenkirchen · Informatik B.Sc.  
**Author:** Ananthu Chandra Babu  
**Supervisor:** Prof. Dr. Tobias Urban  
**Year:** 2026

---

## Overview

This repository contains the complete technical artefact for the bachelor thesis:

> *"Shift-Left Security in CI/CD Pipelines: Design, Implementation and Indicative Evaluation of SAST, SCA and Secret Scanning Using a Containerised Flask Web Application on AWS ECS Fargate"*

The artefact implements and evaluates a shift-left security pipeline that integrates four security tools — Gitleaks, Semgrep, Trivy and tfsec — into a GitHub Actions CI/CD pipeline. A deliberately vulnerable Flask application (flask-webgoat) serves as the evaluation target.

---

## Repository Structure

```
.
├── .github/workflows/
│   ├── baseline.yml
│   ├── hardened.yml
│   ├── parallel.yml
│   └── security-scan-reusable.yml
├── flask_webgoat/
├── rules/
├── scripts/
│   ├── generate_report.py
│   └── generate_generic_report.py
├── terraform/
├── data/
│   └── runtime.json
└── docs/
    └── PORTABILITY.md
```

### Key Directories

- **.github/workflows/** — Contains all pipeline definitions:
  - `baseline.yml` — Docker build only, no security tools
  - `hardened.yml` — Sequential security scanning with all 4 tools
  - `parallel.yml` — Parallel execution for runtime comparison
  - `security-scan-reusable.yml` — Reusable workflow callable from any Python project

- **flask_webgoat/** — Intentionally vulnerable Flask application used as the evaluation target

- **rules/** — Custom Semgrep rules covering 7 CWE categories: CWE-502, CWE-22, CWE-601, CWE-200, CWE-284, CWE-16, CWE-94

- **scripts/** — Dashboard generators:
  - `generate_report.py` — Thesis evaluation dashboard
  - `generate_generic_report.py` — Generic security dashboard

- **terraform/** — Hardened AWS ECS Fargate infrastructure as code

- **data/runtime.json** — Runtime statistics from controlled experiments (n=10 per pipeline)

- **docs/PORTABILITY.md** — Guide for adopting the reusable workflow in other projects

---

## Pipelines

| Pipeline | Trigger | Purpose |
|----------|---------|---------|
| `baseline.yml` | Push to main | Pre-shift-left baseline — Docker build only |
| `hardened.yml` | Push to main | Hardened sequential pipeline — all 4 security tools |
| `parallel.yml` | Manual | Runtime comparison — all tools run simultaneously |
| `security-scan-reusable.yml` | `workflow_call` | Reusable workflow for any Python project |

Both `baseline.yml` and `hardened.yml` trigger on every push, enabling direct side-by-side comparison of pre- and post-shift-left execution.

---

## Security Tools

| Tool | Version | Category | Purpose |
|------|---------|----------|---------|
| Gitleaks | v8.18.4 | Secret Scanning | Detects hardcoded secrets and credentials |
| Semgrep | v1.162.0 | SAST | Static code analysis with default and 7 custom rules |
| Trivy | latest | SCA + Container | Dependency CVE scanning and container image analysis |
| tfsec | v1.28.11 | IaC SAST | Terraform infrastructure misconfiguration detection |

---

## Evaluation Results

### Detection Performance

| Tool | Precision | Recall | F1 Score |
|------|-----------|--------|----------|
| Semgrep | 90.9% | 100.0% | 95.2% |
| Gitleaks | 100.0% | 100.0% | 100.0% |
| Trivy | 100.0% | 66.7% | 80.0% |
| **Combined** | **92.9%** | **92.9%** | **92.9%** |

**Ground truth:** 13 out of 14 application vulnerabilities detected across V01–V14.  
**IaC assessment:** 8 findings classified (3 remediated, 2 intentional, 2 known limitations, 1 false positive).

### Runtime Comparison (n=10 per pipeline)

| Pipeline | Mean | Std Dev |
|----------|------|---------|
| Baseline (no security) | 35.5s | ±7.6s |
| Parallel (4 tools) | 231s | ±54.6s |
| Sequential (4 tools) | 303s | ±38.3s |

---

## Dashboard

The thesis evaluation dashboard is automatically deployed to GitHub Pages on every push:

**[https://ananthu3212.github.io/shift-left-security-thesis/](https://ananthu3212.github.io/shift-left-security-thesis/)**

---

## Custom Semgrep Rules

Seven custom rules extend the default `p/python` ruleset to detect vulnerabilities missed by default scanners:

| Rule | CWE | OWASP Category |
|------|-----|----------------|
| flask-insecure-deserialization-pickle | CWE-502 | A08:2021 — Software and Data Integrity Failures |
| flask-path-traversal-string-concat | CWE-22 | A01:2021 — Broken Access Control |
| flask-open-redirect-request-param | CWE-601 | A01:2021 — Broken Access Control |
| sqlite-trace-callback-data-exposure | CWE-200 | A02:2021 — Cryptographic Failures |
| flask-cors-wildcard-origin | CWE-284 | A01:2021 — Broken Access Control |
| flask-csp-unsafe-inline | CWE-16 | A05:2021 — Security Misconfiguration |
| flask-debug-mode-enabled | CWE-94 | A05:2021 — Security Misconfiguration |

---

## Reusable Workflow

Any Python project can adopt shift-left security scanning by adding one file to their workflow:

```yaml
jobs:
  security:
    uses: ananthu3212/shift-left-security-thesis/.github/workflows/security-scan-reusable.yml@main
    with:
      docker-image-name: my-app
      semgrep-config: p/python
      trivy-severity: HIGH,CRITICAL
      fail-on-findings: true
```

For complete documentation, see **[docs/PORTABILITY.md](docs/PORTABILITY.md)**.  
For a live portability demonstration, see **[ananthu3212/test-python-app](https://github.com/ananthu3212/test-python-app)**.

---

## Infrastructure

The Terraform configuration in `/terraform` provisions a hardened AWS ECS Fargate environment with the following security measures:

- **Networking:** Private subnets with VPC endpoints for ECR, S3, CloudWatch, and Secrets Manager
- **Encryption:** KMS encryption for ECR, CloudWatch Logs, and Secrets Manager
- **Access Control:** Separation of IAM execution role and task role, OIDC federation for GitHub Actions
- **Container Hardening:** Non-root user, read-only filesystem, dropped Linux capabilities
- **Compliance:** NIS2 §30 BSIG controls mapped to infrastructure hardening measures

Infrastructure is provisioned on demand and destroyed after each session to minimise cost.

---

## Reproducing the Evaluation

Follow these steps to reproduce the full evaluation:

1. **Fork this repository**
2. **Enable GitHub Pages:** Go to Settings → Pages → Source: GitHub Actions
3. **Trigger pipelines:** Push any commit to `main` to trigger both `baseline.yml` and `hardened.yml` simultaneously
4. **View results:** Access the evaluation dashboard at `https://<your-username>.github.io/<repo-name>/`
5. **Runtime comparison:** Go to Actions → Parallel Pipeline → Run workflow to trigger the parallel execution
6. **Download data:** Runtime statistics are available as workflow artifacts after each run

---

## License

This project is part of a bachelor thesis at Westfälische Hochschule Gelsenkirchen.