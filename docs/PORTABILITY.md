# Reusable Workflow — Portability Guide

This document explains how any Python project can adopt the shift-left security pipeline defined in this thesis repository without copying any tool configuration.

---

## How it works

The reusable workflow (security-scan-reusable.yml) is a self-contained security pipeline that any GitHub repository can call via workflow_call. The consuming project needs only one workflow file — no tool installation, no configuration duplication, no knowledge of Gitleaks, Semgrep or Trivy required.

**Consuming project:** security-scan.yml (5 lines of config)

**Thesis repository:** security-scan-reusable.yml containing:
- Secret Scanning (Gitleaks v8.18.4)
- SAST (Semgrep v1.162.0)
- SCA + Image Scan (Trivy)
- Security Dashboard (GitHub Pages)

---

## Quick Start

**Step 1** — Create .github/workflows/security-scan.yml in your repository:

name: Security Scan

on:
  push:
    branches: [ main ]
  workflow_dispatch:

permissions:
  security-events: write
  contents: read
  pages: write
  id-token: write

jobs:
  security:
    uses: ananthu3212/shift-left-security-thesis/.github/workflows/security-scan-reusable.yml@main
    with:
      docker-image-name: my-app-name
      semgrep-config: p/python
      trivy-severity: HIGH,CRITICAL
      fail-on-findings: true

**Step 2** — Enable GitHub Pages: Settings -> Pages -> Source: GitHub Actions

**Step 3** — Push a commit. The pipeline runs automatically.

**Step 4** — View your security dashboard at:
https://YOUR_USERNAME.github.io/YOUR_REPO_NAME/

---

## Inputs

- docker-image-name (Required) — Name for the Docker image to build and scan
- semgrep-config (Optional, default: p/python) — Semgrep ruleset. Use p/javascript for JS, p/java for Java
- custom-rules-path (Optional, default: empty) — Path to a directory of custom Semgrep rules in your repo
- trivy-severity (Optional, default: HIGH,CRITICAL) — CVE severity threshold
- fail-on-findings (Optional, default: true) — Block pipeline when findings detected. Use false for audit mode

---

## Operating Modes

**Strict mode (recommended for production)**
fail-on-findings: true
Pipeline blocks when any vulnerability is detected. Developers must fix findings before merging.

**Audit mode (recommended for initial adoption)**
fail-on-findings: false
Pipeline reports findings but does not block. Useful when first adopting the workflow to understand the current vulnerability landscape before enforcing gates.

---

## What gets scanned

Tool: Gitleaks
What it scans: Source code for hardcoded secrets and credentials
Version: v8.18.4

Tool: Semgrep
What it scans: Python source code for security vulnerabilities
Version: v1.162.0

Tool: Trivy
What it scans: Python dependencies (requirements.txt) and Docker image
Version: latest

---

## Outputs

- Security dashboard — GitHub Pages URL with HTML findings report per tool
- Gitleaks report — Artifact: gitleaks-report (JSON secret scan results)
- Semgrep report — Artifact: semgrep-report (JSON + SARIF SAST results)
- Trivy report — Artifact: trivy-reports (JSON + SARIF CVE results)
- GitHub Security tab — Repository -> Security (SARIF findings from Semgrep and Trivy)

---

## Live Demonstration

The reusable workflow was tested on an independent repository containing a deliberately vulnerable Flask application:

- Repository: https://github.com/ananthu3212/test-python-app
- Dashboard: https://ananthu3212.github.io/test-python-app/
- Findings detected: SQL injection (Semgrep), HIGH CVEs in Flask and Werkzeug (Trivy)
- Result: Pipeline blocked — demonstrating that the reusable workflow correctly enforces security gates on any consuming project

---

## Requirements for consuming projects

- Repository must be public OR GitHub Actions must have access to the thesis repo
- A Dockerfile must exist in the repository root
- GitHub Pages must be enabled (Settings -> Pages -> Source: GitHub Actions)
- Workflow permissions must include pages: write and id-token: write

---

## Portability classification of custom Semgrep rules

The 7 custom rules in rules/ of the thesis repository can optionally be used by consuming projects via the custom-rules-path input. Each rule's portability:

- deserialization.yaml — Portable — Any Python app using pickle
- path-traversal.yaml — Portable — Any Flask app with file operations
- open-redirect.yaml — Portable — Any Flask app with redirects
- sensitive-data-exposure.yaml — Flask-specific — Uses SQLite trace callback pattern
- cors-wildcard.yaml — Portable — Any Flask app using flask-cors
- csp-unsafe-inline.yaml — Portable — Any Flask app setting CSP headers
- flask-debug-mode.yaml — Portable — Any Flask app