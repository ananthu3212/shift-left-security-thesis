# Using the Shift-Left Security Pipeline in Your Project

This document explains how to adopt the reusable security scanning
pipeline from this thesis in any GitHub-hosted Python project.

---

## What the pipeline does

On every push, the pipeline runs three security tools in sequence:

| Stage | Tool | What it scans |
|---|---|---|
| 1 | Gitleaks | Full git history for hardcoded secrets and credentials |
| 2 | Semgrep | Source code for vulnerabilities (SAST) |
| 3 | Trivy | Dependencies and container image for known CVEs (SCA) |

All findings are uploaded to the **GitHub Security tab** (Code scanning)
and a summary is written to the **Actions run summary** after every push.

---

## Quickstart — add to any Python project in 5 minutes

Create `.github/workflows/security-scan.yml` in your repository:

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    uses: ananthu3212/shift-left-security-thesis/.github/workflows/security-scan-reusable.yml@main
    with:
      docker-image-name: my-app:latest
```

That is the minimum configuration. Push this file and the pipeline
runs automatically on the next commit.

---

## All available inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `docker-image-name` | Yes | — | Docker image name to build and scan |
| `semgrep-config` | No | `p/python` | Semgrep ruleset to apply |
| `custom-rules-path` | No | `""` | Path to custom Semgrep rules directory |
| `trivy-severity` | No | `HIGH,CRITICAL` | Severity levels to report and block on |
| `fail-on-findings` | No | `true` | Block pipeline when findings are detected |

---

## Full configuration example

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    uses: ananthu3212/shift-left-security-thesis/.github/workflows/security-scan-reusable.yml@main
    with:
      docker-image-name: my-flask-app:latest
      semgrep-config: p/python
      custom-rules-path: rules/
      trivy-severity: HIGH,CRITICAL
      fail-on-findings: true
```

---

## Adding custom Semgrep rules

Custom rules let you detect vulnerability patterns specific to your
codebase that community rulesets miss. Create a `rules/` directory
in your project root and add `.yaml` rule files:

```
my-project/
├── rules/
│   ├── sql-injection.yaml
│   ├── open-redirect.yaml
│   └── debug-mode.yaml
├── app.py
└── requirements.txt
```

Then pass the directory path via `custom-rules-path: rules/`.

See the [Semgrep rule syntax documentation](https://semgrep.dev/docs/writing-rules/rule-syntax/)
for how to write custom rules. The seven custom rules written for
this thesis (in the `rules/` directory) can be used as examples.

---

## Audit-only mode

Set `fail-on-findings: false` to run the pipeline in audit mode.
All findings are still reported and uploaded to the Security tab,
but the pipeline does not block deployment. This is useful when
first adopting the pipeline on an existing codebase with known
technical debt.

```yaml
jobs:
  security:
    uses: ananthu3212/shift-left-security-thesis/.github/workflows/security-scan-reusable.yml@main
    with:
      docker-image-name: my-app:latest
      fail-on-findings: false
```

---

## Supported languages

The pipeline is designed for Python projects but Semgrep supports
many languages. Change the `semgrep-config` input to target a
different language:

| Language | Config |
|---|---|
| Python | `p/python` |
| JavaScript / TypeScript | `p/javascript` |
| Java | `p/java` |
| Go | `p/golang` |
| PHP | `p/php` |
| Multi-language | `p/security-audit` |

Gitleaks and Trivy are language-agnostic and work for any project.

---

## Outputs

After every run the pipeline produces:

- **GitHub Security tab** — all findings with severity, file, and
  line number, filterable by tool
- **Actions run summary** — vulnerability count table per tool
- **Downloadable artifacts** — raw JSON reports from each tool
  (`gitleaks-report`, `semgrep-report`, `trivy-reports`)

---

## Requirements

- The repository must contain a `Dockerfile` at the root
- GitHub Actions must be enabled for the repository
- The repository must grant `security-events: write` permission
  (automatically inherited from the reusable workflow)

---

## Reference

This reusable workflow was developed as part of the thesis:

> Chandra Babu, A. (2026). *Shift-Left Security in CI/CD Pipelines:
> Design, Implementation and Indicative Evaluation of SAST, SCA and
> Secret Scanning Using a Containerised Flask Web Application on
> AWS ECS Fargate*. Bachelor's thesis, Westfälische Hochschule
> Gelsenkirchen.

Source: [github.com/ananthu3212/shift-left-security-thesis](https://github.com/ananthu3212/shift-left-security-thesis)