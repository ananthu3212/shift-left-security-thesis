#!/usr/bin/env python3
"""
generate_generic_report.py — Generic Security Findings Dashboard

Works for ANY project. No hardcoded ground truth required.
Reads Gitleaks, Semgrep, Trivy, tfsec and OWASP ZAP JSON reports
and generates a findings dashboard showing severity breakdown,
tool results, and OWASP Top 10 coverage.

This script is part of the reusable pipeline and is called
automatically after every scan. No configuration needed.

Thesis: Shift-Left Security in CI/CD Pipelines
Author: Ananthu Chandra Babu
University: Westfälische Hochschule Gelsenkirchen, 2026
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ================================================================
# CWE → OWASP Top 10 2021 mapping
# ================================================================
CWE_TO_OWASP = {
    "CWE-89":  "A03:2021 - Injection",
    "CWE-78":  "A03:2021 - Injection",
    "CWE-79":  "A03:2021 - Injection",
    "CWE-94":  "A03:2021 - Injection",
    "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-22":  "A01:2021 - Broken Access Control",
    "CWE-601": "A01:2021 - Broken Access Control",
    "CWE-284": "A01:2021 - Broken Access Control",
    "CWE-200": "A02:2021 - Cryptographic Failures",
    "CWE-798": "A02:2021 - Cryptographic Failures",
    "CWE-312": "A02:2021 - Cryptographic Failures",
    "CWE-16":  "A05:2021 - Security Misconfiguration",
    "CWE-614": "A05:2021 - Security Misconfiguration",
    "CWE-400": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-1035":"A06:2021 - Vulnerable and Outdated Components",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def parse_semgrep(data):
    if not data:
        return []
    findings = []
    for r in data.get("results", []):
        rule_id = r.get("check_id", "")
        severity = r.get("extra", {}).get("severity", "ERROR").upper()
        metadata = r.get("extra", {}).get("metadata", {})
        cwe = ""
        if isinstance(metadata.get("cwe"), list):
            cwe = metadata["cwe"][0] if metadata["cwe"] else ""
        elif isinstance(metadata.get("cwe"), str):
            cwe = metadata["cwe"]
        owasp = CWE_TO_OWASP.get(cwe.split(":")[0] if ":" in cwe else cwe, "")
        if not owasp:
            owasp_meta = metadata.get("owasp", "")
            if isinstance(owasp_meta, list):
                owasp = owasp_meta[0] if owasp_meta else "Uncategorised"
            else:
                owasp = owasp_meta or "Uncategorised"
        findings.append({
            "rule": rule_id.split(".")[-1],
            "rule_full": rule_id,
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", ""),
            "severity": severity,
            "message": r.get("extra", {}).get("message", "")[:120],
            "cwe": cwe,
            "owasp": owasp,
            "ruleset": "custom" if (
                rule_id.startswith("rules.") or
                rule_id.startswith("thesis-custom-rules.")
            ) else "default",
        })
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 4))
    return findings


def parse_gitleaks(data):
    if not data:
        return []
    findings = []
    for r in data:
        findings.append({
            "rule": r.get("RuleID") or r.get("ruleId") or "unknown",
            "file": r.get("File") or r.get("file") or "",
            "line": r.get("StartLine") or r.get("startLine") or "",
            "commit": (r.get("Commit") or r.get("commit") or "")[:7],
            "secret": "[REDACTED]",
        })
    return findings


def parse_trivy(data):
    if not data:
        return []
    cves = []
    for result in data.get("Results", []):
        for vuln in (result.get("Vulnerabilities") or []):
            cves.append({
                "id": vuln.get("VulnerabilityID", ""),
                "package": vuln.get("PkgName", ""),
                "installed": vuln.get("InstalledVersion", ""),
                "fixed": vuln.get("FixedVersion", "—"),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "title": (vuln.get("Title") or "")[:80],
            })
    cves.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 4))
    return cves


def parse_tfsec(data):
    if not data:
        return []
    findings = []
    for r in (data.get("results") or []):
        findings.append({
            "rule": r.get("rule_id") or r.get("long_id") or "",
            "severity": r.get("severity", "UNKNOWN").upper(),
            "description": (r.get("description") or "")[:100],
            "resource": r.get("location", {}).get("filename", "").replace(
                "/home/runner/work/shift-left-security-thesis/shift-left-security-thesis/", ""
            ),
            "resolution": (r.get("resolution") or "")[:100],
        })
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 4))
    return findings


def parse_zap(data):
    """Parse OWASP ZAP JSON report and return list of alerts sorted by risk."""
    if not data:
        return []
    risk_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFORMATIONAL"}
    alerts = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk_code = str(alert.get("riskcode", "0"))
            alerts.append({
                "name": alert.get("name", alert.get("alert", "")),
                "risk": risk_map.get(risk_code, "INFORMATIONAL"),
                "risk_code": int(risk_code),
                "count": int(alert.get("count", "1")),
                "cwe": alert.get("cweid", "—"),
                "plugin_id": alert.get("pluginid", ""),
                "solution": (alert.get("solution", "") or "")[:200],
            })
    alerts.sort(key=lambda x: x["risk_code"], reverse=True)
    return alerts


def severity_counts(items, key="severity"):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in items:
        sev = item.get(key, "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def generate_html(semgrep_findings, gitleaks_findings, trivy_cves,
                  tfsec_findings, zap_findings,
                  commit_sha, run_number, repo_name):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_findings = (len(semgrep_findings) + len(gitleaks_findings) +
                      len(trivy_cves) + len(tfsec_findings))
    blocked = total_findings > 0
    status_color = "#dc3545" if blocked else "#198754"

    trivy_counts = severity_counts(trivy_cves)
    tfsec_counts = severity_counts(tfsec_findings)

    semgrep_counts = {"ERROR": 0, "WARNING": 0}
    for f in semgrep_findings:
        sev = f["severity"]
        if sev in semgrep_counts:
            semgrep_counts[sev] += 1
        else:
            semgrep_counts["ERROR"] += 1

    # OWASP breakdown from Semgrep
    owasp_map = {}
    for f in semgrep_findings:
        cat = f["owasp"] or "Uncategorised"
        owasp_map[cat] = owasp_map.get(cat, 0) + 1
    owasp_labels = json.dumps(list(owasp_map.keys()))
    owasp_values = json.dumps(list(owasp_map.values()))

    # Severity chart data (Trivy)
    sev_labels = json.dumps(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    sev_values = json.dumps([
        trivy_counts["CRITICAL"],
        trivy_counts["HIGH"],
        trivy_counts["MEDIUM"],
        trivy_counts["LOW"],
    ])

    # Custom vs default
    custom_count = sum(1 for f in semgrep_findings if f["ruleset"] == "custom")
    default_count = sum(1 for f in semgrep_findings if f["ruleset"] == "default")

    # ZAP counts
    zap_total  = len(zap_findings)
    zap_high   = sum(1 for a in zap_findings if a["risk"] == "HIGH")
    zap_medium = sum(1 for a in zap_findings if a["risk"] == "MEDIUM")
    zap_low    = sum(1 for a in zap_findings if a["risk"] == "LOW")
    zap_info   = sum(1 for a in zap_findings if a["risk"] == "INFORMATIONAL")

    # Semgrep rows
    semgrep_rows = ""
    for f in semgrep_findings:
        sev_color = "danger" if f["severity"] == "ERROR" else "warning"
        ruleset_badge = (
            '<span class="badge bg-warning text-dark ms-1">custom</span>'
            if f["ruleset"] == "custom"
            else '<span class="badge bg-secondary ms-1">default</span>'
        )
        semgrep_rows += f"""
        <tr>
            <td><code>{f["rule"]}</code>{ruleset_badge}</td>
            <td><code>{f["file"]}</code></td>
            <td>{f["line"]}</td>
            <td><span class="badge bg-{sev_color}">{f["severity"]}</span></td>
            <td><span class="badge bg-secondary">{f["owasp"][:35] if f["owasp"] else "—"}</span></td>
            <td><small class="text-muted">{f["message"]}</small></td>
        </tr>"""
    if not semgrep_rows:
        semgrep_rows = '<tr><td colspan="6" class="text-center text-muted">No findings</td></tr>'

    # Gitleaks rows
    gitleaks_rows = ""
    for f in gitleaks_findings:
        gitleaks_rows += f"""
        <tr>
            <td><code>{f["rule"]}</code></td>
            <td><code>{f["file"]}</code></td>
            <td>{f["line"]}</td>
            <td>{f["commit"]}</td>
            <td><span class="badge bg-dark">{f["secret"]}</span></td>
        </tr>"""
    if not gitleaks_rows:
        gitleaks_rows = '<tr><td colspan="5" class="text-center text-muted">No secrets detected</td></tr>'

    # Trivy rows
    trivy_rows = ""
    for c in trivy_cves[:50]:
        sev_color = {
            "CRITICAL": "danger",
            "HIGH": "warning",
            "MEDIUM": "info",
            "LOW": "secondary"
        }.get(c["severity"], "secondary")
        trivy_rows += f"""
        <tr>
            <td><code>{c["id"]}</code></td>
            <td>{c["package"]}</td>
            <td>{c["installed"]}</td>
            <td>{c["fixed"]}</td>
            <td><span class="badge bg-{sev_color}">{c["severity"]}</span></td>
            <td><small>{c["title"]}</small></td>
        </tr>"""
    if not trivy_rows:
        trivy_rows = '<tr><td colspan="6" class="text-center text-muted">No CVEs detected</td></tr>'
    remaining = len(trivy_cves) - 50
    trivy_note = (f'<p class="text-muted small mt-2">Showing top 50 of {len(trivy_cves)} '
                  f'total CVEs ordered by severity.</p>') if remaining > 0 else ""

    # tfsec rows
    tfsec_rows = ""
    for f in tfsec_findings:
        sev_color = {
            "CRITICAL": "danger",
            "HIGH": "warning",
            "MEDIUM": "info",
            "LOW": "secondary"
        }.get(f["severity"], "secondary")
        tfsec_rows += f"""
        <tr>
            <td><code>{f["rule"]}</code></td>
            <td><code>{f["resource"]}</code></td>
            <td><span class="badge bg-{sev_color}">{f["severity"]}</span></td>
            <td><small>{f["description"]}</small></td>
            <td><small class="text-muted">{f["resolution"]}</small></td>
        </tr>"""
    if not tfsec_rows:
        tfsec_rows = '<tr><td colspan="5" class="text-center text-muted">No IaC findings detected</td></tr>'

    # ZAP rows
    zap_rows = ""
    if zap_findings:
        for a in zap_findings:
            risk_color = (
                "danger"    if a["risk"] == "HIGH"          else
                "warning"   if a["risk"] == "MEDIUM"        else
                "info"      if a["risk"] == "LOW"           else
                "secondary"
            )
            zap_rows += f"""
        <tr>
            <td><span class="badge bg-{risk_color}">{a["risk"]}</span></td>
            <td>{a["name"]}</td>
            <td><span class="badge bg-dark">CWE-{a["cwe"]}</span></td>
            <td>{a["count"]}</td>
            <td><small class="text-muted">{a["solution"][:150]}</small></td>
        </tr>"""
    else:
        zap_rows = '<tr><td colspan="5" class="text-center text-muted">DAST not enabled — set enable-dast: true in your workflow to activate ZAP scanning</td></tr>'

    # ZAP section — show only when DAST was enabled
    zap_section = f"""
  <h5 class="section-title">🔒 DAST Results (OWASP ZAP 2.17.0)</h5>
  <div class="row g-3 mb-3">
    <div class="col-md-3">
      <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center;">
        <div style="font-size:1.8rem;font-weight:700;color:#f85149;">{zap_high}</div>
        <div style="font-size:0.85rem;color:#8b949e;">🔴 High Risk</div>
      </div>
    </div>
    <div class="col-md-3">
      <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center;">
        <div style="font-size:1.8rem;font-weight:700;color:#e3b341;">{zap_medium}</div>
        <div style="font-size:0.85rem;color:#8b949e;">🟡 Medium Risk</div>
      </div>
    </div>
    <div class="col-md-3">
      <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center;">
        <div style="font-size:1.8rem;font-weight:700;color:#388bfd;">{zap_low}</div>
        <div style="font-size:0.85rem;color:#8b949e;">🔵 Low Risk</div>
      </div>
    </div>
    <div class="col-md-3">
      <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center;">
        <div style="font-size:1.8rem;font-weight:700;color:#8b949e;">{zap_info}</div>
        <div style="font-size:0.85rem;color:#8b949e;">ℹ️ Informational</div>
      </div>
    </div>
  </div>
  <div class="table-responsive mb-4">
    <table class="table table-bordered">
      <thead><tr>
        <th>Risk</th><th>Alert</th><th>CWE</th><th>Instances</th><th>Solution</th>
      </tr></thead>
      <tbody>{zap_rows}</tbody>
    </table>
  </div>"""

    # ZAP metric card — shown always
    zap_metric_card = f"""
  <div class="row g-3 mb-4">
    <div class="col-md-3">
      <div class="metric-card">
        <div class="metric-value" style="color:#a371f7">{zap_total}</div>
        <div class="metric-label">🔒 DAST Alerts (ZAP)</div>
        <div class="mt-2">
          <small class="text-danger">{zap_high} High</small> &nbsp;
          <small class="text-warning">{zap_medium} Medium</small> &nbsp;
          <small class="text-info">{zap_low} Low</small>
        </div>
      </div>
    </div>
    <div class="col-md-9">
      <div class="metric-card" style="text-align:left;">
        <small class="text-muted">
          {"<strong style='color:#a371f7'>DAST scan completed.</strong> ZAP performed a baseline scan against the running application via HTTP. Dynamic analysis complements static tools by detecting runtime security issues such as missing security headers and CORS misconfigurations." if zap_findings else "<strong style='color:#8b949e'>DAST not enabled.</strong> Add <code>enable-dast: true</code>, <code>app-start-command</code>, and <code>app-port</code> to your workflow to activate OWASP ZAP dynamic scanning."}
        </small>
      </div>
    </div>
  </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Scan Report — {repo_name}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; }}
  .metric-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; text-align: center; }}
  .metric-value {{ font-size: 2.2rem; font-weight: 700; }}
  .metric-label {{ font-size: 0.85rem; color: #8b949e; margin-top: 0.3rem; }}
  .section-title {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; margin-bottom: 1.5rem; margin-top: 2rem; }}
  .table {{ --bs-table-bg: #161b22; --bs-table-border-color: #30363d; font-size: 0.875rem; }}
  .status-banner {{ border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; background: {status_color}22; border: 2px solid {status_color}; }}
  .chart-container {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; }}
  code {{ color: #79c0ff; }}
  .navbar-brand {{ font-weight: 700; }}
</style>
</head>
<body>

<nav class="navbar navbar-dark" style="background:#161b22;border-bottom:1px solid #30363d;">
  <div class="container">
    <span class="navbar-brand">🛡️ Security Scan Report</span>
    <span class="text-muted small">
      {repo_name} &nbsp;·&nbsp; Run #{run_number} &nbsp;·&nbsp; {commit_sha[:7]} &nbsp;·&nbsp; {ts}
    </span>
  </div>
</nav>

<div class="container mt-4">

  <div class="status-banner">
    <h3 class="mb-1" style="color:{status_color}">
      {"❌ Pipeline BLOCKED — findings detected" if blocked else "✅ Pipeline PASSED — no findings detected"}
    </h3>
    <p class="mb-0 text-muted">
      <strong style="color:#e6edf3">{len(semgrep_findings)}</strong> SAST findings &nbsp;·&nbsp;
      <strong style="color:#e6edf3">{len(gitleaks_findings)}</strong> secret(s) &nbsp;·&nbsp;
      <strong style="color:#e6edf3">{len(trivy_cves)}</strong> CVEs &nbsp;·&nbsp;
      <strong style="color:#e6edf3">{len(tfsec_findings)}</strong> IaC finding(s) &nbsp;·&nbsp;
      <strong style="color:#a371f7">{zap_total}</strong> DAST alert(s) &nbsp;·&nbsp;
      <strong style="color:#3fb950">{custom_count}</strong> detected by custom rules
    </p>
  </div>

  <div class="row g-3 mb-3">
    <div class="col-md-3">
      <div class="metric-card">
        <div class="metric-value" style="color:#f85149">{len(semgrep_findings)}</div>
        <div class="metric-label">🔍 Semgrep Findings</div>
        <div class="mt-2">
          <small class="text-danger">{semgrep_counts.get("ERROR",0)} errors</small> &nbsp;
          <small class="text-warning">{semgrep_counts.get("WARNING",0)} warnings</small>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="metric-card">
        <div class="metric-value" style="color:#f85149">{len(gitleaks_findings)}</div>
        <div class="metric-label">🔑 Secrets Detected</div>
        <div class="mt-2"><small class="text-muted">secret values redacted</small></div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="metric-card">
        <div class="metric-value" style="color:#f85149">{len(trivy_cves)}</div>
        <div class="metric-label">📦 CVEs Detected</div>
        <div class="mt-2">
          <small class="text-danger">{trivy_counts["CRITICAL"]} critical</small> &nbsp;
          <small class="text-warning">{trivy_counts["HIGH"]} high</small>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="metric-card">
        <div class="metric-value" style="color:#f85149">{len(tfsec_findings)}</div>
        <div class="metric-label">🏗️ IaC Findings</div>
        <div class="mt-2">
          <small class="text-danger">{tfsec_counts["CRITICAL"]} critical</small> &nbsp;
          <small class="text-warning">{tfsec_counts["HIGH"]} high</small>
        </div>
      </div>
    </div>
  </div>

  {zap_metric_card}

  <div class="row g-4 mb-4">
    <div class="col-md-4">
      <div class="chart-container">
        <h6 class="text-muted mb-3">CVE Severity Distribution (Trivy)</h6>
        <canvas id="sevChart" height="220"></canvas>
      </div>
    </div>
    <div class="col-md-4">
      <div class="chart-container">
        <h6 class="text-muted mb-3">OWASP Top 10 Coverage (Semgrep)</h6>
        <canvas id="owaspChart" height="220"></canvas>
      </div>
    </div>
    <div class="col-md-4">
      <div class="chart-container">
        <h6 class="text-muted mb-3">Custom vs Default Rules</h6>
        <canvas id="rulesetChart" height="220"></canvas>
      </div>
    </div>
  </div>

  <h5 class="section-title">🔍 SAST Findings (Semgrep)</h5>
  <div class="table-responsive mb-4">
    <table class="table table-bordered table-hover">
      <thead><tr>
        <th>Rule</th><th>File</th><th>Line</th>
        <th>Severity</th><th>OWASP</th><th>Message</th>
      </tr></thead>
      <tbody>{semgrep_rows}</tbody>
    </table>
  </div>

  <h5 class="section-title">🔑 Secret Scanning (Gitleaks)</h5>
  <div class="table-responsive mb-4">
    <table class="table table-bordered">
      <thead><tr>
        <th>Rule</th><th>File</th><th>Line</th><th>Commit</th><th>Secret</th>
      </tr></thead>
      <tbody>{gitleaks_rows}</tbody>
    </table>
  </div>

  <h5 class="section-title">📦 CVEs (Trivy)</h5>
  <div class="table-responsive mb-2">
    <table class="table table-bordered">
      <thead><tr>
        <th>CVE</th><th>Package</th><th>Installed</th>
        <th>Fixed In</th><th>Severity</th><th>Title</th>
      </tr></thead>
      <tbody>{trivy_rows}</tbody>
    </table>
  </div>
  {trivy_note}

  <h5 class="section-title">🏗️ IaC Security Findings (tfsec)</h5>
  <p class="text-muted small mb-3">
    Infrastructure-as-code security findings from Terraform source analysis.
    Findings should be reviewed to distinguish genuine misconfigurations from
    intentional design decisions and false positives.
  </p>
  <div class="table-responsive mb-4">
    <table class="table table-bordered">
      <thead><tr>
        <th>Rule</th><th>Resource</th><th>Severity</th>
        <th>Description</th><th>Resolution</th>
      </tr></thead>
      <tbody>{tfsec_rows}</tbody>
    </table>
  </div>

  {zap_section}

  <footer class="text-center text-muted py-4 mt-4"
          style="border-top:1px solid #30363d;font-size:0.8rem;">
    Generated by the Shift-Left Security Pipeline &nbsp;·&nbsp;
    <a href="https://github.com/ananthu3212/shift-left-security-thesis"
       style="color:#58a6ff;">ananthu3212/shift-left-security-thesis</a>
  </footer>

</div>

<script>
new Chart(document.getElementById('sevChart'), {{
  type: 'doughnut',
  data: {{
    labels: {sev_labels},
    datasets: [{{
      data: {sev_values},
      backgroundColor: ['#f8514999','#e3b34199','#388bfd99','#8b949e99'],
      borderColor:     ['#f85149',  '#e3b341',  '#388bfd',  '#8b949e'],
      borderWidth: 2
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ labels: {{ color: '#e6edf3', font: {{ size: 11 }} }} }} }}
  }}
}});

new Chart(document.getElementById('owaspChart'), {{
  type: 'bar',
  data: {{
    labels: {owasp_labels},
    datasets: [{{
      label: 'Findings',
      data: {owasp_values},
      backgroundColor: '#388bfd99',
      borderColor: '#388bfd',
      borderWidth: 1
    }}]
  }},
  options: {{
    indexAxis: 'y',
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ color: '#8b949e', stepSize: 1 }}, grid: {{ color: '#21262d' }} }},
      y: {{ ticks: {{ color: '#8b949e', font: {{ size: 10 }} }}, grid: {{ color: '#21262d' }} }}
    }}
  }}
}});

new Chart(document.getElementById('rulesetChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['Custom Rules', 'Default Ruleset', 'No Findings'],
    datasets: [{{
      data: [{custom_count}, {default_count}, {max(0, 1 if total_findings == 0 else 0)}],
      backgroundColor: ['#3fb95099','#388bfd99','#21262d'],
      borderColor:     ['#3fb950',  '#388bfd',  '#30363d'],
      borderWidth: 2
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ labels: {{ color: '#e6edf3', font: {{ size: 11 }} }} }} }}
  }}
}});
</script>
</body>
</html>"""
    return html


def main():
    base = Path("reports")

    semgrep_path  = base / "semgrep-report" / "semgrep-report.json"
    gitleaks_path = base / "gitleaks-report" / "gitleaks-report.json"
    trivy_fs_path = base / "trivy-reports"   / "trivy-fs-report.json"
    tfsec_path    = base / "tfsec-report"    / "tfsec-report.json"
    zap_path      = base / "zap-report"      / "zap-report.json"

    semgrep_data  = load_json(semgrep_path)  or {"results": []}
    gitleaks_data = load_json(gitleaks_path) or []
    trivy_data    = load_json(trivy_fs_path) or {"Results": []}
    tfsec_data    = load_json(tfsec_path)    or {"results": []}
    zap_data      = load_json(zap_path)      or {}

    commit_sha = os.environ.get("GITHUB_SHA", "local")
    run_number = os.environ.get("GITHUB_RUN_NUMBER", "0")
    repo_name  = os.environ.get("GITHUB_REPOSITORY", "your-project")

    semgrep_findings  = parse_semgrep(semgrep_data)
    gitleaks_findings = parse_gitleaks(gitleaks_data)
    trivy_cves        = parse_trivy(trivy_data)
    tfsec_findings    = parse_tfsec(tfsec_data)
    zap_findings      = parse_zap(zap_data)

    html = generate_html(
        semgrep_findings, gitleaks_findings, trivy_cves,
        tfsec_findings, zap_findings,
        commit_sha, run_number, repo_name
    )

    out_dir = Path("generic-dashboard")
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / "index.html"
    out_file.write_text(html, encoding="utf-8")

    print(f"Generic dashboard generated: {out_file}")
    print(f"Semgrep findings:  {len(semgrep_findings)}")
    print(f"Gitleaks findings: {len(gitleaks_findings)}")
    print(f"Trivy CVEs:        {len(trivy_cves)}")
    print(f"tfsec findings:    {len(tfsec_findings)}")
    print(f"ZAP alerts:        {len(zap_findings)}")


if __name__ == "__main__":
    main()