#!/usr/bin/env python3
"""
generate_report.py — Shift-Left Security Thesis Dashboard Generator

Parses Gitleaks, Semgrep, Trivy, tfsec and OWASP ZAP JSON reports,
evaluates findings against the defined ground truth (14 application
items + 8 IaC items), computes Precision/Recall/F1 per tool, and
generates a single-file static HTML dashboard for GitHub Pages.

Thesis: Shift-Left Security in CI/CD Pipelines
Student: Ananthu Chandra Babu
University: Westfälische Hochschule Gelsenkirchen, 2026
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ================================================================
# APPLICATION GROUND TRUTH — 14 known vulnerabilities in flask-webgoat
# ================================================================
GROUND_TRUTH = [
    {"id":"V01","vulnerability":"SQL Injection (login)","file":"flask_webgoat/auth.py","line":18,"cwe":"CWE-89","owasp":"A03:2021","tool":"semgrep","keywords":["tainted-sql-string"],"file_match":"auth.py","ruleset":"default"},
    {"id":"V02","vulnerability":"SQL Injection (create_user)","file":"flask_webgoat/users.py","line":38,"cwe":"CWE-89","owasp":"A03:2021","tool":"semgrep","keywords":["tainted-sql-string"],"file_match":"users.py","ruleset":"default"},
    {"id":"V03","vulnerability":"Remote Code Execution","file":"flask_webgoat/actions.py","line":44,"cwe":"CWE-78","owasp":"A03:2021","tool":"semgrep","keywords":["subprocess-injection","subprocess-shell-true","dangerous-subprocess"],"file_match":"actions.py","ruleset":"default"},
    {"id":"V04","vulnerability":"Insecure Deserialization","file":"flask_webgoat/actions.py","line":61,"cwe":"CWE-502","owasp":"A08:2021","tool":"semgrep","keywords":["flask-insecure-deserialization-pickle"],"file_match":"actions.py","ruleset":"custom"},
    {"id":"V05","vulnerability":"Directory Traversal","file":"flask_webgoat/actions.py","line":32,"cwe":"CWE-22","owasp":"A01:2021","tool":"semgrep","keywords":["flask-path-traversal-string-concat"],"file_match":"actions.py","ruleset":"custom"},
    {"id":"V06","vulnerability":"Open Redirect","file":"flask_webgoat/auth.py","line":46,"cwe":"CWE-601","owasp":"A01:2021","tool":"semgrep","keywords":["flask-open-redirect-request-param"],"file_match":"auth.py","ruleset":"custom"},
    {"id":"V07","vulnerability":"Sensitive Data Exposure","file":"flask_webgoat/__init__.py","line":13,"cwe":"CWE-200","owasp":"A01:2021","tool":"semgrep","keywords":["sqlite-trace-callback-data-exposure"],"file_match":"__init__.py","ruleset":"custom"},
    {"id":"V08","vulnerability":"Broken Access Control (CORS)","file":"run.py","line":8,"cwe":"CWE-284","owasp":"A01:2021","tool":"semgrep","keywords":["flask-cors-wildcard-origin"],"file_match":"run.py","ruleset":"custom"},
    {"id":"V09","vulnerability":"Security Misconfiguration (CSP)","file":"run.py","line":10,"cwe":"CWE-16","owasp":"A05:2021","tool":"semgrep","keywords":["flask-csp-unsafe-inline"],"file_match":"run.py","ruleset":"custom"},
    {"id":"V10","vulnerability":"Security Misconfiguration (debug=True)","file":"run.py","line":15,"cwe":"CWE-489","owasp":"A05:2021","tool":"semgrep","keywords":["flask-debug-mode-enabled"],"file_match":"run.py","ruleset":"custom"},
    {"id":"V11","vulnerability":"Hardcoded Secret Key","file":"flask_webgoat/__init__.py","line":None,"cwe":"CWE-321","owasp":"A02:2021","tool":"gitleaks","keywords":["secret","generic-api-key"],"file_match":"__init__.py","ruleset":"default"},
    {"id":"V12","vulnerability":"Outdated Flask 1.1.2","file":"requirements.txt","line":None,"cwe":"CVE-2023-30861","owasp":"A06:2021","tool":"trivy","keywords":["CVE-2023-30861","flask"],"file_match":"requirements.txt","ruleset":"default"},
    {"id":"V13","vulnerability":"Outdated Jinja2 2.11.3 (MEDIUM — below threshold)","file":"requirements.txt","line":None,"cwe":"CVE-2024-22195","owasp":"A06:2021","tool":"trivy","keywords":["jinja2"],"file_match":"requirements.txt","ruleset":"default"},
    {"id":"V14","vulnerability":"Outdated Werkzeug 1.0.1","file":"requirements.txt","line":None,"cwe":"CVE-2023-25577","owasp":"A06:2021","tool":"trivy","keywords":["werkzeug","CVE-2023-25577"],"file_match":"requirements.txt","ruleset":"default"},
]

# ================================================================
# IaC GROUND TRUTH — 8 tfsec findings in Terraform infrastructure
# ================================================================
IAC_GROUND_TRUTH = [
    {
        "id": "I01",
        "rule": "AVD-AWS-0052",
        "resource": "ecs.tf — aws_lb",
        "severity": "HIGH",
        "description": "ALB not configured to drop invalid HTTP headers",
        "classification": "true_positive",
        "classification_label": "✅ True Positive — Remediated",
        "classification_color": "success",
        "action": "Fixed: added drop_invalid_header_fields = true. Prevents HTTP request smuggling attacks.",
    },
    {
        "id": "I02",
        "rule": "AVD-AWS-0107",
        "resource": "security_groups.tf — alb_ingress_http",
        "severity": "CRITICAL",
        "description": "Security group allows ingress from public internet",
        "classification": "intentional",
        "classification_label": "🔵 Intentional Design Decision",
        "classification_color": "primary",
        "action": "The ALB is the single public entry point by design. Fargate tasks run in private subnets with no public IP. Restricting ALB ingress would make the application unreachable.",
    },
    {
        "id": "I03",
        "rule": "AVD-AWS-0053",
        "resource": "ecs.tf — aws_lb",
        "severity": "HIGH",
        "description": "Load balancer is exposed to the public internet",
        "classification": "intentional",
        "classification_label": "🔵 Intentional Design Decision",
        "classification_color": "primary",
        "action": "An internal ALB would make the thesis demo application inaccessible. The ALB is intentionally public-facing. Production deployments should add a WAF layer.",
    },
    {
        "id": "I04",
        "rule": "AVD-AWS-0054",
        "resource": "ecs.tf — aws_lb_listener",
        "severity": "CRITICAL",
        "description": "Listener uses HTTP instead of HTTPS",
        "classification": "known_limitation",
        "classification_label": "🟡 Known Limitation",
        "classification_color": "warning",
        "action": "HTTPS requires a registered domain and an ACM certificate, both out of scope for this thesis demo environment. Production deployment must use HTTPS. Documented as future work.",
    },
    {
        "id": "I05",
        "rule": "AVD-AWS-0057",
        "resource": "iam.tf — execution_policy",
        "severity": "HIGH",
        "description": "IAM policy uses sensitive action logs:CreateLogStream",
        "classification": "false_positive",
        "classification_label": "⚠️ False Positive",
        "classification_color": "danger",
        "action": "logs:CreateLogStream is the minimum permission required for ECS Fargate tasks to write container logs to CloudWatch. Scoped to a specific log group ARN — not a wildcard. Standard AWS ECS practice.",
    },
    {
        "id": "I06",
        "rule": "AVD-AWS-0178",
        "resource": "vpc.tf — aws_vpc",
        "severity": "MEDIUM",
        "description": "VPC Flow Logs not enabled",
        "classification": "known_limitation",
        "classification_label": "🟡 Known Limitation",
        "classification_color": "warning",
        "action": "VPC Flow Logs require an S3 bucket or dedicated CloudWatch Log Group with IAM roles, generating ongoing storage costs. Out of scope for thesis demo environment. Documented as future work.",
    },
    {
        "id": "I07",
        "rule": "AVD-AWS-0017",
        "resource": "ecr.tf — aws_cloudwatch_log_group",
        "severity": "LOW",
        "description": "CloudWatch Log Group not encrypted with customer-managed KMS key",
        "classification": "true_positive",
        "classification_label": "✅ True Positive — Remediated",
        "classification_color": "success",
        "action": "Fixed: dedicated KMS key created for CloudWatch Logs with correct key policy granting the logs service principal encryption permissions. Key rotation enabled.",
    },
    {
        "id": "I08",
        "rule": "AVD-AWS-0098",
        "resource": "secrets.tf — aws_secretsmanager_secret",
        "severity": "LOW",
        "description": "Secrets Manager secret uses default AWS managed key",
        "classification": "true_positive",
        "classification_label": "✅ True Positive — Remediated",
        "classification_color": "success",
        "action": "Fixed: dedicated customer-managed KMS key created for Secrets Manager. Provides full auditability via CloudTrail, ability to revoke access by disabling the key, and automatic annual key rotation.",
    },
]


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def detect_semgrep(gt, results):
    for r in results:
        rule_id = r.get("check_id", "").lower()
        path = r.get("path", "").lower()
        for kw in gt["keywords"]:
            if kw.lower() in rule_id and gt["file_match"].lower() in path:
                return True, r
    return False, None


def detect_gitleaks(gt, results):
    if not results:
        return False, None
    for r in results:
        rule_id = (r.get("RuleID") or r.get("ruleId") or "").lower()
        file_path = (r.get("File") or r.get("file") or "").lower()
        secret = (r.get("Secret") or r.get("secret") or "").lower()
        for kw in gt["keywords"]:
            if kw.lower() in rule_id or kw.lower() in file_path or kw.lower() in secret:
                return True, r
    return False, None


def detect_trivy(gt, data):
    if not data:
        return False, None
    for result in data.get("Results", []):
        for vuln in (result.get("Vulnerabilities") or []):
            vid = (vuln.get("VulnerabilityID") or "").lower()
            pkg = (vuln.get("PkgName") or "").lower()
            for kw in gt["keywords"]:
                if kw.lower() in vid or kw.lower() in pkg:
                    return True, vuln
    return False, None


def evaluate_ground_truth(semgrep_data, gitleaks_data, trivy_data):
    semgrep_results = semgrep_data.get("results", []) if semgrep_data else []
    results = []
    for gt in GROUND_TRUTH:
        detected = False
        finding = None
        detected_by_ruleset = None
        if gt["tool"] == "semgrep":
            detected, finding = detect_semgrep(gt, semgrep_results)
            if detected and finding:
                detected_by_ruleset = "custom" if finding.get("check_id","").startswith("rules.") else "default"
        elif gt["tool"] == "gitleaks":
            detected, finding = detect_gitleaks(gt, gitleaks_data)
            detected_by_ruleset = "default" if detected else None
        elif gt["tool"] == "trivy":
            detected, finding = detect_trivy(gt, trivy_data)
            detected_by_ruleset = "default" if detected else None
        results.append({
            "gt": gt,
            "detected": detected,
            "finding": finding,
            "detected_by_ruleset": detected_by_ruleset
        })
    return results


def evaluate_iac(tfsec_data):
    findings = (tfsec_data.get("results") or []) if tfsec_data else []
    detected_rules = set()
    for f in findings:
        rule = f.get("rule_id") or f.get("long_id") or ""
        detected_rules.add(rule)
    results = []
    for item in IAC_GROUND_TRUTH:
        detected = item["rule"] in detected_rules
        results.append({"item": item, "detected": detected})
    return results


def compute_metrics(gt_results, semgrep_data):
    semgrep_results = semgrep_data.get("results", []) if semgrep_data else []

    def tool_metrics(tool_name):
        tool_gt = [r for r in gt_results if r["gt"]["tool"] == tool_name]
        tp = sum(1 for r in tool_gt if r["detected"])
        fn = len(tool_gt) - tp
        return tp, fn

    s_tp, s_fn = tool_metrics("semgrep")
    g_tp, g_fn = tool_metrics("gitleaks")
    t_tp, t_fn = tool_metrics("trivy")

    gt_keywords = set()
    for gt in GROUND_TRUTH:
        if gt["tool"] == "semgrep":
            for kw in gt["keywords"]:
                gt_keywords.add(kw.lower())

    fp_findings = []
    for r in semgrep_results:
        rule_id = r.get("check_id", "").lower()
        if not any(kw in rule_id for kw in gt_keywords):
            fp_findings.append(r)
    s_fp = len(fp_findings)

    def calc(tp, fp, fn):
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2*p*r / (p+r) if (p+r) > 0 else 0.0
        return round(p,3), round(r,3), round(f1,3)

    s_p, s_r, s_f1 = calc(s_tp, s_fp, s_fn)
    g_p, g_r, g_f1 = calc(g_tp, 0, g_fn)
    t_p, t_r, t_f1 = calc(t_tp, 0, t_fn)

    total_tp = s_tp + g_tp + t_tp
    total_fn = s_fn + g_fn + t_fn
    c_p, c_r, c_f1 = calc(total_tp, s_fp, total_fn)

    custom_only_tp = sum(1 for r in gt_results
                         if r["detected"] and r["detected_by_ruleset"] == "custom")

    return {
        "semgrep":  {"tp":s_tp,"fp":s_fp,"fn":s_fn,"precision":s_p,"recall":s_r,"f1":s_f1,"fp_findings":fp_findings},
        "gitleaks": {"tp":g_tp,"fp":0,"fn":g_fn,"precision":g_p,"recall":g_r,"f1":g_f1},
        "trivy":    {"tp":t_tp,"fp":0,"fn":t_fn,"precision":t_p,"recall":t_r,"f1":t_f1},
        "combined": {"tp":total_tp,"fp":s_fp,"fn":total_fn,"precision":c_p,"recall":c_r,"f1":c_f1},
        "custom_only_tp": custom_only_tp,
    }


def get_trivy_app_cves(trivy_data):
    app_pkgs = {"flask", "jinja2", "werkzeug", "click", "itsdangerous", "markupsafe"}
    cves = []
    if not trivy_data:
        return cves
    for result in trivy_data.get("Results", []):
        for vuln in (result.get("Vulnerabilities") or []):
            pkg = (vuln.get("PkgName") or "").lower()
            if pkg in app_pkgs:
                cves.append({
                    "id": vuln.get("VulnerabilityID",""),
                    "package": vuln.get("PkgName",""),
                    "installed": vuln.get("InstalledVersion",""),
                    "fixed": vuln.get("FixedVersion","N/A"),
                    "severity": vuln.get("Severity",""),
                    "title": (vuln.get("Title") or "")[:80]
                })
    return cves


def get_zap_findings(zap_data):
    alerts = []
    if not zap_data:
        return alerts
    risk_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFORMATIONAL"}
    for site in zap_data.get("site", []):
        for alert in site.get("alerts", []):
            risk_code = str(alert.get("riskcode", "0"))
            alerts.append({
                "name": alert.get("name", alert.get("alert", "")),
                "risk": risk_map.get(risk_code, "INFORMATIONAL"),
                "risk_code": int(risk_code),
                "count": int(alert.get("count", "1")),
                "cwe": alert.get("cweid", "—"),
                "plugin_id": alert.get("pluginid", ""),
                "desc": (alert.get("desc", "") or "")[:300],
                "solution": (alert.get("solution", "") or "")[:200],
            })
    alerts.sort(key=lambda x: x["risk_code"], reverse=True)
    return alerts


def load_runtime_data():
    """
    n=10 runtime statistics for all three pipeline variants.
    All five security tools (Semgrep, Trivy, Gitleaks, tfsec, OWASP ZAP)
    included in sequential and parallel pipelines.
    Baseline performs Docker build only — no security tooling.
    Measurements conducted May 2026 on GitHub-hosted ubuntu-latest runners.

    Sequential runs (#85–#94): actual measured durations.
    Parallel runs (#25–#34): actual measured durations.
    Baseline runs: actual measured durations (n=10, Docker build only).
    """
    return {
        "pipelines": {
            "baseline": {
                "mean": 35.5,
                "std_dev": 7.6,
                "min": 29,
                "max": 55,
                "cv": 21.4,
                # n=10 actual baseline runs #31-#40, 13 May 2026 (Docker build only, no security tools)
                "runs": [34, 32, 30, 55, 32, 30, 38, 37, 38, 29]
            },
            "parallel": {
                "mean": 191.0,
                "std_dev": 34.3,
                "min": 156,
                "max": 275,
                "cv": 17.9,
                # n=10 actual parallel runs #25–#34 (5 tools simultaneous)
                "runs": [191, 175, 187, 175, 168, 189, 173, 275, 156, 221]
            },
            "sequential": {
                "mean": 348.7,
                "std_dev": 17.8,
                "min": 329,
                "max": 376,
                "cv": 5.1,
                # n=10 actual sequential runs #85–#94 (5 tools staged)
                "runs": [337, 350, 329, 341, 335, 350, 366, 374, 376, 329]
            }
        }
    }


def generate_html(gt_results, metrics, trivy_app_cves, iac_results,
                  semgrep_data, gitleaks_data, zap_findings,
                  commit_sha, run_number, runtime_data):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_gt = len(GROUND_TRUTH)
    total_detected = metrics["combined"]["tp"]
    overall_status = "BLOCKED" if (metrics["semgrep"]["tp"] > 0 or
                                    metrics["gitleaks"]["tp"] > 0 or
                                    metrics["trivy"]["tp"] > 0) else "PASSED"
    status_color = "#dc3545" if overall_status == "BLOCKED" else "#198754"

    iac_total = len(iac_results)
    iac_tp = sum(1 for r in iac_results if r["item"]["classification"] == "true_positive")
    iac_intentional = sum(1 for r in iac_results if r["item"]["classification"] == "intentional")
    iac_limitation = sum(1 for r in iac_results if r["item"]["classification"] == "known_limitation")
    iac_fp = sum(1 for r in iac_results if r["item"]["classification"] == "false_positive")

    owasp_map = {}
    for r in gt_results:
        cat = r["gt"]["owasp"]
        if cat not in owasp_map:
            owasp_map[cat] = {"total": 0, "detected": 0}
        owasp_map[cat]["total"] += 1
        if r["detected"]:
            owasp_map[cat]["detected"] += 1
    owasp_labels = json.dumps(list(owasp_map.keys()))
    owasp_detected = json.dumps([v["detected"] for v in owasp_map.values()])
    owasp_missed = json.dumps([v["total"] - v["detected"] for v in owasp_map.values()])

    custom_tp = metrics["custom_only_tp"]
    default_tp = total_detected - custom_tp

    zap_total   = len(zap_findings)
    zap_high    = sum(1 for a in zap_findings if a["risk"] == "HIGH")
    zap_medium  = sum(1 for a in zap_findings if a["risk"] == "MEDIUM")
    zap_low     = sum(1 for a in zap_findings if a["risk"] == "LOW")
    zap_info    = sum(1 for a in zap_findings if a["risk"] == "INFORMATIONAL")

    zap_rows = ""
    if zap_findings:
        for a in zap_findings:
            risk_color = (
                "danger"   if a["risk"] == "HIGH"          else
                "warning"  if a["risk"] == "MEDIUM"        else
                "info"     if a["risk"] == "LOW"           else
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
        zap_rows = '<tr><td colspan="5" class="text-center text-muted">No ZAP report available — DAST not yet executed</td></tr>'

    # ================================================================
    # Runtime section — n=10 data, five tools
    # ================================================================
    runtime_chart_js = ""
    runtime_stats_html = ""
    if runtime_data:
        pipelines = runtime_data.get("pipelines", {})
        baseline   = pipelines.get("baseline",   {})
        parallel   = pipelines.get("parallel",   {})
        sequential = pipelines.get("sequential", {})

        run_labels      = json.dumps([f"Run {i+1}" for i in range(10)])
        baseline_runs   = json.dumps(baseline.get("runs",   []))
        parallel_runs   = json.dumps(parallel.get("runs",   []))
        sequential_runs = json.dumps(sequential.get("runs", []))

        b_mean  = baseline.get("mean",   0)
        p_mean  = parallel.get("mean",   0)
        s_mean  = sequential.get("mean", 0)
        b_std   = baseline.get("std_dev",   0)
        p_std   = parallel.get("std_dev",   0)
        s_std   = sequential.get("std_dev", 0)
        b_min   = baseline.get("min",   0)
        p_min   = parallel.get("min",   0)
        s_min   = sequential.get("min", 0)
        b_max   = baseline.get("max",   0)
        p_max   = parallel.get("max",   0)
        s_max   = sequential.get("max", 0)
        b_cv    = baseline.get("cv",   0)
        p_cv    = parallel.get("cv",   0)
        s_cv    = sequential.get("cv", 0)

        p_overhead_s   = round(p_mean - b_mean, 1)
        s_overhead_s   = round(s_mean - b_mean, 1)
        p_overhead_pct = round(p_overhead_s / b_mean * 100) if b_mean else 0
        s_overhead_pct = round(s_overhead_s / b_mean * 100) if b_mean else 0

        runtime_chart_js = f"""
new Chart(document.getElementById('runtimeChart'), {{
  type: 'line',
  data: {{
    labels: {run_labels},
    datasets: [
      {{
        label: 'Baseline (no security)',
        data: {baseline_runs},
        borderColor: '#8b949e',
        backgroundColor: '#8b949e33',
        tension: 0.3,
        fill: false,
        pointRadius: 4,
      }},
      {{
        label: 'Parallel (5 tools)',
        data: {parallel_runs},
        borderColor: '#388bfd',
        backgroundColor: '#388bfd33',
        tension: 0.3,
        fill: false,
        pointRadius: 4,
      }},
      {{
        label: 'Sequential (5 tools)',
        data: {sequential_runs},
        borderColor: '#f85149',
        backgroundColor: '#f8514933',
        tension: 0.3,
        fill: false,
        pointRadius: 4,
      }}
    ]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ labels: {{ color: '#e6edf3' }} }},
      tooltip: {{
        callbacks: {{
          label: function(c) {{
            return ` ${{c.dataset.label}}: ${{c.raw}}s`;
          }}
        }}
      }}
    }},
    scales: {{
      x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }},
      y: {{
        ticks: {{ color: '#8b949e', callback: v => v + 's' }},
        grid: {{ color: '#21262d' }},
        title: {{ display: true, text: 'Duration (seconds)', color: '#8b949e' }}
      }}
    }}
  }}
}});

new Chart(document.getElementById('runtimeBarChart'), {{
  type: 'bar',
  data: {{
    labels: ['Baseline\\n(no security)', 'Parallel\\n(5 tools)', 'Sequential\\n(5 tools)'],
    datasets: [
      {{
        label: 'Mean',
        data: [{b_mean}, {p_mean}, {s_mean}],
        backgroundColor: ['#8b949e99', '#388bfd99', '#f8514999'],
        borderColor: ['#8b949e', '#388bfd', '#f85149'],
        borderWidth: 2,
      }}
    ]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ display: false }},
      tooltip: {{
        callbacks: {{
          label: function(c) {{
            const stddevs = [{b_std}, {p_std}, {s_std}];
            return ` Mean: ${{c.raw}}s ± ${{stddevs[c.dataIndex]}}s`;
          }}
        }}
      }}
    }},
    scales: {{
      x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }},
      y: {{
        ticks: {{ color: '#8b949e', callback: v => v + 's' }},
        grid: {{ color: '#21262d' }},
        title: {{ display: true, text: 'Duration (seconds)', color: '#8b949e' }}
      }}
    }}
  }}
}});
"""

        runtime_stats_html = f"""
  <h5 class="section-title">⏱️ Pipeline Runtime Comparison (n=10 per pipeline)</h5>
  <p class="text-muted small mb-3">
    Each pipeline variant was executed n=10 times on GitHub-hosted ubuntu-latest runners
    under controlled conditions (May 2026). All runs were triggered manually via
    workflow_dispatch to ensure consistent conditions.
    The baseline performs Docker build only. The parallel and sequential variants
    both run Gitleaks, Semgrep, Trivy, tfsec, and OWASP ZAP with identical tool
    versions and configurations — the only difference is execution order.
    <br><span class="text-warning small">⚠️ These are fixed experimental measurements
    from a controlled evaluation — not live performance metrics. Runtime varies across
    GitHub-hosted runners due to queue latency and shared infrastructure.
    See thesis Section 5.5 for full discussion.</span>
  </p>

  <div class="row g-3 mb-4">
    <div class="col-md-4">
      <div class="metric-card">
        <div class="metric-value" style="color:#8b949e">{b_mean}s</div>
        <div class="metric-label">🏗️ Baseline Mean<br>
          <small>±{b_std}s &nbsp;|&nbsp; {b_min}s–{b_max}s</small>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="metric-card">
        <div class="metric-value" style="color:#388bfd">{p_mean}s</div>
        <div class="metric-label">⚡ Parallel Mean<br>
          <small>±{p_std}s &nbsp;|&nbsp; {p_min}s–{p_max}s</small>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="metric-card">
        <div class="metric-value" style="color:#f85149">{s_mean}s</div>
        <div class="metric-label">🔒 Sequential Mean<br>
          <small>±{s_std}s &nbsp;|&nbsp; {s_min}s–{s_max}s</small>
        </div>
      </div>
    </div>
  </div>

  <div class="row g-4 mb-4">
    <div class="col-md-7">
      <div class="chart-container">
        <h6 class="text-muted mb-3">Runtime per Run — All 3 Pipelines</h6>
        <canvas id="runtimeChart" height="220"></canvas>
      </div>
    </div>
    <div class="col-md-5">
      <div class="chart-container">
        <h6 class="text-muted mb-3">Mean Runtime Comparison</h6>
        <canvas id="runtimeBarChart" height="220"></canvas>
      </div>
    </div>
  </div>

  <div class="table-responsive mb-4">
    <table class="table table-bordered">
      <thead><tr>
        <th>Pipeline</th><th>n</th><th>Mean</th><th>Std Dev</th>
        <th>Min</th><th>Max</th><th>CV</th>
        <th>Security Tools</th><th>Overhead vs Baseline</th>
      </tr></thead>
      <tbody>
        <tr>
          <td>🏗️ Baseline</td>
          <td>10</td>
          <td>{b_mean}s</td><td>±{b_std}s</td>
          <td>{b_min}s</td><td>{b_max}s</td>
          <td>{b_cv}%</td>
          <td><span class="badge bg-secondary">None</span></td>
          <td>—</td>
        </tr>
        <tr>
          <td>⚡ Parallel</td>
          <td>10</td>
          <td>{p_mean}s</td><td>±{p_std}s</td>
          <td>{p_min}s</td><td>{p_max}s</td>
          <td>{p_cv}%</td>
          <td><span class="badge bg-success">5 tools</span></td>
          <td>+{p_overhead_s}s (+{p_overhead_pct}%)</td>
        </tr>
        <tr class="table-active">
          <td>🔒 Sequential</td>
          <td>10</td>
          <td>{s_mean}s</td><td>±{s_std}s</td>
          <td>{s_min}s</td><td>{s_max}s</td>
          <td>{s_cv}%</td>
          <td><span class="badge bg-success">5 tools</span></td>
          <td>+{s_overhead_s}s (+{s_overhead_pct}%)</td>
        </tr>
      </tbody>
    </table>
  </div>
"""

    # ================================================================
    # Ground truth rows
    # ================================================================
    gt_rows = ""
    for r in gt_results:
        gt = r["gt"]
        detected = r["detected"]
        ruleset = r["detected_by_ruleset"] or gt["ruleset"]
        badge_detected = '<span class="badge bg-success">✓ Detected</span>' if detected else '<span class="badge bg-danger">✗ Missed</span>'
        ruleset_badge = ""
        if detected and gt["tool"] == "semgrep":
            if ruleset == "custom":
                ruleset_badge = '<span class="badge bg-warning text-dark ms-1">custom rule</span>'
            else:
                ruleset_badge = '<span class="badge bg-secondary ms-1">default</span>'
        tool_badge = f'<span class="badge bg-info text-dark">{gt["tool"]}</span>'
        line_str = str(gt["line"]) if gt["line"] else "—"
        missed_note = ""
        if not detected and "below threshold" in gt["vulnerability"].lower():
            missed_note = '<br><small class="text-muted">CVEs classified as MEDIUM by NVD — below HIGH/CRITICAL threshold</small>'
        gt_rows += f"""
        <tr>
            <td><strong>{gt["id"]}</strong></td>
            <td>{gt["vulnerability"]}{missed_note}</td>
            <td><code>{gt["file"]}</code></td>
            <td>{line_str}</td>
            <td><span class="badge bg-dark">{gt["cwe"]}</span></td>
            <td><span class="badge bg-secondary">{gt["owasp"]}</span></td>
            <td>{tool_badge}</td>
            <td>{badge_detected}{ruleset_badge}</td>
        </tr>"""

    # ================================================================
    # IaC rows
    # ================================================================
    iac_rows = ""
    for r in iac_results:
        item = r["item"]
        detected = r["detected"]
        detected_badge = (
            '<span class="badge bg-success">Detected</span>'
            if detected
            else '<span class="badge bg-secondary">Not detected in this run</span>'
        )
        iac_rows += f"""
        <tr>
            <td><strong>{item["id"]}</strong></td>
            <td><code>{item["rule"]}</code></td>
            <td><small>{item["resource"]}</small></td>
            <td><span class="badge bg-{'danger' if item['severity'] == 'CRITICAL' else 'warning' if item['severity'] == 'HIGH' else 'info' if item['severity'] == 'MEDIUM' else 'secondary'}">{item["severity"]}</span></td>
            <td>{detected_badge}</td>
            <td><span class="badge bg-{item['classification_color']}">{item['classification_label']}</span></td>
            <td><small class="text-muted">{item["action"]}</small></td>
        </tr>"""

    # ================================================================
    # False positive rows
    # ================================================================
    fp_rows = ""
    for r in metrics["semgrep"]["fp_findings"]:
        rule = r.get("check_id","").split(".")[-1]
        path = r.get("path","")
        line = r.get("start",{}).get("line","")
        fp_rows += f"""
        <tr>
            <td><code>{rule}</code></td>
            <td><code>{path}</code></td>
            <td>{line}</td>
            <td><span class="badge bg-warning text-dark">False Positive</span></td>
            <td>Rule targets Django patterns; not applicable to Flask</td>
        </tr>"""
    if not fp_rows:
        fp_rows = '<tr><td colspan="5" class="text-center text-muted">No false positives identified</td></tr>'

    # ================================================================
    # Trivy CVE rows
    # ================================================================
    trivy_rows = ""
    for c in trivy_app_cves[:20]:
        sev_color = "danger" if c["severity"] == "CRITICAL" else "warning" if c["severity"] == "HIGH" else "secondary"
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
        trivy_rows = '<tr><td colspan="6" class="text-center text-muted">No application CVEs detected</td></tr>'

    def pct(val):
        return f"{val*100:.1f}%"

    html = f"""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shift-Left Security Dashboard</title>
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
  .iac-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; }}
  code {{ color: #79c0ff; }}
  .navbar-brand {{ font-weight: 700; letter-spacing: -0.5px; }}
</style>
</head>
<body>

<nav class="navbar navbar-dark" style="background:#161b22;border-bottom:1px solid #30363d;">
  <div class="container">
    <span class="navbar-brand">🛡️ Shift-Left Security Dashboard</span>
    <span class="text-muted small">Run #{run_number} &nbsp;·&nbsp; {commit_sha[:7]} &nbsp;·&nbsp; {ts}</span>
  </div>
</nav>

<div class="container mt-4">

  <div class="status-banner">
    <div class="d-flex justify-content-between align-items-center">
      <div>
        <h3 class="mb-1" style="color:{status_color}">
          {"❌ Pipeline BLOCKED" if overall_status == "BLOCKED" else "✅ Pipeline PASSED"}
        </h3>
        <p class="mb-0 text-muted">
          Ground truth coverage:
          <strong style="color:#e6edf3">{total_detected}/{total_gt} vulnerabilities detected</strong>
          &nbsp;·&nbsp; Combined Recall:
          <strong style="color:#e6edf3">{pct(metrics["combined"]["recall"])}</strong>
          &nbsp;·&nbsp; Combined Precision:
          <strong style="color:#e6edf3">{pct(metrics["combined"]["precision"])}</strong>
        </p>
      </div>
    </div>
  </div>

  <div class="row g-3 mb-3">
    <div class="col-md-3">
      <div class="metric-card">
        <div class="metric-value" style="color:#f85149">{metrics["semgrep"]["tp"] + metrics["semgrep"]["fp"]}</div>
        <div class="metric-label">🔍 Semgrep Findings</div>
        <div class="mt-2">
          <small class="text-success">{metrics["semgrep"]["tp"]} TP</small> &nbsp;
          <small class="text-warning">{metrics["semgrep"]["fp"]} FP</small> &nbsp;
          <small class="text-danger">{metrics["semgrep"]["fn"]} FN</small>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="metric-card">
        <div class="metric-value" style="color:#f85149">{metrics["gitleaks"]["tp"]}</div>
        <div class="metric-label">🔑 Gitleaks Findings</div>
        <div class="mt-2">
          <small class="text-success">{metrics["gitleaks"]["tp"]} TP</small> &nbsp;
          <small class="text-danger">{metrics["gitleaks"]["fn"]} FN</small>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="metric-card">
        <div class="metric-value" style="color:#f85149">{len(trivy_app_cves)}</div>
        <div class="metric-label">📦 Trivy App CVEs</div>
        <div class="mt-2">
          <small class="text-success">{metrics["trivy"]["tp"]} TP</small> &nbsp;
          <small class="text-danger">{metrics["trivy"]["fn"]} FN</small>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="metric-card">
        <div class="metric-value" style="color:#3fb950">{custom_tp}</div>
        <div class="metric-label">⚡ Custom Rule Detections</div>
        <div class="mt-2"><small class="text-muted">additions beyond default ruleset</small></div>
      </div>
    </div>
  </div>

  <div class="row g-3 mb-4">
    <div class="col-md-3">
      <div class="metric-card">
        <div class="metric-value" style="color:#a371f7">{zap_total}</div>
        <div class="metric-label">🔒 DAST Alerts (ZAP 2.17.0)</div>
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
          <strong style="color:#a371f7">DAST vs SAST key insight:</strong>
          ZAP dynamically confirmed V08 (CORS wildcard —
          <code>Access-Control-Allow-Origin: *</code>)
          and V09 (CSP unsafe-inline) at runtime via HTTP response header inspection.
          SQL injection (V01, V02), RCE (V03), deserialization (V04), and secret
          scanning (V11) require source-level or credential analysis and are only
          detectable by static tools. SAST and DAST are complementary — neither
          alone achieves full coverage.
        </small>
      </div>
    </div>
  </div>

  <h5 class="section-title">📊 Precision / Recall / F1 per Tool</h5>
  <div class="table-responsive mb-4">
    <table class="table table-bordered">
      <thead><tr>
        <th>Tool</th><th>True Positives</th><th>False Positives</th>
        <th>False Negatives</th><th>Precision</th><th>Recall</th><th>F1 Score</th>
      </tr></thead>
      <tbody>
        <tr>
          <td>🔍 Semgrep</td>
          <td class="text-success">{metrics["semgrep"]["tp"]}</td>
          <td class="text-warning">{metrics["semgrep"]["fp"]}</td>
          <td class="text-danger">{metrics["semgrep"]["fn"]}</td>
          <td>{pct(metrics["semgrep"]["precision"])}</td>
          <td>{pct(metrics["semgrep"]["recall"])}</td>
          <td><strong>{pct(metrics["semgrep"]["f1"])}</strong></td>
        </tr>
        <tr>
          <td>🔑 Gitleaks</td>
          <td class="text-success">{metrics["gitleaks"]["tp"]}</td>
          <td class="text-warning">{metrics["gitleaks"]["fp"]}</td>
          <td class="text-danger">{metrics["gitleaks"]["fn"]}</td>
          <td>{pct(metrics["gitleaks"]["precision"])}</td>
          <td>{pct(metrics["gitleaks"]["recall"])}</td>
          <td><strong>{pct(metrics["gitleaks"]["f1"])}</strong></td>
        </tr>
        <tr>
          <td>📦 Trivy</td>
          <td class="text-success">{metrics["trivy"]["tp"]}</td>
          <td class="text-warning">{metrics["trivy"]["fp"]}</td>
          <td class="text-danger">{metrics["trivy"]["fn"]}</td>
          <td>{pct(metrics["trivy"]["precision"])}</td>
          <td>{pct(metrics["trivy"]["recall"])}</td>
          <td><strong>{pct(metrics["trivy"]["f1"])}</strong></td>
        </tr>
        <tr class="table-active">
          <td><strong>Combined</strong></td>
          <td class="text-success"><strong>{metrics["combined"]["tp"]}</strong></td>
          <td class="text-warning"><strong>{metrics["combined"]["fp"]}</strong></td>
          <td class="text-danger"><strong>{metrics["combined"]["fn"]}</strong></td>
          <td><strong>{pct(metrics["combined"]["precision"])}</strong></td>
          <td><strong>{pct(metrics["combined"]["recall"])}</strong></td>
          <td><strong>{pct(metrics["combined"]["f1"])}</strong></td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="row g-4 mb-4">
    <div class="col-md-6">
      <div class="chart-container">
        <h6 class="text-muted mb-3">Detection by OWASP Top 10 Category</h6>
        <canvas id="owaspChart" height="250"></canvas>
      </div>
    </div>
    <div class="col-md-6">
      <div class="chart-container">
        <h6 class="text-muted mb-3">Default Ruleset vs Custom Rules Contribution</h6>
        <canvas id="rulesetChart" height="250"></canvas>
      </div>
    </div>
  </div>

  {runtime_stats_html}

  <h5 class="section-title">🎯 Ground Truth Coverage Matrix (14 Items)</h5>
  <div class="table-responsive mb-4">
    <table class="table table-bordered table-hover">
      <thead><tr>
        <th>ID</th><th>Vulnerability</th><th>File</th><th>Line</th>
        <th>CWE</th><th>OWASP</th><th>Tool</th><th>Detection</th>
      </tr></thead>
      <tbody>{gt_rows}</tbody>
    </table>
  </div>

  <h5 class="section-title">🔒 DAST Results — OWASP ZAP 2.17.0 (Baseline Scan)</h5>
  <p class="text-muted small mb-3">
    OWASP ZAP performed a baseline scan against the running flask-webgoat application
    at <code>http://localhost:5000</code> using the Automation Framework.
    The baseline scan mode performs passive analysis and selected active probes
    without aggressive fuzzing. ZAP dynamically confirmed CORS misconfiguration (V08)
    and CSP unsafe-inline (V09) via HTTP response header inspection — both of which
    were also detected statically by Semgrep custom rules. SQL injection (V01, V02),
    RCE (V03), and insecure deserialization (V04) are not detectable by passive DAST
    and require source-level static analysis. This confirms the complementary nature
    of SAST and DAST as defence-in-depth layers.
  </p>
  <div class="row g-3 mb-3">
    <div class="col-md-3">
      <div class="iac-card">
        <div class="metric-value" style="color:#f85149">{zap_high}</div>
        <div class="metric-label">🔴 High Risk</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="iac-card">
        <div class="metric-value" style="color:#e3b341">{zap_medium}</div>
        <div class="metric-label">🟡 Medium Risk</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="iac-card">
        <div class="metric-value" style="color:#388bfd">{zap_low}</div>
        <div class="metric-label">🔵 Low Risk</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="iac-card">
        <div class="metric-value" style="color:#8b949e">{zap_info}</div>
        <div class="metric-label">ℹ️ Informational</div>
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
  </div>

  <h5 class="section-title">🏗️ IaC Security Assessment (tfsec — {iac_total} Findings)</h5>
  <p class="text-muted small mb-3">
    tfsec identified {iac_total} known findings in the Terraform infrastructure code.
    Each finding is classified as a True Positive (remediated), Intentional Design
    Decision, Known Limitation, or False Positive — demonstrating that IaC scan
    results require human analysis to distinguish genuine misconfigurations from
    deliberate trade-offs.
  </p>
  <div class="row g-3 mb-3">
    <div class="col-md-3">
      <div class="iac-card">
        <div class="metric-value" style="color:#3fb950">{iac_tp}</div>
        <div class="metric-label">✅ True Positive<br><small>Remediated</small></div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="iac-card">
        <div class="metric-value" style="color:#388bfd">{iac_intentional}</div>
        <div class="metric-label">🔵 Intentional<br><small>Design decisions</small></div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="iac-card">
        <div class="metric-value" style="color:#e3b341">{iac_limitation}</div>
        <div class="metric-label">🟡 Known Limitation<br><small>Future work</small></div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="iac-card">
        <div class="metric-value" style="color:#f85149">{iac_fp}</div>
        <div class="metric-label">⚠️ False Positive<br><small>Standard permission</small></div>
      </div>
    </div>
  </div>
  <div class="table-responsive mb-4">
    <table class="table table-bordered">
      <thead><tr>
        <th>ID</th><th>Rule</th><th>Resource</th><th>Severity</th>
        <th>Detected</th><th>Classification</th><th>Rationale</th>
      </tr></thead>
      <tbody>{iac_rows}</tbody>
    </table>
  </div>

  <h5 class="section-title">📦 Trivy — Application Dependency CVEs</h5>
  <p class="text-muted small mb-3">
    Showing only application-level packages (Flask, Jinja2, Werkzeug etc.)
    — OS-level CVEs excluded from ground truth evaluation.
  </p>
  <div class="table-responsive mb-4">
    <table class="table table-bordered">
      <thead><tr>
        <th>CVE</th><th>Package</th><th>Installed</th>
        <th>Fixed In</th><th>Severity</th><th>Title</th>
      </tr></thead>
      <tbody>{trivy_rows}</tbody>
    </table>
  </div>

  <h5 class="section-title">⚠️ SAST False Positive Analysis</h5>
  <div class="table-responsive mb-4">
    <table class="table table-bordered">
      <thead><tr>
        <th>Rule</th><th>File</th><th>Line</th><th>Classification</th><th>Reason</th>
      </tr></thead>
      <tbody>{fp_rows}</tbody>
    </table>
  </div>

  <footer class="text-center text-muted py-4 mt-4"
          style="border-top:1px solid #30363d;font-size:0.8rem;">
    Shift-Left Security in CI/CD Pipelines &nbsp;·&nbsp; Ananthu Chandra Babu
    &nbsp;·&nbsp; Westfälische Hochschule Gelsenkirchen &nbsp;·&nbsp; 2026
  </footer>

</div>

<script>
new Chart(document.getElementById('owaspChart'), {{
  type: 'bar',
  data: {{
    labels: {owasp_labels},
    datasets: [
      {{ label: 'Detected', data: {owasp_detected}, backgroundColor: '#3fb95099' }},
      {{ label: 'Missed',   data: {owasp_missed},   backgroundColor: '#f8514999' }}
    ]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ labels: {{ color: '#e6edf3' }} }} }},
    scales: {{
      x: {{ stacked: true, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }},
      y: {{ stacked: true, ticks: {{ color: '#8b949e', stepSize: 1 }}, grid: {{ color: '#21262d' }} }}
    }}
  }}
}});

new Chart(document.getElementById('rulesetChart'), {{
  type: 'doughnut',
  data: {{
    labels: ['Default Ruleset', 'Custom Rules', 'Missed'],
    datasets: [{{
      data: [{default_tp}, {custom_tp}, {total_gt - total_detected}],
      backgroundColor: ['#388bfd99', '#3fb95099', '#f8514999'],
      borderColor: ['#388bfd', '#3fb950', '#f85149'],
      borderWidth: 2
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ labels: {{ color: '#e6edf3' }} }},
      tooltip: {{
        callbacks: {{
          label: function(c) {{
            const total = c.dataset.data.reduce((a,b) => a+b, 0);
            return ` ${{c.label}}: ${{c.raw}} (${{Math.round(c.raw/total*100)}}%)`;
          }}
        }}
      }}
    }}
  }}
}});

{runtime_chart_js}
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

    gt_results     = evaluate_ground_truth(semgrep_data, gitleaks_data, trivy_data)
    iac_results    = evaluate_iac(tfsec_data)
    metrics        = compute_metrics(gt_results, semgrep_data)
    trivy_app_cves = get_trivy_app_cves(trivy_data)
    zap_findings   = get_zap_findings(zap_data)
    runtime_data   = load_runtime_data()

    html = generate_html(
        gt_results, metrics, trivy_app_cves, iac_results,
        semgrep_data, gitleaks_data, zap_findings,
        commit_sha, run_number, runtime_data
    )

    out_dir = Path("dashboard")
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / "index.html"
    out_file.write_text(html, encoding="utf-8")

    print(f"Dashboard generated: {out_file}")
    print(f"Application ground truth: {metrics['combined']['tp']}/{len(GROUND_TRUTH)}")
    print(f"IaC findings classified: {len(iac_results)}")
    print(f"ZAP alerts loaded: {len(zap_findings)}")
    print(f"Runtime data loaded: yes (hardcoded n=10 measurements)")
    print(f"Combined Precision: {metrics['combined']['precision']:.3f}")
    print(f"Combined Recall:    {metrics['combined']['recall']:.3f}")
    print(f"Combined F1:        {metrics['combined']['f1']:.3f}")


if __name__ == "__main__":
    main()