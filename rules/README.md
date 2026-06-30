# Custom Semgrep Rules

This directory contains the custom Semgrep rules developed for the thesis
*Shift-Left Security in CI/CD Pipelines*. They target vulnerability
patterns that the default `p/python` community ruleset does not detect.

There are **nine** custom rules in total. They were developed in two
stages, following the build–evaluate–redesign loop of the thesis
methodology:

- **Seven** rules were written first, against the deliberately vulnerable
  flask-webgoat application, to detect ground-truth items V04–V10.
- **Two** further rules — `ssti-fstring.yaml` and
  `jwt-insecure-decode.yaml` — were added after the portability
  evaluation, which exposed vulnerability patterns the first seven rules
  did not cover. These two do not fire on flask-webgoat; they target
  patterns found only in the wider portability sample.

---

## Rule overview

| Rule file | Rule ID | Vulnerability | CWE | OWASP    | Ground truth | Stage |
|---|---|---|---|----------|---|---|
| `deserialization.yaml` | `flask-insecure-deserialization-pickle` | `pickle.loads()` inside a Flask route | CWE-502 | A08:2021 | V04 | Primary |
| `path-traversal.yaml` | `flask-path-traversal-string-concat` | Path built from concatenated user input | CWE-22 | A01:2021 | V05 | Primary |
| `open-redirect.yaml` | `flask-open-redirect-request-param` | `redirect()` with an unvalidated request parameter | CWE-601 | A01:2021 | V06 | Primary |
| `sensitive-data-exposure.yaml` | `sqlite-trace-callback-data-exposure` | SQLite `set_trace_callback(print)` logs all queries | CWE-200 | A02:2021 | V07 | Primary |
| `cors-wildcard.yaml` | `flask-cors-wildcard-origin` | `Access-Control-Allow-Origin` set to `*` | CWE-284 | A01:2021 | V08 | Primary |
| `csp-unsafe-inline.yaml` | `flask-csp-unsafe-inline` | Content-Security-Policy permits `unsafe-inline` | CWE-16 | A05:2021 | V09 | Primary |
| `flask-debug-mode.yaml` | `flask-debug-mode-enabled` | `app.run(debug=True)` enabled | CWE-489 | A05:2021 | V10 | Primary |
| `ssti-fstring.yaml` | `flask-ssti-dynamic-template` | `render_template_string` with a non-literal template | CWE-94 | A03:2021 | — | Portability |
| `jwt-insecure-decode.yaml` | `flask-jwt-insecure-decode` | `jwt.decode(..., verify=False)` disables signature checks | CWE-347 | A02:2021 | — | Portability |

The seven primary rules each map to one flask-webgoat ground-truth item
(V04–V10). The two portability rules target patterns absent from
flask-webgoat and therefore carry no flask-webgoat ground-truth ID; they
are exercised against the independent applications in the portability
evaluation.

---

## Scope and limitations of the rules

These rules detect vulnerability *classes* rather than memorised
project-specific instances: the same rule fires on the same insecure
pattern in code it was never written against. That said, each rule is
bounded to the specific pattern it encodes, and this boundary is real
rather than incidental.

Two consequences follow, both observed in the thesis evaluation:

- A rule does not fire where a framework expresses the same weakness
  through a construct the pattern does not match. For example,
  `ssti-fstring.yaml` matches the `render_template_string` sink but not
  a template injection built with `jinja2.Template`; the latter is a
  documented miss.
- Pattern-based static analysis of this kind cannot reach authorisation
  or business-logic weaknesses, such as broken access control or
  insecure direct object references, which have no fixed syntactic
  signature.

The rules are therefore best understood as class-targeted but
pattern-bounded. Adopting them for another project, or another
framework, requires adapting or extending the patterns to that
project's own routing and sinks; the rules provide no detection for a
pattern they do not encode.

---

## Rule structure

Each rule follows this structure:

```yaml
rules:
  - id: your-rule-id
    pattern: <pattern to match>
    message: >
      Description of the vulnerability and how to fix it.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-XX"
      owasp: "AXX:2021"
```

Rules with more than one condition use `patterns:` with `pattern:`,
`pattern-inside:`, `pattern-not:`, or `metavariable-regex:` clauses, as
several of the rules in this directory do.

Full syntax reference:
https://semgrep.dev/docs/writing-rules/rule-syntax/

---

## Testing rules locally

```bash
# Test all rules against the current directory
semgrep --config=rules/ --verbose .

# Test a single rule
semgrep --config=rules/deserialization.yaml .

# Test and output JSON for analysis
semgrep --config=rules/ --json -o results.json .
```

---

## Reference

These rules were developed as part of:

> Chandra Babu, A. (2026). *Shift-Left Security in CI/CD Pipelines*.
> Bachelor's thesis, Westfälische Hochschule Gelsenkirchen.