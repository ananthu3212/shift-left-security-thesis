# Custom Semgrep Rules

This directory contains custom Semgrep rules developed for this thesis.
They target vulnerability patterns that the default `p/python` community
ruleset does not detect.

---

## Rule overview

| Rule file | Vulnerability | CWE | OWASP | Portability |
|---|---|---|---|---|
| `deserialization.yaml` | Insecure use of `pickle.loads()` inside a Flask route | CWE-502 | A08:2021 | ✅ Any Flask app |
| `open-redirect.yaml` | `redirect()` called with unvalidated request parameter | CWE-601 | A01:2021 | ✅ Any Flask app |
| `cors-wildcard.yaml` | `Access-Control-Allow-Origin` set to `*` | CWE-284 | A01:2021 | ✅ Any Flask app |
| `csp-unsafe-inline.yaml` | Content-Security-Policy permits `unsafe-inline` | CWE-16 | A05:2021 | ✅ Any Flask app |
| `flask-debug-mode.yaml` | `app.run(debug=True)` enabled | CWE-94 | A05:2021 | ✅ Any Flask app |
| `sensitive-data-exposure.yaml` | SQLite `set_trace_callback(print)` logs all queries | CWE-200 | A02:2021 | ✅ Any SQLite app |
| `path-traversal.yaml` | Path constructed by concatenating user input | CWE-22 | A01:2021 | ⚠️ Pattern-specific |

---

## Portability notes

Six of the seven rules are generic and apply to any Python Flask
application. They detect vulnerability classes, not project-specific
code patterns.

The `path-traversal.yaml` rule matches a specific two-line pattern
found in flask-webgoat. When adopting this pipeline for another
project, either:

- Use it as a template and adapt the pattern to your codebase
- Replace it with a broader path traversal rule using:

```yaml
rules:
  - id: generic-path-traversal
    patterns:
      - pattern: Path($A + $SEP + $B)
      - pattern-inside: |
          @$APP.route(...)
          def $FUNC(...):
            ...
    message: >
      Path constructed using string concatenation inside a Flask route.
      Validate and resolve against a known base directory.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-22"
      owasp: "A01:2021 - Broken Access Control"
```

---

## How to write rules for your project

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

For rules with multiple conditions use `patterns:` with
`pattern:` and `pattern-inside:` clauses.

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