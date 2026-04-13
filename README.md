# znuzhgfw

`znuzhgfw` is a Python web security scanner for authorized assessments. It combines a same-origin crawler, a set of focused web scanners, deduplicated findings, and multi-format reporting into a single CLI tool that can be installed from PyPI.

The project is designed for security engineers, pentesters, defenders, and researchers who want fast reconnaissance with evidence-aware reporting instead of raw pattern spam. It is not an exploit framework and it does not replace manual validation.

## What It Does

- Crawls a target with depth control and same-origin filtering
- Classifies URLs to reduce static asset noise by default
- Runs a focused set of web security checks against meaningful targets
- Records findings with severity, confidence, and proof level
- Deduplicates repeated findings and tracks occurrences
- Generates HTML, JSON, and Markdown reports
- Supports report filtering with confidence and proof thresholds

## Features

- Same-origin crawler with URL normalization and placeholder filtering
- Scanner coverage for:
  - SQL injection
  - Cross-site scripting
  - Server-side template injection
  - Local file inclusion / path traversal
  - Open redirect
  - CRLF injection
  - Security headers
  - HTTP methods
  - Rate limiting
  - Common endpoint discovery
  - Basic WAF detection
- Proof-oriented finding model:
  - `pattern`
  - `heuristic`
  - `reflected`
  - `verified`
- Confidence levels:
  - `LOW`
  - `MEDIUM`
  - `HIGH`
- Noise reduction:
  - finding deduplication
  - occurrence tracking
  - static asset filtering by default
  - calmer labeling for weak signals
- Report outputs:
  - HTML
  - JSON
  - Markdown
- PyPI installation and CLI entry point

## Installation

### PyPI

```bash
pip install znuzhgfw
```

### From Source

```bash
git clone https://github.com/znuzhg/znuzhgfw.git
cd znuzhgfw
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

On Windows PowerShell, use:

```powershell
.venv\Scripts\Activate.ps1
```

## Quick Start

Show help:

```bash
znuzhgfw --help
```

Basic scan:

```bash
znuzhgfw --url https://example.com
```

Write an HTML report:

```bash
znuzhgfw --url https://example.com --report-format html --out report.html
```

Lower-noise run with stronger report filtering:

```bash
znuzhgfw --url https://example.com --confidence-threshold medium --proof-threshold heuristic
```

Include static assets in crawl inventory without actively scanning them:

```bash
znuzhgfw --url https://example.com --include-static
```

Enable limited active checks on static assets:

```bash
znuzhgfw --url https://example.com --scan-assets
```

At the moment, `--scan-assets` is intentionally conservative. It expands active scope for scanners that are meaningful on asset responses, such as security header and HTTP method checks. It does not turn static files into full SQLi, XSS, or SSTI targets.

## CLI Options

| Option | Description |
| --- | --- |
| `--url` | Target URL to scan. Required. |
| `--threads` | Number of worker threads for the scan engine. |
| `--depth` | Crawl depth for same-origin discovery. |
| `--cookies` | Raw `Cookie` header to attach to requests. |
| `--report-format` | Output format: `html`, `json`, `md`, or `markdown`. |
| `--out` / `--report` | Output path for the generated report. |
| `--include-static` | Keep static assets in crawl inventory without active scanning. |
| `--scan-assets` | Allow limited active checks on static assets. |
| `--confidence-threshold` | Minimum confidence to keep in the report. |
| `--proof-threshold` | Minimum proof level to keep in the report. |
| `--dedupe` / `--no-dedupe` | Enable or disable finding deduplication. |
| `--max-urls` | Limit the number of URLs queued by the crawler. |
| `--skip-rate-limit` | Disable rate limiting checks. |
| `--skip-headers` | Disable security header checks. |
| `--skip-dirscan` | Disable common endpoint discovery. |

## Scanner Coverage

The project ships with the following scanners:

| Scanner | Purpose | Notes |
| --- | --- | --- |
| Security headers | Checks common hardening headers such as CSP, HSTS, and X-Frame-Options | Document responses are the primary signal; asset checks are optional and calmer |
| Rate limiting | Looks for rate limit headers and observable throttling behavior | Focuses on meaningful endpoints instead of every URL |
| Directory discovery | Probes a small set of common paths | Reports notable or exposed endpoints, not every path as a vulnerability |
| XSS | Checks reflected XSS patterns and DOM sink/source patterns | Encoded reflection is downgraded |
| SSTI | Tests query parameters with conservative template probes | Requires response changes beyond simple literal reflection |
| SQLi | Uses boolean, error-based, and time-delay probes | Baseline comparisons reduce weak detections |
| LFI / path traversal | Tests candidate file-related parameters | Requires response changes relative to baseline |
| Open redirect | Tests redirect-style parameters | Looks for externally introduced redirect targets |
| HTTP methods | Checks `OPTIONS` and `TRACE` behavior | Host-level summary style findings |
| WAF detection | Looks for basic WAF fingerprints in headers or body | Heuristic signal only |
| CRLF injection | Looks for newly introduced headers after payload injection | Requires header-level evidence |

## Evidence Model

Each finding carries both impact and evidence metadata:

- `severity`: impact-oriented rating from `INFO` to `CRITICAL`
- `confidence`: how reliable the signal is
- `proof_level`: how strong the observed evidence is

Current proof levels:

- `pattern`: static or weak signal only
- `heuristic`: suspicious behavior, but not yet strong confirmation
- `reflected`: meaningful response change or reflection-based evidence
- `verified`: strong, direct evidence observed by the tool

This model is intentionally conservative. A finding may be low severity but still worth manual review, and a heuristic result should not be treated as confirmed exploitation.

## Reports

`znuzhgfw` supports:

- HTML reports for human review
- JSON reports for automation and pipelines
- Markdown reports for notes or ticketing workflows

Reports include:

- severity distribution
- confidence distribution
- proof-level distribution
- scanner distribution
- deduplicated findings
- occurrence counts
- security header summary
- top risk findings
- high-confidence findings

## Safety and Ethics

Use this tool only on systems you own or are explicitly authorized to test.

Do not use `znuzhgfw` for unauthorized access, disruption, or hostile scanning. The software is provided for defensive, educational, and authorized security testing workflows. You are responsible for how you use it.

## Limitations

Be explicit about what this tool is and is not:

- Some checks are heuristic and can still produce false positives or false negatives.
- Not every finding is exploit proof.
- Browser-executed JavaScript behavior is not fully modeled; DOM XSS findings are not the same as a browser-verified exploit.
- Time-based checks can vary with network and server conditions.
- Static asset handling is intentionally conservative to reduce noise, which means some edge cases may require manual follow-up.
- Manual validation is still required before claiming a confirmed vulnerability.

## Development and Testing

Run the test suite:

```bash
pytest -q
```

Build the package:

```bash
python -m build
```

Validate package metadata:

```bash
python -m twine check dist/*
```

Smoke test the installed CLI from the built wheel:

```bash
python -m pip uninstall znuzhgfw -y
python -m pip install dist/*.whl
znuzhgfw --help
```

On PowerShell, expand the wheel path explicitly if needed:

```powershell
python -m pip install (Get-ChildItem dist\*.whl | Select-Object -ExpandProperty FullName)
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution workflow and validation expectations.

## Security

If you believe you found a vulnerability in the project itself, follow the process in [SECURITY.md](SECURITY.md) and avoid opening a public issue for sensitive details.

## License

This project is released under the [MIT License](LICENSE).
