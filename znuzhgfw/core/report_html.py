from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


SEVERITY_COLORS = {
    "CRITICAL": "#c1121f",
    "HIGH": "#e85d04",
    "MEDIUM": "#f48c06",
    "LOW": "#8ecae6",
    "INFO": "#adb5bd",
}
CONFIDENCE_COLORS = {
    "HIGH": "#2a9d8f",
    "MEDIUM": "#e9c46a",
    "LOW": "#6c757d",
}
PROOF_COLORS = {
    "verified": "#2a9d8f",
    "reflected": "#3a86ff",
    "heuristic": "#ffb703",
    "pattern": "#6c757d",
}


def _escape_html(text: Any) -> str:
    import html

    return html.escape(str(text or ""))


def _badge(label: str, color: str) -> str:
    return (
        f'<span class="badge" style="border-color:{color};color:{color};">'
        f"{_escape_html(label)}</span>"
    )


def _distribution_panel(title: str, values: dict[str, int], color_map: dict[str, str]) -> str:
    pills = []
    for key, count in values.items():
        color = color_map.get(key, "#adb5bd")
        pills.append(
            "<div class='metric-pill' style='border-color:{color};'>"
            "<span class='metric-label' style='color:{color};'>{label}</span>"
            "<span class='metric-count'>{count}</span>"
            "</div>".format(
                color=color,
                label=_escape_html(key),
                count=count,
            )
        )
    return (
        "<div class='card'>"
        f"<h2>{_escape_html(title)}</h2>"
        "<div class='metric-grid'>{}</div>"
        "</div>".format("".join(pills))
    )


def _render_evidence_block(finding: dict[str, Any]) -> str:
    detail = str(finding.get("detail") or "").strip()
    evidence = finding.get("evidence") or {}
    lines: list[str] = []
    if detail:
        lines.append(_escape_html(detail))

    if isinstance(evidence, dict):
        for key, value in sorted(evidence.items()):
            if isinstance(value, list):
                rendered = ", ".join(_escape_html(item) for item in value)
            else:
                rendered = _escape_html(value)
            lines.append(f"<strong>{_escape_html(key)}:</strong> {rendered}")

    if not lines:
        return ""
    return "<div class='finding-detail'>{}</div>".format("<br/>".join(lines))


def _risk_key(finding: dict[str, Any]) -> tuple[int, int, int, str]:
    severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    confidence_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    proof_order = {"pattern": 0, "heuristic": 1, "reflected": 2, "verified": 3}
    severity = str(finding.get("severity") or "INFO").upper()
    confidence = str(finding.get("confidence") or "LOW").upper()
    proof_level = str(finding.get("proof_level") or "pattern").lower()
    return (
        severity_order.get(severity, 0),
        confidence_order.get(confidence, 0),
        proof_order.get(proof_level, 0),
        str(finding.get("title") or ""),
    )


def render_html_report(
    target: str,
    summary: dict[str, Any],
    findings: list[dict[str, Any]],
    generated_at: datetime | None = None,
) -> str:
    generated_at = generated_at or datetime.now(UTC)
    security_headers = summary.get("security_headers", {})
    asset_samples = summary.get("asset_samples", [])
    assets_discovered = summary.get("assets_discovered", 0)
    raw_total = summary.get("raw_findings", len(findings))
    unique_total = summary.get("unique_findings", len(findings))
    deduplicated = summary.get("deduplicated", max(raw_total - unique_total, 0))
    top_risks = sorted(findings, key=_risk_key, reverse=True)[:5]
    high_confidence_findings = [
        finding for finding in sorted(findings, key=_risk_key, reverse=True)
        if str(finding.get("confidence") or "LOW").upper() == "HIGH"
    ]
    by_scanner = summary.get("by_scanner", {})
    scanner_colors = {name: "#f4a261" for name in by_scanner}

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>ZNUZHGFW Report - {_escape_html(target)}</title>
<style>
    :root {{
        --bg: #0d1b1e;
        --panel: rgba(18, 35, 39, 0.92);
        --panel-soft: rgba(24, 49, 56, 0.78);
        --border: rgba(173, 181, 189, 0.18);
        --text: #edf6f9;
        --muted: #b7c4c7;
        --accent: #f4a261;
        --shadow: 0 20px 60px rgba(0, 0, 0, 0.25);
    }}

    * {{
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }}

    body {{
        background:
            radial-gradient(circle at 15% 20%, rgba(42, 157, 143, 0.18), transparent 32%),
            radial-gradient(circle at 85% 0%, rgba(244, 162, 97, 0.16), transparent 25%),
            linear-gradient(180deg, #071114 0%, var(--bg) 100%);
        color: var(--text);
        font-family: "Segoe UI", system-ui, sans-serif;
        min-height: 100vh;
        padding: 28px;
    }}

    .container {{
        max-width: 1240px;
        margin: 0 auto;
    }}

    .header {{
        display: grid;
        grid-template-columns: 1.4fr 1fr;
        gap: 18px;
        margin-bottom: 24px;
    }}

    .hero, .card, .finding {{
        background: var(--panel);
        backdrop-filter: blur(12px);
        border: 1px solid var(--border);
        border-radius: 18px;
        box-shadow: var(--shadow);
    }}

    .hero {{
        padding: 24px;
    }}

    .hero h1 {{
        font-size: 28px;
        letter-spacing: 0.04em;
        margin-bottom: 10px;
    }}

    .hero p {{
        color: var(--muted);
        line-height: 1.5;
        max-width: 56ch;
    }}

    .meta {{
        display: grid;
        gap: 12px;
    }}

    .meta .card {{
        padding: 18px;
    }}

    .summary-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
        gap: 16px;
        margin-bottom: 22px;
    }}

    .card {{
        padding: 18px;
    }}

    .card h2 {{
        font-size: 15px;
        margin-bottom: 10px;
        color: var(--text);
    }}

    .big-number {{
        font-size: 28px;
        font-weight: 700;
        margin-bottom: 4px;
    }}

    .caption {{
        color: var(--muted);
        font-size: 13px;
        line-height: 1.45;
    }}

    .metric-grid {{
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
    }}

    .metric-pill {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 10px;
        border-radius: 999px;
        border: 1px solid var(--border);
        background: rgba(255, 255, 255, 0.02);
        font-size: 12px;
    }}

    .metric-label {{
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }}

    .metric-count {{
        font-weight: 700;
        color: var(--text);
    }}

    .section-title {{
        font-size: 18px;
        margin: 28px 0 12px;
        color: var(--text);
    }}

    .header-summary {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        gap: 14px;
    }}

    .header-summary ul {{
        list-style: none;
        display: grid;
        gap: 6px;
    }}

    .header-summary li {{
        color: var(--muted);
        font-size: 13px;
        line-height: 1.45;
    }}

    .findings {{
        display: grid;
        gap: 16px;
    }}

    .finding {{
        padding: 18px;
    }}

    .finding-head {{
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: flex-start;
    }}

    .finding-id {{
        color: var(--muted);
        font-size: 12px;
        letter-spacing: 0.06em;
    }}

    .finding-title {{
        font-size: 17px;
        font-weight: 650;
        margin-top: 4px;
    }}

    .finding-meta {{
        margin-top: 10px;
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
    }}

    .badge {{
        display: inline-flex;
        align-items: center;
        padding: 4px 10px;
        border-radius: 999px;
        border: 1px solid;
        font-size: 11px;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }}

    .finding-body {{
        margin-top: 14px;
        display: grid;
        gap: 10px;
    }}

    .finding-info {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
        gap: 10px;
    }}

    .info-box {{
        background: var(--panel-soft);
        border-radius: 12px;
        border: 1px solid var(--border);
        padding: 12px;
    }}

    .info-label {{
        color: var(--muted);
        display: block;
        font-size: 11px;
        letter-spacing: 0.07em;
        margin-bottom: 4px;
        text-transform: uppercase;
    }}

    .info-box code, .finding-detail code, a {{
        color: #ffe8d6;
    }}

    .finding-detail {{
        background: rgba(255, 255, 255, 0.03);
        border-radius: 12px;
        border: 1px solid var(--border);
        color: var(--muted);
        font-size: 13px;
        line-height: 1.55;
        padding: 12px;
        white-space: pre-wrap;
        word-break: break-word;
    }}

    .footer {{
        color: var(--muted);
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        justify-content: space-between;
        margin-top: 28px;
        padding-bottom: 8px;
        font-size: 12px;
    }}

    @media (max-width: 860px) {{
        .header {{
            grid-template-columns: 1fr;
        }}

        body {{
            padding: 18px;
        }}

        .finding-head {{
            flex-direction: column;
        }}
    }}
</style>
</head>
<body>
<div class="container">
    <section class="header">
        <div class="hero">
            <h1>ZNUZHGFW Security Report</h1>
            <p>
                Noise-reduced scan output for <strong>{_escape_html(target)}</strong>.
                Findings are deduplicated, annotated with confidence and proof level,
                and static asset noise is excluded unless explicitly enabled.
            </p>
        </div>
        <div class="meta">
            <div class="card">
                <h2>Run Metadata</h2>
                <div class="caption">Generated: {_escape_html(generated_at.isoformat())} UTC</div>
                <div class="caption">Scanned targets: {summary.get("scanned_targets", 0)}</div>
                <div class="caption">Discovered documents: {summary.get("documents_discovered", 0)}</div>
                <div class="caption">Discovered assets: {assets_discovered}</div>
            </div>
            <div class="card">
                <h2>Noise Reduction</h2>
                <div class="big-number">{deduplicated}</div>
                <div class="caption">
                    Duplicate occurrences suppressed. Raw occurrences: {raw_total}. Unique findings: {unique_total}.
                </div>
            </div>
        </div>
    </section>

    <section class="summary-grid">
        <div class="card">
            <h2>Unique Findings</h2>
            <div class="big-number">{unique_total}</div>
            <div class="caption">Post-deduplication findings included in this report.</div>
        </div>
        <div class="card">
            <h2>Raw Occurrences</h2>
            <div class="big-number">{raw_total}</div>
            <div class="caption">All finding instances observed before aggregation.</div>
        </div>
        <div class="card">
            <h2>Assets Excluded</h2>
            <div class="big-number">{assets_discovered}</div>
            <div class="caption">Static assets discovered during crawling and excluded from active checks by default.</div>
        </div>
        <div class="card">
            <h2>Report Posture</h2>
            <div class="big-number">{_escape_html(str(summary.get("by_proof_level", {}).get("verified", 0)))}</div>
            <div class="caption">Verified findings recorded in this run.</div>
        </div>
        {_distribution_panel("Severity Distribution", summary.get("by_severity", {}), SEVERITY_COLORS)}
        {_distribution_panel("Confidence Distribution", summary.get("by_confidence", {}), CONFIDENCE_COLORS)}
        {_distribution_panel("Proof Distribution", summary.get("by_proof_level", {}), PROOF_COLORS)}
        {_distribution_panel("Scanner Distribution", by_scanner, scanner_colors)}
    </section>
"""

    if security_headers:
        html += "<h2 class='section-title'>Security Header Summary</h2><section class='header-summary'>"
        for host, headers in sorted(security_headers.items()):
            html += (
                "<div class='card'><h2>{}</h2><ul>{}</ul></div>".format(
                    _escape_html(host),
                    "".join(
                        "<li><strong>{}</strong> missing on {} document(s)</li>".format(
                            _escape_html(header_name),
                            count,
                        )
                        for header_name, count in sorted(headers.items())
                    ),
                )
            )
        html += "</section>"

    if asset_samples:
        html += "<h2 class='section-title'>Discovered Assets</h2><section class='header-summary'>"
        html += "<div class='card'><h2>Static inventory sample</h2><ul>{}</ul></div>".format(
            "".join(
                f"<li><code>{_escape_html(asset_url)}</code></li>"
                for asset_url in asset_samples
            )
        )
        html += "</section>"

    if top_risks:
        html += "<h2 class='section-title'>Top 5 Risk Findings</h2><section class='header-summary'>"
        html += "".join(
            (
                "<div class='card'><h2>{}</h2><ul>"
                "<li>{} / {} / {}</li>"
                "<li>{}</li>"
                "</ul></div>"
            ).format(
                _escape_html(finding.get("title", "Untitled Finding")),
                _escape_html(str(finding.get("severity") or "INFO").upper()),
                _escape_html(str(finding.get("confidence") or "LOW").upper()),
                _escape_html(str(finding.get("proof_level") or "pattern").lower()),
                _escape_html(finding.get("scanner") or "unknown"),
            )
            for finding in top_risks
        )
        html += "</section>"

    if high_confidence_findings:
        html += "<h2 class='section-title'>High Confidence Findings</h2><section class='header-summary'>"
        html += "<div class='card'><h2>High confidence sample</h2><ul>{}</ul></div>".format(
            "".join(
                "<li><strong>{}</strong> at {}</li>".format(
                    _escape_html(finding.get("title", "Untitled Finding")),
                    _escape_html(finding.get("url") or finding.get("normalized_url") or ""),
                )
                for finding in high_confidence_findings[:10]
            )
        )
        html += "</section>"

    html += "<h2 class='section-title'>Findings</h2><section class='findings'>"
    if not findings:
        html += (
            "<div class='card'><div class='caption'>No findings recorded for this target.</div></div>"
        )
    else:
        for finding in findings:
            severity = str(finding.get("severity") or "INFO").upper()
            confidence = str(finding.get("confidence") or "LOW").upper()
            proof_level = str(finding.get("proof_level") or "pattern").lower()
            occurrence_count = int(finding.get("occurrences") or 1)
            category = finding.get("category") or ""
            scanner = finding.get("scanner") or ""
            url = finding.get("url") or ""
            param = finding.get("param") or ""
            payload = finding.get("payload") or ""
            tags = finding.get("tags") or []
            example_urls = finding.get("example_urls") or []

            html += f"""
            <article class="finding">
                <div class="finding-head">
                    <div>
                        <div class="finding-id">#{_escape_html(finding.get("id"))}</div>
                        <div class="finding-title">{_escape_html(finding.get("title"))}</div>
                    </div>
                    <div class="finding-meta">
                        {_badge(severity, SEVERITY_COLORS.get(severity, "#adb5bd"))}
                        {_badge(f"confidence {confidence}", CONFIDENCE_COLORS.get(confidence, "#adb5bd"))}
                        {_badge(proof_level, PROOF_COLORS.get(proof_level, "#adb5bd"))}
                        {_badge(f"occurrences {occurrence_count}", "#adb5bd")}
                    </div>
                </div>
                <div class="finding-body">
                    <div class="finding-info">
            """

            if category:
                html += (
                    "<div class='info-box'><span class='info-label'>Category</span>"
                    f"{_escape_html(category)}</div>"
                )
            if scanner:
                html += (
                    "<div class='info-box'><span class='info-label'>Scanner</span>"
                    f"{_escape_html(scanner)}</div>"
                )
            if url:
                html += (
                    "<div class='info-box'><span class='info-label'>URL</span>"
                    f"<a href='{_escape_html(url)}' target='_blank' rel='noopener noreferrer'>{_escape_html(url)}</a>"
                    "</div>"
                )
            if param:
                html += (
                    "<div class='info-box'><span class='info-label'>Parameter</span>"
                    f"<code>{_escape_html(param)}</code></div>"
                )
            if payload:
                html += (
                    "<div class='info-box'><span class='info-label'>Payload</span>"
                    f"<code>{_escape_html(payload)}</code></div>"
                )
            if tags:
                html += (
                    "<div class='info-box'><span class='info-label'>Tags</span>"
                    f"{_escape_html(', '.join(tags))}</div>"
                )
            if example_urls:
                html += (
                    "<div class='info-box'><span class='info-label'>Examples</span>"
                    f"{_escape_html(', '.join(example_urls))}</div>"
                )

            html += "</div>"
            html += _render_evidence_block(finding)
            html += "</div></article>"

    html += """
    </section>

    <footer class="footer">
        <span>Generated by ZNUZHGFW for authorized security testing.</span>
        <span>Severity reflects impact, while confidence and proof level reflect evidence quality.</span>
    </footer>
</div>
</body>
</html>
"""
    return html
