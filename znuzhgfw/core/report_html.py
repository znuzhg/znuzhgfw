# znuzhgfw/core/report_html.py
from __future__ import annotations

from datetime import datetime
from typing import List, Dict, Any


SEVERITY_COLORS = {
    "CRITICAL": "#ff1744",
    "HIGH": "#ff5252",
    "MEDIUM": "#ff9100",
    "LOW": "#ffd600",
    "INFO": "#26c6da",
}


def _escape_html(text: str) -> str:
    import html
    return html.escape(str(text or ""))


def render_html_report(
    target: str,
    summary: Dict[str, Any],
    findings: List[Dict[str, Any]],
    generated_at: datetime | None = None,
) -> str:
    """
    findings beklenen format:
    [
      {
        "id": 1,
        "title": "DOM XSS sink present",
        "severity": "LOW",
        "url": "https://...",
        "detail": "Pattern: innerHTML = ...",
        "category": "XSS",          # optional
        "scanner": "xss",           # optional
      },
      ...
    ]

    summary:
    {
      "total": 8,
      "by_severity": {
         "CRITICAL": 0,
         "HIGH": 0,
         "MEDIUM": 0,
         "LOW": 6,
         "INFO": 2
      }
    }
    """
    generated_at = generated_at or datetime.utcnow()

    def sev_color(sev: str) -> str:
        return SEVERITY_COLORS.get(sev.upper(), "#ffffff")

    def sev_badge(sev: str) -> str:
        c = sev_color(sev)
        return f'''
        <span class="badge" style="border-color:{c};color:{c};">
            { _escape_html(sev.upper()) }
        </span>
        '''

    total = summary.get("total", len(findings))
    by_sev = summary.get("by_severity", {})

    # HTML START
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>ZNUZHGFW Report - { _escape_html(target) }</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
    * {{
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI",
                     Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans",
                     "Helvetica Neue", sans-serif;
    }}

    body {{
        background: radial-gradient(circle at top, #240000 0, #000000 55%);
        color: #f5f5f5;
        padding: 24px;
    }}

    .container {{
        max-width: 1100px;
        margin: 0 auto;
    }}

    .header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 24px;
        border-bottom: 1px solid #ff1744;
        padding-bottom: 16px;
    }}

    .logo {{
        font-family: monospace;
        font-size: 20px;
        letter-spacing: 2px;
        color: #ff1744;
    }}

    .logo span.accent {{
        color: #ffffff;
    }}

    .meta {{
        text-align: right;
        font-size: 12px;
        color: #bbbbbb;
    }}

    .pill {{
        display: inline-block;
        padding: 2px 8px;
        border-radius: 999px;
        border: 1px solid #444;
        font-size: 11px;
        margin-left: 6px;
    }}

    .summary {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
    }}

    .card {{
        background: linear-gradient(145deg, #121212, #050505);
        border-radius: 10px;
        padding: 16px;
        border: 1px solid #222;
        box-shadow: 0 0 0 1px rgba(255, 23, 68, 0.07);
    }}

    .card.highlight {{
        border-color: #ff1744;
        box-shadow: 0 0 18px rgba(255, 23, 68, 0.35);
    }}

    .card h2 {{
        font-size: 16px;
        margin-bottom: 8px;
        color: #ffffff;
    }}

    .card p {{
        font-size: 13px;
        color: #bdbdbd;
    }}

    .severity-grid {{
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 8px;
    }}

    .sev-pill {{
        font-size: 11px;
        padding: 3px 8px;
        border-radius: 999px;
        border: 1px solid #333;
        background: #111;
    }}

    .sev-pill span.label {{
        opacity: 0.7;
        margin-right: 4px;
    }}

    .sev-pill span.count {{
        font-weight: 600;
    }}

    .badge {{
        display: inline-block;
        font-size: 11px;
        padding: 2px 8px;
        border-radius: 999px;
        border: 1px solid;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-right: 6px;
    }}

    .badge.secondary {{
        border-color: #616161;
        color: #9e9e9e;
    }}

    .section-title {{
        font-size: 18px;
        margin-bottom: 12px;
        margin-top: 24px;
        border-left: 3px solid #ff1744;
        padding-left: 10px;
    }}

    .finding {{
        margin-bottom: 14px;
        padding-bottom: 12px;
        border-bottom: 1px dashed #333;
    }}

    .finding:last-child {{
        border-bottom: none;
    }}

    .finding-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
    }}

    .finding-title {{
        font-size: 14px;
        font-weight: 600;
        color: #f5f5f5;
    }}

    .finding-id {{
        font-size: 11px;
        color: #757575;
        margin-right: 6px;
    }}

    .finding-meta {{
        margin-top: 4px;
        font-size: 11px;
        color: #9e9e9e;
    }}

    .finding-meta code {{
        background: #1b1b1b;
        padding: 1px 5px;
        border-radius: 4px;
        font-size: 11px;
    }}

    .finding-detail {{
        margin-top: 8px;
        font-size: 13px;
        color: #c7c7c7;
        white-space: pre-wrap;
    }}

    a.url {{
        color: #ff5252;
        text-decoration: none;
        word-break: break-all;
    }}

    a.url:hover {{
        text-decoration: underline;
    }}

    .footer {{
        margin-top: 32px;
        font-size: 11px;
        color: #777;
        border-top: 1px solid #222;
        padding-top: 12px;
        display: flex;
        justify-content: space-between;
        gap: 12px;
        flex-wrap: wrap;
    }}

    .footer span.brand {{
        color: #ff1744;
    }}
</style>
</head>
<body>
<div class="container">

  <header class="header">
    <div class="logo">
      [ ZNUZHG<span class="accent">FW</span> ]<br/>
      <span style="font-size: 11px; color:#aaaaaa;">
        Red Team Style Web Vulnerability Scanner
      </span>
    </div>
    <div class="meta">
      <div>Target: <strong>{_escape_html(target)}</strong></div>
      <div>Generated: {generated_at.isoformat()} UTC</div>
      <div>
        Total Findings:
        <span class="pill">{total}</span>
      </div>
    </div>
  </header>

  <section class="summary">
    <div class="card highlight">
      <h2>Summary</h2>
      <p>Overall scan result for the target.</p>
      <div style="margin-top:8px;font-size:12px;">
        Total findings: <strong>{total}</strong>
      </div>
    </div>

    <div class="card">
      <h2>By Severity</h2>
      <div class="severity-grid">
    """

    # Severity pills
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_sev.get(sev, 0)
        color = sev_color(sev)
        html += f"""
        <div class="sev-pill" style="border-color:{color};">
          <span class="label" style="color:{color};">{sev}</span>
          <span class="count">{count}</span>
        </div>
        """

    html += """
      </div>
    </div>

    <div class="card">
      <h2>Notes</h2>
      <p>
        This report is generated by <strong>ZNUZHGFW</strong> for authorized security testing only.
        Running scans on systems without explicit permission may be illegal.
      </p>
    </div>
  </section>
    """

    # Findings Section
    html += """
  <section>
    <h1 class="section-title">Findings</h1>
  """

    if not findings:
        html += """
    <p style="font-size:13px;color:#9e9e9e;">
      No findings recorded for this target.
    </p>
        """
    else:
        for f in findings:
            fid = f.get("id", "")
            title = _escape_html(f.get("title", "Untitled Finding"))
            sev = (f.get("severity") or "INFO").upper()
            url = _escape_html(f.get("url", ""))
            detail = _escape_html(f.get("detail", ""))
            category = _escape_html(f.get("category", ""))
            scanner = _escape_html(f.get("scanner", ""))

            meta_bits = []
            if category:
                meta_bits.append(f"Category: <code>{category}</code>")
            if scanner:
                meta_bits.append(f"Scanner: <code>{scanner}</code>")
            meta_html = " | ".join(meta_bits)

            html += f"""
    <article class="finding">
      <div class="finding-header">
        <div>
          <span class="finding-id">#{fid}</span>
          <span class="finding-title">{title}</span>
        </div>
        <div>
          {sev_badge(sev)}
      """

            # Ek badge: URL varsa HTTP
            if url:
                html += '<span class="badge secondary">HTTP</span>'

            html += """
        </div>
      </div>
      <div class="finding-meta">
      """

            if url:
                html += f'URL: <a class="url" href="{url}" target="_blank" rel="noopener noreferrer">{url}</a>'
                if meta_html:
                    html += f"<br/>{meta_html}"
            else:
                if meta_html:
                    html += meta_html

            html += f"""
      </div>
      <div class="finding-detail">
        {detail}
      </div>
    </article>
      """

    html += """
  </section>

  <footer class="footer">
    <div>
      Generated by <span class="brand">ZNUZHGFW</span> — Offensive Security style, Defensive purpose.
    </div>
    <div>
      Use only on systems where you have explicit permission.
    </div>
  </footer>

</div>
</body>
</html>
    """

    return html
