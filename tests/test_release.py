from __future__ import annotations

import json
import subprocess
import sys
from contextlib import contextmanager
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/":
            body = """
            <html>
              <head><link rel="stylesheet" href="/static/app.css?ver=1"></head>
              <body>
                <a href="/login">Login</a>
                <a href="/search?q=test">Search</a>
              </body>
            </html>
            """
            self._write_html(body)
            return

        if path == "/login":
            self._write_html("<html><form action='/login'><input name='user'></form></html>")
            return

        if path == "/search":
            query = params.get("q", [""])[0]
            if query == "{{7*7}}":
                body = "<html>49</html>"
            else:
                body = f"<html>{escape(query)}</html>"
            self._write_html(body)
            return

        if path == "/static/app.css":
            self.send_response(200)
            self.send_header("Content-Type", "text/css")
            self.end_headers()
            self.wfile.write(b"body { color: #333; }")
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return None

    def _write_html(self, body: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


@contextmanager
def fixture_server() -> str:
    server = HTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_fixture_scan_report_regression(tmp_path) -> None:
    with fixture_server() as base_url:
        report_path = tmp_path / "fixture-report.json"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "znuzhgfw.main",
                "--url",
                base_url,
                "--depth",
                "1",
                "--threads",
                "1",
                "--report-format",
                "json",
                "--out",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    assert result.returncode == 0, result.stderr or result.stdout
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    summary = payload["summary"]
    findings = payload["findings"]
    finding_urls = [
        str(finding.get("url") or finding.get("normalized_url") or "")
        for finding in findings
    ]

    assert summary["assets_discovered"] >= 1
    assert summary["raw_findings"] >= len(findings)
    assert summary["deduplicated"] >= 1
    assert "by_scanner" in summary
    assert "by_confidence" in summary
    assert "by_proof_level" in summary
    assert len(findings) <= 12
    assert all("/static/app.css" not in url for url in finding_urls)
