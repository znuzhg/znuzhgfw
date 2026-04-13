from __future__ import annotations

from collections import defaultdict

from znuzhgfw.core.report import Report
from znuzhgfw.core.utils import ScanConfig, build_context, inject_param_to_url
from znuzhgfw.scanners.ratelimit import RateLimitScanner
from znuzhgfw.scanners.sqli import SQLiScanner
from znuzhgfw.scanners.ssti import SSTIScanner
from znuzhgfw.scanners.xss import XSSScanner


class DummyLogger:
    def log(self, msg: str) -> None:
        return None


class FakeResponse:
    def __init__(self, text: str = "", status_code: int = 200, headers: dict[str, str] | None = None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}


class FakeSession:
    def __init__(self, responses: dict[str, list[FakeResponse] | FakeResponse]):
        self.responses = responses
        self.calls = defaultdict(int)

    def get(self, url: str, **_: object) -> FakeResponse:
        current = self.responses.get(url)
        if current is None:
            raise KeyError(f"Unexpected URL: {url}")
        if isinstance(current, list):
            index = self.calls[url]
            self.calls[url] += 1
            if index >= len(current):
                return current[-1]
            return current[index]
        self.calls[url] += 1
        return current


def test_ssti_single_marker_stays_heuristic() -> None:
    url = "https://example.com/search?q=test"
    payload_url = inject_param_to_url(url, "q", "{{7*7}}")
    alt_payload_url = inject_param_to_url(url, "q", "${7*7}")
    erb_payload_url = inject_param_to_url(url, "q", "<%= 7 * 7 %>")
    session = FakeSession(
        {
            url: FakeResponse("<html>search</html>"),
            payload_url: FakeResponse("<html>49</html>"),
            alt_payload_url: FakeResponse("<html>${7*7}</html>"),
            erb_payload_url: FakeResponse("<html><%= 7 * 7 %></html>"),
        }
    )
    report = Report(url)
    scanner = SSTIScanner(session, DummyLogger(), report, ScanConfig())
    context = build_context(url, session.get(url))

    scanner.scan(url, html=context.html, context=context)

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.title == "SSTI suspicion"
    assert finding.proof_level == "heuristic"
    assert finding.confidence == "LOW"


def test_xss_encoded_reflection_is_low_confidence() -> None:
    url = "https://example.com/page?q=test"
    payload_url = inject_param_to_url(url, "q", "<script>alert(1)</script>")
    second_payload_url = inject_param_to_url(url, "q", "\"><script>alert(1)</script>")
    third_payload_url = inject_param_to_url(url, "q", "'><script>alert(1)</script>")
    fourth_payload_url = inject_param_to_url(url, "q", "\"><img src=x onerror=alert(1)>")
    encoded = "&lt;script&gt;alert(1)&lt;/script&gt;"
    session = FakeSession(
        {
            url: FakeResponse("<html>safe</html>"),
            payload_url: FakeResponse(f"<html>{encoded}</html>"),
            second_payload_url: FakeResponse("<html>safe</html>"),
            third_payload_url: FakeResponse("<html>safe</html>"),
            fourth_payload_url: FakeResponse("<html>safe</html>"),
        }
    )
    report = Report(url)
    scanner = XSSScanner(session, DummyLogger(), report, ScanConfig())
    context = build_context(url, session.get(url))

    scanner.scan(url, html=context.html, context=context)

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.title == "Encoded XSS reflection pattern"
    assert finding.severity == "LOW"
    assert finding.confidence == "LOW"
    assert finding.proof_level == "pattern"


def test_sqli_boolean_uses_baseline_consistency() -> None:
    url = "https://example.com/products?id=1"
    true_url = inject_param_to_url(url, "id", "1' OR '1'='1")
    false_url = inject_param_to_url(url, "id", "1' OR '1'='2")
    session = FakeSession(
        {
            url: FakeResponse("<table><td>row</td></table>"),
            true_url: FakeResponse("<table><td>row</td></table>"),
            false_url: FakeResponse("<html>No rows</html>"),
            inject_param_to_url(url, "id", "\" OR \"1\"=\"1"): FakeResponse("<table><td>row</td></table>"),
            inject_param_to_url(url, "id", "\" OR \"1\"=\"2"): FakeResponse("<table><td>row</td></table>"),
            inject_param_to_url(url, "id", "' OR ''='"): FakeResponse("<table><td>row</td></table>"),
            inject_param_to_url(url, "id", "' AND ''!='"): FakeResponse("<table><td>row</td></table>"),
            inject_param_to_url(url, "id", "'"): FakeResponse("<table><td>row</td></table>"),
            inject_param_to_url(url, "id", '"'): FakeResponse("<table><td>row</td></table>"),
            inject_param_to_url(url, "id", "`"): FakeResponse("<table><td>row</td></table>"),
            inject_param_to_url(url, "id", "1'; SELECT 1 --"): FakeResponse("<table><td>row</td></table>"),
            inject_param_to_url(url, "id", "1' OR SLEEP(3)--"): FakeResponse("<table><td>row</td></table>"),
            inject_param_to_url(url, "id", "1\" OR SLEEP(3)--"): FakeResponse("<table><td>row</td></table>"),
            inject_param_to_url(url, "id", "1') OR SLEEP(3)--"): FakeResponse("<table><td>row</td></table>"),
        }
    )
    report = Report(url)
    scanner = SQLiScanner(session, DummyLogger(), report, ScanConfig())
    context = build_context(url, session.get(url))

    scanner.scan(url, html=context.html, context=context)

    assert any(finding.title == "SQLi boolean anomaly" for finding in report.findings)


def test_rate_limit_requires_behavior_for_verified_signal() -> None:
    url = "https://example.com/login"
    responses = [
        FakeResponse("ok", 200, {"Content-Type": "text/html", "X-RateLimit-Limit": "10"}),
        FakeResponse("ok", 200, {"Content-Type": "text/html", "X-RateLimit-Limit": "10"}),
        FakeResponse("ok", 200, {"Content-Type": "text/html", "X-RateLimit-Limit": "10"}),
        FakeResponse("ok", 200, {"Content-Type": "text/html", "X-RateLimit-Limit": "10"}),
        FakeResponse("ok", 200, {"Content-Type": "text/html", "X-RateLimit-Limit": "10"}),
        FakeResponse("ok", 200, {"Content-Type": "text/html", "X-RateLimit-Limit": "10"}),
        FakeResponse("ok", 200, {"Content-Type": "text/html", "X-RateLimit-Limit": "10"}),
        FakeResponse("ok", 200, {"Content-Type": "text/html", "X-RateLimit-Limit": "10"}),
        FakeResponse("ok", 200, {"Content-Type": "text/html", "X-RateLimit-Limit": "10"}),
        FakeResponse("ok", 200, {"Content-Type": "text/html", "X-RateLimit-Limit": "10"}),
    ]
    session = FakeSession({url: responses})
    report = Report(url)
    scanner = RateLimitScanner(session, DummyLogger(), report, ScanConfig())
    context = build_context(url, session.get(url))

    scanner.scan(url, html=context.html, context=context)

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.title == "Rate limiting headers advertised"
    assert finding.proof_level == "heuristic"
    assert finding.confidence == "MEDIUM"
