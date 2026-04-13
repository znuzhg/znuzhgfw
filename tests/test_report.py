from znuzhgfw.core.report import Report
from znuzhgfw.core.utils import classify_url


def test_report_deduplicates_and_tracks_occurrences() -> None:
    report = Report("https://example.com")
    report.add(
        severity="LOW",
        title="Missing Security Header",
        url="https://example.com",
        category="Security Headers",
        scanner="HeaderScanner",
        evidence={"header": "Content-Security-Policy"},
    )
    report.add(
        severity="LOW",
        title="Missing Security Header",
        url="https://example.com/page",
        normalized_url="https://example.com",
        category="Security Headers",
        scanner="HeaderScanner",
        evidence={"header": "Content-Security-Policy"},
        example_urls=["https://example.com/page"],
    )

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.occurrences == 2
    assert "https://example.com/page" in finding.example_urls


def test_report_respects_thresholds() -> None:
    report = Report(
        "https://example.com",
        confidence_threshold="MEDIUM",
        proof_threshold="reflected",
    )
    dropped = report.add(
        severity="LOW",
        title="Pattern detected",
        url="https://example.com",
        confidence="LOW",
        proof_level="pattern",
    )
    kept = report.add(
        severity="MEDIUM",
        title="Reflected issue",
        url="https://example.com",
        confidence="MEDIUM",
        proof_level="reflected",
    )

    assert dropped is None
    assert kept is not None
    assert len(report.findings) == 1


def test_report_summary_counts_deduplicated_occurrences() -> None:
    report = Report("https://example.com")
    for _ in range(3):
        report.add(
            severity="INFO",
            title="Notable endpoint discovered",
            url="https://example.com/login",
            category="Content Discovery",
            scanner="DirectoryScanner",
            fingerprint="dirscan:test:/login",
        )

    summary = report.summary()
    assert summary["unique_findings"] == 1
    assert summary["raw_findings"] == 3
    assert summary["deduplicated"] == 2


def test_report_fingerprint_distinguishes_proof_level() -> None:
    report = Report("https://example.com")
    report.add(
        severity="LOW",
        title="Potential issue",
        url="https://example.com/search?q=test",
        category="XSS",
        scanner="XSSScanner",
        param="q",
        payload="<script>alert(1)</script>",
        proof_level="pattern",
    )
    report.add(
        severity="MEDIUM",
        title="Potential issue",
        url="https://example.com/search?q=test",
        category="XSS",
        scanner="XSSScanner",
        param="q",
        payload="<script>alert(1)</script>",
        proof_level="reflected",
    )

    assert len(report.findings) == 2


def test_html_report_renders_release_sections(tmp_path) -> None:
    report = Report("https://example.com")
    report.record_discovered(classify_url("https://example.com/"))
    report.record_discovered(classify_url("https://example.com/static/app.css"))
    report.record_scanned_target("https://example.com/")
    report.add(
        severity="LOW",
        title="Missing Security Header",
        url="https://example.com",
        normalized_url="https://example.com",
        category="Security Headers",
        scanner="HeaderScanner",
        confidence="MEDIUM",
        proof_level="pattern",
        evidence={"header": "Content-Security-Policy", "host": "example.com"},
    )
    report.add(
        severity="LOW",
        title="Missing Security Header",
        url="https://example.com/login",
        normalized_url="https://example.com",
        category="Security Headers",
        scanner="HeaderScanner",
        confidence="MEDIUM",
        proof_level="pattern",
        evidence={"header": "Content-Security-Policy", "host": "example.com"},
    )
    report.add(
        severity="HIGH",
        title="Open redirect likely",
        url="https://example.com/redirect?next=http://example.com",
        category="Open Redirect",
        scanner="RedirectScanner",
        confidence="HIGH",
        proof_level="verified",
        param="next",
        payload="http://example.com",
    )

    destination = tmp_path / "report.html"
    report.write_html(destination)
    html = destination.read_text(encoding="utf-8")

    assert "Top 5 Risk Findings" in html
    assert "High Confidence Findings" in html
    assert "Scanner Distribution" in html
    assert "Security Header Summary" in html
    assert "occurrences 2" in html
