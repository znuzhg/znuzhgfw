from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit

from .report_html import render_html_report
from .utils import (
    CONFIDENCE_ORDER,
    PROOF_ORDER,
    SEVERITY_ORDER,
    URLInfo,
    hash_value,
    level_at_least,
    merge_evidence,
    merge_unique_strings,
    normalize_confidence,
    normalize_proof_level,
    normalize_severity,
    normalize_url,
    stronger_level,
)


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Confidence = Literal["HIGH", "MEDIUM", "LOW"]
ProofLevel = Literal["verified", "reflected", "heuristic", "pattern"]


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass
class Finding:
    id: int
    title: str
    severity: Severity
    url: str = ""
    normalized_url: str = ""
    detail: str = ""
    category: str | None = None
    scanner: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: Confidence = "LOW"
    proof_level: ProofLevel = "pattern"
    tags: list[str] = field(default_factory=list)
    param: str | None = None
    payload: str | None = None
    occurrences: int = 1
    fingerprint: str = ""
    example_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _evidence_key(evidence: Mapping[str, Any] | None) -> str:
    if not evidence:
        return ""
    chunks: list[str] = []
    for key in sorted(evidence):
        value = evidence[key]
        if isinstance(value, list):
            chunks.append(f"{key}={','.join(str(item) for item in value)}")
        else:
            chunks.append(f"{key}={value}")
    return "|".join(chunks)


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_ORDER.get(finding.severity, 0),
            -CONFIDENCE_ORDER.get(finding.confidence, 0),
            -PROOF_ORDER.get(finding.proof_level, 0),
            (finding.scanner or "").lower(),
            (finding.title or "").lower(),
            finding.normalized_url,
        ),
    )


def _top_risks(findings: list[Finding], limit: int = 5) -> list[Finding]:
    return _sort_findings(findings)[:limit]


def _high_confidence_findings(findings: list[Finding]) -> list[Finding]:
    return [
        finding
        for finding in _sort_findings(findings)
        if finding.confidence == "HIGH"
    ]


def _build_header_summary(findings: list[Finding]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for finding in findings:
        if finding.category != "Security Headers":
            continue
        header_name = str(finding.evidence.get("header") or "").strip()
        host = str(finding.evidence.get("host") or urlsplit(finding.url).netloc).strip()
        if not header_name or not host:
            continue
        summary.setdefault(host, {})
        summary[host][header_name] = summary[host].get(header_name, 0) + finding.occurrences
    return summary


def build_summary(
    findings: list[Finding],
    discovered_targets: Mapping[str, URLInfo] | None = None,
    scanned_targets: int = 0,
) -> dict[str, Any]:
    by_severity = {key: 0 for key in SEVERITY_ORDER}
    by_confidence = {key: 0 for key in CONFIDENCE_ORDER}
    by_proof_level = {key: 0 for key in PROOF_ORDER}
    by_scanner: dict[str, int] = {}
    by_category: dict[str, int] = {}

    raw_total = sum(finding.occurrences for finding in findings)
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_confidence[finding.confidence] = by_confidence.get(finding.confidence, 0) + 1
        by_proof_level[finding.proof_level] = by_proof_level.get(finding.proof_level, 0) + 1
        if finding.scanner:
            by_scanner[finding.scanner] = by_scanner.get(finding.scanner, 0) + 1
        if finding.category:
            by_category[finding.category] = by_category.get(finding.category, 0) + 1

    documents_discovered = 0
    assets_discovered = 0
    asset_samples: list[str] = []
    if discovered_targets:
        for target in discovered_targets.values():
            if target.is_document:
                documents_discovered += 1
            elif target.is_static:
                assets_discovered += 1
                if len(asset_samples) < 10:
                    asset_samples.append(target.normalized_url)

    return {
        "total": len(findings),
        "unique_findings": len(findings),
        "raw_findings": raw_total,
        "deduplicated": max(raw_total - len(findings), 0),
        "scanned_targets": scanned_targets,
        "documents_discovered": documents_discovered,
        "assets_discovered": assets_discovered,
        "asset_samples": asset_samples,
        "by_severity": by_severity,
        "by_confidence": by_confidence,
        "by_proof_level": by_proof_level,
        "by_scanner": dict(sorted(by_scanner.items())),
        "by_category": dict(sorted(by_category.items())),
        "security_headers": _build_header_summary(findings),
    }


def _render_evidence_block(finding: Finding) -> list[str]:
    lines: list[str] = []
    if finding.detail:
        lines.append(finding.detail)
    if finding.evidence:
        for key, value in sorted(finding.evidence.items()):
            if isinstance(value, list):
                joined = ", ".join(str(item) for item in value)
                lines.append(f"{key}: {joined}")
            else:
                lines.append(f"{key}: {value}")
    return lines


def render_markdown_report(
    target: str,
    summary: dict[str, Any],
    findings: list[Finding],
    generated_at: datetime | None = None,
) -> str:
    generated_at = generated_at or _utcnow()
    lines: list[str] = []

    lines.append("# ZNUZHG Pentest Report\n")
    lines.append(f"**Target:** `{target}`\n")
    lines.append(f"**Generated at:** {generated_at.isoformat()} UTC\n")
    lines.append("## Summary\n")
    lines.append(f"- **Unique findings:** {summary['unique_findings']}")
    lines.append(f"- **Raw finding occurrences:** {summary['raw_findings']}")
    lines.append(f"- **Deduplicated duplicates removed:** {summary['deduplicated']}")
    lines.append(f"- **Scanned targets:** {summary['scanned_targets']}")
    lines.append(f"- **Discovered documents:** {summary['documents_discovered']}")
    lines.append(f"- **Discovered assets:** {summary['assets_discovered']}")
    lines.append("- **By Severity:**")
    for severity, count in summary["by_severity"].items():
        lines.append(f"  - {severity}: {count}")
    lines.append("- **By Confidence:**")
    for confidence, count in summary["by_confidence"].items():
        lines.append(f"  - {confidence}: {count}")
    lines.append("- **By Proof Level:**")
    for proof_level, count in summary["by_proof_level"].items():
        lines.append(f"  - {proof_level}: {count}")
    lines.append("\n---\n")

    header_summary = summary.get("security_headers", {})
    if header_summary:
        lines.append("## Security Header Summary\n")
        for host, headers in header_summary.items():
            lines.append(f"### {host}")
            for header_name, count in sorted(headers.items()):
                lines.append(f"- {header_name}: observed missing on {count} document(s)")
        lines.append("")

    asset_samples = summary.get("asset_samples", [])
    if asset_samples:
        lines.append("## Discovered Assets\n")
        for asset_url in asset_samples:
            lines.append(f"- `{asset_url}`")
        lines.append("")

    scanner_distribution = summary.get("by_scanner", {})
    if scanner_distribution:
        lines.append("## Findings by Scanner\n")
        for scanner_name, count in scanner_distribution.items():
            lines.append(f"- **{scanner_name}**: {count}")
        lines.append("")

    top_risks = _top_risks(findings)
    if top_risks:
        lines.append("## Top 5 Risk Findings\n")
        for finding in top_risks:
            lines.append(
                f"- **{finding.severity} / {finding.confidence}**: {finding.title} ({finding.scanner or 'unknown'})"
            )
        lines.append("")

    high_confidence = _high_confidence_findings(findings)
    if high_confidence:
        lines.append("## High Confidence Findings\n")
        for finding in high_confidence[:10]:
            lines.append(
                f"- **{finding.severity}**: {finding.title} at `{finding.url or finding.normalized_url}`"
            )
        lines.append("")

    lines.append("## Findings\n")
    sorted_findings = _sort_findings(findings)
    if not sorted_findings:
        lines.append("_No findings recorded._")
    else:
        for finding in sorted_findings:
            lines.append(f"### #{finding.id} — {finding.title}")
            lines.append(f"- **Severity:** {finding.severity}")
            lines.append(f"- **Confidence:** {finding.confidence}")
            lines.append(f"- **Proof level:** {finding.proof_level}")
            lines.append(f"- **Occurrences:** {finding.occurrences}")
            if finding.url:
                lines.append(f"- **URL:** `{finding.url}`")
            if finding.category:
                lines.append(f"- **Category:** `{finding.category}`")
            if finding.scanner:
                lines.append(f"- **Scanner:** `{finding.scanner}`")
            if finding.param:
                lines.append(f"- **Parameter:** `{finding.param}`")
            if finding.payload:
                lines.append(f"- **Payload:** `{finding.payload}`")
            if finding.tags:
                lines.append(f"- **Tags:** {', '.join(finding.tags)}")
            if finding.example_urls:
                lines.append(f"- **Examples:** {', '.join(finding.example_urls)}")
            evidence_lines = _render_evidence_block(finding)
            if evidence_lines:
                lines.append("")
                lines.append("```text")
                lines.extend(evidence_lines)
                lines.append("```")
            lines.append("")

    lines.append("---")
    lines.append(
        "> Generated by **ZNUZHGFW**. Use only on systems where you have explicit permission.\n"
    )
    return "\n".join(lines)


def render_json_report(
    target: str,
    summary: dict[str, Any],
    findings: list[Finding],
    generated_at: datetime | None = None,
) -> str:
    import json

    generated_at = generated_at or _utcnow()
    data = {
        "target": target,
        "generated_at": _format_timestamp(generated_at),
        "summary": summary,
        "findings": [finding.to_dict() for finding in _sort_findings(findings)],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def write_report(
    path: str | Path,
    target: str,
    findings: list[Finding],
    fmt: Literal["html", "markdown", "md", "json"] = "html",
    *,
    discovered_targets: Mapping[str, URLInfo] | None = None,
    scanned_targets: int = 0,
) -> Path:
    destination = Path(path)
    summary = build_summary(findings, discovered_targets, scanned_targets)
    generated_at = _utcnow()
    fmt_normalized = fmt.lower()

    if fmt_normalized in ("md", "markdown"):
        content = render_markdown_report(target, summary, findings, generated_at)
    elif fmt_normalized == "json":
        content = render_json_report(target, summary, findings, generated_at)
    elif fmt_normalized == "html":
        content = render_html_report(
            target,
            summary,
            [finding.to_dict() for finding in _sort_findings(findings)],
            generated_at,
        )
    else:
        raise ValueError(f"Unknown report format: {fmt}")

    destination.write_text(content, encoding="utf-8")
    return destination


class Report:
    def __init__(
        self,
        target: str,
        *,
        dedupe: bool = True,
        confidence_threshold: str = "LOW",
        proof_threshold: str = "pattern",
    ):
        self.target = target
        self.findings: list[Finding] = []
        self.discovered_targets: dict[str, URLInfo] = {}
        self.scanned_targets: set[str] = set()
        self._finding_index: dict[str, Finding] = {}
        self._counter = 1
        self._lock = Lock()
        self.dedupe = dedupe
        self.confidence_threshold = normalize_confidence(confidence_threshold)
        self.proof_threshold = normalize_proof_level(proof_threshold)

    def record_discovered(self, target: URLInfo) -> None:
        with self._lock:
            self.discovered_targets.setdefault(target.normalized_url, target)

    def record_scanned_target(self, normalized_url: str) -> None:
        with self._lock:
            if normalized_url:
                self.scanned_targets.add(normalized_url)

    def _make_fingerprint(
        self,
        *,
        title: str,
        category: str | None,
        scanner: str | None,
        normalized_url: str,
        param: str | None,
        payload: str | None,
        proof_level: str,
        evidence: Mapping[str, Any] | None,
    ) -> str:
        return hash_value(
            scanner,
            title,
            category,
            normalized_url,
            param,
            payload,
            proof_level,
            _evidence_key(evidence),
        )

    def add(
        self,
        *,
        severity: Severity = "INFO",
        title: str = "",
        url: str = "",
        normalized_url: str = "",
        detail: str = "",
        category: str | None = None,
        scanner: str | None = None,
        evidence: Mapping[str, Any] | None = None,
        confidence: Confidence | str = "LOW",
        proof_level: ProofLevel | str = "pattern",
        tags: list[str] | None = None,
        param: str | None = None,
        payload: str | None = None,
        fingerprint: str | None = None,
        example_urls: list[str] | None = None,
    ) -> Finding | None:
        normalized_severity = normalize_severity(severity)
        normalized_conf = normalize_confidence(str(confidence))
        normalized_proof = normalize_proof_level(str(proof_level))
        final_url = url or normalized_url
        final_normalized_url = normalize_url(normalized_url or final_url)

        if not level_at_least(
            normalized_conf,
            self.confidence_threshold,
            CONFIDENCE_ORDER,
        ):
            return None
        if not level_at_least(normalized_proof, self.proof_threshold, PROOF_ORDER):
            return None

        example_values = list(example_urls or [])
        if final_url:
            example_values.insert(0, final_url)

        finding_fingerprint = fingerprint or self._make_fingerprint(
            title=title or "Untitled Finding",
            category=category,
            scanner=scanner,
            normalized_url=final_normalized_url,
            param=param,
            payload=payload,
            proof_level=normalized_proof,
            evidence=evidence,
        )

        with self._lock:
            if self.dedupe and finding_fingerprint in self._finding_index:
                existing = self._finding_index[finding_fingerprint]
                existing.occurrences += 1
                existing.severity = stronger_level(
                    existing.severity,
                    normalized_severity,
                    SEVERITY_ORDER,
                )
                existing.confidence = stronger_level(
                    existing.confidence,
                    normalized_conf,
                    CONFIDENCE_ORDER,
                )
                existing.proof_level = stronger_level(
                    existing.proof_level,
                    normalized_proof,
                    PROOF_ORDER,
                )
                if detail and detail not in existing.detail:
                    if existing.detail:
                        existing.detail = f"{existing.detail}\n\nAdditional evidence:\n{detail}"
                    else:
                        existing.detail = detail
                existing.tags = sorted(set(existing.tags + list(tags or [])))
                existing.example_urls = merge_unique_strings(
                    existing.example_urls,
                    example_values,
                    limit=6,
                )
                existing.evidence = merge_evidence(existing.evidence, evidence)
                if not existing.param and param:
                    existing.param = param
                if not existing.payload and payload:
                    existing.payload = payload
                return existing

            finding = Finding(
                id=self._counter,
                title=title or "Untitled Finding",
                severity=normalized_severity,
                url=final_url,
                normalized_url=final_normalized_url,
                detail=detail,
                category=category,
                scanner=scanner,
                evidence=dict(evidence or {}),
                confidence=normalized_conf,
                proof_level=normalized_proof,
                tags=sorted(set(tags or [])),
                param=param,
                payload=payload,
                occurrences=1,
                fingerprint=finding_fingerprint,
                example_urls=merge_unique_strings([], example_values, limit=6),
            )
            self.findings.append(finding)
            if self.dedupe:
                self._finding_index[finding_fingerprint] = finding
            self._counter += 1
            return finding

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return build_summary(
                list(self.findings),
                self.discovered_targets,
                len(self.scanned_targets),
            )

    def sorted_findings(self) -> list[Finding]:
        with self._lock:
            return _sort_findings(list(self.findings))

    def write_html(self, path: str | Path) -> Path:
        summary = self.summary()
        payload = [finding.to_dict() for finding in self.sorted_findings()]
        out = render_html_report(self.target, summary, payload, _utcnow())
        destination = Path(path)
        destination.write_text(out, encoding="utf-8")
        return destination

    def write_markdown(self, path: str | Path) -> Path:
        summary = self.summary()
        out = render_markdown_report(
            self.target,
            summary,
            self.sorted_findings(),
            _utcnow(),
        )
        destination = Path(path)
        destination.write_text(out, encoding="utf-8")
        return destination

    def write_json(self, path: str | Path) -> Path:
        summary = self.summary()
        out = render_json_report(
            self.target,
            summary,
            self.sorted_findings(),
            _utcnow(),
        )
        destination = Path(path)
        destination.write_text(out, encoding="utf-8")
        return destination
