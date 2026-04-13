from __future__ import annotations

from znuzhgfw.core.scanner_base import ScannerBase
from znuzhgfw.core.utils import (
    ScanContext,
    get_query_params,
    inject_param_to_url,
    is_candidate_param,
    normalize_url,
)


SSTI_TESTS = (
    ("{{7*7}}", "49", ("jinja", "twig", "liquid")),
    ("${7*7}", "49", ("freemarker", "el")),
    ("<%= 7 * 7 %>", "49", ("erb",)),
)
TEMPLATE_ENGINE_HINTS = {
    "erb": ("erb", "actionview", "rails"),
    "el": ("expression language", "javax.el"),
    "freemarker": ("freemarker",),
    "jinja": ("jinja", "jinja2", "werkzeug"),
    "liquid": ("liquid",),
    "twig": ("twig",),
}
SSTI_ERROR_PATTERNS = (
    "template syntax error",
    "unexpected end of template",
    "jinja2",
    "freemarker",
    "liquid error",
    "mustache",
    "twig",
    "velocity",
)


class SSTIScanner(ScannerBase):
    def should_scan(self, context: ScanContext) -> bool:
        return context.is_dynamic and bool(context.target.query)

    def _engine_hits(self, body_lower: str, baseline_lower: str, engines: tuple[str, ...]) -> list[str]:
        hits: list[str] = []
        for engine in engines:
            patterns = TEMPLATE_ENGINE_HINTS.get(engine, ())
            if any(pattern in body_lower and pattern not in baseline_lower for pattern in patterns):
                hits.append(engine)
        return sorted(set(hits))

    def scan(
        self,
        url: str,
        html: str | None = None,
        context: ScanContext | None = None,
    ) -> None:
        if context is None:
            return

        params = get_query_params(url)
        if not params or context.is_static:
            return

        baseline_text = context.text or ""
        baseline_lower = baseline_text.lower()
        self.logger.log(f"[SSTI] Testing {normalize_url(url)}")

        for param in params:
            if not is_candidate_param(param, "ssti"):
                continue

            marker_hits: list[dict[str, str]] = []
            engine_hits: list[str] = []
            heuristic_hits: list[str] = []

            for payload, expected_marker, engines in SSTI_TESTS:
                injected_url = inject_param_to_url(url, param, payload)
                try:
                    response = self.session.get(injected_url, verify=False, timeout=10)
                except Exception as exc:
                    self.logger.log(f"[SSTI] Error {url}: {exc}")
                    continue

                body = response.text
                body_lower = body.lower()
                if payload in body:
                    continue

                if expected_marker in body and expected_marker not in baseline_text:
                    marker_hits.append(
                        {
                            "payload": payload,
                            "marker": expected_marker,
                            "status_code": str(response.status_code),
                        }
                    )
                    engine_hits.extend(self._engine_hits(body_lower, baseline_lower, engines))
                    continue

                matched_error = next(
                    (
                        pattern
                        for pattern in SSTI_ERROR_PATTERNS
                        if pattern in body_lower and pattern not in baseline_lower
                    ),
                    "",
                )
                if matched_error:
                    heuristic_hits.append(matched_error)
                    heuristic_hits.extend(self._engine_hits(body_lower, baseline_lower, engines))

            unique_marker_hits = {
                (hit["payload"], hit["marker"], hit["status_code"])
                for hit in marker_hits
            }
            unique_engine_hits = sorted(set(engine_hits))
            unique_heuristics = sorted(set(heuristic_hits))

            if unique_engine_hits and unique_marker_hits:
                self.report.add(
                    severity="HIGH",
                    title="SSTI verified",
                    url=normalize_url(url),
                    normalized_url=normalize_url(url),
                    detail=(
                        "Template arithmetic evaluation was observed together with engine-specific response hints."
                    ),
                    category="Server-Side Template Injection",
                    scanner="SSTIScanner",
                    evidence={
                        "param": param,
                        "engines": unique_engine_hits,
                        "marker_hits": [
                            {
                                "payload": payload,
                                "marker": marker,
                                "status_code": status_code,
                            }
                            for payload, marker, status_code in sorted(unique_marker_hits)
                        ],
                    },
                    confidence="HIGH",
                    proof_level="verified",
                    tags=["ssti", "verified"],
                    param=param,
                )
                continue

            if len(unique_marker_hits) >= 2:
                self.report.add(
                    severity="MEDIUM",
                    title="SSTI likely",
                    url=normalize_url(url),
                    normalized_url=normalize_url(url),
                    detail=(
                        "Multiple template arithmetic probes produced evaluated output absent from the baseline response."
                    ),
                    category="Server-Side Template Injection",
                    scanner="SSTIScanner",
                    evidence={
                        "param": param,
                        "marker_hits": [
                            {
                                "payload": payload,
                                "marker": marker,
                                "status_code": status_code,
                            }
                            for payload, marker, status_code in sorted(unique_marker_hits)
                        ],
                    },
                    confidence="MEDIUM",
                    proof_level="reflected",
                    tags=["ssti", "reflected"],
                    param=param,
                )
                continue

            if unique_marker_hits:
                self.report.add(
                    severity="LOW",
                    title="SSTI suspicion",
                    url=normalize_url(url),
                    normalized_url=normalize_url(url),
                    detail=(
                        "A single template arithmetic probe altered the response, but engine-specific confirmation was not observed."
                    ),
                    category="Server-Side Template Injection",
                    scanner="SSTIScanner",
                    evidence={
                        "param": param,
                        "marker_hits": [
                            {
                                "payload": payload,
                                "marker": marker,
                                "status_code": status_code,
                            }
                            for payload, marker, status_code in sorted(unique_marker_hits)
                        ],
                    },
                    confidence="LOW",
                    proof_level="heuristic",
                    tags=["ssti", "heuristic"],
                    param=param,
                )
                continue

            if unique_heuristics:
                self.report.add(
                    severity="LOW",
                    title="SSTI pattern detected",
                    url=normalize_url(url),
                    normalized_url=normalize_url(url),
                    detail=(
                        "Template-related error patterns appeared after probe payloads, but no expression evaluation was confirmed."
                    ),
                    category="Server-Side Template Injection",
                    scanner="SSTIScanner",
                    evidence={"param": param, "patterns": unique_heuristics},
                    confidence="LOW",
                    proof_level="pattern",
                    tags=["ssti", "pattern"],
                    param=param,
                )
