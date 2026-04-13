from __future__ import annotations

import html
import re

from znuzhgfw.core.payloads import DOM_XSS_PATTERNS, XSS_PAYLOADS
from znuzhgfw.core.scanner_base import ScannerBase
from znuzhgfw.core.utils import (
    ScanContext,
    get_query_params,
    inject_param_to_url,
    is_candidate_param,
    normalize_url,
)


DOM_SOURCE_PATTERNS = (
    r"location\.hash",
    r"location\.search",
    r"document\.URL",
    r"document\.location",
)
REFLECTION_PROBES = XSS_PAYLOADS[:4]


class XSSScanner(ScannerBase):
    def should_scan(self, context: ScanContext) -> bool:
        return context.is_document

    def _detect_dom_patterns(self, url: str, html_body: str) -> None:
        if not html_body:
            return

        sinks = sorted(
            {
                pattern
                for pattern in DOM_XSS_PATTERNS
                if re.search(pattern, html_body, re.IGNORECASE)
            }
        )
        if not sinks:
            return

        sources = sorted(
            {
                pattern
                for pattern in DOM_SOURCE_PATTERNS
                if re.search(pattern, html_body, re.IGNORECASE)
            }
        )
        title = (
            "DOM XSS source-to-sink pattern detected"
            if sources
            else "DOM sink pattern detected"
        )
        self.report.add(
            severity="LOW" if sources else "INFO",
            title=title,
            url=normalize_url(url),
            normalized_url=normalize_url(url),
            detail=(
                "Client-side source and sink patterns were observed in the same document."
                if sources
                else "Potential DOM sinks were found, but exploitability was not verified."
            ),
            category="Cross-Site Scripting",
            scanner="XSSScanner",
            evidence={"sinks": sinks, "sources": sources},
            confidence="MEDIUM" if sources else "LOW",
            proof_level="heuristic" if sources else "pattern",
            tags=["dom-xss", "pattern"],
        )

    def _reflection_context(self, body: str, payload: str) -> str:
        index = body.find(payload)
        if index < 0:
            return ""
        snippet = body[max(index - 120, 0) : index + len(payload) + 120].lower()
        if "<script" in snippet:
            return "script"
        if any(token in snippet for token in ('="', "='", " onerror", " onload", " onclick")):
            return "attribute"
        if "<" in snippet and ">" in snippet:
            return "html"
        return "text"

    def _encoded_variants(self, payload: str) -> list[str]:
        return sorted(
            {
                html.escape(payload, quote=True),
                html.escape(payload, quote=False),
            }
        )

    def _test_reflection(self, url: str, baseline_text: str) -> None:
        params = get_query_params(url)
        if not params:
            return

        self.logger.log(f"[XSS] Testing GET params for {normalize_url(url)}")
        baseline_lower = baseline_text.lower()
        for param in params:
            if not is_candidate_param(param, "xss"):
                continue

            for payload in REFLECTION_PROBES:
                injected_url = inject_param_to_url(url, param, payload)
                try:
                    response = self.session.get(injected_url, verify=False, timeout=10)
                except Exception as exc:
                    self.logger.log(f"[XSS] Error {url}: {exc}")
                    continue

                body = response.text
                body_lower = body.lower()
                raw_reflected = payload in body and payload.lower() not in baseline_lower
                encoded_reflection = any(
                    encoded in body and encoded.lower() not in baseline_lower
                    for encoded in self._encoded_variants(payload)
                )

                if not raw_reflected and not encoded_reflection:
                    continue

                if encoded_reflection and not raw_reflected:
                    self.report.add(
                        severity="LOW",
                        title="Encoded XSS reflection pattern",
                        url=injected_url,
                        normalized_url=normalize_url(url),
                        detail=(
                            "Payload reflection appears HTML-encoded in the response. "
                            "This does not demonstrate exploitability."
                        ),
                        category="Cross-Site Scripting",
                        scanner="XSSScanner",
                        evidence={
                            "param": param,
                            "payload": payload,
                            "context": "encoded",
                            "status_code": response.status_code,
                        },
                        confidence="LOW",
                        proof_level="pattern",
                        tags=["xss", "encoded"],
                        param=param,
                        payload=payload,
                    )
                    break

                context_name = self._reflection_context(body, payload) or "unknown"
                exploitable_context = context_name in {"attribute", "html", "script"}
                self.report.add(
                    severity="MEDIUM" if exploitable_context else "LOW",
                    title="Reflected XSS likely" if exploitable_context else "XSS reflection pattern",
                    url=injected_url,
                    normalized_url=normalize_url(url),
                    detail=(
                        "Payload reflected raw in a potentially executable context."
                        if exploitable_context
                        else "Payload reflected raw, but the observed context does not prove script execution."
                    ),
                    category="Cross-Site Scripting",
                    scanner="XSSScanner",
                    evidence={
                        "param": param,
                        "payload": payload,
                        "context": context_name,
                        "status_code": response.status_code,
                    },
                    confidence="MEDIUM" if exploitable_context else "LOW",
                    proof_level="reflected" if exploitable_context else "heuristic",
                    tags=["xss", "reflection"],
                    param=param,
                    payload=payload,
                )
                break

    def scan(
        self,
        url: str,
        html: str | None = None,
        context: ScanContext | None = None,
    ) -> None:
        baseline = html or (context.text if context else "")
        if context is not None and context.target.query:
            self._test_reflection(url, baseline)
        if html:
            self._detect_dom_patterns(url, html)
