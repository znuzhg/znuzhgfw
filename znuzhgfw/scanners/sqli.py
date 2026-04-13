from __future__ import annotations

import re
import statistics
import time

from znuzhgfw.core.payloads import BOOLEAN_PAIRS, SQL_ERROR_PATTERNS, TIME_PAYLOADS
from znuzhgfw.core.scanner_base import ScannerBase
from znuzhgfw.core.utils import (
    ScanContext,
    get_query_params,
    inject_param_to_url,
    is_candidate_param,
    normalize_url,
)


class SQLiScanner(ScannerBase):
    def _fingerprint(self, text: str, status_code: int) -> dict[str, int]:
        return {
            "status": status_code,
            "length": len(text),
            "table_cells": text.count("<td>"),
        }

    def _similar(
        self,
        left: dict[str, int],
        right: dict[str, int],
        *,
        length_tolerance: float = 0.05,
        cell_tolerance: int = 2,
    ) -> bool:
        if left["status"] != right["status"]:
            return False
        max_length = max(left["length"], right["length"], 1)
        length_delta = abs(left["length"] - right["length"]) / max_length
        cell_delta = abs(left["table_cells"] - right["table_cells"])
        return length_delta <= length_tolerance and cell_delta <= cell_tolerance

    def _measure_average_delay(self, url: str, repeats: int = 2) -> list[float]:
        samples: list[float] = []
        for _ in range(repeats):
            started_at = time.time()
            self.session.get(url, verify=False, timeout=10)
            samples.append(time.time() - started_at)
        return samples

    def should_scan(self, context: ScanContext) -> bool:
        return bool(context.target.query) and not context.is_static

    def scan(
        self,
        url: str,
        html: str | None = None,
        context: ScanContext | None = None,
    ) -> None:
        params = get_query_params(url)
        if not params:
            return

        self.logger.log(f"[SQLi] Testing GET params for {normalize_url(url)}")
        try:
            baseline_response = context.response or self.session.get(
                url,
                verify=False,
                timeout=10,
            )
        except Exception as exc:
            self.logger.log(f"[SQLi] Baseline error for {url}: {exc}")
            return

        baseline_body = baseline_response.text
        baseline_body_lower = baseline_body.lower()
        baseline_fp = self._fingerprint(
            baseline_body,
            baseline_response.status_code,
        )

        for param in params:
            if not is_candidate_param(param, "sqli"):
                continue

            for true_payload, false_payload in BOOLEAN_PAIRS:
                try:
                    true_response = self.session.get(
                        inject_param_to_url(url, param, true_payload),
                        verify=False,
                        timeout=10,
                    )
                    false_response = self.session.get(
                        inject_param_to_url(url, param, false_payload),
                        verify=False,
                        timeout=10,
                    )
                except Exception as exc:
                    self.logger.log(f"[SQLi] Boolean error {url}: {exc}")
                    continue

                true_fp = self._fingerprint(true_response.text, true_response.status_code)
                false_fp = self._fingerprint(false_response.text, false_response.status_code)
                if self._similar(true_fp, false_fp):
                    continue

                true_matches_baseline = self._similar(true_fp, baseline_fp)
                false_matches_baseline = self._similar(false_fp, baseline_fp)
                if true_matches_baseline == false_matches_baseline:
                    continue

                self.report.add(
                    severity="LOW",
                    title="SQLi boolean anomaly",
                    url=normalize_url(url),
                    normalized_url=normalize_url(url),
                    detail=(
                        "Baseline, TRUE and FALSE responses diverged in a way consistent with boolean-controlled behavior."
                    ),
                    category="SQL Injection",
                    scanner="SQLiScanner",
                    evidence={
                        "param": param,
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "baseline": baseline_fp,
                        "true": true_fp,
                        "false": false_fp,
                    },
                    confidence="MEDIUM",
                    proof_level="heuristic",
                    tags=["sqli", "boolean-based"],
                    param=param,
                )
                break

            error_detected = False
            for payload in ("'", '"', "`", "1'; SELECT 1 --"):
                try:
                    injected_url = inject_param_to_url(url, param, payload)
                    response = self.session.get(injected_url, verify=False, timeout=10)
                except Exception as exc:
                    self.logger.log(f"[SQLi] Error-based error {url}: {exc}")
                    continue

                matched_error = next(
                    (
                        pattern
                        for pattern in SQL_ERROR_PATTERNS
                        if re.search(pattern, response.text, re.IGNORECASE)
                        and not re.search(pattern, baseline_body, re.IGNORECASE)
                    ),
                    "",
                )
                if not matched_error:
                    continue

                self.report.add(
                    severity="MEDIUM",
                    title="SQL error pattern after payload",
                    url=injected_url,
                    normalized_url=normalize_url(url),
                    detail="Database error signatures were introduced after a quote-breaking payload.",
                    category="SQL Injection",
                    scanner="SQLiScanner",
                    evidence={
                        "param": param,
                        "payload": payload,
                        "matched_error": matched_error,
                        "status_code": response.status_code,
                    },
                    confidence="HIGH",
                    proof_level="reflected",
                    tags=["sqli", "error-based"],
                    param=param,
                    payload=payload,
                )
                error_detected = True
                break

            if error_detected:
                continue

            try:
                baseline_samples = self._measure_average_delay(url, repeats=2)
            except Exception:
                baseline_samples = [0.5, 0.5]
            baseline_avg = statistics.mean(baseline_samples)

            for payload in TIME_PAYLOADS:
                injected_url = inject_param_to_url(url, param, payload)
                try:
                    payload_samples = self._measure_average_delay(injected_url, repeats=2)
                except Exception as exc:
                    self.logger.log(f"[SQLi] Time-based error {url}: {exc}")
                    continue

                payload_avg = statistics.mean(payload_samples)
                extra_delay = payload_avg - baseline_avg
                if extra_delay <= 2.5:
                    continue

                self.report.add(
                    severity="MEDIUM",
                    title="SQLi time delay anomaly",
                    url=injected_url,
                    normalized_url=normalize_url(url),
                    detail=(
                        "Repeated time-based probes introduced a stable response delay relative to the baseline."
                    ),
                    category="SQL Injection",
                    scanner="SQLiScanner",
                    evidence={
                        "param": param,
                        "payload": payload,
                        "baseline_delays_s": [round(sample, 2) for sample in baseline_samples],
                        "payload_delays_s": [round(sample, 2) for sample in payload_samples],
                        "baseline_avg_s": round(baseline_avg, 2),
                        "payload_avg_s": round(payload_avg, 2),
                        "extra_delay_s": round(extra_delay, 2),
                    },
                    confidence="MEDIUM",
                    proof_level="reflected",
                    tags=["sqli", "time-based"],
                    param=param,
                    payload=payload,
                )
                break


SQLScanner = SQLiScanner
