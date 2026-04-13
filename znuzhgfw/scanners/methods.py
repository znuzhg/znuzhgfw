from __future__ import annotations

from threading import Lock

from znuzhgfw.core.scanner_base import ScannerBase
from znuzhgfw.core.utils import ScanContext, is_sensitive_method_target


RISKY_METHODS = {"CONNECT", "DELETE", "PATCH", "PUT", "TRACE"}


class MethodsScanner(ScannerBase):
    asset_scan_enabled = True

    def __init__(self, session, logger, report, config=None):
        super().__init__(session, logger, report, config)
        self._scanned_hosts: set[str] = set()
        self._lock = Lock()

    def should_scan(self, context: ScanContext) -> bool:
        return is_sensitive_method_target(context.target) or (
            context.is_static and self.config.scan_assets
        )

    def _mark_host(self, host_url: str) -> bool:
        with self._lock:
            if host_url in self._scanned_hosts:
                return False
            self._scanned_hosts.add(host_url)
            return True

    def scan(
        self,
        url: str,
        html: str | None = None,
        context: ScanContext | None = None,
    ) -> None:
        if context is None or not self._mark_host(context.target.host_url):
            return

        self.logger.log(f"[METHODS] Checking HTTP methods for {context.target.host_url}")
        try:
            options_response = self.session.options(
                context.target.host_url,
                verify=False,
                timeout=10,
            )
        except Exception as exc:
            self.logger.log(f"[METHODS] OPTIONS error {context.target.host_url}: {exc}")
            return

        allow_header = options_response.headers.get("Allow", "")
        allowed_methods = {
            method.strip().upper()
            for method in allow_header.split(",")
            if method.strip()
        }
        risky_allowed = sorted(method for method in allowed_methods if method in RISKY_METHODS)

        if risky_allowed:
            self.report.add(
                severity="LOW",
                title="Risky HTTP methods exposed",
                url=context.target.host_url,
                normalized_url=context.target.host_url,
                detail="The Allow header exposes methods that are more sensitive than standard read-only operations.",
                category="HTTP Methods",
                scanner="MethodsScanner",
                evidence={"allow": sorted(allowed_methods), "risky_methods": risky_allowed},
                confidence="HIGH",
                proof_level="verified",
                tags=["methods", "host-summary"],
                fingerprint=f"methods:allow:{context.target.host}",
            )

        try:
            trace_response = self.session.request(
                "TRACE",
                context.target.host_url,
                verify=False,
                timeout=10,
            )
        except Exception:
            return

        if trace_response.status_code < 400:
            self.report.add(
                severity="LOW",
                title="TRACE method enabled",
                url=context.target.host_url,
                normalized_url=context.target.host_url,
                detail="TRACE responded successfully on the host root.",
                category="HTTP Methods",
                scanner="MethodsScanner",
                evidence={"status_code": trace_response.status_code},
                confidence="HIGH",
                proof_level="verified",
                tags=["methods", "trace"],
                fingerprint=f"methods:trace:{context.target.host}",
            )


MethodScanner = MethodsScanner
