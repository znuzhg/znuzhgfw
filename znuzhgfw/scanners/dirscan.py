from __future__ import annotations

from threading import Lock
from urllib.parse import urljoin

from znuzhgfw.core.payloads import COMMON_PATHS
from znuzhgfw.core.scanner_base import ScannerBase
from znuzhgfw.core.utils import ScanContext, normalize_url


INTERESTING_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403}
EXPECTED_COMMON_PATHS = {"/admin", "/login"}
SENSITIVE_COMMON_PATHS = {"/.git/", "/backup", "/old", "/phpinfo.php"}


class DirectoryScanner(ScannerBase):
    def __init__(self, session, logger, report, config=None):
        super().__init__(session, logger, report, config)
        self._scanned_hosts: set[str] = set()
        self._lock = Lock()

    def should_scan(self, context: ScanContext) -> bool:
        return context.is_document and not self.config.skip_dirscan

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
        if context is None:
            return

        base = context.target.host_url
        if not self._mark_host(base):
            return

        self.logger.log(f"[DIR] Scanning common paths at {base}")
        for path in COMMON_PATHS:
            target = urljoin(base, path)
            try:
                response = self.session.get(
                    target,
                    verify=False,
                    timeout=10,
                    allow_redirects=False,
                )
            except Exception as exc:
                self.logger.log(f"[DIR] Error {target}: {exc}")
                continue

            if response.status_code not in INTERESTING_STATUSES:
                continue

            normalized_target = normalize_url(target)
            if path in SENSITIVE_COMMON_PATHS:
                severity = "LOW"
                title = "Exposed common endpoint"
            else:
                severity = "INFO"
                title = "Notable endpoint discovered"

            self.report.add(
                severity=severity,
                title=title,
                url=normalized_target,
                normalized_url=normalized_target,
                detail=(
                    "A common endpoint responded successfully. Common login/admin paths are "
                    "reported as notable inventory rather than as a direct vulnerability."
                ),
                category="Content Discovery",
                scanner="DirectoryScanner",
                evidence={
                    "path": path,
                    "status_code": response.status_code,
                    "location": response.headers.get("Location", ""),
                },
                confidence="HIGH",
                proof_level="verified",
                tags=[
                    "common-endpoint" if path in EXPECTED_COMMON_PATHS else "inventory",
                ],
                fingerprint=f"dirscan:{context.target.host}:{path}",
            )


DrScanScanner = DirectoryScanner
