import time
from urllib.parse import urlparse, parse_qs, urlencode

from znuzhgfw.core.payloads import BOOLEAN_PAIRS, SQL_ERROR_PATTERNS, TIME_PAYLOADS
from znuzhgfw.core.scanner_base import ScannerBase


class SQLiScanner(ScannerBase):
    def _fingerprint(self, text: str, status_code: int):
        return {
            "status": status_code,
            "length": len(text),
            "td_count": text.count("<td>"),
        }

    def _similar(self, fp1, fp2, length_tolerance=0.05, td_tolerance=2):
        if fp1["status"] != fp2["status"]:
            return False
        len1, len2 = fp1["length"], fp2["length"]
        max_len = max(len1, len2, 1)
        len_diff_ratio = abs(len1 - len2) / max_len
        td_diff = abs(fp1["td_count"] - fp2["td_count"])
        return len_diff_ratio <= length_tolerance and td_diff <= td_tolerance

    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return url
        qs[param] = [payload]
        new_q = urlencode(qs, doseq=True)
        return parsed._replace(query=new_q).geturl()

    def _test_get_params(self, url: str):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return

        self.logger.log(f"[SQLi] Testing GET params for {url}")
        try:
            base_resp = self.session.get(url, verify=False, timeout=10)
        except Exception as e:
            self.logger.log(f"[SQLi] Baseline error for {url}: {e}")
            return
        base_fp = self._fingerprint(base_resp.text, base_resp.status_code)

        for param in qs.keys():
            # Boolean
            for true_p, false_p in BOOLEAN_PAIRS:
                try:
                    r_true = self.session.get(
                        self._inject(url, param, true_p), verify=False, timeout=10
                    )
                    r_false = self.session.get(
                        self._inject(url, param, false_p), verify=False, timeout=10
                    )
                except Exception as e:
                    self.logger.log(f"[SQLi] Bool error {url}: {e}")
                    continue

                fp_true = self._fingerprint(r_true.text, r_true.status_code)
                fp_false = self._fingerprint(r_false.text, r_false.status_code)

                if not self._similar(fp_true, fp_false):
                    detail = (
                        f"Param: {param}\nTRUE: {true_p}\nFALSE: {false_p}\n"
                        "Response fingerprints differ."
                    )
                    self.report.add(
                        severity="medium",
                        title="SQLi Boolean-based suspicion",
                        url=url,
                        detail=detail,
                        category="SQL Injection",
                        scanner="SQLiScanner",
                    )

            # Error-based
            for payload in ["'", "\"", "`", "1'; SELECT 1 --"]:
                try:
                    inj_url = self._inject(url, param, payload)
                    r = self.session.get(inj_url, verify=False, timeout=10)
                except Exception as e:
                    self.logger.log(f"[SQLi] Error-based error {url}: {e}")
                    continue
                lower = r.text.lower()
                if any(pat in lower for pat in SQL_ERROR_PATTERNS):
                    detail = f"Param: {param}\nPayload: {payload}\nSQL error pattern found."
                    self.report.add(
                        severity="high",
                        title="SQLi Error-based",
                        url=inj_url,
                        detail=detail,
                        category="SQL Injection",
                        scanner="SQLiScanner",
                    )

            # Time-based
            try:
                t0 = time.time()
                self.session.get(url, verify=False, timeout=10)
                base_t = time.time() - t0
            except Exception:
                base_t = 0.5

            for payload in TIME_PAYLOADS:
                try:
                    inj_url = self._inject(url, param, payload)
                    t0 = time.time()
                    self.session.get(inj_url, verify=False, timeout=10)
                    delay = time.time() - t0
                    extra = delay - base_t
                except Exception as e:
                    self.logger.log(f"[SQLi] Time-based error {url}: {e}")
                    continue

                if extra > 2.5:
                    detail = (
                        f"Param: {param}\nPayload: {payload}\nExtra delay: {extra:.2f}s"
                    )
                    self.report.add(
                        severity="high",
                        title="SQLi Time-based (Blind) suspicion",
                        url=inj_url,
                        detail=detail,
                        category="SQL Injection",
                        scanner="SQLiScanner",
                    )

    def _test_forms(self, url: str, html: str):
        # Basit: 'ad', 'soyad', 'il' formu gibi POST paramları için payload yollanabilirdi.
        # Bu v0.2'de yalın bırakıyoruz, istersen sonra derinleştiririz.
        pass

    def scan(self, url: str, html: str | None = None):
        self._test_get_params(url)
        if html:
            self._test_forms(url, html)
SQLScanner = SQLiScanner
