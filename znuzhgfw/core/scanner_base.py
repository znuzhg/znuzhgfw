from abc import ABC, abstractmethod
from typing import Any

import requests

from .logger import Logger
from .report import Report
from .utils import ScanConfig, ScanContext


class ScannerBase(ABC):
    asset_scan_enabled = False

    def __init__(
        self,
        session: requests.Session,
        logger: Logger,
        report: Report,
        config: ScanConfig | None = None,
    ):
        self.session = session
        self.logger = logger
        self.report = report
        self.config = config or ScanConfig()

    def should_scan(self, context: ScanContext) -> bool:
        return True

    def can_scan_context(self, context: ScanContext) -> bool:
        if context.is_static:
            return self.config.scan_assets and self.asset_scan_enabled
        return True

    @abstractmethod
    def scan(
        self,
        url: str,
        html: str | None = None,
        context: ScanContext | None = None,
    ):
        """
        Her scanner kendi testini uygular.
        html parametresi varsa (önceden fetch edilmişse) kullanabilir.
        """
        ...
