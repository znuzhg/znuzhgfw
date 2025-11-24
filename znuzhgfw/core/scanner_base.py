from abc import ABC, abstractmethod
from typing import Any

import requests

from .logger import Logger
from .report import Report


class ScannerBase(ABC):
    def __init__(self, session: requests.Session, logger: Logger, report: Report):
        self.session = session
        self.logger = logger
        self.report = report

    @abstractmethod
    def scan(self, url: str, html: str | None = None):
        """
        Her scanner kendi testini uygular.
        html parametresi varsa (önceden fetch edilmişse) kullanabilir.
        """
        ...
