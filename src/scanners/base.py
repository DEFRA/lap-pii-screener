from __future__ import annotations

from abc import ABC, abstractmethod

from models.finding import Finding, ScanConfig


class AbstractScanner(ABC):
    """Common interface every scanner must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier used in Finding.scanners and log messages."""

    @abstractmethod
    async def is_available(self) -> bool:
        """
        Return True if the scanner can run in the current environment
        (binary present, Docker accessible, API reachable, etc.).
        Must never raise.
        """

    @abstractmethod
    async def scan(self, config: ScanConfig) -> list[Finding]:
        """
        Execute the scan and return normalised Finding objects.
        Must never raise — log errors and return an empty list on failure.
        """
