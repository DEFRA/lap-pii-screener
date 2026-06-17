from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Regulation:
    id: str
    name: str
    article: str
    statutory_ref: str
    last_verified: str


class RegulationEngine:
    """Maps PII category keys to applicable UK regulations.

    Loads ``config/regulations.yaml`` at startup and builds an inverted index
    from category → list[Regulation].  Gracefully returns an empty list for
    unknown categories rather than raising.
    """

    def __init__(self) -> None:
        reg_path = Path(__file__).parent.parent / "config" / "regulations.yaml"
        with open(reg_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        # Canonical regulation objects keyed by id
        self._regulations: dict[str, Regulation] = {}
        # Inverted index: category → [regulation_id, ...]
        self._category_map: dict[str, list[str]] = {}

        for entry in data.get("regulations", []):
            reg = Regulation(
                id=entry["id"],
                name=entry["name"],
                article=entry.get("article", ""),
                statutory_ref=entry.get("statutory_ref", ""),
                last_verified=entry.get("last_verified", ""),
            )
            self._regulations[reg.id] = reg
            for category in entry.get("applies_to_categories", []):
                self._category_map.setdefault(category, []).append(reg.id)

    def lookup(self, category: str) -> list[str]:
        """Return a sorted list of regulation IDs that apply to *category*."""
        return sorted(self._category_map.get(category, []))

    def get(self, regulation_id: str) -> Regulation | None:
        """Return the Regulation object for *regulation_id*, or None."""
        return self._regulations.get(regulation_id)

    @property
    def all_regulations(self) -> list[Regulation]:
        """Return all regulations in definition order."""
        return list(self._regulations.values())
