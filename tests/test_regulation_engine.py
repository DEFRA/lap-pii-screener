"""Tests for remediation.regulation_engine.RegulationEngine."""
from __future__ import annotations

import pytest

from remediation.regulation_engine import Regulation, RegulationEngine


@pytest.fixture(scope="module")
def engine() -> RegulationEngine:
    return RegulationEngine()


class TestRegulationEngineLookup:
    def test_known_pii_category_returns_ids(self, engine: RegulationEngine) -> None:
        result = engine.lookup("pii_email")

        assert isinstance(result, list)
        assert len(result) > 0

    def test_unknown_category_returns_empty_list(self, engine: RegulationEngine) -> None:
        assert engine.lookup("nonexistent_xyz_category_99") == []

    def test_result_is_sorted(self, engine: RegulationEngine) -> None:
        result = engine.lookup("pii_email")

        assert result == sorted(result)

    def test_returns_list_type(self, engine: RegulationEngine) -> None:
        result = engine.lookup("pii_phone")

        assert isinstance(result, list)

    def test_returns_strings(self, engine: RegulationEngine) -> None:
        result = engine.lookup("pii_email")

        assert all(isinstance(r, str) for r in result)


class TestRegulationEngineGet:
    def test_get_known_regulation_returns_object(self, engine: RegulationEngine) -> None:
        all_regs = engine.all_regulations
        assert len(all_regs) > 0

        first = all_regs[0]
        result = engine.get(first.id)

        assert result is not None
        assert isinstance(result, Regulation)
        assert result.id == first.id

    def test_get_unknown_returns_none(self, engine: RegulationEngine) -> None:
        assert engine.get("NONEXISTENT-REGULATION-9999") is None

    def test_regulation_has_required_fields(self, engine: RegulationEngine) -> None:
        for reg in engine.all_regulations:
            assert reg.id
            assert reg.name


class TestRegulationEngineAllRegulations:
    def test_all_regulations_not_empty(self, engine: RegulationEngine) -> None:
        assert len(engine.all_regulations) > 0

    def test_all_regulations_are_regulation_objects(self, engine: RegulationEngine) -> None:
        for reg in engine.all_regulations:
            assert isinstance(reg, Regulation)

    def test_all_regulations_have_unique_ids(self, engine: RegulationEngine) -> None:
        ids = [r.id for r in engine.all_regulations]

        assert len(ids) == len(set(ids))
