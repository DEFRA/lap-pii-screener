"""Tests for remediation.engine.RemediationEngine."""
from __future__ import annotations

import pytest

from remediation.engine import RemediationEngine, RemediationRule


@pytest.fixture(scope="module")
def engine() -> RemediationEngine:
    return RemediationEngine()


# --------------------------------------------------------------------------- #
# lookup                                                                       #
# --------------------------------------------------------------------------- #


class TestLookup:
    def test_known_category_returns_rule(self, engine: RemediationEngine) -> None:
        rule = engine.lookup("pii_email")

        assert rule is not None
        assert isinstance(rule, RemediationRule)

    def test_unknown_category_returns_none(self, engine: RemediationEngine) -> None:
        assert engine.lookup("nonexistent_category_xyz_99") is None

    def test_rule_has_severity(self, engine: RemediationEngine) -> None:
        rule = engine.lookup("hardcoded_password")

        assert rule is not None
        assert rule.severity in {"critical", "high", "medium", "low", "info"}

    def test_rule_has_fix_steps(self, engine: RemediationEngine) -> None:
        rule = engine.lookup("hardcoded_password")

        assert rule is not None
        assert len(rule.fix_steps) > 0

    def test_rule_has_description(self, engine: RemediationEngine) -> None:
        rule = engine.lookup("api_key_aws_access")

        assert rule is not None
        assert rule.description

    @pytest.mark.parametrize("category", [
        "pii_email",
        "pii_phone",
        "api_key_aws_access",
        "hardcoded_password",
        "jwt_token",
        "generic_secret",
    ])
    def test_standard_categories_are_present(self, engine: RemediationEngine, category: str) -> None:
        assert engine.lookup(category) is not None


# --------------------------------------------------------------------------- #
# resolve                                                                      #
# --------------------------------------------------------------------------- #


class TestResolve:
    def test_exact_match(self, engine: RemediationEngine) -> None:
        category, rule = engine.resolve("pii_email")

        assert category == "pii_email"
        assert rule is not None

    def test_hyphen_normalised_to_underscore_before_exact_match(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("pii-email")

        assert category == "pii_email"
        assert rule is not None

    def test_substring_match(self, engine: RemediationEngine) -> None:
        # "hardcoded_password" is a known key; rule_id that contains it should match
        category, rule = engine.resolve("java:my_hardcoded_password_rule")

        assert category == "hardcoded_password"

    def test_keyword_aws_access(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("aws-access-key-id")

        assert category == "api_key_aws_access"

    def test_keyword_aws_secret(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("aws_secret_access_key")

        assert category == "api_key_aws_secret"

    def test_keyword_github(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("github_token_leaked")

        assert category == "api_key_github"

    def test_keyword_stripe(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("stripe_secret_key")

        assert category == "api_key_stripe"

    def test_keyword_email(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("email_address_detected")

        assert category == "pii_email"

    def test_keyword_password(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("some_password_field")

        assert category == "hardcoded_password"

    def test_keyword_jwt(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("jwt_bearer_token")

        assert category == "jwt_token"

    def test_keyword_ssn(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("ssn_number_detected")

        assert category == "pii_ssn"

    def test_keyword_credit_card(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("credit_card_number")

        assert category == "pii_credit_card"

    def test_keyword_private_key(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("rsa_private_key")

        assert category == "private_key_rsa"

    def test_sonarqube_s2068_rule(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("java:S2068")

        assert category == "hardcoded_password"

    def test_sonarqube_s1313_rule(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("java:S1313")

        assert category == "pii_ip_address"

    def test_fallback_to_generic_secret(self, engine: RemediationEngine) -> None:
        category, _ = engine.resolve("zzz_no_match_xyz_12345")

        assert category == "generic_secret"

    def test_returns_tuple_of_two(self, engine: RemediationEngine) -> None:
        result = engine.resolve("pii_email")

        assert len(result) == 2
