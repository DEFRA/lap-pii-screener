"""Tests for obfuscation.faker_strategies (optional Faker integration)."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import obfuscation.faker_strategies as fs


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _mock_faker() -> MagicMock:
    """Return a MagicMock that mimics the Faker instance API used in generators."""
    mock = MagicMock()
    mock.email.return_value = "fake@example.com"
    mock.phone_number.return_value = "+44 7700 900123"
    mock.ssn.return_value = "123-45-6789"
    mock.credit_card_number.return_value = "4111111111111111"
    mock.iban.return_value = "GB29NWBK60161331926819"
    mock.bothify.return_value = "AB12345678"
    mock.bban.return_value = "12345678901234"
    mock.date_of_birth.return_value.isoformat.return_value = "1990-01-01"
    mock.ipv4.return_value = "192.168.1.1"
    mock.name.return_value = "Jane Smith"
    mock.address.return_value = "123 Fake St\nLondon\nSW1A 1AA"
    mock.mac_address.return_value = "aa:bb:cc:dd:ee:ff"
    mock.postcode.return_value = "SW1A 1AA"
    mock.password.return_value = "P@ssw0rd1234!!"
    mock.word.return_value = "example"
    return mock


# --------------------------------------------------------------------------- #
# get_faker_replacement — when faker is unavailable                            #
# --------------------------------------------------------------------------- #


class TestGetFakerReplacementUnavailable:
    def test_raises_import_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", False)
        with pytest.raises(ImportError, match="faker"):
            fs.get_faker_replacement("pii_email")

    def test_error_message_contains_install_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", False)
        with pytest.raises(ImportError, match="pip install faker"):
            fs.get_faker_replacement("generic_secret")


# --------------------------------------------------------------------------- #
# get_faker_replacement — when faker is available (mocked)                    #
# --------------------------------------------------------------------------- #


class TestGetFakerReplacementAvailable:
    def test_known_category_pii_email(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement("pii_email")
        assert result == "fake@example.com"

    def test_known_category_pii_phone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement("pii_phone")
        assert result == "+44 7700 900123"

    def test_known_category_pii_ssn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        assert fs.get_faker_replacement("pii_ssn") == "123-45-6789"

    def test_known_category_pii_address(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement("pii_address")
        assert "123 Fake St" in result
        assert "\n" not in result  # newlines replaced with ", "

    def test_known_category_pii_dob(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        assert fs.get_faker_replacement("pii_dob") == "1990-01-01"

    def test_known_category_api_key_aws_access(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        mock.bothify.return_value = "abcdefghijklmnop"
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement("api_key_aws_access")
        assert result.startswith("AKIA")

    def test_known_category_api_key_github(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        mock.bothify.return_value = "abcdefghijklmnopqrstuvwxyz0123456789"
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement("api_key_github")
        assert result.startswith("ghp_")

    def test_known_category_api_key_stripe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        mock.bothify.return_value = "abcdefghijklmnopqrstuvwx"
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement("api_key_stripe")
        assert result.startswith("sk_live_")

    def test_known_category_api_key_openai(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement("api_key_openai")
        assert result.startswith("sk-")

    def test_known_category_api_key_sendgrid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement("api_key_sendgrid")
        assert result.startswith("SG.")

    def test_known_category_api_key_slack(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement("api_key_slack")
        assert result.startswith("xoxb-")

    def test_known_category_db_connection_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement("db_connection_string")
        assert "Server=" in result

    def test_unknown_category_falls_back_to_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        mock.password.return_value = "fallback-secret"
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement("completely_unknown_xyz")
        assert result == "fallback-secret"

    def test_generator_exception_uses_password_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        mock.email.side_effect = RuntimeError("faker blew up")
        mock.password.return_value = "safe-fallback"
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement("pii_email")
        assert result == "safe-fallback"

    @pytest.mark.parametrize("category", list(fs._FAKER_GENERATORS.keys()))
    def test_all_known_categories_return_nonempty_string(
        self, monkeypatch: pytest.MonkeyPatch, category: str
    ) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        result = fs.get_faker_replacement(category)
        assert isinstance(result, str)
        assert len(result) > 0


# --------------------------------------------------------------------------- #
# set_seed                                                                     #
# --------------------------------------------------------------------------- #


class TestSetSeed:
    def test_raises_import_error_when_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", False)
        with pytest.raises(ImportError, match="faker"):
            fs.set_seed(42)

    def test_calls_seed_instance_with_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        fs.set_seed(99)
        mock.seed_instance.assert_called_once_with(99)

    def test_none_seed_does_not_call_seed_instance(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        fs.set_seed(None)
        mock.seed_instance.assert_not_called()

    def test_zero_seed_calls_seed_instance(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock = _mock_faker()
        monkeypatch.setattr(fs, "FAKER_AVAILABLE", True)
        monkeypatch.setattr(fs, "_faker", mock)
        fs.set_seed(0)
        mock.seed_instance.assert_called_once_with(0)
