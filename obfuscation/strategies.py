"""Category → replacement token mapping for obfuscation."""
from __future__ import annotations

_REPLACEMENTS: dict[str, str] = {
    # PII
    "pii_email":              "[REDACTED_EMAIL]",
    "pii_phone":              "[REDACTED_PHONE]",
    "pii_ssn":                "[REDACTED_SSN]",
    "pii_credit_card":        "[REDACTED_CREDIT_CARD]",
    "pii_iban":               "[REDACTED_IBAN]",
    "pii_passport":           "[REDACTED_PASSPORT]",
    "pii_drivers_license":    "[REDACTED_DRIVERS_LICENSE]",
    "pii_bank_account":       "[REDACTED_BANK_ACCOUNT]",
    "pii_dob":                "[REDACTED_DOB]",
    "pii_ip_address":         "[REDACTED_IP]",
    "pii_person_name":        "[REDACTED_NAME]",
    "pii_address":            "[REDACTED_ADDRESS]",
    "pii_mac_address":        "[REDACTED_MAC]",
    # UK-specific
    "pii_nhs_number":         "[REDACTED_NHS_NUMBER]",
    "pii_uk_postcode":        "[REDACTED_POSTCODE]",
    "pii_uk_driving_licence": "[REDACTED_DRIVING_LICENCE]",
    # API keys
    "api_key_aws_access":     "[REDACTED_AWS_ACCESS_KEY]",
    "api_key_aws_secret":     "[REDACTED_AWS_SECRET_KEY]",
    "api_key_gcp":            "[REDACTED_GCP_API_KEY]",
    "api_key_azure":          "[REDACTED_AZURE_KEY]",
    "api_key_github":         "[REDACTED_GITHUB_TOKEN]",
    "api_key_gitlab":         "[REDACTED_GITLAB_TOKEN]",
    "api_key_stripe":         "[REDACTED_STRIPE_KEY]",
    "api_key_slack":          "[REDACTED_SLACK_TOKEN]",
    "api_key_twilio":         "[REDACTED_TWILIO_TOKEN]",
    "api_key_sendgrid":       "[REDACTED_SENDGRID_KEY]",
    "api_key_openai":         "[REDACTED_OPENAI_KEY]",
    "api_key_generic":        "[REDACTED_API_KEY]",
    # Credentials
    "hardcoded_password":     "[REDACTED_PASSWORD]",
    "db_password":            "[REDACTED_DB_PASSWORD]",
    "oauth_secret":           "[REDACTED_OAUTH_SECRET]",
    # Cryptography
    "private_key_rsa":        "[REDACTED_RSA_PRIVATE_KEY]",
    "encryption_key":         "[REDACTED_ENCRYPTION_KEY]",
    "jwt_token":              "[REDACTED_JWT]",
    # Database
    "db_connection_string":   "[REDACTED_DB_CONNECTION]",
    # Misc
    "webhook_url_secret":     "[REDACTED_WEBHOOK_URL]",
    "generic_secret":         "[REDACTED_SECRET]",
}


def get_replacement(category: str) -> str:
    """Return the obfuscation placeholder token for *category*.

    Falls back to ``'[REDACTED]'`` for unknown categories.
    """
    return _REPLACEMENTS.get(category, "[REDACTED]")
