"""Generate realistic fake data to replace PII using Faker library."""
from __future__ import annotations

from faker import Faker

# Use a single Faker instance
_faker = Faker()

# Category → Faker method mapping
_FAKER_GENERATORS: dict[str, callable] = {
    # PII
    "pii_email":              lambda: _faker.email(),
    "pii_phone":              lambda: _faker.phone_number(),
    "pii_ssn":                lambda: _faker.ssn(),
    "pii_credit_card":        lambda: _faker.credit_card_number(card_type=None),
    "pii_iban":               lambda: _faker.iban(),
    "pii_passport":           lambda: _faker.bothify(text='??########'),
    "pii_drivers_license":    lambda: _faker.bothify(text='??########'),
    "pii_bank_account":       lambda: _faker.bban(),
    "pii_dob":                lambda: _faker.date_of_birth(minimum_age=18, maximum_age=80).isoformat(),
    "pii_ip_address":         lambda: _faker.ipv4(),
    "pii_person_name":        lambda: _faker.name(),
    "pii_address":            lambda: _faker.address().replace('\n', ', '),
    "pii_mac_address":        lambda: _faker.mac_address(),
    # UK-specific
    "pii_nhs_number":         lambda: _faker.bothify(text='###-###-####'),
    "pii_uk_postcode":        lambda: _faker.postcode(),
    "pii_uk_driving_licence": lambda: _faker.bothify(text='??#######'),
    # API keys (generate plausible-looking tokens)
    "api_key_aws_access":     lambda: f"AKIA{_faker.bothify(text='?'*16).upper()}",
    "api_key_aws_secret":     lambda: _faker.password(length=40, special_chars=True),
    "api_key_gcp":            lambda: _faker.password(length=39),
    "api_key_azure":          lambda: _faker.password(length=88),
    "api_key_github":         lambda: f"ghp_{_faker.bothify(text='?'*36).lower()}",
    "api_key_gitlab":         lambda: _faker.password(length=20),
    "api_key_stripe":         lambda: f"sk_live_{_faker.bothify(text='?'*24).lower()}",
    "api_key_slack":          lambda: f"xoxb-{_faker.bothify(text='?'*9)}-{_faker.bothify(text='?'*12)}-{_faker.bothify(text='?'*32)}",
    "api_key_twilio":         lambda: _faker.password(length=32),
    "api_key_sendgrid":       lambda: f"SG.{_faker.password(length=69)}",
    "api_key_openai":         lambda: f"sk-{_faker.bothify(text='?'*48).lower()}",
    "api_key_generic":        lambda: _faker.password(length=32),
    # Credentials
    "hardcoded_password":     lambda: _faker.password(length=16, special_chars=True),
    "db_password":            lambda: _faker.password(length=16, special_chars=True),
    "oauth_secret":           lambda: _faker.password(length=32),
    # Cryptography
    "private_key_rsa":        lambda: _faker.password(length=64),
    "encryption_key":         lambda: _faker.password(length=32),
    "jwt_token":              lambda: _faker.password(length=256),
    # Database
    "db_connection_string":   lambda: f"Server=db-{_faker.word()}.example.com;Database={_faker.word()};User=admin;Password={_faker.password()}",
    # Misc
    "webhook_url_secret":     lambda: _faker.password(length=32),
    "generic_secret":         lambda: _faker.password(length=32),
}


def set_seed(seed: int | None = None) -> None:
    """Set the Faker seed for reproducible generation.
    
    Pass None to disable seeding (random mode).
    """
    if seed is not None:
        Faker.seed(seed)


def get_faker_replacement(category: str) -> str:
    """Generate a realistic fake value for *category*.

    Falls back to a generic password for unknown categories.
    
    Args:
        category: The finding category (e.g., 'pii_email', 'api_key_aws_access')
    
    Returns:
        A realistic fake value appropriate for the category.
    """
    generator = _FAKER_GENERATORS.get(category)
    if generator:
        try:
            return generator()
        except Exception:
            # If generation fails, return a safe fallback
            return _faker.password(length=32)
    # Unknown category — return generic password
    return _faker.password(length=32)

