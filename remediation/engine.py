from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class RemediationRule:
    severity: str
    description: str
    fix_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


# Keyword-based fallback mapping from scanner rule IDs → our category keys
_KEYWORD_MAP: list[tuple[list[str], str]] = [
    (["aws_access", "aws-access", "AKIA"], "api_key_aws_access"),
    (["aws_secret", "aws-secret", "aws_key"], "api_key_aws_secret"),
    (["gcp", "google_api", "google-api"], "api_key_gcp"),
    (["azure"], "api_key_azure"),
    (["github", "gh_token", "ghp_"], "api_key_github"),
    (["gitlab"], "api_key_gitlab"),
    (["stripe"], "api_key_stripe"),
    (["slack"], "api_key_slack"),
    (["twilio"], "api_key_twilio"),
    (["sendgrid"], "api_key_sendgrid"),
    (["openai", "sk-"], "api_key_openai"),
    (["password", "passwd", "pwd"], "hardcoded_password"),
    (["jwt", "json_web_token"], "jwt_token"),
    (["oauth", "client_secret"], "oauth_secret"),
    (["rsa", "ec_private", "openssh", "private_key"], "private_key_rsa"),
    (["private", "key"], "private_key_generic"),
    (["aes", "des", "encryption_key", "cipher_key"], "encryption_key"),
    (["connection_string", "connstr", "jdbc", "mongo", "redis", "mysql", "postgresql"], "db_connection_string"),
    (["db_password", "database_password"], "db_password"),
    (["webhook"], "webhook_url_secret"),
    (["email"], "pii_email"),
    (["phone", "tel"], "pii_phone"),
    (["ssn", "social_security"], "pii_ssn"),
    (["credit_card", "creditcard", "card_number", "luhn"], "pii_credit_card"),
    (["passport"], "pii_passport"),
    (["drivers_license", "driver_license", "dl_number"], "pii_drivers_license"),
    (["iban", "bank_account"], "pii_iban_bank"),
    (["date_of_birth", "dob"], "pii_date_of_birth"),
    (["ip_address", "ipv4"], "pii_ip_address"),
    (["person", "name"], "pii_person_name"),
    (["address"], "pii_address"),
    # SonarQube S-rule numbers (appear as e.g. "java:S2068" → lowercased to "java:s2068")
    (["s2068", "s6890", "s5344", "s105"], "hardcoded_password"),  # hard-coded credentials
    (["s1313"],                            "pii_ip_address"),       # hard-coded IP address
    (["s5547", "s4790", "s5542"],          "encryption_key"),       # weak cipher/hash/crypto
    (["s2077", "s3649"],                   "db_connection_string"), # SQL injection / query
]


class RemediationEngine:
    def __init__(self) -> None:
        rules_path = Path(__file__).parent / "rules.yaml"
        with open(rules_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        self._rules: dict[str, RemediationRule] = {}
        for key, val in data.get("categories", {}).items():
            self._rules[key] = RemediationRule(
                severity=val.get("severity", "medium"),
                description=val.get("description", ""),
                fix_steps=val.get("fix_steps", []),
                references=val.get("references", []),
            )

    def lookup(self, category: str) -> Optional[RemediationRule]:
        """Exact-key lookup — returns None if category not in catalogue."""
        return self._rules.get(category)

    def resolve(self, rule_id: str) -> tuple[str, Optional[RemediationRule]]:
        """
        Map an arbitrary scanner rule ID to a category key and return
        the corresponding rule.  Falls back to keyword heuristics, then
        to 'generic_secret'.
        """
        rule_id_lower = rule_id.lower().replace("-", "_")

        # 1. Exact match
        if rule_id_lower in self._rules:
            return rule_id_lower, self._rules[rule_id_lower]

        # 2. Substring match against known keys
        for key in self._rules:
            if key in rule_id_lower:
                return key, self._rules[key]

        # 3. Keyword heuristics
        for keywords, category in _KEYWORD_MAP:
            if any(kw in rule_id_lower for kw in keywords):
                return category, self._rules.get(category)

        # 4. Fallback
        return "generic_secret", self._rules.get("generic_secret")
