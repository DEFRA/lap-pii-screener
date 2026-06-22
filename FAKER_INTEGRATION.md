# Faker Integration for PII Obfuscation & Reports

This document describes the new Faker integration that enables realistic fake data replacement as an alternative to simple redaction.

## Overview

Users can now choose how to obfuscate PII and secrets:
- **redaction** (default): Replace with `[REDACTED_*]` placeholder tokens
- **faker**: Replace with realistic fake data (names, emails, phone numbers, etc.)
- **all**: Ask for each finding during interactive TUI review

## Features

### 1. Faker-Generated Replacement Values

The new `src/obfuscation/faker_strategies.py` module generates realistic fake data for 54+ categories:

**PII Categories:**
- `pii_email`, `pii_phone`, `pii_ssn`, `pii_credit_card`, `pii_iban`, `pii_passport`, `pii_drivers_license`, `pii_bank_account`, `pii_dob`, `pii_ip_address`, `pii_person_name`, `pii_address`, `pii_mac_address`

**UK-Specific:**
- `pii_nhs_number`, `pii_uk_postcode`, `pii_uk_driving_licence`

**API Keys & Credentials:**
- AWS (access/secret), GCP, Azure, GitHub, GitLab, Stripe, Slack, Twilio, SendGrid, OpenAI, generic API keys
- `hardcoded_password`, `db_password`, `oauth_secret`

**Cryptography & Security:**
- `private_key_rsa`, `encryption_key`, `jwt_token`, `db_connection_string`, `webhook_url_secret`, `generic_secret`

### 2. Enhanced ReviewItem Model

Added `obfuscation_strategy` field to track which strategy was used for each finding:

```python
class ReviewItem(BaseModel):
    # ... existing fields ...
    obfuscation_strategy: str = "redaction"  # "redaction" or "faker"
```

### 3. CLI Enhancement

Added `--obfuscation-strategy` option to the `obfuscate` command:

```bash
# Use Faker for all findings
sensitive-scanner obfuscate ./myrepo --obfuscation-strategy faker

# Use default redaction
sensitive-scanner obfuscate ./myrepo --obfuscation-strategy redaction

# Ask per-finding in TUI
sensitive-scanner obfuscate ./myrepo --obfuscation-strategy all
```

### 4. Interactive TUI Enhancement

During the interactive review (`obfuscate` command), users can toggle between strategies:

- **[f]aker**: Switch between redaction and Faker for the current finding
  - Shows the new replacement value immediately
  - Persists to the session file

```
  Decision [a]pprove / [e]dit+approve / [f]aker / [s]kip / [A]ll-approve / [S]kip-all / [q]uit
```

### 5. HTML Report Tags

Report findings show a visual indicator when Faker was used:

- **"✓ Obfuscated"** badge (green) — Redaction strategy
- **"✦ Faker"** badge (blue) — Faker strategy

### 6. Backward Compatibility

- Default behavior unchanged (redaction)
- Existing sessions work as before
- Old code ignores the new `obfuscation_strategy` field if not present

## Implementation Details

### Files Modified

1. **pyproject.toml**
   - Added `faker==28.1.0` to dependencies

2. **src/obfuscation/faker_strategies.py** (NEW)
   - Implements `get_faker_replacement(category: str) -> str`
   - Maps 54+ finding categories to Faker generators
   - Generates realistic, category-appropriate fake values

3. **src/obfuscation/session.py**
   - Added `obfuscation_strategy` field to `ReviewItem`
   - Updated `from_findings()` to accept and use `obfuscation_strategy` parameter
   - Updated factory method to generate replacements based on strategy

4. **src/obfuscation/reviewer.py**
   - Added `_decide_toggle_faker()` function for [f] option
   - Updated `_build_info_grid()` to display current strategy
   - Updated decision prompt to include Faker toggle option

5. **src/cli.py (obfuscate command)**
   - Added `--obfuscation-strategy` parameter
   - Added validation for strategy values
   - Updated docstring with Faker examples
   - Pass strategy to `ReviewSession.from_findings()`

6. **src/templates/report.html.j2**
   - Added `.obf-faker` CSS class for Faker badge styling
   - Updated obfuscation column to check strategy and display appropriate badge
   - Added Faker icon (✦) for visual distinction

## Usage Examples

### Example 1: Replace all findings with Faker

```bash
sensitive-scanner obfuscate ./my-project --obfuscation-strategy faker
```

This scans the project, marks all findings as approved with Faker replacements, and applies them without user interaction.

### Example 2: Ask per-finding

```bash
sensitive-scanner obfuscate ./my-project --obfuscation-strategy all
```

Opens the interactive TUI where users can:
- Press [a] to approve with current strategy
- Press [f] to toggle to Faker and see the replacement
- Press [e] to edit the replacement manually
- Press [s] to skip

### Example 3: Auto-approve critical with Faker, review others

```bash
sensitive-scanner obfuscate ./my-project \
  --obfuscation-strategy faker \
  --auto-approve critical
```

### Example 4: Generate reports showing Faker usage

```bash
sensitive-scanner obfuscate ./my-project \
  --obfuscation-strategy faker \
  --report obfuscation-report.html
```

The HTML report will show:
- ✓ Findings obfuscated with redaction
- ✦ Findings obfuscated with Faker

## Testing the Integration

### Setup

```bash
# 1. Install uv package manager
pip install uv

# 2. Sync project dependencies (including dev dependencies)
uv sync --extra dev

# 3. Verify Faker is installed
python -c "from faker import Faker; print(Faker().name())"
```

### Manual Testing

```bash
# Test Faker strategy module directly
python -c "
from src.obfuscation.faker_strategies import get_faker_replacement
print('Email:', get_faker_replacement('pii_email'))
print('Phone:', get_faker_replacement('pii_phone'))
print('SSN:', get_faker_replacement('pii_ssn'))
"

# Run a test scan with Faker
sensitive-scanner obfuscate ./test-project --obfuscation-strategy faker --dry-run

# Generate an HTML report
sensitive-scanner obfuscate ./test-project \
  --obfuscation-strategy faker \
  --report test-report.html
```

### Automated Testing

```bash
# Run the full test suite
uv run pytest tests/ -v --cov=src

# Run specific obfuscation tests
uv run pytest tests/test_obfuscation.py -v
uv run pytest tests/test_reviewer.py -v

# Run CLI tests
uv run pytest tests/test_cli.py::test_obfuscate -v
```

## Data Quality Notes

### Faker Advantages

1. **Realistic**: Generated data looks like real data (proper formats, plausible values)
2. **Type-Preserving**: Email looks like an email, phone looks like a phone number
3. **Testable**: Code using fake data is more likely to pass validation checks
4. **Privacy-Friendly**: Easy to share test data without exposing real PII
5. **Deterministic (seed-based)**: Can optionally seed Faker for reproducible results

### Faker Limitations

1. **Not 100% Realistic**: Some generated values may not perfectly match real-world patterns
2. **Categories Not Found**: Unknown categories fall back to generic 32-char passwords
3. **Locale-Specific**: Some generators (addresses, phone formats) are locale-specific (defaults to English)
4. **Performance**: Slower than simple string replacement (negligible for typical codebases <100K files)

## Future Enhancements

1. **Seed-Based Reproducibility**: Allow users to seed Faker for deterministic generation
2. **Locale Support**: Let users specify locales (e.g., `--faker-locale fr_FR`)
3. **Custom Mappings**: Allow users to define custom category→Faker method mappings
4. **Preservation Rules**: Smart preservation of field lengths/formats for backward compatibility
5. **A/B Testing Support**: Generate multiple variants per finding for testing

## Configuration File Support

Users can specify the default strategy in `sensitive-scanner.yaml`:

```yaml
obfuscation:
  strategy: faker
  # or: redaction, all
```

## Troubleshooting

### Issue: "faker" strategy not recognized
**Solution**: Ensure Faker is installed: `pip install faker`

### Issue: Unknown category falls back to generic password
**Solution**: This is expected for rare categories. The fallback ensures nothing breaks.

### Issue: HTML report doesn't show Faker badge
**Solution**: 
1. Verify the session file was saved with strategy info
2. Check that findings have `obfuscation_strategy == "faker"`
3. Ensure HTML report was generated with updated template

## References

- **Faker Documentation**: https://faker.readthedocs.io/
- **Project Structure**: See `docs/design/HIGH-LEVEL-DESIGN.md`
- **Obfuscation Guide**: See `docs/guides/obfuscation.md`
