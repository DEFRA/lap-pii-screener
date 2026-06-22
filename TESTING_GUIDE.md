# Faker Integration Testing Guide

## Quick Verification

Before running full tests, verify the basic Python syntax is correct:

```bash
cd c:\Github\lap-pii-screener.worktrees\agents-faker-integration-for-reports

# Check that the modules can be imported
python -c "from src.obfuscation.faker_strategies import get_faker_replacement; print(get_faker_replacement('pii_email'))"
python -c "from src.obfuscation.session import ReviewItem; print(ReviewItem.__fields__)"
python -c "from src.models.finding import Finding; print('OK')"
```

## Unit Test Examples

### Test 1: Faker Generation

```python
# tests/test_faker_strategies.py
from src.obfuscation.faker_strategies import get_faker_replacement, set_seed

def test_faker_email():
    email = get_faker_replacement('pii_email')
    assert '@' in email
    assert '.' in email

def test_faker_phone():
    phone = get_faker_replacement('pii_phone')
    assert len(phone) > 0

def test_faker_ssn():
    ssn = get_faker_replacement('pii_ssn')
    assert len(ssn) > 0

def test_faker_reproducible():
    set_seed(42)
    val1 = get_faker_replacement('pii_email')
    
    set_seed(42)
    val2 = get_faker_replacement('pii_email')
    
    assert val1 == val2  # Same seed produces same value

def test_faker_unknown_category():
    result = get_faker_replacement('unknown_category')
    assert len(result) == 32  # Falls back to 32-char password
```

### Test 2: ReviewItem Strategy

```python
# tests/test_session_faker.py
from src.obfuscation.session import ReviewItem
from src.models.finding import Finding

def test_review_item_has_strategy():
    item = ReviewItem(
        finding_id='test1',
        file='test.py',
        line=1,
        rule_id='rule1',
        category='pii_email',
        severity='high',
        scanners=['test'],
        match_display='john****',
        replacement='john@example.com',
        obfuscation_strategy='faker'
    )
    assert item.obfuscation_strategy == 'faker'

def test_review_item_default_strategy():
    item = ReviewItem(
        finding_id='test1',
        file='test.py',
        line=1,
        rule_id='rule1',
        category='pii_email',
        severity='high',
        scanners=['test'],
        match_display='john****',
        replacement='[REDACTED_EMAIL]'
    )
    assert item.obfuscation_strategy == 'redaction'  # default
```

### Test 3: Session Factory

```python
# tests/test_session_factory.py
from src.obfuscation.session import ReviewSession
from src.models.finding import Finding

def test_from_findings_with_faker():
    findings = [
        Finding(
            id='f1',
            category='pii_email',
            severity='high',
            file='test.py',
            line=10,
            match='john@example.com',
            rule_id='email-rule'
        )
    ]
    
    session = ReviewSession.from_findings(
        findings,
        scan_id='scan1',
        target_path='/tmp',
        obfuscation_strategy='faker'
    )
    
    assert len(session.items) == 1
    item = session.items[0]
    assert item.obfuscation_strategy == 'faker'
    assert '@' in item.replacement  # Should be a real email format

def test_from_findings_with_redaction():
    findings = [
        Finding(
            id='f1',
            category='pii_email',
            severity='high',
            file='test.py',
            line=10,
            match='john@example.com',
            rule_id='email-rule'
        )
    ]
    
    session = ReviewSession.from_findings(
        findings,
        scan_id='scan1',
        target_path='/tmp',
        obfuscation_strategy='redaction'
    )
    
    assert len(session.items) == 1
    item = session.items[0]
    assert item.obfuscation_strategy == 'redaction'
    assert '[REDACTED_EMAIL]' in item.replacement
```

### Test 4: CLI Integration

```bash
# Dry-run test to verify no files are modified
sensitive-scanner obfuscate ./test-repo \
  --obfuscation-strategy faker \
  --dry-run \
  --backup-dir ./backups-fake

# Test with redaction (default)
sensitive-scanner obfuscate ./test-repo \
  --obfuscation-strategy redaction \
  --dry-run \
  --backup-dir ./backups-redact
```

### Test 5: Report Generation

```bash
# Generate HTML report with Faker findings
sensitive-scanner obfuscate ./test-repo \
  --obfuscation-strategy faker \
  --report faker-report.html \
  --dry-run

# Verify the report shows "✦ Faker" badges
grep -c "obf-faker" faker-report.html
```

## Integration Test Workflow

### Setup Test Environment

```bash
# Create a test directory with some PII
mkdir -p /tmp/test-pii-project
cat > /tmp/test-pii-project/config.py << 'EOF'
# Configuration file with PII
DATABASE_PASSWORD = "password123"
ADMIN_EMAIL = "admin@company.com"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
USER_NAME = "John Doe"
PHONE = "555-123-4567"
EOF

cd /tmp/test-pii-project
```

### Test Faker Strategy

```bash
# 1. Scan with Faker strategy (dry-run)
sensitive-scanner obfuscate . \
  --obfuscation-strategy faker \
  --dry-run \
  --report faker-test.html

# 2. Verify HTML report
echo "Checking for Faker badges in report..."
grep "obf-faker" faker-test.html || echo "No Faker badges found"
grep "✦ Faker" faker-test.html || echo "Faker indicator not present"

# 3. Check the session file shows strategy
cat pii-review-session.json | grep obfuscation_strategy
```

### Test Redaction Strategy

```bash
# Compare with redaction strategy
sensitive-scanner obfuscate . \
  --obfuscation-strategy redaction \
  --dry-run \
  --report redaction-test.html

# Verify HTML report has different badges
grep "obf-approved" redaction-test.html || echo "No obfuscation badges found"
```

### Test "All" Strategy

```bash
# This requires interactive input - would need to automate keypresses
# For now, test that the option is accepted:
sensitive-scanner obfuscate . \
  --obfuscation-strategy all \
  --dry-run \
  2>&1 | grep -q "TUI" && echo "All strategy accepted"
```

## Automated Test Suite

Run the complete test suite:

```bash
# Install test dependencies
uv sync --extra dev

# Run all tests
uv run pytest tests/ -v --cov=src --cov-report=html

# Run only faker-related tests
uv run pytest tests/ -k "faker" -v
uv run pytest tests/test_obfuscation.py -v
uv run pytest tests/test_reviewer.py -v
uv run pytest tests/test_session.py -v
```

## Expected Test Results

### All Tests Should Pass

```
tests/test_faker_strategies.py::test_faker_email PASSED
tests/test_faker_strategies.py::test_faker_phone PASSED
tests/test_faker_strategies.py::test_faker_ssn PASSED
tests/test_faker_strategies.py::test_faker_reproducible PASSED
tests/test_faker_strategies.py::test_faker_unknown_category PASSED

tests/test_session_faker.py::test_review_item_has_strategy PASSED
tests/test_session_faker.py::test_review_item_default_strategy PASSED

tests/test_session_factory.py::test_from_findings_with_faker PASSED
tests/test_session_factory.py::test_from_findings_with_redaction PASSED
```

## Regression Testing

Ensure existing functionality still works:

```bash
# Test basic scan (should not be affected)
sensitive-scanner scan ./test-repo --format console

# Test obfuscate without --obfuscation-strategy (should default to redaction)
sensitive-scanner obfuscate ./test-repo --dry-run

# Test existing report generation
sensitive-scanner scan ./test-repo --format html --output test.html
```

## Performance Testing

Faker generation might be slightly slower than simple string replacement:

```bash
# Time a large project scan with redaction
time sensitive-scanner obfuscate ./large-project \
  --obfuscation-strategy redaction \
  --dry-run

# Time the same with Faker
time sensitive-scanner obfuscate ./large-project \
  --obfuscation-strategy faker \
  --dry-run

# Difference should be negligible (< 5% overhead)
```

## Troubleshooting Test Failures

### Issue: "faker module not found"
```bash
pip install faker
```

### Issue: "Invalid obfuscation_strategy"
```bash
# Verify you're using valid values
sensitive-scanner obfuscate ./repo --obfuscation-strategy faker  # ✓
sensitive-scanner obfuscate ./repo --obfuscation-strategy redaction  # ✓
sensitive-scanner obfuscate ./repo --obfuscation-strategy all  # ✓
sensitive-scanner obfuscate ./repo --obfuscation-strategy foobar  # ✗
```

### Issue: Session not saving obfuscation_strategy
```bash
# The field was added to ReviewItem, so new sessions will have it
# Old sessions without the field will default to "redaction"
cat pii-review-session.json | jq '.items[0].obfuscation_strategy'
```

### Issue: HTML report not showing Faker badges
```bash
# Verify:
# 1. obfuscation_strategy was set to "faker" in session
# 2. Decision was set to "approved"
# 3. HTML template was updated (check for .obf-faker class)
cat pii-review-session.json | jq '.items[] | select(.decision=="approved") | .obfuscation_strategy'
grep "obf-faker" report.html
```

## Clean Up

```bash
# Remove test artifacts
rm -rf /tmp/test-pii-project
rm -rf .pii-backups
rm pii-review-session.json
rm faker-test.html redaction-test.html
```
