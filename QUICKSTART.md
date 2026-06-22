# Quick Start: Faker Integration

Get started with realistic fake data replacement in 5 minutes!

## Installation

```bash
# Install Faker dependency
pip install faker

# Or sync the entire project
uv sync
```

## Basic Usage

### Replace All Findings with Fake Data

```bash
sensitive-scanner obfuscate ./my-project --obfuscation-strategy faker
```

This will:
1. Scan for PII and secrets
2. Replace all findings with realistic fake data (names, emails, phone numbers, etc.)
3. Create backups in `.pii-backups/`
4. Show the obfuscation report

### Preview Before Applying (Dry-Run)

```bash
sensitive-scanner obfuscate ./my-project \
  --obfuscation-strategy faker \
  --dry-run \
  --report faker-preview.html
```

Open `faker-preview.html` to see what would be replaced. Look for the blue "✦ Faker" badges.

### Interactive Mode: Choose per Finding

```bash
sensitive-scanner obfuscate ./my-project
```

Then during the interactive review:
- Press **[a]** to approve with current strategy
- Press **[f]** to toggle to Faker and see the fake value
- Press **[s]** to skip (leave unchanged)
- Press **[e]** to edit the replacement manually

### Compare Strategies

```bash
# Redaction version
sensitive-scanner obfuscate ./project \
  --obfuscation-strategy redaction \
  --dry-run \
  --report redacted.html

# Faker version
sensitive-scanner obfuscate ./project \
  --obfuscation-strategy faker \
  --dry-run \
  --report faker.html

# Now compare the two HTML reports!
```

## What Gets Replaced with Fake Data

### Personal Information
- **Emails**: john@example.com
- **Names**: Jane Smith
- **Phone Numbers**: (555) 123-4567
- **Dates of Birth**: 1985-03-15
- **Addresses**: 123 Main St, Springfield, IL
- **SSNs**: 123-45-6789
- **Passport Numbers**: AB1234567

### Financial Data
- **Credit Cards**: 4532015112830366
- **Bank Accounts**: DE89370400440532013000
- **IBANs**: GB82WEST12345698765432

### Technical Credentials
- **API Keys**: AKIA followed by 16 characters
- **Passwords**: 16-character random strings
- **Database Connection Strings**: `Server=db-word.example.com;...`
- **JWT Tokens**: 256-character tokens
- **RSA Keys**: 64-character private keys

## Understanding the Report

Open the HTML report to see:

### Green Badges: "✓ Obfuscated"
These findings were replaced with `[REDACTED]` placeholders.

### Blue Badges: "✦ Faker"
These findings were replaced with realistic fake data.

Each badge shows the replacement value below it.

## Comparison Table

| Aspect | Redaction | Faker |
|--------|-----------|-------|
| Format | `[REDACTED_EMAIL]` | `john.smith@example.com` |
| Testability | Won't pass email validation | Passes email validation |
| Readability | Less readable | More readable |
| Privacy | High | High |
| Data Type | Generic | Matched to category |

## Common Scenarios

### Scenario 1: Create Test Data with Fake PII
```bash
# Replace all email addresses with fake ones
sensitive-scanner obfuscate ./project \
  --obfuscation-strategy faker
```

Now your test suites can run with realistic-looking (but completely fake) data!

### Scenario 2: Sanitize Logs Before Sharing
```bash
# Replace secrets with fake credentials
sensitive-scanner obfuscate ./logs \
  --obfuscation-strategy faker \
  --dry-run \
  --report sanitized.html
```

The logs now look real but contain no actual sensitive data.

### Scenario 3: Create Compliant Test Fixtures
```bash
# Replace all PII with fake data for GDPR compliance
sensitive-scanner obfuscate ./fixtures \
  --obfuscation-strategy faker
```

Your test fixtures now comply with privacy regulations!

### Scenario 4: Auto-Obfuscate Critical Findings
```bash
# Auto-approve critical+high with Faker, review others
sensitive-scanner obfuscate ./project \
  --obfuscation-strategy faker \
  --auto-approve critical
```

High-risk findings are immediately protected with fake data!

## Tips & Tricks

### Tip 1: Use --show-secrets to See Real Values
```bash
sensitive-scanner obfuscate ./project \
  --obfuscation-strategy faker \
  --show-secrets
```
This helps you verify what's actually being replaced.

### Tip 2: Save Session for Reuse
```bash
# First run: review and make decisions
sensitive-scanner obfuscate ./project \
  --obfuscation-strategy faker

# Session saved to: pii-review-session.json

# Later: re-apply the same decisions
sensitive-scanner obfuscate ./project \
  --apply-session pii-review-session.json
```

### Tip 3: Generate Reports with Diff
```bash
# Create two reports for comparison
sensitive-scanner obfuscate ./project \
  --obfuscation-strategy faker \
  --report faker-report.html \
  --dry-run

sensitive-scanner obfuscate ./project \
  --obfuscation-strategy redaction \
  --report redaction-report.html \
  --dry-run

# Open both in your browser and compare!
```

### Tip 4: Batch Process Multiple Projects
```bash
for project in project1 project2 project3; do
  echo "Processing $project..."
  sensitive-scanner obfuscate "./$project" \
    --obfuscation-strategy faker \
    --report "$project-faker-report.html" \
    --dry-run
done
```

## Troubleshooting

### Q: "faker module not found"
**A:** Install it with `pip install faker`

### Q: Fake data looks wrong
**A:** This is normal! Faker generates plausible but random data. Use `--show-secrets` to see what's being replaced.

### Q: Want different fake data?
**A:** Use the [e] option during TUI review to customize any replacement.

### Q: How do I know which strategy was used?
**A:** Open the HTML report and look for the badge color:
- Green = Redaction
- Blue = Faker

## For More Information

- **Full Guide**: See `FAKER_INTEGRATION.md`
- **Testing**: See `TESTING_GUIDE.md`
- **Implementation Details**: See `IMPLEMENTATION_SUMMARY.md`
- **CLI Help**: `sensitive-scanner obfuscate --help`

## Examples

### Example 1: Preview Faker Replacements
```bash
sensitive-scanner obfuscate ./myrepo \
  --obfuscation-strategy faker \
  --dry-run \
  --report preview.html

# Then open preview.html in a browser
```

### Example 2: Apply Faker to Critical Findings
```bash
sensitive-scanner obfuscate ./myrepo \
  --obfuscation-strategy faker \
  --auto-approve high
```

### Example 3: Interactive Review with Faker Toggle
```bash
sensitive-scanner obfuscate ./myrepo

# In TUI:
# 1. View each finding
# 2. Press [f] to see Faker version
# 3. Press [a] to approve with current strategy
# 4. Press [s] to skip
```

### Example 4: Create Test Data from Real Code
```bash
# Scan production code
sensitive-scanner obfuscate ./production \
  --obfuscation-strategy faker \
  --report test-data.html

# Now you have test data with realistic (fake) PII!
```

---

**That's it! You're ready to start using Faker for realistic PII obfuscation.** 🎉

For questions, see the full documentation or run `sensitive-scanner obfuscate --help`.
