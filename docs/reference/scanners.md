# Scanners

PII Screener runs up to four independent scanning engines against a codebase and merges their results. Each engine targets a different class of problem — running them together closes the blind spots that any single tool would leave.

**Page contents**
- [How results are combined](#how-results-are-combined)
- [Tier architecture](#tier-architecture)
- [Gitleaks](#gitleaks)
- [Semgrep](#semgrep)
- [Presidio (custom PII scanner)](#presidio-custom-pii-scanner)
- [SonarQube](#sonarqube)
  - [Deployment options](#sonarqube-deployment-options)
  - [SonarCloud vs self-hosted](#sonarcloud-vs-self-hosted)

---

## How results are combined

Each scanner produces a list of `Finding` objects. Before the report is written, the orchestrator runs three deduplication passes:

1. **Same rule on the same line** — if two scanners fire the same rule on the same file and line, the finding is kept once with both scanner names listed.
2. **Same match value on the same line** — if two different rules detect the exact same value on the same line, the higher-severity finding is kept.
3. **Same category on the same line** — if two rules detect different fragments of the same sensitive item on the same line (e.g. one catches `FullName = "Alice Smith"` and another catches `"Alice Smith"`), they collapse into one finding.

The `scanners` field on every finding shows every engine that independently flagged it. When multiple scanners agree, the **confidence score is boosted** by 8% per additional engine (capped at 99%).

---

## Tier architecture

Scanners activate automatically based on what is available. The CLI reports the active tier at scan time.

| Tier | Scanners active | What is required |
|---|---|---|
| 1 | Gitleaks + Semgrep + Presidio | Python + Gitleaks binary (auto-downloaded) |
| 2 | + SonarQube Community (Java) | Java 17+ and sonar-scanner CLI |
| 2 (Docker) | + SonarQube Community (Docker) | Docker Desktop |
| 3 | + SonarCloud | SonarCloud account + token |

---

## Gitleaks

**Implementation:** `scanners/gitleaks_scanner.py`  
**Rule configuration:** `config/gitleaks.toml`  
**Acquired from:** [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) (open source, MIT)

### What it does

Gitleaks is a purpose-built secret scanner. It scans every file in the target directory — and optionally the full Git commit history — against a large library of regular expression rules that match known secret formats. Each rule targets a specific service or format: AWS access keys follow a distinct `AKIA...` prefix, GitHub tokens follow `ghp_...`, and so on. This specificity gives Gitleaks a very low false-positive rate compared to generic pattern matching.

### How it works

1. On first run the scanner downloads a pinned Gitleaks binary to `~\.sensitive-scanner\bin\`. If Gitleaks is already on PATH, that version is used. As a last resort it falls back to running via Docker (`ghcr.io/gitleaks/gitleaks`).
2. Gitleaks is invoked as a subprocess with `--report-format json --no-git` (or with Git history enabled if `--history` is passed).
3. The JSON output is parsed into `Finding` objects and post-filtered against the configured exclusion list.
4. Match values are redacted by default (`john****`). Pass `--show-secrets` to see the full value.

### Custom rules in gitleaks.toml

The file `config/gitleaks.toml` extends the default Gitleaks ruleset with project-specific rules:

| Rule ID | What it matches |
|---|---|
| `custom-pii-email` | Email addresses in any context |
| `custom-pii-ssn` | US Social Security Numbers |
| `custom-pii-phone` | UK mobile and international phone numbers |
| `custom-pii-phone-eu` | EU landline number format |
| `custom-pii-iban` | IBAN bank account numbers |
| `custom-pii-passport` | Generic passport number format |
| `custom-pii-ni-number` | UK National Insurance numbers |
| `custom-pii-dob` | Dates of birth (ISO and common formats, URL-path-guarded) |

### Why Gitleaks was chosen

- Purpose-built for secrets — not a general linter pressed into service
- Supports Git history scanning, which catches secrets deleted from HEAD but still in commit history
- Ships with rules covering 150+ services out of the box
- Uses the RE2 regex engine (safe on large repos, no catastrophic backtracking)
- Single static binary, no runtime dependencies, auto-downloaded by the setup wizard

### Alternatives considered

| Tool | Why not chosen |
|---|---|
| **TruffleHog** | Slower on large repos; entropy-based approach generates more false positives |
| **detect-secrets** | Yelp's tool; good but narrower ruleset and less active maintenance |
| **git-secrets** | AWS-only rules; does not scan working tree |

---

## Semgrep

**Implementation:** `scanners/semgrep_scanner.py`  
**Rulesets:** `p/secrets`, `p/owasp-top-ten`, `p/default`  
**Acquired from:** [semgrep.dev](https://semgrep.dev) (open source, LGPL)

### What it does

Semgrep understands code structure rather than just text. It uses abstract syntax tree (AST) matching to find patterns that are semantically meaningful — for example, a function call with a hardcoded string argument, regardless of whitespace, variable naming, or how the call is split across lines. PII Screener runs three community-maintained rulesets:

| Ruleset | Focus |
|---|---|
| `p/secrets` | Hardcoded secrets, tokens, and passwords in source code |
| `p/owasp-top-ten` | SQL injection, XSS, insecure deserialisation, broken authentication |
| `p/default` | General security and quality issues across many languages |

### How it works

1. Semgrep is installed as a Python package (`uv sync --extra semgrep`). The scanner locates it relative to the running Python interpreter.
2. It is invoked with `--json` output and `--exclude` flags for each directory in the exclusion list.
3. The `extra.metadata.confidence` field is read if present (HIGH/MEDIUM/LOW); otherwise severity is used as a proxy.
4. Results are post-filtered by the exclusion configuration before being returned.

### Why Semgrep was chosen

- Language-aware: the same rule works across Python, JavaScript, Java, C#, Go, and many others
- The `p/owasp-top-ten` ruleset adds a code-security layer beyond what secret scanners cover
- Runs fully offline with community rulesets — no source code leaves the machine
- pip-installable via `uv sync --extra semgrep`, no separate binary or container needed
- Community rulesets are reviewed by Semgrep Inc.

### Alternatives considered

| Tool | Why not chosen |
|---|---|
| **Bandit** | Python-only; Semgrep covers the same ground and more languages |
| **ESLint security plugins** | JavaScript-only |
| **CodeQL** | Very powerful but requires a full build environment and significantly more setup overhead |

---

## Presidio (custom PII scanner)

**Implementation:** `scanners/pii_scanner.py`  
**Built custom for this project**

### Why it was built custom

No existing open-source scanner covered the combination of structured PII patterns, UK-specific identifiers, and NLP-based name detection in a single pass. Gitleaks and Semgrep focus on secrets and security bugs respectively; neither has comprehensive PII rules. A custom scanner provided:

- Full control over which patterns to include and at what severity
- Luhn algorithm validation for credit card numbers (eliminates most false positives)
- Modulus-11 checksum validation for NHS numbers
- Pluggable NLP via Microsoft Presidio or spaCy without depending on an external API
- All analysis stays local — nothing leaves the machine

### Technique 1 — Structured pattern matching

A curated set of compiled regular expressions matches well-defined data formats. Each rule has an assigned confidence level reflecting how specific the pattern is:

| Rule ID | What it matches | Confidence | Validation |
|---|---|---|---|
| `private_key_pem` | PEM private key headers | 99% | Literal string |
| `pii_credit_card` | Visa, Mastercard, Amex, Discover | 95% | Luhn algorithm |
| `pii_nhs_number` | UK NHS numbers (3-3-4 format) | 95% | Modulus-11 checksum |
| `db_conn_string` | Database URLs with embedded credentials | 92% | URL scheme match |
| `pii_ssn` | US Social Security Numbers | 90% | Invalid prefix exclusions |
| `pii_ni_number` | UK National Insurance numbers | 90% | Format-specific regex |
| `jwt_token` | JSON Web Tokens | 90% | 3-part base64 structure |
| `hardcoded_password` | `password = "..."` assignments | 88% | Named key context |
| `pii_email` | Email addresses | 88% | Standard RFC pattern |
| `pii_iban` | International Bank Account Numbers | 85% | Country code + check digits |
| `pii_uk_driving_licence` | DVLA driving licence numbers | 85% | DVLA structure |
| `pii_uk_sort_code` | UK sort codes with named key | 85% | Named key context |
| `pii_uk_account_number` | UK 8-digit account numbers | 85% | Named key context |
| `pii_uk_postcode` | UK postcodes | 82% | Outward/inward format |
| `pii_person_name` | Person names with named key | 80% | Identifier context |
| `pii_phone` / `pii_uk_phone_mobile` | UK and US phone numbers | 80% | Structured format |
| `pii_dob` / `pii_dob_uk` | Dates of birth | 78% | URL-path-guarded |
| `pii_passport` | Generic passport numbers | 72% | Short alphanumeric |
| `pii_mac_address` | MAC addresses | 70% | 6-octet format |
| `pii_ip_address` | IPv4 in string literals | 65% | Inside quotes only |
| `pii_person_name_bare_key` | Name with bare `name` key | 60% | Broad key match |
| `pii_ipv6_address` | Full IPv6 addresses | 60% | 8-group format |

#### Date of birth false positive guard

The DoB patterns include a negative lookbehind `(?<!/)` before the year and a negative lookahead `(?!/)` after the day. This prevents matching URL archive paths like `http://example.com/archives/2007/07/27/` where `2007/07/27` is a publication date, not a date of birth.

### Technique 2 — Named Entity Recognition (optional)

When Microsoft Presidio or spaCy is installed, the scanner also runs NLP on code comments and string literal content to detect person names and locations — patterns no regex can reliably detect.

**Presidio** (preferred): uses a trained ML model and returns a confidence score (0.0–1.0) for each detected entity. Findings from Presidio carry the actual model score as their confidence value. Detections below 0.70 are discarded.

**spaCy** (fallback): uses the `en_core_web_sm` English model. Returns entity labels without individual scores; detections are assigned a fixed confidence of 0.65.

Neither backend sends data to an external service.

### How the scanner works

1. Walks the target directory recursively, skipping binary files, files over 2 MB, and known non-text extensions.
2. Each text file is run through all active regex patterns.
3. Each match is validated (Luhn / NHS checksum where applicable) before becoming a Finding.
4. If NLP is available, comment and string-literal lines are extracted and passed through the NER pipeline.
5. Results are returned and merged with the other scanners' results in the orchestrator.

### Alternatives considered

| Tool | Why not chosen |
|---|---|
| **AWS Macie** | Cloud-only, sends data externally, cost per GB |
| **Google DLP API** | Cloud-only, sends data externally |
| **Azure Purview** | Enterprise licensing, significant infrastructure overhead |
| **PIIvot / pii-detector** | Narrower coverage, less actively maintained |

---

## SonarQube

**Implementation:** `scanners/sonarqube_scanner.py`  
**Acquired from:** [sonarsource.com](https://www.sonarsource.com) (Community Edition is free)

### What it does

SonarQube performs deep, language-specific static analysis including:

- **Data-flow tracking** — follows a value from where it enters the program to where it is used
- **Taint analysis** — identifies when user-controlled input reaches a dangerous operation (e.g. a SQL query)
- **Inter-procedural reasoning** — traces issues across function calls, not just within a single method

These capabilities are beyond what pattern-based scanners can do. SonarQube is the only scanner in this stack that can find a SQL injection vulnerability where the user input and the query are in different files.

It reports two distinct types of issue:

- **Vulnerabilities and Bugs** — fetched via `/api/issues/search`
- **Security Hotspots** — fetched separately via `/api/hotspots/search` (SonarQube 10+ moved these to a dedicated endpoint)

Findings from SonarQube that cannot be mapped to a known PII or secret category are discarded — injection-type issues, CSRF, DoS, and other categories that have no actionable meaning in the context of this tool are filtered out.

### SonarQube deployment options

There are three ways to run SonarQube with PII Screener, each with different trade-offs:

---

#### Option 1 — Native Java (recommended default)

SonarQube runs as a Java application directly on your machine. The `setup --sonarqube` command downloads and configures everything automatically.

**Benefits:**
- Fastest scan times (no container overhead)
- Uses the least memory
- Can be started and stopped independently of Docker
- Automatically configured to use port 9100 (avoids conflicts with ZScaler on port 9000)
- Works fully offline once installed

**Drawbacks:**
- Requires Java 17+
- Does not start automatically on login — you must start it before scanning
- Large download (~500 MB) on first setup

**Setup:**
```powershell
sensitive-scanner setup --sonarqube
```

**Starting after a reboot:**
```powershell
& "$env:USERPROFILE\.sensitive-scanner\sonarqube\bin\windows-x86-64\StartSonar.bat"
```

---

#### Option 2 — Docker

SonarQube runs in a Docker container. Useful if you already use Docker and do not want to install Java separately.

**Benefits:**
- No Java installation needed
- Isolated from the host OS
- Easy to tear down and recreate

**Drawbacks:**
- Requires Docker Desktop to be running
- Slightly slower than native Java due to container overhead
- Docker Desktop itself requires more memory than the native Java approach
- On Windows, Docker Desktop starts automatically at login but takes 1–2 minutes itself to be ready

**Setup:**
```powershell
docker compose -f docker\docker-compose.yml up -d
```

The compose file configures the correct ports and volume mounts automatically.

---

#### Option 3 — SonarCloud

SonarCloud is the hosted SaaS version of SonarQube operated by Sonar. You connect to it with a token from [sonarcloud.io](https://sonarcloud.io).

**Benefits:**
- No local infrastructure at all
- Always up to date with the latest rules
- The analysis server is maintained for you

**Drawbacks:**
- **Source code is uploaded to Sonar's servers** — not suitable for projects with confidentiality requirements or air-gapped environments
- Requires internet access for every scan
- Free tier has public repositories only; private repositories require a paid plan
- Analysis may take longer depending on queue depth

**When to choose SonarCloud:** public or low-sensitivity repositories where you want SonarQube's depth without managing any infrastructure.

---

#### Comparison summary

| | Native Java | Docker | SonarCloud |
|---|---|---|---|
| Setup effort | Medium (Java install) | Low (Docker only) | Low (token only) |
| Internet needed (ongoing) | No | No | Yes |
| Source code stays local | Yes | Yes | **No** |
| Scan speed | Fastest | Fast | Depends on queue |
| Memory footprint | ~1.5 GB | ~2 GB | None locally |
| Auto-start on login | No | Yes (with Docker Desktop) | N/A |
| Air-gapped compatible | Yes | Yes (if images pre-pulled) | **No** |

### Why SonarQube was chosen

- Only tool in the stack with inter-procedural data-flow analysis
- Community Edition is free and self-hosted
- Well-established in enterprise security pipelines; findings reference recognised CWE and OWASP IDs
- Acts as an independent verification layer: a finding confirmed by both a pattern scanner and SonarQube carries significantly higher confidence
- Supports all major languages used in government digital services (Java, Python, C#, JavaScript, TypeScript)

### Alternatives considered

| Tool | Why not chosen |
|---|---|
| **CodeQL** | Extremely powerful but requires repository access via GitHub and a complete build environment; complex to run locally |
| **Checkmarx** | Enterprise licensing costs; not self-hostable on free tier |
| **Veracode** | Cloud-only; source code leaves the organisation |
| **Fortify** | Expensive licensing; complex on-premise deployment |
