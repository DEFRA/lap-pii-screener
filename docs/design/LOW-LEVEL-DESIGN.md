# Low-Level Design — Sensitive Code Screener

> Companion to [HIGH-LEVEL-DESIGN.md](HIGH-LEVEL-DESIGN.md). The HLD covers the
> system shape and component responsibilities; this LLD documents the concrete
> classes, data models, method-level control flow, and lifecycle state used by
> the implementation in `src/`. All diagrams are inline Mermaid so they render
> directly on GitHub and in any Markdown preview.

---

## 1. Scope

This document describes:

- The Pydantic/​dataclass **data models** that flow through the system.
- The **scanner class hierarchy** and the orchestration pipeline.
- The **remediation / regulation enrichment** engines.
- The **obfuscation** review-and-apply subsystem and its decision lifecycle.
- Key **sequence flows** (scan, obfuscate) at the method level.

File paths are given relative to the repository root. Method and field names
match the source exactly so the diagrams can be used for navigation.

---

## 2. Module Dependency Graph

How the Python packages under `src/` depend on one another. Arrows point from a
module to the modules it imports.

```mermaid
flowchart TD
    CLI["cli.py<br/><i>Typer commands</i>"]
    SRV["server.py<br/><i>MCP tools</i>"]

    ORCH["scanners/orchestrator.py"]
    BASE["scanners/base.py<br/>AbstractScanner"]
    GL["scanners/gitleaks_scanner.py"]
    SG["scanners/semgrep_scanner.py"]
    PII["scanners/pii_scanner.py"]
    SQ["scanners/sonarqube_scanner.py"]

    REM["remediation/engine.py<br/>RemediationEngine"]
    REG["remediation/regulation_engine.py<br/>RegulationEngine"]

    MF["models/finding.py<br/>ScanConfig · Finding"]
    MR["models/report.py<br/>Report · ScanSummary"]

    REP["reporting/*<br/>console · md · html · json"]

    OBF["obfuscation/engine.py"]
    OSESS["obfuscation/session.py<br/>ReviewSession · ReviewItem"]
    OSTRAT["obfuscation/strategies.py"]
    OREV["obfuscation/reviewer.py"]

    CFG["config_loader.py"]

    CLI --> ORCH
    CLI --> REP
    CLI --> OBF
    CLI --> OREV
    CLI --> CFG
    SRV --> ORCH
    SRV --> REP
    SRV --> REM

    ORCH --> BASE
    ORCH --> GL
    ORCH --> SG
    ORCH --> PII
    ORCH --> SQ
    ORCH --> REM
    ORCH --> MF
    ORCH --> MR

    GL --> BASE
    SG --> BASE
    PII --> BASE
    SQ --> BASE
    GL --> MF
    SG --> MF
    PII --> MF
    SQ --> MF
    PII --> REM
    PII --> REG

    REM --> MF
    REG --> MF
    REP --> MR

    OBF --> OSESS
    OSESS --> OSTRAT
    OSESS --> MF
    OREV --> OSESS

    classDef entry fill:#DBEAFE,stroke:#2563EB,color:#1E3A8A
    classDef scan fill:#FEF3C7,stroke:#D97706,color:#92400E
    classDef model fill:#EFF6FF,stroke:#3B82F6,color:#1E3A8A
    classDef eng fill:#F3E8FF,stroke:#7C3AED,color:#4C1D95
    classDef rep fill:#F0FDF4,stroke:#16A34A,color:#14532D
    classDef obf fill:#FCE7F3,stroke:#DB2777,color:#9D174D
    classDef misc fill:#F1F5F9,stroke:#64748B,color:#334155

    class CLI,SRV entry
    class ORCH,BASE,GL,SG,PII,SQ scan
    class MF,MR model
    class REM,REG eng
    class REP rep
    class OBF,OSESS,OSTRAT,OREV obf
    class CFG misc
```

---

## 3. Core Data Models

The three Pydantic models that carry scan state. `ScanConfig` is the input,
`Finding` is the unit of output, and `Report` aggregates findings with a
computed `ScanSummary`.

```mermaid
classDiagram
    class ScanConfig {
        +str path
        +list~str~ scanners
        +str project_name
        +bool include_git_history
        +str sonar_host_url
        +str sonar_token
        +str sonar_project_key
        +list~str~ exclude_paths
        +list~str~ exclude_files
        +list~str~ exclude_patterns
        +dict suppress_by_scanner
        +list~str~ suppress_global
        +bool show_secrets
        +bool skip_comments
    }

    class Finding {
        +str id
        +list~str~ scanners
        +str category
        +str severity
        +float confidence
        +str file
        +int line
        +str match
        +str rule_id
        +str message
        +str remediation_description
        +list~str~ fix_steps
        +list~str~ references
        +list~str~ regulations
        +make_id(file, line, rule_id)$ str
        +redact(value)$ str
    }

    class ScanSummary {
        +int total
        +int critical
        +int high
        +int medium
        +int low
        +int info
        +int files_scanned
        +int files_skipped
        +int lines_scanned
        +int lines_skipped
        +dict by_category
        +dict by_scanner
    }

    class Report {
        +str scan_id
        +str target_path
        +str project_name
        +datetime scanned_at
        +float duration_seconds
        +int tier_used
        +list~str~ scanners_run
        +dict scanner_durations
        +list~Finding~ findings
        +ScanSummary summary
        +build_summary() void
    }

    Report "1" *-- "many" Finding : findings
    Report "1" *-- "1" ScanSummary : summary
    ScanConfig ..> Finding : produces (via scanners)
```

> `Finding.id` is a 16-char SHA-256 of `file:line:rule_id` (`make_id`), which is
> also the deduplication key. `Finding.match` is always stored redacted
> (`redact` keeps the first 4 chars), and `confidence` defaults to `0.70`.
> `ScanConfig.scanners` defaults to `[gitleaks, semgrep, presidio]`.
> `Report.build_summary()` recomputes `ScanSummary` counters from the current
> `findings` list.

---

## 4. Scanner Class Hierarchy

Every scanner implements the same three-member async contract defined by
`AbstractScanner`. The orchestrator holds one singleton instance of each in the
`_ALL_SCANNERS` registry.

```mermaid
classDiagram
    class AbstractScanner {
        <<abstract>>
        +name() str
        +is_available()* bool
        +scan(config)* list~Finding~
    }

    class GitleaksScanner {
        +name() str
        +is_available() bool
        +scan(config) list~Finding~
    }
    class SemgrepScanner {
        +name() str
        +is_available() bool
        +scan(config) list~Finding~
    }
    class PIIScanner {
        +name() str
        +is_available() bool
        +scan(config) list~Finding~
    }
    class SonarQubeScanner {
        +name() str
        +is_available() bool
        +scan(config) list~Finding~
    }

    AbstractScanner <|-- GitleaksScanner
    AbstractScanner <|-- SemgrepScanner
    AbstractScanner <|-- PIIScanner
    AbstractScanner <|-- SonarQubeScanner
```

> `name` is a property; `is_available()` must never raise and reports whether
> the backend can run in the current environment; `scan()` must never raise —
> on failure it logs and returns `[]`. The fixed `name` values are
> `gitleaks`, `semgrep`, `presidio`, and `sonarqube` respectively — note the PII
> scanner's name is `presidio`, which is also its key in the orchestrator
> registry.

---

## 5. Enrichment Engines

After scanners return raw findings, two engines attach human-readable
remediation guidance and statutory regulation references. Both load their
catalogues from YAML at construction and build in-memory indexes.

```mermaid
classDiagram
    class RemediationRule {
        <<dataclass>>
        +str severity
        +str description
        +list~str~ fix_steps
        +list~str~ references
    }
    class RemediationEngine {
        -dict _rules
        +lookup(category) RemediationRule
        +resolve(rule_id) tuple
    }

    class Regulation {
        <<dataclass>>
        +str id
        +str name
        +str article
        +str statutory_ref
        +str last_verified
    }
    class RegulationEngine {
        -dict _regulations
        -dict _category_map
        +lookup(category) list~str~
        +get(regulation_id) Regulation
        +all_regulations() list~Regulation~
    }

    RemediationEngine "1" *-- "many" RemediationRule : _rules
    RegulationEngine "1" *-- "many" Regulation : _regulations
```

> `RemediationEngine.resolve()` maps an arbitrary scanner `rule_id` to one of the
> catalogue category keys using, in order: (1) exact match, (2) substring match,
> (3) the `_KEYWORD_MAP` heuristics, finally falling back to `generic_secret`.
> `RegulationEngine` builds an inverted `category → [regulation_id]` index so a
> PII category resolves to the applicable UK GDPR / PCI DSS / PSR 2017 entries.

---

## 6. Scan Sequence (CLI path)

End-to-end flow of `sensitive-scanner scan <path>` from command invocation to
rendered output. The MCP `scan_codebase` tool follows the same path from
`run_scan` onward.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant CLI as cli.scan
    participant ORCH as orchestrator.run_scan
    participant DET as detect_available_scanners
    participant S as Scanners (async gather)
    participant REM as RemediationEngine
    participant REG as RegulationEngine
    participant R as Report
    participant REP as reporting.render_*

    User->>CLI: scan path --scanners --format --output
    CLI->>CLI: build ScanConfig (merge excludes + suppressions)
    CLI->>ORCH: await run_scan(config)
    ORCH->>DET: detect_available_scanners(requested)
    DET-->>ORCH: (scanners, tier)
    ORCH->>S: asyncio.gather(_timed(s) for s in scanners)
    S-->>ORCH: list[list[Finding]] + per-scanner durations
    ORCH->>ORCH: _apply_suppression_per_scanner()
    ORCH->>ORCH: _deduplicate()  (3-pass merge)
    ORCH->>ORCH: _filter_inline_suppressions()  (# noscan)
    Note over ORCH,REG: enrichment happens inside each scanner<br/>via RemediationEngine + RegulationEngine
    ORCH->>REM: resolve(rule_id) -> category + fix steps
    ORCH->>REG: lookup(category) -> regulations
    ORCH->>R: _build_report(...)
    ORCH->>ORCH: _cache_report(report)  -> ~/.sensitive-scanner/last_report.json
    ORCH-->>CLI: Report
    CLI->>REP: render_console / markdown / html / json
    REP-->>User: terminal output or written file
```

---

## 7. Deduplication Pipeline

`_deduplicate()` runs three passes, each keyed differently, merging scanner
lists and boosting confidence when multiple engines agree (+8% per extra
scanner, capped at 0.99). The higher-severity finding always wins.

```mermaid
flowchart TD
    RAW["Raw findings<br/>(flattened from all scanners)"]
    P1{"Pass 1<br/>key = file:line:rule_id"}
    P2{"Pass 2<br/>key = file:line:match"}
    P3{"Pass 3<br/>key = file:line:category"}
    OUT["Deduplicated findings"]

    RAW --> P1
    P1 -->|"same rule, multiple scanners<br/>→ merge scanner lists"| P2
    P2 -->|"same match string, different rule<br/>→ keep higher severity"| P3
    P3 -->|"same category, different match/rule<br/>→ keep higher severity"| OUT

    MERGE["_merge(existing, incoming):<br/>• winner = lower _SEV_RANK<br/>• scanners = union (order-preserving)<br/>• confidence = min(0.99, max(c) + 0.08·(n−1))"]
    P1 -.uses.-> MERGE
    P2 -.uses.-> MERGE
    P3 -.uses.-> MERGE

    classDef io fill:#DBEAFE,stroke:#2563EB,color:#1E3A8A
    classDef pass fill:#FEF3C7,stroke:#D97706,color:#92400E
    classDef helper fill:#F3E8FF,stroke:#7C3AED,color:#4C1D95
    class RAW,OUT io
    class P1,P2,P3 pass
    class MERGE helper
```

---

## 8. Obfuscation Subsystem

The obfuscate command builds a `ReviewSession` of `ReviewItem`s, lets the user
(or auto-approval) decide each one, then `apply_session` writes redacted
placeholders to source files with full backups for rollback.

```mermaid
classDiagram
    class ReviewItem {
        +str finding_id
        +str file
        +int line
        +str rule_id
        +str category
        +str severity
        +list~str~ scanners
        +str match_display
        +Optional~str~ raw_match
        +str replacement
        +bool obfuscatable
        +str non_obfuscatable_reason
        +Decision decision
        +str skip_reason
        +float confidence
    }

    class ReviewSession {
        +str scan_id
        +str target_path
        +datetime created_at
        +Optional~datetime~ applied_at
        +list~ReviewItem~ items
    }

    class ItemResult {
        <<dataclass>>
        +str finding_id
        +str file
        +int line
        +str replacement
        +bool applied
        +str reason
    }

    class ApplyResult {
        <<dataclass>>
        +list~ItemResult~ item_results
        +list~str~ backed_up
        +applied_count() int
        +failed_count() int
    }

    ReviewSession "1" *-- "many" ReviewItem : items
    ApplyResult "1" *-- "many" ItemResult : item_results
    ReviewItem ..> ItemResult : becomes (on apply)
```

> `Decision` is a `Literal["pending", "approved", "skipped", "manual"]`.
> `replacement` comes from `strategies.get_replacement(category)` (e.g.
> `pii_email → [REDACTED_EMAIL]`), defaulting to `[REDACTED]`. Files with
> extensions in `_NON_OBFUSCATABLE_EXTENSIONS` (archives, Office docs, binaries)
> are marked `obfuscatable = false` and forced to the `manual` decision.

---

## 9. Obfuscation Decision Lifecycle

Each `ReviewItem.decision` moves through this state machine. Only `approved`
items are written to disk by `apply_session`.

```mermaid
stateDiagram-v2
    [*] --> pending : item created from Finding
    pending --> approved : user approves / auto-approve by severity
    pending --> skipped : user skips (records skip_reason)
    pending --> manual : non-obfuscatable file type
    approved --> [*] : written to source + backed up
    skipped --> [*] : left unchanged
    manual --> [*] : reported for manual remediation
```

---

## 10. Obfuscation Apply Sequence

`apply_session` groups items by file, backs up each touched file, performs the
text replacement, then records `applied_at`. `--dry-run` skips all writes but
still produces an `ApplyResult` preview.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant CLI as cli.obfuscate
    participant REV as reviewer.run_review
    participant SESS as ReviewSession
    participant ENG as engine.apply_session
    participant FS as Filesystem

    User->>CLI: obfuscate --apply (or --dry-run)
    CLI->>SESS: build session from cached Report findings
    CLI->>REV: run_review(session)  (TUI / auto-approve)
    REV-->>SESS: set each ReviewItem.decision
    CLI->>ENG: apply_session(session, backup_dir, dry_run)
    loop per file with approved items
        ENG->>FS: _backup_file(src, backup_dir, target_root)
        ENG->>FS: replace raw_match -> replacement in source
        ENG->>ENG: record ItemResult(applied=true/false)
    end
    ENG->>SESS: set applied_at = now (unless dry_run)
    ENG-->>CLI: ApplyResult (applied_count / failed_count / backed_up)
    CLI-->>User: summary table + optional HTML report
```

---

## 11. Report Cache Lifecycle

A single most-recent report is persisted so subsequent commands
(`report`, `obfuscate`, MCP `get_report`/`list_findings`) can operate without
re-scanning.

```mermaid
flowchart LR
    SCAN["run_scan()"] -->|"_cache_report()"| FILE[("~/.sensitive-scanner/<br/>last_report.json")]
    FILE -->|"load cached Report"| RPT["report command"]
    FILE -->|"load cached Report"| OBF["obfuscate command"]
    FILE -->|"load cached Report"| MCP["MCP get_report /<br/>list_findings / get_remediation"]

    classDef proc fill:#DCFCE7,stroke:#16A34A,color:#14532D
    classDef store fill:#FEF3C7,stroke:#D97706,color:#92400E
    classDef cons fill:#DBEAFE,stroke:#2563EB,color:#1E3A8A
    class SCAN proc
    class FILE store
    class RPT,OBF,MCP cons
```

---

## 12. Cross-References

| Concern | HLD section | Source |
|---|---|---|
| Component responsibilities | HLD §3–§4 | `src/scanners/orchestrator.py` |
| Suppression hierarchy | HLD §7 | `src/scanners/orchestrator.py`, `config_loader.py` |
| Scanner tiers | HLD §8 | `src/scanners/orchestrator.py` |
| MCP interface | HLD §9 | `src/server.py` |
| Data models | LLD §3 | `src/models/finding.py`, `src/models/report.py` |
| Enrichment | LLD §5 | `src/remediation/engine.py`, `regulation_engine.py` |
| Obfuscation | LLD §8–§10 | `src/obfuscation/*` |
