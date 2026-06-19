# Obfuscation

The obfuscation feature lets you replace sensitive values directly in your source files — turning a real API key or person name into a safe placeholder — with interactive review, dry-run preview, and full rollback.

**Page contents**
- [Overview](#overview)
- [Session files](#session-files)
- [The review TUI](#the-review-tui)
- [Workflow: full scan and review](#workflow-full-scan-and-review)
- [Workflow: apply a saved session](#workflow-apply-a-saved-session)
- [Dry run](#dry-run)
- [Auto-approve by severity](#auto-approve-by-severity)
- [Obfuscation report](#obfuscation-report)
- [Rollback](#rollback)
- [Editing a session item](#editing-a-session-item)
- [Suppressions in obfuscation](#suppressions-in-obfuscation)
- [All obfuscation options reference](#all-obfuscation-options-reference)

---

## Overview

The obfuscation process has three stages:

1. **Scan** — the target directory is scanned with `show_secrets=True` so that the actual matched values are captured (not redacted). These raw values are needed to do the replacement.

2. **Review** — a terminal UI (TUI) presents each finding one at a time. You decide whether to approve, skip, or edit the replacement text for each one. Your decisions are saved in a session file.

3. **Apply** — approved replacements are written to the source files. Backups are created first. If anything goes wrong, rollback restores the originals.

---

## Session files

When `obfuscate` runs, it creates a session file (default: `pii-review-session.json` in the scan target directory). This JSON file records every finding and your decision for it:

| Field | What it stores |
|---|---|
| `finding_id` | The ID of the original scan finding |
| `file` | File path relative to the scan root |
| `line` | Line number |
| `rule_id` | The rule that triggered the finding |
| `category` | Finding category |
| `severity` | Finding severity |
| `scanners` | Which scanners detected this |
| `match_display` | Redacted preview shown in the report |
| `raw_match` | The actual value to be replaced (hidden by default in reports) |
| `replacement` | The placeholder value to substitute |
| `decision` | `approved`, `skipped`, `manual`, or `pending` |
| `skip_reason` | Optional explanation when skipped |
| `confidence` | Detection confidence score |

**Why save to a file?** Large codebases may have dozens or hundreds of findings. The session file lets you:
- Stop mid-review and continue later
- Edit decisions after the fact with `sensitive-scanner edit`
- Apply the same set of replacements across multiple clones or branches
- Re-apply after checking out a new version of the code

Session files contain raw match values. Treat them like credentials — do not commit them to source control.

### Non-obfuscatable findings

Some findings are marked `manual` automatically and skipped in the TUI. These are cases where automated text replacement is not safe or practical:

- Binary files (images, compiled code, archives)
- Database or configuration values that must match a real pattern to be valid
- Values detected in built output (the source file should be fixed instead)

The session still records them so they appear in the report with a `manual` note.

---

## The review TUI

The TUI presents findings one at a time in a formatted panel. Each panel shows:

- Finding ID, file path and line number
- Category and severity
- Scanners that detected this finding
- Confidence score (colour coded: green ≥85%, amber 65–84%, red <65%)
- The replacement placeholder that will be substituted if you approve
- The `noscan` comment that will be appended to suppress future scans

At the bottom of the panel, the available keys are shown:

| Key | Action |
|---|---|
| `a` | **Approve** — accept the default replacement and move on |
| `e` | **Edit + approve** — type a custom replacement text before approving |
| `s` | **Skip** — do not obfuscate this finding; you are prompted for an optional reason |
| `A` | **Approve all** — approve every remaining finding in the same category at once |
| `S` | **Skip all** — skip every remaining finding in the same category; you are prompted for a shared reason |
| `q` | **Quit** — save the session and exit (findings not yet reviewed remain `pending`) |

When you press `s` or `S`, a reason prompt appears. Enter any explanation (or leave blank). Single-character inputs matching a key (`a`, `s`, `q`, `e`) are cleared automatically to prevent accidentally pressing a key from registering as the reason.

The session is saved automatically after each decision. If you press `q` or close the terminal mid-review, the session file preserves all decisions made so far.

---

## Workflow: full scan and review

```powershell
# Scan, review, and apply in one command
sensitive-scanner obfuscate C:\Github\MyProject
```

This runs the full workflow:
1. Scans the directory
2. Opens the TUI review
3. After you finish reviewing, prompts whether to apply
4. Applies approved replacements and backs up original files
5. Prints the backup directory path

To save an HTML report at the end:

```powershell
sensitive-scanner obfuscate C:\Github\MyProject --report report.html
```

To choose specific scanners:

```powershell
sensitive-scanner obfuscate C:\Github\MyProject --scanners gitleaks,presidio
```

To specify where the session file is saved:

```powershell
sensitive-scanner obfuscate C:\Github\MyProject --session C:\tmp\review-session.json
```

---

## Workflow: apply a saved session

If you have already reviewed a session (or edited it with `sensitive-scanner edit`), apply it without re-scanning:

```powershell
# Apply the default session file (pii-review-session.json in the target dir)
sensitive-scanner obfuscate C:\Github\MyProject --apply

# Apply a specific session file
sensitive-scanner obfuscate C:\Github\MyProject --apply-session C:\tmp\review-session.json
```

This is useful when:
- You want to apply the same session to a freshly checked-out copy of the repository
- You stopped mid-review and want to apply only what you have decided so far
- You edited the session with `sensitive-scanner edit` and want to re-apply

---

## Dry run

Preview exactly what replacements would be made without writing any files:

```powershell
sensitive-scanner obfuscate C:\Github\MyProject --dry-run
```

The TUI and application process run normally, but no files are written and no backups are created. Output shows what would have changed.

To preview applying a saved session:

```powershell
sensitive-scanner obfuscate C:\Github\MyProject --apply --dry-run
```

---

## Auto-approve by severity

Skip the TUI entirely for findings above a severity threshold — they are approved automatically:

```powershell
# Auto-approve all critical findings; review everything else in the TUI
sensitive-scanner obfuscate C:\Github\MyProject --auto-approve critical

# Auto-approve critical and high
sensitive-scanner obfuscate C:\Github\MyProject --auto-approve high
```

Valid values: `critical`, `high`, `medium`, `low`. Auto-approve processes all findings at or above the specified severity without showing them in the TUI.

---

## Obfuscation report

Generate an HTML report that shows every finding alongside its obfuscation status:

```powershell
# Generate during the obfuscate workflow
sensitive-scanner obfuscate C:\Github\MyProject --report obfuscation-report.html

# Generate after applying a session
sensitive-scanner obfuscate C:\Github\MyProject --apply --report obfuscation-report.html
```

The report adds an **Obfuscation** column to the standard finding table:

| Decision | What it means |
|---|---|
| `approved` | The replacement was applied (or would be applied in dry-run) |
| `skipped` | You chose to leave this finding as-is; skip reason shown if provided |
| `manual` | Cannot be auto-replaced — requires manual action |
| `pending` | Review was not completed for this finding |

To include the full matched values in the report (instead of redacted):

```powershell
sensitive-scanner obfuscate C:\Github\MyProject --apply --report report.html --show-secrets
```

> **Warning:** Reports with `--show-secrets` contain actual sensitive values. Do not share or commit them.

You can also attach a session to any standard scan report using the `--session` flag on the `scan` command:

```powershell
sensitive-scanner scan C:\Github\MyProject --format html --output report.html \
  --session C:\Github\MyProject\pii-review-session.json
```

---

## Rollback

Every time `obfuscate` applies changes, it saves a timestamped backup of every file it modifies. The backup directory path is printed at the end of a successful apply:

```
Backups in: C:\Github\MyProject\.pii-backups\20260609_143022
To undo:   sensitive-scanner rollback C:\Github\MyProject --backup-dir .pii-backups\20260609_143022
```

To restore all modified files from a backup:

```powershell
sensitive-scanner rollback C:\Github\MyProject --backup-dir .pii-backups\20260609_143022
```

This copies the backed-up originals back over the modified files. All other files are left untouched.

**Important notes:**
- Rollback restores the files exactly as they were before the obfuscation was applied
- It does not affect the session file — your review decisions are preserved
- You can re-apply the session after making manual fixes, or delete approvals you no longer want with `sensitive-scanner edit`
- If backups were lost or deleted, rollback is not possible — use Git to restore: `git checkout -- <file>`

### Backup directory structure

Each backup run creates a directory named with the timestamp of the apply operation:

```
.pii-backups/
  20260609_143022/
    src/
      config.py          ← original copy of src/config.py
    tests/
      fixtures/
        sample.json      ← original copy of tests/fixtures/sample.json
```

The structure mirrors the scan target directory. Backups from multiple apply runs accumulate as separate timestamped directories. You can safely delete old backup directories once you are confident the changes are correct.

---

## Editing a session item

Change a decision, replacement text, or skip reason for a specific finding after the TUI review:

```powershell
sensitive-scanner edit <finding-id> --session pii-review-session.json
```

Replace `<finding-id>` with the ID shown in the finding table (first column). If you omit options, the command shows the current state and prompts interactively.

Available options:

```
sensitive-scanner edit <finding-id> [OPTIONS]

  --session PATH       Session file (defaults to pii-review-session.json in cwd)
  --report PATH        Regenerate HTML report after saving (optional)
  --replacement TEXT   New replacement text
  --decision TEXT      New decision: approved | skipped | pending
  --skip-reason TEXT   Reason for skipping (when setting decision to skipped)
```

To change a skipped finding to approved:

```powershell
sensitive-scanner edit abc123 --decision approved
```

To change the replacement text:

```powershell
sensitive-scanner edit abc123 --replacement "[REDACTED_EMAIL]"
```

To add a skip reason to a finding you want to leave in place:

```powershell
sensitive-scanner edit abc123 --decision skipped --skip-reason "test fixture — not real data"
```

After editing, run `--apply` again to apply the updated session:

```powershell
sensitive-scanner obfuscate C:\Github\MyProject --apply
```

---

## Suppressions in obfuscation

Suppressions work the same as for the `scan` command. The `obfuscate` command reads:

1. `config\suppress.txt` (global install-level suppressions)
2. `<target>\suppress.txt` (project-level suppressions)

Suppressed findings are excluded before the TUI is shown — they do not appear in the review queue and are not written to the session file.

When applying a saved session (`--apply`), session items whose rule ID matches an active suppression are also removed before applying, so rules added to `suppress.txt` after the initial review are respected on re-apply.

For per-scanner suppressions, see [Scanning → Suppressing false positives](scanning.md#suppressing-false-positives).

---

## All obfuscation options reference

```
sensitive-scanner obfuscate <path> [OPTIONS]

Arguments:
  path                      Directory to scan and obfuscate (required)

Options:
  -s, --scanners TEXT       Comma-separated scanners (default: all available)
      --session PATH        Save/load session from this path
                            (default: <target>/pii-review-session.json)
      --apply               Apply the default session without scan or TUI
      --apply-session PATH  Apply a specific session file without scan or TUI
      --report PATH         Write HTML report to this file after applying
      --backup-dir PATH     Directory for backups (default: <target>/.pii-backups/<timestamp>)
      --dry-run             Preview replacements without writing files
      --auto-approve TEXT   Auto-approve findings at or above: critical|high|medium|low
      --show-secrets        Show full matched values in the TUI (not redacted)

sensitive-scanner rollback <path> [OPTIONS]

Arguments:
  path                      The directory that was originally obfuscated

Options:
      --backup-dir PATH     Backup directory to restore from (required)

sensitive-scanner edit <finding-id> [OPTIONS]

Arguments:
  finding-id                The finding ID to edit

Options:
      --session PATH        Session file (default: pii-review-session.json in cwd)
      --report PATH         Regenerate HTML report after saving
      --replacement TEXT    New replacement text
      --decision TEXT       New decision: approved|skipped|pending
      --skip-reason TEXT    Skip reason text
```
