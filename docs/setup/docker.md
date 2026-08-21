# Docker Setup

This guide covers running the sensitive scanner inside a Docker container. This is useful when you want to avoid installing Python, Java, or other dependencies locally, or when running on a machine where direct installation is not possible.

If you prefer a local installation, see the [Setup Guide](setup.md) instead.

**Page contents**

- [What you need](#what-you-need)
- [Step 1 — Start the container](#step-1--start-the-container)
- [Step 2 — Initialize the scanner](#step-2--initialize-the-scanner)
- [Step 3 — Run the scanner](#step-3--run-the-scanner)

---

## What you need

| Requirement                        | Purpose                                       |
| ---------------------------------- | --------------------------------------------- |
| **Docker**                         | Runs the container — see options below        |
| **The lap-pii-screener source**    | Cloned locally — the Docker scripts live here |
| **The legacy source code to scan** | The directory you want to scan                |

Any of the following Docker setups will work:

- **Docker Desktop** (Windows/macOS) — [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/)
- **Docker via WSL** (Windows) — install Docker Engine inside a WSL 2 distro
- **Docker Engine** (Linux) — install via your distro's package manager

---

## Step 1 — Start the container

Run the appropriate `init-docker` script for your shell. Pass the path to the source code you want to scan. The script builds the Docker image if needed, then drops you into an interactive shell inside the container.

The source directory is mounted at `/source` inside the container — you do not need to specify it again for subsequent commands. You can also reference it via the `PII_SCREENER_SOURCE_DIR` environment variable.

### Bash / WSL

```bash
./scripts/init-docker /path/to/legacy-source
```

### Windows CMD

```cmd
scripts\init-docker.cmd C:\path\to\legacy-source
```

### PowerShell

```powershell
./scripts/init-docker.ps1 -SourceDir C:\path\to\legacy-source
```

> **WSL note:** The CMD and PowerShell variants automatically fall back to the bash script via WSL if native Docker is not available but WSL with Docker is.

---

## Step 2 — Initialize the scanner

Once inside the container, run one of the following to download dependencies and set up the scanner tools. You only need to do this once — results are cached in `.cache/` in the project directory.

### Full setup (recommended)

Installs all extras, including SonarQube and the spaCy NLP model:

```bash
./scripts/init-full
```

### Slim setup

Installs only the baseline dependencies without optional extras:

```bash
./scripts/init-slim
```

See the [Setup Guide](setup.md) for details on what each scanner provides.

---

## Step 3 — Run the scanner

Use `scripts/screener` to run any scanner command. The source directory you passed to `init-docker` is automatically available at `/source` — you do not need to specify the path again.

```bash
./scripts/screener scan /source
```

All commands described in the [Scanning guide](../guides/scanning.md) work the same way. Replace `sensitive-scanner` with `./scripts/screener`. For example:

```bash
# Scan with a specific output format
./scripts/screener scan /source --format html --output /source/report.html

# Scan Git history
./scripts/screener scan /source --git-history
```

Refer to the [Scanning guide](../guides/scanning.md) for the full list of options.
