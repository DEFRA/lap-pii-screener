<#
.SYNOPSIS
Initializes and runs the Dockerized sensitive scanner environment on PowerShell.

.DESCRIPTION
Builds the scanner image if needed, prepares local cache folders, and runs the
container with project and source mounts.

.PARAMETER SourceDir
Path to the source directory to scan.

.EXAMPLE
./scripts/init-docker.ps1 -SourceDir C:\path\to\repo-to-scan
#>

param(
  [Parameter(Mandatory)][string]$SourceDir
)

$PiiScreenerDir = Split-Path $PSScriptRoot -Parent

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  if ((Get-Command wsl -ErrorAction SilentlyContinue) -and (wsl docker --version 2>$null)) {
    $wslInit = (wsl wslpath -a "$($PSScriptRoot.Replace('\', '/'))/init-docker").Trim()
    wsl bash $wslInit $SourceDir
    exit $LASTEXITCODE
  }
  Write-Error "Docker is not installed and no WSL Docker fallback is available."
  exit 1
}

New-Item -Force -ItemType Directory "$PiiScreenerDir\.cache\sensitive-scanner" | Out-Null
New-Item -Force -ItemType Directory "$PiiScreenerDir\.cache\uv" | Out-Null
New-Item -Force -ItemType Directory "$PiiScreenerDir\.cache\uv-python" | Out-Null

if (-not (docker images -q lap-pii-screener 2>$null)) {
  docker build -t lap-pii-screener $PSScriptRoot
}

docker run --rm -it `
  --mount "type=bind,source=$PiiScreenerDir,target=/home/node/lap-pii-screener" `
  --mount "type=bind,source=$SourceDir,target=/source" `
  --mount "type=bind,source=$PiiScreenerDir\.cache\sensitive-scanner,target=/home/node/.sensitive-scanner" `
  --mount "type=bind,source=$PiiScreenerDir\.cache\uv,target=/home/node/.cache/uv" `
  --mount "type=bind,source=$PiiScreenerDir\.cache\uv-python,target=/home/node/.local/share/uv/python" `
  lap-pii-screener
