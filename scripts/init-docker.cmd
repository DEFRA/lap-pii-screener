REM Initializes and runs the Dockerized sensitive scanner environment on Windows CMD.
REM Usage: scripts\init-docker.cmd <source-directory>
REM Example: scripts\init-docker.cmd C:\path\to\repo-to-scan

@echo off
setlocal enabledelayedexpansion

if "%~1"=="" (
  echo Usage: init-docker.cmd ^<source-directory^>
  exit /b 1
)

set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
for %%i in ("%SCRIPT_DIR%") do set "PII_SCREENER_DIR=%%~dpi"
set "PII_SCREENER_DIR=%PII_SCREENER_DIR:~0,-1%"
set "SOURCE_DIR=%~1"

if not exist "%PII_SCREENER_DIR%\.cache\sensitive-scanner" mkdir "%PII_SCREENER_DIR%\.cache\sensitive-scanner"
if not exist "%PII_SCREENER_DIR%\.cache\uv" mkdir "%PII_SCREENER_DIR%\.cache\uv"
if not exist "%PII_SCREENER_DIR%\.cache\uv-python" mkdir "%PII_SCREENER_DIR%\.cache\uv-python"

where docker >nul 2>&1
if errorlevel 1 (
  where wsl >nul 2>&1
  if not errorlevel 1 (
    wsl docker --version >nul 2>&1
    if not errorlevel 1 (
      for /f %%p in ('wsl wslpath -a "%SCRIPT_DIR%/init-docker"') do wsl bash %%p "%SOURCE_DIR%"
      exit /b %errorlevel%
    )
  )
  echo Error: Docker is not installed and no WSL Docker fallback is available.
  exit /b 1
)

for /f %%i in ('docker images -q lap-pii-screener 2^>nul') do set IMAGE_ID=%%i
if not defined IMAGE_ID (
  docker build -t lap-pii-screener "%SCRIPT_DIR%"
)

docker run --rm -it ^
  --mount "type=bind,source=%PII_SCREENER_DIR%,target=/home/node/lap-pii-screener" ^
  --mount "type=bind,source=%SOURCE_DIR%,target=/source" ^
  --mount "type=bind,source=%PII_SCREENER_DIR%\.cache\sensitive-scanner,target=/home/node/.sensitive-scanner" ^
  --mount "type=bind,source=%PII_SCREENER_DIR%\.cache\uv-python,target=/home/node/.local/share/uv/python" ^
  --mount "type=bind,source=%PII_SCREENER_DIR%\.cache\uv,target=/home/node/.cache/uv" ^
  lap-pii-screener
