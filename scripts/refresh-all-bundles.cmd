@echo off
REM refresh-all-bundles.cmd
REM
REM Convenience wrapper around scripts\refresh-all-bundles.ps1 so the
REM orchestrator can be launched from cmd.exe or by double-clicking
REM without worrying about PowerShell execution policy.
REM
REM Prefers PowerShell 7+ (pwsh) when present, falls back to the
REM built-in Windows PowerShell 5.1 otherwise.
REM
REM Forwards all arguments through, e.g.:
REM   scripts\refresh-all-bundles.cmd -NucleiTag v9.9.0

setlocal
set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%refresh-all-bundles.ps1"

where pwsh >nul 2>nul
if %errorlevel%==0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
    exit /b %errorlevel%
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
exit /b %errorlevel%
