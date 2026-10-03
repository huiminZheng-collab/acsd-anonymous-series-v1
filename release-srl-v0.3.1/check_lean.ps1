# check_lean.ps1 — CI guard for SealedLineage.lean
# Run from the repo root. Fails the build if Lean reports any errors or warnings.
# Usage: .\check_lean.ps1
#        In CI (no elan on PATH): $env:LEAN_EXE = "C:\path\to\lean.exe"; .\check_lean.ps1

param(
    [string]$LeanExe = ""
)

# Locate lean.exe: prefer env var, then elan default, then PATH
if ($LeanExe -eq "") {
    $candidates = @(
        $env:LEAN_EXE,
        "$env:USERPROFILE\.elan\bin\lean.exe",
        "$HOME/.elan/bin/lean"        # Unix fallback
    ) | Where-Object { $_ -ne $null -and $_ -ne "" }

    foreach ($c in $candidates) {
        if (Test-Path $c) { $LeanExe = $c; break }
    }
}

if ($LeanExe -eq "" -or -not (Test-Path $LeanExe)) {
    $found = Get-Command lean -ErrorAction SilentlyContinue
    if ($found) { $LeanExe = $found.Source }
}

if ($LeanExe -eq "") {
    Write-Error "lean.exe not found. Set LEAN_EXE env var or install via elan."
    exit 1
}

$LeanFile = "research\srl_prototype\SealedLineage.lean"
if (-not (Test-Path $LeanFile)) {
    Write-Error "Lean file not found: $LeanFile"
    exit 1
}

Write-Host "Lean: $LeanExe"
Write-Host "File: $LeanFile"

$output = & $LeanExe $LeanFile 2>&1
$exitCode = $LASTEXITCODE

if ($output) {
    Write-Host "--- Lean output ---"
    $output | ForEach-Object { Write-Host $_ }
    Write-Host "-------------------"
}

if ($exitCode -ne 0) {
    Write-Error "Lean compilation FAILED (exit $exitCode). Fix errors before committing."
    exit 1
}

# warningAsError true is set in the file, so any warning is already a compile error.
# If we reach here the file is clean.
Write-Host "OK: SealedLineage.lean compiled with 0 errors, 0 warnings."
exit 0
