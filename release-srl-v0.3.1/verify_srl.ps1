# verify_srl.ps1 — one-command acceptance check for the frozen SRL profile
# Run from any directory: .\verify_srl.ps1

param(
    [string]$PythonExe = "python",
    [string]$LeanExe = ""
)

$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot

try {
    Write-Host "== SRL Python verification =="
    & $PythonExe -m unittest discover -s research/srl_prototype -p "test_*.py"
    if ($LASTEXITCODE -ne 0) {
        throw "SRL Python verification failed (exit $LASTEXITCODE)."
    }

    Write-Host "== SRL Lean verification =="
    if ($LeanExe -ne "") {
        & "$PSScriptRoot\check_lean.ps1" -LeanExe $LeanExe
    } else {
        & "$PSScriptRoot\check_lean.ps1"
    }
    if ($LASTEXITCODE -ne 0) {
        throw "SRL Lean verification failed (exit $LASTEXITCODE)."
    }

    Write-Host "OK: SRL v0.3.1 acceptance checks passed."
} finally {
    Pop-Location
}
