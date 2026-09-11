$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location (Join-Path $root 'artifact')
try { .\run.ps1 } finally { Pop-Location }
node (Join-Path $root 'verify-release-manifest.cjs')
