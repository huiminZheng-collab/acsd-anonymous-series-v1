$ErrorActionPreference = 'Stop'
$toolchain = 'leanprover/lean4:v4.33.1'
$elan = Get-Command elan -ErrorAction SilentlyContinue
if (-not $elan) { throw 'elan not found on PATH' }
$elanPath = $elan.Source
& $elanPath toolchain install $toolchain
if ($LASTEXITCODE -ne 0) { throw "failed to install $toolchain" }
& $elanPath default $toolchain
