$ErrorActionPreference = 'Continue'
$pyCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyCommand) { $pyCommand = Get-Command py -ErrorAction SilentlyContinue }
if (-not $pyCommand) { throw 'neither python nor py was found on PATH' }
$py = $pyCommand.Source
$env:ACSD_SKIP_NETWORK = "1"
& $py -m unittest -q 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Python tests failed with exit code $LASTEXITCODE" }
& $py generate_demo.py | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Demo generation failed with exit code $LASTEXITCODE" }
& $py verify_pec.py
if ($LASTEXITCODE -ne 0) { throw "PEC verification failed with exit code $LASTEXITCODE" }
$lakePath = $env:ACSD_LAKE
if (-not $lakePath) {
  $lakeCommand = Get-Command lake -ErrorAction SilentlyContinue
  if ($lakeCommand) { $lakePath = $lakeCommand.Source }
}
if (-not $lakePath) {
  $elanLake = Join-Path $env:USERPROFILE '.elan\bin\lake.exe'
  if (Test-Path $elanLake) { $lakePath = $elanLake }
}
if ($lakePath) {
  Push-Location formal
  try {
    & $lakePath build
    if ($LASTEXITCODE -ne 0) { throw "Lean build failed with exit code $LASTEXITCODE" }
  } finally { Pop-Location }
  Write-Output '{"formal_status":"PASS","lean":"4.33.1"}'
} else {
  Write-Output '{"formal_status":"PENDING_TOOLCHAIN","hint":"set ACSD_LAKE to lake executable"}'
}
