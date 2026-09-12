$ErrorActionPreference = 'Stop'
$env:PYTHONDONTWRITEBYTECODE = '1'
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$PythonExe = if (Test-Path -LiteralPath $BundledPython) { $BundledPython } else { (Get-Command python -ErrorAction Stop).Source }
$DepsDir = Join-Path $ProjectDir '.deps'
$VendorDir = Join-Path $ProjectDir 'vendor'
if (-not (Test-Path -LiteralPath (Join-Path $DepsDir 'cbor2\__init__.py'))) {
    & $PythonExe -m pip install --target $DepsDir --require-hashes --no-index --find-links $VendorDir -r (Join-Path $ProjectDir 'requirements.lock')
    if ($LASTEXITCODE -ne 0) { throw 'Offline cbor2 installation failed' }
}
& $PythonExe (Join-Path $ProjectDir 'generate.py')
if ($LASTEXITCODE -ne 0) { throw 'anonymous series fixture generation failed' }
node (Join-Path $ProjectDir 'verify-standalone.cjs') 'artifacts/standalone-packages/p-v1.json'
if ($LASTEXITCODE -ne 0) { throw 'standalone-only verification failed' }
node (Join-Path $ProjectDir 'verify-independent.cjs')
if ($LASTEXITCODE -ne 0) { throw 'independent series verification failed' }
node (Join-Path $ProjectDir 'build-manifest.cjs')
if ($LASTEXITCODE -ne 0) { throw 'public manifest construction failed' }
node (Join-Path $ProjectDir 'verify-manifest.cjs')
if ($LASTEXITCODE -ne 0) { throw 'public manifest verification failed' }
