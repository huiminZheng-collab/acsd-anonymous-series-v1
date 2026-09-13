$ErrorActionPreference = 'Continue'
$pyCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyCommand) { $pyCommand = Get-Command py -ErrorAction SilentlyContinue }
if (-not $pyCommand) { throw 'neither python nor py was found on PATH' }
$py = $pyCommand.Source
$env:PYTHONDONTWRITEBYTECODE = "1"
& $py check.py
if ($LASTEXITCODE -ne 0) { throw "ACSD check failed with exit code $LASTEXITCODE" }
