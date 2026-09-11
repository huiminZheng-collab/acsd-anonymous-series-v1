$ErrorActionPreference = 'Stop'
$ProjectDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$OutDir = Join-Path $ProjectDir 'out'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Set-Location -LiteralPath $ProjectDir

$LeanSources = Get-ChildItem -LiteralPath (Join-Path $ProjectDir 'ACSD') -Filter '*.lean' -File
$forbidden = $LeanSources | Select-String -Pattern '\bsorry\b|\badmit\b|^\s*axiom\b' -AllMatches
if ($forbidden) {
  $forbidden | Out-String | Set-Content -Encoding UTF8 (Join-Path $OutDir 'forbidden-proof-tokens.log')
  throw 'Refusing to build: project source contains sorry, admit, or axiom.'
}
$LeanSources.FullName | Set-Content -Encoding UTF8 (Join-Path $OutDir 'source-files.log')
'source token audit: PASS (no sorry, admit, or project-defined axiom declaration)' |
  Set-Content -Encoding UTF8 (Join-Path $OutDir 'source-audit.log')

$LocalLake = Join-Path $ProjectDir 'tools\toolchains\lean-4.33.1-windows\bin\lake.exe'
if (Test-Path -LiteralPath $LocalLake) {
  $LakePath = $LocalLake
} else {
  $Lake = Get-Command lake -ErrorAction SilentlyContinue
  if (-not $Lake) { throw 'Lean/Lake is not available. Install the pinned toolchain before claiming kernel-checked proofs.' }
  $LakePath = $Lake.Source
}

& $LakePath --version | Tee-Object -FilePath (Join-Path $OutDir 'lean-version.txt')
& $LakePath build 2>&1 | Tee-Object -FilePath (Join-Path $OutDir 'build.log')
if ($LASTEXITCODE -ne 0) { throw "lake build failed with exit code $LASTEXITCODE" }
& $LakePath env lean ACSD\AxiomAudit.lean 2>&1 | Tee-Object -FilePath (Join-Path $OutDir 'axioms.txt')
if ($LASTEXITCODE -ne 0) { throw "Lean axiom audit failed with exit code $LASTEXITCODE" }
if (Select-String -Path (Join-Path $OutDir 'axioms.txt') -Pattern 'sorryAx') { throw 'Axiom audit found sorryAx.' }
if (Select-String -Path (Join-Path $OutDir 'axioms.txt') -Pattern 'depends on axioms:') { throw 'Axiom audit found a theorem with an axiom dependency.' }
