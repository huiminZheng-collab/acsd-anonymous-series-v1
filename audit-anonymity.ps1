$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$deny = @(
  ('z' + 'heng'),
  ('C:' + '\\Users\\'),
  ('C:' + '/Users/'),
  ('Documents' + '\\Codex'),
  ('\\.' + 'codex\\'),
  ('@' + 'gmail\\.com'),
  ('@' + 'outlook\\.com'),
  ('@' + 'qq\\.com'),
  ('orcid' + '\\.org')
)
$forbiddenDirectories = @('private-test-keys', '.deps', 'node_modules', '__pycache__', '.npm-cache')
$hits = [System.Collections.Generic.List[string]]::new()

foreach ($directory in Get-ChildItem -LiteralPath $root -Recurse -Directory -Force) {
  if ($directory.Name -in $forbiddenDirectories) {
    $hits.Add("forbidden directory: $($directory.FullName)")
  }
}

foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File -Force) {
  if ($file.FullName -match '\\.git\\') { continue }
  $relative = $file.FullName.Substring($root.Length + 1)
  if ($file.Extension -ieq '.pdf') {
    $text = (& pdftotext $file.FullName - 2>$null | Out-String) + (& pdfinfo $file.FullName 2>$null | Out-String)
  } else {
    try { $text = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($file.FullName)) }
    catch { $text = '' }
  }
  foreach ($pattern in $deny) {
    if ($text -match $pattern) { $hits.Add("$relative matches deny pattern: $pattern") }
  }
}

if ($hits.Count -gt 0) { throw ($hits -join [Environment]::NewLine) }
Write-Output (ConvertTo-Json @{ schema = 'acsd-anonymity-audit/v1'; result = 'PASS'; scope = 'public payload plus PDF text and metadata' } -Compress)
