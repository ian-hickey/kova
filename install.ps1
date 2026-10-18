# kova installer for Windows -- https://kovaverified.io/install.ps1
#   irm https://kovaverified.io/install.ps1 | iex
# Downloads the latest release for this architecture from GitHub Releases, verifies the
# published SHA-256, installs to %LOCALAPPDATA%\Programs\kova and adds it to the user PATH.
# Override: $env:KOVA_VERSION (tag), $env:KOVA_INSTALL_DIR (folder).
$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$Repo = 'ian-hickey/kova'
$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'amd64' }
  'ARM64' { 'arm64' }
  default { throw "kova: unsupported architecture $($env:PROCESSOR_ARCHITECTURE)" }
}

$Version = $env:KOVA_VERSION
if (-not $Version) {
  $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'kova-installer' }
  $Version = $rel.tag_name
}
if (-not $Version) { throw 'kova: could not determine the latest release (set $env:KOVA_VERSION, e.g. v0.1.0)' }

$Asset = "kova-windows-$Arch.exe"
$Url   = "https://github.com/$Repo/releases/download/$Version/$Asset"
$Dir   = if ($env:KOVA_INSTALL_DIR) { $env:KOVA_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\kova' }
$Tmp   = Join-Path ([System.IO.Path]::GetTempPath()) ("kova-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $Dir, $Tmp | Out-Null

Write-Host "Downloading kova $Version for windows/$Arch ..."
$Exe = Join-Path $Tmp $Asset
Invoke-WebRequest -Uri $Url -OutFile $Exe -UseBasicParsing

$Sha = "$Exe.sha256"
$haveSha = $true
try { Invoke-WebRequest -Uri "$Url.sha256" -OutFile $Sha -UseBasicParsing } catch { $haveSha = $false }
if ($haveSha) {
  $want = ((Get-Content -Path $Sha -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
  $got  = (Get-FileHash -Algorithm SHA256 -Path $Exe).Hash.ToLowerInvariant()
  if ($got -ne $want) { Remove-Item -Recurse -Force $Tmp; throw "kova: checksum mismatch for $Asset" }
} else {
  Write-Host 'kova: no checksum published for this asset, skipping verification'
}

Move-Item -Force -Path $Exe -Destination (Join-Path $Dir 'kova.exe')
Remove-Item -Recurse -Force $Tmp
Write-Host "Installed $Dir\kova.exe"

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $Dir) {
  [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $Dir), 'User')
  $env:Path = "$env:Path;$Dir"
  Write-Host "Added $Dir to your user PATH (new terminals pick it up automatically)."
}

Write-Host ''
Write-Host 'Next:  kova init        # pin this machine''s agent tools and install session hooks'
Write-Host '       kova wrap --all  # route MCP servers through the verifying proxy'
