#Requires -Version 5.1
<#
.SYNOPSIS
  Install and pair the Orbit computer node as a Windows service.
.DESCRIPTION
  Pinned tagged releases only. Pairs with `orbit-computer-node pair`
  (verified HTTPS), then registers a service running `serve`.
  Uses sc.exe when available; for restart-on-failure prefer nssm
  (see docs/INSTALL.md). Prints status at the end.
.PARAMETER Version
  Pinned release tag, e.g. v0.1.0. Required.
.PARAMETER Server
  https:// server origin. Required (https only).
.PARAMETER PairCode
  One-use owner pairing code. Required.
.PARAMETER CaFile
  Extra root CA for self-signed/fixture setups.
.PARAMETER Bin
  Path to orbit-computer-node.exe (default: PATH lookup).
.PARAMETER DryRun
  Print planned actions, change nothing.
#>
param(
  [string]$Version = $env:ORBIT_VERSION,
  [Parameter(Mandatory = $true)][string]$Server,
  [Parameter(Mandatory = $true)][string]$PairCode,
  [string]$CaFile = "",
  [string]$Bin = "",
  [switch]$DryRun
)
$ErrorActionPreference = "Stop"
if ($Version -match '^refs/tags/(.+)$') { $Version = $Matches[1] }
if ($Version -notmatch '^v\d+\.\d+\.\d+') { throw "refusing unpinned install: pass -Version vX.Y.Z (got '$Version')" }
if ($Server -notlike 'https://*') { throw "-Server must be https:// (node pairs over verified HTTPS only)" }
if ([string]::IsNullOrWhiteSpace($PairCode)) { throw "-PairCode is required" }
if ([string]::IsNullOrWhiteSpace($Bin)) {
  $found = (Get-Command orbit-computer-node -ErrorAction SilentlyContinue)
  if ($null -eq $found) { throw "orbit-computer-node not found (pass -Bin PATH from release $Version)" }
  $Bin = $found.Source
}
$stateDir = if ($env:ORBIT_NODE_STATE_DIR) { $env:ORBIT_NODE_STATE_DIR } else { Join-Path $env:LOCALAPPDATA 'Orbit\Node' }
$config = Join-Path $stateDir 'node.json'
Write-Host "orbit node installer $Version (Windows)"
Write-Host "detect: bin=$Bin state=$stateDir"
$pairArgs = @('--config', $config, 'pair', '--server', $Server, '--code', $PairCode, '--state', $config)
if ($CaFile -ne '') { $pairArgs += @('--ca-file', $CaFile) }
if ($DryRun) {
  Write-Host "[dry-run] New-Item -ItemType Directory $stateDir"
  Write-Host "[dry-run] $Bin --config $config pair --server $Server --code <redacted> --state $config"
  Write-Host "[dry-run] sc.exe create orbit-node binPath= `"$Bin --config $config serve`" start= auto"
  Write-Host "[dry-run] note: for restart-on-failure use nssm (see docs/INSTALL.md)"
  Write-Host "[dry-run] $Bin --config $config status"
  exit 0
}
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
& $Bin @pairArgs
$svcArgs = "`"$Bin`" --config `"$config`" serve"
$existing = (Get-Service orbit-node -ErrorAction SilentlyContinue)
if ($null -ne $existing) { sc.exe delete orbit-node | Out-Null; Start-Sleep -Seconds 2 }
sc.exe create orbit-node binPath= $svcArgs start= auto | Out-Null
sc.exe start orbit-node
Write-Host "note: sc.exe services do not auto-restart on crash; install nssm and run:"
Write-Host "  nssm install orbit-node `"$Bin`" --config `"$config`" serve"
& $Bin --config $config status
Write-Host "node paired and service registered"
