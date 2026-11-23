[CmdletBinding()]
param([switch]$AllowLossy)
& (Join-Path $PSScriptRoot 'Build-AdblockRules.ps1') -AllowLossy:$AllowLossy
