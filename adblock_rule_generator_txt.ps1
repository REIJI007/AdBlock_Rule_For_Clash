[CmdletBinding()]
param([switch]$AllowLossy)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdBlockRuleEngine.psm1') -Force
Invoke-AdblockGeneration -Format 'txt' -Strict:(-not $AllowLossy)
