[CmdletBinding()]
param([switch]$AllowLossy)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdBlockRuleEngine.psm1') -Force
Invoke-AdblockGeneration -Format 'yaml' -Strict:(-not $AllowLossy)
