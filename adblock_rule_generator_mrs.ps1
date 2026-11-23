[CmdletBinding()]
param([switch]$AllowLossy)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdBlockRuleEngine.psm1') -Force

# Keep each artifact's entry point and publication workflow independent.
Invoke-AdblockGeneration -Format 'mrs' -SourceConfigPath (Join-Path $PSScriptRoot 'config/upstream-sources.json') -Strict:(-not $AllowLossy)
