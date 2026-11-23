[CmdletBinding()]
param([switch]$AllowLossy)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdBlockRuleEngine.psm1') -Force

# This entry point generates YAML only. TXT has its own independent workflow.
Invoke-AdblockGeneration -Format 'yaml' -Strict:(-not $AllowLossy)
