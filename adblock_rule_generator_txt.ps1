[CmdletBinding()]
param([switch]$AllowLossy)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdBlockRuleEngine.psm1') -Force

# This entry point generates TXT only. YAML has its own independent workflow.
Invoke-AdblockGeneration -Format 'txt' -Strict:(-not $AllowLossy)
