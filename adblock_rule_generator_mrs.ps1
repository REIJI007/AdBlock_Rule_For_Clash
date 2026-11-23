[CmdletBinding()]
param([switch]$AllowLossy)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdBlockRuleEngine.psm1') -Force

# This entry point builds only a temporary MRS conversion input.
# The MRS workflow converts it and publishes adblock_reject.mrs independently.
Invoke-AdblockGeneration -Format 'mrs' -Strict:(-not $AllowLossy)
