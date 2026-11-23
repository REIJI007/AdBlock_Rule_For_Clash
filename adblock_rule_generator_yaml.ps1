[CmdletBinding()]
param([ValidateSet('yaml','txt','both')][string]$Format = 'yaml',[switch]$AllowLossy)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdBlockRuleEngine.psm1') -Force
Invoke-AdblockGeneration -Format $Format -Strict:(-not $AllowLossy)
