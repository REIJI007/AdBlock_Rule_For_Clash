[CmdletBinding()]
param([switch]$AllowLossy)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdBlockRuleEngine.psm1') -Force

try {
    Invoke-AdblockRuleBuild -RepositoryRoot $PSScriptRoot -SourceConfigPath (Join-Path $PSScriptRoot 'config/upstream-sources.json') -AllowLossy:$AllowLossy | Format-List
}
catch {
    Write-Error $_
    exit 1
}
