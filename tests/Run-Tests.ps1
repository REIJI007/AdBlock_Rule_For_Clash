Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '../AdBlockRuleEngine.psm1') -Force

function Assert-Equal {
    param($Actual,$Expected,[string]$Message)
    if ($Actual -ne $Expected) {
        throw "ASSERT FAILED: $Message; expected=[$Expected], actual=[$Actual]"
    }
}
function Assert-True {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw "ASSERT FAILED: $Message" }
}

Initialize-AdblockPsl -Content @'
com
uk
co.uk
*.ck
!www.ck
'@

Assert-Equal (Get-AdblockPublicSuffix 'shop.example.co.uk') 'co.uk' 'PSL exact multi-label suffix'
Assert-Equal (Get-AdblockPublicSuffix 'a.b.ck') 'b.ck' 'PSL wildcard suffix'
Assert-Equal (Get-AdblockPublicSuffix 'www.ck') 'ck' 'PSL exception rule'
Assert-True (Test-AdblockPublicSuffix 'co.uk') 'PSL public suffix membership'
Assert-True (Test-AdblockDnsDomain 'com' -AllowPublicSuffix) 'single-label PSL suffix is parseable'
Assert-True (-not (Test-AdblockDnsDomain '1.2.3.4' -AllowPublicSuffix)) 'IPv4 literals are not DNS host rules'

# Priority is evaluated globally, not by nearest domain label.
$rules = @(
    (New-AdblockRule -Domain 'example.com' -MatchType SUFFIX -Action ALLOW),
    (New-AdblockRule -Domain 'ads.example.com' -MatchType EXACT -Action BLOCK),
    (New-AdblockRule -Domain 'important.example.com' -MatchType SUFFIX -Action BLOCK -IsImportant $true),
    (New-AdblockRule -Domain 'vip.important.example.com' -MatchType EXACT -Action ALLOW -IsImportant $true)
)
$trie = New-AdblockRuleTrie -Rules $rules
Assert-Equal (Get-AdblockDecision -Trie $trie -Domain 'ads.example.com') 'ALLOW' 'P2 suffix allow outranks P3 exact block'
Assert-Equal (Get-AdblockDecision -Trie $trie -Domain 'x.important.example.com') 'BLOCK' 'P1 suffix block outranks P2 allow ancestor'
Assert-Equal (Get-AdblockDecision -Trie $trie -Domain 'vip.important.example.com') 'ALLOW' 'P0 exact allow outranks P1 suffix block'
Assert-Equal (Get-AdblockDecision -Trie $trie -Domain 'notexample.com') 'UNKNOWN' 'suffix boundary must include a dot'

$exactOnly = New-AdblockRuleTrie -Rules @(
    (New-AdblockRule -Domain 'ads.example.com' -MatchType EXACT -Action BLOCK)
)
Assert-Equal (Get-AdblockDecision -Trie $exactOnly -Domain 'ads.example.com') 'BLOCK' 'P3 exact rule matches apex'
Assert-Equal (Get-AdblockDecision -Trie $exactOnly -Domain 'x.ads.example.com') 'UNKNOWN' 'P3 exact rule does not inherit'

$parsedBase = Parse-AdblockRuleLine -Line '||example.com^$important' -DefaultAction BLOCK
$parsedCancel = Parse-AdblockRuleLine -Line '||example.com^$important,badfilter' -DefaultAction BLOCK
$parsedOther = Parse-AdblockRuleLine -Line '||example.com^$badfilter' -DefaultAction BLOCK
Assert-Equal $parsedBase.Identity $parsedCancel.Identity 'badfilter identity includes priority modifiers'
$resolved = Resolve-AdblockRuleSet -ParsedRules @($parsedBase,$parsedCancel)
Assert-Equal $resolved.Rules.Count 0 'matching badfilter cancels its exact base rule'
$resolvedOther = Resolve-AdblockRuleSet -ParsedRules @($parsedBase,$parsedOther)
Assert-Equal $resolvedOther.Rules.Count 1 'badfilter without important does not cancel important rule'

$blockedParent = New-AdblockRule -Domain 'example.com' -MatchType SUFFIX -Action BLOCK
$allowExactChild = New-AdblockRule -Domain 'safe.example.com' -MatchType EXACT -Action ALLOW
$partial = Get-AdblockCompilation -Rules @($blockedParent,$allowExactChild)
Assert-Equal $partial.Status 'UNREPRESENTABLE' 'suffix block plus exact whitelist is unrepresentable'
Assert-Equal $partial.Conflicts[0].Type 'PARTIAL_OVERLAP' 'partial overlap is diagnosed'

# A P0 exact exception at a blocked suffix apex must not make the unblocked
# descendants disappear from analysis: the descendant space remains blocked.
$p0ApexAllow = New-AdblockRule -Domain 'p0.example.org' -MatchType EXACT -Action ALLOW -IsImportant $true
$p4SameSuffix = New-AdblockRule -Domain 'p0.example.org' -MatchType SUFFIX -Action BLOCK
$p0Partial = Get-AdblockCompilation -Rules @($p0ApexAllow,$p4SameSuffix)
Assert-Equal $p0Partial.Status 'UNREPRESENTABLE' 'P0 exact apex exception plus P4 suffix block is unrepresentable'

# A P1 exact block takes precedence only at its own name; a P2 suffix allow
# controls descendants. The resulting block set is exactly one DOMAIN rule.
$p1ApexBlock = New-AdblockRule -Domain 'p1.example.org' -MatchType EXACT -Action BLOCK -IsImportant $true
$p2SameSuffixAllow = New-AdblockRule -Domain 'p1.example.org' -MatchType SUFFIX -Action ALLOW
$p4SameSuffixBlock = New-AdblockRule -Domain 'p1.example.org' -MatchType SUFFIX -Action BLOCK
$p1ExactOnly = Get-AdblockCompilation -Rules @($p1ApexBlock,$p2SameSuffixAllow,$p4SameSuffixBlock)
Assert-Equal $p1ExactOnly.Status 'EXACT' 'P1 exact exception boundary leaves descendants controlled by P2 suffix allow'
Assert-Equal $p1ExactOnly.OutputRules.Count 1 'only P1 exact domain remains blocked'
Assert-Equal $p1ExactOnly.OutputRules[0].Type 'DOMAIN' 'P1 exact result is emitted as DOMAIN'
Assert-Equal $p1ExactOnly.OutputRules[0].Domain 'p1.example.org' 'P1 apex domain is preserved'

$allowParent = New-AdblockRule -Domain 'example.com' -MatchType SUFFIX -Action ALLOW
$coveredChild = New-AdblockRule -Domain 'ads.example.com' -MatchType SUFFIX -Action BLOCK
$covered = Get-AdblockCompilation -Rules @($allowParent,$coveredChild)
Assert-Equal $covered.Status 'EXACT' 'higher priority parent allow fully suppresses ordinary suffix block'
Assert-Equal $covered.OutputRules.Count 0 'fully covered blacklist omitted'

$disjointBlock = New-AdblockRule -Domain 'bad.example.com' -MatchType SUFFIX -Action BLOCK
$disjointAllow = New-AdblockRule -Domain 'safe.other.net' -MatchType SUFFIX -Action ALLOW
$disjoint = Get-AdblockCompilation -Rules @($disjointBlock,$disjointAllow)
Assert-Equal $disjoint.Status 'EXACT' 'disjoint allowlist does not affect blacklist'
Assert-Equal $disjoint.OutputRules.Count 1 'disjoint suffix rule retained'
Assert-Equal $disjoint.OutputRules[0].Type 'DOMAIN-SUFFIX' 'suffix emitted as DOMAIN-SUFFIX'

$parent = New-AdblockRule -Domain 'example.com' -MatchType SUFFIX -Action BLOCK
$childSuffix = New-AdblockRule -Domain 'ads.example.com' -MatchType SUFFIX -Action BLOCK
$childExact = New-AdblockRule -Domain 'api.example.com' -MatchType EXACT -Action BLOCK
$compressed = Get-AdblockCompilation -Rules @($parent,$childSuffix,$childExact)
Assert-Equal $compressed.OutputRules.Count 1 'reverse trie compression removes covered child rules'
Assert-Equal $compressed.OutputRules[0].Domain 'example.com' 'broadest safe suffix retained'

$hosts = Parse-AdblockRuleLine -Line '0.0.0.0 ads.example.com tracker.example.com' -DefaultAction BLOCK
Assert-Equal $hosts.Count 2 'hosts lines may contain multiple host names'
Assert-Equal $hosts[1].MatchType 'EXACT' 'hosts records retain exact match type'

$hostsAllow = Parse-AdblockRuleLine -Line '0.0.0.0 allow.example.com' -DefaultAction ALLOW -HostsMatchType SUFFIX
Assert-Equal $hostsAllow[0].MatchType 'SUFFIX' 'hosts allowlist match scope is explicit per source'

$unsupported = Parse-AdblockRuleLine -Line '||example.com^$script' -DefaultAction BLOCK
Assert-Equal $unsupported.State 'OutOfScope' 'context-sensitive modifier is not widened to a DNS block'

$unboundedAnchor = Parse-AdblockRuleLine -Line '||example.com' -DefaultAction BLOCK
Assert-Equal $unboundedAnchor.State 'OutOfScope' 'domain-anchor without caret boundary is not widened to a suffix rule'
$suffixAnchor = Parse-AdblockRuleLine -Line '||example.com^' -DefaultAction BLOCK
Assert-Equal $suffixAnchor.MatchType 'SUFFIX' 'caret-bounded domain anchor maps to suffix'

$allowSourceRule = Parse-AdblockRuleLine -Line '||example.net^' -DefaultAction ALLOW
Assert-Equal $allowSourceRule.Action 'ALLOW' 'source default action is explicit'
Assert-Equal $allowSourceRule.Priority 2 'normal source allow maps to P2'
$importantAllow = Parse-AdblockRuleLine -Line '@@||example.net^$important' -DefaultAction BLOCK
Assert-Equal $importantAllow.Priority 0 'important allow maps to P0'

$plainAllow = Parse-AdblockRuleLine -Line 'safe.example.net' -DefaultAction ALLOW -PlainDomainMatchType SUFFIX
Assert-Equal $plainAllow.MatchType 'SUFFIX' 'plain allowlist host match type comes from source metadata'
$plainBlock = Parse-AdblockRuleLine -Line 'ads.example.net' -DefaultAction BLOCK -PlainDomainMatchType EXACT
Assert-Equal $plainBlock.MatchType 'EXACT' 'plain blocklist host match type comes from source metadata'

# A top-level public suffix remains a suffix rule; PSL classification must
# never rewrite its original match type to EXACT.
$tldRule = Parse-AdblockRuleLine -Line '||com^' -DefaultAction BLOCK
Assert-Equal $tldRule.MatchType 'SUFFIX' 'PSL apex rules preserve suffix match type'
$tldCompiled = Get-AdblockCompilation -Rules @($tldRule)
Assert-Equal $tldCompiled.OutputRules.Count 1 'PSL suffix rule is emitted'
Assert-Equal $tldCompiled.OutputRules[0].Type 'DOMAIN-SUFFIX' 'PSL suffix is never rewritten to DOMAIN'
Assert-Equal $tldCompiled.OutputRules[0].Domain 'com' 'TLD suffix identity is preserved'

# Deterministic property test: insertion order cannot change matching results.
$random = [System.Random]::new(20261123)
$randomRules = [System.Collections.Generic.List[object]]::new()
$labels = @('ads','track','api','safe','cdn','metrics','img','edge')
foreach ($label in $labels) {
    $action = if ($random.Next(0,2) -eq 0) { 'BLOCK' } else { 'ALLOW' }
    $match = if ($random.Next(0,2) -eq 0) { 'EXACT' } else { 'SUFFIX' }
    $important = ($random.Next(0,5) -eq 0)
    $randomRules.Add((New-AdblockRule -Domain "$label.example.net" -MatchType $match -Action $action -IsImportant $important))
}
$forward = New-AdblockRuleTrie -Rules $randomRules.ToArray()
$reversedRules = [object[]]$randomRules.ToArray()
[array]::Reverse($reversedRules)
$reverse = New-AdblockRuleTrie -Rules $reversedRules
foreach ($host in @('example.net','ads.example.net','x.ads.example.net','safe.example.net','new.other.net')) {
    Assert-Equal (Get-AdblockDecision -Trie $forward -Domain $host) (Get-AdblockDecision -Trie $reverse -Domain $host) "rule-order invariance for $host"
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ('adblock-test-' + [Guid]::NewGuid().ToString('N'))
try {
    Write-AdblockCompiledOutputs -Rules @(
        [PSCustomObject]@{ Type='DOMAIN'; Domain='api.example.com' },
        [PSCustomObject]@{ Type='DOMAIN-SUFFIX'; Domain='ads.example.net' }
    ) -OutputDirectory $temp
    $yaml = Get-Content (Join-Path $temp 'adblock_reject.yaml') -Raw
    $txt = Get-Content (Join-Path $temp 'adblock_reject.txt') -Raw
    $domainYaml = Get-Content (Join-Path $temp 'adblock_reject_domain.yaml') -Raw
    Assert-True ($yaml -match 'DOMAIN,api\.example\.com' -and $yaml -match 'DOMAIN-SUFFIX,ads\.example\.net') 'YAML emits both supported rule types'
    Assert-True ($txt -match '^DOMAIN,api\.example\.com' -and $txt -match 'DOMAIN-SUFFIX,ads\.example\.net') 'TXT emits same rules as plain text'
    Assert-True ($txt -notmatch 'payload:|ALLOW|WHITELIST') 'TXT contains only positive blacklist expressions'
    Assert-True ($domainYaml -match 'api\.example\.com' -and $domainYaml -match '\+\.ads\.example\.net') 'MRS domain input preserves exact and apex-inclusive suffix semantics'
    Assert-True ($domainYaml -notmatch 'full:') 'MRS domain behavior does not use classical full: syntax'
}
finally {
    if (Test-Path $temp) { Remove-Item $temp -Recurse -Force }
}

$configPath = Join-Path $PSScriptRoot '../config/upstream-sources.json'
$config = Get-Content $configPath -Raw | ConvertFrom-Json
Assert-True ($config.sources.Count -ge 300) 'migrated upstream config retains the complete 300+ source set'
foreach ($source in $config.sources) {
    Assert-True ($source.defaultAction -in @('BLOCK','ALLOW')) "explicit action configured for $($source.url)"
    Assert-True ($source.plainDomainMatchType -in @('EXACT','SUFFIX')) "plain domain semantics configured for $($source.url)"
    Assert-True ($source.hostsMatchType -in @('EXACT','SUFFIX')) "hosts semantics configured for $($source.url)"
    Assert-True ($null -ne $source.required) "required/optional policy configured for $($source.url)"
}

Write-Host 'All AdBlock rule-engine tests passed.'
