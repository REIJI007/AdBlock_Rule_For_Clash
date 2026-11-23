BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../AdBlockRuleEngine.psm1') -Force
    function New-Rule {
        param([string]$Domain,[ValidateSet('EXACT','SUFFIX')][string]$MatchType,[ValidateSet('ALLOW','BLOCK')][string]$Action,[ValidateRange(0,4)][int]$Priority)
        [PSCustomObject]@{ Domain=$Domain; MatchType=$MatchType; Action=$Action; Priority=$Priority }
    }
    function Get-ReferenceDecision {
        param([string]$Domain,[object[]]$Rules)
        $matchedRules = @($Rules | Where-Object {
            if ($_.MatchType -eq 'EXACT') { return $_.Domain -ieq $Domain }
            $Domain -ieq $_.Domain -or $Domain.EndsWith('.' + $_.Domain,[StringComparison]::OrdinalIgnoreCase)
        })
        if ($matchedRules.Count -eq 0) { return 'UNKNOWN' }
        return ($matchedRules | Sort-Object Priority | Select-Object -First 1).Action
    }
}

Describe 'Five-tier priority evaluation' {
    It 'P0 allow outranks an ancestor P1 block' {
        $rules = @((New-Rule 'example.com' SUFFIX BLOCK 1),(New-Rule 'safe.example.com' SUFFIX ALLOW 0))
        (Get-AdblockDomainDecision 'api.safe.example.com' $rules).Decision | Should -Be 'ALLOW'
    }
    It 'P1 block outranks a descendant P2 allow' {
        $rules = @((New-Rule 'example.com' SUFFIX BLOCK 1),(New-Rule 'safe.example.com' SUFFIX ALLOW 2))
        (Get-AdblockDomainDecision 'api.safe.example.com' $rules).Decision | Should -Be 'BLOCK'
    }
    It 'P2 suffix allow outranks a P3 exact block' {
        $rules = @((New-Rule 'example.com' SUFFIX ALLOW 2),(New-Rule 'ads.example.com' EXACT BLOCK 3))
        (Get-AdblockDomainDecision 'ads.example.com' $rules).Decision | Should -Be 'ALLOW'
    }
    It 'P2 suffix allow outranks a P4 suffix block regardless of distance' {
        $rules = @((New-Rule 'example.com' SUFFIX BLOCK 4),(New-Rule 'safe.example.com' SUFFIX ALLOW 2))
        (Get-AdblockDomainDecision 'x.safe.example.com' $rules).Decision | Should -Be 'ALLOW'
    }
    It 'P1 exact block overrides a P2 suffix allow' {
        $rules = @((New-Rule 'example.com' SUFFIX ALLOW 2),(New-Rule 'ads.example.com' EXACT BLOCK 1))
        (Get-AdblockDomainDecision 'ads.example.com' $rules).Decision | Should -Be 'BLOCK'
    }
    It 'P3 exact block does not inherit to descendants' {
        $rules = @((New-Rule 'example.com' EXACT BLOCK 3))
        (Get-AdblockDomainDecision 'www.example.com' $rules).Decision | Should -Be 'UNKNOWN'
    }
    It 'suffix matching respects DNS label boundaries' {
        Test-AdblockSuffixMatch 'notexample.com' 'example.com' | Should -BeFalse
        Test-AdblockSuffixMatch 'a.example.com' 'example.com' | Should -BeTrue
        Test-AdblockSuffixMatch 'example.com' 'example.com' | Should -BeTrue
    }
    It 'parses exact domain exception anchors with caret-pipe delimiters' {
        InModuleScope AdBlockRuleEngine {
            $allow = Parse-Rule -line '@@|api.taboola.com^|'
            $allow.Action | Should -Be 'EXCLUDE'
            $allow.Domain | Should -Be 'api.taboola.com'

            $importantAllow = Parse-Rule -line '@@|api.taboola.com^|$important'
            $importantAllow.Action | Should -Be 'EXCLUDE'
            $importantAllow.IsImportant | Should -BeTrue

            $reasonAllow = Parse-Rule -line '@@||api.taboola.com^$reason=known-breakage'
            $reasonAllow.Action | Should -Be 'EXCLUDE'
            $reasonAllow.IsImportant | Should -BeFalse

            $contextAllow = Parse-Rule -line '@@||api.taboola.com^$script'
            $contextAllow.Action | Should -Be 'SKIP'

            $block = Parse-Rule -line '|api.taboola.com^|'
            $block.Action | Should -Be 'EXACT'
            $block.Domain | Should -Be 'api.taboola.com'
        }
    }
    It 'normalizes Unicode IDN domain rules to Punycode' {
        InModuleScope AdBlockRuleEngine {
            $parsed = Parse-Rule -line '||例子.测试^'
            $parsed.Action | Should -Be 'SUFFIX'
            (Normalize-Domain $parsed.Domain) | Should -Be 'xn--fsqu00a.xn--0zwm56d'
        }
    }
    It 'priority numbers are stable' {
        (Get-AdblockRulePriority ALLOW SUFFIX $true) | Should -Be 0
        (Get-AdblockRulePriority BLOCK EXACT $true) | Should -Be 1
        (Get-AdblockRulePriority ALLOW EXACT $false) | Should -Be 2
        (Get-AdblockRulePriority BLOCK EXACT $false) | Should -Be 3
        (Get-AdblockRulePriority BLOCK SUFFIX $false) | Should -Be 4
    }
}

Describe 'Strict parser accounting' {
    It 'fails closed for unknown or unparseable rule syntax' {
        Test-AdblockStrictParseIssue 'no-pattern-match' | Should -BeTrue
        Test-AdblockStrictParseIssue 'whitelist-unparseable' | Should -BeTrue
        Test-AdblockStrictParseIssue 'unresolvable-wildcard' | Should -BeTrue
    }

    It 'allows explicitly classified non-DNS rules to be counted as skipped' {
        Test-AdblockStrictParseIssue 'comment-or-cosmetic' | Should -BeFalse
        Test-AdblockStrictParseIssue 'unsupported-modifier:script' | Should -BeFalse
        Test-AdblockStrictParseIssue 'path-or-query-specific-rule' | Should -BeFalse
    }
}

Describe 'Lossless positive-rule compilation' {
    It 'fails when a suffix block contains a suffix allow hole' {
        $rules = @((New-Rule 'example.com' SUFFIX BLOCK 4),(New-Rule 'safe.example.com' SUFFIX ALLOW 2))
        { Compile-AdblockRules -Rules $rules -Strict $true } | Should -Throw '*PARTIAL_OVERLAP*'
    }
    It 'fails when a suffix block contains an exact allow hole' {
        $rules = @((New-Rule 'example.com' SUFFIX BLOCK 4),(New-Rule 'safe.example.com' EXACT ALLOW 2))
        { Compile-AdblockRules -Rules $rules -Strict $true } | Should -Throw '*PARTIAL_OVERLAP*'
    }
    It 'removes a blacklisted exact name fully covered by a suffix allow' {
        $rules = @((New-Rule 'example.com' SUFFIX ALLOW 2),(New-Rule 'ads.example.com' EXACT BLOCK 3))
        $result = Compile-AdblockRules -Rules $rules -Strict $true
        $result.Exact.Count | Should -Be 0
        $result.Suffix.Count | Should -Be 0
        $result.IsLossless | Should -BeTrue
    }
    It 'prunes nested blocked suffix rules using trie ancestry' {
        $rules = @(
            (New-Rule 'example.com' SUFFIX BLOCK 4),
            (New-Rule 'ads.example.com' SUFFIX BLOCK 4),
            (New-Rule 'tracker.ads.example.com' EXACT BLOCK 3)
        )
        $result = Compile-AdblockRules -Rules $rules -Strict $true
        $result.Suffix.Count | Should -Be 1
        $result.Suffix | Should -Contain 'example.com'
        $result.Exact.Count | Should -Be 0
    }
    It 'keeps a child suffix block below a parent allow and prunes exact duplicates' {
        $rules = @((New-Rule 'example.com' SUFFIX ALLOW 2),(New-Rule 'ads.example.com' SUFFIX BLOCK 1),(New-Rule 'api.ads.example.com' EXACT BLOCK 3))
        $result = Compile-AdblockRules -Rules $rules -Strict $true
        $result.Suffix | Should -Contain 'ads.example.com'
        $result.Exact.Count | Should -Be 0
    }
    It 'preserves a top-level suffix rule as a suffix rule' {
        $result = Compile-AdblockRules -Rules @((New-Rule 'com' SUFFIX BLOCK 4)) -Strict $true
        $result.Suffix | Should -Contain 'com'
        $result.Exact.Count | Should -Be 0
    }
}

Describe 'Rule identity and Public Suffix List' {
    It 'normalizes badfilter identity and preserves other modifiers' {
        $base = Get-AdblockRuleIdentity '||example.com^$important,third-party'
        $cancel = Get-AdblockRuleIdentity '||example.com^$badfilter,third-party,important'
        $different = Get-AdblockRuleIdentity '||example.com^$badfilter,important'
        $cancel | Should -Be $base
        $different | Should -Not -Be $base
    }
    It 'honors exact, wildcard and exception PSL rules' {
        Set-AdblockPublicSuffixRules @('com','uk','co.uk','*.ck','!www.ck') | Should -Be 5
        Get-PublicSuffix 'www.example.co.uk' | Should -Be 'co.uk'
        Get-PublicSuffix 'a.b.ck' | Should -Be 'b.ck'
        Get-PublicSuffix 'www.ck' | Should -Be 'ck'
        Is-PublicSuffix 'co.uk' | Should -BeTrue
        Is-PublicSuffix 'example.co.uk' | Should -BeFalse
    }
}

Describe 'Trie and reference evaluator consistency' {
    It 'matches a linear reference across deterministic random rule sets' {
        $random = [System.Random]::new(20261123)
        $domains = @('example.com','ads.example.com','safe.example.com','api.safe.example.com','tracker.example.net','example.net','a.example.net','shop.example.org')
        $priorities = @(0,1,2,3,4)
        for ($round=0; $round -lt 80; $round++) {
            $rules = [System.Collections.Generic.List[object]]::new()
            for ($i=0; $i -lt 10; $i++) {
                $domain = $domains[$random.Next(0,$domains.Count)]
                $matchType = if ($random.Next(0,2) -eq 0) { 'EXACT' } else { 'SUFFIX' }
                $priority = $priorities[$random.Next(0,$priorities.Count)]
                $action = if ($priority -in @(0,2)) { 'ALLOW' } else { 'BLOCK' }
                if ($priority -eq 3 -and $matchType -eq 'SUFFIX') { $priority = 4 }
                if ($priority -eq 4 -and $matchType -eq 'EXACT') { $priority = 3 }
                $rules.Add((New-Rule $domain $matchType $action $priority))
            }
            foreach ($query in $domains) {
                $expected = Get-ReferenceDecision $query $rules.ToArray()
                $actual = (Get-AdblockDomainDecision $query $rules.ToArray()).Decision
                $actual | Should -Be $expected
            }
        }
    }
}
