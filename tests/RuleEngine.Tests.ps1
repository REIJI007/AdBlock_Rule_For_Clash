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


Describe 'Explicit source semantics and ingestion safeguards' {
    It 'uses per-source plain-domain and hosts matching metadata' {
        InModuleScope AdBlockRuleEngine {
            $plainBlock = Parse-Rule -line 'ads.example.com'
            (Get-AdblockMatchType -Parsed $plainBlock -RawRule 'ads.example.com' -PlainDomainMatchType EXACT -HostsMatchType EXACT) | Should -Be 'EXACT'
            (Get-AdblockMatchType -Parsed $plainBlock -RawRule 'ads.example.com' -PlainDomainMatchType SUFFIX -HostsMatchType EXACT) | Should -Be 'SUFFIX'

            $plainAllow = Parse-Rule -line 'safe.example.com' -isWhitelistSource $true
            (Get-AdblockMatchType -Parsed $plainAllow -RawRule 'safe.example.com' -PlainDomainMatchType SUFFIX -HostsMatchType EXACT) | Should -Be 'SUFFIX'

            $hosts = Parse-Rule -line '0.0.0.0 tracker.example.com'
            (Get-AdblockMatchType -Parsed $hosts -RawRule '0.0.0.0 tracker.example.com' -PlainDomainMatchType EXACT -HostsMatchType SUFFIX) | Should -Be 'SUFFIX'
        }
    }

    It 'does not widen an unbounded domain anchor into a suffix rule' {
        InModuleScope AdBlockRuleEngine {
            $block = Parse-Rule -line '||example.com'
            $block.Action | Should -Be 'SKIP'
            $block.SkipReason | Should -Be 'unbounded-domain-anchor'

            $allow = Parse-Rule -line '@@||example.com'
            $allow.Action | Should -Be 'SKIP'
            $allow.SkipReason | Should -Be 'unbounded-domain-anchor'
        }
    }

    It 'reads bounded HTTP responses and computes the hash from original bytes' {
        InModuleScope AdBlockRuleEngine {
            $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::OK)
            try {
                $body = '||example.com^' + [Environment]::NewLine
                $response.Content = [System.Net.Http.StringContent]::new($body,[System.Text.Encoding]::UTF8,'text/plain')
                $result = Read-AdblockHttpResponse -Response $response -MaxBytes 1024
                $result.Content | Should -Be $body
                $result.Bytes | Should -Be ([System.Text.Encoding]::UTF8.GetByteCount($body))
                $result.Sha256 | Should -Match '^[0-9a-f]{64}$'
                $result.StatusCode | Should -Be 200
            }
            finally {
                $response.Dispose()
            }
        }
    }

    It 'rejects oversized and HTML error responses' {
        InModuleScope AdBlockRuleEngine {
            $oversized = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::OK)
            try {
                $oversized.Content = [System.Net.Http.StringContent]::new(('x' * 100))
                { Read-AdblockHttpResponse -Response $oversized -MaxBytes 10 } | Should -Throw '*maxBytes*'
            }
            finally {
                $oversized.Dispose()
            }

            $html = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::OK)
            try {
                $html.Content = [System.Net.Http.StringContent]::new('<!doctype html><html>upstream error</html>')
                { Read-AdblockHttpResponse -Response $html -MaxBytes 1024 } | Should -Throw '*HTML*'
            }
            finally {
                $html.Dispose()
            }
        }
    }

    It 'expands known-safe lines while failing closed on conditional uBO directives' {
        InModuleScope AdBlockRuleEngine {
            $client = [System.Net.Http.HttpClient]::new()
            $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $manifest = [System.Collections.Generic.List[object]]::new()
            try {
                $content = @'
||before.example^
!#if env_chromium
||conditional.example^
!#endif
||after.example^
'@
                $expanded = Expand-AdblockIncludes -Content $content -SourceUrl 'https://example.test/list.txt' -Client $client -Visited $visited -IncludeManifest $manifest
                $expanded.Lines.Count | Should -Be 2
                $expanded.Lines[0].Text | Should -Be '||before.example^'
                $expanded.Lines[1].Text | Should -Be '||after.example^'
                $expanded.Issues.Count | Should -Be 1
                $expanded.Issues[0] | Should -Match 'conditional-preprocessor-not-evaluated'
            }
            finally {
                $client.Dispose()
            }
        }
    }

    It 'keeps the 317-source manifest complete and validates all operational metadata' {
        $manifestPath = Join-Path $PSScriptRoot '../sources.json'
        $sources = @(Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json)
        $sources.Count | Should -Be 317
        (@($sources | Where-Object enabled).Count) | Should -Be 316
        (@($sources | Where-Object { $_.enabled -and $_.required }).Count) | Should -Be 315
        (@($sources | Where-Object { $_.enabled -and $_.defaultAction -eq 'ALLOW' }).Count) | Should -Be 35
        (@($sources | Select-Object -ExpandProperty url -Unique)).Count | Should -Be 317
        (@($sources | Where-Object defaultAction -eq 'ALLOW')).Count | Should -Be 36
        (@($sources | Where-Object preprocessor -eq 'UBO')).Count | Should -Be 33

        foreach ($source in $sources) {
            $source.syntax | Should -BeIn @('AUTO','ADBLOCK','HOSTS','DNSMASQ')
            $source.preprocessor | Should -BeIn @('NONE','UBO')
            $source.plainDomainMatchType | Should -BeIn @('EXACT','SUFFIX')
            $source.hostsMatchType | Should -BeIn @('EXACT','SUFFIX')
            $source.required | Should -BeOfType ([bool])
            $source.enabled | Should -BeOfType ([bool])
            $source.maxBytes | Should -BeGreaterThan 0
            $source.retries | Should -BeIn @(0,1,2,3,4,5)
            $source.timeoutSeconds | Should -BeIn @(30,45,60,75,90,120,180,240,300)
            ([Uri]$source.url).Scheme | Should -Be 'https'
        }
    }
}

    
Describe 'AdGuard SDNS internal exclusion scope' {
    It 'does not compile AdGuard SDNS internal exclusions as a global allowlist' {
        $manifestPath = Join-Path $PSScriptRoot '../sources.json'
        $sources = @(Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json)
        $internalExclusions = $sources | Where-Object { $_.id -eq 'source-236' }
        $internalExclusions.Count | Should -Be 1
        $internalExclusions.url | Should -Match '/Filters/exclusions\.txt$'
        $internalExclusions.enabled | Should -BeFalse
        $internalExclusions.required | Should -BeFalse

        InModuleScope AdBlockRuleEngine {
            $active = @(Get-AdblockSourceConfig)
            ($active | Where-Object { $_.id -eq 'source-236' }).Count | Should -Be 0
        }
    }

}
