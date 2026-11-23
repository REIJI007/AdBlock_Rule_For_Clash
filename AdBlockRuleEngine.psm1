# AdBlockRuleEngine.psm1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:SourceConfigByUrl = @{}
$script:PslRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Normalize-Domain([string]$Domain) {
    if ([string]::IsNullOrWhiteSpace($Domain)) { return $null }
    $d = $Domain.Trim().TrimEnd('.').ToLowerInvariant()
    try {
        $idn = [System.Globalization.IdnMapping]::new()
        $idn.UseStd3AsciiRules = $true
        return $idn.GetAscii($d).ToLowerInvariant()
    } catch { return $d }
}

function Is-ValidDNSDomain([string]$Domain) {
    if ([string]::IsNullOrWhiteSpace($Domain)) { return $false }
    $d = Normalize-Domain $Domain
    if ($null -eq $d -or $d.Length -gt 253) { return $false }
    if ($d -match '[\s\(\)\[\]\/\\:\;@\,\+]' -or $d -match '_') { return $false }
    $labels = $d -split '\.'
    # Single-label public suffixes (for example "com") are valid filter patterns.
    if ($labels.Count -lt 1) { return $false }
    foreach ($label in $labels) {
        if ($label.Length -eq 0 -or $label.Length -gt 63) { return $false }
        if ($label -notmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$') { return $false }
    }
    return $true
}

function Resolve-WildcardDomain([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    if ($Raw -match '^\*+\.(.+)$') {
        $candidate = Normalize-Domain $Matches[1]
        if (Is-ValidDNSDomain $candidate) { return $candidate }
    }
    return $null
}

function Get-PublicSuffix([string]$Domain) {
    $d = Normalize-Domain $Domain
    if (-not (Is-ValidDNSDomain $d) -or $script:PslRules.Count -eq 0) { return $null }
    $labels = $d -split '\.'
    $bestLength = 1
    $exceptionLength = 0
    for ($i = 0; $i -lt $labels.Length; $i++) {
        $candidate = ($labels[$i..($labels.Length - 1)] -join '.')
        if ($script:PslRules.Contains("!$candidate")) {
            $candidateLength = $labels.Length - $i - 1
            if ($candidateLength -gt $exceptionLength) { $exceptionLength = $candidateLength }
        }
        if ($script:PslRules.Contains($candidate)) {
            $candidateLength = $labels.Length - $i
            if ($candidateLength -gt $bestLength) { $bestLength = $candidateLength }
        }
        if ($i -lt ($labels.Length - 1)) {
            $wildcardSuffix = ($labels[($i + 1)..($labels.Length - 1)] -join '.')
            if ($script:PslRules.Contains("*.$wildcardSuffix")) {
                $candidateLength = $labels.Length - $i
                if ($candidateLength -gt $bestLength) { $bestLength = $candidateLength }
            }
        }
    }
    if ($exceptionLength -gt 0) { $bestLength = $exceptionLength }
    return ($labels[($labels.Length - $bestLength)..($labels.Length - 1)] -join '.')
}

function Is-PublicSuffix([string]$Domain) {
    $suffix = Get-PublicSuffix $Domain
    return ($null -ne $suffix -and (Normalize-Domain $Domain) -eq $suffix)
}

function Get-AdblockRuleIdentity([string]$RawRule) {
    if ([string]::IsNullOrWhiteSpace($RawRule)) { return $null }
    $line = $RawRule.Trim().ToLowerInvariant()
    $dollar = $line.IndexOf('$')
    if ($dollar -lt 0) { return $line }
    $pattern = $line.Substring(0, $dollar)
    $mods = @(
        $line.Substring($dollar + 1).Split(',') |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and (($_ -split '=')[0] -ne 'badfilter') } |
        Sort-Object
    )
    if ($mods.Count -eq 0) { return $pattern }
    return ($pattern + '$' + ($mods -join ','))
}

function Get-AdblockMatchType([object]$Parsed, [string]$RawRule) {
    if ($Parsed.IsWildcard) { return 'WILDCARD' }
    if ($RawRule -match '^@@\|\|') { return 'SUFFIX' }
    if ($RawRule -match '^\|[a-zA-Z0-9]') { return 'EXACT' }
    switch -Regex ($Parsed.SourceFormat) {
        'suffix|dnsmasq' { return 'SUFFIX' }
        default { return 'EXACT' }
    }
}

function Get-AdblockRulePriority([string]$Action, [string]$MatchType, [bool]$IsImportant) {
    if ($Action -eq 'ALLOW') { if ($IsImportant) { return 0 }; return 2 }
    if ($Action -eq 'BLOCK') {
        if ($IsImportant) { return 1 }
        if ($MatchType -eq 'EXACT') { return 3 }
        if ($MatchType -eq 'SUFFIX') { return 4 }
    }
    throw "Unsupported rule action/match type: $Action / $MatchType"
}

function Test-AdblockSuffixMatch([string]$QueryDomain, [string]$RuleDomain) {
    $q = Normalize-Domain $QueryDomain
    $r = Normalize-Domain $RuleDomain
    if ([string]::IsNullOrWhiteSpace($q) -or [string]::IsNullOrWhiteSpace($r)) { return $false }
    return ($q -eq $r -or $q.EndsWith('.' + $r, [System.StringComparison]::OrdinalIgnoreCase))
}

function Test-AdblockDomainWithin([string]$Domain, [string]$Root) {
    return Test-AdblockSuffixMatch -QueryDomain $Domain -RuleDomain $Root
}

function New-AdblockRuleIndex([object[]]$Rules) {
    $newNode = { [PSCustomObject]@{
        Children = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Rules = [System.Collections.Generic.List[object]]::new()
    } }
    $root = & $newNode
    $exact = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $Rules) {
        if ($rule.MatchType -eq 'SUFFIX') {
            $labels = ([string]$rule.Domain).Split('.')
            [array]::Reverse($labels)
            $node = $root
            foreach ($label in $labels) {
                if (-not $node.Children.ContainsKey($label)) { $node.Children.Add($label, (& $newNode)) }
                $node = $node.Children[$label]
            }
            $node.Rules.Add($rule)
        } elseif ($rule.MatchType -eq 'EXACT') {
            $d = [string]$rule.Domain
            if (-not $exact.ContainsKey($d)) { $exact.Add($d, [System.Collections.Generic.List[object]]::new()) }
            $exact[$d].Add($rule)
        }
    }
    return [PSCustomObject]@{ SuffixRoot = $root; Exact = $exact }
}

function Get-AdblockSuffixMatches([string]$Domain, [object]$Index) {
    $labels = (Normalize-Domain $Domain).Split('.')
    [array]::Reverse($labels)
    $matches = [System.Collections.Generic.List[object]]::new()
    $node = $Index.SuffixRoot
    foreach ($label in $labels) {
        if (-not $node.Children.ContainsKey($label)) { break }
        $node = $node.Children[$label]
        foreach ($rule in $node.Rules) { $matches.Add($rule) }
    }
    return ,$matches.ToArray()
}

function Get-AdblockBestRule([object[]]$Matches) {
    $winner = $null
    foreach ($rule in $Matches) {
        if ($null -eq $winner -or [int]$rule.Priority -lt [int]$winner.Priority) { $winner = $rule }
    }
    return $winner
}

function Get-AdblockDomainDecisionByIndex([string]$Domain, [object]$Index) {
    $d = Normalize-Domain $Domain
    if (-not (Is-ValidDNSDomain $d)) { return [PSCustomObject]@{ Decision = 'UNKNOWN'; Priority = $null; Rule = $null } }
    $matches = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in (Get-AdblockSuffixMatches -Domain $d -Index $Index)) { $matches.Add($rule) }
    if ($Index.Exact.ContainsKey($d)) { foreach ($rule in $Index.Exact[$d]) { $matches.Add($rule) } }
    $winner = Get-AdblockBestRule -Matches $matches.ToArray()
    if ($null -eq $winner) { return [PSCustomObject]@{ Decision = 'UNKNOWN'; Priority = $null; Rule = $null } }
    return [PSCustomObject]@{ Decision = $winner.Action; Priority = [int]$winner.Priority; Rule = $winner }
}

function Get-AdblockSuffixDecisionByIndex([string]$Domain, [object]$Index) {
    $matches = Get-AdblockSuffixMatches -Domain $Domain -Index $Index
    $winner = Get-AdblockBestRule -Matches $matches
    if ($null -eq $winner) { return [PSCustomObject]@{ Decision = 'UNKNOWN'; Priority = $null; Rule = $null } }
    return [PSCustomObject]@{ Decision = $winner.Action; Priority = [int]$winner.Priority; Rule = $winner }
}

function Get-AdblockDomainDecision([string]$Domain, [object[]]$Rules) {
    $index = New-AdblockRuleIndex -Rules $Rules
    return Get-AdblockDomainDecisionByIndex -Domain $Domain -Index $index
}

function Compile-AdblockRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]]$Rules,
        [bool]$Strict = $true,
        [object[]]$PreExistingIssues = @()
    )
    $index = New-AdblockRuleIndex -Rules $Rules
    $suffixDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $exactDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $Rules) {
        if ($rule.MatchType -eq 'SUFFIX') { [void]$suffixDomains.Add([string]$rule.Domain) }
        elseif ($rule.MatchType -eq 'EXACT') { [void]$exactDomains.Add([string]$rule.Domain) }
    }
    $suffixStates = @{}
    foreach ($domain in $suffixDomains) { $suffixStates[$domain] = (Get-AdblockSuffixDecisionByIndex -Domain $domain -Index $index).Decision }
    $issues = [System.Collections.Generic.List[object]]::new()
    foreach ($issue in $PreExistingIssues) { $issues.Add($issue) }
    $rootsWithHoles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($root in $suffixDomains) {
        if ($suffixStates[$root] -ne 'BLOCK') { continue }
        $holes = [System.Collections.Generic.List[string]]::new()
        foreach ($candidate in $suffixDomains) {
            if ($candidate -eq $root -or -not (Test-AdblockDomainWithin -Domain $candidate -Root $root)) { continue }
            if ($suffixStates[$candidate] -eq 'ALLOW') { $holes.Add("suffix:$candidate") }
        }
        foreach ($candidate in $exactDomains) {
            if (-not (Test-AdblockDomainWithin -Domain $candidate -Root $root)) { continue }
            $decision = Get-AdblockDomainDecisionByIndex -Domain $candidate -Index $index
            if ($decision.Decision -eq 'ALLOW') { $holes.Add("exact:$candidate") }
        }
        if ($holes.Count -gt 0) {
            [void]$rootsWithHoles.Add($root)
            $issues.Add([PSCustomObject]@{
                Type = 'PARTIAL_OVERLAP'; Root = $root; Detail = ($holes -join '; ')
                Message = "Blocked suffix '$root' contains allowed exception(s): $($holes -join ', ')"
            })
        }
    }

    $eligibleSuffixes = [System.Collections.Generic.List[string]]::new()
    foreach ($domain in $suffixDomains) {
        if ($suffixStates[$domain] -eq 'BLOCK' -and -not $rootsWithHoles.Contains($domain)) { $eligibleSuffixes.Add($domain) }
    }
    $outputSuffix = [System.Collections.Generic.List[string]]::new()
    foreach ($domain in $eligibleSuffixes) {
        $coveredByAncestor = $false
        foreach ($parent in $eligibleSuffixes) {
            if ($parent -ne $domain -and (Test-AdblockDomainWithin -Domain $domain -Root $parent)) { $coveredByAncestor = $true; break }
        }
        if (-not $coveredByAncestor) { $outputSuffix.Add($domain) }
    }

    $outputExact = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($domain in $exactDomains) {
        $decision = Get-AdblockDomainDecisionByIndex -Domain $domain -Index $index
        if ($decision.Decision -ne 'BLOCK') { continue }
        $covered = $false
        foreach ($suffix in $outputSuffix) {
            if (Test-AdblockDomainWithin -Domain $domain -Root $suffix) { $covered = $true; break }
        }
        if (-not $covered) { [void]$outputExact.Add($domain) }
    }

    $exactArray = @($outputExact)
    $suffixArray = @($outputSuffix)
    [array]::Sort($exactArray, [System.StringComparer]::OrdinalIgnoreCase)
    [array]::Sort($suffixArray, [System.StringComparer]::OrdinalIgnoreCase)
    if ($Strict -and $issues.Count -gt 0) {
        $summary = ($issues | ForEach-Object { "$($_.Type): $($_.Message)" }) -join [Environment]::NewLine
        throw "Strict compilation failed: $($issues.Count) unrepresentable conflict(s). No output was written. $summary"
    }
    return [PSCustomObject]@{
        Exact = $exactArray; Suffix = $suffixArray; Issues = $issues.ToArray()
        IsLossless = ($issues.Count -eq 0); TotalRules = $exactArray.Count + $suffixArray.Count
    }
}

function Set-AdblockPublicSuffixRules {
    [CmdletBinding()]
    param([string[]]$Rules)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Rules) {
        $rule = ([string]$entry).Trim()
        if (-not $rule -or $rule.StartsWith('//')) { continue }
        $prefix = ''
        if ($rule.StartsWith('!')) { $prefix = '!'; $rule = $rule.Substring(1) }
        elseif ($rule.StartsWith('*.')) { $prefix = '*.'; $rule = $rule.Substring(2) }
        $ascii = Normalize-Domain $rule
        if (Is-ValidDNSDomain $ascii) { [void]$set.Add($prefix + $ascii) }
    }
    $script:PslRules = $set
    return $set.Count
}

function Load-AdblockPublicSuffixList {
    [CmdletBinding()]
    param([string]$Uri = 'https://publicsuffix.org/list/public_suffix_list.dat')
    $response = Invoke-WebRequest -Uri $Uri -TimeoutSec 45 -MaximumRedirection 10 -Headers @{ 'User-Agent' = 'AdBlock_Rule_For_Clash/1.0' } -ErrorAction Stop
    $count = Set-AdblockPublicSuffixRules -Rules ($response.Content -split '\r?\n')
    if ($count -lt 1000) { throw "PSL data looks incomplete ($count rules)." }
    return $count
}

function Get-AdblockSourceConfig {
    param([string]$Path = (Join-Path $PSScriptRoot 'sources.json'))
    if (-not (Test-Path -LiteralPath $Path)) { throw "Source manifest not found: $Path" }
    $items = @(Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json)
    if ($items.Count -eq 0) { throw "Source manifest is empty: $Path" }
    $script:SourceConfigByUrl = @{}
    foreach ($item in $items) {
        if (-not $item.enabled) { continue }
        if ($item.defaultAction -notin @('ALLOW','BLOCK')) { throw "Invalid defaultAction: $($item.url)" }
        if ($script:SourceConfigByUrl.ContainsKey([string]$item.url)) { throw "Duplicate source URL: $($item.url)" }
        $script:SourceConfigByUrl[[string]$item.url] = $item
    }
    return @($items | Where-Object { $_.enabled })
}

function Invoke-AdblockGeneration {
    [CmdletBinding()]
    param(
        [ValidateSet('yaml','txt','both')]
        [string]$Format = 'yaml',
        [bool]$Strict = $true
    )

    $sources = @(Get-AdblockSourceConfig)
    $downloadResults = @(
        $sources | ForEach-Object -Parallel {
            $source = $_
            $result = $null
            $lastError = $null

            for ($attempt = 1; $attempt -le 3; $attempt++) {
                try {
                    $response = Invoke-WebRequest -Uri $source.url -TimeoutSec 45 -MaximumRedirection 10 -Headers @{
                        'User-Agent' = 'AdBlock_Rule_For_Clash/1.0'
                    } -ErrorAction Stop

                    $body = [string]$response.Content
                    if ([string]::IsNullOrWhiteSpace($body)) { throw 'Empty response body' }
                    if ($body -match '^\s*<(?:!doctype\s+html|html)\b') { throw 'Received HTML instead of a filter list' }

                    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($body)
                    $sha = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
                    if ($source.sha256 -and $sha -ne ([string]$source.sha256).ToLowerInvariant()) {
                        throw 'SHA-256 mismatch with pinned source hash'
                    }

                    $result = [PSCustomObject]@{
                        Source = $source
                        Content = $body
                        Success = $true
                        Attempts = $attempt
                        Error = $null
                        Sha256 = $sha
                        ByteCount = $bytes.Length
                    }
                    break
                }
                catch {
                    $lastError = $_.Exception.Message
                    if ($attempt -lt 3) { Start-Sleep -Seconds (2 * $attempt) }
                }
            }

            if ($null -eq $result) {
                $result = [PSCustomObject]@{
                    Source = $source
                    Content = $null
                    Success = $false
                    Attempts = 3
                    Error = $lastError
                    Sha256 = $null
                    ByteCount = 0
                }
            }
            $result
        } -ThrottleLimit 12
    )

    $failed = @($downloadResults | Where-Object { -not $_.Success })
    foreach ($item in $failed) {
        Write-Warning "Download failed: $($item.Source.url): $($item.Error)"
    }

    $requiredFailures = @($failed | Where-Object { $_.Source.required })
    if ($requiredFailures.Count -gt 0) {
        throw "Strict source acquisition failed: $($requiredFailures.Count) required source(s) unavailable. No output was written."
    }

    $successfulSources = @($downloadResults | Where-Object { $_.Success } | Sort-Object { $_.Source.url })
    $fingerprintInput = ($successfulSources | ForEach-Object {
        "$($_.Source.url)|$($_.Sha256)|$($_.ByteCount)"
    }) -join [Environment]::NewLine
    $fingerprintBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($fingerprintInput)
    $snapshotHash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($fingerprintBytes)).ToLowerInvariant()
    Write-Host "Source snapshot SHA-256: $snapshotHash ($($successfulSources.Count) source files)"

    $null = Load-AdblockPublicSuffixList
    $rawRules = [System.Collections.Generic.List[object]]::new()
    $badfilterKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $preIssues = [System.Collections.Generic.List[object]]::new()
    $skipStats = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $stats = @{
        Parsed = 0
        Skipped = 0
        Invalid = 0
        Badfilter = 0
        Wildcard = 0
        PublicSuffix = 0
        HostsExpanded = 0
        Preprocessor = 0
    }

    foreach ($download in $downloadResults) {
        if (-not $download.Success) { continue }

        $url = [string]$download.Source.url
        $isWhitelistSource = Is-WhitelistSource $url
        $lineNumber = 0

        foreach ($line in ($download.Content -split '\r?\n')) {
            $lineNumber++
            $sourceLine = $line.Trim()

            # uBlock directives alter the effective source before parsing. Do not
            # mistake them for comments: without an evaluator they are unresolved.
            if ($sourceLine -match '^!#(?:include|if|elif|else|endif|ifdef|ifndef)\b') {
                $stats.Preprocessor++
                $preIssues.Add([PSCustomObject]@{
                    Type = 'UNPROCESSED_PREPROCESSOR'
                    Root = $url
                    Detail = $sourceLine
                    Message = "uBlock preprocessor directive requires expansion/context evaluation: $sourceLine"
                })
                continue
            }

            # A hosts line can contain multiple hostnames. Preserve every mapping.
            $linesToParse = @($sourceLine)
            if ($sourceLine -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+(.+)$') {
                $hostsIp = $Matches[1]
                $hostNamesText = $Matches[2]
                $hostTokens = @($hostNamesText -split '\s+')
                if ($hostTokens.Count -gt 1) {
                    $expanded = [System.Collections.Generic.List[string]]::new()
                    foreach ($hostName in $hostTokens) {
                        if (-not $hostName -or $hostName.StartsWith('#')) { break }
                        $expanded.Add("$hostsIp $hostName")
                    }
                    if ($expanded.Count -gt 0) {
                        $linesToParse = $expanded.ToArray()
                        $stats.HostsExpanded += $expanded.Count
                    }
                }
            }

            foreach ($rawLine in $linesToParse) {
                $parsed = Parse-Rule -line $rawLine -isWhitelistSource $isWhitelistSource
                $stats.Parsed++

                if ($parsed.Action -eq 'SKIP') {
                    $stats.Skipped++
                    $reason = [string]$parsed.SkipReason
                    if (-not $skipStats.ContainsKey($reason)) { $skipStats[$reason] = 0 }
                    $skipStats[$reason]++
                    continue
                }

                $identity = Get-AdblockRuleIdentity $rawLine
                if ($parsed.Action -eq 'BADFILTER') {
                    [void]$badfilterKeys.Add($url + [char]10 + $identity)
                    $stats.Badfilter++
                    continue
                }

                if ($parsed.IsWildcard) {
                    $stats.Wildcard++
                    $preIssues.Add([PSCustomObject]@{
                        Type = 'UNSUPPORTED_WILDCARD'
                        Root = $parsed.Domain
                        Detail = $rawLine
                        Message = "Wildcard pattern cannot be represented losslessly by DOMAIN / DOMAIN-SUFFIX: $rawLine"
                    })
                    continue
                }

                $matchType = Get-AdblockMatchType -Parsed $parsed -RawRule $rawLine
                $domain = Normalize-Domain ([string]$parsed.Domain)
                if (-not (Is-ValidDNSDomain $domain)) {
                    $stats.Invalid++
                    $preIssues.Add([PSCustomObject]@{
                        Type = 'INVALID_DOMAIN'
                        Root = $domain
                        Detail = $rawLine
                        Message = "Parsed domain is not a valid DNS rule name: $rawLine"
                    })
                    continue
                }

                $action = if ($parsed.Action -eq 'EXCLUDE') { 'ALLOW' } else { 'BLOCK' }
                $important = [bool]$parsed.IsImportant
                $priority = Get-AdblockRulePriority -Action $action -MatchType $matchType -IsImportant $important

                if (Is-PublicSuffix $domain) { $stats.PublicSuffix++ }

                $rawRules.Add([PSCustomObject]@{
                    Domain = $domain
                    MatchType = $matchType
                    Action = $action
                    Priority = $priority
                    IsImportant = $important
                    RawRule = $rawLine
                    RuleIdentity = $identity
                    SourceUrl = $url
                    SourceLine = $lineNumber
                    SourceFormat = $parsed.SourceFormat
                })
            }
        }
    }

    # $badfilter is bound to the source subscription and normalized base rule.
    # Match type and every non-badfilter modifier remain part of rule identity.
    $activeRules = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $rawRules) {
        $key = $rule.SourceUrl + [char]10 + $rule.RuleIdentity
        if (-not $badfilterKeys.Contains($key)) {
            $activeRules.Add($rule)
        }
    }

    # Semantic deduplication keeps one diagnostic record per effective rule.
    $dedup = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $activeRules) {
        $key = "$($rule.Priority)|$($rule.Action)|$($rule.MatchType)|$($rule.Domain)"
        if (-not $dedup.ContainsKey($key)) { $dedup.Add($key, $rule) }
    }
    $rules = @($dedup.Values)

    $compiled = Compile-AdblockRules -Rules $rules -Strict:$Strict -PreExistingIssues $preIssues.ToArray()
    $exact = @($compiled.Exact)
    $suffix = @($compiled.Suffix)

    # Render only the requested positive blacklist syntax.
    $yamlRules = @($suffix | ForEach-Object { "  - DOMAIN-SUFFIX,$_" }) +
                 @($exact | ForEach-Object { "  - DOMAIN,$_" })
    $yamlText = @(
        '# Generated by AdBlock_Rule_For_Clash'
        "# DOMAIN: $($exact.Count)"
        "# DOMAIN-SUFFIX: $($suffix.Count)"
        'payload:'
    ) + $yamlRules
    $txtRules = @($suffix | ForEach-Object { "DOMAIN-SUFFIX,$_" }) +
                @($exact | ForEach-Object { "DOMAIN,$_" })

    $outputs = @()
    if ($Format -in @('yaml','both')) {
        $outputs += @{
            Path = Join-Path $PSScriptRoot 'adblock_reject.yaml'
            Text = ($yamlText -join [Environment]::NewLine) + [Environment]::NewLine
        }
    }
    if ($Format -in @('txt','both')) {
        $outputs += @{
            Path = Join-Path $PSScriptRoot 'adblock_reject.txt'
            Text = ($txtRules -join [Environment]::NewLine) + [Environment]::NewLine
        }
    }

    # Write only after all acquisition, parsing and semantic checks succeed.
    foreach ($output in $outputs) {
        $temp = $output.Path + '.tmp'
        [System.IO.File]::WriteAllText($temp, $output.Text, [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temp -Destination $output.Path -Force
        Write-Host "Generated: $($output.Path)"
    }

    Write-Host "Sources: $($sources.Count); downloaded: $($downloadResults.Count - $failed.Count); failed optional: $($failed.Count)"
    Write-Host "Snapshot SHA-256: $snapshotHash"
    Write-Host "Parsed lines: $($stats.Parsed); active semantic rules: $($rules.Count)"
    Write-Host "DOMAIN: $($exact.Count); DOMAIN-SUFFIX: $($suffix.Count)"
    Write-Host "Skipped non-domain rules: $($stats.Skipped); invalid: $($stats.Invalid); wildcard: $($stats.Wildcard)"
    Write-Host "Public-suffix patterns retained with original match type: $($stats.PublicSuffix); badfilter cancellations: $($stats.Badfilter)"
    if ($skipStats.Count -gt 0) {
        Write-Host ("Skip reasons: " + (($skipStats.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', '))
    }

    return [PSCustomObject]@{
        Sources = $sources.Count
        Downloaded = $downloadResults.Count - $failed.Count
        FailedOptional = @($failed | Where-Object { -not $_.Source.required }).Count
        SnapshotSha256 = $snapshotHash
        ParsedLines = $stats.Parsed
        ActiveRules = $rules.Count
        ExactCount = $exact.Count
        SuffixCount = $suffix.Count
        BadfilterCount = $stats.Badfilter
        SkippedCount = $stats.Skipped
        InvalidCount = $stats.Invalid
        UnrepresentableCount = $compiled.Issues.Count
        IsLossless = $compiled.IsLossless
    }
}

$modAllowSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@('all','reason') | ForEach-Object { $modAllowSet.Add($_) | Out-Null }

function Resolve-Modifiers([string]$modStr) {
    $ret = [PSCustomObject]@{ Decision = "CONTINUE"; SkipReason = $null; IsImportant = $false }
    if ([string]::IsNullOrWhiteSpace($modStr)) { return $ret }
    foreach ($mod in ($modStr -split ',' | ForEach-Object { $_.Trim().ToLower() })) {
        $modName = ($mod -split '=')[0]
        if ($modName -eq 'important') { $ret.IsImportant = $true; continue }
        if ($modAllowSet.Contains($modName)) { continue }
        if ($modName -eq 'dnsrewrite') {
            $rv = if ($mod -match '=(.+)$') { $Matches[1] } else { '' }
            if ($rv -eq 'nxdomain' -or $rv -match '^noerror;a;[\d.]+$' -or $rv -match '^noerror;aaaa;[0:]*$' -or $rv -eq 'noerror;aaaa;::1') { continue }
            $ret.Decision = "SKIP";
            $ret.SkipReason = "dnsrewrite-non-block:$rv"; return $ret
        }
        $ret.Decision = "SKIP"
        $ret.SkipReason = "unsupported-modifier:$modName"; return $ret
    }
    if ($ret.IsImportant) { $ret.Decision = "IMPORTANT_CONTINUE" }
    return $ret
}

$whitelistSubresourceTypes = [System.Collections.Generic.HashSet[string]]@('document','script','image','stylesheet','css','object','xmlhttprequest','xhr','media','font','subdocument','ping','websocket','webrtc','other','object-subrequest')

function Is-ContextConstrainedWhitelist([string]$modStr) {
    if ([string]::IsNullOrWhiteSpace($modStr)) { return $false }
    foreach ($mod in ($modStr -split ',' | ForEach-Object { ($_ -split '=')[0].Trim().ToLower() })) {
        if ($mod -notin @('important','all')) { return $true }
    }
    return $false
}

function Get-WhitelistImportantFlag([string]$modStr) {
    if ([string]::IsNullOrWhiteSpace($modStr)) { return $false }
    foreach ($mod in ($modStr -split ',' | ForEach-Object { $_.Trim().ToLower() })) {
        if ($mod -eq 'important') { return $true }
    }
    return $false
}

function Is-WhitelistSource([string]$url) {
    if ($null -eq $script:SourceConfigByUrl) { return $false }
    if ($script:SourceConfigByUrl.ContainsKey($url)) {
        return ($script:SourceConfigByUrl[$url].defaultAction -eq 'ALLOW')
    }
    return $false
}

# ── 集中式规则解析函数 ───────────────────────────────────────
function Parse-Rule {
    param([string]$line, [bool]$isWhitelistSource = $false)

    $result = [PSCustomObject]@{
        Action      = "SKIP"
        Domain      = $null
        SkipReason  = "unmatched"
        SourceFormat = "unknown"
        IsImportant = $false
        IsWildcard  = $false
    }

    if (
        [string]::IsNullOrWhiteSpace($line) -or
        $line.StartsWith("!") -or
        $line.StartsWith("#") -or
        $line.StartsWith("[") -or
        $line -match '##|#\?#|#@#|#\$#'
    ) {
        $result.SkipReason = "comment-or-cosmetic"
        return $result
    }

    if ($line -match '^/.+/(\$.*)?$') {
        $result.SkipReason = "regex-rule"
        return $result
    }

    if ($line -match '^\|https?://') {
        $result.SkipReason = "exact-url-rule"
        return $result
    }

    # Adblock 白名单规则
    if ($line.StartsWith("@@")) {
        $extractDomain = $null
        $modPartRaw = $null

        if (
            $line -match '^@@\|\|([\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?(?:\.[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?)+)(.*)
        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[2]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}]{2,})) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}]{2,})\|(\$(.+))?) {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([\p{L}\p{N}*][\p{L}\p{N}*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}]{2,})/([^/]*)) {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([\p{L}\p{N}.-]+\.[\p{L}]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}]{2,})/) {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}]{2,})) {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
) {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)

        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[5]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }

        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            }
            else {
                $result.Action = "EXCLUDE"
                $result.Domain = $extractDomain
                $result.SourceFormat = "adblock-whitelist"
                $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        }
        else {
            $result.SkipReason = "whitelist-unparseable"
        }

        return $result
    }

    # 精确 URL / AdGuard 精确域名规则
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower()
        $modStr = $Matches[3]

        if (-not [string]::IsNullOrWhiteSpace($modStr)) {
            $exactMods = @($modStr -split ',' | ForEach-Object { (($_ -split '=')[0]).Trim().ToLower() })
            if ($exactMods -contains 'badfilter') {
                $result.Action = 'BADFILTER'
                $result.Domain = $candidate
                return $result
            }
        }

        $modResult = Resolve-Modifiers $modStr

        if ($modResult.Decision -eq "SKIP") {
            $result.SkipReason = $modResult.SkipReason
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-exact"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "adguard-exact"
        }

        $result.Domain = $candidate
        $result.IsImportant = $modResult.IsImportant

        return $result
    }

    # Adblock || 域名规则
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower()
        $rest = $Matches[2]
        $dollarIndex = $rest.IndexOf('$')

        $restBeforeDollar = if ($dollarIndex -ge 0) {
            $rest.Substring(0, $dollarIndex)
        }
        else {
            $rest
        }

        if ($raw -match '[/?]' -or $restBeforeDollar -notmatch '^\^?$') {
            $result.SkipReason = "path-or-query-specific-rule"
            return $result
        }

        # 处理 $badfilter 撤销规则
        if ($rest -match '^\^?\$(.+)$') {
            $modList = (
                $Matches[1] -split ',' |
                ForEach-Object {
                    ($_ -split '=')[0].Trim().ToLower()
                }
            )

            if ($modList -contains 'badfilter') {
                $domain = $raw

                if (
                    $domain -notmatch '\*' -and
                    $domain -notmatch '^\d{1,3}(\.\d{1,3}){3}$'
                ) {
                    $result.Action = "BADFILTER"
                    $result.Domain = $domain
                    return $result
                }
            }
        }

        # 处理其他修饰符
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]

            if ($modResult.Decision -eq "SKIP") {
                $result.SkipReason = $modResult.SkipReason
                return $result
            }

            $result.IsImportant = $modResult.IsImportant
        }

        # 解析通配域名
        $domain = $null

        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw

            if ($null -eq $domain) {
                $result.SkipReason = "unresolvable-wildcard"
                return $result
            }

            $result.IsWildcard = $true
        }
        else {
            $domain = $raw
        }

        # 不将 IP 地址作为域名后缀规则
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $result.SkipReason = "ip-address"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-suffix"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "adblock-suffix"
        }

        $result.Domain = $domain

        return $result
    }

    # Hosts 文件规则
    if (
        $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$'
    ) {
        $domain = $Matches[2].ToLower()

        if ($domain -in @("localhost", "localhost.localdomain", "local", "broadcasthost")) {
            $result.SkipReason = "localhost-entry"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-hosts"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "hosts"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq address 规则
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower()
        $target = $Matches[2].Trim()
        $isBlock = $false

        switch -Regex ($target) {
            '^$' {
                $isBlock = $true
            }
            '^0\.0\.0\.0$' {
                $isBlock = $true
            }
            '^127\.0\.0\.1$' {
                $isBlock = $true
            }
            '^::$' {
                $isBlock = $true
            }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' {
                $isBlock = $true
            }
            '^#$' {
                $isBlock = $false
            }
            default {
                $isBlock = $false
            }
        }

        if (-not $isBlock) {
            $result.SkipReason = "dnsmasq-dns-forward:$target"
            return $result
        }

        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-address"
        }

        $result.Domain = $domain

        return $result
    }

    # dnsmasq server 路由规则不作为屏蔽规则
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') {
        $result.SkipReason = "dnsmasq-server-routing"
        return $result
    }

    # dnsmasq local 规则
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-dnsmasq-local"
        }
        else {
            $result.Action = "SUFFIX"
            $result.SourceFormat = "dnsmasq-local"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    # 纯域名规则
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) {
            $result.Action = "EXCLUDE"
            $result.SourceFormat = "whitelist-plain"
        }
        else {
            $result.Action = "EXACT"
            $result.SourceFormat = "plain-domain"
        }

        $result.Domain = $Matches[1].ToLower()

        return $result
    }

    $result.SkipReason = "no-pattern-match"

    return $result
}
Export-ModuleMember -Function @(
    'Get-AdblockRuleIdentity',
    'Get-AdblockRulePriority',
    'Test-AdblockSuffixMatch',
    'Get-AdblockDomainDecision',
    'Compile-AdblockRules',
    'Get-PublicSuffix',
    'Is-PublicSuffix',
    'Set-AdblockPublicSuffixRules',
    'Load-AdblockPublicSuffixList',
    'Invoke-AdblockGeneration'
)
