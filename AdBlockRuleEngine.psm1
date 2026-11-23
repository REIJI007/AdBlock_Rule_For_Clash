Set-StrictMode -Version Latest

$script:PslExact = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:PslWildcard = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:PslException = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function ConvertTo-NormalizedDomain {
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Domain)
    if ([string]::IsNullOrWhiteSpace($Domain)) { return $null }
    $value = $Domain.Trim()
    if ($value.EndsWith('..')) { return $null }
    if ($value.EndsWith('.')) { $value = $value.Substring(0, $value.Length - 1) }
    try {
        $idn = [System.Globalization.IdnMapping]::new()
        return $idn.GetAscii($value).ToLowerInvariant()
    } catch { return $null }
}

function Initialize-AdblockPsl {
    param([Parameter(Mandatory)][string]$Content)
    $script:PslExact.Clear()
    $script:PslWildcard.Clear()
    $script:PslException.Clear()
    foreach ($rawLine in ($Content -split '\r?\n')) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith('//')) { continue }
        if ($line.StartsWith('!')) {
            $domain = ConvertTo-NormalizedDomain $line.Substring(1)
            if ($domain) { [void]$script:PslException.Add($domain) }
            continue
        }
        if ($line.StartsWith('*.')) {
            $domain = ConvertTo-NormalizedDomain $line.Substring(2)
            if ($domain) { [void]$script:PslWildcard.Add($domain) }
            continue
        }
        $domain = ConvertTo-NormalizedDomain $line
        if ($domain) { [void]$script:PslExact.Add($domain) }
    }
}

function Get-AdblockPublicSuffix {
    param([Parameter(Mandatory)][string]$Domain)
    $normalized = ConvertTo-NormalizedDomain $Domain
    if (-not $normalized) { return $null }
    $labels = $normalized.Split('.')
    $bestLength = 1
    $bestSuffix = $labels[-1]
    for ($i = 0; $i -lt $labels.Length; $i++) {
        $candidate = ($labels[$i..($labels.Length - 1)] -join '.')
        $candidateLength = $labels.Length - $i
        if ($script:PslException.Contains($candidate)) {
            if ($candidateLength - 1 -gt 0) {
                return ($labels[($i + 1)..($labels.Length - 1)] -join '.')
            }
        }
        if ($script:PslExact.Contains($candidate) -and $candidateLength -gt $bestLength) {
            $bestLength = $candidateLength
            $bestSuffix = $candidate
        }
        if ($i -gt 0 -and $script:PslWildcard.Contains($candidate)) {
            $wildcardLength = $candidateLength + 1
            if ($wildcardLength -gt $bestLength) {
                $bestLength = $wildcardLength
                $bestSuffix = ($labels[($i - 1)..($labels.Length - 1)] -join '.')
            }
        }
    }
    return $bestSuffix
}

function Test-AdblockPublicSuffix {
    param([Parameter(Mandatory)][string]$Domain)
    $normalized = ConvertTo-NormalizedDomain $Domain
    if (-not $normalized) { return $false }
    return (Get-AdblockPublicSuffix $normalized) -eq $normalized
}

function Test-AdblockDnsDomain {
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Domain,[switch]$AllowPublicSuffix)
    $normalized = ConvertTo-NormalizedDomain $Domain
    if (-not $normalized -or $normalized.Length -gt 253) { return $false }
    if ($normalized -match '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    $labels = $normalized.Split('.')
    if ($labels.Count -lt 2) {
        return ($AllowPublicSuffix -and (Test-AdblockPublicSuffix $normalized))
    }
    foreach ($label in $labels) {
        if ($label.Length -eq 0 -or $label.Length -gt 63) { return $false }
        if ($label -notmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$') { return $false }
    }
    return $true
}

function Test-DomainWithinSuffix {
    param([Parameter(Mandatory)][string]$Domain,[Parameter(Mandatory)][string]$Suffix)
    return $Domain.Equals($Suffix,[System.StringComparison]::OrdinalIgnoreCase) -or
        $Domain.EndsWith('.' + $Suffix,[System.StringComparison]::OrdinalIgnoreCase)
}

function Get-AdblockRulePriority {
    param([ValidateSet('BLOCK','ALLOW')][string]$Action,[ValidateSet('EXACT','SUFFIX')][string]$MatchType,[bool]$IsImportant)
    if ($Action -eq 'ALLOW' -and $IsImportant) { return 0 }
    if ($Action -eq 'BLOCK' -and $IsImportant) { return 1 }
    if ($Action -eq 'ALLOW') { return 2 }
    if ($MatchType -eq 'EXACT') { return 3 }
    return 4
}

function New-AdblockRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][ValidateSet('EXACT','SUFFIX')][string]$MatchType,
        [Parameter(Mandatory)][ValidateSet('BLOCK','ALLOW')][string]$Action,
        [bool]$IsImportant = $false,
        [string[]]$Modifiers = @(),
        [string]$RawRule = '',
        [string]$SourceUrl = '',
        [int]$SourceLine = 0,
        [bool]$IsBadFilter = $false
    )
    $normalized = ConvertTo-NormalizedDomain $Domain
    if (-not (Test-AdblockDnsDomain $normalized -AllowPublicSuffix)) { throw "Invalid DNS domain: $Domain" }
    $canonicalModifiers = @($Modifiers | ForEach-Object { $_.Trim().ToLowerInvariant() } |
        Where-Object { $_ -and $_ -ne 'badfilter' } | Sort-Object -Unique)
    if ($IsImportant -and $canonicalModifiers -notcontains 'important') {
        $canonicalModifiers += 'important'
        $canonicalModifiers = @($canonicalModifiers | Sort-Object -Unique)
    }
    $priority = Get-AdblockRulePriority -Action $Action -MatchType $MatchType -IsImportant $IsImportant
    $identity = '{0}|{1}|{2}|{3}' -f $Action,$MatchType,$normalized,($canonicalModifiers -join ',')
    return [PSCustomObject]@{
        Domain=$normalized; MatchType=$MatchType; Action=$Action; Priority=$priority
        IsImportant=$IsImportant; Modifiers=$canonicalModifiers; Identity=$identity
        IsBadFilter=$IsBadFilter; RawRule=$RawRule; SourceUrl=$SourceUrl; SourceLine=$SourceLine
        IsPublicSuffix=(Test-AdblockPublicSuffix $normalized)
    }
}

function New-AdblockOutOfScopeRecord {
    param([string]$RawRule,[string]$Reason,[string]$SourceUrl,[int]$SourceLine)
    return [PSCustomObject]@{ State='OutOfScope'; RawRule=$RawRule; Reason=$Reason; SourceUrl=$SourceUrl; SourceLine=$SourceLine }
}

function Resolve-AdblockModifiers {
    param([string]$ModifierText)
    $modifiers = @()
    if ($ModifierText) {
        $modifiers = @($ModifierText.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    }
    $important = $modifiers -contains 'important'
    $badfilter = $modifiers -contains 'badfilter'
    $unsupported = @($modifiers | Where-Object { $_ -notin @('important','badfilter','all') })
    return [PSCustomObject]@{
        IsImportant=$important; IsBadFilter=$badfilter
        Modifiers=@($modifiers | Where-Object { $_ -ne 'badfilter' })
        Unsupported=$unsupported
    }
}

function Parse-AdblockRuleLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Line,
        [Parameter(Mandatory)][ValidateSet('BLOCK','ALLOW')][string]$DefaultAction,
        [string]$SourceUrl='',
        [int]$SourceLine=0,
        [ValidateSet('EXACT','SUFFIX')][string]$PlainDomainMatchType='EXACT',
        [ValidateSet('EXACT','SUFFIX')][string]$HostsMatchType='EXACT'
    )
    $raw = $Line.Trim().TrimStart([char]0xFEFF)
    if (-not $raw -or $raw.StartsWith('!') -or $raw.StartsWith('#') -or $raw.StartsWith('[') -or
        $raw -match '##|#\?#|#@#|#\$#') { return $null }
    if ($raw -match '^!#') {
        return (New-AdblockOutOfScopeRecord $raw 'uBO-preprocessor-directive' $SourceUrl $SourceLine)
    }

    $action = $DefaultAction
    $matchType = $null
    $domain = $null
    $modifierText = ''

    if ($raw -match '^(?<allow>@@)?\|\|(?<host>[^/?^|$\s]+)(?<tail>.*)$') {
        if ($raw.StartsWith('@@')) { $action='ALLOW' }
        $domain=$Matches.host
        $matchType='SUFFIX'
        $tail=$Matches.tail
        if (-not $tail.StartsWith('^')) {
            return (New-AdblockOutOfScopeRecord $raw 'domain-anchor-without-caret-boundary' $SourceUrl $SourceLine)
        }
        if ($tail -match '^\^\$(?<mods>.*)$') { $modifierText=$Matches.mods }
        elseif ($tail -ne '^') {
            return (New-AdblockOutOfScopeRecord $raw 'unsupported-domain-anchor-tail' $SourceUrl $SourceLine)
        }
    }
    elseif ($raw -match '^(?<allow>@@)?\|(?<host>[^|$]+)\|(?:\$(?<mods>.*))?$') {
        if ($raw.StartsWith('@@')) { $action='ALLOW' }
        $domain=$Matches.host
        $matchType='EXACT'
        $modifierText=if ($Matches.ContainsKey('mods')) { [string]$Matches.mods } else { '' }
    }
    elseif ($raw -match '^@@(?<host>[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        $action='ALLOW'
        $domain=$Matches.host
        $matchType='EXACT'
    }
    elseif ($raw -match '^(?<ip>0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+(?<hosts>.+)$') {
        $hostText=($Matches.hosts -split '\s+#',2)[0]
        $result=[System.Collections.Generic.List[object]]::new()
        foreach ($hostName in ($hostText -split '\s+')) {
            if (-not $hostName -or $hostName -in @('localhost','localhost.localdomain','local','broadcasthost')) { continue }
            $normalizedHost=ConvertTo-NormalizedDomain $hostName
            if (Test-AdblockDnsDomain $normalizedHost -AllowPublicSuffix) {
                $result.Add((New-AdblockRule -Domain $normalizedHost -MatchType $HostsMatchType -Action $DefaultAction -RawRule $raw -SourceUrl $SourceUrl -SourceLine $SourceLine))
            }
        }
        return $result.ToArray()
    }
    elseif ($raw -match '^address=/(?<host>[^/]+)/(?<target>[^/]*)$') {
        $target=$Matches.target.Trim()
        if ($target -notin @('','0.0.0.0','127.0.0.1','::','::1','::0','0:0:0:0:0:0:0:0','0:0:0:0:0:0:0:1')) { return $null }
        $domain=$Matches.host
        $matchType='SUFFIX'
    }
    elseif ($raw -match '^server=/[^/]+/') { return $null }
    elseif ($raw -match '^local=/(?<host>[^/]+)/$') {
        $domain=$Matches.host
        $matchType='SUFFIX'
    }
    elseif ($raw -match '^(?<host>[^\s/|$]+)$') {
        $domain=$Matches.host
        $matchType=$PlainDomainMatchType
    }
    elseif ($raw -match '^\|https?://') {
        return (New-AdblockOutOfScopeRecord $raw 'exact-url-rule' $SourceUrl $SourceLine)
    }
    elseif ($raw -match '^\|\|') {
        return (New-AdblockOutOfScopeRecord $raw 'unsupported-domain-pattern' $SourceUrl $SourceLine)
    }
    else { return $null }

    if ($domain -match '\*') {
        return (New-AdblockOutOfScopeRecord $raw 'wildcard-not-expressible-as-domain-or-domain-suffix' $SourceUrl $SourceLine)
    }
    $domain=ConvertTo-NormalizedDomain $domain
    if (-not (Test-AdblockDnsDomain $domain -AllowPublicSuffix)) {
        return (New-AdblockOutOfScopeRecord $raw 'invalid-or-non-DNS-domain' $SourceUrl $SourceLine)
    }

    $modifierResult=Resolve-AdblockModifiers $modifierText
    if ($modifierResult.Unsupported.Count -gt 0) {
        return (New-AdblockOutOfScopeRecord $raw ('context-or-unsupported-modifier:' + ($modifierResult.Unsupported -join ',')) $SourceUrl $SourceLine)
    }

    return (New-AdblockRule -Domain $domain -MatchType $matchType -Action $action -IsImportant $modifierResult.IsImportant -Modifiers $modifierResult.Modifiers -RawRule $raw -SourceUrl $SourceUrl -SourceLine $SourceLine -IsBadFilter $modifierResult.IsBadFilter)
}

function Resolve-AdblockRuleSet {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ParsedRules)
    $cancelledIds=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $cancellations=[System.Collections.Generic.List[object]]::new()
    $baseRules=[System.Collections.Generic.List[object]]::new()
    $outOfScope=[System.Collections.Generic.List[object]]::new()
    foreach ($item in $ParsedRules) {
        if ($null -eq $item) { continue }
        if (($item.PSObject.Properties.Name -contains 'State') -and $item.State -eq 'OutOfScope') { $outOfScope.Add($item); continue }
        if ($item.IsBadFilter) {
            [void]$cancelledIds.Add($item.Identity)
            $cancellations.Add($item)
        } else { $baseRules.Add($item) }
    }
    $active=[System.Collections.Generic.List[object]]::new()
    $cancelled=[System.Collections.Generic.List[object]]::new()
    foreach ($rule in $baseRules) {
        if ($cancelledIds.Contains($rule.Identity)) { $cancelled.Add($rule) }
        else { $active.Add($rule) }
    }
    return [PSCustomObject]@{
        Rules=$active.ToArray(); CancelledRules=$cancelled.ToArray()
        CancellationRules=$cancellations.ToArray(); OutOfScopeRules=$outOfScope.ToArray()
    }
}

function New-AdblockRuleTrieNode {
    return [PSCustomObject]@{
        Children=[System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        ExactRules=[System.Collections.Generic.List[object]]::new()
        SuffixRules=[System.Collections.Generic.List[object]]::new()
        EffectiveAllowRules=[System.Collections.Generic.List[object]]::new()
        HasEffectiveAllow=$false; SubtreeHasEffectiveAllow=$false
        SubtreeEffectiveAllowCount=0
        SubtreeEffectiveAllowRules=[System.Collections.Generic.List[object]]::new()
    }
}

function New-AdblockRuleTrie {
    param([object[]]$Rules)
    $root=New-AdblockRuleTrieNode
    foreach ($rule in $Rules) {
        $node=$root
        $labels=$rule.Domain.Split('.')
        for ($i=$labels.Length-1; $i -ge 0; $i--) {
            $child=$null
            if (-not $node.Children.TryGetValue($labels[$i],[ref]$child)) {
                $child=New-AdblockRuleTrieNode
                $node.Children.Add($labels[$i],$child)
            }
            $node=$child
        }
        if ($rule.MatchType -eq 'SUFFIX') { $node.SuffixRules.Add($rule) }
        else { $node.ExactRules.Add($rule) }
    }
    return $root
}

function Get-AdblockTrieNode {
    param([Parameter(Mandatory)]$Trie,[Parameter(Mandatory)][string]$Domain)
    $node=$Trie
    $labels=$Domain.Split('.')
    for ($i=$labels.Length-1; $i -ge 0; $i--) {
        $child=$null
        if (-not $node.Children.TryGetValue($labels[$i],[ref]$child)) { return $null }
        $node=$child
    }
    return $node
}

function Get-AdblockMatchingRules {
    param([Parameter(Mandatory)]$Trie,[Parameter(Mandatory)][string]$Domain)
    $normalized=ConvertTo-NormalizedDomain $Domain
    if (-not $normalized) { return @() }
    $matches=[System.Collections.Generic.List[object]]::new()
    $node=$Trie
    $labels=$normalized.Split('.')
    for ($i=$labels.Length-1; $i -ge 0; $i--) {
        $child=$null
        if (-not $node.Children.TryGetValue($labels[$i],[ref]$child)) { break }
        $node=$child
        foreach ($rule in $node.SuffixRules) { $matches.Add($rule) }
        if ($i -eq 0) {
            foreach ($rule in $node.ExactRules) { $matches.Add($rule) }
        }
    }
    return $matches.ToArray()
}

function Get-AdblockDecision {
    param([Parameter(Mandatory)]$Trie,[Parameter(Mandatory)][string]$Domain)
    $matches=@(Get-AdblockMatchingRules -Trie $Trie -Domain $Domain)
    if ($matches.Count -eq 0) { return 'UNKNOWN' }
    $bestPriority=6
    $bestAction='UNKNOWN'
    foreach ($rule in $matches) {
        if ($rule.Priority -lt $bestPriority) {
            $bestPriority=$rule.Priority
            $bestAction=$rule.Action
        }
    }
    return $bestAction
}

function Test-AdblockCoveredBySuffixSet {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$SuffixSet
    )
    $labels=$Domain.Split('.')
    for ($i=0; $i -lt $labels.Length; $i++) {
        $candidate=($labels[$i..($labels.Length-1)] -join '.')
        if ($SuffixSet.Contains($candidate)) { return $true }
    }
    return $false
}

function Update-AdblockAllowSubtree {
    param([Parameter(Mandatory)]$Node)
    $Node.SubtreeHasEffectiveAllow=[bool]$Node.HasEffectiveAllow
    $Node.SubtreeEffectiveAllowCount=$Node.EffectiveAllowRules.Count
    $Node.SubtreeEffectiveAllowRules.Clear()
    foreach ($rule in $Node.EffectiveAllowRules) {
        if ($Node.SubtreeEffectiveAllowRules.Count -lt 12) { $Node.SubtreeEffectiveAllowRules.Add($rule) }
    }
    foreach ($child in $Node.Children.Values) {
        [void](Update-AdblockAllowSubtree -Node $child)
        if ($child.SubtreeHasEffectiveAllow) { $Node.SubtreeHasEffectiveAllow=$true }
        $Node.SubtreeEffectiveAllowCount+=$child.SubtreeEffectiveAllowCount
        foreach ($rule in $child.SubtreeEffectiveAllowRules) {
            if ($Node.SubtreeEffectiveAllowRules.Count -lt 12) { $Node.SubtreeEffectiveAllowRules.Add($rule) }
        }
    }
    return $Node.SubtreeHasEffectiveAllow
}

function Get-AdblockCompilation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rules)
    $trie=New-AdblockRuleTrie -Rules $Rules

    # P0 allow always wins. A P2 exact allow is wholly suppressed by any
    # matching P1 block; a P2 suffix allow only by a P1 suffix ancestor/equal.
    foreach ($rule in ($Rules | Where-Object { $_.Action -eq 'ALLOW' })) {
        $effective=$true
        if ($rule.Priority -eq 2) {
            $matching=@(Get-AdblockMatchingRules -Trie $trie -Domain $rule.Domain)
            $p1=@($matching | Where-Object {
                $_.Action -eq 'BLOCK' -and $_.Priority -eq 1 -and
                ($rule.MatchType -eq 'EXACT' -or $_.MatchType -eq 'SUFFIX')
            })
            if ($rule.MatchType -eq 'EXACT' -and $p1.Count -gt 0) {
                $effective=$false
            }
            elseif ($rule.MatchType -eq 'SUFFIX') {
                $p1Suffix=@($matching | Where-Object {
                    $_.Action -eq 'BLOCK' -and $_.Priority -eq 1 -and $_.MatchType -eq 'SUFFIX'
                })
                if ($p1Suffix.Count -gt 0) { $effective=$false }
            }
        }
        if ($effective) {
            $node=Get-AdblockTrieNode -Trie $trie -Domain $rule.Domain
            $node.HasEffectiveAllow=$true
            $node.EffectiveAllowRules.Add($rule)
        }
    }
    [void](Update-AdblockAllowSubtree -Node $trie)

    $suffixDomains=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in ($Rules | Where-Object { $_.Action -eq 'BLOCK' -and $_.MatchType -eq 'SUFFIX' })) {
        [void]$suffixDomains.Add($rule.Domain)
    }

    $safeSuffixes=[System.Collections.Generic.List[string]]::new()
    $conflicts=[System.Collections.Generic.List[object]]::new()
    foreach ($domain in ($suffixDomains | Sort-Object)) {
        $apexAction=Get-AdblockDecision -Trie $trie -Domain $domain
        $node=Get-AdblockTrieNode -Trie $trie -Domain $domain
        $probeLabel='adblock-compiler-probe'
        while ($node.Children.ContainsKey($probeLabel)) { $probeLabel += '-x' }
        $probeDomain=$probeLabel + '.' + $domain
        $probeAction=Get-AdblockDecision -Trie $trie -Domain $probeDomain

        if ($probeAction -ne 'BLOCK') { continue }
        if ($apexAction -ne 'BLOCK' -or $node.SubtreeHasEffectiveAllow) {
            $conflicts.Add([PSCustomObject]@{
                BlackSuffixDomain=$domain
                ApexAction=$apexAction
                DescendantProbeAction=$probeAction
                EffectiveAllowCount=$node.SubtreeEffectiveAllowCount
                EffectiveAllowExamples=@($node.SubtreeEffectiveAllowRules | ForEach-Object { '{0} {1} {2}' -f $_.Action,$_.MatchType,$_.Domain })
                Type='PARTIAL_OVERLAP'
            })
        } else { $safeSuffixes.Add($domain) }
    }

    $finalSuffixes=[System.Collections.Generic.List[string]]::new()
    $finalSuffixSet=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($domain in ($safeSuffixes | Sort-Object { ($_ -split '\.').Count },{ $_ })) {
        if (-not (Test-AdblockCoveredBySuffixSet -Domain $domain -SuffixSet $finalSuffixSet)) {
            $finalSuffixes.Add($domain)
            [void]$finalSuffixSet.Add($domain)
        }
    }

    $exactDomains=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in ($Rules | Where-Object { $_.Action -eq 'BLOCK' -and $_.MatchType -eq 'EXACT' })) {
        [void]$exactDomains.Add($rule.Domain)
    }
    foreach ($conflict in $conflicts) { [void]$exactDomains.Add($conflict.BlackSuffixDomain) }

    $finalExact=[System.Collections.Generic.List[string]]::new()
    foreach ($domain in $exactDomains) {
        if ((Get-AdblockDecision -Trie $trie -Domain $domain) -ne 'BLOCK') { continue }
        if (-not (Test-AdblockCoveredBySuffixSet -Domain $domain -SuffixSet $finalSuffixSet)) {
            $finalExact.Add($domain)
        }
    }

    $outputRules=[System.Collections.Generic.List[object]]::new()
    foreach ($domain in ($finalExact | Sort-Object)) { $outputRules.Add([PSCustomObject]@{Type='DOMAIN';Domain=$domain}) }
    foreach ($domain in ($finalSuffixes | Sort-Object)) { $outputRules.Add([PSCustomObject]@{Type='DOMAIN-SUFFIX';Domain=$domain}) }

    return [PSCustomObject]@{
        Status=$(if ($conflicts.Count -gt 0) {'UNREPRESENTABLE'} else {'EXACT'})
        OutputRules=$outputRules.ToArray()
        Conflicts=$conflicts.ToArray()
        Trie=$trie
    }
}

function Read-AdblockHttpResponse {
    param(
        [Parameter(Mandatory)]$Response,
        [Parameter(Mandatory)][long]$MaxBytes,
        [System.Threading.CancellationToken]$CancellationToken = [System.Threading.CancellationToken]::None
    )
    if (-not $Response.IsSuccessStatusCode) { throw ("HTTP {0} {1}" -f [int]$Response.StatusCode,$Response.ReasonPhrase) }
    if ($null -ne $Response.Content.Headers.ContentLength -and $Response.Content.Headers.ContentLength -gt $MaxBytes) {
        throw "Response exceeds maxBytes ($MaxBytes)"
    }
    $inputStream=$Response.Content.ReadAsStreamAsync($CancellationToken).GetAwaiter().GetResult()
    $memoryStream=[System.IO.MemoryStream]::new()
    $buffer=[byte[]]::new(81920)
    try {
        while (($read=$inputStream.ReadAsync($buffer,0,$buffer.Length,$CancellationToken).GetAwaiter().GetResult()) -gt 0) {
            if (($memoryStream.Length + $read) -gt $MaxBytes) {
                throw "Response exceeds maxBytes ($MaxBytes)"
            }
            $memoryStream.Write($buffer,0,$read)
        }
        $bytes=$memoryStream.ToArray()
    }
    finally {
        $memoryStream.Dispose()
        $inputStream.Dispose()
    }
    if ($bytes.Length -eq 0) { throw 'Empty response body' }
    $encoding=[System.Text.UTF8Encoding]::new($false,$true)
    $content=$encoding.GetString($bytes)
    if ($content -match '^\s*<(?:!doctype\s+html|html)\b') { throw 'Received HTML instead of a filter list' }
    $sha=[System.Security.Cryptography.SHA256]::HashData($bytes)
    return [PSCustomObject]@{
        Content=$content; Bytes=$bytes.Length
        Sha256=[Convert]::ToHexString($sha).ToLowerInvariant()
        StatusCode=[int]$Response.StatusCode
    }
}

function Get-AdblockRemoteText {
    param([Parameter(Mandatory)][System.Net.Http.HttpClient]$Client,[Parameter(Mandatory)][string]$Url,[long]$MaxBytes=25000000,[int]$Retries=2)
    $lastError=$null
    for ($attempt=0; $attempt -le $Retries; $attempt++) {
        $response=$null
        try {
            $cancellation=[System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(75))
            $response=$Client.GetAsync($Url,[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancellation.Token).GetAwaiter().GetResult()
            return (Read-AdblockHttpResponse -Response $response -MaxBytes $MaxBytes -CancellationToken $cancellation.Token)
        }
        catch {
            $lastError=$_.Exception.Message
            if ($attempt -lt $Retries) { Start-Sleep -Seconds ([Math]::Min(2 * ($attempt + 1),8)) }
        }
        finally {
            if ($null -ne $response) { $response.Dispose() }
            if ($null -ne $cancellation) { $cancellation.Dispose() }
        }
    }
    throw "Download failed after $($Retries + 1) attempts: $Url : $lastError"
}

function Invoke-AdblockSourceDownloads {
    param([Parameter(Mandatory)][object[]]$Sources)
    $client=[System.Net.Http.HttpClient]::new()
    $client.Timeout=[TimeSpan]::FromMilliseconds(-1) # per-source cancellation tokens enforce timeoutSeconds
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('AdBlock_Rule_For_Clash/2.0 (+https://github.com/REIJI007/AdBlock_Rule_For_Clash)')
    $results=[System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $manifest=[System.Collections.Generic.List[object]]::new()
    $failedRequired=[System.Collections.Generic.List[string]]::new()

    try {
        $batchSize=12
        for ($offset=0; $offset -lt $Sources.Count; $offset+=$batchSize) {
            $end=[Math]::Min($offset+$batchSize-1,$Sources.Count-1)
            $batch=@($Sources[$offset..$end])
            $pending=[System.Collections.Generic.List[object]]::new()
            foreach ($source in $batch) {
                $timeoutSeconds=[Math]::Max(1,[Math]::Min(300,[int]$source.timeoutSeconds))
                $cancellation=[System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($timeoutSeconds))
                $pending.Add([PSCustomObject]@{
                    Source=$source
                    Task=$client.GetAsync([string]$source.url,[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancellation.Token)
                    Cancellation=$cancellation
                })
            }

            foreach ($item in $pending) {
                $source=$item.Source
                $download=$null
                $errorText=$null
                $response=$null
                $retryCancellation=$null
                for ($attempt=0; $attempt -le [int]$source.retries; $attempt++) {
                    try {
                        if ($attempt -eq 0) {
                            $response=$item.Task.GetAwaiter().GetResult()
                        } else {
                            $retryCancellation=[System.Threading.CancellationTokenSource]::new(
                                [TimeSpan]::FromSeconds([Math]::Max(1,[Math]::Min(300,[int]$source.timeoutSeconds)))
                            )
                            $response=$client.GetAsync([string]$source.url,[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,$retryCancellation.Token).GetAwaiter().GetResult()
                        }
                        $activeToken=if ($attempt -eq 0) { $item.Cancellation.Token } else { $retryCancellation.Token }
                        $download=Read-AdblockHttpResponse -Response $response -MaxBytes ([long]$source.maxBytes) -CancellationToken $activeToken
                        break
                    }
                    catch {
                        $errorText=$_.Exception.Message
                        if ($attempt -lt [int]$source.retries) { Start-Sleep -Seconds ([Math]::Min(2 * ($attempt + 1),8)) }
                    }
                    finally {
                        if ($null -ne $response) { $response.Dispose(); $response=$null }
                        if ($null -ne $retryCancellation) { $retryCancellation.Dispose(); $retryCancellation=$null }
                    }
                }
                $item.Cancellation.Dispose()

                if ($null -eq $download) {
                    $manifest.Add([PSCustomObject]@{Url=[string]$source.url;Required=[bool]$source.required;Status='FAILED';Error=$errorText})
                    if ([bool]$source.required) { $failedRequired.Add(([string]$source.url + ': ' + $errorText)) }
                    continue
                }
                $results[[string]$source.url]=$download.Content
                $manifest.Add([PSCustomObject]@{
                    Url=[string]$source.url;Required=[bool]$source.required;Status='OK'
                    HttpStatus=$download.StatusCode;Bytes=$download.Bytes;Sha256=$download.Sha256
                })
            }
        }
    }
    finally { $client.Dispose() }

    return [PSCustomObject]@{Contents=$results;Manifest=$manifest;FailedRequired=$failedRequired.ToArray()}
}

function Expand-AdblockIncludes {
    param(
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$SourceUrl,
        [Parameter(Mandatory)][System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory)]$Visited,
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$IncludeManifest,
        [int]$Depth=0,
        [int]$MaxDepth=8
    )
    if ($Depth -gt $MaxDepth) { return [PSCustomObject]@{Lines=@();Issues=@("include-depth-exceeded:$SourceUrl")} }

    $lines=[System.Collections.Generic.List[object]]::new()
    $issues=[System.Collections.Generic.List[string]]::new()
    $conditionalDepth=0
    $sourceLines=$Content -split '\r?\n'

    for ($i=0; $i -lt $sourceLines.Length; $i++) {
        $text=$sourceLines[$i].TrimEnd([char]13)

        if ($text -match '^\s*!#if\b') {
            $conditionalDepth++
            $issues.Add(('conditional-preprocessor-not-evaluated:{0}:{1}' -f $SourceUrl,($i+1)))
            continue
        }
        if ($text -match '^\s*!#endif\b') {
            if ($conditionalDepth -gt 0) { $conditionalDepth-- }
            else { $issues.Add(('unbalanced-endif:{0}:{1}' -f $SourceUrl,($i+1))) }
            continue
        }
        if ($conditionalDepth -gt 0) { continue }

        if ($text -match '^\s*!#include\s+(?<target>.+?)\s*$') {
            $target=$Matches.target.Trim().Trim('<','>','"',"'",' ')
            try { $includeUrl=([Uri]::new([Uri]$SourceUrl,$target)).AbsoluteUri }
            catch {
                $issues.Add(('invalid-include-url:{0}:{1}:{2}' -f $SourceUrl,($i+1),$target))
                continue
            }
            if (-not $Visited.Add($includeUrl)) { continue }
            try {
                $download=Get-AdblockRemoteText -Client $Client -Url $includeUrl -Retries 2
                $IncludeManifest.Add([PSCustomObject]@{Url=$includeUrl;Status='OK';Bytes=$download.Bytes;Sha256=$download.Sha256})
                $expanded=Expand-AdblockIncludes -Content $download.Content -SourceUrl $includeUrl -Client $Client -Visited $Visited -IncludeManifest $IncludeManifest -Depth ($Depth+1) -MaxDepth $MaxDepth
                foreach ($entry in $expanded.Lines) { $lines.Add($entry) }
                foreach ($issue in $expanded.Issues) { $issues.Add($issue) }
            }
            catch {
                $IncludeManifest.Add([PSCustomObject]@{Url=$includeUrl;Status='FAILED';Error=$_.Exception.Message})
                $issues.Add(('include-download-failed:{0}:{1}' -f $includeUrl,$_.Exception.Message))
            }
            continue
        }

        if ($text -match '^\s*!#') {
            $issues.Add(('unsupported-preprocessor-directive:{0}:{1}:{2}' -f $SourceUrl,($i+1),$text))
            continue
        }
        $lines.Add([PSCustomObject]@{Text=$text;SourceUrl=$SourceUrl;SourceLine=$i+1})
    }

    if ($conditionalDepth -gt 0) { $issues.Add("unclosed-conditional-preprocessor:$SourceUrl") }
    return [PSCustomObject]@{Lines=$lines.ToArray();Issues=$issues.ToArray()}
}

function Write-AdblockAtomicText {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Content)
    $directory=Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { [void](New-Item -ItemType Directory -Path $directory -Force) }
    $temporaryPath=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    $utf8=[System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($temporaryPath,$Content,$utf8)
    [System.IO.File]::Move($temporaryPath,$Path,$true)
}

function Write-AdblockCompiledOutputs {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rules,[Parameter(Mandatory)][string]$OutputDirectory)
    $ordered=@($Rules | Sort-Object Type,Domain)
    $yaml=[System.Collections.Generic.List[string]]::new()
    $yaml.Add('payload:')
    foreach ($rule in $ordered) { $yaml.Add(('  - {0},{1}' -f $rule.Type,$rule.Domain)) }

    $txt=@($ordered | ForEach-Object { '{0},{1}' -f $_.Type,$_.Domain }) -join [Environment]::NewLine
    if ($txt) { $txt += [Environment]::NewLine }

    $domainYaml=[System.Collections.Generic.List[string]]::new()
    $domainYaml.Add('payload:')
    foreach ($rule in $ordered) {
        if ($rule.Type -eq 'DOMAIN') { $domainYaml.Add(('  - "{0}"' -f $rule.Domain)) }
        else { $domainYaml.Add(('  - "+.{0}"' -f $rule.Domain)) }
    }

    Write-AdblockAtomicText -Path (Join-Path $OutputDirectory 'adblock_reject.yaml') -Content (($yaml -join [Environment]::NewLine)+[Environment]::NewLine)
    Write-AdblockAtomicText -Path (Join-Path $OutputDirectory 'adblock_reject.txt') -Content $txt
    Write-AdblockAtomicText -Path (Join-Path $OutputDirectory 'adblock_reject_domain.yaml') -Content (($domainYaml -join [Environment]::NewLine)+[Environment]::NewLine)
}

function Invoke-AdblockRuleBuild {
    [CmdletBinding()]
    param(
        [string]$RepositoryRoot=$PSScriptRoot,
        [string]$SourceConfigPath=(Join-Path $PSScriptRoot 'config/upstream-sources.json'),
        [switch]$AllowLossy
    )

    $config=Get-Content -LiteralPath $SourceConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($config.schemaVersion -ne 1) { throw "Unsupported source config schema: $($config.schemaVersion)" }
    $sources=@($config.sources)
    if ($sources.Count -eq 0) { throw 'No upstream sources configured' }
    $sourceUrlSet=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($source in $sources) {
        if ($source.defaultAction -notin @('BLOCK','ALLOW')) { throw "Invalid defaultAction for $($source.url)" }
        if (-not $source.url -or $source.syntax -notin @('AUTO','ADBLOCK','HOSTS','DNSMASQ')) { throw "Invalid source configuration: $($source.url)" }
        if ($source.preprocessor -notin @('NONE','UBO')) { throw "Invalid preprocessor for $($source.url)" }
        if ($source.plainDomainMatchType -notin @('EXACT','SUFFIX')) { throw "Invalid plainDomainMatchType for $($source.url)" }
        if ($source.hostsMatchType -notin @('EXACT','SUFFIX')) { throw "Invalid hostsMatchType for $($source.url)" }
        if ([int]$source.timeoutSeconds -lt 1 -or [int]$source.timeoutSeconds -gt 300) { throw "Invalid timeoutSeconds for $($source.url)" }
        if ([long]$source.maxBytes -lt 1 -or [int]$source.retries -lt 0 -or [int]$source.retries -gt 5) { throw "Invalid download limits for $($source.url)" }
        if ($null -eq $source.required) { throw "Source must explicitly declare required: $($source.url)" }
        try { $uri=[Uri]::new([string]$source.url) }
        catch { throw "Invalid upstream source URL: $($source.url)" }
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https') { throw "Upstream source must use HTTPS: $($source.url)" }
        if (-not $sourceUrlSet.Add([string]$source.url)) { throw "Duplicate upstream source URL: $($source.url)" }
    }

    $pslClient=[System.Net.Http.HttpClient]::new()
    try {
        $pslClient.Timeout=[TimeSpan]::FromSeconds(45)
        $pslClient.DefaultRequestHeaders.UserAgent.ParseAdd('AdBlock_Rule_For_Clash/2.0')
        $pslResponse=$pslClient.GetAsync('https://publicsuffix.org/list/public_suffix_list.dat').GetAwaiter().GetResult()
        try { $pslDownload=Read-AdblockHttpResponse -Response $pslResponse -MaxBytes 5000000 }
        finally { $pslResponse.Dispose() }
    }
    finally { $pslClient.Dispose() }
    Initialize-AdblockPsl -Content $pslDownload.Content

    $downloads=Invoke-AdblockSourceDownloads -Sources $sources
    $parsed=[System.Collections.Generic.List[object]]::new()
    $manifest=[System.Collections.Generic.List[object]]::new()
    foreach ($item in $downloads.Manifest) { $manifest.Add($item) }

    if ($downloads.FailedRequired.Count -gt 0) {
        [void](New-Item -ItemType Directory -Path $RepositoryRoot -Force)
        Write-AdblockAtomicText -Path (Join-Path $RepositoryRoot 'adblock_sources_manifest.json') -Content (($manifest | ConvertTo-Json -Depth 8)+[Environment]::NewLine)
        $failureReport=[PSCustomObject]@{
            SchemaVersion=1; Status='SOURCE_FAILURE'; StrictMode=(-not $AllowLossy)
            SourceCount=$sources.Count
            DownloadedSourceCount=@($downloads.Manifest | Where-Object Status -eq 'OK').Count
            FailedRequiredSources=@($downloads.FailedRequired)
        }
        Write-AdblockAtomicText -Path (Join-Path $RepositoryRoot 'adblock_build_report.json') -Content (($failureReport | ConvertTo-Json -Depth 8)+[Environment]::NewLine)
        throw ("Required upstream sources failed; refusing to publish:" + [Environment]::NewLine + ($downloads.FailedRequired -join [Environment]::NewLine))
    }

    $preprocessorIssues=[System.Collections.Generic.List[string]]::new()
    $includeManifest=[System.Collections.Generic.List[object]]::new()
    $includeClient=[System.Net.Http.HttpClient]::new()
    $includeClient.Timeout=[TimeSpan]::FromSeconds(75)
    $includeClient.DefaultRequestHeaders.UserAgent.ParseAdd('AdBlock_Rule_For_Clash/2.0')
    try {
        foreach ($source in $sources) {
            $url=[string]$source.url
            if (-not $downloads.Contents.ContainsKey($url)) { continue }
            if ($source.preprocessor -eq 'UBO') {
                $visited=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                [void]$visited.Add($url)
                $expanded=Expand-AdblockIncludes -Content $downloads.Contents[$url] -SourceUrl $url -Client $includeClient -Visited $visited -IncludeManifest $includeManifest
                foreach ($issue in $expanded.Issues) { $preprocessorIssues.Add($issue) }
            } else {
                $plainLines=[System.Collections.Generic.List[object]]::new()
                $sourceLines=$downloads.Contents[$url] -split '\r?\n'
                for ($lineIndex=0; $lineIndex -lt $sourceLines.Length; $lineIndex++) {
                    if ($sourceLines[$lineIndex] -match '^\s*!#') {
                        $preprocessorIssues.Add(('preprocessor-directive-on-source-not-marked-UBO:{0}:{1}' -f $url,($lineIndex+1)))
                        continue
                    }
                    $plainLines.Add([PSCustomObject]@{Text=$sourceLines[$lineIndex];SourceUrl=$url;SourceLine=$lineIndex+1})
                }
                $expanded=[PSCustomObject]@{Lines=$plainLines.ToArray();Issues=@()}
            }
            foreach ($line in $expanded.Lines) {
                $result=Parse-AdblockRuleLine -Line $line.Text -DefaultAction $source.defaultAction -SourceUrl $line.SourceUrl -SourceLine $line.SourceLine -PlainDomainMatchType $source.plainDomainMatchType -HostsMatchType $source.hostsMatchType
                if ($null -ne $result) { foreach ($entry in @($result)) { $parsed.Add($entry) } }
            }
        }
    }
    finally { $includeClient.Dispose() }

    foreach ($include in $includeManifest) { $manifest.Add($include) }
    $resolved=Resolve-AdblockRuleSet -ParsedRules $parsed.ToArray()
    $compilation=Get-AdblockCompilation -Rules $resolved.Rules
    $status=if ($compilation.Status -eq 'UNREPRESENTABLE' -and $AllowLossy) {'LOSSY'} else {$compilation.Status}

    $buildReport=[PSCustomObject]@{
        SchemaVersion=1; Status=$status; PslSha256=$pslDownload.Sha256
        StrictMode=(-not $AllowLossy); SourceCount=$sources.Count
        DownloadedSourceCount=@($downloads.Manifest | Where-Object Status -eq 'OK').Count
        ParsedRuleCount=$parsed.Count; SupportedRuleCount=$resolved.Rules.Count
        CancelledRuleCount=$resolved.CancelledRules.Count; BadfilterCount=$resolved.CancellationRules.Count
        OutOfScopeRuleCount=$resolved.OutOfScopeRules.Count
        OutOfScopeExamples=@($resolved.OutOfScopeRules | Select-Object -First 100)
        OutOfScopeSummary=@($resolved.OutOfScopeRules | Group-Object Reason | Sort-Object Name | ForEach-Object { [PSCustomObject]@{Reason=$_.Name;Count=$_.Count} })
        PreprocessorIssueCount=$preprocessorIssues.Count
        PreprocessorIssues=@($preprocessorIssues)
        PublicSuffixRuleCount=$script:PslExact.Count+$script:PslWildcard.Count+$script:PslException.Count
        OutputRuleCount=$compilation.OutputRules.Count
        DomainCount=@($compilation.OutputRules | Where-Object Type -eq 'DOMAIN').Count
        DomainSuffixCount=@($compilation.OutputRules | Where-Object Type -eq 'DOMAIN-SUFFIX').Count
        ConflictCount=$compilation.Conflicts.Count; Conflicts=@($compilation.Conflicts | Sort-Object BlackSuffixDomain)
    }

    [void](New-Item -ItemType Directory -Path $RepositoryRoot -Force)
    Write-AdblockAtomicText -Path (Join-Path $RepositoryRoot 'adblock_sources_manifest.json') -Content (($manifest | ConvertTo-Json -Depth 8)+[Environment]::NewLine)
    Write-AdblockAtomicText -Path (Join-Path $RepositoryRoot 'adblock_build_report.json') -Content (($buildReport | ConvertTo-Json -Depth 12)+[Environment]::NewLine)

    if ($preprocessorIssues.Count -gt 0) {
        throw ("uBO preprocessing has unresolved environment directives:" + [Environment]::NewLine + ($preprocessorIssues -join [Environment]::NewLine))
    }
    if ($compilation.Status -eq 'UNREPRESENTABLE' -and -not $AllowLossy) {
        throw "Rules cannot be represented by DOMAIN/DOMAIN-SUFFIX without changing behavior. See adblock_build_report.json. Conflicts: $($compilation.Conflicts.Count)"
    }

    Write-AdblockCompiledOutputs -Rules $compilation.OutputRules -OutputDirectory $RepositoryRoot
    Write-Host ('Build status: {0}; sources: {1}; supported: {2}; cancelled: {3}; out-of-scope: {4}; output: DOMAIN {5} / DOMAIN-SUFFIX {6}' -f $status,$sources.Count,$resolved.Rules.Count,$resolved.CancelledRules.Count,$resolved.OutOfScopeRules.Count,$buildReport.DomainCount,$buildReport.DomainSuffixCount)
    return $buildReport
}

Export-ModuleMember -Function @(
    'Initialize-AdblockPsl','Get-AdblockPublicSuffix','Test-AdblockPublicSuffix','Test-AdblockDnsDomain',
    'New-AdblockRule','Parse-AdblockRuleLine','Resolve-AdblockRuleSet','New-AdblockRuleTrie',
    'Get-AdblockMatchingRules','Get-AdblockDecision','Test-AdblockCoveredBySuffixSet','Get-AdblockCompilation',
    'Write-AdblockCompiledOutputs','Invoke-AdblockRuleBuild'
)
