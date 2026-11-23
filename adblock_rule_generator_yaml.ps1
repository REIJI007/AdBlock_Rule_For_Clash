# AdBlock rule generator — embedded shared core
[CmdletBinding()]
param(
    [switch]$AllowLossy,
    [switch]$TestMode
)

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

function Test-PublicSuffix([string]$Domain) {
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

function Get-AdblockMatchType(
    [object]$Parsed,
    [string]$RawRule,
    [ValidateSet('EXACT','SUFFIX')][string]$PlainDomainMatchType = 'EXACT',
    [ValidateSet('EXACT','SUFFIX')][string]$HostsMatchType = 'EXACT'
) {
    if ($Parsed.IsWildcard) { return 'WILDCARD' }
    if ($RawRule -match '^@@\|\|') { return 'SUFFIX' }
    if ($RawRule -match '^\|[a-zA-Z0-9]') { return 'EXACT' }
    if ($Parsed.SourceFormat -in @('plain-domain','whitelist-plain')) { return $PlainDomainMatchType }
    if ($Parsed.SourceFormat -in @('hosts','whitelist-hosts')) { return $HostsMatchType }
    if ($Parsed.SourceFormat -match 'suffix|dnsmasq') { return 'SUFFIX' }
    return 'EXACT'
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

function Convert-AdblockRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Rules,
        [bool]$Strict = $true,
        [object[]]$PreExistingIssues = @()
    )

    $index = New-AdblockRuleIndex -Rules $Rules
    $suffixDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $exactDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($rule in $Rules) {
        if ($rule.MatchType -eq 'SUFFIX') {
            [void]$suffixDomains.Add([string]$rule.Domain)
        }
        elseif ($rule.MatchType -eq 'EXACT') {
            [void]$exactDomains.Add([string]$rule.Domain)
        }
    }

    # Evaluate the suffix-only state once per rule node. Queries walk the
    # reverse-label trie, so work scales with domain depth, not RuleCount^2.
    $suffixStates = @{}
    foreach ($domain in $suffixDomains) {
        $suffixStates[$domain] = (Get-AdblockSuffixDecisionByIndex -Domain $domain -Index $index).Decision
    }

    $issues = [System.Collections.Generic.List[object]]::new()
    foreach ($issue in $PreExistingIssues) { $issues.Add($issue) }

    $rootsWithHoles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $holeDetails = @{}

    # A suffix ALLOW node creates a hole in every blocked suffix ancestor.
    foreach ($candidate in $suffixDomains) {
        if ($suffixStates[$candidate] -ne 'ALLOW') { continue }

        foreach ($ancestorRule in (Get-AdblockSuffixMatches -Domain $candidate -Index $index)) {
            $root = [string]$ancestorRule.Domain
            if ($root -eq $candidate) { continue }
            if (-not $suffixStates.ContainsKey($root) -or $suffixStates[$root] -ne 'BLOCK') { continue }

            [void]$rootsWithHoles.Add($root)
            if (-not $holeDetails.ContainsKey($root)) {
                $holeDetails[$root] = [System.Collections.Generic.List[string]]::new()
            }
            $detail = "suffix allow '$candidate'"
            if (-not $holeDetails[$root].Contains($detail)) { $holeDetails[$root].Add($detail) }
        }
    }

    # An exact ALLOW node is also a single-host hole in every blocked suffix
    # ancestor, including a suffix rule at the exact same hostname.
    foreach ($candidate in $exactDomains) {
        $decision = Get-AdblockDomainDecisionByIndex -Domain $candidate -Index $index
        if ($decision.Decision -ne 'ALLOW') { continue }

        foreach ($ancestorRule in (Get-AdblockSuffixMatches -Domain $candidate -Index $index)) {
            $root = [string]$ancestorRule.Domain
            if (-not $suffixStates.ContainsKey($root) -or $suffixStates[$root] -ne 'BLOCK') { continue }

            [void]$rootsWithHoles.Add($root)
            if (-not $holeDetails.ContainsKey($root)) {
                $holeDetails[$root] = [System.Collections.Generic.List[string]]::new()
            }
            $detail = "exact allow '$candidate'"
            if (-not $holeDetails[$root].Contains($detail)) { $holeDetails[$root].Add($detail) }
        }
    }

    foreach ($root in $rootsWithHoles) {
        $detailText = $holeDetails[$root] -join ', '
        $issues.Add([PSCustomObject]@{
            Type = 'PARTIAL_OVERLAP'
            Root = $root
            Detail = $detailText
            Message = "Blocked suffix '$root' contains allowed exception(s): $detailText"
        })
    }

    # Candidate suffix rules are those whose effective suffix-only state is
    # BLOCK and whose subtree has no allowed hole.
    $eligibleSuffixes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($domain in $suffixDomains) {
        if ($suffixStates[$domain] -eq 'BLOCK' -and -not $rootsWithHoles.Contains($domain)) {
            [void]$eligibleSuffixes.Add($domain)
        }
    }

    # Remove a suffix rule when an eligible ancestor suffix already covers it.
    $outputSuffix = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($domain in $eligibleSuffixes) {
        $coveredByAncestor = $false
        foreach ($ancestorRule in (Get-AdblockSuffixMatches -Domain $domain -Index $index)) {
            $ancestor = [string]$ancestorRule.Domain
            if ($ancestor -ne $domain -and $eligibleSuffixes.Contains($ancestor)) {
                $coveredByAncestor = $true
                break
            }
        }
        if (-not $coveredByAncestor) { [void]$outputSuffix.Add($domain) }
    }

    # Exact rules only remain when they block at their own hostname and no
    # emitted suffix ancestor already covers that hostname.
    $outputExact = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($domain in $exactDomains) {
        $decision = Get-AdblockDomainDecisionByIndex -Domain $domain -Index $index
        if ($decision.Decision -ne 'BLOCK') { continue }

        $coveredBySuffix = $false
        foreach ($ancestorRule in (Get-AdblockSuffixMatches -Domain $domain -Index $index)) {
            if ($outputSuffix.Contains([string]$ancestorRule.Domain)) {
                $coveredBySuffix = $true
                break
            }
        }
        if (-not $coveredBySuffix) { [void]$outputExact.Add($domain) }
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
        Exact = $exactArray
        Suffix = $suffixArray
        Issues = $issues.ToArray()
        IsLossless = ($issues.Count -eq 0)
        TotalRules = $exactArray.Count + $suffixArray.Count
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

function Import-AdblockPublicSuffixList {
    [CmdletBinding()]
    param([string]$Uri='https://publicsuffix.org/list/public_suffix_list.dat')
    $client=[System.Net.Http.HttpClient]::new()
    try {
        $client.Timeout=[TimeSpan]::FromSeconds(45)
        $client.DefaultRequestHeaders.UserAgent.ParseAdd('AdBlock_Rule_For_Clash/2.0')
        Write-AdblockConsole -Level INFO -Message ("正在下载 PSL 公共后缀列表：{0}" -f $Uri)
    $download=Get-AdblockRemoteText -Client $client -Url $Uri -MaxBytes 5000000 -Retries 2 -TimeoutSeconds 45
    } finally { $client.Dispose() }
    $count=Set-AdblockPublicSuffixRules -Rules ($download.Content -split '\r?\n')
    if ($count -lt 1000) { throw "PSL data looks incomplete ($count rules)." }
    return $count
}


function Read-AdblockHttpResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Response,
        [long]$MaxBytes = 25000000,
        [System.Threading.CancellationToken]$CancellationToken = [System.Threading.CancellationToken]::None
    )
    if (-not $Response.IsSuccessStatusCode) { throw ('HTTP {0} {1}' -f [int]$Response.StatusCode,$Response.ReasonPhrase) }
    if ($null -ne $Response.Content.Headers.ContentLength -and [long]$Response.Content.Headers.ContentLength -gt $MaxBytes) {
        throw "Response exceeds maxBytes ($MaxBytes)"
    }
    $inputStream = $Response.Content.ReadAsStreamAsync($CancellationToken).GetAwaiter().GetResult()
    $memoryStream = [System.IO.MemoryStream]::new()
    $buffer = [byte[]]::new(81920)
    try {
        while (($read = $inputStream.ReadAsync($buffer,0,$buffer.Length,$CancellationToken).GetAwaiter().GetResult()) -gt 0) {
            if (($memoryStream.Length + $read) -gt $MaxBytes) { throw "Response exceeds maxBytes ($MaxBytes)" }
            $memoryStream.Write($buffer,0,$read)
        }
        $bytes = $memoryStream.ToArray()
    }
    finally {
        $memoryStream.Dispose()
        $inputStream.Dispose()
    }
    if ($bytes.Length -eq 0) { throw 'Empty response body' }
    try { $content = [System.Text.UTF8Encoding]::new($false,$true).GetString($bytes) }
    catch { throw "Response is not valid UTF-8: $($_.Exception.Message)" }
    if ($content -match '^\s*<(?:!doctype\s+html|html)\b') { throw 'Received HTML instead of a filter list' }
    $sha = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return [PSCustomObject]@{Content=$content;Bytes=$bytes.Length;Sha256=[Convert]::ToHexString($sha).ToLowerInvariant();StatusCode=[int]$Response.StatusCode}
}

function Get-AdblockRemoteText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory)][string]$Url,
        [long]$MaxBytes = 25000000,
        [int]$Retries = 2,
        [int]$TimeoutSeconds = 75
    )
    $lastError = $null
    for ($attempt=0; $attempt -le $Retries; $attempt++) {
        $response = $null
        $cancellation = $null
        try {
            $cancellation = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSeconds))
            $response = $Client.GetAsync($Url,[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancellation.Token).GetAwaiter().GetResult()
            return (Read-AdblockHttpResponse -Response $response -MaxBytes $MaxBytes -CancellationToken $cancellation.Token)
        }
        catch {
            $lastError = $_.Exception.Message
            if ($attempt -lt $Retries) { Start-Sleep -Seconds ([Math]::Min(2 * ($attempt + 1),8)) }
        }
        finally {
            if ($null -ne $response) { $response.Dispose() }
            if ($null -ne $cancellation) { $cancellation.Dispose() }
        }
    }
    throw ("Download failed after {0} attempts: {1}: {2}" -f ($Retries+1),$Url,$lastError)
}

function Write-AdblockConsole {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('STAGE','INFO','SUCCESS','WARNING','ERROR')][string]$Level,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message
    )
    $time = (Get-Date).ToString('HH:mm:ss')
    $color = switch ($Level) {
        'STAGE'   { 'Cyan' }
        'SUCCESS' { 'Green' }
        'WARNING' { 'Yellow' }
        'ERROR'   { 'Red' }
        default   { 'Gray' }
    }
    Write-Host ("[{0}] [{1,-7}] {2}" -f $time,$Level,$Message) -ForegroundColor $color
}

function Invoke-AdblockSourceDownloads {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Sources)
    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromMilliseconds(-1)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('AdBlock_Rule_For_Clash/2.0 (+https://github.com/REIJI007/AdBlock_Rule_For_Clash)')
    $contents = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $manifest = [System.Collections.Generic.List[object]]::new()
    $failedRequired = [System.Collections.Generic.List[string]]::new()
    try {
        $batchSize = 12
        for ($offset=0; $offset -lt $Sources.Count; $offset += $batchSize) {
            $end = [Math]::Min($offset+$batchSize-1,$Sources.Count-1)
            $batch = @($Sources[$offset..$end])
            $pending = [System.Collections.Generic.List[object]]::new()
            foreach ($source in $batch) {
                $sourceIndex = $offset + $pending.Count + 1
                Write-AdblockConsole -Level INFO -Message ("[{0}/{1}] 正在发起上游下载：{2}" -f $sourceIndex,$Sources.Count,$source.url)
                $timeout = [Math]::Max(1,[Math]::Min(300,[int]$source.timeoutSeconds))
                $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($timeout))
                $task = $client.GetAsync([string]$source.url,[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cts.Token)
                $pending.Add([PSCustomObject]@{Source=$source;Task=$task;Cancellation=$cts;SourceIndex=$sourceIndex})
            }
            foreach ($item in $pending) {
                $source=$item.Source; $sourceIndex=[int]$item.SourceIndex
                $sourceTimer=[System.Diagnostics.Stopwatch]::StartNew()
                $download=$null; $errorText=$null; $response=$null; $retryCts=$null; $attempts=0
                for ($attempt=0; $attempt -le [int]$source.retries; $attempt++) {
                    $attempts++
                    try {
                        if ($attempt -eq 0) {
                            $response=$item.Task.GetAwaiter().GetResult()
                            $token=$item.Cancellation.Token
                        } else {
                            $timeout=[Math]::Max(1,[Math]::Min(300,[int]$source.timeoutSeconds))
                            $retryCts=[System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($timeout))
                            $response=$client.GetAsync([string]$source.url,[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,$retryCts.Token).GetAwaiter().GetResult()
                            $token=$retryCts.Token
                        }
                        $download=Read-AdblockHttpResponse -Response $response -MaxBytes ([long]$source.maxBytes) -CancellationToken $token
                        if ($source.sha256 -and $download.Sha256 -ne ([string]$source.sha256).ToLowerInvariant()) { throw 'SHA-256 mismatch with pinned source hash' }
                        break
                    }
                    catch {
                        $errorText=$_.Exception.Message
                        if ($attempt -lt [int]$source.retries) { Start-Sleep -Seconds ([Math]::Min(2*($attempt+1),8)) }
                    }
                    finally {
                        if ($null -ne $response) { $response.Dispose(); $response=$null }
                        if ($null -ne $retryCts) { $retryCts.Dispose(); $retryCts=$null }
                    }
                }
                $item.Cancellation.Dispose()
                $sourceTimer.Stop()
                if ($null -eq $download) {
                    Write-AdblockConsole -Level ERROR -Message ("[{0}/{1}] 上游下载失败（尝试 {2} 次，耗时 {3:N1}s）：{4}；原因：{5}" -f $sourceIndex,$Sources.Count,$attempts,$sourceTimer.Elapsed.TotalSeconds,$source.url,$errorText)
                    $manifest.Add([PSCustomObject]@{Type='source';Url=[string]$source.url;Required=[bool]$source.required;Status='FAILED';Attempts=$attempts;Error=$errorText})
                    if ([bool]$source.required) { $failedRequired.Add(([string]$source.url+': '+$errorText)) }
                    continue
                }
                $contents[[string]$source.url]=$download.Content
                $manifest.Add([PSCustomObject]@{Type='source';Url=[string]$source.url;Required=[bool]$source.required;Status='OK';Attempts=$attempts;HttpStatus=$download.StatusCode;Bytes=$download.Bytes;Sha256=$download.Sha256})
                Write-AdblockConsole -Level SUCCESS -Message ("[{0}/{1}] 下载完成：HTTP {2}，{3:N1} KB，{4} 次尝试，耗时 {5:N1}s：{6}" -f $sourceIndex,$Sources.Count,$download.StatusCode,($download.Bytes/1KB),$attempts,$sourceTimer.Elapsed.TotalSeconds,$source.url)
            }
        }
    }
    finally { $client.Dispose() }
    return [PSCustomObject]@{Contents=$contents;Manifest=$manifest;FailedRequired=$failedRequired.ToArray()}
}

function Expand-AdblockIncludes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$SourceUrl,
        [Parameter(Mandatory)][System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory)]$Visited,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$IncludeManifest,
        [long]$MaxBytes=25000000,
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
            if ($conditionalDepth -gt 0) { $conditionalDepth-- } else { $issues.Add(('unbalanced-endif:{0}:{1}' -f $SourceUrl,($i+1))) }
            continue
        }
        if ($conditionalDepth -gt 0) { continue }
        if ($text -match '^\s*!#include\s+(?<target>.+?)\s*$') {
            $target=$Matches.target.Trim().Trim([char[]]@('<','>','"',[char]39,' '))
            try {
                $includeUri=[Uri]::new([Uri]$SourceUrl,$target)
                if (-not $includeUri.IsAbsoluteUri -or $includeUri.Scheme -ne 'https') { throw 'uBO includes must resolve to HTTPS URLs.' }
                $includeUrl=$includeUri.AbsoluteUri
            } catch {
                $issues.Add(('invalid-include-url:{0}:{1}:{2}' -f $SourceUrl,($i+1),$target))
                continue
            }
            if (-not $Visited.Add($includeUrl)) { continue }
            try {
                Write-AdblockConsole -Level INFO -Message ("    正在下载 uBO Include：{0}" -f $includeUrl)
                $download=Get-AdblockRemoteText -Client $Client -Url $includeUrl -MaxBytes $MaxBytes -Retries 2 -TimeoutSeconds 75
                $IncludeManifest.Add([PSCustomObject]@{Type='include';Url=$includeUrl;Required=$true;Status='OK';Bytes=$download.Bytes;Sha256=$download.Sha256})
                Write-AdblockConsole -Level SUCCESS -Message ("    uBO Include 下载完成：{0:N1} KB：{1}" -f ($download.Bytes/1KB),$includeUrl)
                $expanded=Expand-AdblockIncludes -Content $download.Content -SourceUrl $includeUrl -Client $Client -Visited $Visited -IncludeManifest $IncludeManifest -MaxBytes $MaxBytes -Depth ($Depth+1) -MaxDepth $MaxDepth
                foreach ($entry in $expanded.Lines) { $lines.Add($entry) }
                foreach ($issue in $expanded.Issues) { $issues.Add($issue) }
            } catch {
                Write-AdblockConsole -Level ERROR -Message ("    uBO Include 下载失败：{0}；原因：{1}" -f $includeUrl,$_.Exception.Message)
                $IncludeManifest.Add([PSCustomObject]@{Type='include';Url=$includeUrl;Required=$true;Status='FAILED';Error=$_.Exception.Message})
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
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    $directory=Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory)) {
        [void](New-Item -ItemType Directory -Path $directory -Force)
    }
    $tempPath=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try {
        [System.IO.File]::WriteAllText($tempPath,$Content,[System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tempPath -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force }
    }
}

function Get-AdblockSourceConfig {
    [CmdletBinding()]
    param([string]$Path=(Join-Path $PSScriptRoot 'upstream-sources.json'))
    if (-not (Test-Path -LiteralPath $Path)) { throw "Upstream source list not found: $Path" }
    $urls = @(Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    if ($urls.Count -eq 0) { throw "Upstream source list is empty: $Path" }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $sources = [System.Collections.Generic.List[object]]::new()
    foreach ($value in $urls) {
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
            throw 'upstream-sources.json must be a JSON array of URL strings only.'
        }
        $url = [string]$value
        try { $uri = [Uri]::new($url) } catch { throw "Invalid upstream URL: $url" }
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https') { throw "Upstream URL must use HTTPS: $url" }
        if (-not $seen.Add($url)) { throw "Duplicate upstream URL: $url" }

        # All sources use the same ingestion policy. Rule actions and syntax
        # are detected from the downloaded content, never from the source URL.
        $sources.Add([PSCustomObject]@{
            id = "source-$($sources.Count + 1)"
            url = $url
            required = $true
            enabled = $true
            syntax = 'AUTO'
            preprocessor = 'AUTO'
            plainDomainMatchType = 'EXACT'
            hostsMatchType = 'EXACT'
            maxBytes = 25000000
            retries = 2
            timeoutSeconds = 75
            sha256 = $null
        })
    }
    return $sources.ToArray()
}


function Invoke-AdblockGeneration {
    [CmdletBinding()]
    param(
        [ValidateSet('yaml','txt')][string]$Format='yaml',
        [string]$SourceListPath=(Join-Path $PSScriptRoot 'upstream-sources.json'),
        [bool]$Strict=$true
    )
    $repositoryRoot=$PSScriptRoot
    $buildTimer=[System.Diagnostics.Stopwatch]::StartNew()
    $manifestPath=Join-Path $repositoryRoot ('adblock_sources_manifest_' + $Format + '.json')
    $reportPath=Join-Path $repositoryRoot ('adblock_build_report_' + $Format + '.json')

    Write-Host ''
    Write-AdblockConsole -Level STAGE -Message ('========== AdBlock {0} 规则生成开始 ==========' -f $Format.ToUpperInvariant())
    Write-AdblockConsole -Level INFO -Message ("运行模式：{0}；PowerShell：{1}" -f $(if($Strict){'严格模式'}else{'允许有损模式'}),$PSVersionTable.PSVersion)
    Write-AdblockConsole -Level STAGE -Message '阶段 1/6：读取上游规则源清单'
    Write-AdblockConsole -Level INFO -Message ("来源文件：{0}" -f $SourceListPath)
    $sources=@(Get-AdblockSourceConfig -Path $SourceListPath)
    Write-AdblockConsole -Level SUCCESS -Message ("已加载 {0} 个上游链接，全部按规则内容自动识别语法和动作。" -f $sources.Count)

    Write-AdblockConsole -Level STAGE -Message ("阶段 2/6：下载上游规则源（每批最多 12 个并发请求，共 {0} 个）" -f $sources.Count)
    $downloads=Invoke-AdblockSourceDownloads -Sources $sources
    $downloadedCount=@($downloads.Manifest | Where-Object { $_.Type -eq 'source' -and $_.Status -eq 'OK' }).Count
    $failedCount=@($downloads.Manifest | Where-Object { $_.Type -eq 'source' -and $_.Status -eq 'FAILED' }).Count
    Write-AdblockConsole -Level INFO -Message ("上游下载汇总：成功 {0}，失败 {1}，总计 {2}" -f $downloadedCount,$failedCount,$sources.Count)
    $manifest=[System.Collections.Generic.List[object]]::new()
    foreach ($item in $downloads.Manifest) { $manifest.Add($item) }

    if (@($downloads.FailedRequired).Count -gt 0) {
        Write-AdblockConsole -Level ERROR -Message ("有 {0} 个必需上游源下载失败，严格停止生成。" -f $downloads.FailedRequired.Count)
        foreach ($failure in $downloads.FailedRequired) {
            Write-AdblockConsole -Level ERROR -Message $failure
        }
        Write-AdblockAtomicText -Path $manifestPath -Content (($manifest | ConvertTo-Json -Depth 8)+[Environment]::NewLine)
        $failedReport=[PSCustomObject]@{
            SchemaVersion=1;Format=$Format;Status='SOURCE_FAILURE';StrictMode=$Strict;SourceCount=$sources.Count
            DownloadedSourceCount=@($manifest | Where-Object { $_.Type -eq 'source' -and $_.Status -eq 'OK' }).Count
            FailedRequiredSources=@($downloads.FailedRequired)
        }
        Write-AdblockAtomicText -Path $reportPath -Content (($failedReport | ConvertTo-Json -Depth 12)+[Environment]::NewLine)
        throw ("Required upstream sources failed; refusing to publish:"+[Environment]::NewLine+($downloads.FailedRequired -join [Environment]::NewLine))
    }

    Write-AdblockConsole -Level STAGE -Message '阶段 3/6：加载 Public Suffix List（PSL）'
    $pslRuleCount=Import-AdblockPublicSuffixList
    Write-AdblockConsole -Level SUCCESS -Message ("PSL 加载完成，共 {0} 条规则。" -f $pslRuleCount)

    Write-AdblockConsole -Level STAGE -Message '阶段 4/6：解析上游规则、展开 Hosts 和 uBO Include'
    $preIssues=[System.Collections.Generic.List[object]]::new()
    $preprocessorIssues=[System.Collections.Generic.List[string]]::new()
    $includeManifest=[System.Collections.Generic.List[object]]::new()
    $rawRules=[System.Collections.Generic.List[object]]::new()
    $badfilterKeys=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $skipStats=[System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $stats=@{Parsed=0;Skipped=0;Invalid=0;Badfilter=0;Wildcard=0;PublicSuffix=0;HostsExpanded=0}
    $includeClient=[System.Net.Http.HttpClient]::new()
    $includeClient.Timeout=[TimeSpan]::FromMilliseconds(-1)
    $includeClient.DefaultRequestHeaders.UserAgent.ParseAdd('AdBlock_Rule_For_Clash/2.0')
    try {
        $sourceIndex=0
        foreach ($source in $sources) {
            $sourceIndex++
            $subscriptionUrl=[string]$source.url
            $parsedBefore=$stats.Parsed
            $skippedBefore=$stats.Skipped
            $rulesBefore=$rawRules.Count
            if (-not $downloads.Contents.ContainsKey($subscriptionUrl)) {
                Write-AdblockConsole -Level WARNING -Message ("[{0}/{1}] 下载内容缺失，跳过解析：{2}" -f $sourceIndex,$sources.Count,$subscriptionUrl)
                continue
            }
            Write-AdblockConsole -Level INFO -Message ("[{0}/{1}] 正在解析上游规则：{2}" -f $sourceIndex,$sources.Count,$subscriptionUrl)
            if ($downloads.Contents[$subscriptionUrl] -match '(?im)^\s*!#') {
                $visited=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                [void]$visited.Add($subscriptionUrl)
                $expanded=Expand-AdblockIncludes -Content $downloads.Contents[$subscriptionUrl] -SourceUrl $subscriptionUrl -Client $includeClient -Visited $visited -IncludeManifest $includeManifest -MaxBytes ([long]$source.maxBytes)
            } else {
                $plainLines=[System.Collections.Generic.List[object]]::new()
                $sourceLines=$downloads.Contents[$subscriptionUrl] -split '\r?\n'
                for ($lineIndex=0; $lineIndex -lt $sourceLines.Length; $lineIndex++) {
                    $lineText=([string]$sourceLines[$lineIndex]).TrimStart([char]0xFEFF)
                    $plainLines.Add([PSCustomObject]@{Text=$lineText;SourceUrl=$subscriptionUrl;SourceLine=$lineIndex+1})
                }
                $expanded=[PSCustomObject]@{Lines=$plainLines.ToArray();Issues=@()}
            }
            foreach ($issue in $expanded.Issues) { $preprocessorIssues.Add([string]$issue) }
            foreach ($lineRecord in $expanded.Lines) {
                $rawText=([string]$lineRecord.Text).Trim()
                $linesToParse=@([PSCustomObject]@{Text=$rawText;SourceUrl=[string]$lineRecord.SourceUrl;SourceLine=[int]$lineRecord.SourceLine})
                if ($rawText -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+(.+)$') {
                    $hostsIp=$Matches[1]
                    $hostTokens=@($Matches[2] -split '\s+')
                    if ($hostTokens.Count -gt 1) {
                        $expandedHosts=[System.Collections.Generic.List[object]]::new()
                        foreach ($hostName in $hostTokens) {
                            if (-not $hostName -or $hostName.StartsWith('#')) { break }
                            $expandedHosts.Add([PSCustomObject]@{Text="$hostsIp $hostName";SourceUrl=[string]$lineRecord.SourceUrl;SourceLine=[int]$lineRecord.SourceLine})
                        }
                        if ($expandedHosts.Count -gt 0) { $linesToParse=$expandedHosts.ToArray(); $stats.HostsExpanded+=$expandedHosts.Count }
                    }
                }
                foreach ($lineToParse in $linesToParse) {
                    $rawLine=[string]$lineToParse.Text
                    $lineSourceUrl=[string]$lineToParse.SourceUrl
                    $lineNumber=[int]$lineToParse.SourceLine
                    $parsed=Parse-Rule -line $rawLine -SourceSyntax 'AUTO'
                    $stats.Parsed++
                    if ($parsed.Action -eq 'SKIP') {
                        $stats.Skipped++
                        $reason=[string]$parsed.SkipReason
                        if (-not $skipStats.ContainsKey($reason)) { $skipStats[$reason]=0 }
                        $skipStats[$reason]++
                        if (Test-AdblockStrictParseIssue -SkipReason $reason) {
                            $preIssues.Add([PSCustomObject]@{
                                Type='UNRECOGNIZED_RULE_SYNTAX';Root=$lineSourceUrl;Detail=$rawLine
                                Message=('Unrecognized rule syntax in source {0}, line {1}: {2}' -f $lineSourceUrl,$lineNumber,$rawLine)
                            })
                        }
                        continue
                    }
                    $identity=Get-AdblockRuleIdentity $rawLine
                    if ($parsed.Action -eq 'BADFILTER') {
                        [void]$badfilterKeys.Add($subscriptionUrl+[char]10+$identity)
                        $stats.Badfilter++
                        continue
                    }
                    if ($parsed.IsWildcard) {
                        $stats.Wildcard++
                        $preIssues.Add([PSCustomObject]@{
                            Type='UNSUPPORTED_WILDCARD';Root=$parsed.Domain;Detail=$rawLine
                            Message="Wildcard pattern cannot be represented losslessly by DOMAIN / DOMAIN-SUFFIX: $rawLine"
                        })
                        continue
                    }
                    $matchType=Get-AdblockMatchType -Parsed $parsed -RawRule $rawLine -PlainDomainMatchType ([string]$source.plainDomainMatchType) -HostsMatchType ([string]$source.hostsMatchType)
                    $domain=Normalize-Domain ([string]$parsed.Domain)
                    if (-not (Is-ValidDNSDomain $domain)) {
                        $stats.Invalid++
                        $preIssues.Add([PSCustomObject]@{
                            Type='INVALID_DOMAIN';Root=$domain;Detail=$rawLine
                            Message=('Parsed domain is not a valid DNS rule name at {0}:{1}: {2}' -f $lineSourceUrl,$lineNumber,$rawLine)
                        })
                        continue
                    }
                    $action=if ($parsed.Action -eq 'EXCLUDE') {'ALLOW'} else {'BLOCK'}
                    $important=[bool]$parsed.IsImportant
                    $priority=Get-AdblockRulePriority -Action $action -MatchType $matchType -IsImportant $important
                    if (Test-PublicSuffix $domain) { $stats.PublicSuffix++ }
                    $rawRules.Add([PSCustomObject]@{
                        Domain=$domain;MatchType=$matchType;Action=$action;Priority=$priority;IsImportant=$important
                        RawRule=$rawLine;RuleIdentity=$identity;SourceUrl=$lineSourceUrl;SubscriptionUrl=$subscriptionUrl
                        SourceLine=$lineNumber;SourceFormat=$parsed.SourceFormat
                    })
                }
            }
            Write-AdblockConsole -Level SUCCESS -Message ("[{0}/{1}] 来源解析完成：解析 {2} 行，提取候选规则 {3} 条，跳过 {4} 行。" -f $sourceIndex,$sources.Count,($stats.Parsed-$parsedBefore),($rawRules.Count-$rulesBefore),($stats.Skipped-$skippedBefore))
        }
    } finally { $includeClient.Dispose() }

    foreach ($include in $includeManifest) { $manifest.Add($include) }
    Write-AdblockConsole -Level INFO -Message ("规则解析阶段结束：已解析 {0} 行，原始候选规则 {1} 条，uBO Include {2} 个，预处理问题 {3} 个。" -f $stats.Parsed,$rawRules.Count,$includeManifest.Count,$preprocessorIssues.Count)
    foreach ($issue in $preprocessorIssues) {
        Write-AdblockConsole -Level WARNING -Message ("预处理未完全解析：{0}" -f $issue)
        $preIssues.Add([PSCustomObject]@{Type='UNRESOLVED_PREPROCESSOR';Root='';Detail=[string]$issue;Message=[string]$issue})
    }
    Write-AdblockConsole -Level STAGE -Message '阶段 5/6：应用 badfilter、规则去重、优先级裁决与无损性检查'
    Write-AdblockConsole -Level INFO -Message ("检测到 {0} 个 badfilter 撤销身份。" -f $badfilterKeys.Count)
    $activeRules=[System.Collections.Generic.List[object]]::new()
    foreach ($rule in $rawRules) {
        $key=$rule.SubscriptionUrl+[char]10+$rule.RuleIdentity
        if (-not $badfilterKeys.Contains($key)) { $activeRules.Add($rule) }
    }
    $dedup=[System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $activeRules) {
        $key="$($rule.Priority)|$($rule.Action)|$($rule.MatchType)|$($rule.Domain)"
        if (-not $dedup.ContainsKey($key)) { $dedup.Add($key,$rule) }
    }
    $rules=@($dedup.Values)
    Write-AdblockConsole -Level INFO -Message ("规则整理完成：原始候选 {0} 条，badfilter 移除 {1} 条，去重后活动规则 {2} 条。" -f $rawRules.Count,($rawRules.Count-$activeRules.Count),$rules.Count)
    $allowCount=@($rules | Where-Object { $_.Action -eq 'ALLOW' }).Count
    $blockCount=@($rules | Where-Object { $_.Action -eq 'BLOCK' }).Count
    Write-AdblockConsole -Level INFO -Message ("规则动作统计：ALLOW {0} 条，BLOCK {1} 条。" -f $allowCount,$blockCount)
    Write-AdblockConsole -Level INFO -Message '正在执行五级优先级裁决、白名单例外检测和冗余规则剪枝...'
    $compileTimer=[System.Diagnostics.Stopwatch]::StartNew()
    $compiled=Convert-AdblockRules -Rules $rules -Strict:$false -PreExistingIssues $preIssues.ToArray()
    $compileTimer.Stop()
    Write-AdblockConsole -Level SUCCESS -Message ("规则编译完成，耗时 {0:N1}s；精确域名 {1} 条，后缀域名 {2} 条，冲突/不可表达问题 {3} 个。" -f $compileTimer.Elapsed.TotalSeconds,$compiled.Exact.Count,$compiled.Suffix.Count,$compiled.Issues.Count)
    if ($compiled.Issues.Count -gt 0) {
        foreach ($issue in @($compiled.Issues | Select-Object -First 10)) {
            Write-AdblockConsole -Level WARNING -Message ("{0}: {1}" -f $issue.Type,$issue.Message)
        }
        if ($compiled.Issues.Count -gt 10) {
            Write-AdblockConsole -Level WARNING -Message ("其余 {0} 个问题请查看构建报告。" -f ($compiled.Issues.Count-10))
        }
    }
    $successfulSources=@($manifest | Where-Object { $_.Type -eq 'source' -and $_.Status -eq 'OK' } | Sort-Object Url)
    $fingerprintParts=@($successfulSources | ForEach-Object { "$($_.Url)|$($_.Sha256)|$($_.Bytes)" })
    $fingerprintInput=$fingerprintParts -join [Environment]::NewLine
    $fingerprintBytes=[System.Text.UTF8Encoding]::new($false).GetBytes($fingerprintInput)
    $snapshotHash=[Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($fingerprintBytes)).ToLowerInvariant()
    $exact=@($compiled.Exact); $suffix=@($compiled.Suffix)
    $status=if ($compiled.IsLossless) {'EXACT'} else {'UNREPRESENTABLE'}
    $report=[PSCustomObject]@{
        SchemaVersion=1;Format=$Format;Status=$status;StrictMode=$Strict;SourceCount=$sources.Count;DownloadedSourceCount=$successfulSources.Count
        FailedOptionalSourceCount=@($manifest | Where-Object { $_.Type -eq 'source' -and $_.Status -eq 'FAILED' -and -not $_.Required }).Count
        SnapshotSha256=$snapshotHash;ParsedLineCount=$stats.Parsed;ActiveRuleCount=$rules.Count
        DomainCount=$exact.Count;DomainSuffixCount=$suffix.Count;BadfilterCount=$stats.Badfilter
        SkippedLineCount=$stats.Skipped;InvalidDomainCount=$stats.Invalid;WildcardCount=$stats.Wildcard
        HostsExpandedCount=$stats.HostsExpanded;PreprocessorIssueCount=$preprocessorIssues.Count
        PreprocessorIssues=@($preprocessorIssues);PublicSuffixRuleCount=$stats.PublicSuffix
        ConflictCount=$compiled.Issues.Count;Conflicts=@($compiled.Issues)
        SkipReasonSummary=@($skipStats.GetEnumerator() | Sort-Object Name | ForEach-Object { [PSCustomObject]@{Reason=$_.Key;Count=$_.Value} })
        IncludeCount=$includeManifest.Count
    }
    Write-AdblockAtomicText -Path $manifestPath -Content (($manifest | ConvertTo-Json -Depth 10)+[Environment]::NewLine)
    Write-AdblockAtomicText -Path $reportPath -Content (($report | ConvertTo-Json -Depth 14)+[Environment]::NewLine)
    if ($Strict -and -not $compiled.IsLossless) {
        Write-AdblockConsole -Level ERROR -Message ("严格模式阻止生成：发现 {0} 个不可无损表达的问题；原有规则文件不会被覆盖。报告：{1}" -f $compiled.Issues.Count,$reportPath)
        throw ("Strict compilation failed: {0} unrepresentable issue(s). No generated provider files were overwritten. See {1}." -f $compiled.Issues.Count,$reportPath)
    }
    Write-AdblockConsole -Level STAGE -Message '阶段 6/6：生成并原子写入规则文件'
    $outputs=[System.Collections.Generic.List[object]]::new()
    if ($Format -eq 'yaml') {
        $yamlRules=@($suffix | ForEach-Object {'  - DOMAIN-SUFFIX,'+$_})+@($exact | ForEach-Object {'  - DOMAIN,'+$_})
        $yamlText=@('# Generated by AdBlock_Rule_For_Clash',"# DOMAIN: $($exact.Count)","# DOMAIN-SUFFIX: $($suffix.Count)",'payload:')+$yamlRules
        $outputs.Add([PSCustomObject]@{
            Path=(Join-Path $repositoryRoot 'adblock_reject.yaml')
            Text=($yamlText -join [Environment]::NewLine)+[Environment]::NewLine
        })
    }
    elseif ($Format -eq 'txt') {
        $txtRules=@($suffix | ForEach-Object {'DOMAIN-SUFFIX,'+$_})+@($exact | ForEach-Object {'DOMAIN,'+$_})
        $outputs.Add([PSCustomObject]@{
            Path=(Join-Path $repositoryRoot 'adblock_reject.txt')
            Text=($txtRules -join [Environment]::NewLine)+[Environment]::NewLine
        })
    }
    else {
        throw "Unsupported output format: $Format"
    }
    foreach ($output in $outputs) {
        Write-AdblockAtomicText -Path $output.Path -Content $output.Text
        Write-AdblockConsole -Level SUCCESS -Message ("规则文件已写入：{0}" -f $output.Path)
    }

    $buildTimer.Stop()
    $totalSkipped=($skipStats.Values | Measure-Object -Sum).Sum
    if ($null -eq $totalSkipped) { $totalSkipped=0 }
    Write-Host ''
    Write-AdblockConsole -Level STAGE -Message ("========== AdBlock {0} 规则生成完成 ==========" -f $Format.ToUpperInvariant())
    Write-AdblockConsole -Level SUCCESS -Message ("总规则数：{0}（DOMAIN：{1}；DOMAIN-SUFFIX：{2}）" -f ($exact.Count+$suffix.Count),$exact.Count,$suffix.Count)
    Write-AdblockConsole -Level INFO -Message ("上游来源：{0}；下载成功：{1}；下载失败：{2}" -f $sources.Count,$successfulSources.Count,$failedCount)
    Write-AdblockConsole -Level INFO -Message ("解析行数：{0}；有效规则：{1}；ALLOW：{2}；BLOCK：{3}" -f $stats.Parsed,$rules.Count,$allowCount,$blockCount)
    Write-AdblockConsole -Level INFO -Message ("跳过：{0}；无效域名：{1}；通配符：{2}；badfilter：{3}；Hosts 展开：{4}" -f $totalSkipped,$stats.Invalid,$stats.Wildcard,$stats.Badfilter,$stats.HostsExpanded)
    Write-AdblockConsole -Level INFO -Message ("PSL 规则：{0}；uBO Include：{1}；构建问题：{2}" -f $pslRuleCount,$includeManifest.Count,$compiled.Issues.Count)
    Write-AdblockConsole -Level INFO -Message ("来源快照 SHA-256：{0}" -f $snapshotHash)
    Write-AdblockConsole -Level INFO -Message ("构建报告：{0}" -f $reportPath)
    Write-AdblockConsole -Level INFO -Message ("来源清单：{0}" -f $manifestPath)
    Write-AdblockConsole -Level SUCCESS -Message ("总耗时：{0}" -f $buildTimer.Elapsed.ToString())
    Write-Host ''
    Write-AdblockConsole -Level INFO -Message '生成文件预览（前 10 行）：'
    Get-Content -LiteralPath $outputs[0].Path -TotalCount 10 | ForEach-Object { Write-Host ("  {0}" -f $_) }
    Write-Host ''
    return $report
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
        if ($mod -notin @('important','all','reason')) { return $true }
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

function Test-AdblockStrictParseIssue([string]$SkipReason) {
    # Explicitly understood non-DNS rules may be skipped and counted. Unknown
    # syntax must stop strict compilation rather than silently lose a rule.
    return ($SkipReason -in @('no-pattern-match','whitelist-unparseable','unresolvable-wildcard','syntax-mismatch'))
}

# ── 集中式规则解析函数 ───────────────────────────────────────
function Parse-Rule {
    param(
        [string]$line,
        [bool]$isWhitelistSource = $false,
        [ValidateSet('AUTO','ADBLOCK','HOSTS','DNSMASQ')][string]$SourceSyntax = 'AUTO'
    )

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

    # Respect source-level syntax declarations. AUTO retains safe auto-detection.
    $isHostsLine = $line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+'
    $isDnsmasqLine = $line -match '^(address|server|local)=/'
    if (
        ($SourceSyntax -eq 'HOSTS' -and -not $isHostsLine) -or
        ($SourceSyntax -eq 'DNSMASQ' -and -not $isDnsmasqLine) -or
        ($SourceSyntax -eq 'ADBLOCK' -and ($isHostsLine -or $isDnsmasqLine))
    ) {
        $result.SkipReason = "syntax-mismatch"
        return $result
    }

    # Adblock 白名单规则
    if ($line.StartsWith("@@")) {
        $extractDomain = $null
        $modPartRaw = $null

        if (
            $line -match '^@@\|\|([\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?(?:\.[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?)+)(.*)$'
        ) {
            $extractDomain = $Matches[1].ToLower()
            $afterDomain = $Matches[2]

            if ($afterDomain -match '^[\^]?[/?]') {
                $result.SkipReason = "whitelist-path-or-query-specific"
                return $result
            }
            $dollarIdx = $afterDomain.IndexOf('$')
            $beforeMods = if ($dollarIdx -ge 0) { $afterDomain.Substring(0, $dollarIdx) } else { $afterDomain }
            if ([string]::IsNullOrEmpty($beforeMods)) {
                $result.SkipReason = "unbounded-domain-anchor"
                return $result
            }
            if ($beforeMods -notmatch '^\^?\|?$') {
                $result.SkipReason = "whitelist-pattern-after-domain"
                return $result
            }

            if ($dollarIdx -ge 0) {
                $modPartRaw = $afterDomain.Substring($dollarIdx + 1)
            }
        }
        elseif ($line -match '^@@\|([\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}]{2,})(?:\^?\|)(?:\$(.*))?$') {
            $extractDomain = $Matches[1].ToLower()
            $modPartRaw = $Matches[2]
        }
        elseif ($line -match '^@@([\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}]{2,})$') {
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
    if ($line -match '^\|([\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}]{2,})(?:\^?\|)(\$(.+))?$') {
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

        if ([string]::IsNullOrEmpty($restBeforeDollar)) {
            $result.SkipReason = "unbounded-domain-anchor"
            return $result
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
    if ($line -match '^address=/([\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}]{2,})/([^/]*)$') {
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
    if ($line -match '^local=/([\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}]{2,})/$') {
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
    if ($line -match '^([\p{L}\p{N}][\p{L}\p{N}.-]*\.[\p{L}]{2,})$') {
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
if (-not $TestMode) {
    Invoke-AdblockGeneration -Format 'yaml' -SourceListPath (Join-Path $PSScriptRoot 'upstream-sources.json') -Strict:(-not $AllowLossy)
}
