[CmdletBinding()]
param(
    [ValidateSet("clash", "sing-box")]
    [string]$TargetFormat = "clash"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Split-Path -Parent $PSScriptRoot
switch ($TargetFormat) {
    "clash" {
        $generatorPath = Join-Path $repoRoot "adblock_rule_generator_yaml.ps1"
        $artifactName = "adblock_reject.yaml"
    }
    "sing-box" {
        $generatorPath = Join-Path $repoRoot "adblock_rule_generator_json.ps1"
        $artifactName = "adblock_reject.json"
    }
}

if (-not (Test-Path -LiteralPath $generatorPath)) {
    throw "找不到生产生成器：$generatorPath"
}

$resultsDirectory = Join-Path $PSScriptRoot "TestResults"
[System.IO.Directory]::CreateDirectory($resultsDirectory) | Out-Null
$reportPath = Join-Path $resultsDirectory "upstream-semantic-metrics.json"
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("upstream-semantic-audit-" + [guid]::NewGuid().ToString("N"))
[System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null

# 直接执行生产生成器，不复制或重写解析、优先级和投影算法。
# 仅将文件写入位置改到临时目录，并移除交互式 Pause。
$generatorSource = [System.IO.File]::ReadAllText($generatorPath)
$generatorSource = $generatorSource.Replace('$PSScriptRoot', $tempRoot.Replace("'", "''"))
$generatorSource = [regex]::Replace($generatorSource, '(?im)^\s*Pause\s*$', '')

$generatorSource += @'

$__upstreamAuditState = [PSCustomObject]@{
    UrlList = @($urlList)
    UrlContents = @($urlContents)
    ParsedRuleCount = $parsedRulesByKey.Count
    SkipStats = $skipStats
    ValidExactRules = $validExactRules
    ValidSuffixRules = $validSuffixRules
    ExcludedExactDomains = $excludedExactDomains
    ExcludedSuffixDomains = $excludedSuffixDomains
    ImportantExactDomains = $importantExactDomains
    ImportantSuffixDomains = $importantSuffixDomains
    ImportantWhitelistExactDomains = $importantWhitelistExactDomains
    ImportantWhitelistSuffixDomains = $importantWhitelistSuffixDomains
    SuffixConflictExactDomains = $suffixConflictExactDomains
    ClassExactBlocks = $classExactBlocks
    ClassSuffixBlocks = $classSuffixBlocks
}
'@

# dot-source 使生产生成器的真实中间集合可供后续审计读取。
. ([scriptblock]::Create($generatorSource))
$state = $__upstreamAuditState
if ($null -eq $state) {
    throw "生产生成器未导出审计状态，无法计算全量上游语义一致率"
}

$sha256 = [System.Security.Cryptography.SHA256]::Create()
$sourceDigestLines = [System.Collections.Generic.List[string]]::new()
$failedUrls = [System.Collections.Generic.List[string]]::new()
$sourceBytes = [int64]0
$sourceLineCount = [int64]0

foreach ($item in $state.UrlContents) {
    if ($null -eq $item.Content -or [string]::IsNullOrWhiteSpace([string]$item.Content)) {
        $failedUrls.Add([string]$item.Url)
        continue
    }

    $contentBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$item.Content)
    $sourceBytes += $contentBytes.Length
    $sourceLineCount += ([regex]::Matches([string]$item.Content, '\r?\n').Count + 1)
    $contentHash = [BitConverter]::ToString($sha256.ComputeHash($contentBytes)).Replace("-", "").ToLowerInvariant()
    $sourceDigestLines.Add(([string]$item.Url) + "|" + $contentHash)
}

$snapshotPayload = [System.Text.Encoding]::UTF8.GetBytes(($sourceDigestLines -join [Environment]::NewLine))
$snapshotHash = [BitConverter]::ToString($sha256.ComputeHash($snapshotPayload)).Replace("-", "").ToLowerInvariant()
$sha256.Dispose()

if ($failedUrls.Count -gt 0 -or $state.UrlContents.Count -ne $state.UrlList.Count) {
    $incompleteReport = [ordered]@{
        schemaVersion = "1.0.0"
        status = "incomplete"
        targetFormat = $TargetFormat
        sourceUrlCount = $state.UrlList.Count
        sourceResponseCount = $state.UrlContents.Count
        successfulSourceCount = $sourceDigestLines.Count
        failedSourceCount = $failedUrls.Count
        failedSourceUrls = @($failedUrls)
        sourceBytes = $sourceBytes
        sourceLineCount = $sourceLineCount
        partialSnapshotSha256 = $snapshotHash
        semanticAgreementPercent = $null
        note = "未能完整获取全部上游源，禁止将部分数据计算为全量语义一致率。"
    }
    $incompleteReport | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding utf8
    Write-Host "全量上游审计未完成：$($failedUrls.Count) 个源下载失败；不输出百分比。"
    throw "上游源抓取不完整，详情见 $reportPath"
}

function Get-AuditEffectiveRuleKind {
    param([Parameter(Mandatory)][string]$Domain)

    $labels = $Domain -split '\.'
    $current = $Domain

    # P0：重要白名单。
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length - 1)] -join '.')
        if ($i -eq 0 -and $state.ImportantWhitelistExactDomains.Contains($current)) { return "WHITELIST" }
        if ($state.ImportantWhitelistSuffixDomains.Contains($current)) { return "WHITELIST" }
    }

    # P1：重要黑名单。
    $current = $Domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length - 1)] -join '.')
        if ($i -eq 0 -and $state.ImportantExactDomains.Contains($current)) { return "EXACT" }
        if ($state.ImportantSuffixDomains.Contains($current)) { return "SUFFIX" }
    }

    # P2-P4：从当前域名向父域查找，最近的规则优先，同层例外优先。
    $current = $Domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length - 1)] -join '.')
        if ($i -eq 0 -and $state.ExcludedExactDomains.Contains($current)) { return "WHITELIST" }
        if ($state.ExcludedSuffixDomains.Contains($current)) { return "WHITELIST" }
        if ($i -eq 0 -and $state.ValidExactRules.Contains($current)) { return "EXACT" }
        if ($state.ValidSuffixRules.Contains($current)) { return "SUFFIX" }
    }

    return "UNKNOWN"
}

$artifactPath = Join-Path $repoRoot $artifactName
if (-not (Test-Path -LiteralPath $artifactPath)) {
    throw "找不到仓库中待审计的正式产物：$artifactPath"
}

$artifactFileSha256 = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
$artifactHeaderGeneratedAt = $null
$artifactExactDomains = [System.Collections.Generic.List[string]]::new()
$artifactSuffixDomains = [System.Collections.Generic.List[string]]::new()

if ($TargetFormat -eq "clash") {
    foreach ($line in (Get-Content -LiteralPath $artifactPath -Encoding utf8)) {
        if ($line -match '^# 生成时间：(.*)$') {
            $artifactHeaderGeneratedAt = $Matches[1].Trim()
        }
        elseif ($line -match '^\s*-\s+DOMAIN,([^,\s]+)\s*$') {
            $artifactExactDomains.Add($Matches[1])
        }
        elseif ($line -match '^\s*-\s+DOMAIN-SUFFIX,([^,\s]+)\s*$') {
            $artifactSuffixDomains.Add($Matches[1])
        }
    }
}
else {
    $json = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    if ([int]$json.version -ne 1 -or @($json.rules).Count -ne 1) {
        throw "sing-box 产物结构不符合预期"
    }
    foreach ($domain in @($json.rules[0].domain)) {
        $artifactExactDomains.Add([string]$domain)
    }
    foreach ($domain in @($json.rules[0].domain_suffix)) {
        $artifactSuffixDomains.Add([string]$domain)
    }
}

$exactSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$suffixSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($domain in $artifactExactDomains) { $exactSet.Add($domain) | Out-Null }
foreach ($domain in $artifactSuffixDomains) { $suffixSet.Add($domain) | Out-Null }

if (
    $exactSet.Count -ne $artifactExactDomains.Count -or
    $suffixSet.Count -ne $artifactSuffixDomains.Count
) {
    throw "仓库产物包含重复的精确域名或后缀域名条目"
}

$consistentEntries = 0
$mismatchedEntries = [System.Collections.Generic.List[object]]::new()
$mismatchCounts = [ordered]@{
    exactOutputButEffectiveSuffixSource = 0
    exactOutputWithoutEffectiveExactSource = 0
    suffixOutputWithoutSourceSuffix = 0
    suffixOutputWithEffectiveWhitelistException = 0
    suffixOutputNotEffectivelyBlocked = 0
}

# DOMAIN 项只有在上游有效规则类型也是 EXACT 时才计为一致。
# 如果上游有效规则是 SUFFIX，说明产物将其匹配范围收窄为单一主机名。
foreach ($domain in $artifactExactDomains) {
    $kind = Get-AuditEffectiveRuleKind -Domain $domain
    if ($kind -eq "EXACT") {
        $consistentEntries++
    }
    else {
        if ($kind -eq "SUFFIX") {
            $mismatchCounts.exactOutputButEffectiveSuffixSource++
            $reason = "上游有效规则为后缀匹配，产物却收窄为精确域名"
        }
        else {
            $mismatchCounts.exactOutputWithoutEffectiveExactSource++
            $reason = "该产物精确域名没有对应的有效上游精确规则"
        }
        $mismatchedEntries.Add([PSCustomObject]@{
            type = "DOMAIN"
            domain = $domain
            effectiveUpstreamRuleKind = $kind
            reason = $reason
        })
    }
}

# DOMAIN-SUFFIX 项必须有对应上游后缀规则，且其范围内不存在有效白名单例外。
foreach ($domain in $artifactSuffixDomains) {
    $hasSourceSuffix = $state.ValidSuffixRules.Contains($domain)
    $hasEffectiveWhitelistException = $state.SuffixConflictExactDomains.Contains($domain)
    $isEffectivelyBlocked = (Get-EffectiveStatus $domain) -like "BLACKLIST*"

    if ($hasSourceSuffix -and -not $hasEffectiveWhitelistException -and $isEffectivelyBlocked) {
        $consistentEntries++
    }
    else {
        if (-not $hasSourceSuffix) {
            $mismatchCounts.suffixOutputWithoutSourceSuffix++
            $reason = "产物后缀规则没有对应的上游后缀规则"
        }
        elseif ($hasEffectiveWhitelistException) {
            $mismatchCounts.suffixOutputWithEffectiveWhitelistException++
            $reason = "产物后缀范围覆盖了上游有效白名单例外"
        }
        else {
            $mismatchCounts.suffixOutputNotEffectivelyBlocked++
            $reason = "该产物后缀在上游有效规则中并非黑名单"
        }
        $mismatchedEntries.Add([PSCustomObject]@{
            type = "DOMAIN-SUFFIX"
            domain = $domain
            effectiveUpstreamRuleKind = (Get-AuditEffectiveRuleKind -Domain $domain)
            reason = $reason
        })
    }
}

$totalEntries = $artifactExactDomains.Count + $artifactSuffixDomains.Count
if ($totalEntries -le 0) {
    throw "产物没有可审计的域名条目"
}
$agreementPercent = [math]::Round(($consistentEntries / [double]$totalEntries) * 100, 6)
$skippedRuleCount = 0
if ($state.SkipStats.Count -gt 0) {
    $skippedRuleCount = [int](($state.SkipStats.Values | Measure-Object -Sum).Sum)
}

$metrics = [ordered]@{
    schemaVersion = "1.0.0"
    status = "complete"
    generatedAtUtc = [DateTime]::UtcNow.ToString("o")
    targetFormat = $TargetFormat
    artifactSource = "checked-in repository artifact"
    artifactFileSha256 = $artifactFileSha256
    artifactHeaderGeneratedAt = $artifactHeaderGeneratedAt
    upstreamSourceUrlCount = $state.UrlList.Count
    successfullyDownloadedSourceCount = $sourceDigestLines.Count
    failedSourceCount = 0
    sourceBytes = $sourceBytes
    sourceLineCount = $sourceLineCount
    sourceSnapshotSha256 = $snapshotHash
    uniqueParsedRuleIdentityCount = $state.ParsedRuleCount
    skippedRuleCount = $skippedRuleCount
    artifactExactEntryCount = $artifactExactDomains.Count
    artifactSuffixEntryCount = $artifactSuffixDomains.Count
    artifactEntryTotal = $totalEntries
    semanticallyConsistentEntryCount = $consistentEntries
    semanticMismatchEntryCount = $mismatchedEntries.Count
    semanticAgreementPercent = $agreementPercent
    semanticMismatchBreakdown = $mismatchCounts
    semanticMismatches = @($mismatchedEntries)
    formula = "semanticallyConsistentEntryCount / artifactEntryTotal * 100"
    methodology = "DOMAIN counts only when the effective upstream rule at that domain is EXACT. DOMAIN-SUFFIX counts only when a corresponding upstream suffix rule exists, the domain is effectively blocked, and no effective whitelist exception is projected below it. A suffix-to-exact projection is a semantic mismatch unless the effective upstream rule is itself exact."
}

$metrics | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding utf8

Write-Host ""
Write-Host "===== 完整上游语义一致率 ====="
Write-Host "上游源：$($sourceDigestLines.Count)/$($state.UrlList.Count) 成功"
Write-Host "产物条目：$totalEntries（DOMAIN $($artifactExactDomains.Count)，DOMAIN-SUFFIX $($artifactSuffixDomains.Count)）"
Write-Host "语义一致：$consistentEntries"
Write-Host "语义不一致：$($mismatchedEntries.Count)"
Write-Host "语义一致率：$agreementPercent%"
Write-Host "上游快照 SHA-256：$snapshotHash"
Write-Host "机器可读报告：$reportPath"

if ($mismatchedEntries.Count -gt 0) {
    Write-Host "不一致分类：$(($mismatchCounts | ConvertTo-Json -Compress))"
}
if ($agreementPercent -lt 100) {
    Write-Warning "存在产物条目的匹配范围与完整上游有效规则不一致，请检查 JSON 报告中的 semanticMismatches。"
}
) {
            $artifactHeaderGeneratedAt = $Matches[1].Trim()
        }
        elseif ($line -match '^\s*-\s+DOMAIN,([^,\s]+)\s*
            $artifactExactDomains.Add($Matches[1])
        }
        elseif ($line -match '^\s*-\s+DOMAIN-SUFFIX,([^,\s]+)\s*$') {
            $artifactSuffixDomains.Add($Matches[1])
        }
    }
}
else {
    $json = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    if ([int]$json.version -ne 1 -or @($json.rules).Count -ne 1) {
        throw "sing-box 产物结构不符合预期"
    }
    foreach ($domain in @($json.rules[0].domain)) {
        $artifactExactDomains.Add([string]$domain)
    }
    foreach ($domain in @($json.rules[0].domain_suffix)) {
        $artifactSuffixDomains.Add([string]$domain)
    }
}

$exactSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$suffixSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($domain in $artifactExactDomains) { $exactSet.Add($domain) | Out-Null }
foreach ($domain in $artifactSuffixDomains) { $suffixSet.Add($domain) | Out-Null }

if (
    $exactSet.Count -ne $artifactExactDomains.Count -or
    $suffixSet.Count -ne $artifactSuffixDomains.Count
) {
    throw "仓库产物包含重复的精确域名或后缀域名条目"
}

$consistentEntries = 0
$mismatchedEntries = [System.Collections.Generic.List[object]]::new()
$mismatchCounts = [ordered]@{
    exactOutputButEffectiveSuffixSource = 0
    exactOutputWithoutEffectiveExactSource = 0
    suffixOutputWithoutSourceSuffix = 0
    suffixOutputWithEffectiveWhitelistException = 0
    suffixOutputNotEffectivelyBlocked = 0
}

# DOMAIN 项只有在上游有效规则类型也是 EXACT 时才计为一致。
# 如果上游有效规则是 SUFFIX，说明产物将其匹配范围收窄为单一主机名。
foreach ($domain in $artifactExactDomains) {
    $kind = Get-AuditEffectiveRuleKind -Domain $domain
    if ($kind -eq "EXACT") {
        $consistentEntries++
    }
    else {
        if ($kind -eq "SUFFIX") {
            $mismatchCounts.exactOutputButEffectiveSuffixSource++
            $reason = "上游有效规则为后缀匹配，产物却收窄为精确域名"
        }
        else {
            $mismatchCounts.exactOutputWithoutEffectiveExactSource++
            $reason = "该产物精确域名没有对应的有效上游精确规则"
        }
        $mismatchedEntries.Add([PSCustomObject]@{
            type = "DOMAIN"
            domain = $domain
            effectiveUpstreamRuleKind = $kind
            reason = $reason
        })
    }
}

# DOMAIN-SUFFIX 项必须有对应上游后缀规则，且其范围内不存在有效白名单例外。
foreach ($domain in $artifactSuffixDomains) {
    $hasSourceSuffix = $state.ValidSuffixRules.Contains($domain)
    $hasEffectiveWhitelistException = $state.SuffixConflictExactDomains.Contains($domain)
    $isEffectivelyBlocked = (Get-EffectiveStatus $domain) -like "BLACKLIST*"

    if ($hasSourceSuffix -and -not $hasEffectiveWhitelistException -and $isEffectivelyBlocked) {
        $consistentEntries++
    }
    else {
        if (-not $hasSourceSuffix) {
            $mismatchCounts.suffixOutputWithoutSourceSuffix++
            $reason = "产物后缀规则没有对应的上游后缀规则"
        }
        elseif ($hasEffectiveWhitelistException) {
            $mismatchCounts.suffixOutputWithEffectiveWhitelistException++
            $reason = "产物后缀范围覆盖了上游有效白名单例外"
        }
        else {
            $mismatchCounts.suffixOutputNotEffectivelyBlocked++
            $reason = "该产物后缀在上游有效规则中并非黑名单"
        }
        $mismatchedEntries.Add([PSCustomObject]@{
            type = "DOMAIN-SUFFIX"
            domain = $domain
            effectiveUpstreamRuleKind = (Get-AuditEffectiveRuleKind -Domain $domain)
            reason = $reason
        })
    }
}

$totalEntries = $artifactExactDomains.Count + $artifactSuffixDomains.Count
if ($totalEntries -le 0) {
    throw "产物没有可审计的域名条目"
}
$agreementPercent = [math]::Round(($consistentEntries / [double]$totalEntries) * 100, 6)
$skippedRuleCount = 0
if ($state.SkipStats.Count -gt 0) {
    $skippedRuleCount = [int](($state.SkipStats.Values | Measure-Object -Sum).Sum)
}

$metrics = [ordered]@{
    schemaVersion = "1.0.0"
    status = "complete"
    generatedAtUtc = [DateTime]::UtcNow.ToString("o")
    targetFormat = $TargetFormat
    upstreamSourceUrlCount = $state.UrlList.Count
    successfullyDownloadedSourceCount = $sourceDigestLines.Count
    failedSourceCount = 0
    sourceBytes = $sourceBytes
    sourceLineCount = $sourceLineCount
    sourceSnapshotSha256 = $snapshotHash
    uniqueParsedRuleIdentityCount = $state.ParsedRuleCount
    skippedRuleCount = $skippedRuleCount
    artifactExactEntryCount = $artifactExactDomains.Count
    artifactSuffixEntryCount = $artifactSuffixDomains.Count
    artifactEntryTotal = $totalEntries
    semanticallyConsistentEntryCount = $consistentEntries
    semanticMismatchEntryCount = $mismatchedEntries.Count
    semanticAgreementPercent = $agreementPercent
    semanticMismatchBreakdown = $mismatchCounts
    semanticMismatches = @($mismatchedEntries)
    formula = "semanticallyConsistentEntryCount / artifactEntryTotal * 100"
    methodology = "DOMAIN counts only when the effective upstream rule at that domain is EXACT. DOMAIN-SUFFIX counts only when a corresponding upstream suffix rule exists, the domain is effectively blocked, and no effective whitelist exception is projected below it. A suffix-to-exact projection is a semantic mismatch unless the effective upstream rule is itself exact."
}

$metrics | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding utf8

Write-Host ""
Write-Host "===== 完整上游语义一致率 ====="
Write-Host "上游源：$($sourceDigestLines.Count)/$($state.UrlList.Count) 成功"
Write-Host "产物条目：$totalEntries（DOMAIN $($artifactExactDomains.Count)，DOMAIN-SUFFIX $($artifactSuffixDomains.Count)）"
Write-Host "语义一致：$consistentEntries"
Write-Host "语义不一致：$($mismatchedEntries.Count)"
Write-Host "语义一致率：$agreementPercent%"
Write-Host "上游快照 SHA-256：$snapshotHash"
Write-Host "机器可读报告：$reportPath"

if ($mismatchedEntries.Count -gt 0) {
    Write-Host "不一致分类：$(($mismatchCounts | ConvertTo-Json -Compress))"
}
if ($agreementPercent -lt 100) {
    Write-Warning "存在产物条目的匹配范围与完整上游有效规则不一致，请检查 JSON 报告中的 semanticMismatches。"
}
) {
            $artifactExactDomains.Add($Matches[1])
        }
        elseif ($line -match '^\s*-\s+DOMAIN-SUFFIX,([^,\s]+)\s*$') {
            $artifactSuffixDomains.Add($Matches[1])
        }
    }
}
else {
    $json = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    if ([int]$json.version -ne 1 -or @($json.rules).Count -ne 1) {
        throw "sing-box 产物结构不符合预期"
    }
    foreach ($domain in @($json.rules[0].domain)) {
        $artifactExactDomains.Add([string]$domain)
    }
    foreach ($domain in @($json.rules[0].domain_suffix)) {
        $artifactSuffixDomains.Add([string]$domain)
    }
}

$exactSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$suffixSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($domain in $artifactExactDomains) { $exactSet.Add($domain) | Out-Null }
foreach ($domain in $artifactSuffixDomains) { $suffixSet.Add($domain) | Out-Null }

if (
    $exactSet.Count -ne $artifactExactDomains.Count -or
    $suffixSet.Count -ne $artifactSuffixDomains.Count
) {
    throw "仓库产物包含重复的精确域名或后缀域名条目"
}

$consistentEntries = 0
$mismatchedEntries = [System.Collections.Generic.List[object]]::new()
$mismatchCounts = [ordered]@{
    exactOutputButEffectiveSuffixSource = 0
    exactOutputWithoutEffectiveExactSource = 0
    suffixOutputWithoutSourceSuffix = 0
    suffixOutputWithEffectiveWhitelistException = 0
    suffixOutputNotEffectivelyBlocked = 0
}

# DOMAIN 项只有在上游有效规则类型也是 EXACT 时才计为一致。
# 如果上游有效规则是 SUFFIX，说明产物将其匹配范围收窄为单一主机名。
foreach ($domain in $artifactExactDomains) {
    $kind = Get-AuditEffectiveRuleKind -Domain $domain
    if ($kind -eq "EXACT") {
        $consistentEntries++
    }
    else {
        if ($kind -eq "SUFFIX") {
            $mismatchCounts.exactOutputButEffectiveSuffixSource++
            $reason = "上游有效规则为后缀匹配，产物却收窄为精确域名"
        }
        else {
            $mismatchCounts.exactOutputWithoutEffectiveExactSource++
            $reason = "该产物精确域名没有对应的有效上游精确规则"
        }
        $mismatchedEntries.Add([PSCustomObject]@{
            type = "DOMAIN"
            domain = $domain
            effectiveUpstreamRuleKind = $kind
            reason = $reason
        })
    }
}

# DOMAIN-SUFFIX 项必须有对应上游后缀规则，且其范围内不存在有效白名单例外。
foreach ($domain in $artifactSuffixDomains) {
    $hasSourceSuffix = $state.ValidSuffixRules.Contains($domain)
    $hasEffectiveWhitelistException = $state.SuffixConflictExactDomains.Contains($domain)
    $isEffectivelyBlocked = (Get-EffectiveStatus $domain) -like "BLACKLIST*"

    if ($hasSourceSuffix -and -not $hasEffectiveWhitelistException -and $isEffectivelyBlocked) {
        $consistentEntries++
    }
    else {
        if (-not $hasSourceSuffix) {
            $mismatchCounts.suffixOutputWithoutSourceSuffix++
            $reason = "产物后缀规则没有对应的上游后缀规则"
        }
        elseif ($hasEffectiveWhitelistException) {
            $mismatchCounts.suffixOutputWithEffectiveWhitelistException++
            $reason = "产物后缀范围覆盖了上游有效白名单例外"
        }
        else {
            $mismatchCounts.suffixOutputNotEffectivelyBlocked++
            $reason = "该产物后缀在上游有效规则中并非黑名单"
        }
        $mismatchedEntries.Add([PSCustomObject]@{
            type = "DOMAIN-SUFFIX"
            domain = $domain
            effectiveUpstreamRuleKind = (Get-AuditEffectiveRuleKind -Domain $domain)
            reason = $reason
        })
    }
}

$totalEntries = $artifactExactDomains.Count + $artifactSuffixDomains.Count
if ($totalEntries -le 0) {
    throw "产物没有可审计的域名条目"
}
$agreementPercent = [math]::Round(($consistentEntries / [double]$totalEntries) * 100, 6)
$skippedRuleCount = 0
if ($state.SkipStats.Count -gt 0) {
    $skippedRuleCount = [int](($state.SkipStats.Values | Measure-Object -Sum).Sum)
}

$metrics = [ordered]@{
    schemaVersion = "1.0.0"
    status = "complete"
    generatedAtUtc = [DateTime]::UtcNow.ToString("o")
    targetFormat = $TargetFormat
    upstreamSourceUrlCount = $state.UrlList.Count
    successfullyDownloadedSourceCount = $sourceDigestLines.Count
    failedSourceCount = 0
    sourceBytes = $sourceBytes
    sourceLineCount = $sourceLineCount
    sourceSnapshotSha256 = $snapshotHash
    uniqueParsedRuleIdentityCount = $state.ParsedRuleCount
    skippedRuleCount = $skippedRuleCount
    artifactExactEntryCount = $artifactExactDomains.Count
    artifactSuffixEntryCount = $artifactSuffixDomains.Count
    artifactEntryTotal = $totalEntries
    semanticallyConsistentEntryCount = $consistentEntries
    semanticMismatchEntryCount = $mismatchedEntries.Count
    semanticAgreementPercent = $agreementPercent
    semanticMismatchBreakdown = $mismatchCounts
    semanticMismatches = @($mismatchedEntries)
    formula = "semanticallyConsistentEntryCount / artifactEntryTotal * 100"
    methodology = "DOMAIN counts only when the effective upstream rule at that domain is EXACT. DOMAIN-SUFFIX counts only when a corresponding upstream suffix rule exists, the domain is effectively blocked, and no effective whitelist exception is projected below it. A suffix-to-exact projection is a semantic mismatch unless the effective upstream rule is itself exact."
}

$metrics | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding utf8

Write-Host ""
Write-Host "===== 完整上游语义一致率 ====="
Write-Host "上游源：$($sourceDigestLines.Count)/$($state.UrlList.Count) 成功"
Write-Host "产物条目：$totalEntries（DOMAIN $($artifactExactDomains.Count)，DOMAIN-SUFFIX $($artifactSuffixDomains.Count)）"
Write-Host "语义一致：$consistentEntries"
Write-Host "语义不一致：$($mismatchedEntries.Count)"
Write-Host "语义一致率：$agreementPercent%"
Write-Host "上游快照 SHA-256：$snapshotHash"
Write-Host "机器可读报告：$reportPath"

if ($mismatchedEntries.Count -gt 0) {
    Write-Host "不一致分类：$(($mismatchCounts | ConvertTo-Json -Compress))"
}
if ($agreementPercent -lt 100) {
    Write-Warning "存在产物条目的匹配范围与完整上游有效规则不一致，请检查 JSON 报告中的 semanticMismatches。"
}
