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

# 运行原始生产生成器以取得完整上游解析与优先级状态。
# 输出目录重定向至临时目录；审计对象仍是仓库中检出的正式产物文件。
$generatorSource = [System.IO.File]::ReadAllText($generatorPath)
$generatorSource = $generatorSource.Replace('$PSScriptRoot', $tempRoot.Replace("'", "''"))
$generatorSource = [regex]::Replace($generatorSource, '(?im)^\s*Pause\s*$', '')

$stateExport = @'

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
}
'@

# 仅运行到生产生成器完成白名单冲突分析的位置；后续全量产物排序和写盘与本次语义审计无关。
$projectionMarker = '$rawSuffixSet = [System.Collections.Generic.HashSet[string]]::new'
$projectionIndex = $generatorSource.IndexOf($projectionMarker, [System.StringComparison]::Ordinal)
if ($projectionIndex -lt 0) {
    throw "无法定位生产生成器的规则投影边界；拒绝使用不完整的审计状态"
}
$generatorSource = $generatorSource.Substring(0, $projectionIndex) + $stateExport

. ([scriptblock]::Create($generatorSource))
$state = $__upstreamAuditState
if ($null -eq $state) {
    throw "生产生成器未导出完整上游解析状态，无法计算语义一致率"
}

# 对全部成功下载的源文件生成可复核的内容指纹。
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$sourceDigestLines = [System.Collections.Generic.List[string]]::new()
$failedUrls = [System.Collections.Generic.List[string]]::new()
$sourceBytes = [int64]0
$sourceLineCount = [int64]0

foreach ($item in $state.UrlContents) {
    if ($null -eq $item.Content) {
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
        note = "未能完整获取全部上游源，禁止将部分抓取数据计算为全量语义一致率。"
    }
    $incompleteReport | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding utf8
    Write-Host "全量上游审计未完成：$($failedUrls.Count) 个源下载失败；不输出百分比。"
    throw "上游源抓取不完整，详情见 $reportPath"
}

function Get-AuditEffectiveRuleKind {
    param([Parameter(Mandatory)][string]$Domain)

    $labels = $Domain -split '\.'
    $current = $Domain

    # P0：重要白名单优先。
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length - 1)] -join '.')
        if ($i -eq 0 -and $state.ImportantWhitelistExactDomains.Contains($current)) { return "WHITELIST" }
        if ($state.ImportantWhitelistSuffixDomains.Contains($current)) { return "WHITELIST" }
    }

    # P1：重要黑名单优先。
    $current = $Domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length - 1)] -join '.')
        if ($i -eq 0 -and $state.ImportantExactDomains.Contains($current)) { return "EXACT" }
        if ($state.ImportantSuffixDomains.Contains($current)) { return "SUFFIX" }
    }

    # P2-P4：距离当前域名最近的规则优先，同一层级先检查例外。
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
    if ($json.rules[0].domain -isnot [array] -or $json.rules[0].domain_suffix -isnot [array]) {
        throw "sing-box domain 与 domain_suffix 必须为 JSON 数组"
    }
    foreach ($domain in $json.rules[0].domain) {
        $artifactExactDomains.Add([string]$domain)
    }
    foreach ($domain in $json.rules[0].domain_suffix) {
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
    suffixOutputWithoutEffectiveSuffixSource = 0
    suffixOutputWithEffectiveWhitelistException = 0
}

# DOMAIN 保留精确匹配语义：上游在该域名上的有效规则必须为 EXACT。
foreach ($domain in $artifactExactDomains) {
    $kind = Get-AuditEffectiveRuleKind -Domain $domain
    if ($kind -eq "EXACT") {
        $consistentEntries++
        continue
    }

    if ($kind -eq "SUFFIX") {
        $mismatchCounts.exactOutputButEffectiveSuffixSource++
        $reason = "上游有效规则为后缀匹配，产物却收窄为精确域名"
    }
    else {
        $mismatchCounts.exactOutputWithoutEffectiveExactSource++
        $reason = "产物精确域名没有对应的有效上游精确规则"
    }

    $mismatchedEntries.Add([PSCustomObject]@{
        type = "DOMAIN"
        domain = $domain
        effectiveUpstreamRuleKind = $kind
        reason = $reason
    })
}

# DOMAIN-SUFFIX 保留后缀匹配语义：必须有有效上游后缀规则，且无例外冲突。
foreach ($domain in $artifactSuffixDomains) {
    $hasSourceSuffix = $state.ValidSuffixRules.Contains($domain)
    $hasEffectiveWhitelistException = $state.SuffixConflictExactDomains.Contains($domain)
    $isEffectivelyBlocked = (Get-EffectiveStatus $domain) -like "BLACKLIST*"

    if ($hasSourceSuffix -and -not $hasEffectiveWhitelistException -and $isEffectivelyBlocked) {
        $consistentEntries++
        continue
    }

    if ($hasSourceSuffix -and $hasEffectiveWhitelistException) {
        $mismatchCounts.suffixOutputWithEffectiveWhitelistException++
        $reason = "产物后缀范围覆盖了上游有效白名单例外"
    }
    else {
        $mismatchCounts.suffixOutputWithoutEffectiveSuffixSource++
        $reason = "产物后缀规则没有对应的有效上游后缀规则"
    }

    $mismatchedEntries.Add([PSCustomObject]@{
        type = "DOMAIN-SUFFIX"
        domain = $domain
        effectiveUpstreamRuleKind = $kind
        reason = $reason
    })
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
    methodology = "Each checked-in DOMAIN entry counts only when the effective upstream rule at that hostname is EXACT. Each checked-in DOMAIN-SUFFIX entry counts only when an upstream suffix rule exists, the root domain is effectively blocked, and no effective whitelist exception is projected beneath that suffix. Unproven scope-equivalence remains in the denominator and is not counted in the numerator."
}

$metrics | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding utf8

Write-Host ""
Write-Host "===== 完整上游语义一致率 ====="
Write-Host "上游源：$($sourceDigestLines.Count)/$($state.UrlList.Count) 成功"
Write-Host "产物条目：$totalEntries（DOMAIN $($artifactExactDomains.Count)，DOMAIN-SUFFIX $($artifactSuffixDomains.Count)）"
Write-Host "语义一致：$consistentEntries"
Write-Host "语义不一致：$($mismatchedEntries.Count)"
Write-Host "语义一致率：$agreementPercent%"
Write-Host "产物 SHA-256：$artifactFileSha256"
Write-Host "上游快照 SHA-256：$snapshotHash"
Write-Host "机器可读报告：$reportPath"

if ($mismatchedEntries.Count -gt 0) {
    Write-Host "不一致分类：$(($mismatchCounts | ConvertTo-Json -Compress))"
    Write-Host "不一致样本：$(($mismatchedEntries | Select-Object -First 20 | ConvertTo-Json -Compress))"
}
