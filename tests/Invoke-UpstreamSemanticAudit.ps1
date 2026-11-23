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
    DownloadErrors = @(if (Test-Path -LiteralPath $logFilePath) { Get-Content -LiteralPath $logFilePath | Where-Object { $_ -match '^下载 .* 时出错:' } })
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
$emptySourceUrls = [System.Collections.Generic.List[string]]::new()
$sourceBytes = [int64]0
$sourceLineCount = [int64]0

foreach ($item in $state.UrlContents) {
    if ($null -eq $item.Content) {
        $failedUrls.Add([string]$item.Url)
        continue
    }

    $contentBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$item.Content)
    if ($contentBytes.Length -eq 0) { $emptySourceUrls.Add([string]$item.Url) }
    $sourceBytes += $contentBytes.Length
    $sourceLineCount += ([regex]::Matches([string]$item.Content, '\r?\n').Count + 1)
    $contentHash = [BitConverter]::ToString($sha256.ComputeHash($contentBytes)).Replace("-", "").ToLowerInvariant()
    $sourceDigestLines.Add(([string]$item.Url) + "|" + $contentHash)
}

$snapshotPayload = [System.Text.Encoding]::UTF8.GetBytes(($sourceDigestLines -join [Environment]::NewLine))
$snapshotHash = [BitConverter]::ToString($sha256.ComputeHash($snapshotPayload)).Replace("-", "").ToLowerInvariant()
$sha256.Dispose()

$skippedRuleCount = [int64]0
$skipReasonCounts = [ordered]@{}
foreach ($reason in $state.SkipStats.Keys) {
    $reasonCount = [int64]$state.SkipStats[$reason]
    $skipReasonCounts[[string]$reason] = $reasonCount
    $skippedRuleCount += $reasonCount
}


if ($failedUrls.Count -gt 0 -or $state.UrlContents.Count -ne $state.UrlList.Count) {
    $incompleteReport = [ordered]@{
        schemaVersion = "2.0.0"
        status = "incomplete"
        evaluationMethod = "all-upstream-domain-rule-boundaries"
        targetFormat = $TargetFormat
        sourceUrlCount = $state.UrlList.Count
        sourceResponseCount = $state.UrlContents.Count
        successfulSourceCount = $sourceDigestLines.Count
        failedSourceCount = $failedUrls.Count
        failedSourceUrls = @($failedUrls)
        downloadErrors = @($state.DownloadErrors)
        emptySourceCount = $emptySourceUrls.Count
        emptySourceUrls = @($emptySourceUrls)
        sourceBytes = $sourceBytes
        sourceLineCount = $sourceLineCount
        partialSnapshotSha256 = $snapshotHash
        uniqueParsedRuleIdentityCount = $state.ParsedRuleCount
        skippedOrCancelledRuleCount = $skippedRuleCount
        skipReasonCounts = $skipReasonCounts
        confusionMatrix = $null
        metricsPercent = [ordered]@{
            semanticAgreement = $null
            precision = $null
            recall = $null
            f1 = $null
        }
        note = "至少一个上游源下载失败或返回空内容；禁止基于部分上游数据计算总体语义指标。"
    }
    $incompleteReport | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding utf8
    Write-Host "全量上游审计未完成：$($failedUrls.Count) 个源下载失败；不输出百分比。"
    throw "上游源抓取不完整，详情见 $reportPath"
}

function Add-AuditBoundaryAndParents {
    param(
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$Boundaries
    )

    $normalized = Normalize-Domain $Domain
    if (-not (Is-ValidDNSDomain $normalized)) {
        throw "上游或产物包含无法参与域名语义评估的域名：$Domain"
    }

    $Boundaries.Add($normalized) | Out-Null
    $labels = $normalized -split '\.'
    for ($i = 1; $i -lt $labels.Length - 1; $i++) {
        $parent = ($labels[$i..($labels.Length - 1)] -join '.')
        $Boundaries.Add($parent) | Out-Null
    }
}

function Test-AuditArtifactBlocksDomain {
    param([Parameter(Mandatory)][string]$Domain)

    if ($artifactExactSet.Contains($Domain)) { return $true }

    # Clash DOMAIN-SUFFIX 命中根域本身及其任意点分隔子域。
    $labels = $Domain -split '\.'
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $candidate = ($labels[$i..($labels.Length - 1)] -join '.')
        if ($artifactSuffixSet.Contains($candidate)) { return $true }
    }

    return $false
}

function Add-AuditProbeResult {
    param([Parameter(Mandatory)][string]$Domain)

    $upstreamStatus = Get-EffectiveStatus $Domain
    $expectedBlocked = $upstreamStatus -like "BLACKLIST*"
    $actualBlocked = Test-AuditArtifactBlocksDomain $Domain

    if ($expectedBlocked -and $actualBlocked) {
        $auditCounts.TP++
    }
    elseif ($expectedBlocked -and -not $actualBlocked) {
        $auditCounts.FN++
        if ($falseNegativeExamples.Count -lt $maxMismatchExamples) {
            $falseNegativeExamples.Add([PSCustomObject]@{
                domain = $Domain
                upstreamStatus = $upstreamStatus
                artifactBlocked = $false
                reason = "完整上游有效规则要求拦截，但正式产物未命中"
            })
        }
    }
    elseif (-not $expectedBlocked -and $actualBlocked) {
        $auditCounts.FP++
        if ($falsePositiveExamples.Count -lt $maxMismatchExamples) {
            $falsePositiveExamples.Add([PSCustomObject]@{
                domain = $Domain
                upstreamStatus = $upstreamStatus
                artifactBlocked = $true
                reason = "完整上游有效规则未要求拦截，但正式产物发生了拦截"
            })
        }
    }
    else {
        $auditCounts.TN++
    }
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
            $artifactExactDomains.Add((Normalize-Domain $Matches[1]))
        }
        elseif ($line -match '^\s*-\s+DOMAIN-SUFFIX,([^,\s]+)\s*$') {
            $artifactSuffixDomains.Add((Normalize-Domain $Matches[1]))
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
        $artifactExactDomains.Add((Normalize-Domain ([string]$domain)))
    }
    foreach ($domain in $json.rules[0].domain_suffix) {
        $artifactSuffixDomains.Add((Normalize-Domain ([string]$domain)))
    }
}

$artifactExactSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$artifactSuffixSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($domain in $artifactExactDomains) {
    if (-not (Is-ValidDNSDomain $domain)) { throw "产物包含无效 DOMAIN：$domain" }
    if (-not $artifactExactSet.Add($domain)) { throw "产物包含重复的 DOMAIN：$domain" }
}
foreach ($domain in $artifactSuffixDomains) {
    if (-not (Is-ValidDNSDomain $domain)) { throw "产物包含无效 DOMAIN-SUFFIX：$domain" }
    if (-not $artifactSuffixSet.Add($domain)) { throw "产物包含重复的 DOMAIN-SUFFIX：$domain" }
}
if ($artifactExactSet.Count + $artifactSuffixSet.Count -le 0) {
    throw "产物没有可审计的域名条目"
}

# 评估语料由所有成功抓取、经生产解析器解析、badfilter 撤销及优先级处理后的域名级规则构成。
$upstreamRuleDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($domain in $state.ValidExactRules) { $upstreamRuleDomains.Add((Normalize-Domain $domain)) | Out-Null }
foreach ($domain in $state.ValidSuffixRules) { $upstreamRuleDomains.Add((Normalize-Domain $domain)) | Out-Null }
foreach ($domain in $state.ExcludedExactDomains) { $upstreamRuleDomains.Add((Normalize-Domain $domain)) | Out-Null }
foreach ($domain in $state.ExcludedSuffixDomains) { $upstreamRuleDomains.Add((Normalize-Domain $domain)) | Out-Null }

if ($upstreamRuleDomains.Count -le 0) {
    throw "完整上游源没有产生可评估的有效域名级规则"
}

$evaluationBoundaries = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($domain in $upstreamRuleDomains) {
    Add-AuditBoundaryAndParents -Domain $domain -Boundaries $evaluationBoundaries
}
# 将产物独有条目及其父域也纳入，以识别没有上游依据的额外拦截。
foreach ($domain in $artifactExactDomains) {
    Add-AuditBoundaryAndParents -Domain $domain -Boundaries $evaluationBoundaries
}
foreach ($domain in $artifactSuffixDomains) {
    Add-AuditBoundaryAndParents -Domain $domain -Boundaries $evaluationBoundaries
}

# 所有显式域名及其父域均构成规则树边界；每个边界使用根域和一个未占用的代表子域。
$evaluationDomainList = [System.Collections.Generic.List[string]]::new()
foreach ($domain in $evaluationBoundaries) { $evaluationDomainList.Add($domain) }
$evaluationDomainList.Sort([System.StringComparer]::OrdinalIgnoreCase)

$auditCounts = [PSCustomObject]@{
    TP = [int64]0
    FP = [int64]0
    TN = [int64]0
    FN = [int64]0
}
$falsePositiveExamples = [System.Collections.Generic.List[object]]::new()
$falseNegativeExamples = [System.Collections.Generic.List[object]]::new()
$maxMismatchExamples = 100
$representativeSubdomainCount = [int64]0
$unrepresentableSubdomainBoundaryCount = [int64]0
$processedBoundaryCount = [int64]0

foreach ($domain in $evaluationDomainList) {
    Add-AuditProbeResult -Domain $domain

    # 域名最长为 253 字符；若无法再添加子域标签，只评估根域并明确计数。
    if ($domain.Length -le 251) {
        $probeLabel = "q"
        $probeDomain = "$probeLabel.$domain"
        $probeIndex = 0
        while ($evaluationBoundaries.Contains($probeDomain)) {
            $probeIndex++
            $probeLabel = "q$probeIndex"
            if ($probeLabel.Length -gt 63) {
                $probeDomain = $null
                break
            }
            $probeDomain = "$probeLabel.$domain"
            if ($probeDomain.Length -gt 253) {
                $probeDomain = $null
                break
            }
        }

        if ($null -ne $probeDomain) {
            Add-AuditProbeResult -Domain $probeDomain
            $representativeSubdomainCount++
        }
        else {
            $unrepresentableSubdomainBoundaryCount++
        }
    }
    else {
        $unrepresentableSubdomainBoundaryCount++
    }

    $processedBoundaryCount++
    if (($processedBoundaryCount % 50000) -eq 0) {
        Write-Host "已评估 $processedBoundaryCount / $($evaluationDomainList.Count) 个域名边界..."
    }
}

$evaluationPointCount = $auditCounts.TP + $auditCounts.FP + $auditCounts.TN + $auditCounts.FN
if ($evaluationPointCount -le 0) {
    throw "全量上游语义评估没有生成任何有效评估点"
}

$agreementPercent = [math]::Round(
    100.0 * ($auditCounts.TP + $auditCounts.TN) / $evaluationPointCount,
    6
)
$precisionPercent = if (($auditCounts.TP + $auditCounts.FP) -gt 0) {
    [math]::Round(100.0 * $auditCounts.TP / ($auditCounts.TP + $auditCounts.FP), 6)
} else { $null }
$recallPercent = if (($auditCounts.TP + $auditCounts.FN) -gt 0) {
    [math]::Round(100.0 * $auditCounts.TP / ($auditCounts.TP + $auditCounts.FN), 6)
} else { $null }
$f1Percent = if (
    $null -ne $precisionPercent -and
    $null -ne $recallPercent -and
    ($precisionPercent + $recallPercent) -gt 0
) {
    [math]::Round(
        2 * $precisionPercent * $recallPercent / ($precisionPercent + $recallPercent),
        6
    )
} else { $null }

$metrics = [ordered]@{
    schemaVersion = "2.0.0"
    status = "complete"
    generatedAtUtc = [DateTime]::UtcNow.ToString("o")
    targetFormat = $TargetFormat
    evaluationMethod = "all-upstream-domain-rule-boundaries"
    artifactSource = "checked-in repository artifact"
    artifactFileSha256 = $artifactFileSha256
    artifactHeaderGeneratedAt = $artifactHeaderGeneratedAt
    upstreamSourceUrlCount = $state.UrlList.Count
    successfullyDownloadedSourceCount = $sourceDigestLines.Count
    failedSourceCount = 0
    emptySourceCount = $emptySourceUrls.Count
    emptySourceUrls = @($emptySourceUrls)
    sourceBytes = $sourceBytes
    sourceLineCount = $sourceLineCount
    sourceSnapshotSha256 = $snapshotHash
    uniqueParsedRuleIdentityCount = $state.ParsedRuleCount
    activeExactBlacklistDomainCount = $state.ValidExactRules.Count
    activeSuffixBlacklistDomainCount = $state.ValidSuffixRules.Count
    activeExactWhitelistDomainCount = $state.ExcludedExactDomains.Count
    activeSuffixWhitelistDomainCount = $state.ExcludedSuffixDomains.Count
    uniqueUpstreamDomainRuleDomainCount = $upstreamRuleDomains.Count
    evaluationBoundaryDomainCount = $evaluationBoundaries.Count
    representativeSubdomainCount = $representativeSubdomainCount
    unrepresentableSubdomainBoundaryCount = $unrepresentableSubdomainBoundaryCount
    evaluationPointCount = $evaluationPointCount
    skippedOrCancelledRuleCount = $skippedRuleCount
    skipReasonCounts = $skipReasonCounts
    artifactExactEntryCount = $artifactExactDomains.Count
    artifactSuffixEntryCount = $artifactSuffixDomains.Count
    artifactEntryTotal = $artifactExactDomains.Count + $artifactSuffixDomains.Count
    confusionMatrix = [ordered]@{
        truePositive = $auditCounts.TP
        falsePositive = $auditCounts.FP
        trueNegative = $auditCounts.TN
        falseNegative = $auditCounts.FN
    }
    metricsPercent = [ordered]@{
        semanticAgreement = $agreementPercent
        precision = $precisionPercent
        recall = $recallPercent
        f1 = $f1Percent
    }
    falsePositiveCount = $auditCounts.FP
    falseNegativeCount = $auditCounts.FN
    falsePositiveExamples = @($falsePositiveExamples)
    falseNegativeExamples = @($falseNegativeExamples)
    mismatchExamplesLimit = $maxMismatchExamples
    methodology = "The evaluation corpus is derived from every active, successfully parsed upstream domain-level exact/suffix blacklist and whitelist domain, plus every domain in the checked-in artifact. Each rule domain and every ancestor boundary is evaluated at the boundary itself and at one collision-free representative child domain. The upstream expected decision comes from the generator's effective-priority resolver; the observed decision comes from the checked-in DOMAIN/DOMAIN-SUFFIX artifact. This represents every distinguishable region in the finite exact/suffix rule-boundary tree. Unsupported URL-, path-, resource-, regex-, wildcard- and context-specific rules are not coerced into domain semantics; they are counted separately as skipped. A successfully fetched zero-byte upstream file is valid and recorded as an empty source, not as a download failure; a null content value is reserved for a failed request."
    scopeNote = "Precision, recall, F1 and semantic agreement are weighted over deterministic rule-boundary representative points, not Internet traffic, unique registrable domains, or every possible DNS name. The 34 fixed probes are not used to estimate these metrics."
}

$metrics | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $reportPath -Encoding utf8

$precisionText = if ($null -eq $precisionPercent) { "N/A" } else { "$precisionPercent%" }
$recallText = if ($null -eq $recallPercent) { "N/A" } else { "$recallPercent%" }
$f1Text = if ($null -eq $f1Percent) { "N/A" } else { "$f1Percent%" }
$summary = @(
    "## 全量上游规则语义评估（$TargetFormat）",
    "",
    "| 指标 | 结果 |",
    "|---|---:|",
    "| 上游源成功数 | $($sourceDigestLines.Count) / $($state.UrlList.Count) |",
    "| 成功但为空的源 | $($emptySourceUrls.Count) |",
    "| 唯一上游域名规则域名 | $($upstreamRuleDomains.Count) |",
    "| 语义边界域名节点 | $($evaluationBoundaries.Count) |",
    "| 评估点（根域 + 代表子域） | $evaluationPointCount |",
    "| TP / FP / TN / FN | $($auditCounts.TP) / $($auditCounts.FP) / $($auditCounts.TN) / $($auditCounts.FN) |",
    "| 语义一致率 | $agreementPercent% |",
    "| Precision | $precisionText |",
    "| Recall | $recallText |",
    "| F1 | $f1Text |",
    "| 跳过或撤销的上游规则数 | $skippedRuleCount |",
    "",
    "评估语料由全部有效上游域名规则及其规则边界构造；固定 34 个探针不参与总体指标计算。",
    "上游快照 SHA-256：$snapshotHash",
    "机器可读报告：$reportPath"
) -join [Environment]::NewLine

if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_STEP_SUMMARY)) {
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summary -Encoding utf8
}
Write-Host ""
Write-Host $summary
Write-Host "误拦截样本（最多 $maxMismatchExamples 条）：$(($falsePositiveExamples | ConvertTo-Json -Compress -Depth 5))"
Write-Host "漏拦截样本（最多 $maxMismatchExamples 条）：$(($falseNegativeExamples | ConvertTo-Json -Compress -Depth 5))"
