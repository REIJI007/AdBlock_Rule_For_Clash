[CmdletBinding()]
param(
    [ValidateSet("clash", "sing-box")]
    [string]$TargetFormat = "clash"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$script:assertionCount = 0

function Assert-Equal {
    param([object]$Expected, [object]$Actual, [string]$Context)
    $script:assertionCount++
    if (-not [object]::Equals($Expected, $Actual)) {
        throw "断言失败：$Context；预期=[$Expected]，实际=[$Actual]"
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Context)
    $script:assertionCount++
    if (-not $Condition) { throw "断言失败：$Context" }
}


$repoRoot = Split-Path -Parent $PSScriptRoot
$fixturePath = Join-Path $PSScriptRoot "fixtures/semantic-cases.json"
if (-not (Test-Path -LiteralPath $fixturePath)) { throw "找不到语义回归样本：$fixturePath" }
$fixture = Get-Content -LiteralPath $fixturePath -Raw -Encoding utf8 | ConvertFrom-Json

switch ($TargetFormat) {
    "clash" {
        $generatorPath = Join-Path $repoRoot "adblock_rule_generator_yaml.ps1"
        $outputMarker = "# ── 输出 YAML 规则集"
        $outputFileName = "adblock_reject.yaml"
        $oldOutputAssignment = '$outputPath = "$PSScriptRoot/adblock_reject.yaml"'
        $projectName = "AdBlock_Rule_For_Clash"
    }
    "sing-box" {
        $generatorPath = Join-Path $repoRoot "adblock_rule_generator_json.ps1"
        $outputMarker = "# ── 输出 sing-box JSON 规则集"
        $outputFileName = "adblock_reject.json"
        $oldOutputAssignment = '$outputPath = "$PSScriptRoot/adblock_reject.json"'
        $projectName = "AdBlock_Rule_For_Sing-box"
    }
}
if (-not (Test-Path -LiteralPath $generatorPath)) { throw "找不到被测规则生成脚本：$generatorPath" }

# 通过 PowerShell AST 仅载入生产脚本中的真实函数定义，不执行下载、写文件或暂停。
$tokens = $null
$parseErrors = $null
$generatorAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $generatorPath, [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    $details = ($parseErrors | ForEach-Object { $_.Message }) -join [Environment]::NewLine
    throw ("生产脚本存在 PowerShell 语法错误：" + [Environment]::NewLine + $details)
}

$requiredFunctions = @(
    "Get-RuleIdentity",
    "Resolve-Modifiers",
    "Is-ContextConstrainedWhitelist",
    "Get-WhitelistImportantFlag",
    "Is-WhitelistSource",
    "Normalize-Domain",
    "Is-ValidDNSDomain",
    "Get-ParentDomains",
    "Parse-Rule",
    "Get-EffectiveStatus"
)
$allFunctionAsts = @(
    $generatorAst.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] },
        $true
    )
)
$selectedFunctionAsts = @($allFunctionAsts | Where-Object { $requiredFunctions -contains $_.Name })
foreach ($functionName in $requiredFunctions) {
    $functionMatches = @($selectedFunctionAsts | Where-Object { $_.Name -eq $functionName })
    Assert-Equal 1 $functionMatches.Count "生产函数 $functionName 必须且只能定义一次"
}
$functionDefinitions = ($selectedFunctionAsts | Sort-Object { $_.Extent.StartOffset } | ForEach-Object { $_.Extent.Text }) -join ([Environment]::NewLine + [Environment]::NewLine)
. ([scriptblock]::Create($functionDefinitions))
$script:_parentCache = [System.Collections.Generic.Dictionary[string, string[]]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

# 第一遍：解析固定样本并收集 badfilter 规则身份。
$badfilterCancelKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$parsedRulesByKey = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
$skipCaseCount = 0
$badfilterCaseCount = 0

foreach ($rule in $fixture.rules) {
    $sourceUrl = if ($rule.source -eq "allowlist") {
        "https://fixtures.invalid/allowlist.txt"
    } else {
        "https://fixtures.invalid/filter-list.txt"
    }
    $isWhitelistSource = Is-WhitelistSource $sourceUrl
    $parsed = Parse-Rule $rule.line -isWhitelistSource $isWhitelistSource

    Assert-Equal $rule.expectedAction $parsed.Action "规则 [$($rule.id)] 的解析动作"
    if ($rule.PSObject.Properties.Name -contains "expectedDomain") {
        Assert-Equal $rule.expectedDomain $parsed.Domain "规则 [$($rule.id)] 的域名"
    }
    if ($rule.PSObject.Properties.Name -contains "expectedSourceFormat") {
        Assert-Equal $rule.expectedSourceFormat $parsed.SourceFormat "规则 [$($rule.id)] 的来源格式"
    }
    if ($rule.PSObject.Properties.Name -contains "expectedImportant") {
        Assert-Equal ([bool]$rule.expectedImportant) ([bool]$parsed.IsImportant) "规则 [$($rule.id)] 的 important 标记"
    }

    switch ($parsed.Action) {
        "BADFILTER" {
            $badfilterCaseCount++
            Assert-True (-not [string]::IsNullOrWhiteSpace($parsed.RuleKey)) "规则 [$($rule.id)] 必须生成可撤销的规则身份"
            $badfilterCancelKeys.Add($parsed.RuleKey) | Out-Null
        }
        "SKIP" { $skipCaseCount++ }
        default {
            if ($parsed.Action -in @("EXCLUDE", "SUFFIX", "EXACT")) {
                Assert-True (-not [string]::IsNullOrWhiteSpace($parsed.RuleKey)) "规则 [$($rule.id)] 必须生成唯一规则身份"
                $storeKey = "$($parsed.Action)|$($parsed.RuleKey)"
                if (-not $parsedRulesByKey.ContainsKey($storeKey)) { $parsedRulesByKey[$storeKey] = $parsed }
            }
            else { throw "规则 [$($rule.id)] 返回未预期动作：$($parsed.Action)" }
        }
    }
}

# Hosts 一行多主机名：按生产主脚本中的展开规则逐一送入真实解析函数。
$hostsParsedCount = 0
foreach ($hostsLine in $fixture.hostsLines) {
    $normalizedLine = $hostsLine.Trim().Trim([char]0xFEFF)
    $hostsMatch = [regex]::Match($normalizedLine, '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+(.+)$')
    Assert-True $hostsMatch.Success "Hosts 样本必须识别为有效条目"
    $hostPart = ($hostsMatch.Groups[2].Value -split '\s+#', 2)[0]

    foreach ($hostName in ($hostPart -split '\s+')) {
        if ($hostName -match '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
            $candidateLine = "$($hostsMatch.Groups[1].Value) $hostName"
            $parsed = Parse-Rule $candidateLine -isWhitelistSource $false
            Assert-Equal "EXACT" $parsed.Action "Hosts 主机名 [$hostName] 必须解析为精确域名"
            Assert-Equal $hostName $parsed.Domain "Hosts 主机名 [$hostName] 不得丢失"
            $storeKey = "$($parsed.Action)|$($parsed.RuleKey)"
            $parsedRulesByKey[$storeKey] = $parsed
            $hostsParsedCount++
        }
    }
}
Assert-Equal 2 $hostsParsedCount "Hosts 单行中的两个主机名都必须被展开"

# 第二遍：应用规则身份级 badfilter，并构建精确/后缀黑白名单集合。
$uniqueSuffixRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$uniqueExactRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$excludedExactDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$excludedSuffixDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$importantExactDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$importantSuffixDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$importantWhitelistExactDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$importantWhitelistSuffixDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$cancelledRuleCount = 0

foreach ($parsed in $parsedRulesByKey.Values) {
    if ($parsed.IsFilterRule -and $parsed.RuleKey -and $badfilterCancelKeys.Contains($parsed.RuleKey)) {
        $cancelledRuleCount++
        continue
    }

    $domain = Normalize-Domain $parsed.Domain
    if (-not (Is-ValidDNSDomain $domain)) { throw "解析器输出了非法域名：$($parsed.Domain)" }
    if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') { throw "解析器将 IP 地址误交给域名集合：$domain" }

    switch ($parsed.Action) {
        "EXCLUDE" {
            $isSuffixException = $parsed.SourceFormat -in @("whitelist-suffix", "whitelist-dnsmasq")
            if ($isSuffixException) {
                $excludedSuffixDomains.Add($domain) | Out-Null
                if ($parsed.IsImportant) { $importantWhitelistSuffixDomains.Add($domain) | Out-Null }
            } else {
                $excludedExactDomains.Add($domain) | Out-Null
                if ($parsed.IsImportant) { $importantWhitelistExactDomains.Add($domain) | Out-Null }
            }
        }
        "SUFFIX" {
            $uniqueSuffixRules.Add($domain) | Out-Null
            if ($parsed.IsImportant) { $importantSuffixDomains.Add($domain) | Out-Null }
        }
        "EXACT" {
            $uniqueExactRules.Add($domain) | Out-Null
            if ($parsed.IsImportant) { $importantExactDomains.Add($domain) | Out-Null }
        }
    }
}

Assert-Equal 1 $cancelledRuleCount "badfilter 只能撤销匹配的 important 规则，不得撤销同域普通规则"
Assert-True ($uniqueSuffixRules.Contains("badfilter.example.test")) "同域普通后缀黑名单必须保留"
Assert-True (-not $importantSuffixDomains.Contains("badfilter.example.test")) "被撤销的重要后缀黑名单不得保留"

$validSuffixRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$validExactRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($domain in $uniqueSuffixRules) {
    if (Is-ValidDNSDomain $domain) { $validSuffixRules.Add($domain) | Out-Null }
}
foreach ($domain in $uniqueExactRules) {
    if (Is-ValidDNSDomain $domain) { $validExactRules.Add($domain) | Out-Null }
}

# 锁定生产优先级解析器的继承边界，防止字符串扫描优化改变语义。
$effectiveStatusCases = @(
    [PSCustomObject]@{ Domain = "ads.example.test"; Expected = "BLACKLIST_P4" },
    [PSCustomObject]@{ Domain = "safe.ads.example.test"; Expected = "WHITELIST_P2" },
    [PSCustomObject]@{ Domain = "blocked.safe.ads.example.test"; Expected = "BLACKLIST_P4" },
    [PSCustomObject]@{ Domain = "tracker.example.test"; Expected = "BLACKLIST_P3" },
    [PSCustomObject]@{ Domain = "sub.tracker.example.test"; Expected = "UNKNOWN" },
    [PSCustomObject]@{ Domain = "priority.example.test"; Expected = "BLACKLIST_P1" },
    [PSCustomObject]@{ Domain = "important-exception.priority.example.test"; Expected = "WHITELIST_P0" },
    [PSCustomObject]@{ Domain = "exact-safe.important-parent.example.test"; Expected = "WHITELIST_P0" },
    [PSCustomObject]@{ Domain = "child.exact-safe.important-parent.example.test"; Expected = "BLACKLIST_P1" },
    [PSCustomObject]@{ Domain = "badfilter.example.test"; Expected = "BLACKLIST_P4" }
)
foreach ($statusCase in $effectiveStatusCases) {
    Assert-Equal $statusCase.Expected (Get-EffectiveStatus $statusCase.Domain) "域名 [$($statusCase.Domain)] 的有效优先级"
}

$parentDomainCases = @(
    [PSCustomObject]@{ Domain = "a.b.c"; Expected = "b.c" },
    [PSCustomObject]@{ Domain = "a.b.c.d"; Expected = "b.c.d,c.d" },
    [PSCustomObject]@{ Domain = "a.b"; Expected = "" }
)
foreach ($parentCase in $parentDomainCases) {
    Assert-Equal $parentCase.Expected ((Get-ParentDomains $parentCase.Domain) -join ",") "域名 [$($parentCase.Domain)] 的父域提取"
}

# 执行生产脚本中的真实方案 A 投影代码，而非在测试中另写替代实现。
$generatorSource = [System.IO.File]::ReadAllText($generatorPath)
$projectionStartMatch = [regex]::Match($generatorSource, '(?m)^\$suffixConflictExactDomains\s*=')
if (-not $projectionStartMatch.Success) { throw "无法从生产脚本定位方案 A 投影代码" }
$projectionEnd = $generatorSource.IndexOf($outputMarker, $projectionStartMatch.Index, [System.StringComparison]::Ordinal)
if ($projectionEnd -lt 0) { throw "无法定位生产脚本的输出区段边界" }
$projectionCode = $generatorSource.Substring($projectionStartMatch.Index, $projectionEnd - $projectionStartMatch.Index)
. ([scriptblock]::Create($projectionCode))

# 执行生产脚本自己的文件输出代码，并将产物写入临时路径。
$consoleMarker = "# ── 控制台诊断输出"
$outputStart = $generatorSource.IndexOf($outputMarker, [System.StringComparison]::Ordinal)
$outputEnd = $generatorSource.IndexOf($consoleMarker, $outputStart, [System.StringComparison]::Ordinal)
if ($outputStart -lt 0 -or $outputEnd -lt 0) { throw "无法定位生产脚本的实际文件输出区段" }
$outputCode = $generatorSource.Substring($outputStart, $outputEnd - $outputStart)

$tempExtension = if ($TargetFormat -eq "clash") { ".yaml" } else { ".json" }
$tempOutputPath = Join-Path ([System.IO.Path]::GetTempPath()) (
    "semantic-regression-" + [guid]::NewGuid().ToString("N") + $tempExtension
)
$newOutputAssignment = '$outputPath = "' + $tempOutputPath + '"'
Assert-True ($outputCode.Contains($oldOutputAssignment)) "生产输出区段必须包含且能重定向输出路径"
$outputCode = $outputCode.Replace($oldOutputAssignment, $newOutputAssignment)

try {
    . ([scriptblock]::Create($outputCode))
    Assert-True (Test-Path -LiteralPath $tempOutputPath) "生产输出代码必须生成产物"

    $artifactExactDomains = @()
    $artifactSuffixDomains = @()

    if ($TargetFormat -eq "clash") {
        $artifactText = Get-Content -LiteralPath $tempOutputPath -Raw -Encoding utf8
        foreach ($line in ($artifactText -split "\r?\n")) {
            if ($line -match '^\s*-\s+DOMAIN,([^,\s]+)\s*$') {
                $artifactExactDomains += $Matches[1]
            }
            elseif ($line -match '^\s*-\s+DOMAIN-SUFFIX,([^,\s]+)\s*$') {
                $artifactSuffixDomains += $Matches[1]
            }
            elseif ($line -match '^\s*-\s+') {
                throw "Clash 产物包含不允许的规则类型：$line"
            }
        }
    }
    else {
        $json = Get-Content -LiteralPath $tempOutputPath -Raw -Encoding utf8 | ConvertFrom-Json
        Assert-Equal 1 ([int]$json.version) "sing-box JSON 规则集版本必须为 1"
        $jsonRuleCount = @($json.rules).Count
        Assert-Equal 1 $jsonRuleCount "sing-box JSON 必须输出一个默认规则对象"
        $ruleObject = @($json.rules)[0]
        Assert-True ($ruleObject.domain -is [array]) "sing-box domain 字段必须始终为 JSON 数组"
        Assert-True ($ruleObject.domain_suffix -is [array]) "sing-box domain_suffix 字段必须始终为 JSON 数组"
        $artifactExactDomains = @($ruleObject.domain)
        $artifactSuffixDomains = @($ruleObject.domain_suffix)
    }

    foreach ($domain in $artifactExactDomains) {
        Assert-True ($classExactBlocks.Contains($domain)) "产物精确规则 [$domain] 必须来自最终精确规则集合"
    }
    foreach ($domain in $artifactSuffixDomains) {
        Assert-True ($classSuffixBlocks.Contains($domain)) "产物后缀规则 [$domain] 必须来自最终后缀规则集合"
    }

    $report = [ordered]@{
        project = $projectName
        target_format = $TargetFormat
        generator = [System.IO.Path]::GetFileName($generatorPath)
        corpus_version = $fixture.corpusVersion
        generated_at = (Get-Date).ToString("o")
        parser_cases = @($fixture.rules).Count
        parser_assertions = $script:assertionCount
        skipped_rule_cases = $skipCaseCount
        badfilter_cases = $badfilterCaseCount
        cancelled_rules = $cancelledRuleCount
        hosts_entries_expanded = $hostsParsedCount
        emitted_exact_rules = @($artifactExactDomains).Count
        emitted_suffix_rules = @($artifactSuffixDomains).Count
        suffix_conflicts_narrowed = $suffixConflictExactDomains.Count
        artifact_structure_valid = $true
        artifact_path = $outputFileName
        scope_note = "该脚本只验证解析器边界、规则集合来源和产物结构，不使用固定 34 个探针估计总体性能。全量语义一致率、Precision、Recall、F1 与 TP/FP/TN/FN 由 Invoke-UpstreamSemanticAudit.ps1 基于完整上游域名规则边界计算。"
    }

    $resultsDirectory = Join-Path $PSScriptRoot "TestResults"
    New-Item -ItemType Directory -Path $resultsDirectory -Force | Out-Null
    $reportPath = Join-Path $resultsDirectory "parser-regression.json"
    $report | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $reportPath -Encoding utf8

    $summary = @(
        "## 解析器与产物结构回归结果（$TargetFormat）",
        "",
        "| 指标 | 结果 |",
        "|---|---:|",
        "| 规则解析样本 | $(@($fixture.rules).Count) |",
        "| 解析断言 | $script:assertionCount |",
        "| 非域名级跳过样本 | $skipCaseCount |",
        "| badfilter 样本 | $badfilterCaseCount |",
        "| Hosts 展开条目 | $hostsParsedCount |",
        "| 产物 DOMAIN 条目 | $(@($artifactExactDomains).Count) |",
        "| 产物 DOMAIN-SUFFIX 条目 | $(@($artifactSuffixDomains).Count) |",
        "| 父后缀冲突降级数 | $($suffixConflictExactDomains.Count) |",
        "",
        "总体语义指标不由固定探针计算；请查看 upstream-semantic-metrics.json。"
    ) -join [Environment]::NewLine

    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_STEP_SUMMARY)) {
        Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summary -Encoding utf8
    }

    Write-Host ""
    Write-Host $summary
    Write-Host "详细机器可读报告：$reportPath"


    Write-Host "全部解析器与产物结构回归断言通过。断言总数：$script:assertionCount"
}
finally {
    if (Test-Path -LiteralPath $tempOutputPath) {
        Remove-Item -LiteralPath $tempOutputPath -Force
    }
}
