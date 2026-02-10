# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0

# 定义广告过滤器URL列表
$urlList = @(
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_18_Annoyances_Cookies/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_19_Annoyances_Popups/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_20_Annoyances_MobileApp/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_21_Annoyances_Other/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_22_Annoyances_Widgets/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_101_EasyList/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_104_EasyListChina/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_118_EasyPrivacy/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_122_FanboysAnnoyances/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_123_FanboysSocialBlockingList/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_201_WebAnnoyancesUltralist/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_204_PeterLowesList/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_207_AdblockWarningRemovalList/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_208_Online_Malicious_URL_Blocklist/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_209_ADgkMobileChinalist/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_210_Spam404/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_211_AntiAdblockKillerReek/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_219_ChinaListAndEasyList/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_220_CJXsAnnoyanceList/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_228_xinggsf/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_229_IdontCareAboutCookies/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_239_FanboyAntifonts/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_240_BarbBlock/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_241_FanboyCookiemonster/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_242_NoCoin/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_250_DandelionSproutAnnoyances/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_251_LegitimateURLShortener/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_255_Phishing_URL_Blocklist/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_256_Scam_Blocklist/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/ThirdParty/filter_257_uBlock_Origin_Badware_risks/filter.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/adservers_firstparty.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/foreign.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/cryptominers.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/adservers.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/adservers_firstparty.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/allowlist.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/allowlist_stealth.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/antiadblock.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/replace.txt",  
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/BaseFilter/sections/content_blocker.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exclusions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exceptions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/rules.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/mobile.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/popups.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SocialFilter/sections/social_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/popups_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/popups_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/AnnoyancesFilter/Widgets/sections/widgets.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/adservers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/ChineseFilter/sections/replace.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/adservers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/allowlist_app.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/allowlist_web.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/antiadblock.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/MobileFilter/sections/replace.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/cookies_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/cookies_general.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/cookies_specific.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/general_elemhide.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/general_extensions.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/mobile.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/mobile_allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/TrackParamFilter/sections/allowlist.txt",
"https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/TrackParamFilter/sections/general_url.txt",
"https://raw.githubusercontent.com/REIJI007/AdBlock_Rule_For_Clash/refs/heads/main/allow%20list"
)

# 日志文件路径
$logFilePath = "$PSScriptRoot/adblock_log.txt"

# 创建两个HashSet来存储唯一的规则和排除的域名
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new()

# 创建WebClient对象用于下载规则
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

# DNS规范验证函数
function Is-ValidDNSDomain($domain) {
    if ($domain.Length -gt 253) { return $false }
    $labels = $domain -split "\."
    foreach ($label in $labels) {
        if ($label.Length -eq 0 -or $label.Length -gt 63) { return $false }
        if ($label -notmatch "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$") {
            return $false
        }
    }
    $tld = $labels[-1]
    if ($tld -notmatch "^[a-zA-Z]{2,}$") { return $false }
    return $true
}

foreach ($url in $urlList) {
    Write-Host "正在处理: $url"
    Add-Content -Path $logFilePath -Value "正在处理: $url"
    try {
        # 读取并拆分内容为行
        $content = $webClient.DownloadString($url)
        $lines = $content -split "`n"

        foreach ($line in $lines) {
            # 直接处理以 @@ 开头的规则，提取域名并加入白名单
            if ($line.StartsWith('@@')) {
                $domains = $line -replace '^@@', '' -split '[^\w.-]+'
                foreach ($domain in $domains) {
                    if (-not [string]::IsNullOrWhiteSpace($domain) -and $domain -match '[\w-]+(\.[[\w-]+)+') {
                        $excludedDomains.Add($domain.Trim()) | Out-Null
                    }
                }
            }
            else {
                # 匹配 Adblock/Easylist 格式的规则
                if ($line -match '^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^$') {
                    $domain = $Matches[1]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 匹配 Hosts 文件格式的 IPv4 规则
                elseif ($line -match '^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                    $domain = $Matches[2]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 匹配 Hosts 文件格式的 IPv6 规则（以 ::1 或 :: 开头）
                elseif ($line -match '^::(1)?\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                    $domain = $Matches[2]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 匹配 Dnsmasq address=/域名/格式的规则
                elseif ($line -match '^address=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
                    $domain = $Matches[1]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 匹配 Dnsmasq server=/域名/的规则
                elseif ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
                    $domain = $Matches[1]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 匹配通配符规则
                elseif ($line -match '^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^$') {
                    $domain = $Matches[1]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 处理纯域名行
                elseif ($line -match '^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                    $domain = $Matches[1]
                    $uniqueRules.Add($domain) | Out-Null
                }
            }
        }
    }
    catch {
        Write-Host "处理 $url 时出错: $_"
        Add-Content -Path $logFilePath -Value "处理 $url 时出错: $_"
    }
}

# 在写入文件之前进行DNS规范验证
$validRules = [System.Collections.Generic.HashSet[string]]::new()
$validExcludedDomains = [System.Collections.Generic.HashSet[string]]::new()

foreach ($domain in $uniqueRules) {
    if (Is-ValidDNSDomain($domain)) {
        $validRules.Add($domain) | Out-Null
    }
}

foreach ($domain in $excludedDomains) {
    if (Is-ValidDNSDomain($domain)) {
        $validExcludedDomains.Add($domain) | Out-Null
    }
}

# 排除所有白名单规则中的域名
$finalRules = $validRules | Where-Object { -not $validExcludedDomains.Contains($_) }

# 对规则进行排序并格式化
$formattedRules = $finalRules | Sort-Object | ForEach-Object {"- '$_'"}

# 统计生成的规则条目数量
$ruleCount = $finalRules.Count

# 获取当前时间并转换为东八区时间
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 创建文本格式的字符串
$textContent = @"
# Title: AdBlock_Rule_For_Clash
# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Clash/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: $generationTime
# Generated AdBlock rules
# Total entries: $ruleCount

payload:
$($formattedRules -join "`n")
"@

# 定义输出文件路径
$outputPath = "$PSScriptRoot/adblock_reject.yaml"
$textContent | Out-File -FilePath $outputPath -Encoding utf8

# 输出生成的有效规则总数
Write-Host "生成的有效规则总数: $ruleCount"
Add-Content -Path $logFilePath -Value "Total entries: $ruleCount"

