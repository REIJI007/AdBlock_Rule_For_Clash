# 【项目标题】AdBlock_Rule_For_Clash
# 【核心功能】从多个上游广告过滤源抓取规则，经精确解析后转换为Clash兼容的 DOMAIN-SUFFIX 与 DOMAIN 格式，最终生成clash规则集文件
# 【项目主页】https://github.com/REIJI007/AdBlock_Rule_For_Clash
# 【开源协议1】GPL-3.0 
# 【开源协议2】CC-BY-NC-SA 4.0

# ── 上游规则源列表 ────────────────────────────────────────────────────────────
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
    "https://raw.githubusercontent.com/AdguardTeam/ADguardFilters/master/TrackParamFilter/sections/general_url.txt"
)

# 凡携带以下修饰符的规则均在 HTTP/浏览器/应用层生效，DNS 层无法实施，直接跳过整条规则
$modSkipSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
# 列表：按逻辑语义分段注释（保持原顺序，仅在分段处加入注释）
@(
    # — 变换 / 重定向 / 安全策略 相关
    'redirect','redirect-rule','csp','replace',
    # — 参数与请求剪裁、Cookie、Header、权限 相关
    'removeparam','queryprune','cookie','header','permissions',
    # — 内联资源 / 媒体 / 内容 相关
    'inline-script','inline-font','empty','mp4','urltransform','jsonprune','hls','referrerpolicy','content',
    # — 屏蔽/隐藏/过滤 相关（通用或特定选择器）
    'genericblock','generichide','specifichide','elemhide','badfilter','urlblock',
    # — 应用/客户端/标签/方向/来源 标识 相关
    'app','client','ctag','to','from',
    # — 第三方/第一方 标识（及其变体）相关
    'third-party','3p','first-party','1p','~third-party','~3p',
    # — 严格一方/三方 模式及其反向标记
    'strict1p','~strict1p','strict3p','~strict3p','extension',
    # — 弹窗/网络/方法/协议/隐私功能 等行为或信号相关
    'popup','popunder','ping','webrtc','network','method','dnstype','protectedaudience','privacysandbox'
)
# 将上面的每个关键字逐一添加到 HashSet 中；使用 Out-Null 丢弃 Add 的返回值（布尔）
| ForEach-Object { $modSkipSet.Add($_) | Out-Null }

# ── 加载公共后缀列表（PSL） ───────────────────────────────────────────────────
$pslSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
Write-Host "正在加载 PSL 公共后缀列表..."
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0")
$pslContent = $wc.DownloadString("https://publicsuffix.org/list/public_suffix_list.dat")
foreach ($pslLine in ($pslContent -split "`n")) {
    $pslLine = $pslLine.Trim()
    if ($pslLine.StartsWith("//") -or [string]::IsNullOrWhiteSpace($pslLine)) { continue }
    if ($pslLine.StartsWith("!") -or $pslLine.StartsWith("*")) { continue }
    $pslSet.Add($pslLine) | Out-Null
}
Write-Host "PSL 加载完成，共 $($pslSet.Count) 条"

# ── 工具函数 ───────────────────────────────────────────────


function Normalize-Domain([string]$domain) {
    if ([string]::IsNullOrWhiteSpace($domain)) { return $null }
    $d = $domain.Trim()
    try {
        $idn = New-Object System.Globalization.IdnMapping
        $ascii = $idn.GetAscii($d)
        return $ascii.ToLowerInvariant()
    } catch {
        return $d.ToLowerInvariant()
    }
}

function Is-ValidDNSDomain([string]$domain) {
    if ([string]::IsNullOrWhiteSpace($domain)) { return $false }
    $domain = Normalize-Domain $domain
    if ($domain.Length -gt 253) { return $false }
    if ($domain -match '[\s\(\)\[\]\/\\:\;@\,\+]' -or $domain -match '_') { return $false }

    $labels = $domain -split '\.'
    if ($labels.Count -lt 2) { return $false }

    foreach ($label in $labels) {
        if ($label.Length -eq 0 -or $label.Length -gt 63) { return $false }
        if ($label -notmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$') { return $false }
    }

    if ($labels[-1].Length -lt 2) { return $false }
    return $true
}


function Is-PublicSuffix([string]$domain) {
    return $pslSet.Contains($domain)
}


function Resolve-WildcardDomain([string]$raw) {
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    if ($raw -match '^\*+\.(.+)$') {
        $candidate = Normalize-Domain $Matches[1]
        if (Is-ValidDNSDomain $candidate) { return $candidate }
    }
    return $null
}


$script:_parentCache = [System.Collections.Generic.Dictionary[string, string[]]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Get-ParentDomains([string]$domain) {
    $cached = $null
    if ($script:_parentCache.TryGetValue($domain, [ref]$cached)) { return $cached }
    $labels  = $domain -split "\."
    $parents = [System.Collections.Generic.List[string]]::new()
    for ($i = 1; $i -lt $labels.Length - 1; $i++) {
        $parents.Add(($labels[$i..($labels.Length - 1)] -join "."))
    }
    $result = $parents.ToArray()
    $script:_parentCache[$domain] = $result
    return $result
}

function Resolve-Modifiers([string]$modStr) {
    $ret = [PSCustomObject]@{ Decision = "CONTINUE"; SkipReason = $null; IsImportant = $false }
    if ([string]::IsNullOrWhiteSpace($modStr)) { return $ret }
    foreach ($mod in ($modStr -split ',' | ForEach-Object { $_.Trim().ToLower() })) {
        $modName = ($mod -split '=')[0]
        if ($modSkipSet.Contains($modName)) {
            $ret.Decision = "SKIP"; $ret.SkipReason = "non-dns-modifier:$modName"; return $ret
        }
        if ($modName -eq 'dnsrewrite') {
            $rv = if ($mod -match '=(.+)$') { $Matches[1] } else { '' }
            if ($rv -eq 'nxdomain' -or $rv -match '^noerror;a;[\d.]+$' -or $rv -match '^noerror;aaaa;[0:]*$' -or $rv -eq 'noerror;aaaa;::1') { continue }
            $ret.Decision = "SKIP"; $ret.SkipReason = "dnsrewrite-non-block:$rv"; return $ret
        }
        if ($modName -eq 'domain') {
            $dv = if ($mod -match '=(.+)$') { $Matches[1] } else { '' }
            if ($dv -eq '*' -or $dv -eq '~*') { continue }
            $ret.Decision = "SKIP"; $ret.SkipReason = "context-dependent:domain=$dv"; return $ret
        }
        if ($modName -eq 'important') { $ret.IsImportant = $true; continue }
    }
    if ($ret.IsImportant) { $ret.Decision = "IMPORTANT_CONTINUE" }
    return $ret
}

$whitelistSubresourceTypes = [System.Collections.Generic.HashSet[string]]@('script','image','stylesheet','css','object','xmlhttprequest','xhr','media','font','subdocument','ping','websocket','webrtc','other','object-subrequest')

function Is-ContextConstrainedWhitelist([string]$modStr) {
    if ([string]::IsNullOrWhiteSpace($modStr)) { return $false }
    foreach ($mod in ($modStr -split ',' | ForEach-Object { ($_ -split '=')[0].Trim().ToLower() })) {
        if ($whitelistSubresourceTypes.Contains($mod) -or $modSkipSet.Contains($mod)) { return $true }
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

# ── 文件语义分类函数 ───────────────────────────────────────
function Is-WhitelistSource([string]$url) {
    return $url -match "(?i)allowlist|exclusions|exceptions|whitelist"
}

# ── 集中式规则解析函数 ───────────────────────────────────────
function Parse-Rule {
    param([string]$line, [bool]$isWhitelistSource = $false)
    $result = [PSCustomObject]@{
        Action = "SKIP"; Domain = $null; SkipReason = "unmatched"; SourceFormat = "unknown"; IsImportant = $false; IsWildcard = $false
    }
    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("!") -or $line.StartsWith("#") -or $line.StartsWith("[") -or $line -match '##|#\?#|#@#|#\$#') {
        $result.SkipReason = "comment-or-cosmetic"; return $result
    }
    if ($line -match '^/.+/(\$.*)?$') { $result.SkipReason = "regex-rule"; return $result }
    if ($line -match '^\|https?://') { $result.SkipReason = "exact-url-rule"; return $result }
    if ($line.StartsWith("@@")) {
        $extractDomain = $null; $modPartRaw = $null
        if ($line -match '^@@\|\|([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)(.*)$') {
            $extractDomain = $Matches[1].ToLower(); $afterDomain = $Matches[5]
            if ($afterDomain -match '^[\^]?[/?]') { $result.SkipReason = "whitelist-path-or-query-specific"; return $result }
            if ($afterDomain -match '^\^?\$(.+)$') { $modPartRaw = $Matches[1] }
        } elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }
        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            } else {
                $result.Action = "EXCLUDE"; $result.Domain = $extractDomain; $result.SourceFormat = "adblock-whitelist"; $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        } else { $result.SkipReason = "whitelist-unparseable" }
        return $result
    }
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower(); $modStr = $Matches[3]
        $modResult = Resolve-Modifiers $modStr
        if ($modResult.Decision -eq "SKIP") { $result.SkipReason = $modResult.SkipReason; return $result }
        if ($isWhitelistSource) { $result.Action = "EXCLUDE"; $result.SourceFormat = "whitelist-exact" } else { $result.Action = "EXACT"; $result.SourceFormat = "adguard-exact" }
        $result.Domain = $candidate; $result.IsImportant = $modResult.IsImportant
        return $result
    }
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower(); $rest = $Matches[2]
        $restBeforeDollar = if ($rest -match '^([^$]*)') { $Matches[1] } else { '' }
        if ($raw -match '[/?]' -or $restBeforeDollar -match '[/?]') { $result.SkipReason = "path-or-query-specific-rule"; return $result }
        if ($rest -match '^\^?\$(.+)$') {
            $modResult = Resolve-Modifiers $Matches[1]
            if ($modResult.Decision -eq "SKIP") { $result.SkipReason = $modResult.SkipReason; return $result }
            $result.IsImportant = $modResult.IsImportant
        }
        $domain = $null
        if ($raw -match '\*') {
            $domain = Resolve-WildcardDomain $raw
            if ($null -eq $domain) { $result.SkipReason = "unresolvable-wildcard"; return $result }
            $result.IsWildcard = $true
        } else { $domain = $raw }
        if ($domain -match '^\d{1,3}(\.\d{1,3}){3}$') { $result.SkipReason = "ip-address"; return $result }
        if ($isWhitelistSource) { $result.Action = "EXCLUDE"; $result.SourceFormat = "whitelist-suffix" } else { $result.Action = "SUFFIX"; $result.SourceFormat = "adblock-suffix" }
        $result.Domain = $domain
        return $result
    }
    if ($line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$') {
        $domain = $Matches[2].ToLower()
        if ($domain -in @("localhost","localhost.localdomain","local","broadcasthost")) { $result.SkipReason = "localhost-entry"; return $result }
        if ($isWhitelistSource) { $result.Action = "EXCLUDE"; $result.SourceFormat = "whitelist-hosts" } else { $result.Action = "EXACT"; $result.SourceFormat = "hosts" }
        $result.Domain = $domain
        return $result
    }
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower(); $target = $Matches[2].Trim()
        $isBlock = $false
        switch -Regex ($target) {
            '^$' { $isBlock = $true }
            '^0\.0\.0\.0$' { $isBlock = $true }
            '^127\.0\.0\.1$' { $isBlock = $true }
            '^::$' { $isBlock = $true }
            '^(::1|::0|0:0:0:0:0:0:0:0|0:0:0:0:0:0:0:1)$' { $isBlock = $true }
            '^#$' { $isBlock = $false }
            default { $isBlock = $false }
        }
        if (-not $isBlock) { $result.SkipReason = "dnsmasq-dns-forward:$target"; return $result }
        if ($isWhitelistSource) { $result.Action = "EXCLUDE"; $result.SourceFormat = "whitelist-dnsmasq" } else { $result.Action = "SUFFIX"; $result.SourceFormat = "dnsmasq-address" }
        $result.Domain = $domain
        return $result
    }
    if ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/') { $result.SkipReason = "dnsmasq-server-routing"; return $result }
    if ($line -match '^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
        if ($isWhitelistSource) { $result.Action = "EXCLUDE"; $result.SourceFormat = "whitelist-dnsmasq-local" } else { $result.Action = "SUFFIX"; $result.SourceFormat = "dnsmasq-local" }
        $result.Domain = $Matches[1].ToLower()
        return $result
    }
    if ($line -match '^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
        if ($isWhitelistSource) { $result.Action = "EXCLUDE"; $result.SourceFormat = "whitelist-plain" } else { $result.Action = "EXACT"; $result.SourceFormat = "plain-domain" }
        $result.Domain = $Matches[1].ToLower()
        return $result
    }
    $result.SkipReason = "no-pattern-match"
    return $result
}

# ── 主采集循环 ───────────────────────────────────────────────
$logFilePath = "$PSScriptRoot/adblock_log.txt"
$uniqueSuffixRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$uniqueExactRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$importantDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$importantWhitelistDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$wildcardSourceDoms = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$skipStats = [System.Collections.Generic.Dictionary[string,int]]::new()
$formatStats = [System.Collections.Generic.Dictionary[string,int]]::new()

$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; Win64) AppleWebKit/537.36")

foreach ($url in $urlList) {
    Write-Host "正在处理: $url"
    Add-Content -Path $logFilePath -Value "正在处理: $url"
    $isWhitelistSrc = Is-WhitelistSource $url
    try {
        $content = $webClient.DownloadString($url)
        foreach ($line in ($content -split "`n")) {
            $parsed = Parse-Rule $line.Trim() -isWhitelistSource $isWhitelistSrc
            switch ($parsed.Action) {
                "EXCLUDE" {
                    if (Is-ValidDNSDomain $parsed.Domain) {
                        $excludedDomains.Add($parsed.Domain) | Out-Null
                        if ($parsed.IsImportant) { $importantWhitelistDomains.Add($parsed.Domain) | Out-Null }
                    }
                    if (-not $formatStats.ContainsKey($parsed.SourceFormat)) { $formatStats[$parsed.SourceFormat] = 0 }
                    $formatStats[$parsed.SourceFormat]++
                }
                "SUFFIX" {
                    if ((Is-ValidDNSDomain $parsed.Domain) -and -not (Is-PublicSuffix $parsed.Domain) -and -not ($parsed.Domain -match '^\d{1,3}(\.\d{1,3}){3}$')) {
                        $uniqueSuffixRules.Add($parsed.Domain) | Out-Null
                        if ($parsed.IsImportant) { $importantDomains.Add($parsed.Domain) | Out-Null }
                        if ($parsed.IsWildcard) { $wildcardSourceDoms.Add($parsed.Domain) | Out-Null }
                    }
                    if (-not $formatStats.ContainsKey($parsed.SourceFormat)) { $formatStats[$parsed.SourceFormat] = 0 }
                    $formatStats[$parsed.SourceFormat]++
                }
                "EXACT" {
                    if ((Is-ValidDNSDomain $parsed.Domain) -and -not (Is-PublicSuffix $parsed.Domain)) {
                        $uniqueExactRules.Add($parsed.Domain) | Out-Null
                        if ($parsed.IsImportant) { $importantDomains.Add($parsed.Domain) | Out-Null }
                    }
                    if (-not $formatStats.ContainsKey($parsed.SourceFormat)) { $formatStats[$parsed.SourceFormat] = 0 }
                    $formatStats[$parsed.SourceFormat]++
                }
                "SKIP" {
                    if (-not $skipStats.ContainsKey($parsed.SkipReason)) { $skipStats[$parsed.SkipReason] = 0 }
                    $skipStats[$parsed.SkipReason]++
                }
            }
        }
    }
    catch {
        Write-Host "处理 $url 时出错: $_"
        Add-Content -Path $logFilePath -Value "处理 $url 时出错: $_"
    }
}

# ── 过滤阶段 + 白名单抑制 + 冲突索引 + 父域剪枝 ─────────────
$validSuffixRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$validExactRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$validExcludedDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($d in $uniqueSuffixRules) {
    if ((Is-ValidDNSDomain $d) -and -not (Is-PublicSuffix $d)) { $validSuffixRules.Add($d) | Out-Null }
}
foreach ($d in $uniqueExactRules) {
    if ((Is-ValidDNSDomain $d) -and -not (Is-PublicSuffix $d)) { $validExactRules.Add($d) | Out-Null }
}
foreach ($d in $excludedDomains) {
    if ((Is-ValidDNSDomain $d) -and -not (Is-PublicSuffix $d)) { $validExcludedDomains.Add($d) | Out-Null }
}

$filteredImportantWhitelist = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($d in $importantWhitelistDomains) {
    if ((Is-ValidDNSDomain $d) -and -not (Is-PublicSuffix $d)) { $filteredImportantWhitelist.Add($d) | Out-Null }
}
$importantWhitelistDomains = $filteredImportantWhitelist

function Should-WhitelistSuppress([string]$domain) {
    if ($importantWhitelistDomains.Contains($domain)) { return $true }
    if ($importantDomains.Contains($domain)) { return $false }
    if ($validExcludedDomains.Contains($domain)) { return $true }
    foreach ($parent in (Get-ParentDomains $domain)) {
        if ($importantWhitelistDomains.Contains($parent)) { return $true }
        if ($importantDomains.Contains($parent)) { return $false }
        if ($validExcludedDomains.Contains($parent)) { return $true }
    }
    return $false
}

Write-Host "正在构建 SUFFIX-白名单子域冲突索引..."
$domainsWithWhitelistedSubdomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($w in $validExcludedDomains) {
    $wIsImportantWL = $importantWhitelistDomains.Contains($w)
    foreach ($anc in (Get-ParentDomains $w)) {
        if (-not $validSuffixRules.Contains($anc)) { continue }
        $ancIsImportantBlock = $importantDomains.Contains($anc)
        if ($wIsImportantWL -or (-not $ancIsImportantBlock)) {
            $domainsWithWhitelistedSubdomains.Add($anc) | Out-Null
        }
    }
}
Write-Host "冲突索引构建完成，涉及 SUFFIX 规则: $($domainsWithWhitelistedSubdomains.Count) 条"

$suffixConflictExactDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$finalSuffixSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($d in $validSuffixRules) {
    if (Should-WhitelistSuppress $d) { continue }
    $dominated = $false
    foreach ($parent in (Get-ParentDomains $d)) {
        if ($validSuffixRules.Contains($parent) -and -not (Should-WhitelistSuppress $parent) -and -not $domainsWithWhitelistedSubdomains.Contains($parent)) {
            $dominated = $true; break
        }
    }
    if ($dominated) { continue }
    if ($domainsWithWhitelistedSubdomains.Contains($d)) {
        $suffixConflictExactDomains.Add($d) | Out-Null
    } else {
        $finalSuffixSet.Add($d) | Out-Null
    }
}

$finalExactSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($d in $validExactRules) {
    if (Should-WhitelistSuppress $d) { continue }
    $covered = $finalSuffixSet.Contains($d)
    if (-not $covered) {
        foreach ($parent in (Get-ParentDomains $d)) {
            if ($finalSuffixSet.Contains($parent)) { $covered = $true; break }
        }
    }
    if (-not $covered) { $finalExactSet.Add($d) | Out-Null }
}

foreach ($d in $suffixConflictExactDomains) {
    $covered = $finalSuffixSet.Contains($d)
    if (-not $covered) {
        foreach ($parent in (Get-ParentDomains $d)) {
            if ($finalSuffixSet.Contains($parent)) { $covered = $true; break }
        }
    }
    if (-not $covered) { $finalExactSet.Add($d) | Out-Null }
}

# ── 三类域名分类 ─────────────
Write-Host "正在构建三类域名集合（优先级:白名单 > DOMAIN > DOMAIN-SUFFIX，且三者无交集）..."

$classWhitelist = $validExcludedDomains.Clone()

$classExactBlocks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($d in $finalExactSet) {
    if (-not $classWhitelist.Contains($d)) { $classExactBlocks.Add($d) | Out-Null }
}

$classSuffixBlocks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($d in $finalSuffixSet) {
    if (-not $classWhitelist.Contains($d) -and -not $classExactBlocks.Contains($d)) { $classSuffixBlocks.Add($d) | Out-Null }
}

Write-Host "三类集合构建完成：Whitelist $($classWhitelist.Count) | DOMAIN $($classExactBlocks.Count) | DOMAIN-SUFFIX $($classSuffixBlocks.Count)"

# ── 输出 YAML 规则集（视觉优化版：DOMAIN-SUFFIX在前，DOMAIN在后 + payload上下空行） ───────────────────────────────
$ruleCount    = $classExactBlocks.Count + $classSuffixBlocks.Count
$generateTime = (Get-Date -AsUTC).AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

$allLines = [System.Collections.Generic.List[string]]::new()
$allLines.Add("# Title: AdBlock_Rule_For_Clash")
$allLines.Add("# Description: 适用于Clash的域名拦截规则集，每20分钟更新一次，确保即时同步上游")
$allLines.Add("# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Clash")
$allLines.Add("# LICENSE1: GPL-3.0")
$allLines.Add("# LICENSE2: CC-BY-NC-SA 4.0")
$allLines.Add("# Generated Time: $generateTime")
$allLines.Add("# Total Rules: $ruleCount")
$allLines.Add("# DOMAIN : $($classExactBlocks.Count)")
$allLines.Add("# DOMAIN-SUFFIX : $($classSuffixBlocks.Count)")
$allLines.Add("# Whitelist : $($classWhitelist.Count)")
$allLines.Add("")
$allLines.Add("payload:")
$allLines.Add("")

# 先输出 DOMAIN-SUFFIX
foreach ($d in ($classSuffixBlocks | Sort-Object)) {
    if ($wildcardSourceDoms.Contains($d)) {
        $allLines.Add("  # [APEX-WARN] $d 由通配符规则提升")
    }
    $allLines.Add("  - DOMAIN-SUFFIX,$d")
}

# 再输出 DOMAIN精确封锁
foreach ($d in ($classExactBlocks | Sort-Object)) {
    if ($suffixConflictExactDomains.Contains($d)) {
        $allLines.Add("  # $d 因白名单子域冲突降级")
    }
    $allLines.Add("  - DOMAIN,$d")
}

$outputPath = "$PSScriptRoot/adblock_reject.yaml"
($allLines -join "`n") | Out-File -FilePath $outputPath -Encoding utf8

# ── 控制台诊断输出 ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "===== 生成完成 ====="
Write-Host "生成时间: $generateTime"
Write-Host "总规则数: $ruleCount (DOMAIN: $($classExactBlocks.Count) | DOMAIN-SUFFIX: $($classSuffixBlocks.Count))"
Write-Host "白名单放行: $($classWhitelist.Count)"
Write-Host "文件路径: $outputPath"
Write-Host "=== 文件前 20 行预览 ==="
Get-Content -Path $outputPath -TotalCount 20 | ForEach-Object { Write-Host $_ }

$totalSkipped = ($skipStats.Values | Measure-Object -Sum).Sum
Add-Content -Path $logFilePath -Value "Generated at $generateTime | Total: $ruleCount | DOMAIN: $($classExactBlocks.Count) | SUFFIX: $($classSuffixBlocks.Count) | Whitelist: $($classWhitelist.Count) | Skipped: $totalSkipped"
Pause
