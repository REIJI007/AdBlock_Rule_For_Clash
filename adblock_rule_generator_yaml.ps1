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
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Cookies/sections/cookies_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/MobileApp/sections/mobile-app_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Other/sections/annoyances.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Other/sections/self-promo.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Other/sections/tweaks.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/antiadblock.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/popups_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/push-notifications_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Popups/sections/subscriptions_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/Widgets/sections/widgets.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers_firstparty.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/allowlist_stealth.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/antiadblock.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/banner_sizes.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/content_blocker.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/cryptominers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/foreign.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/replace.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/antiadblock.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/replace.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_app.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/allowlist_web.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/antiadblock.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/replace.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/specific_app.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/specific_web.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/popups.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/social_trackers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SocialFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_general.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/cookies_specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_elemhide.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_extensions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile_allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/allowlist.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/general_url.txt",
	"https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/TrackParamFilter/sections/specific.txt",
	"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exceptions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/exclusions.txt",
	"https://raw.githubusercontent.com/AdguardTeam/ADguardSDNSFilter/master/Filters/rules.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_clickthroughs.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_mail_trackers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_microsites.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers.txt",
	"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_original_trackers.txt",
	"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers.txt",
	"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/adservers_firstparty.txt",
	"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/cryptominers.txt",
	"https://adguardteam.github.io/AdguardFilters/BaseFilter/sections/foreign.txt",
	"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/adservers.txt",
	"https://adguardteam.github.io/AdguardFilters/ChineseFilter/sections/adservers_firstparty.txt",
	"https://adguardteam.github.io/AdguardFilters/MobileFilter/sections/adservers.txt",
	"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/mobile.txt",
	"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers.txt",
	"https://adguardteam.github.io/AdguardFilters/SpywareFilter/sections/tracking_servers_firstparty.txt"
)


# 凡携带以下修饰符的规则均在 HTTP/浏览器/应用层生效，DNS 层无法实施，直接跳过整条规则
$modSkipSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
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
) | ForEach-Object { $modSkipSet.Add($_) | Out-Null }

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
            $ret.Decision = "SKIP";
            $ret.SkipReason = "non-dns-modifier:$modName"; return $ret
        }
        if ($modName -eq 'dnsrewrite') {
            $rv = if ($mod -match '=(.+)$') { $Matches[1] } else { '' }
            if ($rv -eq 'nxdomain' -or $rv -match '^noerror;a;[\d.]+$' -or $rv -match '^noerror;aaaa;[0:]*$' -or $rv -eq 'noerror;aaaa;::1') { continue }
            $ret.Decision = "SKIP";
            $ret.SkipReason = "dnsrewrite-non-block:$rv"; return $ret
        }
        if ($modName -eq 'domain') {
            $dv = if ($mod -match '=(.+)$') { $Matches[1] } else { '' }
            if ($dv -eq '*' -or $dv -eq '~*') { continue }
            $ret.Decision = "SKIP";
            $ret.SkipReason = "context-dependent:domain=$dv"; return $ret
        }
        if ($modName -eq 'important') { $ret.IsImportant = $true; continue }
    }
    if ($ret.IsImportant) { $ret.Decision = "IMPORTANT_CONTINUE" }
    return $ret
}

$whitelistSubresourceTypes = [System.Collections.Generic.HashSet[string]]@('document','script','image','stylesheet','css','object','xmlhttprequest','xhr','media','font','subdocument','ping','websocket','webrtc','other','object-subrequest')

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

function Is-WhitelistSource([string]$url) {
    return $url -match "(?i)allowlist|exclusions|exceptions|whitelist"
}

# ── 集中式规则解析函数 ───────────────────────────────────────
function Parse-Rule {
    param([string]$line, [bool]$isWhitelistSource = $false)
    $result = [PSCustomObject]@{
        Action = "SKIP";
        Domain = $null; SkipReason = "unmatched"; SourceFormat = "unknown"; IsImportant = $false;
        IsWildcard = $false
    }
    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("!") -or $line.StartsWith("#") -or $line.StartsWith("[") -or $line -match '##|#\?#|#@#|#\$#') {
        $result.SkipReason = "comment-or-cosmetic";
        return $result
    }
    if ($line -match '^/.+/(\$.*)?$') { $result.SkipReason = "regex-rule"; return $result }
    if ($line -match '^\|https?://') { $result.SkipReason = "exact-url-rule"; return $result }
    if ($line.StartsWith("@@")) {
        $extractDomain = $null;
        $modPartRaw = $null
        if ($line -match '^@@\|\|([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)(.*)$') {
            $extractDomain = $Matches[1].ToLower();
            $afterDomain = $Matches[5]
            if ($afterDomain -match '^[\^]?[/?]') { $result.SkipReason = "whitelist-path-or-query-specific"; return $result }
            if ($afterDomain -match '^\^?\$(.+)$') { $modPartRaw = $Matches[1] }
        } elseif ($line -match '^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
            $extractDomain = $Matches[1].ToLower()
        }
        if ($null -ne $extractDomain) {
            if (Is-ContextConstrainedWhitelist $modPartRaw) {
                $result.SkipReason = "whitelist-context-constrained"
            } else {
                $result.Action = "EXCLUDE";
                $result.Domain = $extractDomain; $result.SourceFormat = "adblock-whitelist"; $result.IsImportant = Get-WhitelistImportantFlag $modPartRaw
            }
        } else { $result.SkipReason = "whitelist-unparseable" }
        return $result
    }
    if ($line -match '^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$') {
        $candidate = $Matches[1].ToLower();
        $modStr = $Matches[3]
        $modResult = Resolve-Modifiers $modStr
        if ($modResult.Decision -eq "SKIP") { $result.SkipReason = $modResult.SkipReason; return $result }
        if ($isWhitelistSource) { $result.Action = "EXCLUDE"; $result.SourceFormat = "whitelist-exact" } else { $result.Action = "EXACT"; $result.SourceFormat = "adguard-exact" }
        $result.Domain = $candidate;
        $result.IsImportant = $modResult.IsImportant
        return $result
    }
    if ($line -match '^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)') {
        $raw = $Matches[1].ToLower();
        $rest = $Matches[2]
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
    if ($line -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$') {
        $domain = $Matches[2].ToLower()
        if ($domain -in @("localhost","localhost.localdomain","local","broadcasthost")) { $result.SkipReason = "localhost-entry"; return $result }
        if ($isWhitelistSource) { $result.Action = "EXCLUDE"; $result.SourceFormat = "whitelist-hosts" } else { $result.Action = "EXACT"; $result.SourceFormat = "hosts" }
        $result.Domain = $domain
        return $result
    }
    if ($line -match '^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$') {
        $domain = $Matches[1].ToLower();
        $target = $Matches[2].Trim()
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
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

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
$validPslRules = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($d in $uniqueSuffixRules) {
    if ((Is-ValidDNSDomain $d) -and -not ($d -match '^\d{1,3}(\.\d{1,3}){3}$')) {
        if (Is-PublicSuffix $d) {
            $validPslRules.Add($d) | Out-Null
        } else {
            $validSuffixRules.Add($d) | Out-Null
        }
    }
}
foreach ($d in $uniqueExactRules) {
    if (Is-ValidDNSDomain $d) {
        if (Is-PublicSuffix $d) {
            $validPslRules.Add($d) | Out-Null
        } else {
            $validExactRules.Add($d) | Out-Null
        }
    }
}
# ── 强化：PSL whitelist（普通+important）移除过滤限制（修复潜在误杀/漏杀） ─────────────
foreach ($d in $excludedDomains) {
    if (Is-ValidDNSDomain $d) {   # 移除 -not (Is-PublicSuffix)：允许PSL apex白名单生效
        $validExcludedDomains.Add($d) | Out-Null
    }
}

$filteredImportantWhitelist = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($d in $importantWhitelistDomains) {
    if (Is-ValidDNSDomain $d) {   # 移除 -not (Is-PublicSuffix)：P0重要白名单支持PSL apex
        $filteredImportantWhitelist.Add($d) | Out-Null
    }
}
$importantWhitelistDomains = $filteredImportantWhitelist

$validExactRules.UnionWith($validPslRules)

# ==========================================
# 核心逻辑：五级优先级判定矩阵与最近邻原则
# ==========================================
function Get-EffectiveStatus([string]$domain) {
    $labels = $domain -split '\.'
    # ── 绝对控制层 (Global Override) ──
    # P0 (最高): $important 白名单 (跨级覆盖一切)
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($importantWhitelistDomains.Contains($current)) { return "WHITELIST_P0" }
    }

    # P1: $important 黑名单 (覆盖所有普通白名单)
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        if ($importantDomains.Contains($current)) { return "BLACKLIST_P1" }
    }

    # ── 结构解析层 (Nearest-Neighbor Win) ──
    # 自底向上遍历：最具体的子域优先级高于宽泛的父域
    $current = $domain
    for ($i = 0; $i -lt $labels.Length - 1; $i++) {
        $current = ($labels[$i..($labels.Length-1)] -join '.')
        # P2: 精确匹配白名单 (赦免特定子域)
        if ($validExcludedDomains.Contains($current)) { return "WHITELIST_P2" }
        # P3: 精确匹配黑名单 (仅在当层匹配时生效，不沿继承链向上扩散)
        if ($i -eq 0 -and $validExactRules.Contains($current)) { return "BLACKLIST_P3" }
        # P4 (最低): 广义后缀/父域黑名单
        if ($validSuffixRules.Contains($current)) { return "BLACKLIST_P4" }
    }
    return "UNKNOWN"
}

Write-Host "正在执行自动降级机制与冲突检测..."
$suffixConflictExactDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$allWhitelists = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$allWhitelists.UnionWith($importantWhitelistDomains)
$allWhitelists.UnionWith($validExcludedDomains)

# 识别有效被赦免的子域，标记其父域的 SUFFIX 规则以执行强制降级
foreach ($w in $allWhitelists) {
    if ((Get-EffectiveStatus $w) -like "WHITELIST*") {
        foreach ($parent in (Get-ParentDomains $w)) {
            if ($validSuffixRules.Contains($parent)) {
                $suffixConflictExactDomains.Add($parent) | Out-Null
            }
        }
    }
}
Write-Host "冲突检测完成，共有 $($suffixConflictExactDomains.Count) 个 SUFFIX 规则需降级为 DOMAIN"

$rawSuffixSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$rawExactSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

$allBlacklists = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$allBlacklists.UnionWith($validSuffixRules)
$allBlacklists.UnionWith($validExactRules)
$allBlacklists.UnionWith($importantDomains)

# 评估所有黑名单候选者的最终生效状态与输出形式
foreach ($d in $allBlacklists) {
    if ((Get-EffectiveStatus $d) -notlike "BLACKLIST*") { continue }
    $isSuffix = $false
    # 若被判定为黑名单，且原属性为 P4(Suffix)，且未被下属白名单「株连」，才维持 SUFFIX；否则降级为 EXACT
    if ($validSuffixRules.Contains($d) -and -not $suffixConflictExactDomains.Contains($d)) {
        $isSuffix = $true
    }
    if ($isSuffix) {
        $rawSuffixSet.Add($d) | Out-Null
    } else {
        $rawExactSet.Add($d) | Out-Null
    }
}

# ── 三类域名分类与冗余剪枝 ─────────────
Write-Host "正在构建三类域名集合与执行冗余剪枝..."
$classSuffixBlocks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($d in $rawSuffixSet) {
    $covered = $false
    # 如果父域已被包含在最终的 Suffix 列表中，则当前子后缀为冗余
    foreach ($parent in (Get-ParentDomains $d)) {
        if ($rawSuffixSet.Contains($parent)) {
            $covered = $true
            break
        }
    }
    if (-not $covered) {
        $classSuffixBlocks.Add($d) | Out-Null
    }
}

$classExactBlocks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($d in $rawExactSet) {
    $covered = $false
    # 如果父域存在于最终的 Suffix 列表中，则当前精确匹配为冗余
    foreach ($parent in (Get-ParentDomains $d)) {
        if ($classSuffixBlocks.Contains($parent)) {
            $covered = $true
            break
        }
    }
    if (-not $covered) {
        $classExactBlocks.Add($d) | Out-Null
    }
}

$classWhitelist = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($w in $allWhitelists) {
    if ((Get-EffectiveStatus $w) -like "WHITELIST*") {
        $classWhitelist.Add($w) | Out-Null
    }
}

Write-Host "三类集合构建完成：Whitelist $($classWhitelist.Count) | DOMAIN $($classExactBlocks.Count) | DOMAIN-SUFFIX $($classSuffixBlocks.Count)"

Write-Host "正在执行冲突父域子域精确补全（封堵降级导致的漏网之鱼）..."

$extraExactBlocks = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($black in $allBlacklists) {
    if ($classWhitelist.Contains($black)) { continue }
    foreach ($parent in (Get-ParentDomains $black)) {
        if ($suffixConflictExactDomains.Contains($parent)) {
            $extraExactBlocks.Add($black) | Out-Null
            break
        }
    }
}

foreach ($e in $extraExactBlocks) {
    $classExactBlocks.Add($e) | Out-Null
}

Write-Host "冲突补全完成：新增 $($extraExactBlocks.Count) 条精确规则（封堵漏杀）"

# ── 输出 YAML 规则集 ───────────────────────────────
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

foreach ($d in ($classSuffixBlocks | Sort-Object)) {
    if ($wildcardSourceDoms.Contains($d)) { $allLines.Add("  # [APEX-WARN] $d 由通配符规则提升") }
    $allLines.Add("  - DOMAIN-SUFFIX,$d")
}

foreach ($d in ($classExactBlocks | Sort-Object)) {
    if ($suffixConflictExactDomains.Contains($d)) { $allLines.Add("  # $d 因白名单子域冲突降级") }
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
Write-Host "PSL Apex DOMAIN (黑): $($validPslRules.Count)"
Write-Host "PSL Apex Whitelist (白) 已全支持"
Write-Host "文件路径: $outputPath"
Write-Host "=== 文件前 20 行预览 ==="
Get-Content -Path $outputPath -TotalCount 20 | ForEach-Object { Write-Host $_ }

$totalSkipped = ($skipStats.Values | Measure-Object -Sum).Sum
Add-Content -Path $logFilePath -Value "Generated at $generateTime | Total: $ruleCount | DOMAIN: $($classExactBlocks.Count) | SUFFIX: $($classSuffixBlocks.Count) | Whitelist: $($classWhitelist.Count) | Skipped: $totalSkipped"
Pause
